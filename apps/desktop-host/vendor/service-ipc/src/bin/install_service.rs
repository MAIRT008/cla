//! 产品网络服务安装助手（改写上游 `bin/install_service.rs` 的 Windows 分支，删去 macOS/Linux 分支）。
//!
//! 由产品安装包的 NSIS 钩子以管理员身份调用（UAC 就是这一步的本机授权），当前机器不执行：
//! `ai-environmental-steward-service-install --action <动作> [--user-from-session | --user-sid S-1-5-21-... --network-root <绝对路径>] --host-exe <绝对路径>`
//!
//! 动作：
//! - `install`：新装。登记或核对服务、收窄目录权限、写安装记录、启动并等到运行。
//! - `prepare-upgrade`（修复或升级替换文件之前，由已安装的旧助手执行；安装器此前已把整个安装目录备份到旁边）：
//!   先按运行状态逐环境回读保护，有请求却没覆盖就拒绝；再把安装记录与运行状态备份到服务状态目录的 `rollback\`，最后停服务。
//!   停服务期间 WFP 基线阻断仍在，受保护程序保持断网。
//! - `repair` / `complete-upgrade`（替换文件之后）：按新装流程启动；失败就停下服务、非零退出，由安装器把整个安装目录换回旧版。
//! - `stop-for-rollback`（安装器回滚之前，由安装目录里现有的助手执行）：核对服务程序路径后停服务并等到停下，让安装器能删掉新文件、放回旧版。
//! - `rollback-upgrade`（安装器已把旧版整个放回之后，由旧助手执行）：复原安装记录与运行状态，启动旧服务并等到运行。
//!
//! 批准用户：`--user-from-session` 取安装器所在会话的桌面用户（WTS 会话用户），而不是提权进程的令牌用户——
//! 用另一个管理员账号提权安装时，两者不同，服务只该放行实际使用桌面的那个人；网络状态根按该用户的配置文件目录推出。
//!
//! 边界：只认助手同目录下核验过的本产品服务程序；已有同名服务但程序路径不同就拒绝，不改、不删；
//! 不查询、不停止、不修复任何上游 Clash Verge 服务；宿主程序路径规范化后必须位于 ProgramFiles；
//! 状态目录 ACL 收窄为 SY/BA，链接密钥目录与日志目录额外只给批准用户读；链接密钥只落文件，不出现在命令行参数或输出里。
//! 每次运行在服务日志目录写 `install-<毫秒>-<进程号>.log`，统一日志收集会带走它。

use std::path::{Path, PathBuf};

/// 维护时一并备份、失败时复原的服务状态文件（相对服务状态目录）。
const STATE_BACKUP_FILES: [&str; 2] = ["install.json", "runtime-state.json"];

fn argument(arguments: &[String], name: &str) -> Option<String> {
    arguments.iter().position(|item| item == name).and_then(|index| arguments.get(index + 1)).cloned()
}

fn parse_action(arguments: &[String]) -> Result<String, String> {
    let action = argument(arguments, "--action").unwrap_or_else(|| "install".to_string());
    match action.as_str() {
        "install" | "repair" | "prepare-upgrade" | "complete-upgrade" | "rollback-upgrade" | "stop-for-rollback" => Ok(action),
        _ => Err("--action must be install, repair, prepare-upgrade, complete-upgrade, rollback-upgrade or stop-for-rollback".to_string()),
    }
}

/// 安装记录与运行状态的回滚副本：在服务状态目录里，与状态文件同样只有 SY/BA 能动。
fn state_rollback_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("rollback")
}

/// 会话的账号名：本地账号的域就是计算机名。用户名为空说明这个会话没有登录的用户。
fn account_name(domain: &str, user: &str) -> Result<String, String> {
    if user.trim().is_empty() {
        return Err("no interactive user is logged on to the installer session".to_string());
    }
    Ok(if domain.is_empty() { user.to_string() } else { format!("{domain}\\{user}") })
}

/// 注册表字符串值的两种类型，取值与 windows-sys 的 `REG_SZ`、`REG_EXPAND_SZ` 相同。
const REG_SZ_TYPE: u32 = 1;
const REG_EXPAND_SZ_TYPE: u32 = 2;

/// ProfileList 的 `ProfileImagePath`：`REG_SZ` 原样用，`REG_EXPAND_SZ`（标准配置文件通常是这种，例如 `%SystemDrive%\Users\name`）展开环境变量。
/// 展开后仍带 `%` 或不是绝对路径就拒绝，不拿半截路径当网络状态根。
fn profile_directory(value_type: u32, raw: &[u16], expand: impl FnOnce(&str) -> Result<String, String>) -> Result<PathBuf, String> {
    let text = String::from_utf16_lossy(raw);
    let resolved = match value_type {
        REG_SZ_TYPE => text,
        REG_EXPAND_SZ_TYPE => expand(&text)?,
        other => return Err(format!("the desktop user's profile folder has registry type {other}, not a string")),
    };
    let resolved = resolved.trim().to_string();
    if resolved.contains('%') || !steward_service_ipc::core::wfp::is_absolute_windows_path(&resolved) {
        return Err(format!("the desktop user's profile folder {resolved} is not an absolute path"));
    }
    Ok(PathBuf::from(resolved))
}

/// 桌面宿主的网络状态根：`%LOCALAPPDATA%\<产品标识>\network`，按用户配置文件目录推出（宿主用同一个产品标识）。
fn network_root_for_profile(profile: &Path) -> PathBuf {
    profile.join("AppData").join("Local").join(steward_service_ipc::PRODUCT_APP_ID).join("network")
}

/// 批准用户与其网络状态根：钩子给 `--user-from-session` 时取会话用户；显式给 SID 与网络状态根只供脚本化安装使用。
fn resolve_user(arguments: &[String], from_session: impl FnOnce() -> Result<(String, PathBuf), String>) -> Result<(String, PathBuf), String> {
    if arguments.iter().any(|item| item == "--user-from-session") {
        return from_session();
    }
    let user_sid = argument(arguments, "--user-sid").ok_or("--user-from-session, or --user-sid with --network-root, is required")?;
    let network_root = argument(arguments, "--network-root").ok_or("--network-root is required together with --user-sid")?;
    Ok((user_sid, PathBuf::from(network_root)))
}

fn millis_now() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

/// 安装助手自己的日志：写不进时不影响安装结果，但也不假装写了。
struct InstallLog {
    path: Option<PathBuf>,
}

impl InstallLog {
    fn open(log_dir: &Path) -> InstallLog {
        let path = log_dir.join(format!("install-{}-{}.log", millis_now(), std::process::id()));
        InstallLog { path: std::fs::create_dir_all(log_dir).ok().map(|_| path) }
    }

    fn line(&self, text: &str) {
        use std::io::Write;
        if let Some(path) = &self.path {
            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(file, "{} {text}", millis_now());
            }
        }
    }
}

/// 安装器所在会话的桌面用户：会话号 → WTS 用户名与域 → SID → 配置文件目录。
/// 只用本进程所在会话，不取提权令牌；会话 0（服务上下文）或没有登录用户就如实失败。
#[cfg(windows)]
fn session_user() -> Result<(String, PathBuf), String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, REG_VALUE_TYPE, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ};
    use windows_sys::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTSDomainName, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName, WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS,
    };

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }
    unsafe fn from_wide(pointer: *const u16) -> String {
        let mut length = 0usize;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length))
    }
    unsafe fn session_text(session: u32, class: WTS_INFO_CLASS) -> Result<String, String> {
        let mut buffer: *mut u16 = std::ptr::null_mut();
        let mut bytes = 0u32;
        if WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, class, &mut buffer, &mut bytes) == 0 || buffer.is_null() {
            return Err(format!("the installer session cannot be queried: {}", std::io::Error::last_os_error()));
        }
        let text = from_wide(buffer);
        WTSFreeMemory(buffer.cast());
        Ok(text)
    }
    fn expand_environment(text: &str) -> Result<String, String> {
        let source = wide(text);
        let needed = unsafe { ExpandEnvironmentStringsW(source.as_ptr(), std::ptr::null_mut(), 0) };
        if needed == 0 {
            return Err(format!("the profile folder {text} cannot be expanded: {}", std::io::Error::last_os_error()));
        }
        let mut buffer = vec![0u16; needed as usize];
        let written = unsafe { ExpandEnvironmentStringsW(source.as_ptr(), buffer.as_mut_ptr(), needed) };
        if written == 0 || written > needed {
            return Err(format!("the profile folder {text} cannot be expanded: {}", std::io::Error::last_os_error()));
        }
        let length = buffer.iter().position(|&unit| unit == 0).unwrap_or(buffer.len());
        Ok(String::from_utf16_lossy(&buffer[..length]))
    }

    let mut session = 0u32;
    if unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } == 0 {
        return Err(format!("the installer session is unknown: {}", std::io::Error::last_os_error()));
    }
    if session == 0 {
        return Err("the installer runs in session 0 (a service context); run it from the desktop user's session".to_string());
    }
    let user = unsafe { session_text(session, WTSUserName)? };
    let domain = unsafe { session_text(session, WTSDomainName)? };
    let account = wide(&account_name(&domain, &user)?);

    let mut sid_bytes = 0u32;
    let mut domain_chars = 0u32;
    let mut kind: SID_NAME_USE = 0;
    unsafe {
        LookupAccountNameW(std::ptr::null(), account.as_ptr(), std::ptr::null_mut(), &mut sid_bytes, std::ptr::null_mut(), &mut domain_chars, &mut kind);
    }
    if sid_bytes == 0 {
        return Err(format!("the desktop user's account cannot be resolved: {}", std::io::Error::last_os_error()));
    }
    let mut sid = vec![0u8; sid_bytes as usize];
    let mut referenced = vec![0u16; domain_chars.max(1) as usize];
    let found = unsafe {
        LookupAccountNameW(std::ptr::null(), account.as_ptr(), sid.as_mut_ptr().cast(), &mut sid_bytes, referenced.as_mut_ptr(), &mut domain_chars, &mut kind)
    };
    if found == 0 {
        return Err(format!("the desktop user's account cannot be resolved: {}", std::io::Error::last_os_error()));
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) } == 0 || text.is_null() {
        return Err(format!("the desktop user's SID cannot be formatted: {}", std::io::Error::last_os_error()));
    }
    let user_sid = unsafe { from_wide(text) };
    unsafe {
        LocalFree(text.cast());
    }

    let subkey = wide(&format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{user_sid}"));
    let value = wide("ProfileImagePath");
    // 两种字符串类型都接受并关掉自动展开：先拿到原文与实际类型，再由 profile_directory 决定是否展开。
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
    let mut value_type: REG_VALUE_TYPE = 0;
    let mut bytes = 0u32;
    let status = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), value.as_ptr(), flags, &mut value_type, std::ptr::null_mut(), &mut bytes)
    };
    if status != 0 || bytes < 2 {
        return Err(format!("the desktop user's profile folder is not registered (status {status})"));
    }
    let mut buffer = vec![0u16; (bytes as usize).div_ceil(2)];
    let status = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), value.as_ptr(), flags, &mut value_type, buffer.as_mut_ptr().cast(), &mut bytes)
    };
    if status != 0 {
        return Err(format!("the desktop user's profile folder cannot be read (status {status})"));
    }
    let length = buffer.iter().position(|&unit| unit == 0).unwrap_or(buffer.len());
    let profile = profile_directory(value_type, &buffer[..length], expand_environment)?;
    Ok((user_sid, network_root_for_profile(&profile)))
}

#[cfg(windows)]
fn same_program(left: &Path, right: &Path) -> bool {
    let normalize = |path: &Path| {
        std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .trim_matches('"')
            .to_ascii_lowercase()
    };
    normalize(left) == normalize(right)
}

#[cfg(windows)]
fn restrict_directory(directory: &Path, extra_reader_sid: Option<&str>) -> Result<(), String> {
    let icacls = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join("icacls.exe");
    let mut command = std::process::Command::new(icacls);
    command.arg(directory);
    match extra_reader_sid {
        None => {
            command.args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]);
        }
        Some(sid) => {
            command.args(["/grant:r", &format!("*{sid}:(OI)(CI)R")]);
        }
    }
    let status = command.status().map_err(|error| format!("icacls failed to start: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("icacls did not restrict {}", directory.display()))
    }
}

#[cfg(windows)]
fn service_paths() -> Result<steward_service_ipc::ServicePaths, String> {
    let install_dir = std::env::current_exe()
        .map_err(|error| error.to_string())?
        .parent()
        .map(Path::to_path_buf)
        .ok_or("installer has no directory")?;
    let program_data = std::env::var_os("ProgramData").ok_or("ProgramData is not set")?;
    Ok(steward_service_ipc::ServicePaths::rooted(
        PathBuf::from(program_data).join(steward_service_ipc::core::paths::STATE_DIR_NAME),
        install_dir,
    ))
}

#[cfg(windows)]
fn wait_for(service: &windows_service::service::Service, wanted: windows_service::service::ServiceState) -> bool {
    for _ in 0..150 {
        if service.query_status().map(|status| status.current_state == wanted).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    false
}

/// 打开本产品服务并核对它的程序就是本助手同目录的服务程序；不是就不碰。
#[cfg(windows)]
fn open_product_service(paths: &steward_service_ipc::ServicePaths, access: windows_service::service::ServiceAccess) -> Result<windows_service::service::Service, String> {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|error| error.to_string())?;
    let service = manager.open_service(steward_service_ipc::SERVICE_NAME, access).map_err(|error| error.to_string())?;
    let config = service.query_config().map_err(|error| error.to_string())?;
    if !same_program(&config.executable_path, &paths.service_binary()) {
        return Err("the service with the product name points at another program; it was left untouched".to_string());
    }
    Ok(service)
}

#[cfg(windows)]
fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let action = match parse_action(&arguments) {
        Ok(action) => action,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(64);
        }
    };
    let log = match service_paths() {
        Ok(paths) => InstallLog::open(&paths.log_dir()),
        Err(_) => InstallLog { path: None },
    };
    log.line(&format!("action.begin {action} version={}", steward_service_ipc::VERSION));
    let result = match action.as_str() {
        "install" => install(&arguments, &log),
        "prepare-upgrade" => prepare_upgrade(&log),
        "repair" | "complete-upgrade" => complete_upgrade(&arguments, &log),
        "stop-for-rollback" => stop_for_rollback(&log),
        _ => rollback_upgrade(&log),
    };
    match result {
        Ok(()) => log.line(&format!("action.done {action}")),
        Err(error) => {
            log.line(&format!("action.failed {action}: {error}"));
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
fn install(arguments: &[String], log: &InstallLog) -> Result<(), String> {
    use std::ffi::{OsStr, OsString};
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceInfo, ServiceStartType, ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let (user_sid, network_root) = resolve_user(arguments, session_user)?;
    let host_exe = PathBuf::from(argument(arguments, "--host-exe").ok_or("--host-exe is required")?);
    if !steward_service_ipc::core::paths::valid_user_sid(&user_sid) {
        return Err("the approved user is not a local user SID".to_string());
    }
    log.line(&format!("install.approved_user sid={user_sid}"));
    let has_parent = |path: &Path| path.components().any(|part| matches!(part, std::path::Component::ParentDir));
    if !network_root.is_absolute() || has_parent(&network_root) {
        return Err("the network root must be an absolute path without ..".to_string());
    }
    if !host_exe.is_absolute() || !host_exe.is_file() {
        return Err("--host-exe must be the installed desktop host program".to_string());
    }
    let host_exe = std::fs::canonicalize(&host_exe).map_err(|error| format!("--host-exe cannot be resolved: {error}"))?;
    let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from).ok_or("ProgramFiles is not set")?;
    let program_files = std::fs::canonicalize(&program_files).map_err(|error| format!("ProgramFiles cannot be resolved: {error}"))?;
    if !steward_service_ipc::core::paths::is_within(&program_files, &host_exe) {
        return Err("--host-exe must be installed under ProgramFiles so that only administrators can replace the program the service trusts".to_string());
    }

    let paths = service_paths()?;
    let service_binary = paths.service_binary();
    if !service_binary.is_file() {
        return Err(format!("{} is not next to the installer", steward_service_ipc::SERVICE_EXE));
    }

    std::fs::create_dir_all(paths.state_dir()).map_err(|error| error.to_string())?;
    restrict_directory(paths.state_dir(), None)?;
    let link_dir = paths.host_link_key().parent().map(Path::to_path_buf).ok_or("link key has no directory")?;
    std::fs::create_dir_all(&link_dir).map_err(|error| error.to_string())?;
    restrict_directory(&link_dir, Some(&user_sid))?;
    // RC5：只读归档与诊断包导出要读服务与内核日志；批准用户只拿到这个目录的读权限，服务照旧独占写。
    let log_dir = paths.log_dir();
    std::fs::create_dir_all(&log_dir).map_err(|error| error.to_string())?;
    restrict_directory(&log_dir, Some(&user_sid))?;
    let existing_key = std::fs::read_to_string(paths.host_link_key())
        .ok()
        .filter(|text| steward_service_ipc::core::auth::parse_link_key(text).is_ok());
    if existing_key.is_none() {
        let key = steward_service_ipc::core::auth::random_hex(32).map_err(|error| error.to_string())?;
        std::fs::write(paths.host_link_key(), key).map_err(|error| error.to_string())?;
    }
    let record = steward_service_ipc::core::store::InstallRecord {
        approved_user_sid: user_sid,
        network_root: network_root.to_string_lossy().to_string(),
        host_executable: host_exe.to_string_lossy().trim_start_matches(r"\\?\").to_string(),
        installed_at_ms: millis_now() as i64,
        service_version: steward_service_ipc::VERSION.to_string(),
    };
    steward_service_ipc::core::store::write_install_record(&paths, &record).map_err(|error| error.to_string())?;
    log.line("install.state_ready");

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|error| error.to_string())?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG | ServiceAccess::START | ServiceAccess::CHANGE_CONFIG;
    let service = match manager.open_service(steward_service_ipc::SERVICE_NAME, access) {
        Ok(service) => {
            let config = service.query_config().map_err(|error| error.to_string())?;
            if !same_program(&config.executable_path, &service_binary) {
                return Err("an existing service with the product name points at another program; it was left untouched".to_string());
            }
            service
        }
        Err(_) => {
            let info = ServiceInfo {
                name: OsString::from(steward_service_ipc::SERVICE_NAME),
                display_name: OsString::from(steward_service_ipc::core::paths::SERVICE_DISPLAY_NAME),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::AutoStart,
                error_control: ServiceErrorControl::Normal,
                executable_path: service_binary.clone(),
                launch_arguments: vec![],
                dependencies: vec![],
                account_name: None,
                account_password: None,
            };
            let created = manager.create_service(&info, access).map_err(|error| error.to_string())?;
            created
                .set_description("AI Environmental Steward managed network runtime and protection")
                .map_err(|error| error.to_string())?;
            created
        }
    };
    let actions = [5u64, 10, 30]
        .into_iter()
        .map(|delay| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(delay) })
        .collect();
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(actions),
        })
        .map_err(|error| error.to_string())?;
    service.set_failure_actions_on_non_crash_failures(true).map_err(|error| error.to_string())?;
    let state = service.query_status().map_err(|error| error.to_string())?.current_state;
    if matches!(state, ServiceState::Stopped | ServiceState::StopPending) {
        service.start(&Vec::<&OsStr>::new()).map_err(|error| error.to_string())?;
    }
    if !wait_for(&service, ServiceState::Running) {
        return Err("the service did not reach the running state within 30 seconds".to_string());
    }
    log.line("install.service_running");
    Ok(())
}

#[cfg(windows)]
fn prepare_upgrade(log: &InstallLog) -> Result<(), String> {
    use windows_service::service::{ServiceAccess, ServiceState};

    let paths = service_paths()?;
    let service = open_product_service(&paths, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG | ServiceAccess::STOP | ServiceAccess::START)?;

    // 先确认保护：运行状态里请求过的每个环境都回读一遍，没覆盖就不进维护，现有版本照常运行。
    let state = std::fs::read(paths.runtime_state())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<steward_service_ipc::core::network::RuntimeState>(&bytes).ok())
        .unwrap_or_default();
    let protection = steward_service_ipc::core::wfp::product_protection();
    for (environment_ref, record) in state.protection.iter().filter(|(_, record)| record.requested) {
        let outcome = steward_service_ipc::core::network::ProtectionBackend::read(protection.as_ref(), environment_ref, &record.processes, &record.loopback);
        if !outcome.covers(&record.processes) {
            return Err(format!("protection for {environment_ref} is not confirmed; maintenance was refused and the running version was left in place"));
        }
        log.line(&format!("maintenance.protection_confirmed {environment_ref}"));
    }

    // 安装记录与运行状态进回滚副本；程序文件由安装器整目录备份。
    let backup = state_rollback_dir(paths.state_dir());
    let _ = std::fs::remove_dir_all(&backup);
    std::fs::create_dir_all(&backup).map_err(|error| format!("the state backup cannot be created: {error}"))?;
    for name in STATE_BACKUP_FILES {
        let from = paths.state_dir().join(name);
        if from.is_file() {
            std::fs::copy(&from, backup.join(name)).map_err(|error| format!("backing up {name} failed: {error}"))?;
        }
    }
    log.line(&format!("maintenance.state_backup_ready {}", backup.display()));

    // 停服务：WFP 基线阻断不随服务停止撤除，维护窗口里受保护程序保持断网。
    // 停不下来就把服务重新启动再拒绝：安装器随后中止，不能留下一个停着、没人再启动的服务。
    if service.query_status().map_err(|error| error.to_string())?.current_state != ServiceState::Stopped {
        service.stop().map_err(|error| format!("the service could not be stopped: {error}"))?;
        if !wait_for(&service, ServiceState::Stopped) {
            let _ = std::fs::remove_dir_all(&backup);
            let _ = service.start(&Vec::<&std::ffi::OsStr>::new());
            log.line("maintenance.stop_timed_out service_restarted");
            return Err("the service did not stop within 30 seconds; it was started again and the running version was left in place".to_string());
        }
    }
    log.line("maintenance.service_stopped");
    Ok(())
}

/// 修复与升级替换文件之后：按新装流程启动。失败时把服务停下（安装器要替换整个目录），由安装器回到旧版本。
#[cfg(windows)]
fn complete_upgrade(arguments: &[String], log: &InstallLog) -> Result<(), String> {
    use windows_service::service::{ServiceAccess, ServiceState};
    match install(arguments, log) {
        Ok(()) => {
            if let Ok(paths) = service_paths() {
                let _ = std::fs::remove_dir_all(state_rollback_dir(paths.state_dir()));
            }
            Ok(())
        }
        Err(error) => {
            if let Ok(paths) = service_paths() {
                if let Ok(service) = open_product_service(&paths, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG | ServiceAccess::STOP) {
                    if service.query_status().map(|status| status.current_state != ServiceState::Stopped).unwrap_or(false) {
                        let _ = service.stop();
                        let _ = wait_for(&service, ServiceState::Stopped);
                    }
                }
            }
            log.line(&format!("upgrade.failed_needs_full_rollback {error}"));
            Err(format!("the new version did not start ({error}); the installer restores the previous version"))
        }
    }
}

/// 安装器回滚之前：停下本产品服务并等到停下，安装器才能删掉新文件、把旧版整个放回。服务本来就停着也算成功。
#[cfg(windows)]
fn stop_for_rollback(log: &InstallLog) -> Result<(), String> {
    use windows_service::service::{ServiceAccess, ServiceState};
    let paths = service_paths()?;
    let service = open_product_service(&paths, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG | ServiceAccess::STOP)?;
    if service.query_status().map_err(|error| error.to_string())?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        if !wait_for(&service, ServiceState::Stopped) {
            return Err("the service did not stop, so the previous version cannot be put back".to_string());
        }
    }
    log.line("rollback.service_stopped");
    Ok(())
}

/// 安装器已把旧版整个放回：复原安装记录与运行状态，启动旧服务并等到运行。
#[cfg(windows)]
fn rollback_upgrade(log: &InstallLog) -> Result<(), String> {
    use std::ffi::OsStr;
    use windows_service::service::{ServiceAccess, ServiceState};

    let paths = service_paths()?;
    let backup = state_rollback_dir(paths.state_dir());
    for name in STATE_BACKUP_FILES {
        let saved = backup.join(name);
        if saved.is_file() {
            std::fs::copy(&saved, paths.state_dir().join(name)).map_err(|error| format!("restoring {name} failed: {error}"))?;
            log.line(&format!("rollback.restored {name}"));
        }
    }
    let service = open_product_service(&paths, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG | ServiceAccess::STOP | ServiceAccess::START)?;
    if service.query_status().map_err(|error| error.to_string())?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        if !wait_for(&service, ServiceState::Stopped) {
            return Err("the service did not stop for rollback".to_string());
        }
    }
    service.start(&Vec::<&OsStr>::new()).map_err(|error| error.to_string())?;
    if !wait_for(&service, ServiceState::Running) {
        return Err("the restored service did not reach the running state".to_string());
    }
    let _ = std::fs::remove_dir_all(&backup);
    log.line("rollback.service_running");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the AI Environmental Steward network service installs on Windows only");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        std::iter::once("installer").chain(list.iter().copied()).map(str::to_string).collect()
    }

    #[test]
    fn only_the_lifecycle_actions_are_accepted_and_install_is_the_default() {
        assert_eq!(parse_action(&args(&[])).unwrap(), "install");
        for action in ["install", "repair", "prepare-upgrade", "complete-upgrade", "rollback-upgrade", "stop-for-rollback"] {
            assert_eq!(parse_action(&args(&["--action", action])).unwrap(), action);
        }
        for action in ["uninstall", "stop", "", "INSTALL"] {
            assert!(parse_action(&args(&["--action", action])).is_err(), "{action}");
        }
    }

    #[test]
    fn the_state_backup_covers_the_install_record_and_runtime_state_inside_the_service_state_directory() {
        let paths = steward_service_ipc::ServicePaths::rooted(PathBuf::from(r"C:\ProgramData\ai-environmental-steward-service"), PathBuf::new());
        assert!(state_rollback_dir(paths.state_dir()).starts_with(paths.state_dir()));
        let names: Vec<String> = [paths.install_record(), paths.runtime_state()]
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, STATE_BACKUP_FILES.to_vec(), "备份的正是服务读写的两份状态文件");
    }

    #[test]
    fn the_approved_user_comes_from_the_installer_session_unless_given_explicitly() {
        let session = || Ok(("S-1-5-21-1-2-3-1001".to_string(), network_root_for_profile(Path::new(r"C:\Users\desk"))));
        let (sid, root) = resolve_user(&args(&["--user-from-session", "--host-exe", "x"]), session).unwrap();
        assert_eq!(sid, "S-1-5-21-1-2-3-1001");
        assert_eq!(root, PathBuf::from(r"C:\Users\desk").join("AppData").join("Local").join(steward_service_ipc::PRODUCT_APP_ID).join("network"));
        let explicit = resolve_user(&args(&["--user-sid", "S-1-5-21-9", "--network-root", r"D:\n"]), || Err("not used".to_string())).unwrap();
        assert_eq!(explicit.0, "S-1-5-21-9");
        assert!(resolve_user(&args(&["--user-sid", "S-1-5-21-9"]), || Err("not used".to_string())).is_err());
        assert!(resolve_user(&args(&[]), || Err("not used".to_string())).is_err());
        assert!(resolve_user(&args(&["--user-from-session"]), || Err("session 0".to_string())).unwrap_err().contains("session 0"));
    }

    #[test]
    fn the_profile_folder_is_read_as_either_string_type_and_expanded() {
        let raw = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
        let untouched = |_: &str| Err("REG_SZ is not expanded".to_string());
        assert_eq!(profile_directory(REG_SZ_TYPE, &raw(r"C:\Users\desk"), untouched).unwrap(), PathBuf::from(r"C:\Users\desk"));
        let expanded = profile_directory(REG_EXPAND_SZ_TYPE, &raw(r"%SystemDrive%\Users\desk"), |text| Ok(text.replace("%SystemDrive%", "C:"))).unwrap();
        assert_eq!(expanded, PathBuf::from(r"C:\Users\desk"), "标准配置文件的 REG_EXPAND_SZ 展开后可用");
        assert!(profile_directory(REG_EXPAND_SZ_TYPE, &raw(r"%Missing%\desk"), |text| Ok(text.to_string())).is_err(), "展开不了的变量不当路径");
        assert!(profile_directory(REG_EXPAND_SZ_TYPE, &raw(r"%SystemDrive%\Users\desk"), |_| Err("boom".to_string())).unwrap_err().contains("boom"));
        assert!(profile_directory(7, &raw(r"C:\Users\desk"), |text| Ok(text.to_string())).is_err(), "REG_MULTI_SZ 等其他类型拒绝");
        assert!(profile_directory(REG_SZ_TYPE, &raw(r"Users\desk"), |text| Ok(text.to_string())).is_err(), "相对路径拒绝");
    }

    #[test]
    fn a_session_without_a_logged_on_user_is_refused() {
        assert_eq!(account_name("DESKTOP-1", "desk").unwrap(), r"DESKTOP-1\desk");
        assert_eq!(account_name("", "desk").unwrap(), "desk");
        assert!(account_name("DESKTOP-1", "").is_err());
    }

    #[test]
    fn every_run_leaves_its_own_install_log() {
        let dir = std::env::temp_dir().join(format!("steward-install-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = InstallLog::open(&dir);
        log.line("action.begin install");
        let files: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().to_string()).collect();
        assert_eq!(files.len(), 1);
        assert!(files[0].starts_with("install-") && files[0].ends_with(".log"), "{}", files[0]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
