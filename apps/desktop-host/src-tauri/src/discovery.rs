//! 真实发现（只读）：按当前 Windows 用户解析 FD-01 §5.2 列出的位置类型、Chromium 系浏览器与 Profile、
//! 默认浏览器和 WSL 发行版，给出每个候选根的 found / not_found / unreadable / unsupported_link 状态。
//!
//! - 发现阶段不读业务内容。唯一读取的是 Chromium `Local State` 的 Profile 列表；该文件里的其他字段
//!   （含 `os_crypt` 加密密钥）只在本函数内解析、从不返回或落盘。
//! - 路径由环境变量解析出当前用户的实际位置，不硬编码用户名、UUID 或版本目录。
//! - WSL 只从注册表登记发行版名称，不访问 `\\wsl.localhost\…`：那会启动未运行的发行版，属于对用户环境的副作用；
//!   客体扫描与探测要在客体内运行采集器，本版不做，登记为覆盖缺口。
//! - 候选根经用户本地确认才进入授权登记（见 roots.rs），环境声明只由已授权的根生成。
//!
//! 本机没有 cargo/rustc，这个模块尚未编译。

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::roots::AuthorizedRoot;

pub const HOST_ENVIRONMENT_REF: &str = "windows-host";
pub const DISCOVERY_SOURCE: &str = "host-discovery-v1";
const LOCAL_STATE_LIMIT: u64 = 8 * 1024 * 1024;
/// Cookie 库里只有这些站点的记录进入扫描；其余站点的 Cookie 由本地核心在读取后丢弃。
pub const CLAUDE_SITE_HOSTS: [&str; 3] = ["claude.ai", "claude.com", "anthropic.com"];

/// 注册表只读视图：默认浏览器与 WSL 发行版。测试注入替身，产品用 Windows 实现。
pub trait RegistryView: Send + Sync {
    fn https_prog_id(&self) -> Option<String>;
    fn wsl_distributions(&self) -> Vec<String>;
}

/// 当前用户的实际位置；由环境变量解析，缺失时按 Windows 默认结构从用户名拼出。
#[derive(Clone, Debug)]
pub struct UserLocations {
    pub user_profile: PathBuf,
    pub app_data: PathBuf,
    pub local_app_data: PathBuf,
    pub documents: PathBuf,
    pub claude_config_dir: Option<PathBuf>,
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name).ok().filter(|value| !value.is_empty()).map(PathBuf::from)
}

impl UserLocations {
    pub fn for_current_user(windows_user: &str) -> UserLocations {
        let user_profile = env_path("USERPROFILE").unwrap_or_else(|| PathBuf::from(r"C:\Users").join(windows_user));
        let app_data = env_path("APPDATA").unwrap_or_else(|| user_profile.join("AppData").join("Roaming"));
        let local_app_data = env_path("LOCALAPPDATA").unwrap_or_else(|| user_profile.join("AppData").join("Local"));
        UserLocations {
            documents: user_profile.join("Documents"),
            claude_config_dir: env_path("CLAUDE_CONFIG_DIR"),
            user_profile,
            app_data,
            local_app_data,
        }
    }
}

pub struct Discovery {
    pub locations: UserLocations,
    pub registry: Box<dyn RegistryView>,
}

/// 一个候选根的静态说明：位置、归属客户端、类别、扫描前缀与已知格式。
struct Spec {
    root_ref: String,
    kind: &'static str,
    client_ref: &'static str,
    category: &'static str,
    label: String,
    path: PathBuf,
    scan_prefixes: Vec<&'static str>,
    object_kinds: Vec<(&'static str, &'static str)>,
    json_shapes: Vec<(&'static str, &'static str)>,
    profile: Option<Value>,
}

fn spec(root_ref: &str, kind: &'static str, client_ref: &'static str, category: &'static str, label: &str, path: PathBuf) -> Spec {
    Spec {
        root_ref: root_ref.to_string(),
        kind,
        client_ref,
        category,
        label: label.to_string(),
        path,
        scan_prefixes: Vec::new(),
        object_kinds: Vec::new(),
        json_shapes: Vec::new(),
        profile: None,
    }
}

/// 根引用：小写字母、数字与连字符。
pub fn slug(text: &str) -> String {
    let mut out = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() {
            out.push(character.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let trimmed = out.trim_end_matches('-');
    trimmed.chars().take(40).collect()
}

/// FD-01 §5.2 的位置类型。Claude Code 的配置目录优先取 CLAUDE_CONFIG_DIR。
fn fixed_specs(locations: &UserLocations) -> Vec<Spec> {
    let code_home = locations.claude_config_dir.clone().unwrap_or_else(|| locations.user_profile.join(".claude"));
    let mut code = spec("claude-code-home", "directory", "claude-code", "claude_code", "Claude Code 配置目录", code_home);
    code.json_shapes = vec![
        ("settings.json", "claude_code_settings"),
        ("settings.local.json", "claude_code_settings"),
        (".credentials.json", "claude_code_credentials"),
    ];
    let mut code_state = spec("claude-code-state", "file", "claude-code", "claude_code", "Claude Code 账号与项目状态", locations.user_profile.join(".claude.json"));
    code_state.json_shapes = vec![("", "claude_code_state")];
    let mut desktop_roaming = spec("claude-desktop-roaming", "directory", "claude-desktop", "claude_desktop", "Claude Desktop 用户数据", locations.app_data.join("Claude"));
    desktop_roaming.object_kinds = vec![("Network/Cookies", "cookie_sqlite"), ("Cookies", "cookie_sqlite")];
    desktop_roaming.json_shapes = vec![("config.json", "claude_desktop_config")];
    let mut cc_switch = spec("cc-switch", "directory", "cc-switch", "third_party", "CC Switch 配置", locations.user_profile.join(".cc-switch"));
    cc_switch.object_kinds = vec![("cc-switch.db", "cc_switch_sqlite")];
    vec![
        code,
        code_state,
        desktop_roaming,
        spec("claude-desktop-local", "directory", "claude-desktop", "claude_desktop", "Claude Desktop 本地数据", locations.local_app_data.join("Claude")),
        spec("claude-documents", "directory", "claude-desktop", "claude_desktop", "文档中的 Claude 目录", locations.documents.join("Claude")),
        spec("claude-3p-roaming", "directory", "claude-3p", "third_party", "Claude-3p（漫游）", locations.app_data.join("Claude-3p")),
        spec("claude-3p-local", "directory", "claude-3p", "third_party", "Claude-3p（本地）", locations.local_app_data.join("Claude-3p")),
        spec("claude-nest-3p", "directory", "claude-nest-3p", "third_party", "Claude Nest-3p", locations.local_app_data.join("Claude Nest-3p")),
        spec("claude-zh-backup", "directory", "claude-zh-backup", "old_backup", "Claude 中文版旧备份", locations.local_app_data.join("Claude-zh-CN-official-backup")),
        spec("reclaude-home", "directory", "reclaude", "third_party", "reclaude 用户目录", locations.user_profile.join(".reclaude")),
        spec("reclaude-local", "directory", "reclaude", "third_party", "reclaude 数据目录", locations.local_app_data.join("reclaude")),
        cc_switch,
    ]
}

/// Chromium 系浏览器的 User Data 目录。
fn chromium_browsers(locations: &UserLocations) -> Vec<(&'static str, &'static str, PathBuf)> {
    vec![
        ("chrome", "Google Chrome", locations.local_app_data.join("Google").join("Chrome").join("User Data")),
        ("edge", "Microsoft Edge", locations.local_app_data.join("Microsoft").join("Edge").join("User Data")),
        ("brave", "Brave", locations.local_app_data.join("BraveSoftware").join("Brave-Browser").join("User Data")),
    ]
}

/// 只取 Profile 目录名、显示名与最近使用的 Profile；Local State 的其余内容不离开这个函数。
fn chromium_profiles(user_data: &Path) -> (Vec<(String, String)>, Option<String>) {
    let local_state = user_data.join("Local State");
    let parsed = fs::metadata(&local_state)
        .ok()
        .filter(|meta| meta.len() <= LOCAL_STATE_LIMIT)
        .and_then(|_| fs::read_to_string(&local_state).ok())
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let mut profiles: Vec<(String, String)> = Vec::new();
    let mut last_used = None;
    if let Some(profile) = parsed.as_ref().and_then(|value| value.get("profile")) {
        if let Some(cache) = profile.get("info_cache").and_then(Value::as_object) {
            for (directory, info) in cache {
                if user_data.join(directory).is_dir() {
                    let name = info.get("name").and_then(Value::as_str).unwrap_or(directory.as_str()).to_string();
                    profiles.push((directory.clone(), name));
                }
            }
        }
        last_used = profile.get("last_used").and_then(Value::as_str).map(str::to_string);
    }
    if profiles.is_empty() {
        if let Ok(entries) = fs::read_dir(user_data) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if (name == "Default" || name.starts_with("Profile ")) && entry.path().is_dir() {
                    profiles.push((name.clone(), name));
                }
            }
        }
    }
    profiles.sort();
    (profiles, last_used)
}

fn browser_specs(locations: &UserLocations) -> Vec<Spec> {
    let mut specs = Vec::new();
    for (browser, label, user_data) in chromium_browsers(locations) {
        let (profiles, last_used) = chromium_profiles(&user_data);
        for (directory, name) in profiles {
            let mut item = spec(
                &format!("{browser}-{}", slug(&directory)),
                "directory",
                match browser {
                    "chrome" => "browser-chrome",
                    "edge" => "browser-edge",
                    _ => "browser-brave",
                },
                "browser_profile",
                &format!("{label} · {name}"),
                user_data.join(&directory),
            );
            // Claude 站点数据只看 Cookie 库；LevelDB 站点存储本版不支持，按缺口登记，不整目录遍历。
            // 新版在 Network/Cookies，旧版在 Cookies，只声明磁盘上实际存在的那个；都没有就按新版位置报缺。
            let existing: Vec<&'static str> = ["Network/Cookies", "Cookies"]
                .into_iter()
                .filter(|inner| item.path.join(inner).is_file())
                .collect();
            item.scan_prefixes = if existing.is_empty() { vec!["Network/Cookies"] } else { existing };
            item.object_kinds = vec![("Network/Cookies", "cookie_sqlite"), ("Cookies", "cookie_sqlite")];
            item.profile = Some(json!({
                "browser": browser,
                "profile_dir": directory,
                "profile_name": name,
                "last_used": last_used.as_deref() == Some(directory.as_str()),
            }));
            specs.push(item);
        }
    }
    specs
}

/// Firefox 只登记 Profile 目录，Cookie 库格式本版不支持，不能授权扫描。
fn firefox_profiles(locations: &UserLocations) -> Vec<Value> {
    let profiles = locations.app_data.join("Mozilla").join("Firefox").join("Profiles");
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir(&profiles) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                found.push(json!({
                    "root_ref": format!("firefox-{}", slug(&name)),
                    "kind": "directory",
                    "client_ref": "browser-firefox",
                    "category": "browser_profile",
                    "label": format!("Firefox · {name}"),
                    "path": entry.path().to_string_lossy(),
                    "environment_ref": HOST_ENVIRONMENT_REF,
                    "status": "found",
                    "authorizable": false,
                    "reason": "FIREFOX_FORMAT_UNSUPPORTED",
                }));
            }
        }
    }
    found
}

fn status_of(kind: &str, path: &Path) -> &'static str {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "not_found",
        Err(_) => "unreadable",
        Ok(meta) if meta.file_type().is_symlink() => "unsupported_link",
        Ok(meta) if kind == "file" && meta.is_file() => {
            if fs::File::open(path).is_ok() {
                "found"
            } else {
                "unreadable"
            }
        }
        Ok(meta) if kind == "directory" && meta.is_dir() => {
            if fs::read_dir(path).is_ok() {
                "found"
            } else {
                "unreadable"
            }
        }
        Ok(_) => "unreadable",
    }
}

fn candidate_value(item: &Spec) -> Value {
    let status = status_of(item.kind, &item.path);
    let authorizable = status == "found";
    let object_kinds: Vec<Value> = item.object_kinds.iter().map(|(path, kind)| json!({"path": path, "kind": kind})).collect();
    let json_shapes: Vec<Value> = item.json_shapes.iter().map(|(path, role)| json!({"path": path, "role": role})).collect();
    let profile = item.profile.clone().unwrap_or(Value::Null);
    json!({
        "root_ref": item.root_ref,
        "kind": item.kind,
        "client_ref": item.client_ref,
        "category": item.category,
        "label": item.label,
        "path": item.path.to_string_lossy(),
        "environment_ref": HOST_ENVIRONMENT_REF,
        "status": status,
        "authorizable": authorizable,
        "scan_prefixes": item.scan_prefixes,
        "object_kinds": object_kinds,
        "json_shapes": json_shapes,
        "profile": profile,
    })
}

/// https 默认处理程序的 ProgId 到浏览器的对应；认不出的原样报告。
pub fn browser_for_prog_id(prog_id: &str) -> &'static str {
    let lower = prog_id.to_ascii_lowercase();
    if lower.starts_with("chromehtml") {
        "chrome"
    } else if lower.starts_with("msedgehtm") {
        "edge"
    } else if lower.starts_with("bravehtml") {
        "brave"
    } else if lower.starts_with("firefoxurl") {
        "firefox"
    } else {
        "unknown"
    }
}

/// 完整发现结果：候选根、默认浏览器与环境清单。只读，不改任何东西。
pub fn discover(discovery: &Discovery) -> Value {
    let locations = &discovery.locations;
    let mut specs = fixed_specs(locations);
    specs.extend(browser_specs(locations));
    let mut candidates: Vec<Value> = specs.iter().map(candidate_value).collect();
    candidates.extend(firefox_profiles(locations));
    let default_browser = match discovery.registry.https_prog_id() {
        Some(prog_id) => {
            let browser = browser_for_prog_id(&prog_id);
            json!({"status": "DETECTED", "prog_id": prog_id, "browser": browser, "client_ref": format!("browser-{browser}"), "profile_ref": Value::Null})
        }
        None => json!({"status": "NOT_DETECTED", "prog_id": Value::Null, "browser": Value::Null, "client_ref": Value::Null, "profile_ref": Value::Null}),
    };
    let mut environments = vec![json!({"environment_ref": HOST_ENVIRONMENT_REF, "kind": "windows", "status": "DETECTED"})];
    for name in discovery.registry.wsl_distributions() {
        environments.push(json!({
            "environment_ref": format!("wsl-{}", slug(&name)),
            "kind": "wsl",
            "distribution": name,
            "status": "NOT_SCANNED",
            "reason": "WSL_NOT_SCANNED",
        }));
    }
    json!({
        "source": DISCOVERY_SOURCE,
        "environment_ref": HOST_ENVIRONMENT_REF,
        "candidates": candidates,
        "default_browser": default_browser,
        "environments": environments,
    })
}

fn scoped(root_ref: &str, inner: &str) -> String {
    if inner.is_empty() {
        format!("roots/{root_ref}")
    } else {
        format!("roots/{root_ref}/{inner}")
    }
}

/// 路径比较用的规范形：Windows 上统一分隔符、去掉结尾分隔符、不分大小写。
fn normalized_path(path: &str) -> String {
    if cfg!(windows) {
        path.replace('/', "\\").trim_end_matches('\\').to_lowercase()
    } else {
        path.trim_end_matches('/').to_string()
    }
}

/// 登记里的根与此刻发现的候选是不是同一个位置：规范化路径、根类型、客户端、类别与环境都一致才算。
fn authorization_matches(stored: &AuthorizedRoot, candidate: &Value) -> bool {
    let text = |name: &str| candidate.get(name).and_then(Value::as_str).unwrap_or_default().to_string();
    let current_path = text("path");
    !current_path.is_empty()
        && normalized_path(&stored.path.to_string_lossy()) == normalized_path(&current_path)
        && stored.kind.label() == text("kind")
        && stored.client_ref == text("client_ref")
        && stored.category == text("category")
        && stored.environment_ref == text("environment_ref")
}

/// 从发现结果与授权登记生成本地核心消费的环境声明。
/// 只有已授权、此刻仍然存在、且登记位置就是此刻发现位置的根进入扫描范围；发现了但没授权的根作为「未授权」客户端留在声明里，
/// 由核心记成覆盖缺口；授权过但现在找不到的根、或位置已经变了的根，分别报缺口。
pub fn environment_declaration(discovered: &Value, roots: &[AuthorizedRoot]) -> Value {
    let candidates = discovered.get("candidates").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut scopes: Vec<String> = Vec::new();
    let mut clients: Vec<Value> = Vec::new();
    let mut json_shapes: Vec<Value> = Vec::new();
    let mut object_kinds: Vec<Value> = Vec::new();
    let mut gaps: Vec<Value> = Vec::new();
    let mut stale_roots: Vec<String> = Vec::new();
    for candidate in &candidates {
        let root_ref = candidate.get("root_ref").and_then(Value::as_str).unwrap_or_default();
        let status = candidate.get("status").and_then(Value::as_str).unwrap_or_default();
        let authorizable = candidate.get("authorizable").and_then(Value::as_bool) == Some(true);
        let stored = roots.iter().find(|item| item.root_ref == root_ref);
        let registered = stored.is_some();
        if status != "found" {
            if registered {
                gaps.push(json!({"code": "AUTHORIZED_ROOT_MISSING", "message": format!("{root_ref}: authorized earlier but now {status}")}));
            }
            continue;
        }
        if !authorizable {
            gaps.push(json!({
                "code": candidate.get("reason").and_then(Value::as_str).unwrap_or("ROOT_NOT_SUPPORTED"),
                "message": format!("{root_ref}: discovered but its format is not supported"),
            }));
            continue;
        }
        // 同一个 root_ref 不等于同一个位置：登记时的路径、类型、客户端、类别与环境都要和此刻发现的一致，
        // 否则扫描会读登记里的旧位置、声明却指向新位置。对不上就标授权过期，要求重新确认。
        let authorized = stored.map(|item| authorization_matches(item, candidate)).unwrap_or(false);
        if registered && !authorized {
            stale_roots.push(root_ref.to_string());
            gaps.push(json!({
                "code": "AUTHORIZED_ROOT_STALE",
                "message": format!("{root_ref}: the location authorized earlier is not the one discovered now; authorize it again"),
            }));
        }
        let profile_ref = candidate.get("profile").and_then(|profile| profile.get("profile_dir")).cloned().unwrap_or(Value::Null);
        clients.push(json!({
            "client_ref": candidate.get("client_ref").cloned().unwrap_or(Value::Null),
            "environment_ref": HOST_ENVIRONMENT_REF,
            "installed": true,
            "authorized": authorized,
            "path_prefix": scoped(root_ref, ""),
            "profile_ref": profile_ref,
            "category": candidate.get("category").cloned().unwrap_or(Value::Null),
            "label": candidate.get("label").cloned().unwrap_or(Value::Null),
        }));
        if !authorized {
            continue;
        }
        let prefixes: Vec<String> = candidate
            .get("scan_prefixes")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        if prefixes.is_empty() {
            scopes.push(scoped(root_ref, ""));
        } else {
            scopes.extend(prefixes.iter().map(|inner| scoped(root_ref, inner)));
        }
        for item in candidate.get("object_kinds").and_then(Value::as_array).cloned().unwrap_or_default() {
            if let (Some(path), Some(kind)) = (item.get("path").and_then(Value::as_str), item.get("kind").and_then(Value::as_str)) {
                object_kinds.push(json!({"relative_path": scoped(root_ref, path), "kind": kind}));
            }
        }
        for item in candidate.get("json_shapes").and_then(Value::as_array).cloned().unwrap_or_default() {
            if let (Some(path), Some(role)) = (item.get("path").and_then(Value::as_str), item.get("role").and_then(Value::as_str)) {
                json_shapes.push(json!({"relative_path": scoped(root_ref, path), "role": role}));
            }
        }
        if candidate.get("category").and_then(Value::as_str) == Some("browser_profile") {
            gaps.push(json!({
                "code": "SITE_STORAGE_FORMAT_UNSUPPORTED",
                "message": format!("{root_ref}: LevelDB site storage (Local Storage / IndexedDB) is not read in this version"),
            }));
        }
    }
    for environment in discovered.get("environments").and_then(Value::as_array).cloned().unwrap_or_default() {
        if environment.get("status").and_then(Value::as_str) == Some("NOT_SCANNED") {
            gaps.push(json!({
                "code": "WSL_NOT_SCANNED",
                "message": format!("{}: WSL distribution is listed but not scanned", environment.get("environment_ref").and_then(Value::as_str).unwrap_or_default()),
            }));
        }
    }
    let status = if scopes.is_empty() { "NOT_AUTHORIZED" } else { "DETECTED" };
    let default_browser = discovered.get("default_browser").cloned().unwrap_or(Value::Null);
    json!({
        "status": status,
        "environment_ref": HOST_ENVIRONMENT_REF,
        "source_ref": DISCOVERY_SOURCE,
        "source_version": DISCOVERY_SOURCE,
        "scopes": scopes,
        "clients": clients,
        "default_browser": default_browser,
        "json_shapes": json_shapes,
        "object_kinds": object_kinds,
        "site_hosts": CLAUDE_SITE_HOSTS,
        "stale_roots": stale_roots,
        "gaps": gaps,
    })
}

#[cfg(windows)]
pub struct WindowsRegistry;

#[cfg(windows)]
mod registry_ffi {
    use std::ffi::c_void;

    pub type Hkey = *mut c_void;
    /// HKEY_CURRENT_USER：(HKEY)(ULONG_PTR)(LONG)0x80000001，按 LONG 符号扩展。
    pub const HKEY_CURRENT_USER: Hkey = -2147483647isize as Hkey;
    pub const KEY_READ: u32 = 0x0002_0019;
    pub const RRF_RT_REG_SZ: u32 = 0x0000_0002;
    pub const ERROR_NO_MORE_ITEMS: u32 = 259;

    #[link(name = "advapi32")]
    extern "system" {
        pub fn RegGetValueW(hkey: Hkey, sub_key: *const u16, value: *const u16, flags: u32, value_type: *mut u32, data: *mut c_void, data_len: *mut u32) -> u32;
        pub fn RegOpenKeyExW(hkey: Hkey, sub_key: *const u16, options: u32, sam: u32, result: *mut Hkey) -> u32;
        pub fn RegEnumKeyExW(
            hkey: Hkey,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            class: *mut u16,
            class_len: *mut u32,
            last_write: *mut c_void,
        ) -> u32;
        pub fn RegCloseKey(hkey: Hkey) -> u32;
    }
}

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 读 HKCU 下的一个 REG_SZ；任何一步失败都当作没有。
#[cfg(windows)]
fn read_user_string(sub_key: &str, value: &str) -> Option<String> {
    use registry_ffi::*;
    let sub = wide(sub_key);
    let name = wide(value);
    unsafe {
        let mut size: u32 = 0;
        let status = RegGetValueW(HKEY_CURRENT_USER, sub.as_ptr(), name.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), std::ptr::null_mut(), &mut size);
        if status != 0 || size < 2 || size > 64 * 1024 {
            return None;
        }
        let mut buffer = vec![0u16; (size as usize + 1) / 2];
        let mut used = size;
        let status = RegGetValueW(
            HKEY_CURRENT_USER,
            sub.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            &mut used,
        );
        if status != 0 {
            return None;
        }
        let length = buffer.iter().position(|unit| *unit == 0).unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..length])).filter(|text| !text.is_empty())
    }
}

#[cfg(windows)]
const HTTPS_USER_CHOICE: &str = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice";
#[cfg(windows)]
const LXSS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Lxss";

#[cfg(windows)]
impl RegistryView for WindowsRegistry {
    fn https_prog_id(&self) -> Option<String> {
        read_user_string(HTTPS_USER_CHOICE, "ProgId")
    }

    fn wsl_distributions(&self) -> Vec<String> {
        use registry_ffi::*;
        let mut names = Vec::new();
        let key_name = wide(LXSS_KEY);
        unsafe {
            let mut key: Hkey = std::ptr::null_mut();
            if RegOpenKeyExW(HKEY_CURRENT_USER, key_name.as_ptr(), 0, KEY_READ, &mut key) != 0 {
                return names;
            }
            let mut index = 0u32;
            loop {
                let mut buffer = [0u16; 256];
                let mut length = buffer.len() as u32;
                let status = RegEnumKeyExW(
                    key,
                    index,
                    buffer.as_mut_ptr(),
                    &mut length,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if status == ERROR_NO_MORE_ITEMS || status != 0 || index > 64 {
                    break;
                }
                let child = String::from_utf16_lossy(&buffer[..length as usize]);
                if let Some(name) = read_user_string(&format!(r"{LXSS_KEY}\{child}"), "DistributionName") {
                    names.push(name);
                }
                index += 1;
            }
            RegCloseKey(key);
        }
        names.sort();
        names.dedup();
        names
    }
}

/// 非 Windows 平台没有这些注册表项：如实为空。
pub struct NoRegistry;

impl RegistryView for NoRegistry {
    fn https_prog_id(&self) -> Option<String> {
        None
    }

    fn wsl_distributions(&self) -> Vec<String> {
        Vec::new()
    }
}

pub fn product_discovery(windows_user: &str) -> Discovery {
    #[cfg(windows)]
    let registry: Box<dyn RegistryView> = Box::new(WindowsRegistry);
    #[cfg(not(windows))]
    let registry: Box<dyn RegistryView> = Box::new(NoRegistry);
    Discovery { locations: UserLocations::for_current_user(windows_user), registry }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roots::RootKind;

    struct FakeRegistry;

    impl RegistryView for FakeRegistry {
        fn https_prog_id(&self) -> Option<String> {
            Some("ChromeHTML".to_string())
        }
        fn wsl_distributions(&self) -> Vec<String> {
            vec!["Ubuntu-22.04".to_string()]
        }
    }

    fn fixture(label: &str) -> (PathBuf, Discovery) {
        let base = std::env::temp_dir().join(format!("steward-discovery-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let profile = base.join("Users").join("tester");
        let locations = UserLocations {
            app_data: profile.join("AppData").join("Roaming"),
            local_app_data: profile.join("AppData").join("Local"),
            documents: profile.join("Documents"),
            claude_config_dir: None,
            user_profile: profile.clone(),
        };
        fs::create_dir_all(profile.join(".claude")).unwrap();
        fs::write(profile.join(".claude").join("settings.json"), "{}").unwrap();
        fs::write(profile.join(".claude.json"), "{}").unwrap();
        fs::create_dir_all(locations.app_data.join("Claude").join("Network")).unwrap();
        let user_data = locations.local_app_data.join("Google").join("Chrome").join("User Data");
        fs::create_dir_all(user_data.join("Default").join("Network")).unwrap();
        fs::create_dir_all(user_data.join("Profile 1")).unwrap();
        fs::write(
            user_data.join("Local State"),
            r#"{"os_crypt":{"encrypted_key":"RFBBUEkBAAAA-synthetic-secret"},"profile":{"last_used":"Profile 1","info_cache":{"Default":{"name":"Work"},"Profile 1":{"name":"Personal"},"Profile 9":{"name":"Gone"}}}}"#,
        )
        .unwrap();
        fs::create_dir_all(locations.app_data.join("Mozilla").join("Firefox").join("Profiles").join("abcd.default")).unwrap();
        (base, Discovery { locations, registry: Box::new(FakeRegistry) })
    }

    fn candidate<'a>(discovered: &'a Value, root_ref: &str) -> &'a Value {
        discovered["candidates"].as_array().unwrap().iter().find(|item| item["root_ref"] == root_ref).expect(root_ref)
    }

    #[test]
    fn discovery_lists_real_locations_without_leaking_browser_secrets() {
        let (base, discovery) = fixture("list");
        let discovered = discover(&discovery);
        assert_eq!(candidate(&discovered, "claude-code-home")["status"], "found");
        assert_eq!(candidate(&discovered, "claude-code-state")["kind"], "file");
        assert_eq!(candidate(&discovered, "claude-code-state")["status"], "found");
        assert_eq!(candidate(&discovered, "claude-desktop-roaming")["status"], "found");
        assert_eq!(candidate(&discovered, "cc-switch")["status"], "not_found", "未安装不是缺口，如实标没找到");
        assert_eq!(candidate(&discovered, "reclaude-home")["authorizable"], false);
        let chrome = candidate(&discovered, "chrome-default");
        assert_eq!(chrome["profile"]["profile_name"], "Work");
        assert_eq!(candidate(&discovered, "chrome-profile-1")["profile"]["last_used"], true);
        assert!(discovered["candidates"].as_array().unwrap().iter().all(|item| item["root_ref"] != "chrome-profile-9"), "Local State 里有、磁盘上没有的 Profile 不列");
        assert_eq!(candidate(&discovered, "firefox-abcd-default")["authorizable"], false);
        assert_eq!(discovered["default_browser"]["browser"], "chrome");
        assert_eq!(discovered["environments"][1]["environment_ref"], "wsl-ubuntu-22-04");
        assert_eq!(discovered["environments"][1]["status"], "NOT_SCANNED");
        let text = serde_json::to_string(&discovered).unwrap();
        assert!(!text.contains("encrypted_key") && !text.contains("synthetic-secret"), "Local State 的密钥不离开宿主");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn only_authorized_roots_become_scan_scope() {
        let (base, discovery) = fixture("declare");
        let discovered = discover(&discovery);
        let nothing = environment_declaration(&discovered, &[]);
        assert_eq!(nothing["status"], "NOT_AUTHORIZED");
        assert!(nothing["scopes"].as_array().unwrap().is_empty(), "没授权就没有扫描范围");
        assert!(nothing["clients"].as_array().unwrap().iter().all(|client| client["authorized"] == false));

        // 登记按授权当时发现的候选写入（与 commands.rs 的 authorize_roots 相同）。
        let registered = |reference: &str| {
            let item = candidate(&discovered, reference);
            let text = |name: &str| item[name].as_str().unwrap().to_string();
            AuthorizedRoot {
                root_ref: reference.to_string(),
                path: PathBuf::from(text("path")),
                kind: RootKind::parse(&text("kind")).unwrap(),
                client_ref: text("client_ref"),
                category: text("category"),
                environment_ref: text("environment_ref"),
                authorized_at: "2026-09-17T00:00:00.000Z".into(),
            }
        };
        let mut cc_switch = registered("claude-code-home");
        cc_switch.root_ref = "cc-switch".into();
        cc_switch.path = base.join("gone-cc-switch");
        let chosen = vec![registered("claude-code-home"), registered("chrome-default"), cc_switch];
        let declared = environment_declaration(&discovered, &chosen);
        let scopes: Vec<&str> = declared["scopes"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(scopes.contains(&"roots/claude-code-home"));
        assert!(scopes.contains(&"roots/chrome-default/Network/Cookies"), "浏览器只扫 Cookie 库");
        assert!(!scopes.iter().any(|scope| scope.starts_with("roots/chrome-profile-1")), "没授权的 Profile 不进范围");
        let shapes = declared["json_shapes"].as_array().unwrap();
        assert!(shapes.iter().any(|shape| shape["relative_path"] == "roots/claude-code-home/settings.json" && shape["role"] == "claude_code_settings"));
        assert!(shapes.iter().any(|shape| shape["relative_path"] == "roots/claude-code-home/.credentials.json" && shape["role"] == "claude_code_credentials"));
        assert_eq!(declared["site_hosts"], json!(["claude.ai", "claude.com", "anthropic.com"]));
        let kinds = declared["object_kinds"].as_array().unwrap();
        assert!(kinds.iter().any(|item| item["relative_path"] == "roots/chrome-default/Network/Cookies" && item["kind"] == "cookie_sqlite"));
        let gaps: Vec<&str> = declared["gaps"].as_array().unwrap().iter().filter_map(|gap| gap["code"].as_str()).collect();
        assert!(gaps.contains(&"AUTHORIZED_ROOT_MISSING"), "授权过的 cc-switch 现在找不到");
        assert!(gaps.contains(&"WSL_NOT_SCANNED"));
        assert!(gaps.contains(&"SITE_STORAGE_FORMAT_UNSUPPORTED"));
        assert!(gaps.contains(&"FIREFOX_FORMAT_UNSUPPORTED"));
        let clients = declared["clients"].as_array().unwrap();
        assert!(clients.iter().any(|client| client["path_prefix"] == "roots/chrome-profile-1" && client["authorized"] == false), "发现了没授权的 Profile 留作缺口");
        assert_eq!(declared["stale_roots"], json!([]));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_root_whose_location_changed_since_authorization_is_stale_not_authorized() {
        let (base, discovery) = fixture("stale");
        let discovered = discover(&discovery);
        let current = candidate(&discovered, "claude-code-home");
        let authorized_then = |path: PathBuf, kind: RootKind, category: &str| AuthorizedRoot {
            root_ref: "claude-code-home".into(),
            path,
            kind,
            client_ref: current["client_ref"].as_str().unwrap().into(),
            category: category.into(),
            environment_ref: HOST_ENVIRONMENT_REF.into(),
            authorized_at: "2026-09-17T00:00:00.000Z".into(),
        };
        let here = PathBuf::from(current["path"].as_str().unwrap());
        let same = environment_declaration(&discovered, &[authorized_then(here.clone(), RootKind::Directory, "claude_code")]);
        assert_eq!(same["scopes"], json!(["roots/claude-code-home"]), "位置没变仍是已授权");
        if cfg!(windows) {
            let shouted = PathBuf::from(format!("{}\\", here.to_string_lossy().to_uppercase()));
            let same_on_windows = environment_declaration(&discovered, &[authorized_then(shouted, RootKind::Directory, "claude_code")]);
            assert_eq!(same_on_windows["scopes"], json!(["roots/claude-code-home"]), "Windows 路径大小写与结尾分隔符不算变化");
        }

        for (label, stale) in [
            ("CLAUDE_CONFIG_DIR 换了位置", authorized_then(base.join("old-claude"), RootKind::Directory, "claude_code")),
            ("根类型变了", authorized_then(here.clone(), RootKind::File, "claude_code")),
            ("类别变了", authorized_then(here.clone(), RootKind::Directory, "third_party")),
        ] {
            let declared = environment_declaration(&discovered, &[stale]);
            assert!(declared["scopes"].as_array().unwrap().is_empty(), "{label}：不再给扫描范围");
            assert_eq!(declared["status"], "NOT_AUTHORIZED", "{label}");
            assert_eq!(declared["stale_roots"], json!(["claude-code-home"]), "{label}");
            let gaps: Vec<&str> = declared["gaps"].as_array().unwrap().iter().filter_map(|gap| gap["code"].as_str()).collect();
            assert!(gaps.contains(&"AUTHORIZED_ROOT_STALE"), "{label}");
            let client = declared["clients"].as_array().unwrap().iter().find(|item| item["path_prefix"] == "roots/claude-code-home").unwrap().clone();
            assert_eq!(client["authorized"], false, "{label}：不宣称已授权");
        }
        let _ = fs::remove_dir_all(&base);
    }
}
