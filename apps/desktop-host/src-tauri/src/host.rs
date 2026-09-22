use std::path::PathBuf;

use std::sync::Arc;

use crate::commands::{now_millis, parse_iso_millis, HostState};
use crate::control_process::{control_executable_name, ControlMode, ControlSupervisor};
use crate::confirm::{ConfirmationPrompt, UnavailablePrompt};
use crate::service_ipc::{ServiceClient, ServiceLink};
use serde_json::{json, Value};
use steward_service_ipc::{ServiceCommand, PRODUCT_APP_ID};

/// Windows 默认路径逐段用 join 拼出来，必要的字面量写成原始字符串。
/// 普通字符串里的 `\U`、`\P`、`\A` 是非法转义，会直接让 crate 编译不过。
fn local_app_data(windows_user: &str) -> PathBuf {
    match std::env::var("LOCALAPPDATA") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(r"C:\Users")
            .join(windows_user)
            .join("AppData")
            .join("Local"),
    }
}

fn program_files() -> PathBuf {
    match std::env::var("ProgramFiles") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(r"C:\Program Files"),
    }
}

/// 已授权的工作区根：产品安装后由宿主给出，所有受限文件与记录操作收窄在此目录内。
pub fn product_workspace_root(windows_user: &str) -> PathBuf {
    match std::env::var("STEWARD_WORKSPACE_ROOT") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => local_app_data(windows_user)
            .join(PRODUCT_APP_ID)
            .join("workspace"),
    }
}

/// 授权保险库：与受限工作区并列，不在它里面。
/// workspace::resolve 只放行 workspace_root 之内的路径，所以受限原生桥到不了这里。
pub fn product_vault_root(windows_user: &str) -> PathBuf {
    product_workspace_root(windows_user)
        .parent()
        .map(|parent| parent.join("vault"))
        .unwrap_or_else(|| PathBuf::from("vault"))
}

/// 控制端状态目录：与工作区、保险库并列，受限桥的文件操作到不了数据库。
pub fn product_control_state_root(windows_user: &str) -> PathBuf {
    product_workspace_root(windows_user)
        .parent()
        .map(|parent| parent.join("control"))
        .unwrap_or_else(|| PathBuf::from("control"))
}

/// 产品网络状态根：与工作区、保险库并列，受限桥的文件操作到不了；安装器把同一路径批准给服务读取草稿。
pub fn product_network_root(windows_user: &str) -> PathBuf {
    product_workspace_root(windows_user)
        .parent()
        .map(|parent| parent.join("network"))
        .unwrap_or_else(|| PathBuf::from("network"))
}

/// 宿主自己的本地日志目录：控制端没起来、甚至界面没起来时的失败也记在这里。
pub fn product_log_root(windows_user: &str) -> PathBuf {
    product_workspace_root(windows_user)
        .parent()
        .map(|parent| parent.join("logs"))
        .unwrap_or_else(|| PathBuf::from("logs"))
}

/// 已有明确配置的外部控制端（STEWARD_CONTROL_BASE_URL）就只连接它；
/// 否则用本产品资源目录里的控制端程序。两者都没有就如实回报未配置，不合成地址。
pub fn control_mode(resource_dir: Option<PathBuf>, windows_user: &str) -> ControlMode {
    if let Ok(base_url) = std::env::var("STEWARD_CONTROL_BASE_URL") {
        if !base_url.is_empty() {
            return ControlMode::External { base_url, log_dir: product_log_root(windows_user) };
        }
    }
    match resource_dir {
        Some(resources) => ControlMode::Managed {
            executable: resources.join("control").join(control_executable_name()),
            state_dir: product_control_state_root(windows_user),
            log_dir: product_log_root(windows_user),
        },
        None => ControlMode::Unavailable {
            code: "CONTROL_NOT_CONFIGURED".to_string(),
            reason: "宿主没有产品资源目录，也没有配置外部控制端，无法定位控制端".to_string(),
        },
    }
}

/// 已知的可区分第二浏览器；只枚举安装位置，不读 Profile、不启动。
pub fn emergency_candidates(windows_user: &str) -> Vec<Value> {
    let local = local_app_data(windows_user);
    let files = program_files();
    let known: [(&str, &str, &str, PathBuf); 3] = [
        (
            "browser-firefox",
            "second_browser",
            "firefox.exe",
            files.join("Mozilla Firefox").join("firefox.exe"),
        ),
        (
            "browser-edge",
            "second_browser",
            "msedge.exe",
            files.join("Microsoft").join("Edge").join("Application").join("msedge.exe"),
        ),
        (
            "webview-shared",
            "shared_webview",
            "msedgewebview2.exe",
            local
                .join("Microsoft")
                .join("EdgeWebView")
                .join("Application")
                .join("msedgewebview2.exe"),
        ),
    ];
    known
        .iter()
        .map(|(id, kind, process, path)| {
            let installed = path.exists();
            let distinguishable = *kind == "second_browser";
            serde_json::json!({
                "id": id,
                "kind": kind,
                "process": process,
                "path": path.to_string_lossy(),
                "installed": installed,
                "distinguishable": distinguishable,
                "approved": installed && distinguishable
            })
        })
        .collect()
}

fn field<'a>(payload: &'a Value, name: &str) -> Result<&'a str, String> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("NATIVE_PAYLOAD_INVALID: {name} is required"))
}

fn grant_expiry(grant: Option<&Value>) -> Option<i64> {
    grant.and_then(|record| record.get("expires_at")).and_then(Value::as_str).and_then(parse_iso_millis)
}

fn reply_json(outcome: Result<steward_service_ipc::ServiceReply, steward_service_ipc::ServiceError>) -> Value {
    match outcome {
        Ok(reply) => json!({"ok": reply.ok, "code": reply.code, "reason": reply.reason, "receipt": reply.receipt}),
        Err(error) => json!({"ok": false, "code": error.code, "reason": error.reason, "receipt": {"side_effects": false}}),
    }
}

/// 手动应急：先由服务核对已生效配置里有这个浏览器的应急路径、Claude 仍受固定 A/阻断约束且保护有效，
/// 路径准备好后才启动第二浏览器，再把 PID 交给服务读出进程身份；三步都成立才回 ACTIVE。只 spawn 成功不算应急已成立。
/// 到期与关闭都由服务按这份身份执行，不依赖宿主内存或页面存活。
pub fn emergency_open(state: &HostState, payload: &Value, grant: Option<&Value>) -> Result<Value, String> {
    let session_id = field(payload, "session_id")?;
    let host_id = field(payload, "host_id")?;
    let expires_at = field(payload, "expires_at")?;
    let environment_ref = field(payload, "environment_ref")?;
    if environment_ref != state.environment_ref {
        return Err(format!(
            "NATIVE_AUTHORIZATION_TARGET_MISMATCH: this install runs {} but the payload targets {environment_ref}",
            state.environment_ref
        ));
    }
    let expires_at_ms = parse_iso_millis(expires_at).ok_or("NATIVE_PAYLOAD_INVALID: expires_at is not an instant")?;
    let candidate = emergency_candidates(&state.windows_user)
        .into_iter()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(host_id))
        .ok_or("EMERGENCY_HOST_UNAVAILABLE: host is not a known candidate")?;
    if candidate.get("approved").and_then(Value::as_bool) != Some(true) {
        return Err("EMERGENCY_HOST_DENIED: only an installed, distinguishable second browser may be opened".into());
    }
    let process = candidate.get("process").and_then(Value::as_str).unwrap_or_default().to_string();
    let route = reply_json(state.network.write(
        ServiceCommand::OpenEmergencyRoute,
        session_id,
        json!({"environment_ref": environment_ref, "session_ref": session_id, "browser_process": process, "expires_at_ms": expires_at_ms}),
        now_millis(),
        grant_expiry(grant),
    ));
    if route["ok"] != json!(true) {
        return Ok(json!({"ok": false, "status": "ROUTE_NOT_READY", "code": route["code"], "route": route["receipt"]}));
    }
    let executable = candidate.get("path").and_then(Value::as_str).unwrap_or_default().to_string();
    let mut child = match std::process::Command::new(&executable).spawn() {
        Ok(child) => child,
        Err(error) => {
            let closed = reply_json(state.network.write(
                ServiceCommand::CloseEmergencyRoute,
                &format!("{session_id}:spawn-failed"),
                json!({"environment_ref": environment_ref, "session_ref": session_id}),
                now_millis(),
                grant_expiry(grant),
            ));
            return Ok(json!({
                "ok": false,
                "status": "FAILED",
                "code": "EMERGENCY_OPEN_FAILED",
                "reason": error.to_string(),
                "route": route["receipt"],
                "route_closed": closed["receipt"]
            }));
        }
    };
    let bound = reply_json(state.network.write(
        ServiceCommand::OpenEmergencyRoute,
        &format!("{session_id}:bind"),
        json!({"environment_ref": environment_ref, "session_ref": session_id, "phase": "bind_browser", "browser_pid": child.id()}),
        now_millis(),
        grant_expiry(grant),
    ));
    if bound["ok"] != json!(true) {
        // 刚启动的子进程由本宿主持有句柄，按句柄结束不会误伤复用的 PID。
        let _ = child.kill();
        let _ = child.wait();
        let closed = reply_json(state.network.write(
            ServiceCommand::CloseEmergencyRoute,
            &format!("{session_id}:bind-failed"),
            json!({"environment_ref": environment_ref, "session_ref": session_id}),
            now_millis(),
            grant_expiry(grant),
        ));
        return Ok(json!({
            "ok": false,
            "status": "FAILED",
            "code": bound["code"],
            "route": route["receipt"],
            "browser_bind": bound["receipt"],
            "route_closed": closed["receipt"]
        }));
    }
    let record = json!({
        "session_id": session_id,
        "host_id": host_id,
        "process": process,
        "pid": child.id(),
        "browser_bound": true,
        "expires_at": expires_at,
        "environment_ref": environment_ref,
        "open": true,
        "status": "ACTIVE",
        "route_ready": route["receipt"]["route_ready"],
        "claude_constrained": route["receipt"]["claude_constrained"],
        "emergency_scope": route["receipt"]["emergency_scope"],
        "expiry_enforced_by": route["receipt"]["expiry_enforced_by"]
    });
    state
        .emergency
        .lock()
        .map_err(|_| "EMERGENCY_STATE_POISONED".to_string())?
        .insert(session_id.to_string(), record.clone());
    Ok(json!({"ok": true, "status": "ACTIVE", "session": record, "route": route["receipt"]}))
}

/// 关闭应急：会话、浏览器身份与规则都在服务里，宿主重启后照样能关；宿主不按 PID 结束任何进程。
pub fn emergency_close(state: &HostState, payload: &Value, grant: Option<&Value>) -> Result<Value, String> {
    let session_id = field(payload, "session_id")?;
    let environment_ref = field(payload, "environment_ref")?;
    let route = reply_json(state.network.write(
        ServiceCommand::CloseEmergencyRoute,
        session_id,
        json!({"environment_ref": environment_ref, "session_ref": session_id}),
        now_millis(),
        grant_expiry(grant),
    ));
    let receipt = route["receipt"].clone();
    let closed_safely = route["ok"] == json!(true) && receipt["closed_safely"] == json!(true);
    let closed = json!({
        "session_id": session_id,
        "open": receipt["closed"] != json!(true),
        "process_stopped": receipt["browser_stopped"] == json!(true),
        "browser_termination": receipt["browser_termination"],
        "route_closed": receipt["closed"] == json!(true),
        "route_rules_present": receipt["route_rules_present"],
        "closed_safely": closed_safely
    });
    state
        .emergency
        .lock()
        .map_err(|_| "EMERGENCY_STATE_POISONED".to_string())?
        .insert(session_id.to_string(), closed.clone());
    let code = if closed_safely { Value::Null } else { route["code"].clone() };
    Ok(json!({"ok": closed_safely, "session": closed, "route": receipt, "code": code}))
}

pub fn create_host_state(windows_user: String, network: ServiceLink) -> HostState {
    let control = ControlSupervisor::new(control_mode(None, &windows_user));
    create_host_state_with_prompt(windows_user, network, Box::new(UnavailablePrompt), control)
}

pub fn create_host_state_with_prompt(
    windows_user: String,
    network: ServiceLink,
    confirm: Box<dyn ConfirmationPrompt>,
    control: Arc<ControlSupervisor>,
) -> HostState {
    let workspace_root = product_workspace_root(&windows_user);
    let vault_root = product_vault_root(&windows_user);
    let network_root = product_network_root(&windows_user);
    // 首启环境信息来自当前用户的真实发现，不读安装后放进工作区的声明文件。
    let discovery = crate::discovery::product_discovery(&windows_user);
    let log_root = product_log_root(&windows_user);
    let logs = crate::logs::LogDirs {
        host: log_root.clone(),
        control: product_control_state_root(&windows_user).join("logs"),
        service: crate::logs::service_log_dir(),
    };
    HostState {
        windows_user,
        network,
        network_root,
        factory: "product",
        workspace_root,
        control,
        environment_ref: crate::discovery::HOST_ENVIRONMENT_REF.to_string(),
        discovery,
        vault_root,
        vault_lock: std::sync::Mutex::new(()),
        confirm,
        browser_diag: crate::browser_diag::BrowserDiag::new(Box::new(crate::browser_diag::SystemBrowser)),
        emergency: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        logs,
        app_log: crate::logs::AppLog::new(log_root),
        folders: Box::new(crate::logs::SystemFolderOpener),
        notices: Box::new(crate::lifecycle::UnavailableNotices),
    }
}

pub fn create_product_host_state(windows_user: String) -> HostState {
    create_host_state(windows_user, ServiceLink::product())
}

/// 产品装配：确认窗口要挂在真实的应用句柄上，只有拿到 AppHandle 之后才能装。
/// 控制端程序从本产品资源目录定位；启动由调用方在 manage 之后触发。
#[cfg(feature = "tauri")]
pub fn create_product_host_state_with_app(
    windows_user: String,
    app: tauri::AppHandle,
    resource_dir: Option<PathBuf>,
) -> HostState {
    let control = ControlSupervisor::new(control_mode(resource_dir, &windows_user));
    let mut state = create_host_state_with_prompt(
        windows_user,
        ServiceLink::product(),
        Box::new(crate::confirm::NativeDialogPrompt { app: app.clone() }),
        control,
    );
    state.notices = Box::new(crate::lifecycle::TauriNotices { app });
    state
}

/// 注入装配：只给宿主自身测试用。服务客户端、链接密钥与工作区/保险库/网络根都由测试给出，产品装配不会走到这里。
pub fn create_injected_host_state(
    windows_user: String,
    root: PathBuf,
    service: impl ServiceClient + 'static,
    link_key: Vec<u8>,
) -> HostState {
    let mut state = create_host_state_with_prompt(
        windows_user,
        ServiceLink::new(Box::new(service), Ok(link_key)),
        Box::new(crate::confirm::InjectedPrompt { decide: |_prompt: &Value| Ok(true) }),
        ControlSupervisor::new(ControlMode::Unavailable {
            code: "CONTROL_NOT_CONFIGURED".to_string(),
            reason: "注入宿主不托管控制端".to_string(),
        }),
    );
    state.workspace_root = root.join("workspace");
    state.vault_root = root.join("vault");
    state.network_root = root.join("network");
    state.browser_diag = crate::browser_diag::BrowserDiag::new(Box::new(crate::browser_diag::NoBrowser));
    state.logs = crate::logs::LogDirs {
        host: root.join("logs"),
        control: root.join("control").join("logs"),
        service: root.join("service").join("logs"),
    };
    state.app_log = crate::logs::AppLog::new(root.join("logs"));
    state.folders = Box::new(crate::logs::RecordingOpener::default());
    // 注入宿主只看测试根下的合成用户目录，也不读注册表，测试不会碰到跑测试那台机器的真实数据。
    let home = root.join("home");
    state.discovery = crate::discovery::Discovery {
        locations: crate::discovery::UserLocations {
            app_data: home.join("AppData").join("Roaming"),
            local_app_data: home.join("AppData").join("Local"),
            documents: home.join("Documents"),
            claude_config_dir: None,
            user_profile: home,
        },
        registry: Box::new(crate::discovery::NoRegistry),
    };
    state
}
