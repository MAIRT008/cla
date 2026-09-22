pub mod browser_diag;
pub mod commands;
pub mod confirm;
pub mod control_process;
pub mod discovery;
pub mod host;
pub mod lifecycle;
pub mod logs;
pub mod network_runtime;
pub mod roots;
pub mod service_ipc;
pub mod workspace;

pub use commands::{dispatch, dispatch_logged, user_confirm, HostState};
pub use confirm::{ConfirmationPrompt, InjectedPrompt, UnavailablePrompt};
pub use host::{create_injected_host_state, create_product_host_state, product_network_root, product_vault_root};
pub use service_ipc::{assert_product_pipe, product_identity, ServiceClient, ServiceLink, PRODUCT_PIPE};

/// 与 apps/desktop-host/bridge-contract.mjs 一一对应；改这里必须同步改契约。
pub fn registered_ops() -> &'static [&'static str] {
    &[
        "DescribeCapabilities",
        "ReadNetworkState",
        "ApplyNetworkPlan",
        "ProtectEnvironment",
        "NetworkLifecycle",
        "FileRead",
        "FileWrite",
        "FileRemove",
        "FileCopy",
        "FileExists",
        "FileWalk",
        "DirIsolate",
        "DirPreviewRestore",
        "DirRestore",
        "RecordsLoad",
        "RecordSave",
        "BackupSave",
        "DbInspect",
        "DbMutate",
        "DbSimulate",
        "DbFingerprint",
        "DbSnapshot",
        "DbPreviewRestore",
        "DbRestore",
        "EmergencyHosts",
        "EmergencyOpen",
        "EmergencyClose",
        "ControlStatus",
        "ControlSetupAdmin",
        "SessionLoad",
        "SessionSave",
        "SessionClear",
        "DiscoverEnvironment",
        "AuthorizeRoots",
        "RevokeRoots",
        "BrowserDiagListen",
        "BrowserDiagLaunch",
        "BrowserDiagReceive",
        "BrowserDiagClose",
        "LogSources",
        "LogRead",
        "AppLogAppend",
        "LogExportWrite",
        "LogOpenFolder",
        "NotifyCritical",
    ]
}

/// 控制端在 setup 里由后台线程启动，不阻塞窗口；只有应用真正退出（RunEvent::Exit）才停止它。
/// 关窗、托盘与界面退出都不经过产品网络服务：服务、内核与保护不受 GUI 进程退出影响，
/// 宿主也不会在任何窗口或退出事件里发送 StopCoreForMaintenance。
#[cfg(feature = "tauri")]
pub fn run() {
    use tauri::Manager;
    let app = tauri::Builder::default()
        // 单实例必须第一个注册：第二次启动在 setup 之前就退出，不会再起一套控制端、监测调度或宿主，只把既有窗口带到前面。
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| lifecycle::show_main_window(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![commands::steward_request, commands::steward_user_confirm])
        .on_window_event(|window, event| {
            // 关窗只隐藏到托盘：监测、托管控制端与已启用的定时任务继续；第一次时用系统通知提示一次。
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                let state = window.state::<HostState>();
                let marker = lifecycle::background_marker(&state.workspace_root);
                if let Err(error) = lifecycle::announce_background(state.notices.as_ref(), &marker) {
                    logs::record_outcome(&state.app_log, "BackgroundNotice", &Err(error));
                }
            }
        })
        .setup(|app| {
            let windows_user = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into());
            let resource_dir = app.path().resource_dir().ok();
            let state = host::create_product_host_state_with_app(windows_user, app.handle().clone(), resource_dir);
            let control = state.control.clone();
            app.manage(state);
            control.start();
            lifecycle::build_tray(app.handle())?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("desktop host failed to start");
    app.run(|handle, event| match event {
        // 窗口都已隐藏时由系统或最后一个窗口触发的退出请求不退；只有托盘「退出界面」的 app.exit(0) 带退出码。
        tauri::RunEvent::ExitRequested { api, code, .. } if code.is_none() => api.prevent_exit(),
        // 退出界面只停本宿主托管的控制端；产品网络服务、内核与保护不受影响。
        tauri::RunEvent::Exit => handle.state::<HostState>().control.stop(),
        _ => {}
    });
}

#[cfg(not(feature = "tauri"))]
pub fn run() {
    let _state = create_product_host_state(std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into()));
}

#[cfg(test)]
mod host_factory_tests {
    use super::*;
    use serde_json::{json, Value};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use steward_service_ipc::core::auth::verify_envelope;
    use steward_service_ipc::{ServiceCommand, ServiceError, ServiceReply, ServiceRequest, PRODUCT_APP_ID, PROTOCOL};

    const KEY: &[u8] = b"synthetic-host-link-key-0123456789abcdef";
    const ENV: &str = "windows-host";
    const CLAUDE: &str = r"C:\Program Files\Claude\claude.exe";
    const YAML: &str = r#"mode: rule
rules:
  - MATCH,REJECT
"#;

    #[derive(Clone, Default)]
    struct RecordingService {
        calls: Arc<Mutex<Vec<(ServiceCommand, ServiceRequest)>>>,
        protection_effective: Arc<Mutex<bool>>,
    }

    impl ServiceClient for RecordingService {
        fn call(&self, command: ServiceCommand, request: &ServiceRequest) -> Result<ServiceReply, ServiceError> {
            self.calls.lock().unwrap().push((command, request.clone()));
            assert_eq!(request.product_id, PRODUCT_APP_ID);
            assert_eq!(request.protocol, PROTOCOL);
            if command.requires_envelope() {
                let envelope = request.envelope.as_ref().expect("改写命令必须带 envelope");
                verify_envelope(KEY, envelope, command, &request.payload)?;
            } else {
                assert!(request.envelope.is_none(), "读取不带授权");
            }
            let receipt = match command {
                ServiceCommand::Handshake => json!({"product_id": PRODUCT_APP_ID, "protocol": PROTOCOL, "service_instance_id": "svc-synthetic"}),
                ServiceCommand::ObserveRuntime => json!({"service": {"status": "RUNNING"}, "readback": {"status": "VERIFIED"}, "missing": []}),
                ServiceCommand::ValidateConfig => json!({"stages": {"downloaded": {"status": "OK"}, "validated": {"status": "OK"}}}),
                ServiceCommand::ApplyConfig => json!({"overall": "VERIFIED", "stages": {"applied": {"status": "ACCEPTED", "http_status": 204}, "verified": {"status": "VERIFIED"}}}),
                ServiceCommand::EnsureProtection => {
                    let effective = *self.protection_effective.lock().unwrap();
                    if !effective {
                        return Ok(ServiceReply::failure(
                            &ServiceError::new("PROTECTION_NOT_EFFECTIVE", "synthetic"),
                            json!({"effective": false, "new_connections_restricted": false, "side_effects": true}),
                        ));
                    }
                    json!({"effective": true, "new_connections_restricted": true, "side_effects": true})
                }
                ServiceCommand::CloseManagedConnections => json!({"closed_existing": true, "new_connections_restricted": true}),
                ServiceCommand::CloseEmergencyRoute => json!({
                    "closed": true,
                    "closed_safely": true,
                    "browser_stopped": true,
                    "browser_termination": "TERMINATED",
                    "route_rules_present": false,
                    "side_effects": true
                }),
                _ => json!({"side_effects": true}),
            };
            Ok(ServiceReply::success(receipt))
        }
    }

    fn root(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("steward-host-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sha(text: &str) -> String {
        steward_service_ipc::sha256_hex(text.as_bytes())
    }

    fn apply_payload(yaml: &str) -> Value {
        json!({
            "operation_id": "apply-1",
            "environment_ref": ENV,
            "plan_ref": "plan-1",
            "plan_version": "plan:v3:daily_single_ip:abc",
            "assignment_version": "v3",
            "expected_config_sha256": sha(yaml),
            "yaml": yaml,
        })
    }

    #[test]
    fn network_ops_are_signed_service_commands_not_direct_controller_or_wfp_calls() {
        let service = RecordingService::default();
        *service.protection_effective.lock().unwrap() = true;
        let state = create_injected_host_state("synthetic-user".into(), root("ops"), service.clone(), KEY.to_vec());
        assert_eq!(state.environment_ref, ENV);
        let issued = user_confirm(&state, &json!({"scope": "preauthorized_protection", "environment_ref": ENV})).unwrap();
        let reference = issued["authorization_ref"].as_str().unwrap().to_string();

        let applied = dispatch(&state, "ApplyNetworkPlan", &apply_payload(YAML), Some(&reference)).unwrap();
        assert_eq!(applied["ok"], true);
        assert_eq!(applied["receipt"]["overall"], "VERIFIED");
        let calls = service.calls.lock().unwrap().clone();
        let commands: Vec<ServiceCommand> = calls.iter().map(|(command, _)| *command).collect();
        assert_eq!(commands, vec![ServiceCommand::ValidateConfig, ServiceCommand::ApplyConfig]);
        let draft = PathBuf::from(calls[1].1.payload["draft_path"].as_str().unwrap());
        assert!(draft.starts_with(root("ops").join("network").join("drafts")), "草稿只写在产品网络状态根下");
        assert!(calls[1].1.payload.get("yaml").is_none(), "完整 YAML 不进 IPC 载荷");
        assert!(calls[1].1.envelope.as_ref().unwrap().mac.len() == 64);

        let mut tampered = apply_payload(YAML);
        tampered["expected_config_sha256"] = json!(sha("mode: global\n"));
        assert_eq!(dispatch(&state, "ApplyNetworkPlan", &tampered, Some(&reference)).unwrap()["code"], "CONFIG_DIGEST_MISMATCH");
        let forbidden = format!("external-controller: 0.0.0.0:{}\n{YAML}", 9797);
        assert_eq!(dispatch(&state, "ApplyNetworkPlan", &apply_payload(&forbidden), Some(&reference)).unwrap()["code"], "CONFIG_FIELD_FORBIDDEN");
        let mut other_env = apply_payload(YAML);
        other_env["environment_ref"] = json!("wsl-guest");
        assert!(dispatch(&state, "ApplyNetworkPlan", &other_env, Some(&reference)).unwrap_err().starts_with("NATIVE_AUTHORIZATION_TARGET_MISMATCH"));
        assert_eq!(service.calls.lock().unwrap().len(), 2, "被宿主拒绝的请求不到服务");

        let protected = dispatch(
            &state,
            "ProtectEnvironment",
            &json!({"operation_id": "protect-1", "environment_ref": ENV, "action": "block_new", "processes": [CLAUDE], "reason_code": "WRONG_ROUTE"}),
            Some(&reference),
        )
        .unwrap();
        assert_eq!(protected["ok"], true);
        assert_eq!(protected["protection"]["new_connections_restricted"], true);
        assert_eq!(protected["close_existing"]["receipt"]["closed_existing"], true, "关闭既有连接是单独一份回执");

        let read = dispatch(&state, "ReadNetworkState", &json!({"environment_ref": ENV, "include": ["config", "anything"]}), None).unwrap();
        assert_eq!(read["runtime"]["readback"]["status"], "VERIFIED");
        let observe = service.calls.lock().unwrap().iter().rev().find(|(command, _)| *command == ServiceCommand::ObserveRuntime).cloned().unwrap();
        assert_eq!(observe.1.payload["include"], json!(["config"]), "页面不能扩大读取范围");

        assert!(dispatch(&state, "ApplyNetworkPlan", &apply_payload(YAML), None).unwrap_err().starts_with("NATIVE_AUTHORIZATION_REQUIRED"));
        assert!(dispatch(&state, "FileWrite", &json!({"path": "records/x.json", "bytes": ""}), Some(&reference))
            .unwrap_err()
            .starts_with("NATIVE_AUTHORIZATION_SCOPE_INVALID"));
    }

    #[test]
    fn protection_that_is_not_effective_is_not_reported_ok_and_does_not_close_connections() {
        let service = RecordingService::default();
        let state = create_injected_host_state("synthetic-user".into(), root("weak"), service.clone(), KEY.to_vec());
        let issued = user_confirm(&state, &json!({"scope": "preauthorized_protection", "environment_ref": ENV})).unwrap();
        let reference = issued["authorization_ref"].as_str().unwrap().to_string();
        let result = dispatch(
            &state,
            "ProtectEnvironment",
            &json!({"operation_id": "protect-2", "environment_ref": ENV, "action": "block_new", "processes": [CLAUDE], "reason_code": "WRONG_ROUTE"}),
            Some(&reference),
        )
        .unwrap();
        assert_eq!(result["ok"], false, "外层 ok 反映真实保护结果");
        assert_eq!(result["protection"]["new_connections_restricted"], false);
        assert_eq!(result["close_existing"]["status"], "SKIPPED");
        assert!(!service.calls.lock().unwrap().iter().any(|(command, _)| *command == ServiceCommand::CloseManagedConnections));
    }

    #[test]
    fn stop_management_needs_its_own_single_use_confirmation() {
        let service = RecordingService::default();
        let state = create_injected_host_state("synthetic-user".into(), root("stop"), service.clone(), KEY.to_vec());
        let preauthorized = user_confirm(&state, &json!({"scope": "preauthorized_protection", "environment_ref": ENV})).unwrap();
        let stop = json!({"operation_id": "stop-1", "environment_ref": ENV, "event": "stop_management", "processes": [CLAUDE]});
        let denied = dispatch(&state, "NetworkLifecycle", &stop, preauthorized["authorization_ref"].as_str()).unwrap_err();
        assert!(denied.starts_with("NATIVE_AUTHORIZATION_SCOPE_INVALID"), "{denied}");

        let confirmed = user_confirm(&state, &json!({"scope": "stop_management", "environment_ref": ENV, "native_op": "NetworkLifecycle"})).unwrap();
        let reference = confirmed["authorization_ref"].as_str().unwrap().to_string();
        let released = dispatch(&state, "NetworkLifecycle", &stop, Some(&reference)).unwrap();
        assert_eq!(released["command"], "EnsureProtection");
        let sent = service.calls.lock().unwrap().last().cloned().unwrap();
        assert_eq!(sent.1.payload["action"], "release_owned");
        assert!(dispatch(&state, "NetworkLifecycle", &stop, Some(&reference)).unwrap_err().starts_with("NATIVE_AUTHORIZATION_CONSUMED"));

        let restore = json!({"operation_id": "restore-1", "environment_ref": ENV, "event": "restore_last_valid", "reason_code": "WAKE"});
        let restored = dispatch(&state, "NetworkLifecycle", &restore, preauthorized["authorization_ref"].as_str()).unwrap();
        assert_eq!(restored["command"], "RestoreLastValid");
    }

    #[test]
    fn emergency_close_after_a_host_restart_goes_to_the_service_instead_of_killing_a_remembered_pid() {
        let service = RecordingService::default();
        let state = create_injected_host_state("synthetic-user".into(), root("emergency-close"), service.clone(), KEY.to_vec());
        assert!(state.emergency.lock().unwrap().is_empty(), "新宿主进程里没有应急会话记忆");
        let confirmed = user_confirm(&state, &json!({"scope": "emergency_session", "session_ref": "em-1", "native_op": "EmergencyClose"})).unwrap();
        let closed = dispatch(&state, "EmergencyClose", &json!({"session_id": "em-1", "environment_ref": ENV}), confirmed["authorization_ref"].as_str()).unwrap();
        assert_eq!(closed["ok"], true, "{closed}");
        assert_eq!(closed["session"]["process_stopped"], true, "浏览器由服务按核验过的身份结束");
        let sent = service.calls.lock().unwrap().last().cloned().unwrap();
        assert_eq!(sent.0, ServiceCommand::CloseEmergencyRoute);
        assert_eq!(sent.1.payload["session_ref"], "em-1");
    }

    #[test]
    fn real_roots_open_only_after_a_local_authorization_and_never_to_workspace_owned_writes() {
        let base = root("roots");
        let settings = base.join("home").join(".claude").join("settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, "{\"env\":{}}").unwrap();
        let state = create_injected_host_state("synthetic-user".into(), base.clone(), RecordingService::default(), KEY.to_vec());
        let read = json!({"path": "roots/claude-code-home/settings.json"});
        assert!(dispatch(&state, "FileRead", &read, None).unwrap_err().starts_with("NATIVE_PATH_OUT_OF_SCOPE"), "没授权读不到");
        assert_eq!(dispatch(&state, "DiscoverEnvironment", &json!({}), None).unwrap()["environment"]["status"], "NOT_AUTHORIZED");

        let authorized = dispatch(&state, "AuthorizeRoots", &json!({"root_refs": ["claude-code-home"]}), None).unwrap();
        assert_eq!(authorized["authorized_roots"][0]["root_ref"], "claude-code-home");
        let view = dispatch(&state, "DiscoverEnvironment", &json!({}), None).unwrap();
        assert_eq!(view["environment"]["scopes"], json!(["roots/claude-code-home"]));
        assert_eq!(dispatch(&state, "FileRead", &read, None).unwrap()["ok"], true);
        let walked = dispatch(&state, "FileWalk", &json!({"prefixes": ["roots/claude-code-home"]}), None).unwrap();
        assert_eq!(walked["entries"][0]["relative_path"], "roots/claude-code-home/settings.json");
        assert!(dispatch(&state, "AuthorizeRoots", &json!({"root_refs": ["cc-switch"]}), None).unwrap_err().starts_with("NATIVE_ROOT_UNAVAILABLE"), "没发现的位置授权不了");

        let owned = user_confirm(&state, &json!({"scope": "workspace_owned"})).unwrap();
        let owned_ref = owned["authorization_ref"].as_str();
        let write = json!({"path": "roots/claude-code-home/settings.json", "bytes": "e30K"});
        assert!(dispatch(&state, "FileWrite", &write, owned_ref).unwrap_err().starts_with("NATIVE_AUTHORIZATION_TARGET_MISMATCH"));
        let copy = json!({"from": "records/a.json", "to": "roots/claude-code-home/settings.json"});
        assert!(dispatch(&state, "FileCopy", &copy, owned_ref).unwrap_err().starts_with("NATIVE_AUTHORIZATION_TARGET_MISMATCH"), "复制去向不能是真实根");

        let confirmed = user_confirm(
            &state,
            &json!({
                "scope": "single_confirmation",
                "plan_ref": "plan-1",
                "plan_version": 1,
                "action_id": "action-1",
                "action": "json_remove",
                "native_op": "FileWrite",
                "target": {"path": "roots/claude-code-home/settings.json", "kind": "file"}
            }),
        )
        .unwrap();
        assert_eq!(dispatch(&state, "FileWrite", &write, confirmed["authorization_ref"].as_str()).unwrap()["ok"], true);
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{}\n", "单次确认绑定的真实目标被改写");

        dispatch(&state, "RevokeRoots", &json!({"root_refs": ["claude-code-home"]}), None).unwrap();
        assert!(dispatch(&state, "FileRead", &read, None).unwrap_err().starts_with("NATIVE_PATH_OUT_OF_SCOPE"), "撤销后读不到");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn critical_notices_go_through_dispatch_and_an_unshown_notice_is_logged_not_reported_as_shown() {
        let base = root("notify");
        let state = create_injected_host_state("synthetic-user".into(), base.clone(), RecordingService::default(), KEY.to_vec());
        let result = dispatch_logged(&state, "NotifyCritical", &json!({"event": "WRONG_ROUTE", "ref": "alert-1-0"}), None).unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(result["status"], "FAILED");
        assert_eq!(result["code"], "NOTIFICATION_UNAVAILABLE");
        let forged = dispatch_logged(&state, "NotifyCritical", &json!({"event": "WRONG_ROUTE", "ref": "a", "body": "api.anthropic.com"}), None);
        assert!(forged.unwrap_err().starts_with("NOTIFY_FIELD_FORBIDDEN"));
        let appended = dispatch_logged(&state, "AppLogAppend", &json!({"event": "ui.probe", "level": "info"}), None).unwrap();
        let text = std::fs::read_to_string(appended["path"].as_str().unwrap()).unwrap();
        assert!(text.contains("\"op\":\"NotifyCritical\"") && text.contains("NOTIFICATION_UNAVAILABLE"));
        assert!(!text.contains("anthropic"), "页面给的内容不进日志");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn log_ops_read_service_logs_and_every_failed_op_leaves_a_line() {
        let base = root("logs");
        let state = create_injected_host_state("synthetic-user".into(), base.clone(), RecordingService::default(), KEY.to_vec());
        let service_logs = base.join("service").join("logs");
        std::fs::create_dir_all(&service_logs).unwrap();
        std::fs::write(service_logs.join("core.log"), "time=\"t\" level=info msg=\"x\"\n").unwrap();
        let listed = dispatch(&state, "LogSources", &json!({}), None).unwrap();
        assert!(listed["sources"].as_array().unwrap().iter().any(|item| item["source_ref"] == "network_core/core.log"));
        let read = dispatch(&state, "LogRead", &json!({"source_ref": "network_core/core.log"}), None).unwrap();
        assert_eq!(read["ok"], true);
        assert!(dispatch_logged(&state, "FileRead", &json!({"path": "../outside"}), None).is_err());
        let appended = dispatch_logged(&state, "AppLogAppend", &json!({"event": "ui.action_failed", "level": "error", "fields": {"code": "X"}}), None).unwrap();
        let text = std::fs::read_to_string(appended["path"].as_str().unwrap()).unwrap();
        assert!(text.contains("\"op\":\"FileRead\""), "失败的原生操作留了一行");
        assert!(!text.contains("outside"), "载荷不进日志");
        let _ = std::fs::remove_dir_all(&base);
    }
}
