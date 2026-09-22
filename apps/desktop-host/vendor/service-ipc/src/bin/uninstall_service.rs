//! 产品网络服务卸载助手（改写上游 `bin/uninstall_service.rs` 的 Windows 分支，删去 macOS/Linux 分支）。
//!
//! `ai-environmental-steward-service-uninstall [--release-protection] [--delete-state]`
//!
//! - 只停止、删除产品服务名下、且程序路径就是助手同目录本产品服务程序的服务；路径不符就不动；
//! - 不接触任何上游 Clash Verge 服务；
//! - 服务先确实停下（停不下来就不撤保护、不删服务）。之后不看运行状态记录，直接枚举本产品 WFP 子层：
//!   `--release-protection`（用户在卸载时明确选择停止管理并恢复原网络）先删 permit，确认 permit 删净后才删阻断，删完重新枚举；
//!   不给这个开关就只枚举。子层里还剩本产品过滤器、或枚举与删除任何一步出错，都重新启动服务、不删服务、非零退出，
//!   不留下没人管的阻断。运行状态文件丢了也照样能证明。
//! - 子层清干净之后、删服务之前，`--release-protection` 还把已保存的保护请求作废（保留数据时也要），
//!   重装后服务启动不会按旧请求把阻断装回去；写不进就重新启动服务、非零退出，服务按原请求补回保护。
//! - `--delete-state`（用户勾选删除应用数据）只在子层清干净、服务已删后删除本产品服务状态目录，必须和 `--release-protection` 一起给。
//! - 每次运行在服务日志目录写 `install-<毫秒>-<进程号>.log`（删除状态目录时一并删除）。

fn millis_now() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

/// 两个开关的组合规则：删状态之前必须先撤保护，服务状态目录要留到子层清干净之后。
fn validate_flags(release_protection: bool, delete_state: bool) -> Result<(), String> {
    if delete_state && !release_protection {
        return Err("--delete-state needs --release-protection: the service state is only removed after the product protection is released".to_string());
    }
    Ok(())
}

/// 子层没清干净时的拒绝原因。
fn sweep_refusal(release_protection: bool, sweep: &steward_service_ipc::core::wfp::ProductSweep) -> String {
    let code = sweep.code.as_deref().map(|code| format!(", {code}")).unwrap_or_default();
    if release_protection {
        format!(
            "the product protection could not be shown to be fully released ({} of {} filters remain{code}); the service was restarted and left installed so nothing is left blocked without an owner",
            sweep.remaining, sweep.found
        )
    } else {
        format!(
            "product protection is still installed or cannot be counted ({} filters{code}); the service was left installed; uninstall with --release-protection to release it first",
            sweep.remaining
        )
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = uninstall() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn uninstall() -> Result<(), String> {
    use std::ffi::OsStr;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let release_protection = std::env::args().any(|argument| argument == "--release-protection");
    let delete_state = std::env::args().any(|argument| argument == "--delete-state");
    validate_flags(release_protection, delete_state)?;

    let install_dir = std::env::current_exe()
        .map_err(|error| error.to_string())?
        .parent()
        .map(Path::to_path_buf)
        .ok_or("uninstaller has no directory")?;
    let program_data = std::env::var_os("ProgramData").ok_or("ProgramData is not set")?;
    let paths = steward_service_ipc::ServicePaths::rooted(
        PathBuf::from(program_data).join(steward_service_ipc::core::paths::STATE_DIR_NAME),
        install_dir,
    );
    let log_path = paths.log_dir().join(format!("install-{}-{}.log", millis_now(), std::process::id()));
    let log = |text: &str| {
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = writeln!(file, "{} {text}", millis_now());
        }
    };
    log(&format!("uninstall.begin release_protection={release_protection} delete_state={delete_state}"));

    let expected = std::fs::canonicalize(paths.service_binary()).unwrap_or_else(|_| paths.service_binary());
    let normalize = |path: &Path| path.to_string_lossy().trim_start_matches(r"\\?\").trim_matches('"').to_ascii_lowercase();

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|error| error.to_string())?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG | ServiceAccess::STOP | ServiceAccess::START | ServiceAccess::DELETE;
    // 服务可能从没建成（安装中途失败）：那就没有服务可停可删，但子层照样要清点。
    let service = manager.open_service(steward_service_ipc::SERVICE_NAME, access).ok();
    let restart = |why: &str| {
        if let Some(service) = &service {
            let _ = service.start(&Vec::<&OsStr>::new());
        }
        log(&format!("uninstall.stopped_and_service_restarted {why}"));
    };
    if let Some(service) = &service {
        let config = service.query_config().map_err(|error| error.to_string())?;
        let actual = std::fs::canonicalize(&config.executable_path).unwrap_or(config.executable_path.clone());
        if normalize(&actual) != normalize(&expected) {
            return Err("the service with the product name points at another program; it was left untouched".to_string());
        }
        if service.query_status().map_err(|error| error.to_string())?.current_state != ServiceState::Stopped {
            let _ = service.stop();
        }
        let mut stopped = false;
        for _ in 0..150 {
            if service.query_status().map(|status| status.current_state == ServiceState::Stopped).unwrap_or(false) {
                stopped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if !stopped {
            // 服务还在跑就撤保护，它会把阻断重新装回去；先证明停下来，否则什么都不撤、什么都不删。
            restart("service_did_not_stop");
            return Err("the service did not stop within 30 seconds; protection was not released and the service was left installed".to_string());
        }
        log("uninstall.service_stopped");
    } else {
        log("uninstall.service_absent");
    }

    let sweep = steward_service_ipc::core::wfp::product_sublayer_sweep(release_protection);
    log(&format!(
        "uninstall.sweep release={release_protection} found={} removed={} remaining={} code={}",
        sweep.found,
        sweep.removed,
        sweep.remaining,
        sweep.code.as_deref().unwrap_or("none")
    ));
    if !sweep.clean() {
        restart("protection_not_released");
        return Err(sweep_refusal(release_protection, &sweep));
    }

    if release_protection {
        // 用户选择了停止管理：保留数据也要把保护请求作废，否则重装后服务启动会按旧请求把阻断装回去。
        // 状态文件解析不了时，任何服务实例都读不出其中的请求，不会据此装回保护，照常继续。
        let store = steward_service_ipc::core::store::FileStateStore::new(&paths);
        match steward_service_ipc::core::network::revoke_saved_protection(&store, millis_now() as i64) {
            Ok(revoked) => log(&format!("uninstall.protection_requests_revoked count={revoked}")),
            Err(error) if error.code == "SERVICE_STATE_CORRUPT" => log("uninstall.protection_requests_unreadable state_corrupt"),
            Err(error) => {
                restart("protection_request_not_revoked");
                return Err(format!(
                    "the protection requests could not be marked as revoked ({}); the service was restarted and left installed, and it puts the protection back from its requests",
                    error.code
                ));
            }
        }
    }

    if let Some(service) = &service {
        service.delete().map_err(|error| error.to_string())?;
        log("uninstall.service_deleted");
    }

    if delete_state {
        let state_dir = paths.state_dir().to_path_buf();
        if state_dir.file_name().and_then(|name| name.to_str()) != Some(steward_service_ipc::core::paths::STATE_DIR_NAME) {
            return Err("the state directory is not the product namespace; it was left untouched".to_string());
        }
        std::fs::remove_dir_all(&state_dir).map_err(|error| format!("the service state directory could not be removed: {error}"))?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the AI Environmental Steward network service uninstalls on Windows only");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    type ProductSweep = steward_service_ipc::core::wfp::ProductSweep;

    #[test]
    fn state_is_deleted_only_together_with_releasing_protection() {
        assert!(validate_flags(false, false).is_ok());
        assert!(validate_flags(true, false).is_ok());
        assert!(validate_flags(true, true).is_ok());
        assert!(validate_flags(false, true).unwrap_err().starts_with("--delete-state needs --release-protection"));
    }

    #[test]
    fn only_an_empty_product_sublayer_lets_the_service_be_deleted() {
        assert!(ProductSweep { found: 3, removed: 3, remaining: 0, ..ProductSweep::default() }.clean());
        let left = ProductSweep { found: 3, removed: 2, remaining: 1, code: Some("NATIVE_FILTER_DELETE_FAILED".to_string()), ..ProductSweep::default() };
        assert!(!left.clean());
        assert!(sweep_refusal(true, &left).contains("1 of 3 filters remain, NATIVE_FILTER_DELETE_FAILED"));
        let kept = ProductSweep { found: 2, remaining: 2, ..ProductSweep::default() };
        assert!(!kept.clean());
        assert!(sweep_refusal(false, &kept).contains("--release-protection"), "没选撤保护时子层里还有过滤器，就不删服务");
        let unreadable = ProductSweep { code: Some("NATIVE_FILTER_ENUM_FAILED".to_string()), ..ProductSweep::default() };
        assert!(!unreadable.clean(), "枚举失败时数量为零也不算干净");
    }
}
