//! 产品网络服务入口（改写上游 `bin/service.rs`）：Windows 服务调度名改为产品服务名，
//! 业务在多线程运行时里执行（命令在阻塞线程里等待内核接口）。
//! 不在服务控制管理器下时直接退出；只有显式 `--console` 才前台运行，供构建机排障。

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
#[cfg(windows)]
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
#[cfg(windows)]
use windows_service::{define_windows_service, service_dispatcher};

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn main() {
    if std::env::args().any(|argument| argument == "--console") {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        let result = runtime.block_on(steward_service_ipc::run_product_service(async {
            let _ = tokio::signal::ctrl_c().await;
        }));
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(error) = service_dispatcher::start(steward_service_ipc::SERVICE_NAME, ffi_service_main) {
        eprintln!("not started by the service control manager: {error}");
        std::process::exit(2);
    }
}

#[cfg(windows)]
fn service_main(_arguments: Vec<OsString>) {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = shutdown_tx.blocking_send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let Ok(status_handle) = service_control_handler::register(steward_service_ipc::SERVICE_NAME, event_handler) else {
        return;
    };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
    let failed = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime
            .block_on(steward_service_ipc::run_product_service(async move {
                let _ = shutdown_rx.recv().await;
            }))
            .is_err(),
        Err(_) => true,
    };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(if failed { 1 } else { 0 }),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the AI Environmental Steward network service runs on Windows only");
    std::process::exit(2);
}
