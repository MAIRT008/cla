//! 服务 IPC（改写上游 `server.rs`）。保留：监听器异常时的进程内重建与退避上限；
//! 改动：
//! - pipe ACL 从上游 `D:(A;;GA;;;WD)`（Everyone 全权）收窄为 SY/BA 全权 + 安装时批准用户读写；
//! - 服务端从 kode-bridge HTTP 换成 tokio 命名管道 + 长度帧：kode-bridge 0.4.0 的 `RequestContext` 只给连接序号，
//!   拿不到 pipe 句柄；这里在业务分发前用 `GetNamedPipeClientProcessId` 取客户端进程，核对安装记录里的宿主程序；
//! - 只接受 `ServiceCommand` 的 12 个固定命令，业务判定在阻塞线程里执行，读命令不等待改写命令的串行锁；
//! - 常驻定时器执行应急到期与受管路径实例核对，不依赖宿主或页面存活。

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::core::command::ServiceCommand;
use crate::core::controller::PipeController;
use crate::core::logger::RotatingLog;
use crate::core::manager::{MihomoValidator, ProductCoreProcess};
use crate::core::network::{Backends, Clock, NetworkService, PeerPolicy, PeerProcess};
use crate::core::owner::acquire_service_owner;
use crate::core::paths::ServicePaths;
use crate::core::process::RunningProgramProbe;
use crate::core::reconcile::reconcile_service_startup;
use crate::core::state::{set_service_lifecycle_state, ServiceLifecycleState};
use crate::core::store::{read_install_record, read_link_key, FileConfigStore, FileStateStore};
use crate::core::structure::{ServiceError, ServiceReply, WireRequest};
use crate::core::wfp::product_protection;

const IPC_MAX_RESTARTS: usize = 10;
const IPC_RESTART_WINDOW: Duration = Duration::from_secs(10);
const TICK_INTERVAL: Duration = Duration::from_secs(5);

pub struct ServiceHost {
    pub network: NetworkService,
    pub link_key: Vec<u8>,
    pub approved_user_sid: Option<String>,
    pub peers: PeerPolicy,
    pub log: RotatingLog,
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_millis() as i64)
            .unwrap_or_default()
    }
}

/// 一帧请求的分发：命令名、宿主身份与业务判定都在这里核对；返回要写回的回执。
async fn dispatch(host: Arc<ServiceHost>, body: Vec<u8>, peer: Option<PeerProcess>) -> ServiceReply {
    let wire = match serde_json::from_slice::<WireRequest>(&body) {
        Ok(wire) => wire,
        Err(_) => return ServiceReply::rejected(&ServiceError::new("REQUEST_INVALID", "请求体不是服务请求结构")),
    };
    let Some(command) = ServiceCommand::from_name(&wire.command) else {
        return ServiceReply::rejected(&ServiceError::new("COMMAND_UNSUPPORTED", "未知命令"));
    };
    let worker = host.clone();
    let peer_pid = peer.as_ref().map(|process| process.pid);
    let reply = tokio::task::spawn_blocking(move || {
        worker.network.handle_peer(command, &wire.request, &worker.link_key, &worker.peers, peer.as_ref())
    })
    .await
    .unwrap_or_else(|_| ServiceReply::rejected(&ServiceError::new("SERVICE_HANDLER_FAILED", "命令执行线程异常结束")));
    host.log.event("ipc.command", json!({"command": command.name(), "peer_pid": peer_pid, "ok": reply.ok, "code": reply.code}));
    reply
}

#[cfg(windows)]
mod pipe {
    use std::ffi::c_void;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    use super::{dispatch, ServiceHost};
    use crate::core::network::PeerProcess;
    use crate::core::paths::SERVICE_PIPE;
    use crate::core::structure::{encode_frame, frame_length, ServiceError, ServiceReply};

    const SDDL_REVISION_1: u32 = 1;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: *const u16, revision: u32, descriptor: *mut *mut c_void, size: *mut u32) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    /// 由 SDDL 换出的安全描述符；每次创建 pipe 实例都用它，监听结束时释放。
    pub struct PipeSecurity {
        attributes: SecurityAttributes,
    }

    impl PipeSecurity {
        pub fn from_sddl(sddl: &str) -> Result<PipeSecurity, String> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut descriptor: *mut c_void = std::ptr::null_mut();
            let converted = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut()) };
            if converted == 0 || descriptor.is_null() {
                return Err(format!("service pipe security descriptor is invalid: {}", unsafe { GetLastError() }));
            }
            Ok(PipeSecurity {
                attributes: SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32, descriptor, inherit_handle: 0 },
            })
        }

        pub fn create(&mut self, first: bool) -> std::io::Result<NamedPipeServer> {
            let mut options = ServerOptions::new();
            options.first_pipe_instance(first).reject_remote_clients(true);
            unsafe { options.create_with_security_attributes_raw(SERVICE_PIPE, &mut self.attributes as *mut SecurityAttributes as *mut c_void) }
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.attributes.descriptor);
            }
        }
    }

    pub fn peer_of(server: &NamedPipeServer) -> Option<PeerProcess> {
        use std::os::windows::io::AsRawHandle;
        crate::core::process::pipe_client_process(server.as_raw_handle() as *mut c_void)
    }

    async fn read_request(connection: &mut NamedPipeServer) -> Result<Vec<u8>, ServiceError> {
        let invalid = |detail: String| ServiceError::new("REQUEST_INVALID", detail);
        let mut header = [0u8; 4];
        connection.read_exact(&mut header).await.map_err(|error| invalid(error.to_string()))?;
        let mut body = vec![0u8; frame_length(header)?];
        connection.read_exact(&mut body).await.map_err(|error| invalid(error.to_string()))?;
        Ok(body)
    }

    /// 身份在读请求之前就从连接取出：分发时用的是 Windows 给出的客户端进程，而不是请求里的任何字段。
    pub async fn serve_connection(host: Arc<ServiceHost>, mut connection: NamedPipeServer, peer: Option<PeerProcess>) {
        let reply = match read_request(&mut connection).await {
            Ok(body) => dispatch(host, body, peer).await,
            Err(error) => ServiceReply::rejected(&error),
        };
        if let Ok(frame) = encode_frame(&reply) {
            let _ = connection.write_all(&frame).await;
            let _ = connection.flush().await;
        }
        let _ = connection.disconnect();
    }
}

fn record_restart(restarts: &mut Vec<Instant>) -> Result<Duration, String> {
    let now = Instant::now();
    restarts.retain(|at| now.duration_since(*at) < IPC_RESTART_WINDOW);
    restarts.push(now);
    if restarts.len() > IPC_MAX_RESTARTS {
        set_service_lifecycle_state(ServiceLifecycleState::Fatal);
        return Err("service pipe listener restarted too often".to_string());
    }
    Ok(Duration::from_millis(100u64 << restarts.len().min(3)).min(Duration::from_millis(500)))
}

fn spawn_ticker(host: Arc<ServiceHost>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK_INTERVAL).await;
            let worker = host.clone();
            if let Ok(summary) = tokio::task::spawn_blocking(move || worker.network.tick()).await {
                if summary.get("actions").and_then(|actions| actions.as_array()).map(|actions| !actions.is_empty()).unwrap_or(false) {
                    host.log.event("service.tick", summary);
                }
            }
        }
    })
}

/// 监听服务 pipe 直到收到停止信号。每接一个连接立即建好下一个实例，pipe 名不会空出来被别的进程抢占。
/// 服务停止不撤保护：WFP 阻断留在系统里，内核随运行时结束，重启后先恢复保护。
#[cfg(windows)]
pub async fn run_service_until_shutdown(host: Arc<ServiceHost>, shutdown: impl Future<Output = ()>) -> Result<(), String> {
    let mut security = pipe::PipeSecurity::from_sddl(&crate::core::paths::service_pipe_sddl(host.approved_user_sid.as_deref()))?;
    let mut restarts: Vec<Instant> = Vec::new();
    let mut server = security.create(true).map_err(|error| format!("failed to create service pipe: {error}"))?;
    let ticker = spawn_ticker(host.clone());
    set_service_lifecycle_state(ServiceLifecycleState::Running);
    tokio::pin!(shutdown);
    let result = loop {
        let connected = tokio::select! {
            _ = &mut shutdown => break Ok(()),
            connected = server.connect() => connected,
        };
        if let Err(error) = connected {
            set_service_lifecycle_state(ServiceLifecycleState::RecoveringIpc);
            host.log.event("ipc.connect_failed", json!({"error": error.to_string()}));
            let delay = match record_restart(&mut restarts) {
                Ok(delay) => delay,
                Err(fatal) => break Err(fatal),
            };
            tokio::time::sleep(delay).await;
            match security.create(false) {
                Ok(next) => server = next,
                Err(error) => host.log.event("ipc.listener_recreate_failed", json!({"error": error.to_string()})),
            }
            continue;
        }
        let next = loop {
            match security.create(false) {
                Ok(next) => break Ok(next),
                Err(error) => {
                    host.log.event("ipc.listener_recreate_failed", json!({"error": error.to_string()}));
                    match record_restart(&mut restarts) {
                        Ok(delay) => tokio::time::sleep(delay).await,
                        Err(fatal) => break Err(fatal),
                    }
                }
            }
        };
        let next = match next {
            Ok(next) => next,
            Err(fatal) => break Err(fatal),
        };
        let connection = std::mem::replace(&mut server, next);
        let peer = pipe::peer_of(&connection);
        tokio::spawn(pipe::serve_connection(host.clone(), connection, peer));
        set_service_lifecycle_state(ServiceLifecycleState::Running);
    };
    ticker.abort();
    result
}

#[cfg(not(windows))]
pub async fn run_service_until_shutdown(_host: Arc<ServiceHost>, _shutdown: impl Future<Output = ()>) -> Result<(), String> {
    Err("the product service pipe runs on Windows only".to_string())
}

/// 产品服务主流程：单实例锁 → 按身份结束上一轮遗留内核 → 装配真实后端 → 保护先行的启动恢复 → 监听 IPC。
pub async fn run_product_service(shutdown: impl Future<Output = ()>) -> Result<(), String> {
    set_service_lifecycle_state(ServiceLifecycleState::Starting);
    let paths = ServicePaths::product()?;
    let log = RotatingLog::new(paths.log_dir().join("service.log"));
    let Some(_owner) = acquire_service_owner(&paths).await? else {
        return Ok(());
    };
    log.event("service.reconciled", reconcile_service_startup(&paths));
    let install = read_install_record(&paths).map_err(|error| error.to_string())?;
    let link_key = match read_link_key(&paths) {
        Ok(key) => key,
        Err(error) => {
            log.event("service.link_key_unavailable", json!({"code": error.code}));
            Vec::new()
        }
    };
    let handle = tokio::runtime::Handle::current();
    let secret = Arc::new(Mutex::new(String::new()));
    let backends = Backends {
        clock: Box::new(SystemClock),
        state: Box::new(FileStateStore::new(&paths)),
        configs: Box::new(FileConfigStore::new(&paths, install.as_ref())),
        core: Box::new(ProductCoreProcess::new(handle.clone(), paths.clone(), secret.clone())),
        controller: Box::new(PipeController::new(handle, secret)),
        validator: Box::new(MihomoValidator::new(paths.clone())),
        protection: product_protection(),
        processes: Box::new(RunningProgramProbe),
    };
    let network = NetworkService::open(backends).map_err(|error| error.to_string())?;
    let peers = PeerPolicy {
        host_image: install.as_ref().map(|record| record.host_executable.clone()),
        service_image: std::env::current_exe().ok().map(|path| path.to_string_lossy().to_string()),
    };
    if peers.host_image.is_none() {
        log.event("service.host_identity_unapproved", json!({}));
    }
    let host = Arc::new(ServiceHost {
        network,
        link_key,
        approved_user_sid: install.map(|record| record.approved_user_sid),
        peers,
        log,
    });
    let recovering = host.clone();
    let recovered = tokio::task::spawn_blocking(move || recovering.network.recover_after_start()).await;
    match recovered {
        Ok(summary) => host.log.event("service.recovered", summary),
        Err(_) => host.log.event("service.recover_failed", json!({})),
    }
    run_service_until_shutdown(host, shutdown).await
}
