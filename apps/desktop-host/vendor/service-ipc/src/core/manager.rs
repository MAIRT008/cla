//! 固定 Mihomo 进程管理（改写上游 `manager.rs`）。保留：串行启停、子进程守护、退出诊断、退避重启与运行记录；
//! 改动：
//! - 程序只取产品目录下的固定 v1.19.30（`ServicePaths::core_binary`），不接受调用方给出的 core_path，缺失时返回 `CORE_BINARY_MISSING`；
//! - 内核控制只开产品 pipe，`LISTEN_NAMEDPIPE_SDDL` 收窄到 LocalSystem，secret 经环境变量传入，不进命令行；
//! - 有限重启：10 分钟内最多 3 次，重启只加载回读确认过的 last-valid，用尽后停止并记录，不回退未知默认配置；
//! - 日志写产品日志文件并保留尾部供运行记录读取，不再依赖 clash_verge_logger；
//! - 运行记录写进程身份（PID、创建时间、程序路径），不再只有 PID。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::core::auth::random_hex;
use crate::core::logger::RotatingLog;
use crate::core::network::{CoreProcess, CoreStatus, KernelValidator};
use crate::core::paths::{ServicePaths, CORE_PIPE, CORE_PIPE_SDDL};
use crate::core::process::identify_process;
use crate::core::structure::ServiceError;

const MAX_RESTARTS: usize = 3;
const RESTART_WINDOW: Duration = Duration::from_secs(600);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const LOG_RING: usize = 500;
const PIPE_READY_ATTEMPTS: u32 = 50;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or_default()
}

fn backoff_delay(attempt: u32) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }
    Duration::from_secs(1u64 << (attempt - 1).min(5)).min(MAX_BACKOFF)
}

struct Inner {
    paths: ServicePaths,
    running_pid: AtomicU32,
    started_at_ms: AtomicI64,
    restart_count: AtomicU32,
    gave_up: AtomicBool,
    last_exit: Mutex<Option<String>>,
    restart_config: Mutex<Option<PathBuf>>,
    secret: Arc<Mutex<String>>,
    logs: Mutex<VecDeque<String>>,
    core_log: RotatingLog,
    service_log: RotatingLog,
    watchdog: Mutex<Option<(oneshot::Sender<()>, JoinHandle<()>)>>,
}

impl Inner {
    fn remember(&self, line: String) {
        self.core_log.append(&line);
        if let Ok(mut ring) = self.logs.lock() {
            ring.push_back(line);
            while ring.len() > LOG_RING {
                ring.pop_front();
            }
        }
    }
}

pub struct ProductCoreProcess {
    handle: Handle,
    inner: Arc<Inner>,
}

impl ProductCoreProcess {
    /// `secret` 与内核控制客户端共享：每次启动内核都换新值。
    pub fn new(handle: Handle, paths: ServicePaths, secret: Arc<Mutex<String>>) -> ProductCoreProcess {
        let core_log = RotatingLog::new(paths.log_dir().join("core.log"));
        let service_log = RotatingLog::new(paths.log_dir().join("service.log"));
        ProductCoreProcess {
            handle,
            inner: Arc::new(Inner {
                paths,
                running_pid: AtomicU32::new(0),
                started_at_ms: AtomicI64::new(0),
                restart_count: AtomicU32::new(0),
                gave_up: AtomicBool::new(false),
                last_exit: Mutex::new(None),
                restart_config: Mutex::new(None),
                secret,
                logs: Mutex::new(VecDeque::new()),
                core_log,
                service_log,
                watchdog: Mutex::new(None),
            }),
        }
    }
}

#[cfg(windows)]
async fn wait_for_core_pipe() -> bool {
    for _ in 0..PIPE_READY_ATTEMPTS {
        if tokio::net::windows::named_pipe::ClientOptions::new().open(CORE_PIPE).is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[cfg(not(windows))]
async fn wait_for_core_pipe() -> bool {
    false
}

async fn spawn_core(inner: &Arc<Inner>, config_path: &Path) -> Result<Child, ServiceError> {
    let binary = inner.paths.core_binary();
    if !binary.is_file() {
        return Err(ServiceError::new("CORE_BINARY_MISSING", "固定版本内核程序不在产品目录"));
    }
    let secret = random_hex(24)?;
    if let Ok(mut shared) = inner.secret.lock() {
        *shared = secret.clone();
    }
    let mut command = Command::new(&binary);
    command
        .arg("-d")
        .arg(inner.paths.core_home())
        .arg("-f")
        .arg(config_path)
        .arg("-ext-ctl-pipe")
        .arg(CORE_PIPE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().to_ascii_uppercase();
        if name.starts_with("CLASH_") || name == "SAFE_PATHS" || name == "LISTEN_NAMEDPIPE_SDDL" {
            command.env_remove(&key);
        }
    }
    command.env("LISTEN_NAMEDPIPE_SDDL", CORE_PIPE_SDDL).env("CLASH_OVERRIDE_SECRET", &secret);
    let mut child = command.spawn().map_err(|error| ServiceError::new("CORE_START_FAILED", error.to_string()))?;
    let pid = child.id().unwrap_or_default();
    for reader in [child.stdout.take().map(ReaderKind::Out), child.stderr.take().map(ReaderKind::Err)].into_iter().flatten() {
        let sink = inner.clone();
        tokio::spawn(async move {
            match reader {
                ReaderKind::Out(stream) => {
                    let mut lines = BufReader::new(stream).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        sink.remember(line);
                    }
                }
                ReaderKind::Err(stream) => {
                    let mut lines = BufReader::new(stream).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        sink.remember(format!("[stderr] {line}"));
                    }
                }
            }
        });
    }
    if !wait_for_core_pipe().await {
        let _ = child.kill().await;
        return Err(ServiceError::new("CORE_START_TIMEOUT", "内核控制 pipe 没有按时就绪"));
    }
    inner.running_pid.store(pid, Ordering::Relaxed);
    inner.started_at_ms.store(now_ms(), Ordering::Relaxed);
    // 服务持有子进程句柄，此刻 PID 不会被复用；记录完整身份，下次启动对账只结束仍能核验为这个进程的内核。
    match identify_process(pid).ok().flatten().and_then(|identity| serde_json::to_vec(&identity).ok()) {
        Some(record) => {
            let written = std::fs::create_dir_all(inner.paths.runtime_dir()).and_then(|_| std::fs::write(inner.paths.core_runtime(), record));
            if let Err(error) = written {
                inner.service_log.event("core.record_unwritable", json!({"pid": pid, "error": error.to_string()}));
            }
        }
        None => inner.service_log.event("core.identity_unavailable", json!({"pid": pid})),
    }
    inner.service_log.event("core.started", json!({"pid": pid}));
    Ok(child)
}

enum ReaderKind {
    Out(tokio::process::ChildStdout),
    Err(tokio::process::ChildStderr),
}

fn exit_reason(status: &std::io::Result<std::process::ExitStatus>, uptime: Duration) -> String {
    match status {
        Ok(status) => format!("exit code {:?} after {:.1}s", status.code(), uptime.as_secs_f64()),
        Err(error) => format!("wait failed: {error}"),
    }
}

/// 守护循环：内核异常退出时保护不动，按退避有限重启；次数用尽即停止并记录，不开放任何回退。
async fn watchdog(inner: Arc<Inner>, mut child: Child, mut shutdown: oneshot::Receiver<()>) {
    let mut restarts: Vec<Instant> = Vec::new();
    let mut attempt = 0u32;
    'supervise: loop {
        let started = Instant::now();
        let status = tokio::select! {
            _ = &mut shutdown => {
                let _ = child.kill().await;
                break 'supervise;
            }
            status = child.wait() => status,
        };
        let reason = exit_reason(&status, started.elapsed());
        inner.running_pid.store(0, Ordering::Relaxed);
        inner.started_at_ms.store(0, Ordering::Relaxed);
        if let Ok(mut last) = inner.last_exit.lock() {
            *last = Some(reason.clone());
        }
        inner.service_log.event("core.exited", json!({"reason": reason}));
        let _ = std::fs::remove_file(inner.paths.core_runtime());
        loop {
            let now = Instant::now();
            restarts.retain(|at| now.duration_since(*at) < RESTART_WINDOW);
            if restarts.is_empty() {
                attempt = 0;
            }
            if restarts.len() >= MAX_RESTARTS {
                inner.gave_up.store(true, Ordering::Relaxed);
                inner.service_log.event("core.restart_gave_up", json!({"restarts": restarts.len()}));
                break 'supervise;
            }
            restarts.push(now);
            let delay = backoff_delay(attempt);
            attempt += 1;
            if !delay.is_zero() {
                tokio::select! {
                    _ = &mut shutdown => break 'supervise,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            let config = inner.restart_config.lock().ok().and_then(|guard| guard.clone());
            let Some(config) = config else {
                inner.gave_up.store(true, Ordering::Relaxed);
                inner.service_log.event("core.restart_skipped", json!({"reason": "NO_VERIFIED_CONFIG"}));
                break 'supervise;
            };
            match spawn_core(&inner, &config).await {
                Ok(next) => {
                    inner.restart_count.fetch_add(1, Ordering::Relaxed);
                    child = next;
                    continue 'supervise;
                }
                Err(error) => {
                    inner.service_log.event("core.restart_failed", json!({"code": error.code}));
                }
            }
        }
    }
    inner.running_pid.store(0, Ordering::Relaxed);
    let _ = std::fs::remove_file(inner.paths.core_runtime());
}

impl ProductCoreProcess {
    async fn stop_async(inner: &Arc<Inner>) {
        let running = inner.watchdog.lock().ok().and_then(|mut guard| guard.take());
        if let Some((shutdown, handle)) = running {
            let _ = shutdown.send(());
            let _ = handle.await;
        }
        inner.running_pid.store(0, Ordering::Relaxed);
        inner.started_at_ms.store(0, Ordering::Relaxed);
    }
}

impl CoreProcess for ProductCoreProcess {
    fn binary_present(&self) -> bool {
        self.inner.paths.core_binary().is_file()
    }

    fn start(&self, config_path: &Path) -> Result<CoreStatus, ServiceError> {
        let inner = self.inner.clone();
        let config = config_path.to_path_buf();
        self.handle.block_on(async move {
            ProductCoreProcess::stop_async(&inner).await;
            inner.gave_up.store(false, Ordering::Relaxed);
            let child = spawn_core(&inner, &config).await?;
            let (shutdown, receiver) = oneshot::channel();
            let supervised = tokio::spawn(watchdog(inner.clone(), child, receiver));
            if let Ok(mut guard) = inner.watchdog.lock() {
                *guard = Some((shutdown, supervised));
            }
            Ok::<(), ServiceError>(())
        })?;
        Ok(self.status())
    }

    fn stop(&self) -> Result<(), ServiceError> {
        let inner = self.inner.clone();
        self.handle.block_on(async move { ProductCoreProcess::stop_async(&inner).await });
        self.inner.service_log.event("core.stopped", json!({}));
        Ok(())
    }

    fn set_restart_config(&self, config_path: &Path) {
        if let Ok(mut guard) = self.inner.restart_config.lock() {
            *guard = Some(config_path.to_path_buf());
        }
    }

    fn status(&self) -> CoreStatus {
        let pid = self.inner.running_pid.load(Ordering::Relaxed);
        let started = self.inner.started_at_ms.load(Ordering::Relaxed);
        CoreStatus {
            running: pid != 0,
            pid: (pid != 0).then_some(pid),
            started_at_ms: (started != 0).then_some(started),
            restart_count: self.inner.restart_count.load(Ordering::Relaxed),
            last_exit: self.inner.last_exit.lock().ok().and_then(|guard| guard.clone()),
            gave_up: self.inner.gave_up.load(Ordering::Relaxed),
        }
    }

    fn log_tail(&self, max_lines: usize) -> Vec<String> {
        self.inner
            .logs
            .lock()
            .map(|ring| ring.iter().rev().take(max_lines).rev().cloned().collect())
            .unwrap_or_default()
    }
}

/// 固定内核的 `-t` 配置校验：不加载、不开控制接口，只看退出码与内核自己的结论。
pub struct MihomoValidator {
    paths: ServicePaths,
}

impl MihomoValidator {
    pub fn new(paths: ServicePaths) -> MihomoValidator {
        MihomoValidator { paths }
    }
}

impl KernelValidator for MihomoValidator {
    fn validate(&self, config_path: &Path) -> Result<(), ServiceError> {
        let binary = self.paths.core_binary();
        if !binary.is_file() {
            return Err(ServiceError::new("CORE_BINARY_MISSING", "固定版本内核程序不在产品目录"));
        }
        let mut command = StdCommand::new(binary);
        command.arg("-t").arg("-d").arg(self.paths.core_home()).arg("-f").arg(config_path).stdin(Stdio::null());
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().to_ascii_uppercase().starts_with("CLASH_") {
                command.env_remove(&key);
            }
        }
        let output = command.output().map_err(|error| ServiceError::new("CONFIG_KERNEL_UNAVAILABLE", error.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && stdout.contains("test is successful") {
            Ok(())
        } else {
            Err(ServiceError::new("CONFIG_KERNEL_REJECTED", "固定内核校验没有通过"))
        }
    }
}
