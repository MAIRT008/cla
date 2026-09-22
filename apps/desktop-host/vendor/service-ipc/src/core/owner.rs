//! 服务单实例锁（改写上游 `owner.rs`）：锁文件、PID 文件改到产品运行目录；
//! 判断旧实例是否健康时经产品服务 pipe 发 Handshake，不再发送上游固定 magic 文本。
//!
//! PID 文件记录进程身份（PID、创建时间、程序路径）。旧实例不健康时只结束仍能核验为该身份的进程；
//! PID 已被复用或记录读不懂时不结束任何进程，记录改名保留。

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::Duration;

use serde_json::json;

use crate::core::command::ServiceCommand;
use crate::core::network::{end_owned_process, OwnedProcessEnd};
use crate::core::paths::{ServicePaths, PRODUCT_APP_ID, PROTOCOL};
use crate::core::process::{identify_process, RunningProgramProbe};
use crate::core::reconcile::preserve_unverified_record;
use crate::core::structure::ServiceRequest;

pub struct ServiceOwnerGuard {
    _file: File,
    paths: ServicePaths,
}

impl Drop for ServiceOwnerGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.paths.pid_file());
        let _ = std::fs::remove_file(self.paths.owner_lock());
    }
}

fn try_acquire(paths: &ServicePaths) -> Result<Option<ServiceOwnerGuard>, String> {
    let mut file = match OpenOptions::new().read(true).write(true).create_new(true).open(paths.owner_lock()) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
        Err(error) => return Err(format!("failed to create owner lock: {error}")),
    };
    let pid = std::process::id();
    writeln!(file, "pid={pid}").map_err(|error| error.to_string())?;
    writeln!(file, "version={}", crate::VERSION).map_err(|error| error.to_string())?;
    let record = match identify_process(pid) {
        Ok(Some(identity)) => serde_json::to_vec(&identity).map_err(|error| error.to_string())?,
        _ => serde_json::to_vec(&json!({"pid": pid, "identity": "UNAVAILABLE"})).map_err(|error| error.to_string())?,
    };
    std::fs::write(paths.pid_file(), record).map_err(|error| error.to_string())?;
    Ok(Some(ServiceOwnerGuard { _file: file, paths: paths.clone() }))
}

async fn owner_is_healthy() -> bool {
    let request = ServiceRequest { product_id: PRODUCT_APP_ID.to_string(), protocol: PROTOCOL.to_string(), envelope: None, payload: json!({}) };
    let answered = tokio::task::spawn_blocking(move || crate::client::call(ServiceCommand::Handshake, &request, Duration::from_millis(300))).await;
    matches!(answered, Ok(Ok(reply)) if reply.ok)
}

pub async fn acquire_service_owner(paths: &ServicePaths) -> Result<Option<ServiceOwnerGuard>, String> {
    std::fs::create_dir_all(paths.runtime_dir()).map_err(|error| format!("failed to create runtime directory: {error}"))?;
    if let Some(guard) = try_acquire(paths)? {
        return Ok(Some(guard));
    }
    for _ in 0..20 {
        if owner_is_healthy().await {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if let Ok(bytes) = std::fs::read(paths.pid_file()) {
        let outcome = end_owned_process(&RunningProgramProbe, &bytes);
        match &outcome {
            OwnedProcessEnd::Terminated | OwnedProcessEnd::AlreadyGone => {
                let _ = std::fs::remove_file(paths.pid_file());
            }
            OwnedProcessEnd::IdentityMismatch | OwnedProcessEnd::RecordCorrupt => {
                preserve_unverified_record(&paths.pid_file(), &outcome);
            }
            OwnedProcessEnd::Failed(code) => {
                return Err(format!("stale service owner could not be verified or ended: {code}"));
            }
        }
    }
    let _ = std::fs::remove_file(paths.owner_lock());
    for _ in 0..10 {
        if let Some(guard) = try_acquire(paths)? {
            return Ok(Some(guard));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("failed to acquire service owner lock after stale owner cleanup".to_string())
}
