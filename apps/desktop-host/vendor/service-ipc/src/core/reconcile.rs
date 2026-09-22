//! 服务启动对账（改写上游 `reconcile.rs`）：上一轮服务留下的内核进程按运行记录里的身份结束，
//! 再由 `NetworkService::recover_after_start` 恢复保护、关受管路径。
//!
//! 记录绑定 PID、创建时间与程序路径；当前进程与记录不一致（PID 已被复用）或记录读不懂时都不结束任何进程，
//! 记录改名保留作证据，不删除。

use std::path::Path;

use serde_json::{json, Value};

use crate::core::network::{end_owned_process, OwnedProcessEnd};
use crate::core::paths::ServicePaths;
use crate::core::process::RunningProgramProbe;

/// 核验没过的所有权记录改名保留，避免被下一份记录覆盖。
pub fn preserve_unverified_record(path: &Path, outcome: &OwnedProcessEnd) -> Option<String> {
    let label = outcome.code().to_ascii_lowercase();
    let file_name = path.file_name()?.to_string_lossy().to_string();
    let kept = path.with_file_name(format!("{file_name}.{label}"));
    std::fs::rename(path, &kept).ok()?;
    Some(kept.to_string_lossy().to_string())
}

pub fn reconcile_service_startup(paths: &ServicePaths) -> Value {
    let record_path = paths.core_runtime();
    let bytes = match std::fs::read(&record_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return json!({"core_record": "ABSENT"}),
        Err(error) => return json!({"core_record": "UNREADABLE", "error": error.to_string()}),
    };
    let outcome = end_owned_process(&RunningProgramProbe, &bytes);
    let kept = match &outcome {
        OwnedProcessEnd::Terminated | OwnedProcessEnd::AlreadyGone => {
            let _ = std::fs::remove_file(&record_path);
            None
        }
        OwnedProcessEnd::IdentityMismatch | OwnedProcessEnd::RecordCorrupt => preserve_unverified_record(&record_path, &outcome),
        OwnedProcessEnd::Failed(_) => None,
    };
    json!({"core_record": outcome.code(), "record_resolved": outcome.record_resolved(), "kept_as": kept})
}
