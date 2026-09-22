//! 服务本地日志（改写上游 `logger.rs`：去掉 clash_verge_logger 这个漂移的 Git 依赖与 flexi_logger，
//! 改为按大小轮转的追加写）。内核输出与服务事件分两个文件；事件字段由调用方构造，不写配置正文或秘密。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::{json, Value};

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

pub struct RotatingLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl RotatingLog {
    pub fn new(path: PathBuf) -> RotatingLog {
        RotatingLog { path, lock: Mutex::new(()) }
    }

    pub fn append(&self, line: &str) {
        let Ok(_guard) = self.lock.lock() else { return };
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::metadata(&self.path).map(|meta| meta.len() > MAX_LOG_BYTES).unwrap_or(false) {
            let _ = fs::rename(&self.path, self.path.with_extension("1.log"));
        }
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    }

    pub fn event(&self, event: &str, fields: Value) {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_millis() as u64)
            .unwrap_or_default();
        self.append(&json!({"at_ms": at, "event": event, "fields": fields}).to_string());
    }
}
