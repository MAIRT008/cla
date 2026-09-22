//! 本地运行日志：每次启动一个新文件（create_new，不会覆盖上一轮），每行一条 JSON。
//! 字段先脱敏再格式化；写入失败记在 Logger 上，由 /health 与就绪握手明示，不静默吞掉。
//!
//! 没有采用 tracing-appender / flexi_logger：两者把写入错误留在内部（丢弃或转到 stderr），
//! 调用方拿不到，也就没法把「日志未成功保存」回报给宿主和页面。

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::{iso_from_millis, now_millis};

/// 字段名含这些片段即整体替换，不看值长什么样。
const SECRET_KEY_PARTS: &[&str] = &["password", "passwd", "token", "secret", "authorization", "cookie", "api_key", "apikey", "credential"];

pub struct Logger {
    path: PathBuf,
    instance_ref: String,
    file: Mutex<Option<File>>,
    failure: Mutex<Option<String>>,
}

impl Logger {
    /// 创建本轮日志文件。创建失败不阻止服务启动，但状态会一直报 failed，并在 stderr 留一行。
    pub fn create(log_dir: &Path, instance_ref: &str) -> Logger {
        let stamp = iso_from_millis(now_millis()).replace(['-', ':', '.'], "");
        let path = log_dir.join(format!("control-{stamp}-{instance_ref}.log"));
        let opened = std::fs::create_dir_all(log_dir)
            .and_then(|_| OpenOptions::new().append(true).create_new(true).open(&path));
        let (file, failure) = match opened {
            Ok(file) => (Some(file), None),
            Err(error) => {
                let detail = format!("日志文件无法创建：{error}");
                eprintln!("{}", json!({"event": "log.unavailable", "path": path.to_string_lossy(), "detail": detail}));
                (None, Some(detail))
            }
        };
        Logger {
            path,
            instance_ref: instance_ref.to_string(),
            file: Mutex::new(file),
            failure: Mutex::new(failure),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn instance_ref(&self) -> &str {
        &self.instance_ref
    }

    /// "ok" 或 "failed"。一旦失败就保持 failed，不因后续某次写成功而洗白。
    pub fn status(&self) -> &'static str {
        match self.failure.lock() {
            Ok(slot) if slot.is_none() => "ok",
            _ => "failed",
        }
    }

    pub fn failure(&self) -> Option<String> {
        self.failure.lock().ok().and_then(|slot| slot.clone())
    }

    pub fn info(&self, event: &str, request_ref: Option<&str>, fields: Value) -> bool {
        self.write("info", event, request_ref, fields)
    }

    pub fn warn(&self, event: &str, request_ref: Option<&str>, fields: Value) -> bool {
        self.write("warn", event, request_ref, fields)
    }

    pub fn error(&self, event: &str, request_ref: Option<&str>, fields: Value) -> bool {
        self.write("error", event, request_ref, fields)
    }

    fn write(&self, level: &str, event: &str, request_ref: Option<&str>, fields: Value) -> bool {
        let line = json!({
            "at": iso_from_millis(now_millis()),
            "level": level,
            "instance_ref": self.instance_ref,
            "request_ref": request_ref,
            "event": event,
            "fields": redact_value(&fields),
        });
        let mut text = line.to_string();
        text.push('\n');
        let outcome = match self.file.lock() {
            Ok(mut guard) => match guard.as_mut() {
                Some(file) => file.write_all(text.as_bytes()).and_then(|_| file.flush()),
                None => return false,
            },
            Err(_) => return self.record_failure("日志句柄不可用"),
        };
        match outcome {
            Ok(()) => true,
            Err(error) => self.record_failure(&format!("日志写入失败：{error}")),
        }
    }

    fn record_failure(&self, detail: &str) -> bool {
        if let Ok(mut slot) = self.failure.lock() {
            if slot.is_none() {
                *slot = Some(detail.to_string());
                eprintln!("{}", json!({"event": "log.write_failed", "path": self.path.to_string_lossy(), "detail": detail}));
            }
        }
        false
    }
}

fn is_secret_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    SECRET_KEY_PARTS.iter().any(|part| lowered.contains(part))
}

pub fn redact_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut copy = Map::new();
            for (key, item) in map {
                if is_secret_key(key) {
                    copy.insert(key.clone(), json!("[REDACTED]"));
                } else {
                    copy.insert(key.clone(), redact_value(item));
                }
            }
            Value::Object(copy)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::String(text) => Value::String(redact_text(text)),
        other => other.clone(),
    }
}

/// 自由文本里的 `Bearer xxx`，以及 32 位以上连续的十六进制/Base64 串（令牌、密码哈希、凭据）一律遮盖。
pub fn redact_text(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut run = String::new();
    let mut pending_bearer = false;
    let flush = |run: &mut String, output: &mut String, force: bool| {
        if force || run.len() >= 32 {
            output.push_str("[REDACTED]");
        } else {
            output.push_str(run);
        }
        run.clear();
    };
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '_' | '-') {
            run.push(ch);
            continue;
        }
        let force = pending_bearer && !run.is_empty();
        if force {
            pending_bearer = false;
        }
        let is_bearer = run.eq_ignore_ascii_case("bearer");
        flush(&mut run, &mut output, force);
        if is_bearer {
            pending_bearer = true;
        }
        output.push(ch);
    }
    let force = pending_bearer && !run.is_empty();
    flush(&mut run, &mut output, force);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_fields_and_long_runs_are_masked() {
        let value = json!({
            "password": "synthetic-Passw0rd!",
            "nested": {"access_token": "abc", "note": "Bearer short-token-value"},
            "detail": "hash 0123456789abcdef0123456789abcdef0123 end"
        });
        let redacted = redact_value(&value).to_string();
        assert!(!redacted.contains("synthetic-Passw0rd!"));
        assert!(!redacted.contains("short-token-value"));
        assert!(!redacted.contains("0123456789abcdef0123456789abcdef0123"));
        assert!(redacted.contains("hash [REDACTED] end"));
    }
}
