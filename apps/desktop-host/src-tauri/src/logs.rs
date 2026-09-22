//! 本地日志：固定目录里固定命名的日志只读列举与读取、应用日志追加、诊断包导出与打开目录。
//!
//! - 读：宿主日志、控制端日志、产品网络服务的事件日志与内核日志（`core.log` 含访问明细，单独标出）。
//!   只列目录里直接放着的普通文件，名字按类别白名单匹配，不跟随链接，不接受页面给的路径。
//! - 写：只有两处——本进程的应用日志 `app-<时间>-<pid>.log`（按进程分文件，不覆盖上一轮），
//!   和日志目录下的 `exports/<导出编号>/`（新建，不覆盖）。工作区、保险库与服务状态都碰不到。
//! - 脱敏在页面侧用与归档同一份规则完成；这里只对应用日志的字段名做兜底遮盖。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::commands::{iso_from_millis, now_millis};

const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXPORT_BYTES: usize = 32 * 1024 * 1024;
const MAX_APP_FIELDS_BYTES: usize = 8 * 1024;
const MAX_FIELDS: usize = 32;
const MAX_FIELD_CHARS: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Category {
    Host,
    Control,
    NetworkService,
    NetworkCore,
}

const CATEGORIES: [Category; 4] = [Category::Host, Category::Control, Category::NetworkService, Category::NetworkCore];

impl Category {
    fn name(self) -> &'static str {
        match self {
            Category::Host => "host",
            Category::Control => "control",
            Category::NetworkService => "network_service",
            Category::NetworkCore => "network_core",
        }
    }

    fn parse(value: &str) -> Option<Category> {
        CATEGORIES.iter().copied().find(|category| category.name() == value)
    }

    fn accepts(self, file_name: &str) -> bool {
        match self {
            Category::Host => {
                safe_name(file_name) && file_name.ends_with(".log") && (file_name.starts_with("host-control-") || file_name.starts_with("app-"))
            }
            Category::Control => safe_name(file_name) && file_name.ends_with(".log") && file_name.starts_with("control-"),
            Category::NetworkService => file_name == "service.log" || file_name == "service.1.log",
            Category::NetworkCore => file_name == "core.log" || file_name == "core.1.log",
        }
    }

    fn contains_access_history(self) -> bool {
        self == Category::NetworkCore
    }
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 160
        && !name.starts_with('.')
        && !name.contains("..")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn modified_at(meta: &fs::Metadata) -> Option<String> {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|elapsed| iso_from_millis(elapsed.as_millis() as i64))
}

/// 日志目录：宿主（含应用日志与导出包）、控制端、产品网络服务。
pub struct LogDirs {
    pub host: PathBuf,
    pub control: PathBuf,
    pub service: PathBuf,
}

impl LogDirs {
    fn dir(&self, category: Category) -> &Path {
        match category {
            Category::Host => &self.host,
            Category::Control => &self.control,
            Category::NetworkService | Category::NetworkCore => &self.service,
        }
    }

    pub fn exports(&self) -> PathBuf {
        self.host.join("exports")
    }
}

/// 产品网络服务的日志目录：`%ProgramData%\<服务状态目录>\logs`，与服务自己的 `ServicePaths::log_dir` 同一处。
/// 安装器给批准用户开这个目录的只读权限；没开时列举会如实回 unreadable。
pub fn service_log_dir() -> PathBuf {
    let program_data = std::env::var_os("ProgramData")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    steward_service_ipc::ServicePaths::rooted(program_data.join(steward_service_ipc::core::paths::STATE_DIR_NAME), PathBuf::new()).log_dir()
}

pub fn log_sources(dirs: &LogDirs) -> Value {
    let mut sources: Vec<Value> = Vec::new();
    let mut directories: Vec<Value> = Vec::new();
    for category in CATEGORIES {
        let dir = dirs.dir(category);
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                directories.push(json!({"category": category.name(), "status": "missing"}));
                continue;
            }
            Err(error) => {
                directories.push(json!({"category": category.name(), "status": "unreadable", "reason": error.to_string()}));
                continue;
            }
        };
        directories.push(json!({"category": category.name(), "status": "found"}));
        let mut found: Vec<Value> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !category.accepts(&name) {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(entry.path()) else { continue };
            if !meta.is_file() {
                continue;
            }
            found.push(json!({
                "source_ref": format!("{}/{}", category.name(), name),
                "category": category.name(),
                "name": name,
                "size": meta.len(),
                "modified_at": modified_at(&meta),
                "contains_access_history": category.contains_access_history(),
            }));
        }
        found.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        sources.extend(found);
    }
    json!({"ok": true, "sources": sources, "directories": directories})
}

fn parse_source_ref(source_ref: &str) -> Result<(Category, String), String> {
    let (category, name) = source_ref
        .split_once('/')
        .ok_or_else(|| "NATIVE_PAYLOAD_INVALID: source_ref must be <category>/<file>".to_string())?;
    let category = Category::parse(category).ok_or_else(|| format!("NATIVE_PAYLOAD_INVALID: unknown log category {category}"))?;
    if !category.accepts(name) {
        return Err(format!("NATIVE_PAYLOAD_INVALID: {name} is not a {} log", category.name()));
    }
    Ok((category, name.to_string()))
}

/// 只读：打开时带读、写、删共享（std 在 Windows 上的默认），服务照常追加与轮转。
pub fn log_read(dirs: &LogDirs, source_ref: &str) -> Result<Value, String> {
    let (category, name) = parse_source_ref(source_ref)?;
    let path = dirs.dir(category).join(&name);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"ok": false, "code": "LOG_SOURCE_NOT_FOUND", "source_ref": source_ref}));
        }
        Err(error) => return Ok(json!({"ok": false, "code": "LOG_SOURCE_UNREADABLE", "source_ref": source_ref, "reason": error.to_string()})),
    };
    if !meta.is_file() {
        return Ok(json!({"ok": false, "code": "LOG_SOURCE_NOT_FILE", "source_ref": source_ref}));
    }
    if meta.len() > MAX_READ_BYTES {
        return Ok(json!({"ok": false, "code": "LOG_SOURCE_TOO_LARGE", "source_ref": source_ref, "size": meta.len()}));
    }
    match fs::read(&path) {
        Ok(bytes) => Ok(json!({
            "ok": true,
            "source_ref": source_ref,
            "size": bytes.len(),
            "modified_at": modified_at(&meta),
            "contains_access_history": category.contains_access_history(),
            "bytes": crate::workspace::encode_base64(&bytes),
        })),
        Err(error) => Ok(json!({"ok": false, "code": "LOG_SOURCE_UNREADABLE", "source_ref": source_ref, "reason": error.to_string()})),
    }
}

/// 本进程的应用日志：第一次写时按启动时刻与进程号定名，之后一直追加到同一个文件。
pub struct AppLog {
    dir: PathBuf,
    path: Mutex<Option<PathBuf>>,
}

impl AppLog {
    pub fn new(dir: PathBuf) -> AppLog {
        AppLog { dir, path: Mutex::new(None) }
    }

    pub fn append(&self, level: &str, event: &str, fields: &Map<String, Value>) -> Result<PathBuf, String> {
        let line = json!({
            "at": iso_from_millis(now_millis()),
            "level": level,
            "event": event,
            "pid": std::process::id(),
            "fields": fields,
        })
        .to_string();
        let mut slot = self.path.lock().map_err(|_| "APP_LOG_WRITE_FAILED: the application log is unavailable".to_string())?;
        let path = match slot.clone() {
            Some(path) => path,
            None => {
                let stamp = iso_from_millis(now_millis()).replace(['-', ':', '.'], "");
                let path = self.dir.join(format!("app-{stamp}-{}.log", std::process::id()));
                *slot = Some(path.clone());
                path
            }
        };
        fs::create_dir_all(&self.dir)
            .and_then(|_| OpenOptions::new().create(true).append(true).open(&path))
            .and_then(|mut file| {
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
                file.flush()
            })
            .map_err(|error| format!("APP_LOG_WRITE_FAILED: {error}"))?;
        Ok(path)
    }
}

fn secret_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    ["token", "password", "cookie", "secret", "authorization", "api_key", "apikey", "credential"]
        .iter()
        .any(|marker| lowered.contains(marker))
}

/// 页面流程的失败记录：事件名、级别与少量标量字段；秘密字段名一律遮盖，整行有上限。
pub fn app_log_append(log: &AppLog, payload: &Value) -> Result<Value, String> {
    let event = payload
        .get("event")
        .and_then(Value::as_str)
        .ok_or("NATIVE_PAYLOAD_INVALID: event is required")?;
    if event.is_empty()
        || event.len() > 64
        || !event.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err("NATIVE_PAYLOAD_INVALID: event must be a short lowercase name".into());
    }
    let level = payload.get("level").and_then(Value::as_str).unwrap_or("info");
    if !matches!(level, "info" | "warning" | "error") {
        return Err("NATIVE_PAYLOAD_INVALID: level must be info, warning or error".into());
    }
    let mut fields = Map::new();
    if let Some(given) = payload.get("fields") {
        let object = given.as_object().ok_or("NATIVE_PAYLOAD_INVALID: fields must be an object")?;
        if object.len() > MAX_FIELDS {
            return Err("NATIVE_PAYLOAD_INVALID: too many fields".into());
        }
        for (key, value) in object {
            let cleaned = if secret_key(key) {
                json!("[redacted]")
            } else {
                match value {
                    Value::String(text) => json!(text.chars().take(MAX_FIELD_CHARS).collect::<String>()),
                    Value::Number(_) | Value::Bool(_) | Value::Null => value.clone(),
                    _ => return Err(format!("NATIVE_PAYLOAD_INVALID: field {key} must be a string, number, boolean or null")),
                }
            };
            fields.insert(key.chars().take(64).collect(), cleaned);
        }
    }
    if serde_json::to_string(&fields).map(|text| text.len()).unwrap_or(usize::MAX) > MAX_APP_FIELDS_BYTES {
        return Err("NATIVE_PAYLOAD_INVALID: fields are too large".into());
    }
    match log.append(level, event, &fields) {
        Ok(path) => Ok(json!({"ok": true, "path": path.to_string_lossy()})),
        Err(error) => Ok(json!({"ok": false, "code": "APP_LOG_WRITE_FAILED", "reason": error})),
    }
}

fn error_code(text: &str) -> String {
    let head = text.split(':').next().unwrap_or("").trim();
    if !head.is_empty() && head.len() <= 64 && head.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
        head.to_string()
    } else {
        "NATIVE_ERROR".to_string()
    }
}

/// 每个失败的原生操作记一行：只有操作名与错误码，不记载荷、路径或原因正文。应用日志自己的失败不再回写。
pub fn record_outcome(log: &AppLog, op: &str, outcome: &Result<Value, String>) {
    if op == "AppLogAppend" {
        return;
    }
    let code = match outcome {
        Err(error) => Some(error_code(error)),
        Ok(value) if value.get("ok") == Some(&Value::Bool(false)) => {
            Some(error_code(value.get("code").and_then(Value::as_str).unwrap_or("NATIVE_OP_FAILED")))
        }
        Ok(_) => None,
    };
    if let Some(code) = code {
        let mut fields = Map::new();
        fields.insert("op".into(), json!(op));
        fields.insert("code".into(), json!(code));
        let _ = log.append("warning", "native.op_failed", &fields);
    }
}

/// 导出编号：`diag-YYYYMMDD-HHMMSS-<6—16 位十六进制>`。
fn valid_export_ref(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 4
        && parts[0] == "diag"
        && parts[1].len() == 8
        && parts[1].chars().all(|c| c.is_ascii_digit())
        && parts[2].len() == 6
        && parts[2].chars().all(|c| c.is_ascii_digit())
        && (6..=16).contains(&parts[3].len())
        && parts[3].chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn field<'a>(payload: &'a Value, name: &str) -> Result<&'a str, String> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("NATIVE_PAYLOAD_INVALID: {name} is required"))
}

/// 诊断包的一个文件：新建，不覆盖；写到一半失败就删掉半截，页面据此判定诊断包未生成。
pub fn export_write(dirs: &LogDirs, payload: &Value) -> Result<Value, String> {
    let export_ref = field(payload, "export_ref")?;
    if !valid_export_ref(export_ref) {
        return Err("NATIVE_PAYLOAD_INVALID: export_ref must look like diag-YYYYMMDD-HHMMSS-<hex>".into());
    }
    let name = field(payload, "name")?;
    if !safe_name(name) {
        return Err("NATIVE_PAYLOAD_INVALID: export file name is not allowed".into());
    }
    let bytes = crate::workspace::decode_base64(field(payload, "bytes").unwrap_or(""))?;
    if bytes.len() > MAX_EXPORT_BYTES {
        return Err("NATIVE_PAYLOAD_INVALID: export file is too large".into());
    }
    let dir = dirs.exports().join(export_ref);
    let path = dir.join(name);
    let created = fs::create_dir_all(&dir).and_then(|_| OpenOptions::new().write(true).create_new(true).open(&path));
    let mut file = match created {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(json!({"ok": false, "code": "LOG_EXPORT_EXISTS", "name": name}));
        }
        Err(error) => return Ok(json!({"ok": false, "code": "LOG_EXPORT_WRITE_FAILED", "name": name, "reason": error.to_string()})),
    };
    let outcome = file.write_all(&bytes).and_then(|_| file.sync_all());
    if let Err(error) = outcome {
        drop(file);
        let _ = fs::remove_file(&path);
        return Ok(json!({"ok": false, "code": "LOG_EXPORT_WRITE_FAILED", "name": name, "reason": error.to_string()}));
    }
    Ok(json!({"ok": true, "path": path.to_string_lossy(), "size": bytes.len()}))
}

/// 打开目录：用系统文件管理器显示，不读不改里面的内容。
pub trait FolderOpener: Send + Sync {
    fn open(&self, path: &Path) -> Result<(), String>;
}

pub struct SystemFolderOpener;

impl FolderOpener for SystemFolderOpener {
    fn open(&self, path: &Path) -> Result<(), String> {
        let explorer = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("explorer.exe");
        std::process::Command::new(explorer)
            .arg(path)
            .spawn()
            .map(|_| ())
            .map_err(|error| format!("LOG_FOLDER_OPEN_FAILED: {error}"))
    }
}

/// 宿主自身测试用：只记下要打开的目录，不启动文件管理器。
#[derive(Default)]
pub struct RecordingOpener {
    pub opened: Mutex<Vec<PathBuf>>,
}

impl FolderOpener for RecordingOpener {
    fn open(&self, path: &Path) -> Result<(), String> {
        self.opened
            .lock()
            .map_err(|_| "LOG_FOLDER_OPEN_FAILED: recorder unavailable".to_string())?
            .push(path.to_path_buf());
        Ok(())
    }
}

pub fn open_folder(dirs: &LogDirs, opener: &dyn FolderOpener, payload: &Value) -> Result<Value, String> {
    let target = payload.get("target").and_then(Value::as_str).unwrap_or("logs");
    let path = match target {
        "logs" => {
            fs::create_dir_all(&dirs.host).map_err(|error| format!("LOG_FOLDER_OPEN_FAILED: {error}"))?;
            dirs.host.clone()
        }
        "export" => {
            let export_ref = field(payload, "export_ref")?;
            if !valid_export_ref(export_ref) {
                return Err("NATIVE_PAYLOAD_INVALID: export_ref must look like diag-YYYYMMDD-HHMMSS-<hex>".into());
            }
            let path = dirs.exports().join(export_ref);
            if !path.is_dir() {
                return Ok(json!({"ok": false, "code": "LOG_EXPORT_NOT_FOUND"}));
            }
            path
        }
        _ => return Err("NATIVE_PAYLOAD_INVALID: target must be logs or export".into()),
    };
    opener.open(&path)?;
    Ok(json!({"ok": true, "path": path.to_string_lossy()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("steward-logs-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn dirs(base: &Path) -> LogDirs {
        LogDirs { host: base.join("logs"), control: base.join("control").join("logs"), service: base.join("service").join("logs") }
    }

    #[test]
    fn sources_list_only_whitelisted_files_and_mark_access_history() {
        let base = root("list");
        let dirs = dirs(&base);
        fs::create_dir_all(&dirs.service).unwrap();
        fs::create_dir_all(&dirs.host).unwrap();
        fs::write(dirs.service.join("core.log"), "time=\"t\" level=info msg=\"x\"\n").unwrap();
        fs::write(dirs.service.join("service.log"), "{}\n").unwrap();
        fs::write(dirs.service.join("runtime-state.json"), "{}").unwrap();
        fs::write(dirs.host.join("host-control-20260917T000000000Z-1.log"), "{}\n").unwrap();
        fs::write(dirs.host.join("notes.txt"), "x").unwrap();
        let listed = log_sources(&dirs);
        let refs: Vec<&str> = listed["sources"].as_array().unwrap().iter().map(|item| item["source_ref"].as_str().unwrap()).collect();
        assert_eq!(refs, vec!["host/host-control-20260917T000000000Z-1.log", "network_service/service.log", "network_core/core.log"]);
        let core = listed["sources"].as_array().unwrap().iter().find(|item| item["category"] == "network_core").unwrap();
        assert_eq!(core["contains_access_history"], true);
        assert!(listed["directories"].as_array().unwrap().iter().any(|item| item["category"] == "control" && item["status"] == "missing"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn reads_are_confined_to_the_whitelist() {
        let base = root("read");
        let dirs = dirs(&base);
        fs::create_dir_all(&dirs.service).unwrap();
        fs::write(dirs.service.join("core.log"), "line\n").unwrap();
        let read = log_read(&dirs, "network_core/core.log").unwrap();
        assert_eq!(read["ok"], true);
        assert_eq!(crate::workspace::decode_base64(read["bytes"].as_str().unwrap()).unwrap(), b"line\n".to_vec());
        assert_eq!(log_read(&dirs, "network_core/core.1.log").unwrap()["code"], "LOG_SOURCE_NOT_FOUND");
        assert!(log_read(&dirs, "network_core/../link/host-link.key").unwrap_err().starts_with("NATIVE_PAYLOAD_INVALID"));
        assert!(log_read(&dirs, "network_core/runtime-state.json").unwrap_err().starts_with("NATIVE_PAYLOAD_INVALID"));
        assert!(log_read(&dirs, "workspace/records.json").unwrap_err().starts_with("NATIVE_PAYLOAD_INVALID"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn app_log_appends_per_process_masks_secret_fields_and_records_failed_ops() {
        let base = root("app");
        let log = AppLog::new(base.join("logs"));
        let written = app_log_append(&log, &json!({"event": "ui.action_failed", "level": "error", "fields": {"action": "exportDaily", "code": "REPORT_MISSING", "access_token": "abc"}})).unwrap();
        assert_eq!(written["ok"], true);
        record_outcome(&log, "FileRead", &Err("NATIVE_PATH_OUT_OF_SCOPE: C:\\Users\\someone\\secret".to_string()));
        record_outcome(&log, "ReadNetworkState", &Ok(json!({"ok": false, "code": "SERVICE_UNREACHABLE"})));
        record_outcome(&log, "FileExists", &Ok(json!({"ok": true})));
        let path = PathBuf::from(written["path"].as_str().unwrap());
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<Value> = text.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(lines.len(), 3, "成功的操作不记");
        assert_eq!(lines[0]["fields"]["access_token"], "[redacted]");
        assert_eq!(lines[1]["fields"], json!({"op": "FileRead", "code": "NATIVE_PATH_OUT_OF_SCOPE"}), "只记错误码，不记路径");
        assert_eq!(lines[2]["fields"]["code"], "SERVICE_UNREACHABLE");
        assert!(path.file_name().unwrap().to_string_lossy().starts_with("app-"));
        assert!(app_log_append(&log, &json!({"event": "Bad Event"})).unwrap_err().starts_with("NATIVE_PAYLOAD_INVALID"));
        assert!(app_log_append(&log, &json!({"event": "x", "fields": {"nested": {"a": 1}}})).unwrap_err().starts_with("NATIVE_PAYLOAD_INVALID"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn exports_are_new_files_under_the_export_folder_only() {
        let base = root("export");
        let dirs = dirs(&base);
        let payload = json!({"export_ref": "diag-20260917-120000-a1b2c3", "name": "manifest.json", "bytes": crate::workspace::encode_base64(b"{}")});
        let written = export_write(&dirs, &payload).unwrap();
        assert_eq!(written["ok"], true);
        assert!(PathBuf::from(written["path"].as_str().unwrap()).starts_with(dirs.exports()));
        assert_eq!(export_write(&dirs, &payload).unwrap()["code"], "LOG_EXPORT_EXISTS", "不覆盖");
        let escape = json!({"export_ref": "diag-20260917-120000-a1b2c3", "name": "..\\..\\x.log", "bytes": ""});
        assert!(export_write(&dirs, &escape).unwrap_err().starts_with("NATIVE_PAYLOAD_INVALID"));
        let bad_ref = json!({"export_ref": "../../vault", "name": "a.log", "bytes": ""});
        assert!(export_write(&dirs, &bad_ref).unwrap_err().starts_with("NATIVE_PAYLOAD_INVALID"));
        let opener = RecordingOpener::default();
        assert_eq!(open_folder(&dirs, &opener, &json!({"target": "export", "export_ref": "diag-20260917-120000-a1b2c3"})).unwrap()["ok"], true);
        assert_eq!(open_folder(&dirs, &opener, &json!({"target": "export", "export_ref": "diag-20260917-120001-a1b2c3"})).unwrap()["code"], "LOG_EXPORT_NOT_FOUND");
        assert_eq!(opener.opened.lock().unwrap().len(), 1);
        let _ = fs::remove_dir_all(&base);
    }
}
