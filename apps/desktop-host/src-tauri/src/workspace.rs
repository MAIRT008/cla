//! 受限本地能力：文件、记录库与第三方数据库。
//!
//! 契约见 `apps/desktop-host/bridge-contract.mjs`。这里只做原生边界：
//! 路径收窄、字节读写、记录落盘和固定格式数据库的读改恢复；
//! 分类、计划、授权判断与恢复选择仍在 WebView 里的业务模块。
//!
//! 本文件尚未在本机编译：仓库内没有 cargo/rustc，见 evidence/delivery/build-packaging.md。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use rusqlite::types::ValueRef;
use rusqlite::{params, params_from_iter, Connection, OpenFlags};
use serde_json::{json, Map, Value};

pub use crate::roots::Scope;

/// 单次遍历最多列出的条目数：真实目录可能很大，到上限就停，并把截断作为缺口回报，不假装列全了。
const MAX_WALK_ENTRIES: usize = 20_000;

const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64[(triple >> 18) as usize & 63] as char);
        out.push(BASE64[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { BASE64[(triple >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { BASE64[triple as usize & 63] as char } else { '=' });
    }
    out
}

pub fn decode_base64(text: &str) -> Result<Vec<u8>, String> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for character in text.bytes() {
        if character == b'=' || character == b'\n' || character == b'\r' {
            continue;
        }
        let value = BASE64
            .iter()
            .position(|item| *item == character)
            .ok_or_else(|| "base64 payload contains an unsupported character".to_string())?;
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// 把相对路径收窄到已授权的工作区内：拒绝绝对路径、`..` 与任何链接。
pub fn resolve(root: &Path, relative: &str) -> Result<PathBuf, String> {
    if relative.is_empty() {
        return Err("NATIVE_PATH_OUT_OF_SCOPE: path must not be empty".into());
    }
    let candidate = Path::new(relative);
    if candidate.is_absolute() {
        return Err("NATIVE_PATH_OUT_OF_SCOPE: path must be relative".into());
    }
    let mut resolved = root.to_path_buf();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            _ => return Err("NATIVE_PATH_OUT_OF_SCOPE: path escapes the authorized workspace".into()),
        }
    }
    if !resolved.starts_with(root) {
        return Err("NATIVE_PATH_OUT_OF_SCOPE: path escapes the authorized workspace".into());
    }
    let mut cursor = root.to_path_buf();
    if fs::symlink_metadata(&cursor).map(|meta| meta.file_type().is_symlink()).unwrap_or(false) {
        return Err("NATIVE_PATH_OUT_OF_SCOPE: workspace root cannot be a link".into());
    }
    for component in candidate.components() {
        if let Component::Normal(part) = component {
            cursor.push(part);
            if let Ok(meta) = fs::symlink_metadata(&cursor) {
                if meta.file_type().is_symlink() {
                    return Err("NATIVE_PATH_OUT_OF_SCOPE: links are not supported".into());
                }
            }
        }
    }
    Ok(resolved)
}

fn ensure_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    }
    Ok(())
}

pub fn file_read(scope: &Scope, relative: &str) -> Result<Value, String> {
    let target = scope.resolve(relative)?;
    let bytes = fs::read(&target).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(json!({"ok": true, "bytes": encode_base64(&bytes)}))
}

pub fn file_write(scope: &Scope, relative: &str, encoded: &str) -> Result<Value, String> {
    let target = scope.resolve(relative)?;
    ensure_parent(&target)?;
    let bytes = decode_base64(encoded)?;
    fs::write(&target, bytes).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(json!({"ok": true}))
}

pub fn file_remove(scope: &Scope, relative: &str) -> Result<Value, String> {
    let target = scope.resolve(relative)?;
    match fs::symlink_metadata(&target) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(&target).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?,
        Ok(_) => fs::remove_file(&target).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?,
        Err(_) => {}
    }
    Ok(json!({"ok": true}))
}

pub fn file_copy(scope: &Scope, from: &str, to: &str) -> Result<Value, String> {
    let source = scope.resolve(from)?;
    let target = scope.resolve(to)?;
    ensure_parent(&target)?;
    fs::copy(&source, &target).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(json!({"ok": true}))
}

pub fn file_exists(scope: &Scope, relative: &str) -> Result<Value, String> {
    let target = scope.resolve(relative)?;
    Ok(json!({"ok": true, "exists": fs::symlink_metadata(&target).is_ok()}))
}

fn walk_into(scope: &Scope, relative: &str, entries: &mut Vec<Value>) -> Result<(), String> {
    if entries.len() >= MAX_WALK_ENTRIES {
        return Ok(());
    }
    let target = match scope.resolve(relative) {
        Ok(value) => value,
        Err(error) => {
            entries.push(json!({"relative_path": relative, "status": "unreadable", "error": error}));
            return Ok(());
        }
    };
    // 前缀本身就是一个文件（单文件授权根，或扫描前缀直指某个库文件）：列出它自己。
    if let Ok(meta) = fs::symlink_metadata(&target) {
        if meta.file_type().is_symlink() {
            entries.push(json!({"relative_path": relative, "status": "unsupported_link"}));
            return Ok(());
        }
        if meta.is_file() {
            entries.push(json!({"relative_path": relative, "status": "found", "size": meta.len()}));
            return Ok(());
        }
    }
    let read = match fs::read_dir(&target) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            entries.push(json!({"relative_path": relative, "status": "missing"}));
            return Ok(());
        }
        Err(error) => {
            entries.push(json!({"relative_path": relative, "status": "unreadable", "error": error.to_string()}));
            return Ok(());
        }
    };
    let mut names: Vec<String> = Vec::new();
    for item in read {
        let item = item.map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        names.push(item.file_name().to_string_lossy().to_string());
    }
    names.sort();
    for name in names {
        if entries.len() >= MAX_WALK_ENTRIES {
            entries.push(json!({"relative_path": relative, "status": "walk_limit"}));
            return Ok(());
        }
        let child_relative = format!("{relative}/{name}");
        let child = target.join(&name);
        let meta = fs::symlink_metadata(&child).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        if meta.file_type().is_symlink() {
            entries.push(json!({"relative_path": child_relative, "status": "unsupported_link"}));
        } else if meta.is_dir() {
            walk_into(scope, &child_relative, entries)?;
        } else if meta.is_file() {
            entries.push(json!({"relative_path": child_relative, "status": "found", "size": meta.len()}));
        }
    }
    Ok(())
}

pub fn file_walk(scope: &Scope, prefixes: &[Value]) -> Result<Value, String> {
    let mut entries = Vec::new();
    for prefix in prefixes {
        let relative = prefix.as_str().ok_or("NATIVE_PAYLOAD_INVALID: prefixes must be strings")?;
        walk_into(scope, relative, &mut entries)?;
    }
    Ok(json!({"ok": true, "entries": entries}))
}

fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    for item in fs::read_dir(source).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))? {
        let item = item.map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        let meta = item.metadata().map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        let child_target = target.join(item.file_name());
        if meta.is_dir() {
            copy_tree(&item.path(), &child_target)?;
        } else {
            fs::copy(item.path(), &child_target).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        }
    }
    Ok(())
}

pub fn dir_isolate(scope: &Scope, from: &str, to: &str) -> Result<Value, String> {
    let source = scope.resolve(from)?;
    let target = scope.resolve(to)?;
    if !source.is_dir() {
        return Err("UNSUPPORTED_FORMAT: directory isolation target is not a directory".into());
    }
    if fs::symlink_metadata(&target).is_ok() {
        return Err("CONFLICT: isolation target already exists".into());
    }
    ensure_parent(&target)?;
    copy_tree(&source, &target)?;
    fs::remove_dir_all(&source).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(json!({"ok": true}))
}

fn tree_entries(base: &Path, current: &Path, out: &mut Vec<String>) -> Result<(), String> {
    for item in fs::read_dir(current).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))? {
        let item = item.map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        let meta = item.metadata().map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        if meta.is_dir() {
            tree_entries(base, &item.path(), out)?;
        } else {
            let relative = item.path().strip_prefix(base).map_err(|error| error.to_string())?.to_string_lossy().replace('\\', "/");
            out.push(relative);
        }
    }
    Ok(())
}

pub fn dir_preview_restore(scope: &Scope, isolation: &str, target_path: &str) -> Result<Value, String> {
    let isolation_root = scope.resolve(isolation)?;
    let target = scope.resolve(target_path)?;
    let mut stored = Vec::new();
    if isolation_root.is_dir() {
        tree_entries(&isolation_root, &isolation_root, &mut stored)?;
    }
    let mut present = Vec::new();
    if target.is_dir() {
        tree_entries(&target, &target, &mut present)?;
    }
    stored.sort();
    present.sort();
    let conflicts: Vec<Value> = present
        .iter()
        .filter(|item| stored.contains(item))
        .map(|item| json!({"code": "RESTORE_CONFLICT", "path": item}))
        .collect();
    Ok(json!({
        "ok": true,
        "recoverable": conflicts.is_empty(),
        "conflicts": conflicts,
        "entries": stored
    }))
}

pub fn dir_restore(scope: &Scope, isolation: &str, target_path: &str) -> Result<Value, String> {
    let preview = dir_preview_restore(scope, isolation, target_path)?;
    if preview.get("recoverable").and_then(Value::as_bool) != Some(true) {
        return Err("RESTORE_CONFLICT: isolated directory cannot be restored without overwrite".into());
    }
    let isolation_root = scope.resolve(isolation)?;
    let target = scope.resolve(target_path)?;
    copy_tree(&isolation_root, &target)?;
    Ok(json!({"ok": true, "restored": preview.get("entries").cloned().unwrap_or(Value::Null)}))
}

fn records_path(root: &Path) -> Result<PathBuf, String> {
    resolve(root, "state/native-records.json")
}

fn read_records(root: &Path) -> Result<Value, String> {
    let path = records_path(root)?;
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map_err(|error| format!("NATIVE_IO_FAILED: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({"records": [], "backups": []})),
        Err(error) => Err(format!("NATIVE_IO_FAILED: {error}")),
    }
}

fn write_records(root: &Path, value: &Value) -> Result<(), String> {
    let path = records_path(root)?;
    ensure_parent(&path)?;
    let text = serde_json::to_string_pretty(value).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    fs::write(&path, format!("{text}\n")).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))
}

pub fn records_load(root: &Path) -> Result<Value, String> {
    let store = read_records(root)?;
    Ok(json!({
        "ok": true,
        "records": store.get("records").cloned().unwrap_or(json!([])),
        "backups": store.get("backups").cloned().unwrap_or(json!([]))
    }))
}

pub fn record_save(root: &Path, kind: &str, id: &str, payload: &Value, now: &str) -> Result<Value, String> {
    let mut store = read_records(root)?;
    let records = store.get_mut("records").and_then(Value::as_array_mut).ok_or("NATIVE_IO_FAILED: records store is malformed")?;
    let existing = records
        .iter()
        .position(|row| row.get("type").and_then(Value::as_str) == Some(kind) && row.get("id").and_then(Value::as_str) == Some(id));
    let created = existing
        .and_then(|index| records[index].get("created_at").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| now.to_string());
    let row = json!({"type": kind, "id": id, "payload": payload, "created_at": created, "updated_at": now});
    match existing {
        Some(index) => records[index] = row,
        None => records.push(row),
    }
    write_records(root, &store)?;
    Ok(json!({"ok": true}))
}

pub fn backup_save(root: &Path, backup_ref: &str, action_id: &str, payload_path: &str, metadata: &Value, now: &str) -> Result<Value, String> {
    let mut store = read_records(root)?;
    let backups = store.get_mut("backups").and_then(Value::as_array_mut).ok_or("NATIVE_IO_FAILED: backup store is malformed")?;
    backups.retain(|row| row.get("backup_ref").and_then(Value::as_str) != Some(backup_ref));
    backups.push(json!({
        "backup_ref": backup_ref,
        "action_id": action_id,
        "payload_path": payload_path,
        "metadata": metadata,
        "created_at": now
    }));
    write_records(root, &store)?;
    Ok(json!({"ok": true}))
}

fn open_database(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))
}

/// 检查阶段只读打开：不在用户的真实库上触发日志回滚或任何写入。浏览器占着库时如实报错，由核心记成缺口。
fn open_database_read_only(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))
}

/// URL 的主机名（小写）；认不出就是没有。只用于报告第三方端点，不校验可达。
fn url_host(text: &str) -> Option<String> {
    let rest = text.trim().split_once("://").map(|(_, rest)| rest)?;
    let authority = rest.split(|character: char| character == '/' || character == '?' || character == '#').next()?;
    let host_port = authority.rsplit_once('@').map(|(_, host)| host).unwrap_or(authority);
    let host = if host_port.starts_with('[') {
        host_port.split_once(']').map(|(host, _)| format!("{host}]"))?
    } else {
        host_port.split(':').next()?.to_string()
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn non_empty(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).map(|text| !text.trim().is_empty()).unwrap_or(false)
}

fn assert_cc_switch(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| format!("UNSUPPORTED_FORMAT: {error}"))?;
    if version != 18 {
        return Err(format!("UNSUPPORTED_FORMAT: CC Switch schema version {version} is not supported"));
    }
    Ok(())
}

fn assert_cookie_schema(connection: &Connection) -> Result<(), String> {
    let mut statement = connection
        .prepare("SELECT key, value FROM meta WHERE key IN ('version', 'last_compatible_version')")
        .map_err(|error| format!("UNSUPPORTED_FORMAT: {error}"))?;
    let mut versions = BTreeMap::new();
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|error| format!("UNSUPPORTED_FORMAT: {error}"))?;
    for row in rows {
        let (key, value) = row.map_err(|error| format!("UNSUPPORTED_FORMAT: {error}"))?;
        versions.insert(key, value);
    }
    if versions.get("version").map(String::as_str) != Some("24") || versions.get("last_compatible_version").map(String::as_str) != Some("24") {
        return Err("UNSUPPORTED_FORMAT: Chromium cookie schema version 24 is required".into());
    }
    Ok(())
}

const COOKIE_KEY_SQL: &str =
    "name = ?1 AND host_key = ?2 AND top_frame_site_key = ?3 AND path = ?4 AND source_scheme = ?5 AND source_port = ?6 AND has_cross_site_ancestor = ?7";

fn cookie_key_params(selector: &Map<String, Value>) -> Vec<Value> {
    ["name", "host_key", "top_frame_site_key", "path", "source_scheme", "source_port", "has_cross_site_ancestor"]
        .iter()
        .map(|field| selector.get(*field).cloned().unwrap_or(Value::Null))
        .collect()
}

fn bind(values: &[Value]) -> Vec<rusqlite::types::Value> {
    values
        .iter()
        .map(|value| match value {
            Value::Null => rusqlite::types::Value::Null,
            Value::Bool(item) => rusqlite::types::Value::Integer(i64::from(*item)),
            Value::Number(item) => item
                .as_i64()
                .map(rusqlite::types::Value::Integer)
                .unwrap_or_else(|| rusqlite::types::Value::Real(item.as_f64().unwrap_or_default())),
            other => rusqlite::types::Value::Text(other.as_str().map(str::to_string).unwrap_or_else(|| other.to_string())),
        })
        .collect()
}

pub fn db_inspect(scope: &Scope, relative: &str, kind: &str) -> Result<Value, String> {
    let path = scope.resolve(relative)?;
    let connection = open_database_read_only(&path)?;
    if kind == "cc_switch_sqlite" {
        assert_cc_switch(&connection)?;
        let mut statement = connection
            .prepare("SELECT id, app_type, name, settings_config, is_current FROM providers ORDER BY id, app_type")
            .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        let mut providers = Vec::new();
        for row in rows {
            let (id, app_type, name, configuration, current) = row.map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
            let parsed: Value = serde_json::from_str(&configuration).unwrap_or(Value::Null);
            let env = parsed.get("env");
            // 只回报非机密事实：端点主机与「是否带凭据」，Token 本身不离开这个函数。
            let endpoint_host = env.and_then(|value| value.get("ANTHROPIC_BASE_URL")).and_then(Value::as_str).and_then(url_host);
            let credential_present = non_empty(env.and_then(|value| value.get("ANTHROPIC_AUTH_TOKEN")))
                || non_empty(env.and_then(|value| value.get("ANTHROPIC_API_KEY")));
            providers.push(json!({
                "provider_id": id,
                "app_type": app_type,
                "name": name,
                "is_current": current == Some(1),
                "endpoint_host": endpoint_host,
                "credential_present": credential_present,
                "identity_ref": parsed.get("identity_ref").or_else(|| parsed.get("identityRef")).cloned().unwrap_or(Value::Null),
                "protected_usage": configuration.contains("project") || configuration.contains("memory")
            }));
        }
        return Ok(json!({"ok": true, "schema_version": 18, "providers": providers}));
    }
    if kind == "cookie_sqlite" {
        assert_cookie_schema(&connection)?;
        let mut statement = connection
            .prepare("SELECT host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port FROM cookies")
            .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        let rows = statement
            .query_map([], |row| {
                Ok(json!({
                    "host_key": row.get::<_, String>(0)?,
                    "top_frame_site_key": row.get::<_, String>(1)?,
                    "has_cross_site_ancestor": row.get::<_, i64>(2)?,
                    "name": row.get::<_, String>(3)?,
                    "path": row.get::<_, String>(4)?,
                    "source_scheme": row.get::<_, i64>(5)?,
                    "source_port": row.get::<_, i64>(6)?
                }))
            })
            .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        let mut cookies = Vec::new();
        for row in rows {
            cookies.push(row.map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?);
        }
        return Ok(json!({"ok": true, "schema_version": 24, "cookies": cookies}));
    }
    Err("UNSUPPORTED_FORMAT: database adapter is not declared for this format".into())
}

pub fn db_mutate(scope: &Scope, relative: &str, kind: &str, selector: &Value) -> Result<Value, String> {
    let path = scope.resolve(relative)?;
    let connection = open_database(&path)?;
    let selector = selector.as_object().ok_or("NATIVE_PAYLOAD_INVALID: selector must be an object")?;
    if kind == "cc_provider_delete" {
        assert_cc_switch(&connection)?;
        let provider = selector.get("provider_id").cloned().unwrap_or(Value::Null);
        let app_type = selector.get("app_type").cloned().unwrap_or(Value::Null);
        let endpoints = connection
            .execute("DELETE FROM provider_endpoints WHERE provider_id = ?1 AND app_type = ?2", params_from_iter(bind(&[provider.clone(), app_type.clone()])))
            .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        let changed = connection
            .execute("DELETE FROM providers WHERE id = ?1 AND app_type = ?2", params_from_iter(bind(&[provider, app_type])))
            .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        return Ok(json!({"ok": true, "changed": changed, "endpoints": endpoints}));
    }
    if kind == "cookie_delete" {
        assert_cookie_schema(&connection)?;
        let changed = connection
            .execute(&format!("DELETE FROM cookies WHERE {COOKIE_KEY_SQL}"), params_from_iter(bind(&cookie_key_params(selector))))
            .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        return Ok(json!({"ok": true, "changed": changed}));
    }
    Err("UNSUPPORTED_FORMAT: database action is not declared".into())
}

fn sqlite_failed(error: rusqlite::Error) -> String {
    format!("NATIVE_IO_FAILED: {error}")
}

/// 数据库的逻辑指纹：`user_version`、结构（sqlite_master）与每张表的全部行（按全部列排序）取 SHA-256。
/// 经 SQLite 读取，WAL 里已提交的内容一并算在内；与页面布局、主文件字节和 rowid 无关，
/// 所以一致快照、快照上的模拟结果与原库改写后的状态可以直接比较。
fn logical_digest(connection: &Connection) -> Result<String, String> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0)).map_err(sqlite_failed)?;
    let mut text = format!("user_version={version}\n");
    let mut schema = connection
        .prepare("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
        .map_err(sqlite_failed)?;
    let entries: Vec<(String, String, Option<String>)> = schema
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?)))
        .map_err(sqlite_failed)?
        .collect::<Result<_, _>>()
        .map_err(sqlite_failed)?;
    for (kind, name, sql) in &entries {
        text.push_str(&format!("{kind}\t{name}\t{}\n", sql.as_deref().unwrap_or("")));
    }
    for (kind, name, _) in &entries {
        if kind != "table" {
            continue;
        }
        let quoted = format!("\"{}\"", name.replace('"', "\"\""));
        let columns = connection.prepare(&format!("SELECT * FROM {quoted} LIMIT 0")).map_err(sqlite_failed)?.column_count();
        let order: Vec<String> = (1..=columns).map(|index| index.to_string()).collect();
        let mut statement = connection
            .prepare(&format!("SELECT * FROM {quoted} ORDER BY {}", order.join(", ")))
            .map_err(sqlite_failed)?;
        let mut rows = statement.query([]).map_err(sqlite_failed)?;
        text.push_str(&format!("rows\t{name}\n"));
        while let Some(row) = rows.next().map_err(sqlite_failed)? {
            let mut cells: Vec<String> = Vec::with_capacity(columns);
            for index in 0..columns {
                cells.push(match row.get_ref(index).map_err(sqlite_failed)? {
                    ValueRef::Null => "n".to_string(),
                    ValueRef::Integer(value) => format!("i:{value}"),
                    ValueRef::Real(value) => format!("r:{value:?}"),
                    ValueRef::Text(bytes) => format!("t:{}", encode_base64(bytes)),
                    ValueRef::Blob(bytes) => format!("b:{}", encode_base64(bytes)),
                });
            }
            text.push_str(&cells.join("\t"));
            text.push('\n');
        }
    }
    Ok(sha256_hex(text.as_bytes()))
}

pub fn fingerprint_database(scope: &Scope, relative: &str) -> Result<String, String> {
    let path = scope.resolve(relative)?;
    logical_digest(&open_database_read_only(&path)?)
}

/// 一致快照：只读连接上 `VACUUM INTO` 一个新文件，WAL 里已提交的内容都在里面，得到的是独立的单文件库。
/// 库被占用、只读打不开或写不出快照时报 DB_SNAPSHOT_UNAVAILABLE，调用方据此拒绝执行，不退回复制主文件。
fn snapshot_to(source: &Path, target: &Path) -> Result<(), String> {
    ensure_parent(target)?;
    let connection = open_database_read_only(source).map_err(|error| format!("DB_SNAPSHOT_UNAVAILABLE: {error}"))?;
    connection
        .execute("VACUUM INTO ?1", params![target.to_string_lossy().into_owned()])
        .map_err(|error| format!("DB_SNAPSHOT_UNAVAILABLE: {error}"))?;
    Ok(())
}

/// 备份用的一致快照：回快照字节与快照的逻辑指纹，核心拿指纹核对确认时的改前状态。
pub fn db_snapshot(scope: &Scope, relative: &str) -> Result<Value, String> {
    let source = scope.resolve(relative)?;
    let snapshot = scope.resolve(&format!("state/snapshot-{}.sqlite", uuid_like()))?;
    let outcome = snapshot_to(&source, &snapshot).and_then(|_| {
        let digest = logical_digest(&open_database_read_only(&snapshot)?)?;
        let bytes = fs::read(&snapshot).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        Ok(json!({"ok": true, "bytes": encode_base64(&bytes), "sha256": digest}))
    });
    let _ = fs::remove_file(&snapshot);
    outcome
}

/// 在一致快照上试跑改写并回报结果的逻辑指纹；原对象不动。prior 是计划里排在前面、改同一个库的改写，先依次应用。
pub fn db_simulate(scope: &Scope, relative: &str, kind: &str, selector: &Value, prior: &[Value]) -> Result<Value, String> {
    let source = scope.resolve(relative)?;
    let simulation_relative = format!("state/sim-{}.sqlite", uuid_like());
    let simulation = scope.resolve(&simulation_relative)?;
    let outcome = snapshot_to(&source, &simulation).and_then(|_| {
        for step in prior {
            let step_kind = step.get("kind").and_then(Value::as_str).unwrap_or_default();
            let step_selector = step.get("selector").cloned().unwrap_or(Value::Null);
            db_mutate(scope, &simulation_relative, step_kind, &step_selector)?;
        }
        db_mutate(scope, &simulation_relative, kind, selector)?;
        logical_digest(&open_database_read_only(&simulation)?)
    });
    let _ = fs::remove_file(&simulation);
    Ok(json!({"ok": true, "sha256": outcome?}))
}

pub fn db_preview_restore(scope: &Scope, relative: &str, kind: &str, selector: &Value, backup: &str) -> Result<Value, String> {
    let selector = selector.as_object().ok_or("NATIVE_PAYLOAD_INVALID: selector must be an object")?;
    let backup_relative = format!("state/restore-source-{}.sqlite", uuid_like());
    let backup_path = scope.resolve(&backup_relative)?;
    ensure_parent(&backup_path)?;
    fs::write(&backup_path, decode_base64(backup)?).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let target_path = scope.resolve(relative)?;
    let source = open_database(&backup_path)?;
    let target = open_database_read_only(&target_path)?;
    let result = preview_rows(&source, &target, kind, selector);
    drop(source);
    drop(target);
    let _ = fs::remove_file(&backup_path);
    result
}

fn preview_rows(source: &Connection, target: &Connection, kind: &str, selector: &Map<String, Value>) -> Result<Value, String> {
    let (sql, values) = if kind == "cc_provider_delete" {
        assert_cc_switch(source)?;
        assert_cc_switch(target)?;
        (
            "SELECT 1 FROM providers WHERE id = ?1 AND app_type = ?2".to_string(),
            vec![selector.get("provider_id").cloned().unwrap_or(Value::Null), selector.get("app_type").cloned().unwrap_or(Value::Null)],
        )
    } else if kind == "cookie_delete" {
        assert_cookie_schema(source)?;
        assert_cookie_schema(target)?;
        (format!("SELECT 1 FROM cookies WHERE {COOKIE_KEY_SQL}"), cookie_key_params(selector))
    } else {
        return Err("UNSUPPORTED_FORMAT: database restore is not declared".into());
    };
    let in_source = source
        .query_row(&sql, params_from_iter(bind(&values)), |_| Ok(true))
        .unwrap_or(false);
    let in_target = target
        .query_row(&sql, params_from_iter(bind(&values)), |_| Ok(true))
        .unwrap_or(false);
    let conflicts = if in_source && in_target {
        vec![json!({"code": "RESTORE_CONFLICT", "message": "record key now exists"})]
    } else {
        Vec::new()
    };
    Ok(json!({"ok": true, "recoverable": in_source && !in_target, "conflicts": conflicts}))
}

pub fn db_restore(scope: &Scope, relative: &str, kind: &str, selector: &Value, backup: &str) -> Result<Value, String> {
    let preview = db_preview_restore(scope, relative, kind, selector, backup)?;
    if preview.get("recoverable").and_then(Value::as_bool) != Some(true) {
        return Err("RESTORE_CONFLICT: record cannot be restored without overwrite".into());
    }
    let selector = selector.as_object().ok_or("NATIVE_PAYLOAD_INVALID: selector must be an object")?;
    let backup_relative = format!("state/restore-source-{}.sqlite", uuid_like());
    let backup_path = scope.resolve(&backup_relative)?;
    ensure_parent(&backup_path)?;
    fs::write(&backup_path, decode_base64(backup)?).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let target_path = scope.resolve(relative)?;
    let source = open_database(&backup_path)?;
    let mut target = open_database(&target_path)?;
    let outcome = restore_rows(&source, &mut target, kind, selector);
    drop(source);
    drop(target);
    let _ = fs::remove_file(&backup_path);
    outcome
}

fn restore_rows(source: &Connection, target: &mut Connection, kind: &str, selector: &Map<String, Value>) -> Result<Value, String> {
    let transaction = target.transaction().map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let restored = if kind == "cc_provider_delete" {
        let values = vec![selector.get("provider_id").cloned().unwrap_or(Value::Null), selector.get("app_type").cloned().unwrap_or(Value::Null)];
        let copied = copy_row(source, &transaction, "providers", "id = ?1 AND app_type = ?2", &values)?;
        let endpoints = copy_rows(source, &transaction, "provider_endpoints", "provider_id = ?1 AND app_type = ?2", &values)?;
        json!({"ok": true, "source_found": copied, "conflict": false, "endpoints": endpoints})
    } else if kind == "cookie_delete" {
        let copied = copy_row(source, &transaction, "cookies", COOKIE_KEY_SQL, &cookie_key_params(selector))?;
        json!({"ok": true, "source_found": copied, "conflict": false})
    } else {
        transaction.rollback().ok();
        return Err("UNSUPPORTED_FORMAT: database restore is not declared".into());
    };
    transaction.commit().map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(restored)
}

fn column_names(connection: &Connection, table: &str) -> Result<Vec<String>, String> {
    let mut statement = connection
        .prepare(&format!("SELECT * FROM {table} LIMIT 0"))
        .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(statement.column_names().iter().map(|item| (*item).to_string()).collect())
}

fn copy_row(source: &Connection, target: &Connection, table: &str, predicate: &str, values: &[Value]) -> Result<bool, String> {
    Ok(copy_rows(source, target, table, predicate, values)? > 0)
}

fn copy_rows(source: &Connection, target: &Connection, table: &str, predicate: &str, values: &[Value]) -> Result<usize, String> {
    let columns = column_names(source, table)?;
    let quoted: Vec<String> = columns.iter().map(|item| format!("\"{item}\"")).collect();
    let placeholders: Vec<String> = (1..=columns.len()).map(|index| format!("?{index}")).collect();
    let mut statement = source
        .prepare(&format!("SELECT * FROM {table} WHERE {predicate}"))
        .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let mut rows = statement
        .query(params_from_iter(bind(values)))
        .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let mut copied = 0;
    while let Some(row) = rows.next().map_err(|error| format!("NATIVE_IO_FAILED: {error}"))? {
        let mut cells: Vec<rusqlite::types::Value> = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            cells.push(row.get(index).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?);
        }
        target
            .execute(
                &format!("INSERT INTO {table} ({}) VALUES ({})", quoted.join(", "), placeholders.join(", ")),
                params_from_iter(cells),
            )
            .map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
        copied += 1;
    }
    Ok(copied)
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|value| value.as_nanos()).unwrap_or_default();
    format!("{nanos:x}")
}

/// FIPS 180-4 SHA-256：宿主只在需要回报副本指纹时使用。
pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256_digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// FIPS 180-4 SHA-256，返回原始摘要；HMAC 与 hex 版本共用这一份实现。
pub fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut hash: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut message = bytes.to_vec();
    let bit_length = (bytes.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());
    for block in message.chunks(64) {
        let mut w = [0u32; 64];
        for index in 0..16 {
            w[index] = u32::from_be_bytes([block[index * 4], block[index * 4 + 1], block[index * 4 + 2], block[index * 4 + 3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
            w[index] = w[index - 16].wrapping_add(s0).wrapping_add(w[index - 7]).wrapping_add(s1);
        }
        let mut v = hash;
        for index in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let temp1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[index]).wrapping_add(w[index]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let temp2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(temp1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1.wrapping_add(temp2);
        }
        for index in 0..8 {
            hash[index] = hash[index].wrapping_add(v[index]);
        }
    }
    let mut digest = [0u8; 32];
    for (index, word) in hash.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// RFC 2104 HMAC-SHA256：授权记录的完整性标签用它，密钥只存在宿主一侧。
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256_digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for index in 0..64 {
        inner[index] ^= block[index];
        outer[index] ^= block[index];
    }
    let mut inner_message = inner.to_vec();
    inner_message.extend_from_slice(message);
    let inner_digest = sha256_digest(&inner_message);
    let mut outer_message = outer.to_vec();
    outer_message.extend_from_slice(&inner_digest);
    sha256_digest(&outer_message)
}

pub(crate) fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    hmac_sha256(key, message).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 定长比较，避免按字节提前返回。
pub(crate) fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// 单个文件的 SHA-256；对象不存在时返回错误，由调用方区分「缺失」与「漂移」。
pub fn fingerprint_file(scope: &Scope, relative: &str) -> Result<String, String> {
    let target = scope.resolve(relative)?;
    let bytes = fs::read(&target).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(sha256_hex(&bytes))
}

/// 目录指纹与页面侧 fingerprintDirectory 同一算法：
/// 按相对路径排序的 [{path, sha256}] 清单序列化后再取一次 SHA-256。
pub fn fingerprint_directory(scope: &Scope, relative: &str) -> Result<String, String> {
    let mut entries: Vec<Value> = Vec::new();
    walk_into(scope, relative, &mut entries)?;
    let mut found: Vec<String> = entries
        .iter()
        .filter(|entry| entry.get("status").and_then(Value::as_str) == Some("found"))
        .filter_map(|entry| entry.get("relative_path").and_then(Value::as_str).map(str::to_string))
        .collect();
    if found.is_empty() && !scope.resolve(relative)?.is_dir() {
        return Err(format!("NATIVE_IO_FAILED: {relative} is not a readable directory"));
    }
    found.sort();
    let mut listed: Vec<Value> = Vec::new();
    for path in found {
        let suffix = path.get(relative.len() + 1..).unwrap_or_default().to_string();
        listed.push(json!({"path": suffix, "sha256": fingerprint_file(scope, &path)?}));
    }
    let serialized = serde_json::to_string(&listed).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(sha256_hex(serialized.as_bytes()))
}

/// 授权保险库：**不经 resolve**，也不在受限工作区之内。
/// 受限原生桥的所有文件操作都收窄在 workspace_root 里，因此桥碰不到这里的任何文件。
fn vault_file(vault_root: &Path) -> PathBuf {
    vault_root.join("authorizations.json")
}

fn vault_key_file(vault_root: &Path) -> PathBuf {
    vault_root.join("authorization.key")
}

/// 完整性密钥：首次使用时生成并落在保险库里，桥同样够不到。
pub(crate) fn vault_key(vault_root: &Path) -> Result<Vec<u8>, String> {
    let path = vault_key_file(vault_root);
    if let Ok(text) = fs::read_to_string(&path) {
        let trimmed = text.trim();
        if trimmed.len() >= 64 {
            return Ok(trimmed.as_bytes().to_vec());
        }
    }
    let material = format!("{}{}", random_hex(&path), random_hex(&path));
    fs::create_dir_all(vault_root).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    fs::write(&path, &material).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(material.into_bytes())
}

/// 不可预测材料：混合 OS 播种的 hasher、单调时间与运行时地址后取 SHA-256。
pub(crate) fn random_hex(anchor_path: &Path) -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut material: Vec<u8> = Vec::new();
    for _ in 0..4 {
        let mut hasher = RandomState::new().build_hasher();
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|value| value.as_nanos()).unwrap_or_default();
        hasher.write_u128(nanos);
        let anchor = 0u8;
        hasher.write_usize(&anchor as *const u8 as usize);
        material.extend_from_slice(&hasher.finish().to_be_bytes());
    }
    material.extend_from_slice(anchor_path.to_string_lossy().as_bytes());
    sha256_hex(&material)
}

/// 一条记录的签名覆盖它除 mac 外的全部字段。
fn record_mac(key: &[u8], record: &Map<String, Value>) -> Result<String, String> {
    let mut copy = record.clone();
    copy.remove("mac");
    let canonical = serde_json::to_string(&Value::Object(copy)).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(hmac_hex(key, canonical.as_bytes()))
}

/// 账本签名覆盖全部引用的有序列表，插入、删除或重排都会被发现。
fn ledger_mac(key: &[u8], rows: &[Value]) -> String {
    let refs: Vec<&str> = rows
        .iter()
        .filter_map(|row| row.get("authorization_ref").and_then(Value::as_str))
        .collect();
    hmac_hex(key, refs.join("\n").as_bytes())
}

fn read_vault(vault_root: &Path) -> Result<(Vec<Value>, Vec<u8>), String> {
    let key = vault_key(vault_root)?;
    let path = vault_file(vault_root);
    let parsed: Value = match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({"authorizations": [], "ledger_mac": ledger_mac(&key, &[])}),
        Err(error) => return Err(format!("NATIVE_IO_FAILED: {error}")),
    };
    let rows = parsed.get("authorizations").and_then(Value::as_array).cloned().unwrap_or_default();
    let stored_ledger = parsed.get("ledger_mac").and_then(Value::as_str).unwrap_or_default();
    if !constant_time_eq(stored_ledger, &ledger_mac(&key, &rows)) {
        return Err("NATIVE_AUTHORIZATION_STORE_TAMPERED: the authorization ledger does not match its host signature".into());
    }
    Ok((rows, key))
}

fn write_vault(vault_root: &Path, rows: &[Value], key: &[u8]) -> Result<(), String> {
    fs::create_dir_all(vault_root).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let document = json!({"authorizations": rows, "ledger_mac": ledger_mac(key, rows)});
    let text = serde_json::to_string_pretty(&document).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    fs::write(vault_file(vault_root), format!("{text}\n")).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))
}

/// 签发一条授权记录。指纹由宿主自己测量，签名由宿主自己加，页面两样都拿不到。
pub fn authorization_issue(vault_root: &Path, record: &Map<String, Value>) -> Result<Value, String> {
    let (mut rows, key) = read_vault(vault_root)?;
    let mut issued = record.clone();
    issued.insert("authorization_ref".into(), json!(format!("nat-{}", &random_hex(vault_root)[..40])));
    issued.insert("mac".into(), json!(record_mac(&key, &issued)?));
    rows.push(Value::Object(issued.clone()));
    let overflow = rows.len().saturating_sub(500);
    if overflow > 0 {
        rows.drain(0..overflow);
    }
    write_vault(vault_root, &rows, &key)?;
    Ok(Value::Object(issued))
}

/// 按引用取回记录，并核对它的宿主签名。签名对不上就当作没有这条记录。
pub fn authorization_load(vault_root: &Path, reference: &str) -> Result<Option<Value>, String> {
    let (rows, key) = read_vault(vault_root)?;
    let found = rows
        .iter()
        .rev()
        .find(|row| row.get("authorization_ref").and_then(Value::as_str) == Some(reference));
    let Some(row) = found else { return Ok(None) };
    let object = row.as_object().ok_or("NATIVE_AUTHORIZATION_STORE_TAMPERED: malformed record")?;
    let stored = object.get("mac").and_then(Value::as_str).unwrap_or_default();
    if !constant_time_eq(stored, &record_mac(&key, object)?) {
        return Err("NATIVE_AUTHORIZATION_STORE_TAMPERED: this record does not match its host signature".into());
    }
    Ok(Some(row.clone()))
}

/// 一次性消费：读到未消费的记录就当场标记并落盘，同一引用不会被第二次用掉。
/// 调用方持有 vault 互斥锁，读-改-写在锁内完成。
pub fn authorization_consume(vault_root: &Path, reference: &str, op: &str, now: &str) -> Result<Value, String> {
    let (mut rows, key) = read_vault(vault_root)?;
    let index = rows
        .iter()
        .rposition(|row| row.get("authorization_ref").and_then(Value::as_str) == Some(reference))
        .ok_or_else(|| format!("NATIVE_AUTHORIZATION_UNKNOWN: {reference} was never issued by this host"))?;
    let object = rows[index]
        .as_object()
        .cloned()
        .ok_or("NATIVE_AUTHORIZATION_STORE_TAMPERED: malformed record")?;
    let stored = object.get("mac").and_then(Value::as_str).unwrap_or_default().to_string();
    if !constant_time_eq(&stored, &record_mac(&key, &object)?) {
        return Err("NATIVE_AUTHORIZATION_STORE_TAMPERED: this record does not match its host signature".into());
    }
    if object.get("consumed_at").map(|value| !value.is_null()).unwrap_or(false) {
        return Err(format!("NATIVE_AUTHORIZATION_CONSUMED: {reference} was already used once"));
    }
    let mut updated = object;
    updated.insert("consumed_at".into(), json!(now));
    updated.insert("consumed_by_op".into(), json!(op));
    updated.remove("mac");
    let mac = record_mac(&key, &updated)?;
    updated.insert("mac".into(), json!(mac));
    rows[index] = Value::Object(updated.clone());
    write_vault(vault_root, &rows, &key)?;
    Ok(Value::Object(updated))
}

/// 列出全部已签发记录，按签发顺序。复用范围授权时用它找还没过期的那一条。
pub fn authorizations_list(vault_root: &Path) -> Result<Vec<Value>, String> {
    Ok(read_vault(vault_root)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_hosts_drop_paths_ports_and_embedded_credentials() {
        assert_eq!(url_host("https://Relay.Synthetic.invalid:8443/v1?x=1").as_deref(), Some("relay.synthetic.invalid"));
        assert_eq!(url_host("https://user:secret@relay.synthetic.invalid/api").as_deref(), Some("relay.synthetic.invalid"));
        assert_eq!(url_host("http://[::1]:9000/").as_deref(), Some("[::1]"));
        assert_eq!(url_host("not a url"), None);
        assert!(non_empty(Some(&json!(" token "))) && !non_empty(Some(&json!("  "))) && !non_empty(None));
    }

    fn count(path: &Path, sql: &str) -> i64 {
        Connection::open(path).unwrap().query_row(sql, [], |row| row.get(0)).unwrap()
    }

    #[test]
    fn database_snapshots_simulations_and_fingerprints_include_rows_committed_only_to_the_wal() {
        let base = std::env::temp_dir().join(format!("steward-wal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("state")).unwrap();
        let file = base.join("cc.sqlite");
        let writer = Connection::open(&file).unwrap();
        let mode: String = writer.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0)).unwrap();
        assert_eq!(mode, "wal");
        writer
            .execute_batch(
                "PRAGMA user_version = 18;
                 CREATE TABLE providers (id TEXT NOT NULL, app_type TEXT NOT NULL, name TEXT NOT NULL, settings_config TEXT NOT NULL,
                   is_current BOOLEAN NOT NULL DEFAULT 0, PRIMARY KEY (id, app_type));
                 CREATE TABLE provider_endpoints (id INTEGER PRIMARY KEY AUTOINCREMENT, provider_id TEXT NOT NULL, app_type TEXT NOT NULL,
                   url TEXT NOT NULL, added_at INTEGER);",
            )
            .unwrap();
        writer.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())).unwrap();
        writer
            .execute("INSERT INTO providers (id, app_type, name, settings_config) VALUES ('wal-provider', 'claude', 'WAL only', '{}')", [])
            .unwrap();

        let main_only = base.join("main-only.sqlite");
        fs::copy(&file, &main_only).unwrap();
        assert_eq!(count(&main_only, "SELECT COUNT(*) FROM providers"), 0, "前提：只复制主文件拿不到 WAL 里的记录");

        let scope = Scope::workspace_only(&base);
        let before = fingerprint_database(&scope, "cc.sqlite").unwrap();
        let snapshot = db_snapshot(&scope, "cc.sqlite").unwrap();
        assert_eq!(snapshot["sha256"], before.as_str(), "快照的逻辑状态就是原库此刻的状态");
        let copied = base.join("snapshot-copy.sqlite");
        fs::write(&copied, decode_base64(snapshot["bytes"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(count(&copied, "SELECT COUNT(*) FROM providers WHERE id = 'wal-provider'"), 1, "快照含 WAL 里的记录");

        let selector = json!({"provider_id": "wal-provider", "app_type": "claude"});
        let simulated = db_simulate(&scope, "cc.sqlite", "cc_provider_delete", &selector, &[]).unwrap();
        assert_eq!(fingerprint_database(&scope, "cc.sqlite").unwrap(), before, "模拟不动原库");
        db_mutate(&scope, "cc.sqlite", "cc_provider_delete", &selector).unwrap();
        let after = fingerprint_database(&scope, "cc.sqlite").unwrap();
        assert_ne!(after, before);
        assert_eq!(simulated["sha256"], after.as_str(), "快照上的模拟结果与原库改写后的逻辑状态一致");

        writer.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())).unwrap();
        assert_eq!(fingerprint_database(&scope, "cc.sqlite").unwrap(), after, "检查点不改变逻辑指纹");
        drop(writer);
        assert!(db_snapshot(&scope, "missing.sqlite").unwrap_err().starts_with("DB_SNAPSHOT_UNAVAILABLE"), "打不开就没有快照");
        let _ = fs::remove_dir_all(&base);
    }
}
