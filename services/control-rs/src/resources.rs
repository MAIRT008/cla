//! 资源、方案模板与订阅源（迁自 Node 基线 resourceService.mjs）。
//!
//! - 资源：前置 / 出口 A / 出口 B 三种角色，SOCKS5，共享或独享，有效期与状态；每次保存版本加一。
//!   资源只记地址与 credential_ref，不保存任何代理密码；个人接入材料另存为按用户的加密凭据。
//! - 模板：结构校验带出错位置；每次保存生成新的数字版本并留一份历史，已发布分配冻结自己保存时的模板副本。
//!   模板里出现像秘密的键名直接拒绝。
//! - 订阅：链接是秘密，只写不读（列表只给协议+主机）。刷新只解析 Clash / Mihomo YAML 的 `proxies`，
//!   结果与来源、时间、HTTP 状态一起保存；未知格式、缺 proxies、拉取失败都如实落状态，不冒充完成。

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use yaml_rust2::{Yaml, YamlLoader};

use crate::api::{display_url, fields, required_ref, validate_service_url, ApiError};
use crate::http::{HttpRequest, TransportFailure};
use crate::router::{ApiResponse, Ctx};
use crate::secrets::{delete_secret, put_secret, read_secret_text};
use crate::store::{is_constraint, read_failed, write_failed};
use crate::{iso_from_millis, millis_from_iso, ControlError};

const SUBSCRIPTION_TIMEOUT_MS: u64 = 15_000;
const MAX_YAML_ALIASES: usize = 64;
pub const SUPPORTED_SUBSCRIPTION_FORMATS: [&str; 2] = ["clash-yaml", "mihomo-yaml"];

// ---------------------------------------------------------------- 资源

pub fn resource_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let resource_id: String = row.get(0)?;
    let role: String = row.get(1)?;
    let kind: String = row.get(2)?;
    let host: String = row.get(3)?;
    let port: i64 = row.get(4)?;
    let sharing: String = row.get(5)?;
    let status: String = row.get(6)?;
    let expires_at: Option<String> = row.get(7)?;
    let credential_ref: String = row.get(8)?;
    let version: i64 = row.get(9)?;
    let updated_at: String = row.get(10)?;
    Ok(json!({
        "resource_id": resource_id,
        "role": role,
        "kind": kind,
        "host": host,
        "port": port,
        "sharing": sharing,
        "status": status,
        "expires_at": expires_at,
        "credential_ref": credential_ref,
        "version": version,
        "updated_at": updated_at,
    }))
}

const RESOURCE_COLUMNS: &str = "resource_id, role, kind, host, port, sharing, status, expires_at, credential_ref, version, updated_at";

pub fn load_resource(connection: &Connection, resource_id: &str) -> Result<Option<Value>, ControlError> {
    connection
        .query_row(
            &format!("SELECT {RESOURCE_COLUMNS} FROM control_resources WHERE resource_id = ?1"),
            params![resource_id],
            resource_from_row,
        )
        .optional()
        .map_err(read_failed)
}

fn all_resources(connection: &Connection) -> Result<Vec<Value>, ControlError> {
    let mut statement = connection
        .prepare(&format!("SELECT {RESOURCE_COLUMNS} FROM control_resources ORDER BY role, resource_id"))
        .map_err(read_failed)?;
    let rows = statement.query_map([], resource_from_row).map_err(read_failed)?;
    let collected: Result<Vec<Value>, rusqlite::Error> = rows.collect();
    collected.map_err(read_failed)
}

pub fn list_resources(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let (resources, sources) = ctx.app.store.read(|connection| -> Result<(Vec<Value>, Vec<Value>), ControlError> {
        Ok((all_resources(connection)?, all_sources(connection)?))
    })?;
    Ok(ApiResponse::json(200, json!({"resources": resources, "sources": sources})))
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':' | '[' | ']'))
}

pub fn put_resource(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(
        &body,
        &["resource_id", "role", "kind", "host", "port", "sharing", "status", "expires_at", "credential_ref"],
    )?;
    let resource_id = required_ref(&input, &["resource_id"])?;
    let role = input.required_string("role", 16)?;
    if !matches!(role.as_str(), "front" | "A" | "B") {
        return Err(ApiError::new(400, "RESOURCE_INVALID", "role 只能是 front、A 或 B").with("field", json!("role")));
    }
    let kind = input.string("kind", 16)?.unwrap_or_else(|| "socks5".to_string());
    if kind != "socks5" {
        return Err(ApiError::new(400, "RESOURCE_INVALID", "目前只支持 socks5 资源").with("field", json!("kind")));
    }
    let host = input.required_string("host", 253)?.to_ascii_lowercase();
    if !valid_host(&host) {
        return Err(ApiError::new(400, "RESOURCE_INVALID", "host 只能是主机名或 IP 地址").with("field", json!("host")));
    }
    let port = input.ranged("port", 1, 65_535)?.unwrap_or(1080);
    let sharing = input.string("sharing", 16)?.unwrap_or_else(|| "shared".to_string());
    if !matches!(sharing.as_str(), "shared" | "dedicated") {
        return Err(ApiError::new(400, "RESOURCE_INVALID", "sharing 只能是 shared 或 dedicated").with("field", json!("sharing")));
    }
    let status = input.string("status", 16)?.unwrap_or_else(|| "ACTIVE".to_string());
    if !matches!(status.as_str(), "ACTIVE" | "DISABLED") {
        return Err(ApiError::new(400, "RESOURCE_INVALID", "status 只能是 ACTIVE 或 DISABLED").with("field", json!("status")));
    }
    let expires_at = input.instant("expires_at")?;
    let credential_ref = match input.string("credential_ref", 128)? {
        Some(value) => {
            if !crate::api::valid_ref(&value) {
                return Err(ApiError::new(400, "RESOURCE_INVALID", "credential_ref 只能含字母、数字与 . _ : -").with("field", json!("credential_ref")));
            }
            value
        }
        None => format!("cred-{resource_id}"),
    };
    let now = iso_from_millis(ctx.now());
    let (saved, created) = ctx.app.store.write(|transaction| -> Result<(Value, bool), ApiError> {
        let previous: Option<i64> = transaction
            .query_row("SELECT version FROM control_resources WHERE resource_id = ?1", params![resource_id], |row| row.get(0))
            .optional()
            .map_err(read_failed)?;
        transaction
            .execute(
                "INSERT INTO control_resources (resource_id, role, kind, host, port, sharing, status, expires_at, credential_ref, version, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(resource_id) DO UPDATE SET role = excluded.role, kind = excluded.kind, host = excluded.host, port = excluded.port,
                        sharing = excluded.sharing, status = excluded.status, expires_at = excluded.expires_at,
                        credential_ref = excluded.credential_ref, version = excluded.version, updated_at = excluded.updated_at",
                params![resource_id, role, kind, host, port, sharing, status, expires_at, credential_ref, previous.unwrap_or(0) + 1, now],
            )
            .map_err(write_failed)?;
        let saved = load_resource(transaction, &resource_id)?.unwrap_or(Value::Null);
        Ok((saved, previous.is_none()))
    })?;
    ctx.info("admin.resource.saved", json!({"actor": ctx.actor(), "resource_id": resource_id, "role": role, "version": saved["version"]}));
    Ok(ApiResponse::json(200, json!({"ok": true, "resource": saved, "created": created})))
}

// ---------------------------------------------------------------- 模板

const LIST_KEYS: [&str; 5] = ["claude_domains", "claude_processes", "managed_browser_processes", "protected_process_paths", "lan_cidrs"];
const PLANE_KEYS: [&str; 6] = ["login", "config", "model", "quota", "ticket", "support"];
const LOOPBACK_ENDPOINT_FIELDS: [&str; 5] = ["source_process_path", "transport", "address", "port", "purpose"];
const MAX_LOOPBACK_ENDPOINTS: usize = 64;
const SECRET_KEY_PARTS: [&str; 8] = ["password", "passwd", "secret", "token", "credential", "api_key", "apikey", "private"];

fn template_error(path: &str, reason: &str) -> ApiError {
    ApiError::new(400, "TEMPLATE_INVALID", format!("{path} {reason}")).with("path", json!(path))
}

fn reject_secret_keys(value: &Value, path: &str, depth: usize) -> Result<(), ApiError> {
    if depth > 6 {
        return Err(template_error(path, "嵌套过深"));
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lowered = key.to_ascii_lowercase();
                if SECRET_KEY_PARTS.iter().any(|part| lowered.contains(part)) {
                    return Err(ApiError::new(400, "TEMPLATE_SECRET_REJECTED", format!("{path}.{key} 像是秘密字段；模板不保存秘密"))
                        .with("path", json!(format!("{path}.{key}"))));
                }
                reject_secret_keys(child, &format!("{path}.{key}"), depth + 1)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                reject_secret_keys(child, &format!("{path}[{index}]"), depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn string_list(value: &Value, path: &str) -> Result<Value, ApiError> {
    let items = value.as_array().ok_or_else(|| template_error(path, "必须是字符串数组"))?;
    if items.len() > 512 {
        return Err(template_error(path, "最多 512 项"));
    }
    for (index, item) in items.iter().enumerate() {
        match item.as_str() {
            Some(text) if !text.trim().is_empty() && text.chars().count() <= 512 => {}
            _ => return Err(template_error(&format!("{path}[{index}]"), "必须是非空字符串")),
        }
    }
    Ok(value.clone())
}

fn exact_loopback_address(text: &str) -> bool {
    text == "::1" || text.parse::<std::net::Ipv4Addr>().map(|address| address.is_loopback() && address.to_string() == text).unwrap_or(false)
}

/// Mihomo 逻辑规则按逗号切子规则载荷、按括号配对找子规则；含逗号或括号不配对的路径写不出精确规则，模板里直接拒绝。
fn expressible_in_logic_rule(text: &str) -> bool {
    if text.contains(',') {
        return false;
    }
    let mut depth = 0i32;
    for character in text.chars() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

fn absolute_program_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    let drive = bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/');
    (drive || text.starts_with("\\\\")) && !text.contains("..") && text.len() <= 512
}

/// 模板回环端点：每项只认五个字段，程序是绝对路径，协议 tcp/udp，地址是单个精确回环地址，端口是单个整数；
/// 首版不接受通配、端口范围或整个 127.0.0.0/8。空数组表示回环全拦。发起程序是否属于批准程序在整份模板读完后核对。
fn loopback_endpoint_list(value: &Value, path: &str) -> Result<Value, ApiError> {
    let items = value.as_array().ok_or_else(|| template_error(path, "必须是数组"))?;
    if items.len() > MAX_LOOPBACK_ENDPOINTS {
        return Err(template_error(path, "最多 64 项"));
    }
    let mut seen: Vec<String> = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let entry = item.as_object().ok_or_else(|| template_error(&item_path, "必须是对象"))?;
        if let Some(key) = entry.keys().find(|key| !LOOPBACK_ENDPOINT_FIELDS.contains(&key.as_str())) {
            return Err(template_error(&format!("{item_path}.{key}"), "不是认识的字段（source_process_path/transport/address/port/purpose）"));
        }
        let text = |field: &str| entry.get(field).and_then(Value::as_str).unwrap_or_default();
        let source = text("source_process_path");
        if !absolute_program_path(source) {
            return Err(template_error(&format!("{item_path}.source_process_path"), "必须是绝对程序路径"));
        }
        if !expressible_in_logic_rule(source) {
            return Err(template_error(&format!("{item_path}.source_process_path"), "含逗号或括号不配对，受管配置的逻辑规则无法原样表达"));
        }
        let transport = text("transport");
        if transport != "tcp" && transport != "udp" {
            return Err(template_error(&format!("{item_path}.transport"), "只能是 tcp 或 udp"));
        }
        let address = text("address");
        if !exact_loopback_address(address) {
            return Err(template_error(&format!("{item_path}.address"), "只能是单个精确回环地址（127.x.y.z 或 ::1），不接受通配、范围或网段"));
        }
        let Some(port) = entry.get("port").and_then(Value::as_u64).filter(|port| (1..=65_535).contains(port)) else {
            return Err(template_error(&format!("{item_path}.port"), "必须是 1—65535 的单个整数端口"));
        };
        let purpose = text("purpose");
        let purpose_ok = purpose.len() <= 64
            && purpose.bytes().next().map(|first| first.is_ascii_lowercase()).unwrap_or(false)
            && purpose.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !purpose_ok {
            return Err(template_error(&format!("{item_path}.purpose"), "必须是小写标识（字母开头，只含字母数字下划线，最长 64）"));
        }
        let identity = format!("{}|{transport}|{address}|{port}", source.to_lowercase());
        if seen.contains(&identity) {
            return Err(template_error(&item_path, "与前面的端点重复"));
        }
        seen.push(identity);
    }
    Ok(value.clone())
}

/// 校验并规整模板，只保留客户端受管配置会消费的字段（与基线 publicTemplate 同一组）。
pub fn validate_template(value: &Value) -> Result<Value, ApiError> {
    let map = value.as_object().ok_or_else(|| template_error("template", "必须是对象"))?;
    reject_secret_keys(value, "template", 0)?;
    let mut normalized = Map::new();
    for (key, item) in map {
        let path = format!("template.{key}");
        let checked = match key.as_str() {
            "version" => match item.as_str() {
                Some(text) if !text.trim().is_empty() && text.len() <= 128 => item.clone(),
                _ => return Err(template_error(&path, "必须是非空字符串")),
            },
            key if LIST_KEYS.contains(&key) => string_list(item, &path)?,
            "loopback_endpoints" => loopback_endpoint_list(item, &path)?,
            "control_plane" => {
                let plane = item.as_object().ok_or_else(|| template_error(&path, "必须是对象"))?;
                for (group, entries) in plane {
                    let group_path = format!("{path}.{group}");
                    if !PLANE_KEYS.contains(&group.as_str()) {
                        return Err(template_error(&group_path, "不是认识的基础通信分组（login/config/model/quota/ticket/support）"));
                    }
                    let entries = entries.as_array().ok_or_else(|| template_error(&group_path, "必须是数组"))?;
                    for (index, entry) in entries.iter().enumerate() {
                        let entry_path = format!("{group_path}[{index}]");
                        let entry = entry.as_object().ok_or_else(|| template_error(&entry_path, "必须是对象"))?;
                        for (field, field_value) in entry {
                            let field_path = format!("{entry_path}.{field}");
                            let ok = match field.as_str() {
                                "host" => field_value.as_str().map(|text| !text.trim().is_empty() && text.len() <= 253).unwrap_or(false),
                                "outbound" | "path" => field_value.as_str().map(|text| !text.trim().is_empty() && text.len() <= 64).unwrap_or(false),
                                "over_quota" => field_value.is_boolean(),
                                _ => return Err(template_error(&field_path, "不是认识的字段（host/outbound/path/over_quota）")),
                            };
                            if !ok {
                                return Err(template_error(&field_path, "类型或长度不对"));
                            }
                        }
                        if !entry.contains_key("host") {
                            return Err(template_error(&format!("{entry_path}.host"), "必填"));
                        }
                    }
                }
                item.clone()
            }
            "udp_policy" | "ipv6_policy" => match item.as_str() {
                Some(text) if !text.trim().is_empty() && text.len() <= 32 => item.clone(),
                _ => return Err(template_error(&path, "必须是非空字符串")),
            },
            "dns" => {
                if !item.is_object() {
                    return Err(template_error(&path, "必须是对象"));
                }
                item.clone()
            }
            _ => return Err(template_error(&path, "不是认识的模板字段")),
        };
        normalized.insert(key.clone(), checked);
    }
    if let Some(endpoints) = normalized.get("loopback_endpoints").and_then(Value::as_array) {
        let approved: Vec<String> = normalized
            .get("protected_process_paths")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(str::to_lowercase).collect())
            .unwrap_or_default();
        for (index, endpoint) in endpoints.iter().enumerate() {
            let source = endpoint.get("source_process_path").and_then(Value::as_str).unwrap_or_default().to_lowercase();
            if !approved.contains(&source) {
                return Err(template_error(&format!("template.loopback_endpoints[{index}].source_process_path"), "必须属于 protected_process_paths"));
            }
        }
    }
    Ok(Value::Object(normalized))
}

fn template_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(String, String, i64, String, bool, String, String)> {
    let published: i64 = row.get(4)?;
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, published == 1, row.get(5)?, row.get(6)?))
}

/// 模板只有一个版本：控制端记录版本。正文里的 `version` 保存时写成它，读出时再覆盖一次，
/// 修正本规则之前保存的滞后或缺失正文版本；分配的 template_version 与冻结正文因此不会分叉。
fn with_record_version(mut template: Value, version: &str) -> Value {
    if let Value::Object(map) = &mut template {
        map.insert("version".to_string(), Value::String(version.to_string()));
    }
    template
}

fn template_view(row: (String, String, i64, String, bool, String, String)) -> Value {
    let (template_id, version, numeric_version, status, published, template_json, updated_at) = row;
    let template = with_record_version(serde_json::from_str::<Value>(&template_json).unwrap_or(Value::Null), &version);
    json!({
        "template_id": template_id,
        "version": version,
        "numeric_version": numeric_version,
        "status": status,
        "published": published,
        "template": template,
        "updated_at": updated_at,
    })
}

const TEMPLATE_COLUMNS: &str = "template_id, version, numeric_version, status, published, template_json, updated_at";

/// 分配时取模板：指定了就必须存在且未停用；没指定就取最近更新的已发布模板；都没有则拒绝，不回退到内置样例。
pub fn template_for_assignment(connection: &Connection, template_id: Option<&str>) -> Result<Value, ApiError> {
    let row = match template_id {
        Some(id) => connection
            .query_row(&format!("SELECT {TEMPLATE_COLUMNS} FROM control_templates WHERE template_id = ?1"), params![id], template_from_row)
            .optional()
            .map_err(read_failed)?
            .ok_or_else(|| ApiError::new(404, "TEMPLATE_NOT_FOUND", "没有这个方案模板"))?,
        None => connection
            .query_row(
                &format!("SELECT {TEMPLATE_COLUMNS} FROM control_templates WHERE published = 1 AND status = 'ACTIVE' ORDER BY updated_at DESC LIMIT 1"),
                [],
                template_from_row,
            )
            .optional()
            .map_err(read_failed)?
            .ok_or_else(|| ApiError::new(409, "TEMPLATE_UNAVAILABLE", "没有已发布的方案模板；请先保存并发布模板，或在分配里指定模板"))?,
    };
    if row.3 != "ACTIVE" {
        return Err(ApiError::new(409, "TEMPLATE_UNAVAILABLE", "该方案模板已停用"));
    }
    Ok(template_view(row))
}

pub fn list_templates(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let templates = ctx.app.store.read(|connection| -> Result<Vec<Value>, ControlError> {
        let mut statement = connection
            .prepare(&format!("SELECT {TEMPLATE_COLUMNS} FROM control_templates ORDER BY template_id"))
            .map_err(read_failed)?;
        let rows = statement.query_map([], template_from_row).map_err(read_failed)?;
        let collected: Result<Vec<_>, rusqlite::Error> = rows.collect();
        Ok(collected.map_err(read_failed)?.into_iter().map(template_view).collect())
    })?;
    Ok(ApiResponse::json(200, json!({"templates": templates})))
}

pub fn put_template(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["template_id", "template", "version", "status", "published"])?;
    let template_id = required_ref(&input, &["template_id"])?;
    let template = validate_template(input.value("template").ok_or_else(|| template_error("template", "必填"))?)?;
    let version = input.string("version", 128)?;
    let status = input.string("status", 16)?.unwrap_or_else(|| "ACTIVE".to_string());
    if !matches!(status.as_str(), "ACTIVE" | "RETIRED") {
        return Err(ApiError::new(400, "TEMPLATE_INVALID", "status 只能是 ACTIVE 或 RETIRED").with("path", json!("status")));
    }
    let published = input.boolean("published")?.unwrap_or(false);
    let now = iso_from_millis(ctx.now());
    let saved = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        let previous: Option<i64> = transaction
            .query_row("SELECT numeric_version FROM control_templates WHERE template_id = ?1", params![template_id], |row| row.get(0))
            .optional()
            .map_err(read_failed)?;
        let numeric_version = previous.unwrap_or(0) + 1;
        let version_label = version.clone().unwrap_or_else(|| format!("template-v{numeric_version}"));
        let template_json = with_record_version(template.clone(), &version_label).to_string();
        transaction
            .execute(
                "INSERT INTO control_templates (template_id, version, numeric_version, status, published, template_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(template_id) DO UPDATE SET version = excluded.version, numeric_version = excluded.numeric_version,
                        status = excluded.status, published = excluded.published, template_json = excluded.template_json, updated_at = excluded.updated_at",
                params![template_id, version_label, numeric_version, status, if published { 1i64 } else { 0i64 }, template_json, now],
            )
            .map_err(write_failed)?;
        transaction
            .execute(
                "INSERT INTO control_template_versions (template_id, numeric_version, version, template_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![template_id, numeric_version, version_label, template_json, now],
            )
            .map_err(|error| if is_constraint(&error) { ApiError::new(409, "TEMPLATE_INVALID", "模板版本冲突，请重试") } else { ApiError::from(write_failed(error)) })?;
        let row = transaction
            .query_row(&format!("SELECT {TEMPLATE_COLUMNS} FROM control_templates WHERE template_id = ?1"), params![template_id], template_from_row)
            .map_err(read_failed)?;
        Ok(template_view(row))
    })?;
    ctx.info("admin.template.saved", json!({"actor": ctx.actor(), "template_id": template_id, "version": saved["version"], "published": published}));
    Ok(ApiResponse::json(200, json!({"ok": true, "template": saved})))
}

// ---------------------------------------------------------------- 订阅

struct SourceRow {
    source_id: String,
    format: String,
    status: String,
    url_secret_ref: Option<String>,
    url_display: Option<String>,
    version: i64,
    refreshed_at: Option<String>,
    proxy_count: i64,
    proxy_names_json: String,
    error: Option<String>,
    http_status: Option<i64>,
    content_type: Option<String>,
    updated_at: String,
}

const SOURCE_COLUMNS: &str = "source_id, format, status, url_secret_ref, url_display, version, refreshed_at, proxy_count, proxy_names_json, error, http_status, content_type, updated_at";

fn source_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SourceRow> {
    Ok(SourceRow {
        source_id: row.get(0)?,
        format: row.get(1)?,
        status: row.get(2)?,
        url_secret_ref: row.get(3)?,
        url_display: row.get(4)?,
        version: row.get(5)?,
        refreshed_at: row.get(6)?,
        proxy_count: row.get(7)?,
        proxy_names_json: row.get(8)?,
        error: row.get(9)?,
        http_status: row.get(10)?,
        content_type: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

impl SourceRow {
    fn view(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "format": self.format,
            "status": self.status,
            "url_present": self.url_secret_ref.is_some(),
            "url_display": self.url_display,
            "version": self.version,
            "refreshed_at": self.refreshed_at,
            "proxy_count": self.proxy_count,
            "proxy_names": serde_json::from_str::<Value>(&self.proxy_names_json).unwrap_or_else(|_| json!([])),
            "error": self.error,
            "http_status": self.http_status,
            "content_type": self.content_type,
            "updated_at": self.updated_at,
        })
    }
}

fn load_source(connection: &Connection, source_id: &str) -> Result<Option<SourceRow>, ControlError> {
    connection
        .query_row(&format!("SELECT {SOURCE_COLUMNS} FROM control_subscription_sources WHERE source_id = ?1"), params![source_id], source_from_row)
        .optional()
        .map_err(read_failed)
}

fn all_sources(connection: &Connection) -> Result<Vec<Value>, ControlError> {
    let mut statement = connection
        .prepare(&format!("SELECT {SOURCE_COLUMNS} FROM control_subscription_sources ORDER BY source_id"))
        .map_err(read_failed)?;
    let rows = statement.query_map([], source_from_row).map_err(read_failed)?;
    let collected: Result<Vec<SourceRow>, rusqlite::Error> = rows.collect();
    Ok(collected.map_err(read_failed)?.iter().map(SourceRow::view).collect())
}

pub fn list_subscriptions(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let sources = ctx.app.store.read(|connection| -> Result<Vec<Value>, ControlError> { all_sources(connection) })?;
    Ok(ApiResponse::json(200, json!({"sources": sources})))
}

pub fn put_subscription(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["source_id", "format", "status", "url", "clear_url"])?;
    let source_id = required_ref(&input, &["source_id"])?;
    let format = input.string("format", 32)?;
    let status = input.string("status", 16)?;
    if let Some(value) = &status {
        if !matches!(value.as_str(), "PENDING" | "DISABLED") {
            return Err(ApiError::new(400, "SOURCE_INVALID", "保存时 status 只能是 PENDING 或 DISABLED；其他状态由刷新结果决定").with("field", json!("status")));
        }
    }
    let url = input.string("url", 2048)?;
    if let Some(value) = &url {
        validate_service_url(value, "url").map_err(|error| ApiError::new(400, "SOURCE_INVALID", error.reason).with("field", json!("url")))?;
    }
    let clear_url = input.boolean("clear_url")?.unwrap_or(false);
    if url.is_some() && clear_url {
        return Err(ApiError::new(400, "SOURCE_INVALID", "url 与 clear_url 不能同时给出").with("field", json!("url")));
    }
    let now_ms = ctx.now();
    let now = iso_from_millis(now_ms);
    let protector = ctx.app.protector.as_ref();
    let saved = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        let existing = load_source(transaction, &source_id)?;
        let mut secret_ref = existing.as_ref().and_then(|item| item.url_secret_ref.clone());
        let mut url_display = existing.as_ref().and_then(|item| item.url_display.clone());
        if let Some(value) = &url {
            secret_ref = Some(put_secret(transaction, protector, secret_ref.as_deref(), &format!("subscription_url:{source_id}"), value.as_bytes(), now_ms)?);
            url_display = Some(display_url(value));
        }
        let stale = if clear_url {
            url_display = None;
            secret_ref.take()
        } else {
            None
        };
        let merged_format = format
            .clone()
            .or_else(|| existing.as_ref().map(|item| item.format.clone()))
            .unwrap_or_else(|| "clash-yaml".to_string());
        let merged_status = status
            .clone()
            .or_else(|| existing.as_ref().map(|item| item.status.clone()))
            .unwrap_or_else(|| "PENDING".to_string());
        let version = existing.as_ref().map(|item| item.version).unwrap_or(0) + 1;
        transaction
            .execute(
                "INSERT INTO control_subscription_sources (source_id, format, status, url_secret_ref, url_display, version, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(source_id) DO UPDATE SET format = excluded.format, status = excluded.status, url_secret_ref = excluded.url_secret_ref,
                        url_display = excluded.url_display, version = excluded.version, updated_at = excluded.updated_at",
                params![source_id, merged_format, merged_status, secret_ref, url_display, version, now],
            )
            .map_err(write_failed)?;
        if let Some(stale) = stale {
            delete_secret(transaction, &stale)?;
        }
        let row = load_source(transaction, &source_id)?.ok_or_else(|| ApiError::new(500, "CONTROL_STORE_WRITE_FAILED", "订阅源保存后读不回"))?;
        Ok(row.view())
    })?;
    ctx.info("admin.subscription.saved", json!({"actor": ctx.actor(), "source_id": source_id, "url_replaced": url.is_some(), "url_cleared": clear_url}));
    Ok(ApiResponse::json(200, json!({"ok": true, "source": saved})))
}

/// 解析结果：代理名称、类型、服务器与端口；不带任何密码字段。
pub struct ParsedSubscription {
    pub proxies: Vec<Value>,
}

/// 粗略数 YAML 别名引用，防止嵌套别名展开放大内存。
fn alias_count(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0;
    for index in 0..bytes.len() {
        if bytes[index] == b'*' {
            let before = if index == 0 { b' ' } else { bytes[index - 1] };
            let after = bytes.get(index + 1).copied().unwrap_or(b' ');
            if matches!(before, b' ' | b'\t' | b'\n' | b'[' | b',' | b':' | b'-' | b'{') && (after.is_ascii_alphanumeric() || after == b'_') {
                count += 1;
            }
        }
    }
    count
}

fn yaml_scalar(value: &Yaml) -> Value {
    match value {
        Yaml::String(text) => json!(text),
        Yaml::Integer(number) => json!(number),
        Yaml::Real(text) => text.parse::<f64>().map(|number| json!(number)).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// Clash / Mihomo YAML：顶层必须是映射且有 `proxies` 数组。
pub fn parse_clash_yaml(text: &str) -> Result<ParsedSubscription, (&'static str, String)> {
    if alias_count(text) > MAX_YAML_ALIASES {
        return Err(("YAML_ALIAS_LIMIT", format!("YAML 别名引用超过 {MAX_YAML_ALIASES} 个")));
    }
    let documents = YamlLoader::load_from_str(text).map_err(|error| ("YAML_PARSE_FAILED", format!("YAML 解析失败：{error}")))?;
    let document = documents.first().ok_or(("CLASH_PROXIES_MISSING", "YAML 为空".to_string()))?;
    let proxies = document["proxies"]
        .as_vec()
        .ok_or(("CLASH_PROXIES_MISSING", "顶层没有 proxies 数组".to_string()))?;
    let parsed = proxies
        .iter()
        .map(|proxy| {
            json!({
                "name": yaml_scalar(&proxy["name"]),
                "type": yaml_scalar(&proxy["type"]),
                "server": yaml_scalar(&proxy["server"]),
                "port": yaml_scalar(&proxy["port"]),
            })
        })
        .collect();
    Ok(ParsedSubscription { proxies: parsed })
}

enum Fetched {
    Body { text: String, content_type: Option<String> },
    Failed { code: &'static str, http_status: Option<u16>, detail: String },
}

pub fn refresh_subscription(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["source_id", "body", "content_type"])?;
    let source_id = required_ref(&input, &["source_id"])?;
    let supplied = input.raw_string("body", 1_000_000)?;
    let supplied_type = input.string("content_type", 128)?;
    let protector = ctx.app.protector.as_ref();

    let (source, url) = ctx.app.store.read(|connection| -> Result<(SourceRow, Option<String>), ApiError> {
        let source = load_source(connection, &source_id)?.ok_or_else(|| ApiError::new(404, "SOURCE_NOT_FOUND", "没有这个订阅源"))?;
        if source.status == "DISABLED" {
            return Err(ApiError::new(409, "SOURCE_DISABLED", "订阅源已停用"));
        }
        let url = match (&supplied, &source.url_secret_ref) {
            (None, Some(secret_ref)) => Some(read_secret_text(connection, protector, secret_ref, &format!("subscription_url:{source_id}"))?),
            _ => None,
        };
        Ok((source, url))
    })?;

    let fetched = match (supplied, url) {
        (Some(text), _) => Fetched::Body { text, content_type: supplied_type.clone() },
        (None, Some(url)) => {
            let request = HttpRequest::new("GET", url, SUBSCRIPTION_TIMEOUT_MS).header("accept", "*/*");
            match ctx.app.transport.send(&request, ctx.cancel) {
                Ok(response) if response.status >= 400 => Fetched::Failed {
                    code: "SOURCE_FETCH_FAILED",
                    http_status: Some(response.status),
                    detail: format!("订阅地址回 HTTP {}", response.status),
                },
                Ok(response) => match String::from_utf8(response.body) {
                    Ok(text) => Fetched::Body { text, content_type: supplied_type.clone().or(response.content_type) },
                    Err(_) => Fetched::Failed { code: "SOURCE_BODY_INVALID", http_status: Some(response.status), detail: "订阅内容不是 UTF-8 文本".to_string() },
                },
                Err(error) => Fetched::Failed {
                    code: if error.kind == TransportFailure::Cancelled { "SOURCE_FETCH_CANCELLED" } else { "SOURCE_FETCH_FAILED" },
                    http_status: None,
                    detail: error.detail,
                },
            }
        }
        (None, None) => return Err(ApiError::new(400, "SOURCE_EMPTY", "没有提供订阅内容，订阅源也没有保存地址")),
    };

    let now = iso_from_millis(ctx.now());
    let (status, code, error_text, http_status, proxies, content_type): (&str, Option<&str>, Option<String>, Option<u16>, Vec<Value>, Option<String>) = match fetched {
        Fetched::Failed { code, http_status, detail } => {
            ctx.warn("admin.subscription.fetch_failed", json!({"source_id": source_id, "code": code, "http_status": http_status, "detail": detail}));
            ("FAILED", Some(code), Some(code.to_string()), http_status, Vec::new(), None)
        }
        Fetched::Body { text, content_type } => {
            if text.trim().is_empty() {
                ("FAILED", Some("SOURCE_EMPTY"), Some("SOURCE_EMPTY".to_string()), None, Vec::new(), content_type)
            } else if !SUPPORTED_SUBSCRIPTION_FORMATS.contains(&source.format.as_str()) {
                ("UNSUPPORTED", Some("UNSUPPORTED"), Some(format!("format {} is unsupported", source.format)), None, Vec::new(), content_type)
            } else {
                match parse_clash_yaml(&text) {
                    Ok(parsed) => ("ACTIVE", None, None, None, parsed.proxies, content_type.or_else(|| Some("application/x-yaml".to_string()))),
                    Err(("CLASH_PROXIES_MISSING", _)) => ("UNSUPPORTED", Some("UNSUPPORTED"), Some("CLASH_PROXIES_MISSING".to_string()), None, Vec::new(), content_type),
                    Err((code, detail)) => {
                        ctx.warn("admin.subscription.parse_failed", json!({"source_id": source_id, "code": code, "detail": detail}));
                        ("FAILED", Some(code), Some(code.to_string()), None, Vec::new(), content_type)
                    }
                }
            }
        }
    };
    let names: Vec<Value> = proxies.iter().map(|proxy| proxy["name"].clone()).filter(|name| !name.is_null()).collect();
    let saved = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        // 失败时保留上一次成功解析的数量与名称，只改状态与错误。
        let keep_previous = status != "ACTIVE";
        transaction
            .execute(
                "UPDATE control_subscription_sources SET status = ?1, error = ?2, http_status = ?3, refreshed_at = ?4, updated_at = ?4,
                        content_type = COALESCE(?5, content_type),
                        proxy_count = CASE WHEN ?6 THEN proxy_count ELSE ?7 END,
                        proxy_names_json = CASE WHEN ?6 THEN proxy_names_json ELSE ?8 END
                  WHERE source_id = ?9",
                params![status, error_text, http_status.map(i64::from), now, content_type, keep_previous, proxies.len() as i64, Value::Array(names.clone()).to_string(), source_id],
            )
            .map_err(write_failed)?;
        let row = load_source(transaction, &source_id)?.ok_or_else(|| ApiError::new(404, "SOURCE_NOT_FOUND", "没有这个订阅源"))?;
        Ok(row.view())
    })?;
    ctx.info("admin.subscription.refreshed", json!({"actor": ctx.actor(), "source_id": source_id, "status": status, "code": code, "proxy_count": proxies.len()}));
    let mut response = json!({"ok": status == "ACTIVE", "source": saved});
    if let Some(code) = code {
        response["code"] = json!(code);
    }
    if let Some(http_status) = http_status {
        response["http_status"] = json!(http_status);
    }
    if status == "ACTIVE" {
        response["proxies"] = Value::Array(proxies);
    }
    Ok(ApiResponse::json(200, response))
}

/// 资源是否在 `now_ms` 时可用：存在、ACTIVE、未到期。
pub fn resource_usable(resource: &Value, now_ms: i64) -> bool {
    let active = resource.get("status").and_then(Value::as_str) == Some("ACTIVE");
    let expired = resource
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(millis_from_iso)
        .map(|end| now_ms >= end)
        .unwrap_or(false);
    active && !expired
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clash_yaml_is_parsed_without_passwords() {
        let yaml = ["proxies:", "  - {name: a, type: socks5, server: a.example.invalid, port: 1080, password: synthetic}", ""].join("\n");
        let parsed = parse_clash_yaml(&yaml).unwrap();
        assert_eq!(parsed.proxies.len(), 1);
        assert_eq!(parsed.proxies[0]["server"], "a.example.invalid");
        assert!(!parsed.proxies[0].to_string().contains("synthetic"));
        assert_eq!(parse_clash_yaml("just a string").err().unwrap().0, "CLASH_PROXIES_MISSING");
        assert_eq!(parse_clash_yaml("proxies: [").err().unwrap().0, "YAML_PARSE_FAILED");
    }

    #[test]
    fn template_errors_name_the_position() {
        let bad = json!({"control_plane": {"login": [{"host": ""}]}});
        let error = validate_template(&bad).err().unwrap();
        assert_eq!(error.code, "TEMPLATE_INVALID");
        assert_eq!(error.extra["path"], "template.control_plane.login[0].host");
        let secret = json!({"dns": {"api_token": "x"}});
        assert_eq!(validate_template(&secret).err().unwrap().code, "TEMPLATE_SECRET_REJECTED");
        let unknown = json!({"yaml": "proxies: []"});
        assert_eq!(validate_template(&unknown).err().unwrap().extra["path"], "template.yaml");
    }

    #[test]
    fn loopback_endpoints_accept_only_exact_endpoints_of_protected_programs() {
        let claude = r"C:\Program Files\Claude\claude.exe";
        let endpoint = json!({"source_process_path": claude, "transport": "tcp", "address": "127.0.0.1", "port": 43123, "purpose": "oauth_callback"});
        let template = |endpoints: Value| json!({"protected_process_paths": [claude], "loopback_endpoints": endpoints});
        let accepted = validate_template(&template(json!([endpoint.clone(), {"source_process_path": claude.to_uppercase(), "transport": "udp", "address": "::1", "port": 5353, "purpose": "discovery"}]))).unwrap();
        assert_eq!(accepted["loopback_endpoints"][0]["port"], 43123);
        assert!(validate_template(&template(json!([]))).is_ok(), "空清单合法，含义是回环全拦");

        let cases: Vec<(&str, Value, &str)> = vec![
            ("address", json!("127.0.0.0/8"), "template.loopback_endpoints[0].address"),
            ("address", json!("*"), "template.loopback_endpoints[0].address"),
            ("address", json!("localhost"), "template.loopback_endpoints[0].address"),
            ("address", json!("10.0.0.1"), "template.loopback_endpoints[0].address"),
            ("port", json!("43000-43200"), "template.loopback_endpoints[0].port"),
            ("port", json!(0), "template.loopback_endpoints[0].port"),
            ("transport", json!("any"), "template.loopback_endpoints[0].transport"),
            ("purpose", json!("OAuth Callback"), "template.loopback_endpoints[0].purpose"),
            ("source_process_path", json!("claude.exe"), "template.loopback_endpoints[0].source_process_path"),
            ("source_process_path", json!(r"C:\Tools\curl.exe"), "template.loopback_endpoints[0].source_process_path"),
            ("port_range", json!("43000-43200"), "template.loopback_endpoints[0].port_range"),
            ("source_process_path", json!(r"C:\Apps\a,b\tool.exe"), "template.loopback_endpoints[0].source_process_path"),
            ("source_process_path", json!(r"C:\Apps\odd)(\tool.exe"), "template.loopback_endpoints[0].source_process_path"),
        ];
        for (field, value, path) in cases {
            let mut broken = endpoint.clone();
            broken[field] = value;
            let error = validate_template(&template(json!([broken]))).err().unwrap();
            assert_eq!(error.code, "TEMPLATE_INVALID", "{field}");
            assert_eq!(error.extra["path"], path, "{field}");
        }
        let duplicate = validate_template(&template(json!([endpoint.clone(), endpoint.clone()]))).err().unwrap();
        assert_eq!(duplicate.extra["path"], "template.loopback_endpoints[1]");
        let x86 = r"C:\Program Files (x86)\Claude\claude.exe";
        let paired = json!({"protected_process_paths": [x86], "loopback_endpoints": [{"source_process_path": x86, "transport": "tcp", "address": "127.0.0.1", "port": 43123, "purpose": "oauth_callback"}]});
        assert!(validate_template(&paired).is_ok(), "配对的括号可以表达");
        let orphan = validate_template(&json!({"loopback_endpoints": [endpoint]})).err().unwrap();
        assert_eq!(orphan.extra["path"], "template.loopback_endpoints[0].source_process_path", "没有批准程序就没有回环端点");
    }
}
