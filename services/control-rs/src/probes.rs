//! 分环境探测服务配置（FD-02 N26—N33）：管理员按环境登记回显、情报、DoH、Probe 与 STUN 地址，
//! 普通用户只拿到地址。探测协议沿用现有回显、DoH 与 Probe 的解析，这里不自建探测平台；
//! 没有登记的环境，客户端不建端口，诊断按 ENVIRONMENT_PROBE_UNAVAILABLE 如实缺测。
//!
//! 本机没有 cargo/rustc，这个模块尚未编译。

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::api::{fields, validate_service_url, ApiError, Fields};
use crate::router::{ApiResponse, Ctx};
use crate::store::{read_failed, write_failed};
use crate::{iso_from_millis, ControlError};

const URL_FIELDS: [&str; 4] = ["echo_url", "doh_url", "probe_base_url", "intel_url"];
const CLIENT_KINDS: [&str; 3] = ["webview", "wsl-cli", "cli"];
const MAX_STUN_URLS: usize = 4;

fn invalid(field: &str, reason: impl Into<String>) -> ApiError {
    ApiError::new(400, "PROBE_SERVICES_INVALID", reason).with("field", json!(field))
}

/// 环境引用与宿主发现、配额分配用同一种写法：小写字母、数字与连字符。
fn environment_ref(input: &Fields<'_>) -> Result<String, ApiError> {
    let value = input.required_string("environment_ref", 64)?;
    let valid = !value.starts_with('-') && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid {
        return Err(invalid("environment_ref", "environment_ref 只能含小写字母、数字与连字符"));
    }
    Ok(value)
}

/// STUN 只收 `stun:` / `stuns:` 加主机与可选端口；要凭据的 TURN 不在这里配置。
fn valid_stun(url: &str) -> bool {
    let rest = url.strip_prefix("stun:").or_else(|| url.strip_prefix("stuns:"));
    match rest {
        Some(rest) => !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':' | '[' | ']')),
        None => false,
    }
}

fn all(connection: &Connection) -> Result<Vec<Value>, ControlError> {
    let mut statement = connection
        .prepare("SELECT environment_ref, config_json, version, updated_by, updated_at FROM control_probe_services ORDER BY environment_ref")
        .map_err(read_failed)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(read_failed)?;
    let mut out = Vec::new();
    for row in rows {
        let (environment_ref, config, version, updated_by, updated_at) = row.map_err(read_failed)?;
        let config: Value = serde_json::from_str(&config).unwrap_or(Value::Null);
        out.push(json!({
            "environment_ref": environment_ref,
            "config": config,
            "version": version,
            "updated_by": updated_by,
            "updated_at": updated_at,
        }));
    }
    Ok(out)
}

pub fn list(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let items = ctx.app.store.read(all)?;
    Ok(ApiResponse::json(200, json!({"probe_services": items})))
}

/// 登记或更新一个环境的探测服务。带 expected_version 时按版本号防覆盖。
pub fn put(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(
        &body,
        &["environment_ref", "echo_url", "doh_url", "probe_base_url", "intel_url", "stun_urls", "client_kind", "webrtc", "expected_version"],
    )?;
    let environment_ref = environment_ref(&input)?;
    let mut config = Map::new();
    for key in URL_FIELDS {
        if let Some(url) = input.string(key, 2048)? {
            validate_service_url(&url, key)?;
            config.insert(key.to_string(), json!(url));
        }
    }
    if config.is_empty() {
        return Err(invalid("echo_url", "至少要配置回显、DoH、Probe 或情报中的一个地址"));
    }
    if let Some(stun) = input.string_list("stun_urls", MAX_STUN_URLS, 256)? {
        if let Some(bad) = stun.iter().find(|url| !valid_stun(url)) {
            return Err(invalid("stun_urls", format!("{bad} 不是 stun: 或 stuns: 地址")));
        }
        config.insert("stun_urls".to_string(), json!(stun));
    }
    if let Some(kind) = input.string("client_kind", 32)? {
        if !CLIENT_KINDS.contains(&kind.as_str()) {
            return Err(invalid("client_kind", "client_kind 只能是 webview、wsl-cli 或 cli"));
        }
        config.insert("client_kind".to_string(), json!(kind));
    }
    if let Some(webrtc) = input.boolean("webrtc")? {
        config.insert("webrtc".to_string(), json!(webrtc));
    }
    let expected = input.integer("expected_version")?;
    let now = iso_from_millis(ctx.now());
    let actor = ctx.actor().to_string();
    let stored = Value::Object(config).to_string();
    let saved = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        let previous: Option<i64> = transaction
            .query_row("SELECT version FROM control_probe_services WHERE environment_ref = ?1", params![environment_ref], |row| row.get(0))
            .optional()
            .map_err(read_failed)?;
        if let Some(expected) = expected {
            if previous.unwrap_or(0) != expected {
                return Err(ApiError::new(409, "PROBE_SERVICES_CONFLICT", "这个环境的配置已被改过，请刷新后再改")
                    .with("current_version", json!(previous.unwrap_or(0))));
            }
        }
        let version = previous.unwrap_or(0) + 1;
        transaction
            .execute(
                "INSERT INTO control_probe_services (environment_ref, config_json, version, updated_by, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(environment_ref) DO UPDATE SET config_json = excluded.config_json, version = excluded.version,
                        updated_by = excluded.updated_by, updated_at = excluded.updated_at",
                params![environment_ref, stored, version, actor, now],
            )
            .map_err(write_failed)?;
        Ok(json!({
            "environment_ref": environment_ref,
            "config": serde_json::from_str::<Value>(&stored).unwrap_or(Value::Null),
            "version": version,
            "updated_by": actor,
            "updated_at": now,
        }))
    })?;
    ctx.info("admin.probe_services.saved", json!({"actor": ctx.actor(), "environment_ref": saved["environment_ref"], "version": saved["version"]}));
    Ok(ApiResponse::json(200, json!({"ok": true, "probe_services": saved})))
}

pub fn remove(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["environment_ref"])?;
    let environment_ref = environment_ref(&input)?;
    let removed = ctx.app.store.write(|transaction| -> Result<usize, ApiError> {
        Ok(transaction
            .execute("DELETE FROM control_probe_services WHERE environment_ref = ?1", params![environment_ref])
            .map_err(write_failed)?)
    })?;
    if removed == 0 {
        return Err(ApiError::new(404, "PROBE_SERVICES_NOT_FOUND", "这个环境没有探测服务配置"));
    }
    ctx.info("admin.probe_services.removed", json!({"actor": ctx.actor(), "environment_ref": environment_ref}));
    Ok(ApiResponse::json(200, json!({"ok": true, "removed": environment_ref})))
}

/// 普通用户：只拿到每个环境的地址与客户端类型，不含版本、修改人这类管理信息。
pub fn network_view(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let items = ctx.app.store.read(all)?;
    let mut environments = Map::new();
    for item in items {
        if let (Some(reference), Some(config)) = (item["environment_ref"].as_str(), item["config"].as_object()) {
            environments.insert(reference.to_string(), Value::Object(config.clone()));
        }
    }
    Ok(ApiResponse::json(200, json!({"environments": environments})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_addresses_are_plain_stun_without_credentials() {
        assert!(valid_stun("stun:stun.synthetic.invalid:3478"));
        assert!(valid_stun("stuns:[2001:db8::1]:5349"));
        assert!(!valid_stun("turn:relay.synthetic.invalid"));
        assert!(!valid_stun("stun:user@host"));
        assert!(!valid_stun("stun:"));
    }
}
