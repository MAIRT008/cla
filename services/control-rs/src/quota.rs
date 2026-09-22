//! 配额适配与服务状态（迁自 Node 基线 quotaService.mjs 与 networkRoutes.mjs 的配额部分）。
//!
//! 服务节点（当前只接 Remnawave）是配额权威；本库只存绑定、操作回执与快照：
//! - 应用用户与权威侧用户一对一：provider_user_id、username 各自唯一，冲突回 PROVIDER_IDENTITY_CONFLICT；
//! - operation_id 幂等：同一 id 内容不同回 409；已完成直接重放；上次调用结果未知（PENDING）时先回读权威再决定；
//! - 改额度、停用、恢复都以回读到的权威状态为准，节点侧断连效果一律 UNKNOWN，不由调用方声明；
//! - 权威未配置、超时或不可用时返回最后一次快照并标 stale/OFFLINE，不回零、不回无限；
//! - 用户超额（LIMITED）、上游池耗尽（pool.exhausted）、同步失败（stale）分开表达，池余额不由用户额度求和。
//! 外部调用都在数据库事务之外进行；事务只写开始、挂起与完成三种状态。

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::admin_users::existing_user;
use crate::api::{display_url, fields, required_ref, validate_service_url, ApiError, Fields};
use crate::assignments::{published_assignment, validate_assignment};
use crate::remnawave::{contract, provider_username, AuthorityError, Remnawave, UserRead, AUTHORITY_REF, RESET_PERIODS};
use crate::router::{ApiResponse, Ctx};
use crate::secrets::{delete_secret, put_secret, read_secret_text, secret_meta};
use crate::store::{is_constraint, read_failed, write_failed};
use crate::{canonical_json, iso_from_millis, millis_from_iso, ControlError};

const DEFAULT_TIMEOUT_MS: i64 = 15_000;

// ---------------------------------------------------------------- 快照与展示

pub fn load_snapshot(connection: &Connection, user_ref: &str) -> Result<Option<Value>, ControlError> {
    let payload: Option<String> = connection
        .query_row("SELECT payload_json FROM control_quota_snapshots WHERE user_ref = ?1", params![user_ref], |row| row.get(0))
        .optional()
        .map_err(read_failed)?;
    Ok(payload.and_then(|text| serde_json::from_str(&text).ok()))
}

fn save_snapshot(connection: &Connection, snapshot: &Value, now: &str) -> Result<(), ControlError> {
    let user_ref = snapshot.get("user_ref").and_then(Value::as_str).unwrap_or_default();
    connection
        .execute(
            "INSERT INTO control_quota_snapshots (user_ref, payload_json, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(user_ref) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at",
            params![user_ref, snapshot.to_string(), now],
        )
        .map(|_| ())
        .map_err(write_failed)
}

fn int(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    value.as_i64().or_else(|| value.as_f64().filter(|item| item.is_finite()).map(|item| item as i64))
}

fn str_or_null(snapshot: &Value, key: &str) -> Value {
    match snapshot.get(key).and_then(Value::as_str) {
        Some(text) if !text.is_empty() => json!(text),
        _ => Value::Null,
    }
}

fn unknown_object(snapshot: &Value, key: &str) -> Value {
    match snapshot.get(key) {
        Some(value) if value.is_object() => value.clone(),
        _ => json!({"status": "UNKNOWN"}),
    }
}

/// 与基线 publicQuota 同一组字段。
pub fn public_quota(snapshot: Option<&Value>) -> Value {
    let snapshot = match snapshot.filter(|value| value.is_object()) {
        Some(value) => value,
        None => return Value::Null,
    };
    let limit = int(snapshot.get("limit_bytes"));
    let unlimited = snapshot.get("unlimited").and_then(Value::as_bool) == Some(true) || limit == Some(0);
    let used = int(snapshot.get("used_bytes"));
    let remaining = match (unlimited, used, limit) {
        (false, Some(used), Some(limit)) => json!((limit - used).max(0)),
        _ => Value::Null,
    };
    let authority_status = snapshot.get("authority_status").and_then(Value::as_str).unwrap_or("UNKNOWN");
    let node_judgment = if authority_status == "AVAILABLE" {
        snapshot.get("node_new_limit_judgment").and_then(Value::as_str).unwrap_or("UNKNOWN")
    } else {
        "UNAVAILABLE"
    };
    let node_remove = match snapshot.get("node_remove").filter(|value| value.is_object()) {
        Some(effect) => json!({
            "requested": effect.get("requested").and_then(Value::as_bool) == Some(true),
            "accepted": effect.get("accepted").and_then(Value::as_bool) == Some(true),
            "in_flight": effect.get("in_flight").and_then(Value::as_str).unwrap_or("UNKNOWN"),
            "verified_disconnect": effect.get("verified_disconnect").and_then(Value::as_str).unwrap_or("UNKNOWN"),
        }),
        None => Value::Null,
    };
    json!({
        "user_ref": snapshot.get("user_ref").cloned().unwrap_or(Value::Null),
        "status": snapshot.get("status").cloned().unwrap_or(Value::Null),
        "used_bytes": used,
        "limit_bytes": if unlimited { Some(0) } else { limit },
        "unlimited": unlimited,
        "remaining_bytes": remaining,
        "period": str_or_null(snapshot, "period"),
        "last_traffic_reset_at": str_or_null(snapshot, "last_traffic_reset_at"),
        "expire_at": str_or_null(snapshot, "expire_at"),
        "observed_at": str_or_null(snapshot, "observed_at"),
        "measured_at": snapshot.get("measured_at").cloned().unwrap_or(Value::Null),
        "metering_layer": str_or_null(snapshot, "metering_layer"),
        "unit": snapshot.get("unit").and_then(Value::as_str).unwrap_or("bytes"),
        "authority_ref": str_or_null(snapshot, "authority_ref"),
        "authority_status": authority_status,
        "control_status": snapshot.get("control_status").and_then(Value::as_str).unwrap_or("UNKNOWN"),
        "node_new_limit_judgment": node_judgment,
        "stale": snapshot.get("stale").and_then(Value::as_bool) == Some(true),
        "upload_bytes": unknown_object(snapshot, "upload_bytes"),
        "download_bytes": unknown_object(snapshot, "download_bytes"),
        "split_ab": unknown_object(snapshot, "split_ab"),
        "devices": unknown_object(snapshot, "devices"),
        "node_remove": node_remove,
        "proof_scope": str_or_null(snapshot, "proof_scope"),
    })
}

fn unknown_split() -> Value {
    json!({"status": "UNKNOWN", "reason": "upstream userTraffic has usedTrafficBytes only"})
}

fn unknown_node_effect() -> Value {
    json!({"requested": true, "accepted": false, "in_flight": "UNKNOWN", "verified_disconnect": "UNKNOWN"})
}

fn no_node_effect() -> Value {
    json!({"requested": false, "accepted": false, "in_flight": "NONE", "verified_disconnect": "UNKNOWN"})
}

/// 与 src/core/network/quota.mjs 的 readQuotaView 同一组字段，给普通用户额度接口附带。
pub fn read_quota_view(snapshot: Option<&Value>) -> Value {
    let public = public_quota(snapshot);
    if public.is_null() {
        return json!({
            "status": "UNKNOWN", "authority_status": "UNKNOWN", "node_new_limit_judgment": "UNAVAILABLE",
            "used_bytes": null, "limit_bytes": null, "remaining_bytes": null, "unlimited": false, "period": null,
            "observed_at": null, "measured_at": null,
            "split": {"A": {"status": "UNKNOWN", "reason": "upstream field is not provided"}, "B": {"status": "UNKNOWN", "reason": "upstream field is not provided"},
                      "devices": {"status": "UNKNOWN", "reason": "upstream field is not provided"}, "upload": {"status": "UNKNOWN", "reason": "upstream field is not provided"},
                      "download": {"status": "UNKNOWN", "reason": "upstream field is not provided"}},
            "local_bytes": {"scope": "T2_CLIENT_ONLY", "status": "UNKNOWN"},
            "next_action": "WAIT_FOR_SNAPSHOT",
        });
    }
    let status = public["status"].as_str().unwrap_or("UNKNOWN").to_string();
    let next_action = match status.as_str() {
        "LIMITED" => "KEEP_APPROVED_DIRECT_STOP_PROXY",
        "DISABLED" => "WAIT_ADMIN_RESUME",
        "EXPIRED" => "WAIT_RENEWAL",
        _ if public["authority_status"] == "OFFLINE" || public["stale"] == true => "KEEP_LAST_SNAPSHOT_AND_PROTECTION",
        _ => "NONE",
    };
    let mut view = public.clone();
    view["status"] = json!(status);
    view["proxy_paused"] = json!(matches!(status.as_str(), "LIMITED" | "DISABLED" | "EXPIRED"));
    view["degrade_forbidden"] = json!(true);
    view["unknown_direct_forbidden"] = json!(true);
    view["split"] = json!({
        "A": public["split_ab"], "B": public["split_ab"], "devices": public["devices"],
        "upload": public["upload_bytes"], "download": public["download_bytes"],
    });
    view["local_bytes"] = json!({"scope": "T2_CLIENT_ONLY", "status": "UNKNOWN"});
    view["next_action"] = json!(next_action);
    view
}

struct SnapshotInput<'a> {
    user_ref: &'a str,
    projected: &'a Value,
    observed_at: &'a str,
    node_judgment: &'a str,
    node_remove: Value,
}

fn snapshot_from_projected(input: SnapshotInput<'_>) -> Value {
    let projected = input.projected;
    let limit = int(projected.get("trafficLimitBytes"));
    json!({
        "user_ref": input.user_ref,
        "authority_ref": AUTHORITY_REF,
        "provider_user_id": projected.get("id").cloned().unwrap_or(Value::Null),
        "status": projected.get("status").cloned().unwrap_or(Value::Null),
        "used_bytes": int(projected.get("usedTrafficBytes")),
        "limit_bytes": limit,
        "unlimited": limit == Some(0),
        "period": projected.get("trafficLimitStrategy").cloned().unwrap_or(Value::Null),
        "last_traffic_reset_at": projected.get("lastTrafficResetAt").cloned().unwrap_or(Value::Null),
        "expire_at": projected.get("expireAt").cloned().unwrap_or(Value::Null),
        "observed_at": input.observed_at,
        "measured_at": null,
        "metering_layer": "remnawave-backend-user-traffic",
        "unit": "bytes",
        "authority_status": "AVAILABLE",
        "control_status": "AVAILABLE",
        "node_new_limit_judgment": input.node_judgment,
        "stale": false,
        "upload_bytes": unknown_split(),
        "download_bytes": unknown_split(),
        "split_ab": unknown_split(),
        "devices": unknown_split(),
        "node_remove": input.node_remove,
        "proof_scope": "authority-readback",
    })
}

/// 同一周期内用量不能倒退；周期变了必须带重置时间。
fn can_replace_snapshot(previous: Option<&Value>, next: &Value) -> Result<(), &'static str> {
    let previous = match previous {
        Some(value) => value,
        None => return Ok(()),
    };
    if previous.get("user_ref") != next.get("user_ref") {
        return Err("SNAPSHOT_USER_MISMATCH");
    }
    let period = |value: &Value| value.get("period").and_then(Value::as_str).map(str::to_string);
    let reset = |value: &Value| value.get("last_traffic_reset_at").and_then(Value::as_str).map(str::to_string);
    if let (Some(before), Some(after)) = (period(previous), period(next)) {
        if before != after && reset(next).is_none() {
            return Err("SNAPSHOT_PERIOD_MISMATCH");
        }
    }
    if let (Some(before), Some(after)) = (int(previous.get("used_bytes")), int(next.get("used_bytes"))) {
        if after < before && reset(previous) == reset(next) && period(previous) == period(next) {
            return Err("SNAPSHOT_REGRESSION");
        }
    }
    Ok(())
}

fn stale_snapshot(previous: Option<&Value>, user_ref: &str, code: &str) -> Value {
    let authority_status = if matches!(code, "AUTHORITY_UNCONFIGURED" | "AUTHORITY_UNAVAILABLE" | "AUTHORITY_TIMEOUT") { "OFFLINE" } else { "STALE" };
    match previous {
        None => json!({
            "user_ref": user_ref, "status": "UNKNOWN", "stale": true, "authority_status": authority_status,
            "node_new_limit_judgment": "UNAVAILABLE", "control_status": "AVAILABLE",
        }),
        Some(previous) => {
            let mut copy = previous.clone();
            copy["stale"] = json!(true);
            copy["authority_status"] = json!(authority_status);
            copy["node_new_limit_judgment"] = json!("UNAVAILABLE");
            copy["control_status"] = json!("AVAILABLE");
            copy
        }
    }
}

// ---------------------------------------------------------------- 适配配置

struct AdapterRow {
    enabled: bool,
    base_url_secret_ref: Option<String>,
    base_url_display: Option<String>,
    token_secret_ref: Option<String>,
    timeout_ms: i64,
    verification: String,
    last_error_code: Option<String>,
    last_call_at: Option<String>,
    updated_at: String,
}

fn load_adapter(connection: &Connection) -> Result<Option<AdapterRow>, ControlError> {
    connection
        .query_row(
            "SELECT enabled, base_url_secret_ref, base_url_display, token_secret_ref, timeout_ms, verification, last_error_code, last_call_at, updated_at
               FROM control_quota_adapter WHERE singleton = 1",
            [],
            |row| {
                let enabled: i64 = row.get(0)?;
                Ok(AdapterRow {
                    enabled: enabled == 1,
                    base_url_secret_ref: row.get(1)?,
                    base_url_display: row.get(2)?,
                    token_secret_ref: row.get(3)?,
                    timeout_ms: row.get(4)?,
                    verification: row.get(5)?,
                    last_error_code: row.get(6)?,
                    last_call_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(read_failed)
}

fn adapter_configured(row: Option<&AdapterRow>) -> bool {
    row.map(|item| item.enabled && item.base_url_secret_ref.is_some() && item.token_secret_ref.is_some()).unwrap_or(false)
}

fn adapter_view(connection: &Connection) -> Result<Value, ControlError> {
    let row = load_adapter(connection)?;
    let token = secret_meta(connection, row.as_ref().and_then(|item| item.token_secret_ref.as_deref()))?;
    Ok(json!({
        "kind": "remnawave",
        "configured": adapter_configured(row.as_ref()),
        "enabled": row.as_ref().map(|item| item.enabled).unwrap_or(false),
        "base_url_present": row.as_ref().map(|item| item.base_url_secret_ref.is_some()).unwrap_or(false),
        "base_url_display": row.as_ref().and_then(|item| item.base_url_display.clone()),
        "token_present": token.is_some(),
        "token_updated_at": token.as_ref().map(|item| item.updated_at.clone()),
        "timeout_ms": row.as_ref().map(|item| item.timeout_ms).unwrap_or(DEFAULT_TIMEOUT_MS),
        "verification": row.as_ref().map(|item| item.verification.clone()).unwrap_or_else(|| "NOT_TESTED".to_string()),
        "last_error_code": row.as_ref().and_then(|item| item.last_error_code.clone()),
        "last_call_at": row.as_ref().and_then(|item| item.last_call_at.clone()),
        "updated_at": row.as_ref().map(|item| item.updated_at.clone()),
        "contract": contract(),
        "scope_note": "只接 Remnawave 用户额度路径；不代表任意机场订阅都能按用户硬限额",
    }))
}

pub fn get_adapter(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let view = ctx.app.store.read(|connection| -> Result<Value, ControlError> { adapter_view(connection) })?;
    Ok(ApiResponse::json(200, json!({"adapter": view})))
}

pub fn put_adapter(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["kind", "enabled", "base_url", "token", "timeout_ms", "clear_secrets"])?;
    let kind = input.string("kind", 32)?.unwrap_or_else(|| "remnawave".to_string());
    if kind != "remnawave" {
        return Err(ApiError::new(400, "QUOTA_ADAPTER_INVALID", "目前只支持 remnawave 配额适配").with("field", json!("kind")));
    }
    let enabled = input.boolean("enabled")?;
    let base_url = input.string("base_url", 2048)?;
    if let Some(url) = &base_url {
        validate_service_url(url, "base_url").map_err(|error| ApiError::new(400, "QUOTA_ADAPTER_INVALID", error.reason).with("field", json!("base_url")))?;
    }
    let token = input.raw_string("token", 4096)?.filter(|value| !value.is_empty());
    if let Some(value) = &token {
        if value.chars().count() < 8 || value.chars().any(char::is_whitespace) {
            return Err(ApiError::new(400, "QUOTA_ADAPTER_INVALID", "token 至少 8 个字符且不含空白").with("field", json!("token")));
        }
    }
    let timeout_ms = input.ranged("timeout_ms", 1_000, 120_000)?;
    let clear = input.boolean("clear_secrets")?.unwrap_or(false);
    if clear && (base_url.is_some() || token.is_some()) {
        return Err(ApiError::new(400, "QUOTA_ADAPTER_INVALID", "clear_secrets 不能与新的地址或令牌同时给出"));
    }
    let now_ms = ctx.now();
    let now = iso_from_millis(now_ms);
    let actor = ctx.actor().to_string();
    let protector = ctx.app.protector.as_ref();
    let view = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        let existing = load_adapter(transaction)?;
        let mut url_ref = existing.as_ref().and_then(|item| item.base_url_secret_ref.clone());
        let mut display = existing.as_ref().and_then(|item| item.base_url_display.clone());
        let mut token_ref = existing.as_ref().and_then(|item| item.token_secret_ref.clone());
        if let Some(url) = &base_url {
            url_ref = Some(put_secret(transaction, protector, url_ref.as_deref(), "quota_adapter_base_url", url.as_bytes(), now_ms)?);
            display = Some(display_url(url));
        }
        if let Some(value) = &token {
            token_ref = Some(put_secret(transaction, protector, token_ref.as_deref(), "quota_adapter_token", value.as_bytes(), now_ms)?);
        }
        let stale: Vec<String> = if clear {
            display = None;
            [url_ref.take(), token_ref.take()].into_iter().flatten().collect()
        } else {
            Vec::new()
        };
        let reset = base_url.is_some() || token.is_some() || clear;
        let verification = if reset { "NOT_TESTED".to_string() } else { existing.as_ref().map(|item| item.verification.clone()).unwrap_or_else(|| "NOT_TESTED".to_string()) };
        let last_error = if reset { None } else { existing.as_ref().and_then(|item| item.last_error_code.clone()) };
        let last_call = if reset { None } else { existing.as_ref().and_then(|item| item.last_call_at.clone()) };
        let enabled_flag: i64 = if enabled.unwrap_or_else(|| existing.as_ref().map(|item| item.enabled).unwrap_or(false)) { 1 } else { 0 };
        let timeout = timeout_ms.or_else(|| existing.as_ref().map(|item| item.timeout_ms)).unwrap_or(DEFAULT_TIMEOUT_MS);
        transaction
            .execute(
                "INSERT INTO control_quota_adapter (singleton, kind, enabled, base_url_secret_ref, base_url_display, token_secret_ref, timeout_ms, verification, last_error_code, last_call_at, updated_at, updated_by)
                 VALUES (1, 'remnawave', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(singleton) DO UPDATE SET enabled = excluded.enabled, base_url_secret_ref = excluded.base_url_secret_ref,
                        base_url_display = excluded.base_url_display, token_secret_ref = excluded.token_secret_ref, timeout_ms = excluded.timeout_ms,
                        verification = excluded.verification, last_error_code = excluded.last_error_code, last_call_at = excluded.last_call_at,
                        updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                params![enabled_flag, url_ref, display, token_ref, timeout, verification, last_error, last_call, now, actor],
            )
            .map_err(write_failed)?;
        for secret_ref in stale {
            delete_secret(transaction, &secret_ref)?;
        }
        Ok(adapter_view(transaction)?)
    })?;
    ctx.info(
        "admin.quota_adapter.saved",
        json!({"actor": ctx.actor(), "configured": view["configured"], "url_replaced": base_url.is_some(), "token_replaced": token.is_some(), "cleared": clear}),
    );
    Ok(ApiResponse::json(200, json!({"adapter": view})))
}

struct AdapterSecrets {
    base_url: String,
    token: String,
    timeout_ms: u64,
}

/// 读出权威地址与令牌；未启用、缺秘密或秘密读不出都算未配置，不启动任何调用。
fn adapter_secrets(ctx: &Ctx) -> Result<AdapterSecrets, AuthorityError> {
    let protector = ctx.app.protector.as_ref();
    let outcome = ctx.app.store.read(|connection| -> Result<Option<AdapterSecrets>, ControlError> {
        let row = match load_adapter(connection)? {
            Some(row) if adapter_configured(Some(&row)) => row,
            _ => return Ok(None),
        };
        let base_url = read_secret_text(connection, protector, row.base_url_secret_ref.as_deref().unwrap_or_default(), "quota_adapter_base_url")?;
        let token = read_secret_text(connection, protector, row.token_secret_ref.as_deref().unwrap_or_default(), "quota_adapter_token")?;
        Ok(Some(AdapterSecrets { base_url, token, timeout_ms: row.timeout_ms.max(1000) as u64 }))
    });
    match outcome {
        Ok(Some(secrets)) => Ok(secrets),
        Ok(None) => Err(AuthorityError::new("AUTHORITY_UNCONFIGURED", None, false, "quota adapter is not configured; refusing silent mock authority")),
        Err(error) => {
            ctx.error("quota.adapter.secret_unreadable", json!({"code": error.code, "detail": error.reason}));
            Err(AuthorityError::new("AUTHORITY_UNCONFIGURED", None, false, "quota adapter secrets are unreadable"))
        }
    }
}

fn record_authority_outcome(ctx: &Ctx, error: Option<&AuthorityError>) {
    if matches!(error.map(|item| item.code), Some("AUTHORITY_UNCONFIGURED") | Some("AUTHORITY_CANCELLED")) {
        return;
    }
    let (verification, code) = match error {
        None => ("CALL_SUCCEEDED", None),
        Some(error) => ("CALL_FAILED", Some(error.code)),
    };
    let now = iso_from_millis(ctx.now());
    let outcome = ctx.app.store.write(|transaction| -> Result<(), ControlError> {
        transaction
            .execute(
                "UPDATE control_quota_adapter SET verification = ?1, last_error_code = ?2, last_call_at = ?3 WHERE singleton = 1",
                params![verification, code, now],
            )
            .map_err(write_failed)?;
        Ok(())
    });
    if let Err(error) = outcome {
        ctx.warn("quota.adapter.status_write_failed", json!({"code": error.code}));
    }
}

fn authority_api_error(ctx: &Ctx, error: AuthorityError) -> ApiError {
    ctx.warn("quota.authority.failed", json!({"code": error.code, "status": error.status, "detail": error.detail}));
    let reason = match error.code {
        "AUTHORITY_UNCONFIGURED" => "配额权威未配置；没有伪造结果",
        "AUTHORITY_TIMEOUT" => "配额权威请求超时",
        "AUTHORITY_UNAVAILABLE" => "配额权威暂不可用",
        "AUTHORITY_CANCELLED" => "请求已取消",
        "AUTHORITY_UNAUTHORIZED" | "AUTHORITY_FORBIDDEN" => "配额权威拒绝了服务端配置的管理令牌",
        "AUTHORITY_CONFLICT" => "配额权威侧已有同名用户",
        "AUTHORITY_NOT_FOUND" => "配额权威侧找不到该用户",
        "AUTHORITY_RATE_LIMITED" => "配额权威限流",
        "INVALID_RESPONSE" | "UNSUPPORTED" => "配额权威的响应不符合已核对的契约",
        "LIMIT_REQUIRED" => "产品分配必须给出正数额度；0 在权威侧表示无限",
        _ => "配额权威调用失败",
    };
    ApiError::new(crate::api::status_for(error.code), error.code, reason).with("retryable", json!(error.retryable))
}

// ---------------------------------------------------------------- 操作回执

struct Operation {
    operation_id: String,
    user_ref: String,
    kind: &'static str,
    limit_bytes: Option<i64>,
    period: Option<String>,
    expire_at: Option<String>,
    squad_uuid: Option<String>,
}

impl Operation {
    fn digest(&self) -> String {
        canonical_json(&json!({
            "kind": self.kind,
            "user_ref": self.user_ref,
            "limit_bytes": self.limit_bytes,
            "period": self.period,
            "expire_at": self.expire_at,
            "squad_uuid": self.squad_uuid,
        }))
    }
}

enum ReplayState {
    Start,
    Pending,
    Replay(Value),
}

fn replay_state(connection: &Connection, operation: &Operation) -> Result<ReplayState, ApiError> {
    let existing: Option<(String, String, Option<String>)> = connection
        .query_row(
            "SELECT digest, status, result_json FROM control_quota_operations WHERE operation_id = ?1",
            params![operation.operation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(read_failed)?;
    match existing {
        None => Ok(ReplayState::Start),
        Some((digest, _, _)) if digest != operation.digest() => {
            Err(ApiError::new(409, "QUOTA_OPERATION_MISMATCH", "operation_id 不能换内容重复使用"))
        }
        Some((_, _, Some(result))) => Ok(ReplayState::Replay(serde_json::from_str(&result).unwrap_or(Value::Null))),
        Some((_, status, None)) if status == "PENDING" => Ok(ReplayState::Pending),
        Some(_) => Ok(ReplayState::Start),
    }
}

fn begin(connection: &Connection, operation: &Operation, now: &str) -> Result<(), ControlError> {
    connection
        .execute(
            "INSERT INTO control_quota_operations (operation_id, user_ref, kind, digest, status, result_json, error_code, started_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, 'PENDING', NULL, NULL, ?5, NULL)
             ON CONFLICT(operation_id) DO UPDATE SET status = 'PENDING', result_json = NULL, error_code = NULL",
            params![operation.operation_id, operation.user_ref, operation.kind, operation.digest(), now],
        )
        .map(|_| ())
        .map_err(write_failed)
}

fn keep_pending(ctx: &Ctx, operation: &Operation, code: &str) {
    let now = iso_from_millis(ctx.now());
    let outcome = ctx.app.store.write(|transaction| -> Result<(), ControlError> {
        transaction
            .execute(
                "INSERT INTO control_quota_operations (operation_id, user_ref, kind, digest, status, result_json, error_code, started_at, completed_at)
                 VALUES (?1, ?2, ?3, ?4, 'PENDING', NULL, ?5, ?6, NULL)
                 ON CONFLICT(operation_id) DO UPDATE SET status = 'PENDING', result_json = NULL, error_code = excluded.error_code",
                params![operation.operation_id, operation.user_ref, operation.kind, operation.digest(), code, now],
            )
            .map_err(write_failed)?;
        Ok(())
    });
    if let Err(error) = outcome {
        ctx.error("quota.operation.pending_write_failed", json!({"operation_id": operation.operation_id, "code": error.code}));
    }
}

fn remember(connection: &Connection, operation: &Operation, result: &Value, now: &str) -> Result<(), ControlError> {
    connection
        .execute(
            "INSERT INTO control_quota_operations (operation_id, user_ref, kind, digest, status, result_json, error_code, started_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, 'COMPLETED', ?5, NULL, ?6, ?6)
             ON CONFLICT(operation_id) DO UPDATE SET status = 'COMPLETED', result_json = excluded.result_json, error_code = NULL, completed_at = excluded.completed_at",
            params![operation.operation_id, operation.user_ref, operation.kind, operation.digest(), result.to_string(), now],
        )
        .map(|_| ())
        .map_err(write_failed)
}

fn replayed(mut result: Value) -> ApiResponse {
    result["replayed"] = json!(true);
    ApiResponse::json(200, result)
}

struct Binding {
    provider_user_id: i64,
    username: String,
    squad_uuid: Option<String>,
    created_at: String,
}

fn load_binding(connection: &Connection, user_ref: &str) -> Result<Option<Binding>, ControlError> {
    connection
        .query_row(
            "SELECT provider_user_id, username, squad_uuid, created_at FROM control_provider_bindings WHERE user_ref = ?1",
            params![user_ref],
            |row| Ok(Binding { provider_user_id: row.get(0)?, username: row.get(1)?, squad_uuid: row.get(2)?, created_at: row.get(3)? }),
        )
        .optional()
        .map_err(read_failed)
}

fn binding_view(user_ref: &str, binding: &Binding) -> Value {
    json!({
        "user_ref": user_ref,
        "authority_ref": AUTHORITY_REF,
        "provider_user_id": binding.provider_user_id,
        "username": binding.username,
        "squad_uuid": binding.squad_uuid,
        "created_at": binding.created_at,
    })
}

// ---------------------------------------------------------------- 请求解析

fn operation_id(input: &Fields<'_>) -> Result<String, ApiError> {
    match input.string("operation_id", 128)? {
        Some(id) if crate::api::valid_ref(&id) => Ok(id),
        Some(_) => Err(ApiError::invalid("operation_id 只能含字母、数字与 . _ : -").with("field", json!("operation_id"))),
        None => Err(ApiError::new(400, "OPERATION_REQUIRED", "operation_id 必填")),
    }
}

/// limitBytes，或 limit_value + limit_unit（bytes / GB=10^9 / GiB=2^30），与基线 bytesFromLimit 相同。
fn limit_bytes(input: &Fields<'_>) -> Result<Option<i64>, ApiError> {
    if let Some(bytes) = input.integer("limitBytes")? {
        return Ok(Some(bytes));
    }
    let value = match input.number("limit_value")? {
        Some(value) => value,
        None => return Ok(None),
    };
    if value < 0.0 {
        return Err(ApiError::new(400, "LIMIT_INVALID", "额度不能为负"));
    }
    let unit = input.string("limit_unit", 8)?.unwrap_or_else(|| "bytes".to_string());
    let factor = match unit.as_str() {
        "bytes" => 1.0,
        "GB" => 1_000_000_000.0,
        "GiB" => 1_073_741_824.0,
        other => return Err(ApiError::new(400, "LIMIT_UNIT_UNSUPPORTED", format!("不支持的额度单位 {other}"))),
    };
    let bytes = value * factor;
    if !bytes.is_finite() || bytes > 9.0e18 {
        return Err(ApiError::new(400, "LIMIT_INVALID", "额度过大"));
    }
    Ok(Some(bytes.round() as i64))
}

const OPERATION_FIELDS: [&str; 10] = ["userRef", "user_ref", "operation_id", "limitBytes", "limit_value", "limit_unit", "period", "expireAt", "squadUuid", "nodeEffect"];

// ---------------------------------------------------------------- 分配额度身份

pub fn allocate(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let secrets = adapter_secrets(ctx).map_err(|error| authority_api_error(ctx, error))?;
    let body = ctx.body()?;
    let input = fields(&body, &OPERATION_FIELDS)?;
    let user_ref = required_ref(&input, &["userRef", "user_ref"])?;
    let operation_id = operation_id(&input)?;
    let limit = limit_bytes(&input)?.filter(|bytes| *bytes > 0).ok_or_else(|| ApiError::new(400, "LIMIT_REQUIRED", "产品分配不能创建无限额用户"))?;
    let period = input.string("period", 16)?.unwrap_or_else(|| "MONTH".to_string());
    if !RESET_PERIODS.contains(&period.as_str()) {
        return Err(ApiError::new(400, "CONTROL_REQUEST_INVALID", format!("不支持的周期 {period}")).with("field", json!("period")));
    }
    let expire_at = input.instant("expireAt")?.ok_or_else(|| ApiError::new(400, "EXPIRE_AT_REQUIRED", "expireAt 必填"))?;
    let squad_uuid = input.string("squadUuid", 64)?;
    let operation = Operation {
        operation_id,
        user_ref: user_ref.clone(),
        kind: "AllocateUserAccess",
        limit_bytes: Some(limit),
        period: Some(period.clone()),
        expire_at: Some(expire_at.clone()),
        squad_uuid: squad_uuid.clone(),
    };
    let username = provider_username(&user_ref);
    let (state, binding) = ctx.app.store.read(|connection| -> Result<(ReplayState, Option<Binding>), ApiError> {
        existing_user(connection, &user_ref)?;
        Ok((replay_state(connection, &operation)?, load_binding(connection, &user_ref)?))
    })?;
    if let ReplayState::Replay(result) = state {
        return Ok(replayed(result));
    }
    let authority = Remnawave::new(ctx.app.transport.as_ref(), ctx.cancel, &secrets.base_url, &secrets.token, secrets.timeout_ms);

    if let Some(binding) = binding {
        let read = authority.get_user(binding.provider_user_id);
        record_authority_outcome(ctx, read.as_ref().err());
        let read = read.map_err(|error| authority_api_error(ctx, error))?;
        let now = iso_from_millis(ctx.now());
        let snapshot = snapshot_from_projected(SnapshotInput {
            user_ref: &user_ref,
            projected: &read.projected,
            observed_at: &now,
            node_judgment: "AVAILABLE",
            node_remove: Value::Null,
        });
        let result = json!({
            "ok": true,
            "created": false,
            "binding": binding_view(&user_ref, &binding),
            "snapshot": public_quota(Some(&snapshot)),
            "projected": read.projected,
        });
        ctx.app.store.write(|transaction| -> Result<(), ControlError> {
            save_snapshot(transaction, &snapshot, &now)?;
            remember(transaction, &operation, &result, &now)
        })?;
        return Ok(ApiResponse::json(200, result));
    }

    let bind = |read: UserRead, created: bool, recovered: bool| -> Result<ApiResponse, ApiError> {
        let provider_user_id = read.projected["id"].as_i64().unwrap_or(0);
        let now = iso_from_millis(ctx.now());
        let snapshot = snapshot_from_projected(SnapshotInput {
            user_ref: &user_ref,
            projected: &read.projected,
            observed_at: &now,
            node_judgment: "AVAILABLE",
            node_remove: Value::Null,
        });
        let result = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
            let occupied: Option<String> = transaction
                .query_row(
                    "SELECT user_ref FROM control_provider_bindings WHERE provider_user_id = ?1 OR username = ?2",
                    params![provider_user_id, username],
                    |row| row.get(0),
                )
                .optional()
                .map_err(read_failed)?;
            if occupied.as_deref().map(|owner| owner != user_ref).unwrap_or(false) {
                return Err(ApiError::new(409, "PROVIDER_IDENTITY_CONFLICT", "权威侧身份已绑定到另一个应用用户"));
            }
            transaction
                .execute(
                    "INSERT INTO control_provider_bindings (user_ref, provider_user_id, username, authority_ref, squad_uuid, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(user_ref) DO UPDATE SET provider_user_id = excluded.provider_user_id, username = excluded.username, squad_uuid = excluded.squad_uuid",
                    params![user_ref, provider_user_id, username, AUTHORITY_REF, squad_uuid, now],
                )
                .map_err(|error| {
                    if is_constraint(&error) {
                        ApiError::new(409, "PROVIDER_IDENTITY_CONFLICT", "权威侧身份已绑定到另一个应用用户")
                    } else {
                        ApiError::from(write_failed(error))
                    }
                })?;
            let binding = load_binding(transaction, &user_ref)?.ok_or_else(|| ApiError::new(500, "CONTROL_STORE_WRITE_FAILED", "绑定写入后读不回"))?;
            save_snapshot(transaction, &snapshot, &now)?;
            let result = json!({
                "ok": true,
                "created": created,
                "recovered": recovered,
                "binding": binding_view(&user_ref, &binding),
                "snapshot": public_quota(Some(&snapshot)),
                "projected": read.projected,
                "http_status": read.http_status,
            });
            remember(transaction, &operation, &result, &now)?;
            Ok(result)
        });
        match result {
            Ok(result) => {
                ctx.info("admin.quota.allocated", json!({"actor": ctx.actor(), "user_ref": user_ref, "provider_user_id": provider_user_id, "created": created, "recovered": recovered}));
                Ok(ApiResponse::json(200, result))
            }
            Err(error) => {
                keep_pending(ctx, &operation, &error.code);
                Err(error)
            }
        }
    };

    if let ReplayState::Pending = state {
        let found = authority.get_by_username(&username);
        record_authority_outcome(ctx, found.as_ref().err());
        let found = found.map_err(|error| authority_api_error(ctx, error))?;
        return bind(found, false, true);
    }

    let now = iso_from_millis(ctx.now());
    ctx.app.store.write(|transaction| -> Result<(), ControlError> { begin(transaction, &operation, &now) })?;
    let squads: Option<Vec<String>> = squad_uuid.clone().map(|uuid| vec![uuid]);
    match authority.create_user(&username, &expire_at, limit, &period, squads.as_deref()) {
        Ok(created) => {
            record_authority_outcome(ctx, None);
            bind(created, true, false)
        }
        Err(error) if error.code == "AUTHORITY_CONFLICT" => {
            record_authority_outcome(ctx, None);
            match authority.get_by_username(&username) {
                Ok(found) if found.projected["username"].as_str() == Some(username.as_str()) => bind(found, false, true),
                Ok(_) => {
                    keep_pending(ctx, &operation, "PROVIDER_IDENTITY_CONFLICT");
                    Err(ApiError::new(409, "PROVIDER_IDENTITY_CONFLICT", "权威侧用户名已属于另一个身份"))
                }
                Err(error) => {
                    keep_pending(ctx, &operation, error.code);
                    Err(authority_api_error(ctx, error))
                }
            }
        }
        Err(error) => {
            record_authority_outcome(ctx, Some(&error));
            keep_pending(ctx, &operation, error.code);
            Err(authority_api_error(ctx, error))
        }
    }
}

// ---------------------------------------------------------------- 读取用量

/// 读用户用量。结果对象带 ok 标志；权威不可用时回最后快照并标 stale，不抛错。
fn read_user_usage(ctx: &Ctx, user_ref: &str) -> Result<Value, ApiError> {
    let (previous, binding) = ctx.app.store.read(|connection| -> Result<(Option<Value>, Option<Binding>), ControlError> {
        Ok((load_snapshot(connection, user_ref)?, load_binding(connection, user_ref)?))
    })?;
    let store_stale = |code: &str, retryable: bool| -> Result<Value, ApiError> {
        let stale = stale_snapshot(previous.as_ref(), user_ref, code);
        if previous.is_some() {
            let now = iso_from_millis(ctx.now());
            ctx.app.store.write(|transaction| -> Result<(), ControlError> { save_snapshot(transaction, &stale, &now) })?;
        }
        Ok(json!({"ok": false, "code": code, "snapshot": public_quota(Some(&stale)), "retryable": retryable}))
    };
    let secrets = match adapter_secrets(ctx) {
        Ok(secrets) => secrets,
        Err(error) => return store_stale(error.code, false),
    };
    let binding = match binding {
        Some(binding) => binding,
        None => {
            let unknown = json!({"user_ref": user_ref, "status": "UNKNOWN", "authority_status": "UNKNOWN", "node_new_limit_judgment": "UNKNOWN", "control_status": "AVAILABLE"});
            return Ok(json!({"ok": false, "code": "PROVIDER_BINDING_MISSING", "snapshot": public_quota(Some(previous.as_ref().unwrap_or(&unknown)))}));
        }
    };
    let authority = Remnawave::new(ctx.app.transport.as_ref(), ctx.cancel, &secrets.base_url, &secrets.token, secrets.timeout_ms);
    let read = authority.get_user(binding.provider_user_id);
    record_authority_outcome(ctx, read.as_ref().err());
    match read {
        Ok(read) => {
            let now = iso_from_millis(ctx.now());
            let next = snapshot_from_projected(SnapshotInput {
                user_ref,
                projected: &read.projected,
                observed_at: &now,
                node_judgment: "AVAILABLE",
                node_remove: previous.as_ref().and_then(|item| item.get("node_remove").cloned()).unwrap_or(Value::Null),
            });
            if let Err(code) = can_replace_snapshot(previous.as_ref(), &next) {
                let mut kept = previous.clone().unwrap_or(Value::Null);
                if kept.is_object() {
                    kept["stale"] = json!(true);
                }
                return Ok(json!({"ok": false, "code": code, "snapshot": public_quota(Some(&kept))}));
            }
            ctx.app.store.write(|transaction| -> Result<(), ControlError> { save_snapshot(transaction, &next, &now) })?;
            Ok(json!({"ok": true, "snapshot": public_quota(Some(&next)), "projected": read.projected}))
        }
        Err(error) => {
            ctx.warn("quota.usage.authority_failed", json!({"user_ref": user_ref, "code": error.code, "detail": error.detail}));
            store_stale(error.code, error.retryable)
        }
    }
}

pub fn usage(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let user_ref = ctx.query("user_ref").ok_or_else(|| ApiError::invalid("查询参数 user_ref 必填"))?.to_string();
    ctx.app.store.read(|connection| -> Result<(), ApiError> {
        existing_user(connection, &user_ref)?;
        Ok(())
    })?;
    Ok(ApiResponse::json(200, read_user_usage(ctx, &user_ref)?))
}

/// 普通用户读自己的额度：结果附 readQuotaView 视图；权威没配或不可用时回陈旧快照与原因码。
pub fn network_quota(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let actor = ctx.actor().to_string();
    let loaded = read_user_usage(ctx, &actor)?;
    let snapshot = loaded.get("snapshot").cloned().unwrap_or(Value::Null);
    let view = if snapshot.is_null() { Value::Null } else { read_quota_view(Some(&snapshot)) };
    let mut body = json!({
        "user_ref": actor,
        "quota": snapshot,
        "view": view,
        "stale": snapshot.get("stale").and_then(Value::as_bool) == Some(true),
    });
    if loaded.get("ok").and_then(Value::as_bool) != Some(true) {
        body["code"] = loaded.get("code").cloned().unwrap_or(Value::Null);
    }
    Ok(ApiResponse::json(200, body))
}

// ---------------------------------------------------------------- 调额、停用、恢复

fn with_binding(ctx: &Ctx, user_ref: &str, operation: &Operation) -> Result<(ReplayState, Binding), ApiError> {
    ctx.app.store.read(|connection| -> Result<(ReplayState, Binding), ApiError> {
        existing_user(connection, user_ref)?;
        let binding = load_binding(connection, user_ref)?
            .ok_or_else(|| ApiError::new(409, "PROVIDER_BINDING_MISSING", "该用户还没有权威侧身份，请先分配额度身份"))?;
        Ok((replay_state(connection, operation)?, binding))
    })
}

fn finish_with_snapshot(ctx: &Ctx, operation: &Operation, snapshot: &Value, result: Value) -> Result<ApiResponse, ApiError> {
    let now = iso_from_millis(ctx.now());
    ctx.app.store.write(|transaction| -> Result<(), ControlError> {
        save_snapshot(transaction, snapshot, &now)?;
        remember(transaction, operation, &result, &now)
    })?;
    ctx.info("admin.quota.operation", json!({"actor": ctx.actor(), "operation_id": operation.operation_id, "kind": operation.kind, "user_ref": operation.user_ref, "ok": result["ok"]}));
    Ok(ApiResponse::json(200, result))
}

pub fn change_limit(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let secrets = adapter_secrets(ctx).map_err(|error| authority_api_error(ctx, error))?;
    let body = ctx.body()?;
    let input = fields(&body, &OPERATION_FIELDS)?;
    let user_ref = required_ref(&input, &["userRef", "user_ref"])?;
    let operation_id = operation_id(&input)?;
    let limit = limit_bytes(&input)?.filter(|bytes| *bytes > 0).ok_or_else(|| ApiError::new(400, "LIMIT_REQUIRED", "改额度不能设为 0 或无限"))?;
    let operation = Operation { operation_id, user_ref: user_ref.clone(), kind: "ChangeLimit", limit_bytes: Some(limit), period: None, expire_at: None, squad_uuid: None };
    let (state, binding) = with_binding(ctx, &user_ref, &operation)?;
    let pending = match state {
        ReplayState::Replay(result) => return Ok(replayed(result)),
        ReplayState::Pending => true,
        ReplayState::Start => false,
    };
    let authority = Remnawave::new(ctx.app.transport.as_ref(), ctx.cancel, &secrets.base_url, &secrets.token, secrets.timeout_ms);
    let outcome: Result<(UserRead, bool), AuthorityError> = if pending {
        authority.get_user(binding.provider_user_id).map(|read| {
            let accepted = int(read.projected.get("trafficLimitBytes")) == Some(limit);
            (read, accepted)
        })
    } else {
        let now = iso_from_millis(ctx.now());
        ctx.app.store.write(|transaction| -> Result<(), ControlError> { begin(transaction, &operation, &now) })?;
        authority
            .update_limit(binding.provider_user_id, limit)
            .and_then(|_| authority.get_user(binding.provider_user_id))
            .map(|read| (read, true))
    };
    record_authority_outcome(ctx, outcome.as_ref().err());
    let (read, accepted) = match outcome {
        Ok(value) => value,
        Err(error) => {
            if !pending {
                keep_pending(ctx, &operation, error.code);
            }
            return Err(authority_api_error(ctx, error));
        }
    };
    let now = iso_from_millis(ctx.now());
    let snapshot = snapshot_from_projected(SnapshotInput { user_ref: &user_ref, projected: &read.projected, observed_at: &now, node_judgment: "AVAILABLE", node_remove: Value::Null });
    let effective = int(read.projected.get("trafficLimitBytes")) == Some(limit);
    let result = json!({"ok": true, "accepted": accepted, "effective": effective, "snapshot": public_quota(Some(&snapshot)), "http_status": read.http_status, "replayed": pending});
    finish_with_snapshot(ctx, &operation, &snapshot, result)
}

pub fn suspend(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let secrets = adapter_secrets(ctx).map_err(|error| authority_api_error(ctx, error))?;
    let body = ctx.body()?;
    let input = fields(&body, &OPERATION_FIELDS)?;
    let user_ref = required_ref(&input, &["userRef", "user_ref"])?;
    let operation_id = operation_id(&input)?;
    let operation = Operation { operation_id, user_ref: user_ref.clone(), kind: "SuspendUserAccess", limit_bytes: None, period: None, expire_at: None, squad_uuid: None };
    let (state, binding) = with_binding(ctx, &user_ref, &operation)?;
    let pending = match state {
        ReplayState::Replay(result) => return Ok(replayed(result)),
        ReplayState::Pending => true,
        ReplayState::Start => false,
    };
    let authority = Remnawave::new(ctx.app.transport.as_ref(), ctx.cancel, &secrets.base_url, &secrets.token, secrets.timeout_ms);
    let outcome = if pending {
        authority.get_user(binding.provider_user_id)
    } else {
        let now = iso_from_millis(ctx.now());
        ctx.app.store.write(|transaction| -> Result<(), ControlError> { begin(transaction, &operation, &now) })?;
        authority.disable_user(binding.provider_user_id)
    };
    record_authority_outcome(ctx, outcome.as_ref().err());
    let read = match outcome {
        Ok(read) => read,
        Err(error) => {
            if !pending {
                keep_pending(ctx, &operation, error.code);
            }
            return Err(authority_api_error(ctx, error));
        }
    };
    let now = iso_from_millis(ctx.now());
    let disabled = read.projected["status"].as_str() == Some("DISABLED");
    let snapshot = snapshot_from_projected(SnapshotInput {
        user_ref: &user_ref,
        projected: &read.projected,
        observed_at: &now,
        node_judgment: "UNKNOWN",
        node_remove: unknown_node_effect(),
    });
    // 调用结果未知后回读仍未停用：记为进行中，不当成停用成功。
    let result = if pending && !disabled {
        json!({"ok": false, "code": "QUOTA_OPERATION_IN_FLIGHT", "backend_accepted": false, "node_effect": unknown_node_effect(), "snapshot": public_quota(Some(&snapshot)), "replayed": true})
    } else {
        json!({
            "ok": true,
            "backend_accepted": disabled,
            "node_effect": unknown_node_effect(),
            "snapshot": public_quota(Some(&snapshot)),
            "subscription_stop_only": false,
            "http_status": read.http_status,
            "replayed": pending,
        })
    };
    finish_with_snapshot(ctx, &operation, &snapshot, result)
}

fn qualify_resume(projected: &Value, now_ms: i64) -> Result<(), ApiError> {
    if projected.get("subRevokedAt").and_then(Value::as_str).is_some() {
        return Err(ApiError::new(409, "CREDENTIAL_REVOKED", "权威侧已撤销该用户的订阅凭据"));
    }
    if let Some(expire) = projected.get("expireAt").and_then(Value::as_str).and_then(millis_from_iso) {
        if expire <= now_ms {
            return Err(ApiError::new(409, "USER_EXPIRED", "权威侧用户已到期"));
        }
    }
    let limit = int(projected.get("trafficLimitBytes"));
    let used = int(projected.get("usedTrafficBytes")).unwrap_or(0);
    if let Some(limit) = limit {
        if limit != 0 && limit - used <= 0 && projected["status"].as_str() == Some("LIMITED") {
            return Err(ApiError::new(409, "STILL_LIMITED", "额度仍然耗尽；请先调高额度"));
        }
    }
    Ok(())
}

pub fn resume(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let secrets = adapter_secrets(ctx).map_err(|error| authority_api_error(ctx, error))?;
    let body = ctx.body()?;
    let input = fields(&body, &OPERATION_FIELDS)?;
    let user_ref = required_ref(&input, &["userRef", "user_ref"])?;
    let operation_id = operation_id(&input)?;
    let operation = Operation { operation_id, user_ref: user_ref.clone(), kind: "ResumeUserAccess", limit_bytes: None, period: None, expire_at: None, squad_uuid: None };
    let (state, binding) = with_binding(ctx, &user_ref, &operation)?;
    let now_ms = ctx.now();
    let assignment = ctx.app.store.read(|connection| -> Result<Option<Value>, ControlError> { published_assignment(connection, &user_ref) })?;
    let validation = validate_assignment(assignment.as_ref(), assignment.as_ref().and_then(|item| item.get("environment_ref")).and_then(Value::as_str), now_ms);
    if validation["ok"].as_bool() != Some(true) {
        let code = validation["code"].as_str().unwrap_or("ASSIGNMENT_INVALID").to_string();
        let reason = validation["reason"].as_str().unwrap_or("assignment is not usable").to_string();
        return Err(ApiError::new(crate::api::status_for(&code), code, reason).with("issues", validation["issues"].clone()));
    }
    let pending = match state {
        ReplayState::Replay(result) => return Ok(replayed(result)),
        ReplayState::Pending => true,
        ReplayState::Start => false,
    };
    let authority = Remnawave::new(ctx.app.transport.as_ref(), ctx.cancel, &secrets.base_url, &secrets.token, secrets.timeout_ms);
    if !pending {
        let now = iso_from_millis(ctx.now());
        ctx.app.store.write(|transaction| -> Result<(), ControlError> { begin(transaction, &operation, &now) })?;
    }
    let current = authority.get_user(binding.provider_user_id);
    record_authority_outcome(ctx, current.as_ref().err());
    let current = match current {
        Ok(read) => read,
        Err(error) => {
            if !pending {
                keep_pending(ctx, &operation, error.code);
            }
            return Err(authority_api_error(ctx, error));
        }
    };
    if let Err(error) = qualify_resume(&current.projected, now_ms) {
        if !pending {
            keep_pending(ctx, &operation, &error.code);
        }
        return Err(error);
    }
    let roles = assignment.as_ref().and_then(|item| item.get("roles")).cloned().unwrap_or(Value::Null);
    let restored = json!({"A": roles.get("A").cloned().unwrap_or(Value::Null), "B": roles.get("B").cloned().unwrap_or(Value::Null)});
    let now = iso_from_millis(ctx.now());
    if pending {
        let active = current.projected["status"].as_str() == Some("ACTIVE");
        let snapshot = snapshot_from_projected(SnapshotInput {
            user_ref: &user_ref,
            projected: &current.projected,
            observed_at: &now,
            node_judgment: if active { "AVAILABLE" } else { "UNKNOWN" },
            node_remove: no_node_effect(),
        });
        let result = if active {
            json!({"ok": true, "backend_accepted": true, "restored_roles": restored, "snapshot": public_quota(Some(&snapshot)), "http_status": current.http_status, "replayed": true})
        } else {
            json!({"ok": false, "code": "QUOTA_OPERATION_IN_FLIGHT", "snapshot": public_quota(Some(&snapshot)), "replayed": true})
        };
        return finish_with_snapshot(ctx, &operation, &snapshot, result);
    }
    let enabled = authority.enable_user(binding.provider_user_id);
    record_authority_outcome(ctx, enabled.as_ref().err());
    let enabled = match enabled {
        Ok(read) => read,
        Err(error) => {
            keep_pending(ctx, &operation, error.code);
            return Err(authority_api_error(ctx, error));
        }
    };
    let snapshot = snapshot_from_projected(SnapshotInput {
        user_ref: &user_ref,
        projected: &enabled.projected,
        observed_at: &now,
        node_judgment: "AVAILABLE",
        node_remove: no_node_effect(),
    });
    let result = json!({
        "ok": true,
        "backend_accepted": true,
        "restored_roles": restored,
        "snapshot": public_quota(Some(&snapshot)),
        "http_status": enabled.http_status,
        "replayed": false,
    });
    finish_with_snapshot(ctx, &operation, &snapshot, result)
}

// ---------------------------------------------------------------- 资源池与服务状态

pub fn pool(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let secrets = adapter_secrets(ctx).map_err(|error| authority_api_error(ctx, error))?;
    let pool_id = ctx.query("pool_id").unwrap_or("default").to_string();
    if !crate::api::valid_ref(&pool_id) {
        return Err(ApiError::invalid("pool_id 只能含字母、数字与 . _ : -"));
    }
    let authority = Remnawave::new(ctx.app.transport.as_ref(), ctx.cancel, &secrets.base_url, &secrets.token, secrets.timeout_ms);
    let listed = authority.list_nodes();
    record_authority_outcome(ctx, listed.as_ref().err());
    let now = iso_from_millis(ctx.now());
    match listed {
        Ok(nodes) => {
            let exhausted = nodes.iter().any(|node| {
                node["isTrafficTrackingActive"] == true
                    && matches!((int(node.get("trafficLimitBytes")), int(node.get("trafficUsedBytes"))), (Some(limit), Some(used)) if limit > 0 && used >= limit)
            });
            let snapshot = json!({
                "pool_id": pool_id,
                "observed_at": now,
                "source": "remnawave-nodes",
                "nodes": nodes,
                "shared_subscription_balance": {"status": "UNKNOWN", "reason": "PROVIDER_FINANCIAL_BALANCE_UNSUPPORTED"},
                "user_quota_sum_is_not_pool": true,
                "exhausted": exhausted,
                "authority_status": "AVAILABLE",
                "stale": false,
            });
            ctx.app.store.write(|transaction| -> Result<(), ControlError> {
                transaction
                    .execute(
                        "INSERT INTO control_pool_snapshots (pool_id, payload_json, updated_at) VALUES (?1, ?2, ?3)
                         ON CONFLICT(pool_id) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at",
                        params![pool_id, snapshot.to_string(), now],
                    )
                    .map_err(write_failed)?;
                Ok(())
            })?;
            Ok(ApiResponse::json(200, json!({"ok": true, "snapshot": snapshot})))
        }
        Err(error) => {
            ctx.warn("quota.pool.authority_failed", json!({"code": error.code, "detail": error.detail}));
            let previous: Option<String> = ctx.app.store.read(|connection| -> Result<Option<String>, ControlError> {
                connection
                    .query_row("SELECT payload_json FROM control_pool_snapshots WHERE pool_id = ?1", params![pool_id], |row| row.get(0))
                    .optional()
                    .map_err(read_failed)
            })?;
            let snapshot = match previous.and_then(|text| serde_json::from_str::<Value>(&text).ok()) {
                Some(mut kept) => {
                    kept["stale"] = json!(true);
                    kept["authority_status"] = json!("OFFLINE");
                    kept
                }
                None => json!({"pool_id": pool_id, "stale": true, "authority_status": "OFFLINE", "shared_subscription_balance": {"status": "UNKNOWN", "reason": "PROVIDER_FINANCIAL_BALANCE_UNSUPPORTED"}}),
            };
            Ok(ApiResponse::json(200, json!({"ok": false, "code": error.code, "snapshot": snapshot})))
        }
    }
}

pub fn service_state(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let (adapter, available_models, schema) = ctx.app.store.read(|connection| -> Result<(Value, i64, String), ControlError> {
        let available: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM control_model_policies p JOIN control_secrets s ON s.secret_ref = p.secret_ref
                  WHERE p.enabled = 1 AND p.base_url IS NOT NULL AND p.model IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .map_err(read_failed)?;
        let schema: String = connection
            .query_row("SELECT value FROM control_meta WHERE key = 'schema_version'", [], |row| row.get(0))
            .map_err(read_failed)?;
        Ok((adapter_view(connection)?, available, schema))
    })?;
    let mut adapter_summary = Map::new();
    for key in ["configured", "enabled", "verification", "last_error_code", "last_call_at", "base_url_display"] {
        adapter_summary.insert(key.to_string(), adapter.get(key).cloned().unwrap_or(Value::Null));
    }
    Ok(ApiResponse::json(
        200,
        json!({
            "control_status": "AVAILABLE",
            "adapter_configured": adapter["configured"],
            "adapter": Value::Object(adapter_summary),
            "model_tasks_available": available_models,
            "secret_protection": ctx.app.protector.kind(),
            "schema_version": schema,
            "log_status": ctx.app.logger.status(),
            "observed_at": iso_from_millis(ctx.now()),
        }),
    ))
}
