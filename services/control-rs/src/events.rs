//! 最小网络事件（迁自 Node 基线 eventService.mjs）。
//!
//! - 只保存业务需要的引用、分类、保护状态、计数与时间；白名单以外的字段不落库，也不回显。
//! - 正文里出现基线认定的秘密标记（vlessUuid、订阅链接、代理密码、配置 YAML 等）整条拒收。
//! - 以 event_ref 去重合并：计数取大、首次时间不变、末次时间取晚、保护状态只前进不后退。
//! - 普通用户只能提交与读取自己的事件；event_ref 已属于别人时拒绝。管理员可代指定用户提交。

use std::sync::OnceLock;

use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::admin_users::existing_user;
use crate::api::{valid_ref, ApiError};
use crate::router::{ApiResponse, Ctx};
use crate::store::{read_failed, write_failed};
use crate::{iso_from_millis, millis_from_iso, ControlError};

const ALLOWED_FIELDS: [&str; 15] = [
    "event_ref", "user_ref", "environment_ref", "kind", "classification", "protection_status", "action_requested",
    "action_effective", "evidence_ref", "version", "role", "count", "first_at", "last_at", "occurred_at",
];
const MERGED_FIELDS: [&str; 8] = ["environment_ref", "kind", "classification", "action_requested", "action_effective", "evidence_ref", "version", "role"];
const MAX_TEXT_CHARS: usize = 256;

fn secret_marker() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r#"(?i)vlessUuid|trojanPassword|ssPassword|subscriptionUrl|"pass"|proxy_password|yaml:"#).expect("固定的秘密标记规则")
    })
}

fn stage_rank(status: Option<&str>) -> u8 {
    match status {
        Some("PENDING") => 1,
        Some("ACCEPTED") => 2,
        Some("RECORDED") => 3,
        Some("CONFIRMED") => 4,
        _ => 0,
    }
}

fn event_invalid(reason: impl Into<String>) -> ApiError {
    ApiError::new(400, "EVENT_INVALID", reason)
}

fn load_event(connection: &Connection, event_ref: &str) -> Result<Option<(String, Value)>, ControlError> {
    let row: Option<(String, String)> = connection
        .query_row("SELECT user_ref, payload_json FROM control_network_events WHERE event_ref = ?1", params![event_ref], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()
        .map_err(read_failed)?;
    Ok(row.map(|(user_ref, payload)| (user_ref, serde_json::from_str(&payload).unwrap_or(Value::Null))))
}

fn later(left: Option<&str>, right: Option<&str>) -> Option<String> {
    match (left, right) {
        (Some(a), Some(b)) => match (millis_from_iso(a), millis_from_iso(b)) {
            (Some(x), Some(y)) if y < x => Some(a.to_string()),
            _ => Some(b.to_string()),
        },
        (Some(a), None) => Some(a.to_string()),
        (None, Some(b)) => Some(b.to_string()),
        (None, None) => None,
    }
}

pub fn receive(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let object = body.as_object().ok_or_else(|| event_invalid("事件必须是 JSON 对象"))?;
    if secret_marker().is_match(&body.to_string()) {
        ctx.warn("network.event.secret_rejected", json!({"user_ref": ctx.actor()}));
        return Err(ApiError::new(400, "EVENT_SECRET_REJECTED", "最小事件不能携带秘密或完整证据"));
    }
    let mut event = Map::new();
    let mut dropped: Vec<String> = Vec::new();
    for (key, value) in object {
        if !ALLOWED_FIELDS.contains(&key.as_str()) {
            dropped.push(key.clone());
            continue;
        }
        match value {
            Value::String(text) if text.chars().count() > MAX_TEXT_CHARS => {
                return Err(event_invalid(format!("字段 {key} 超过 {MAX_TEXT_CHARS} 个字符")));
            }
            Value::Object(_) | Value::Array(_) => return Err(event_invalid(format!("字段 {key} 只能是字符串、数字或布尔值"))),
            _ => {
                event.insert(key.clone(), value.clone());
            }
        }
    }
    let event_ref = event
        .get("event_ref")
        .and_then(Value::as_str)
        .filter(|reference| valid_ref(reference))
        .ok_or_else(|| event_invalid("event_ref 必填，且只能含字母、数字与 . _ : -"))?
        .to_string();
    let claimed = event.get("user_ref").and_then(Value::as_str).map(str::to_string);
    let actor = ctx.actor().to_string();
    if !ctx.is_admin() && claimed.as_deref().map(|user| user != actor).unwrap_or(false) {
        return Err(ApiError::new(403, "CONTROL_FORBIDDEN", "不能以另一个用户的身份提交事件"));
    }
    let user_ref = if ctx.is_admin() { claimed.unwrap_or_else(|| actor.clone()) } else { actor.clone() };
    for key in ["first_at", "last_at", "occurred_at"] {
        if let Some(value) = event.get(key) {
            if value.as_str().and_then(millis_from_iso).is_none() {
                return Err(event_invalid(format!("字段 {key} 必须是带时区的 ISO 8601 时间")));
            }
        }
    }
    if let Some(count) = event.get("count") {
        if count.as_i64().map(|value| value < 0).unwrap_or(true) {
            return Err(event_invalid("count 必须是非负整数"));
        }
    }
    let now = iso_from_millis(ctx.now());
    let (duplicate, saved) = ctx.app.store.write(|transaction| -> Result<(bool, Value), ApiError> {
        existing_user(transaction, &user_ref)?;
        let existing = load_event(transaction, &event_ref)?;
        if let Some((owner, _)) = &existing {
            if owner != &user_ref {
                return Err(ApiError::new(403, "CONTROL_FORBIDDEN", "这个 event_ref 属于另一个用户"));
            }
        }
        let previous = existing.as_ref().map(|(_, payload)| payload.clone()).unwrap_or(Value::Null);
        let text_of = |source: &Value, key: &str| source.get(key).and_then(Value::as_str).map(str::to_string);
        let first_at = text_of(&previous, "first_at").or_else(|| text_of(&Value::Object(event.clone()), "first_at")).unwrap_or_else(|| now.clone());
        let last_at = later(previous.get("last_at").and_then(Value::as_str), event.get("last_at").and_then(Value::as_str)).unwrap_or_else(|| first_at.clone());
        let count = previous.get("count").and_then(Value::as_i64).unwrap_or(0).max(event.get("count").and_then(Value::as_i64).unwrap_or(1));
        let incoming_stage = event.get("protection_status").and_then(Value::as_str);
        let previous_stage = previous.get("protection_status").and_then(Value::as_str);
        let protection = if stage_rank(incoming_stage) >= stage_rank(previous_stage) {
            incoming_stage.or(previous_stage).map(str::to_string)
        } else {
            previous_stage.map(str::to_string)
        };
        let mut saved = Map::new();
        saved.insert("event_ref".to_string(), json!(event_ref));
        saved.insert("user_ref".to_string(), json!(user_ref));
        for key in MERGED_FIELDS {
            let value = event.get(key).filter(|value| !value.is_null()).or_else(|| previous.get(key)).cloned().unwrap_or(Value::Null);
            saved.insert(key.to_string(), value);
        }
        saved.insert("protection_status".to_string(), json!(protection));
        saved.insert("count".to_string(), json!(count));
        saved.insert("first_at".to_string(), json!(first_at));
        saved.insert("last_at".to_string(), json!(last_at));
        let occurred = text_of(&previous, "occurred_at").or_else(|| event.get("occurred_at").and_then(Value::as_str).map(str::to_string)).unwrap_or_else(|| first_at.clone());
        saved.insert("occurred_at".to_string(), json!(occurred));
        let saved = Value::Object(saved);
        transaction
            .execute(
                "INSERT INTO control_network_events (event_ref, user_ref, payload_json, received_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(event_ref) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at",
                params![event_ref, user_ref, saved.to_string(), now],
            )
            .map_err(write_failed)?;
        let receipt_stage: Option<String> = transaction
            .query_row("SELECT status FROM control_event_receipts WHERE event_ref = ?1", params![event_ref], |row| row.get(0))
            .optional()
            .map_err(read_failed)?;
        if stage_rank(Some("ACCEPTED")) >= stage_rank(receipt_stage.as_deref()) {
            let receipt = json!({"event_ref": event_ref, "user_ref": user_ref, "status": "ACCEPTED", "accepted": true, "received_at": now, "duplicate": existing.is_some()});
            transaction
                .execute(
                    "INSERT INTO control_event_receipts (event_ref, user_ref, status, payload_json) VALUES (?1, ?2, 'ACCEPTED', ?3)
                     ON CONFLICT(event_ref) DO UPDATE SET status = 'ACCEPTED', payload_json = excluded.payload_json",
                    params![event_ref, user_ref, receipt.to_string()],
                )
                .map_err(write_failed)?;
        }
        Ok((existing.is_some(), saved))
    })?;
    ctx.info(
        "network.event.recorded",
        json!({"user_ref": user_ref, "event_ref": event_ref, "duplicate": duplicate, "count": saved["count"], "dropped_fields": dropped}),
    );
    Ok(ApiResponse::json(200, json!({"status": "RECORDED", "event_ref": event_ref, "duplicate": duplicate})))
}

fn events_for(connection: &Connection, user_ref: Option<&str>) -> Result<Vec<Value>, ControlError> {
    let (sql, values): (&str, Vec<String>) = match user_ref {
        Some(user) => ("SELECT payload_json FROM control_network_events WHERE user_ref = ?1 ORDER BY event_ref LIMIT 1000", vec![user.to_string()]),
        None => ("SELECT payload_json FROM control_network_events ORDER BY event_ref LIMIT 1000", Vec::new()),
    };
    let mut statement = connection.prepare(sql).map_err(read_failed)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(values.iter()), |row| row.get::<_, String>(0))
        .map_err(read_failed)?;
    let collected: Result<Vec<String>, rusqlite::Error> = rows.collect();
    Ok(collected
        .map_err(read_failed)?
        .iter()
        .map(|payload| serde_json::from_str(payload).unwrap_or(Value::Null))
        .collect())
}

pub fn list_mine(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let actor = ctx.actor().to_string();
    let events = ctx.app.store.read(|connection| -> Result<Vec<Value>, ControlError> { events_for(connection, Some(&actor)) })?;
    Ok(ApiResponse::json(200, json!({"user_ref": actor, "events": events})))
}

pub fn admin_list(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let user_ref = ctx.query("user_ref").map(str::to_string);
    let events = ctx.app.store.read(|connection| -> Result<Vec<Value>, ApiError> {
        if let Some(user) = &user_ref {
            existing_user(connection, user)?;
        }
        Ok(events_for(connection, user_ref.as_deref())?)
    })?;
    Ok(ApiResponse::json(200, json!({"user_ref": user_ref, "events": events})))
}
