//! 服务器模型配置与 AI 路由（迁自 Node 基线 handler.mjs / modelPolicy.mjs）。
//!
//! - 客户端提交任务类型、提示词版本与正文、工具目录版本和已脱敏消息；提供方、端点、模型、密钥、
//!   输出上限、超时与预算全部取自服务器配置，请求里夹带这些字段直接 400。
//! - 提示词版本与工具目录版本只接受内置协议表（protocol/ai-protocol.json，由客户端同一份源生成）。
//! - task_ref 归属首个提交它的应用用户，并固定首次的任务类型，换类型回 409；同一 turn_ref 重放返回原结果，内容不同回 409。
//! - 预算按任务计：调用次数与 total_tokens；有一次用量未知就按耗尽处理（与基线相同）。
//! - 保存配置只意味着「已配置」：verification 从 NOT_TESTED 开始，只有真实调用成功才变 CALL_SUCCEEDED。
//! - 日志只记任务与轮次引用、任务类型、策略版本、结果码与用量，不记提示词、消息或密钥。

use std::sync::OnceLock;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::api::{fields, valid_ref, validate_service_url, ApiError};
use crate::provider::{self, ChatRequest};
use crate::redact::redact_for_model;
use crate::router::{ApiResponse, Ctx};
use crate::secrets::{delete_secret, put_secret, read_secret_text, secret_meta};
use crate::store::{read_failed, write_failed};
use crate::{canonical_json, iso_from_millis, sha256_hex, ControlError};

pub const TASK_TYPES: [&str; 3] = ["cleanup", "network_diagnosis", "daily_analysis"];
const PROVIDER: &str = "openai-compatible";
const MAX_MESSAGES_CHARS: usize = 64_000;
const MAX_PROMPT_CHARS: usize = 128_000;

fn protocol_table() -> Result<&'static Value, ApiError> {
    static TABLE: OnceLock<Option<Value>> = OnceLock::new();
    TABLE
        .get_or_init(|| serde_json::from_str(include_str!("../protocol/ai-protocol.json")).ok())
        .as_ref()
        .ok_or_else(|| ApiError::new(500, "CONTROL_PROTOCOL_CATALOG_INVALID", "内置 AI 协议表无法解析"))
}

pub struct Protocol {
    pub prompt_version: String,
    pub tool_catalog_version: String,
    pub tools: &'static Value,
}

pub fn protocol_for(task_type: &str) -> Result<Option<Protocol>, ApiError> {
    let entry = match protocol_table()?.get(task_type) {
        Some(entry) => entry,
        None => return Ok(None),
    };
    let text = |key: &str| entry.get(key).and_then(Value::as_str).map(str::to_string);
    match (text("prompt_version"), text("tool_catalog_version"), entry.get("tools")) {
        (Some(prompt_version), Some(tool_catalog_version), Some(tools)) if tools.is_array() => {
            Ok(Some(Protocol { prompt_version, tool_catalog_version, tools }))
        }
        _ => Err(ApiError::new(500, "CONTROL_PROTOCOL_CATALOG_INVALID", "内置 AI 协议表缺字段")),
    }
}

#[derive(Debug, Clone)]
struct Policy {
    enabled: bool,
    base_url: Option<String>,
    model: Option<String>,
    policy_version: String,
    max_model_calls: i64,
    max_total_tokens: i64,
    max_output_tokens: i64,
    timeout_ms: i64,
    secret_ref: Option<String>,
    verification: String,
    last_error_code: Option<String>,
    last_call_at: Option<String>,
    updated_at: String,
}

struct Defaults {
    max_model_calls: i64,
    max_total_tokens: i64,
    max_output_tokens: i64,
    timeout_ms: i64,
}

/// 技术默认值沿用 Node 基线：8 次调用、64000 token（日报分析 16000）、4096 输出、60 秒。
fn defaults(task_type: &str) -> Defaults {
    Defaults {
        max_model_calls: 8,
        max_total_tokens: if task_type == "daily_analysis" { 16_000 } else { 64_000 },
        max_output_tokens: 4096,
        timeout_ms: 60_000,
    }
}

fn load_policy(connection: &Connection, task_type: &str) -> Result<Option<Policy>, ControlError> {
    connection
        .query_row(
            "SELECT enabled, base_url, model, policy_version, max_model_calls, max_total_tokens, max_output_tokens, timeout_ms,
                    secret_ref, verification, last_error_code, last_call_at, updated_at
               FROM control_model_policies WHERE task_type = ?1",
            params![task_type],
            |row| {
                let enabled: i64 = row.get(0)?;
                Ok(Policy {
                    enabled: enabled == 1,
                    base_url: row.get(1)?,
                    model: row.get(2)?,
                    policy_version: row.get(3)?,
                    max_model_calls: row.get(4)?,
                    max_total_tokens: row.get(5)?,
                    max_output_tokens: row.get(6)?,
                    timeout_ms: row.get(7)?,
                    secret_ref: row.get(8)?,
                    verification: row.get(9)?,
                    last_error_code: row.get(10)?,
                    last_call_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(read_failed)
}

/// 不可用原因；可用时为 None。
fn unavailable_reason(policy: Option<&Policy>, secret_present: bool) -> Option<&'static str> {
    match policy {
        None => Some("MODEL_NOT_CONFIGURED"),
        Some(policy) if !policy.enabled => Some("MODEL_DISABLED"),
        Some(policy) if policy.base_url.is_none() || policy.model.is_none() => Some("MODEL_NOT_CONFIGURED"),
        Some(_) if !secret_present => Some("MODEL_SECRET_MISSING"),
        Some(_) => None,
    }
}

fn admin_view(connection: &Connection, task_type: &str) -> Result<Value, ApiError> {
    let policy = load_policy(connection, task_type)?;
    let secret = secret_meta(connection, policy.as_ref().and_then(|item| item.secret_ref.as_deref()))?;
    let reason = unavailable_reason(policy.as_ref(), secret.is_some());
    let protocol = protocol_for(task_type)?;
    let fallback = defaults(task_type);
    let status = if reason.is_none() { "AVAILABLE" } else { "UNAVAILABLE" };
    Ok(json!({
        "task_type": task_type,
        "configured": policy.is_some(),
        "provider": PROVIDER,
        "enabled": policy.as_ref().map(|item| item.enabled).unwrap_or(false),
        "base_url": policy.as_ref().and_then(|item| item.base_url.clone()),
        "model": policy.as_ref().and_then(|item| item.model.clone()),
        "policy_version": policy.as_ref().map(|item| item.policy_version.clone()),
        "max_model_calls": policy.as_ref().map(|item| item.max_model_calls).unwrap_or(fallback.max_model_calls),
        "max_total_tokens": policy.as_ref().map(|item| item.max_total_tokens).unwrap_or(fallback.max_total_tokens),
        "max_output_tokens": policy.as_ref().map(|item| item.max_output_tokens).unwrap_or(fallback.max_output_tokens),
        "timeout_ms": policy.as_ref().map(|item| item.timeout_ms).unwrap_or(fallback.timeout_ms),
        "secret_present": secret.is_some(),
        "secret_updated_at": secret.as_ref().map(|item| item.updated_at.clone()),
        "secret_version": secret.as_ref().map(|item| item.version),
        "status": status,
        "reason": reason,
        "verification": policy.as_ref().map(|item| item.verification.clone()).unwrap_or_else(|| "NOT_TESTED".to_string()),
        "last_error_code": policy.as_ref().and_then(|item| item.last_error_code.clone()),
        "last_call_at": policy.as_ref().and_then(|item| item.last_call_at.clone()),
        "updated_at": policy.as_ref().map(|item| item.updated_at.clone()),
        "prompt_version": protocol.as_ref().map(|item| item.prompt_version.clone()),
        "tool_catalog_version": protocol.as_ref().map(|item| item.tool_catalog_version.clone()),
    }))
}

pub fn get_model_config(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let tasks = ctx.app.store.read(|connection| -> Result<Value, ApiError> {
        let mut tasks = serde_json::Map::new();
        for task_type in TASK_TYPES {
            tasks.insert(task_type.to_string(), admin_view(connection, task_type)?);
        }
        Ok(Value::Object(tasks))
    })?;
    Ok(ApiResponse::json(200, json!({"provider": PROVIDER, "tasks": tasks})))
}

fn config_invalid(reason: impl Into<String>, field: &str) -> ApiError {
    ApiError::new(400, "MODEL_CONFIG_INVALID", reason).with("field", json!(field))
}

pub fn put_model_config(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(
        &body,
        &[
            "task_type", "enabled", "base_url", "model", "policy_version", "max_model_calls", "max_total_tokens",
            "max_output_tokens", "timeout_ms", "api_key", "clear_api_key",
        ],
    )?;
    let task_type = input.required_string("task_type", 64)?;
    if !TASK_TYPES.contains(&task_type.as_str()) {
        return Err(config_invalid("task_type 只能是 cleanup、network_diagnosis 或 daily_analysis", "task_type"));
    }
    let enabled = input.boolean("enabled")?;
    let base_url = input.string("base_url", 2048)?;
    if let Some(url) = &base_url {
        validate_service_url(url, "base_url")?;
    }
    let model = input.string("model", 200)?;
    let policy_version = input.string("policy_version", 128)?;
    if let Some(version) = &policy_version {
        if !valid_ref(version) {
            return Err(config_invalid("policy_version 只能含字母、数字与 . _ : -", "policy_version"));
        }
    }
    let max_model_calls = input.ranged("max_model_calls", 1, 64)?;
    let max_total_tokens = input.ranged("max_total_tokens", 1_000, 2_000_000)?;
    let max_output_tokens = input.ranged("max_output_tokens", 256, 32_768)?;
    let timeout_ms = input.ranged("timeout_ms", 1_000, 300_000)?;
    let api_key = input.raw_string("api_key", 4096)?.filter(|key| !key.is_empty());
    let clear_api_key = input.boolean("clear_api_key")?.unwrap_or(false);
    if api_key.is_some() && clear_api_key {
        return Err(config_invalid("api_key 与 clear_api_key 不能同时给出", "api_key"));
    }
    if let Some(key) = &api_key {
        if key.chars().count() < 8 || key.chars().any(char::is_whitespace) {
            return Err(config_invalid("api_key 至少 8 个字符且不含空白", "api_key"));
        }
    }
    let now = ctx.now();
    let actor = ctx.actor().to_string();
    let protector = ctx.app.protector.as_ref();
    let view = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        let existing = load_policy(transaction, &task_type)?;
        let fallback = defaults(&task_type);
        let merged_version = policy_version
            .clone()
            .or_else(|| existing.as_ref().map(|item| item.policy_version.clone()))
            .ok_or_else(|| config_invalid("首次保存必须给出 policy_version", "policy_version"))?;
        let merged_base_url = base_url.clone().or_else(|| existing.as_ref().and_then(|item| item.base_url.clone()));
        let merged_model = model.clone().or_else(|| existing.as_ref().and_then(|item| item.model.clone()));
        let mut secret_ref = existing.as_ref().and_then(|item| item.secret_ref.clone());
        let endpoint_changed = existing.as_ref().map(|item| item.base_url != merged_base_url || item.model != merged_model).unwrap_or(true);
        if let Some(key) = &api_key {
            secret_ref = Some(put_secret(transaction, protector, secret_ref.as_deref(), &format!("model_api_key:{task_type}"), key.as_bytes(), now)?);
        }
        let stale_secret = if clear_api_key { secret_ref.take() } else { None };
        let verification_reset = endpoint_changed || api_key.is_some() || clear_api_key;
        let verification = if verification_reset {
            "NOT_TESTED".to_string()
        } else {
            existing.as_ref().map(|item| item.verification.clone()).unwrap_or_else(|| "NOT_TESTED".to_string())
        };
        let last_error_code = if verification_reset { None } else { existing.as_ref().and_then(|item| item.last_error_code.clone()) };
        let last_call_at = if verification_reset { None } else { existing.as_ref().and_then(|item| item.last_call_at.clone()) };
        let enabled_flag: i64 = if enabled.unwrap_or_else(|| existing.as_ref().map(|item| item.enabled).unwrap_or(false)) { 1 } else { 0 };
        let calls = max_model_calls.or_else(|| existing.as_ref().map(|item| item.max_model_calls)).unwrap_or(fallback.max_model_calls);
        let tokens = max_total_tokens.or_else(|| existing.as_ref().map(|item| item.max_total_tokens)).unwrap_or(fallback.max_total_tokens);
        let output_tokens = max_output_tokens.or_else(|| existing.as_ref().map(|item| item.max_output_tokens)).unwrap_or(fallback.max_output_tokens);
        let timeout = timeout_ms.or_else(|| existing.as_ref().map(|item| item.timeout_ms)).unwrap_or(fallback.timeout_ms);
        let updated_at = iso_from_millis(now);
        transaction
            .execute(
                "INSERT INTO control_model_policies (task_type, enabled, provider, base_url, model, policy_version, max_model_calls, max_total_tokens,
                        max_output_tokens, timeout_ms, secret_ref, verification, last_error_code, last_call_at, updated_at, updated_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                 ON CONFLICT(task_type) DO UPDATE SET enabled = excluded.enabled, provider = excluded.provider, base_url = excluded.base_url,
                        model = excluded.model, policy_version = excluded.policy_version, max_model_calls = excluded.max_model_calls,
                        max_total_tokens = excluded.max_total_tokens, max_output_tokens = excluded.max_output_tokens, timeout_ms = excluded.timeout_ms,
                        secret_ref = excluded.secret_ref, verification = excluded.verification, last_error_code = excluded.last_error_code,
                        last_call_at = excluded.last_call_at, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                params![
                    task_type,
                    enabled_flag,
                    PROVIDER,
                    merged_base_url,
                    merged_model,
                    merged_version,
                    calls,
                    tokens,
                    output_tokens,
                    timeout,
                    secret_ref,
                    verification,
                    last_error_code,
                    last_call_at,
                    updated_at,
                    actor,
                ],
            )
            .map_err(write_failed)?;
        if let Some(stale) = stale_secret {
            delete_secret(transaction, &stale)?;
        }
        admin_view(transaction, &task_type)
    })?;
    ctx.info(
        "admin.model_config.saved",
        json!({"actor": ctx.actor(), "task_type": task_type, "status": view["status"], "key_replaced": api_key.is_some(), "key_cleared": clear_api_key}),
    );
    Ok(ApiResponse::json(200, json!({"task": view})))
}

pub fn capabilities(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let tasks = ctx.app.store.read(|connection| -> Result<Value, ApiError> {
        let mut tasks = serde_json::Map::new();
        for task_type in TASK_TYPES {
            let policy = load_policy(connection, task_type)?;
            let secret = secret_meta(connection, policy.as_ref().and_then(|item| item.secret_ref.as_deref()))?;
            let entry = match (unavailable_reason(policy.as_ref(), secret.is_some()), policy) {
                (None, Some(policy)) => json!({
                    "status": "AVAILABLE",
                    "policy_version": policy.policy_version,
                    "catalog_version": protocol_for(task_type)?.map(|item| item.tool_catalog_version),
                    "verification": policy.verification,
                }),
                (reason, _) => json!({"status": "UNAVAILABLE", "reason": reason.unwrap_or("MODEL_NOT_CONFIGURED")}),
            };
            tasks.insert(task_type.to_string(), entry);
        }
        Ok(Value::Object(tasks))
    })?;
    Ok(ApiResponse::json(200, json!({"user_ref": ctx.actor(), "tasks": tasks})))
}

struct TurnInput {
    task_ref: String,
    task_type: String,
    turn_ref: String,
    prompt_body: String,
    messages: Value,
    signature: String,
}

fn parse_turn(body: &Value) -> Result<(TurnInput, Protocol), ApiError> {
    let input = fields(
        body,
        &["task_ref", "task_type", "turn_ref", "prompt_version", "prompt_body", "tool_catalog_version", "messages"],
    )
    .map_err(|error| ApiError::invalid("请求含客户端不能决定的模型字段").with("field", error.extra.get("field").cloned().unwrap_or(Value::Null)))?;
    let mut refs = Vec::new();
    for key in ["task_ref", "turn_ref"] {
        let value = input.required_string(key, 128)?;
        if !valid_ref(&value) {
            return Err(ApiError::invalid(format!("{key} 只能含字母、数字与 . _ : -")).with("field", json!(key)));
        }
        refs.push(value);
    }
    let task_type = input.required_string("task_type", 64)?;
    let prompt_version = input.required_string("prompt_version", 128)?;
    let tool_catalog_version = input.required_string("tool_catalog_version", 128)?;
    let prompt_body = input
        .raw_string("prompt_body", MAX_PROMPT_CHARS)?
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| ApiError::invalid("prompt_body 必填").with("field", json!("prompt_body")))?;
    let messages = input
        .array("messages")?
        .ok_or_else(|| ApiError::invalid("messages 必须是数组").with("field", json!("messages")))?;
    let messages = Value::Array(messages.clone());
    if messages.to_string().chars().count() > MAX_MESSAGES_CHARS {
        return Err(ApiError::invalid("messages 超过协议上限").with("field", json!("messages")));
    }
    let protocol = protocol_for(&task_type)?
        .filter(|item| item.prompt_version == prompt_version && item.tool_catalog_version == tool_catalog_version)
        .ok_or_else(|| ApiError::new(400, "CONTROL_PROTOCOL_MISMATCH", "该任务不接受这个提示词或工具目录版本"))?;
    let signature = sha256_hex(
        canonical_json(&json!({
            "task_type": task_type,
            "prompt_version": prompt_version,
            "prompt_body": prompt_body,
            "tool_catalog_version": tool_catalog_version,
            "messages": redact_for_model(&messages),
        }))
        .as_bytes(),
    );
    let turn_ref = refs.pop().unwrap_or_default();
    let task_ref = refs.pop().unwrap_or_default();
    Ok((TurnInput { task_ref, task_type, turn_ref, prompt_body, messages, signature }, protocol))
}

enum Prepared {
    Replay { http_status: u16, response: Value },
    Unavailable(&'static str),
    BudgetExhausted,
    Call { policy: Policy, api_key: String, policy_identity: String },
}

pub fn turn(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let (input, protocol) = parse_turn(&body)?;
    let actor = ctx.actor().to_string();
    let now = ctx.now();
    let protector = ctx.app.protector.as_ref();

    let prepared = ctx.app.store.write(|transaction| -> Result<Prepared, ApiError> {
        let existing: Option<(String, String)> = transaction
            .query_row(
                "SELECT user_ref, task_type FROM control_ai_tasks WHERE task_ref = ?1",
                params![input.task_ref],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(read_failed)?;
        match existing {
            Some((owner, _)) if owner != actor => {
                return Err(ApiError::new(403, "CONTROL_TASK_DENIED", "这个 AI 任务属于另一个应用用户"));
            }
            Some((_, stored_type)) if stored_type != input.task_type => {
                return Err(ApiError::new(409, "CONTROL_TASK_TYPE_MISMATCH", "这个 AI 任务已绑定到另一任务类型，不能换类型继续"));
            }
            Some(_) => {}
            None => {
                transaction
                    .execute(
                        "INSERT INTO control_ai_tasks (task_ref, user_ref, task_type, created_at) VALUES (?1, ?2, ?3, ?4)",
                        params![input.task_ref, actor, input.task_type, iso_from_millis(now)],
                    )
                    .map_err(write_failed)?;
            }
        }
        let prior: Option<(String, i64, String)> = transaction
            .query_row(
                "SELECT signature, http_status, response_json FROM control_ai_turns WHERE task_ref = ?1 AND turn_ref = ?2",
                params![input.task_ref, input.turn_ref],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(read_failed)?;
        if let Some((signature, http_status, response_json)) = prior {
            if signature != input.signature {
                return Err(ApiError::new(409, "CONTROL_TURN_REPLAY_MISMATCH", "同一 turn_ref 不能用不同内容重复提交"));
            }
            let response = serde_json::from_str(&response_json).unwrap_or(Value::Null);
            return Ok(Prepared::Replay { http_status: http_status as u16, response });
        }
        let policy = load_policy(transaction, &input.task_type)?;
        let secret = secret_meta(transaction, policy.as_ref().and_then(|item| item.secret_ref.as_deref()))?;
        if let Some(reason) = unavailable_reason(policy.as_ref(), secret.is_some()) {
            return Ok(Prepared::Unavailable(reason));
        }
        let policy = match policy {
            Some(policy) => policy,
            None => return Ok(Prepared::Unavailable("MODEL_NOT_CONFIGURED")),
        };
        let (turns, unknown, tokens): (i64, i64, i64) = transaction
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN total_tokens IS NULL THEN 1 ELSE 0 END), 0), COALESCE(SUM(total_tokens), 0)
                   FROM control_ai_usage_events WHERE task_ref = ?1",
                params![input.task_ref],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(read_failed)?;
        if turns >= policy.max_model_calls || unknown > 0 || tokens >= policy.max_total_tokens {
            return Ok(Prepared::BudgetExhausted);
        }
        let secret_ref = policy.secret_ref.clone().unwrap_or_default();
        let api_key = match read_secret_text(transaction, protector, &secret_ref, &format!("model_api_key:{}", input.task_type)) {
            Ok(key) => key,
            Err(error) => {
                ctx.error("ai.secret.unreadable", json!({"task_type": input.task_type, "code": error.code, "detail": error.reason}));
                return Ok(Prepared::Unavailable("MODEL_SECRET_UNREADABLE"));
            }
        };
        let policy_identity = format!("{}:{}:{}", policy.policy_version, policy.max_model_calls, policy.max_total_tokens);
        Ok(Prepared::Call { policy, api_key, policy_identity })
    })?;

    let (policy, api_key, policy_identity) = match prepared {
        Prepared::Replay { http_status, response } => {
            ctx.info("ai.turn.replayed", json!({"task_ref": input.task_ref, "turn_ref": input.turn_ref, "http_status": http_status}));
            return Ok(ApiResponse::json(http_status, response));
        }
        Prepared::Unavailable(reason) => {
            return Err(ApiError::new(503, "AI_UNAVAILABLE", reason));
        }
        Prepared::BudgetExhausted => {
            return Err(ApiError::new(429, "AI_BUDGET_EXHAUSTED", "服务端模型预算已用完"));
        }
        Prepared::Call { policy, api_key, policy_identity } => (policy, api_key, policy_identity),
    };

    let mut messages = vec![json!({"role": "system", "content": input.prompt_body})];
    if let Value::Array(items) = &input.messages {
        messages.extend(items.iter().cloned());
    }
    let base_url = policy.base_url.clone().unwrap_or_default();
    let model = policy.model.clone().unwrap_or_default();
    let outcome = provider::complete(
        ctx.app.transport.as_ref(),
        ctx.cancel,
        &ChatRequest {
            base_url: &base_url,
            api_key: &api_key,
            model: &model,
            max_output_tokens: policy.max_output_tokens,
            timeout_ms: policy.timeout_ms,
            messages,
            tools: protocol.tools,
        },
    );
    drop(api_key);

    let finished_at = ctx.now();
    let (http_status, response, usage, status_code) = match &outcome {
        Ok(completion) => (
            200u16,
            json!({
                "status": "OK",
                "assistant": redact_for_model(&completion.assistant),
                "usage": completion.usage,
                "model_policy_version": policy.policy_version,
                "request_ref": input.turn_ref,
            }),
            completion.usage.clone(),
            "OK".to_string(),
        ),
        Err(error) => (
            if error.code == "AI_RATE_LIMITED" { 429u16 } else { 502u16 },
            json!({
                "code": error.code,
                "reason": "AI control request could not be completed",
                "retryable": error.retryable,
                "status": "FAILED",
                "model_policy_version": policy.policy_version,
                "request_ref": input.turn_ref,
            }),
            json!({"status": "UNKNOWN"}),
            error.code.to_string(),
        ),
    };
    let total_tokens = usage.get("total_tokens").and_then(Value::as_i64);
    let verification = if outcome.is_ok() { "CALL_SUCCEEDED" } else { "CALL_FAILED" };
    let last_error = outcome.as_ref().err().map(|error| error.code);
    ctx.app.store.write(|transaction| -> Result<(), ControlError> {
        let stamp = iso_from_millis(finished_at);
        transaction
            .execute(
                "INSERT OR IGNORE INTO control_ai_turns (task_ref, turn_ref, signature, http_status, response_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![input.task_ref, input.turn_ref, input.signature, http_status as i64, response.to_string(), stamp],
            )
            .map_err(write_failed)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO control_ai_usage_events (task_ref, turn_ref, user_ref, task_type, policy_version, policy_identity, status, total_tokens, usage_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    input.task_ref,
                    input.turn_ref,
                    actor,
                    input.task_type,
                    policy.policy_version,
                    policy_identity,
                    status_code,
                    total_tokens,
                    usage.to_string(),
                    stamp
                ],
            )
            .map_err(write_failed)?;
        transaction
            .execute(
                "UPDATE control_model_policies SET verification = ?1, last_error_code = ?2, last_call_at = ?3 WHERE task_type = ?4",
                params![verification, last_error, stamp, input.task_type],
            )
            .map_err(write_failed)?;
        Ok(())
    })?;
    let detail = outcome.as_ref().err().map(|error| error.detail.clone());
    ctx.info(
        "ai.turn.finished",
        json!({
            "task_ref": input.task_ref,
            "turn_ref": input.turn_ref,
            "task_type": input.task_type,
            "policy_version": policy.policy_version,
            "result": status_code,
            "upstream_status": outcome.as_ref().err().and_then(|error| error.upstream_status),
            "total_tokens": total_tokens,
            "detail": detail,
        }),
    );
    Ok(ApiResponse::json(http_status, response))
}
