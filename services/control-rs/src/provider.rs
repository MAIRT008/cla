//! OpenAI 兼容 Chat Completions 的服务端适配。只做本产品用到的那一段：
//! 非流式请求、工具定义、tool_choice=auto、max_completion_tokens；回复只取第一条 choice 的
//! 文本与工具调用，用量取 prompt/completion/total_tokens。模型、端点、密钥、超时全部来自服务器配置，
//! 不接受客户端覆盖，也不做自动重试（与 Node 基线 `maxRetries: 0` 一致）。
//!
//! 错误映射沿 Node 基线 modelProvider.mjs：401/403 → AI_AUTH_FAILED，429 → AI_RATE_LIMITED，
//! 5xx → AI_PROVIDER_UNAVAILABLE，调用方取消 → AI_ABORTED，其余（含超时、连不上、回复无法解析）→ AI_TRANSPORT_UNKNOWN。

use serde_json::{json, Value};

use crate::http::{CancelToken, HttpRequest, HttpTransport, TransportFailure};

pub struct ChatRequest<'a> {
    pub base_url: &'a str,
    pub api_key: &'a str,
    pub model: &'a str,
    pub max_output_tokens: i64,
    pub timeout_ms: i64,
    pub messages: Vec<Value>,
    pub tools: &'a Value,
}

#[derive(Debug, Clone)]
pub struct Completion {
    pub assistant: Value,
    pub usage: Value,
}

#[derive(Debug, Clone)]
pub struct ProviderError {
    pub code: &'static str,
    pub upstream_status: Option<u16>,
    pub retryable: bool,
    /// 只进日志；不含提示词、回复正文或密钥。
    pub detail: String,
}

fn failure(code: &'static str, upstream_status: Option<u16>, retryable: bool, detail: impl Into<String>) -> ProviderError {
    ProviderError { code, upstream_status, retryable, detail: detail.into() }
}

pub fn chat_completions_url(base_url: &str) -> String {
    format!("{}/chat/completions", base_url.trim_end_matches('/'))
}

/// 发出的请求体。单独暴露给测试核对形状。
pub fn request_body(request: &ChatRequest<'_>) -> Value {
    json!({
        "model": request.model,
        "messages": request.messages,
        "tools": request.tools,
        "tool_choice": "auto",
        "max_completion_tokens": request.max_output_tokens,
        "stream": false,
    })
}

fn finite_count(value: &Value) -> Value {
    match value.as_i64() {
        Some(number) if number >= 0 => json!(number),
        _ => match value.as_f64() {
            Some(number) if number.is_finite() && number >= 0.0 => json!(number as i64),
            _ => Value::Null,
        },
    }
}

fn normalized_message(message: &Value) -> Value {
    let content = message.get("content").and_then(Value::as_str).unwrap_or("");
    let calls: Vec<Value> = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|call| {
                    let function = call.get("function").cloned().unwrap_or(Value::Null);
                    json!({
                        "id": call.get("id").cloned().unwrap_or(Value::Null),
                        "type": "function",
                        "function": {
                            "name": function.get("name").cloned().unwrap_or(Value::Null),
                            "arguments": function.get("arguments").and_then(Value::as_str).filter(|text| !text.is_empty()).unwrap_or("{}"),
                        },
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({"role": "assistant", "content": content, "tool_calls": calls})
}

pub fn complete(transport: &dyn HttpTransport, cancel: &CancelToken, request: &ChatRequest<'_>) -> Result<Completion, ProviderError> {
    let http = HttpRequest::new("POST", chat_completions_url(request.base_url), request.timeout_ms.max(1000) as u64)
        .header("authorization", format!("Bearer {}", request.api_key))
        .header("accept", "application/json")
        .json_body(&request_body(request));
    let response = match transport.send(&http, cancel) {
        Ok(response) => response,
        Err(error) => {
            let code = if error.kind == TransportFailure::Cancelled { "AI_ABORTED" } else { "AI_TRANSPORT_UNKNOWN" };
            let retryable = error.kind != TransportFailure::Cancelled;
            return Err(failure(code, None, retryable, error.detail));
        }
    };
    let status = response.status;
    if status == 401 || status == 403 {
        return Err(failure("AI_AUTH_FAILED", Some(status), false, "模型提供方拒绝了服务端配置的密钥"));
    }
    if status == 429 {
        return Err(failure("AI_RATE_LIMITED", Some(status), true, "模型提供方限流"));
    }
    if status >= 500 {
        return Err(failure("AI_PROVIDER_UNAVAILABLE", Some(status), true, "模型提供方暂不可用"));
    }
    if !(200..300).contains(&status) {
        return Err(failure("AI_TRANSPORT_UNKNOWN", Some(status), true, format!("模型提供方回 HTTP {status}")));
    }
    let body = response
        .json()
        .ok_or_else(|| failure("AI_TRANSPORT_UNKNOWN", Some(status), true, "模型回复不是 JSON"))?;
    let message = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .ok_or_else(|| failure("AI_TRANSPORT_UNKNOWN", Some(status), true, "模型回复缺少 choices[0].message"))?;
    let usage = body.get("usage").cloned().unwrap_or(Value::Null);
    Ok(Completion {
        assistant: normalized_message(message),
        usage: json!({
            "prompt_tokens": finite_count(usage.get("prompt_tokens").unwrap_or(&Value::Null)),
            "completion_tokens": finite_count(usage.get("completion_tokens").unwrap_or(&Value::Null)),
            "total_tokens": finite_count(usage.get("total_tokens").unwrap_or(&Value::Null)),
        }),
    })
}
