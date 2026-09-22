//! 路由共用的错误与请求字段读取。
//!
//! HTTP 401 只留给「本应用会话无效」。上游模型或配额服务的鉴权失败一律回 5xx 与各自的错误码，
//! 页面据此只在本应用会话失效时退回登录。

use serde_json::{Map, Value};

use crate::{iso_from_millis, millis_from_iso, ControlError};

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub reason: String,
    pub extra: Map<String, Value>,
}

impl ApiError {
    pub fn new(status: u16, code: impl Into<String>, reason: impl Into<String>) -> ApiError {
        ApiError { status, code: code.into(), reason: reason.into(), extra: Map::new() }
    }

    pub fn invalid(reason: impl Into<String>) -> ApiError {
        ApiError::new(400, "CONTROL_REQUEST_INVALID", reason)
    }

    pub fn with(mut self, key: &str, value: Value) -> ApiError {
        self.extra.insert(key.to_string(), value);
        self
    }

    /// 数据库、随机源、秘密保护这类内部故障：对外只给脱敏说明，细节由路由写进日志。
    pub fn is_internal(&self) -> bool {
        self.status >= 500 && INTERNAL_CODES.contains(&self.code.as_str())
    }
}

const INTERNAL_CODES: &[&str] = &[
    "CONTROL_STORE_READ_FAILED",
    "CONTROL_STORE_WRITE_FAILED",
    "CONTROL_STORE_CORRUPT",
    "CONTROL_RANDOM_UNAVAILABLE",
    "CONTROL_PASSWORD_HASH_FAILED",
    "CONTROL_SECRET_PROTECT_FAILED",
    "CONTROL_SECRET_UNREADABLE",
    "CONTROL_SECRET_MISSING",
    "CONTROL_PROTOCOL_CATALOG_INVALID",
    "CONTROL_INTERNAL",
];

impl From<ControlError> for ApiError {
    fn from(error: ControlError) -> ApiError {
        ApiError::new(status_for(error.code), error.code, error.reason)
    }
}

/// 错误码到 HTTP 状态。沿用 Node 基线 networkRoutes 的映射，差异点在 README「错误语义」一节列明。
pub fn status_for(code: &str) -> u16 {
    match code {
        "CONTROL_REQUEST_INVALID" | "CONTROL_PROTOCOL_MISMATCH" | "LIMIT_REQUIRED" | "LIMIT_INVALID" | "LIMIT_UNIT_UNSUPPORTED"
        | "OPERATION_REQUIRED" | "RESOURCE_INVALID" | "TEMPLATE_INVALID" | "TEMPLATE_SECRET_REJECTED" | "SOURCE_INVALID"
        | "SOURCE_EMPTY" | "ASSIGNMENT_INVALID" | "EVENT_INVALID" | "EVENT_SECRET_REJECTED" | "AUTHORITY_CANCELLED"
        | "ROLE_MISMATCH" | "MODE_NOT_ALLOWED" | "CREDENTIAL_INVALID" | "MODEL_CONFIG_INVALID" | "QUOTA_ADAPTER_INVALID"
        | "EXPIRE_AT_REQUIRED" => 400,
        "CONTROL_FORBIDDEN" | "CONTROL_TASK_DENIED" | "CONTROL_ADMIN_TARGET_DENIED" => 403,
        "CONTROL_USER_NOT_FOUND" | "CONTROL_SESSION_NOT_FOUND" | "RESOURCE_NOT_FOUND" | "TEMPLATE_NOT_FOUND" | "SOURCE_NOT_FOUND"
        | "ASSIGNMENT_NOT_FOUND" | "CREDENTIAL_NOT_FOUND" | "CONTROL_NOT_FOUND" => 404,
        "CONTROL_USER_CONFLICT" | "CONTROL_TURN_REPLAY_MISMATCH" | "QUOTA_OPERATION_MISMATCH" | "PROVIDER_IDENTITY_CONFLICT"
        | "AUTHORITY_CONFLICT" | "ASSIGNMENT_EXPIRED" | "ASSIGNMENT_REVOKED" | "RESOURCE_UNAVAILABLE" | "PROVIDER_BINDING_MISSING"
        | "TEMPLATE_UNAVAILABLE" | "SOURCE_DISABLED" | "CREDENTIAL_REVOKED" | "USER_EXPIRED" | "STILL_LIMITED" => 409,
        "AI_BUDGET_EXHAUSTED" | "AI_RATE_LIMITED" | "AUTHORITY_RATE_LIMITED" => 429,
        "AI_UNAVAILABLE" | "AUTHORITY_UNCONFIGURED" | "AUTHORITY_TIMEOUT" | "AUTHORITY_UNAVAILABLE"
        | "CONTROL_SECRET_PROTECTION_UNAVAILABLE" => 503,
        "AI_AUTH_FAILED" | "AI_PROVIDER_UNAVAILABLE" | "AI_TRANSPORT_UNKNOWN" | "AI_ABORTED" | "AUTHORITY_UNAUTHORIZED"
        | "AUTHORITY_FORBIDDEN" | "AUTHORITY_NOT_FOUND" | "AUTHORITY_REQUEST_FAILED" | "INVALID_RESPONSE" | "UNSUPPORTED"
        | "INVALID_PROVIDER_USER_ID" => 502,
        _ => 500,
    }
}

/// 请求正文里的一个 JSON 对象，只允许列出的字段。
pub struct Fields<'a> {
    map: &'a Map<String, Value>,
}

pub fn fields<'a>(body: &'a Value, allowed: &[&str]) -> Result<Fields<'a>, ApiError> {
    let map = body.as_object().ok_or_else(|| ApiError::invalid("请求正文必须是 JSON 对象"))?;
    if let Some(unknown) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(ApiError::invalid(format!("请求含不接受的字段 {unknown}")).with("field", Value::String(unknown.clone())));
    }
    Ok(Fields { map })
}

fn wrong_type(key: &str, expected: &str) -> ApiError {
    ApiError::invalid(format!("字段 {key} 必须是{expected}")).with("field", Value::String(key.to_string()))
}

impl<'a> Fields<'a> {
    pub fn has(&self, key: &str) -> bool {
        self.map.get(key).map(|value| !value.is_null()).unwrap_or(false)
    }

    pub fn value(&self, key: &str) -> Option<&'a Value> {
        self.map.get(key).filter(|value| !value.is_null())
    }

    /// 第一个出现的别名。Node 基线的请求字段是 camelCase（userRef），新路由用 snake_case。
    pub fn first_key(&self, keys: &[&'static str]) -> Option<&'static str> {
        keys.iter().copied().find(|key| self.has(key))
    }

    /// 可选字符串，按字符数限长；不 trim，密码等字段原样保留。
    pub fn raw_string(&self, key: &str, max_chars: usize) -> Result<Option<String>, ApiError> {
        match self.value(key) {
            None => Ok(None),
            Some(Value::String(text)) if text.chars().count() <= max_chars => Ok(Some(text.clone())),
            Some(Value::String(_)) => Err(ApiError::invalid(format!("字段 {key} 超过 {max_chars} 个字符")).with("field", Value::String(key.to_string()))),
            Some(_) => Err(wrong_type(key, "字符串")),
        }
    }

    /// 可选字符串，去首尾空白，空串视为未提供。
    pub fn string(&self, key: &str, max_chars: usize) -> Result<Option<String>, ApiError> {
        Ok(self.raw_string(key, max_chars)?.map(|text| text.trim().to_string()).filter(|text| !text.is_empty()))
    }

    pub fn required_string(&self, key: &str, max_chars: usize) -> Result<String, ApiError> {
        self.string(key, max_chars)?
            .ok_or_else(|| ApiError::invalid(format!("字段 {key} 必填")).with("field", Value::String(key.to_string())))
    }

    /// 多个别名里取第一个出现的非空字符串。
    pub fn string_any(&self, keys: &[&'static str], max_chars: usize) -> Result<Option<String>, ApiError> {
        match self.first_key(keys) {
            Some(key) => self.string(key, max_chars),
            None => Ok(None),
        }
    }

    pub fn integer(&self, key: &str) -> Result<Option<i64>, ApiError> {
        match self.value(key) {
            None => Ok(None),
            Some(value) => match value.as_i64() {
                Some(number) => Ok(Some(number)),
                None => match value.as_f64() {
                    Some(number) if number.is_finite() && number.fract() == 0.0 && number.abs() < 9.0e15 => Ok(Some(number as i64)),
                    _ => Err(wrong_type(key, "整数")),
                },
            },
        }
    }

    pub fn ranged(&self, key: &str, min: i64, max: i64) -> Result<Option<i64>, ApiError> {
        match self.integer(key)? {
            Some(value) if value < min || value > max => {
                Err(ApiError::invalid(format!("字段 {key} 须在 {min} 到 {max} 之间")).with("field", Value::String(key.to_string())))
            }
            other => Ok(other),
        }
    }

    pub fn number(&self, key: &str) -> Result<Option<f64>, ApiError> {
        match self.value(key) {
            None => Ok(None),
            Some(value) => value.as_f64().filter(|number| number.is_finite()).map(Some).ok_or_else(|| wrong_type(key, "数字")),
        }
    }

    pub fn boolean(&self, key: &str) -> Result<Option<bool>, ApiError> {
        match self.value(key) {
            None => Ok(None),
            Some(Value::Bool(flag)) => Ok(Some(*flag)),
            Some(_) => Err(wrong_type(key, "布尔值")),
        }
    }

    pub fn array(&self, key: &str) -> Result<Option<&'a Vec<Value>>, ApiError> {
        match self.value(key) {
            None => Ok(None),
            Some(Value::Array(items)) => Ok(Some(items)),
            Some(_) => Err(wrong_type(key, "数组")),
        }
    }

    pub fn object(&self, key: &str) -> Result<Option<&'a Map<String, Value>>, ApiError> {
        match self.value(key) {
            None => Ok(None),
            Some(Value::Object(map)) => Ok(Some(map)),
            Some(_) => Err(wrong_type(key, "对象")),
        }
    }

    /// 可选时间：接受 ISO 8601（见 `millis_from_iso`），统一改写成毫秒精度的 UTC 形式。
    pub fn instant(&self, key: &str) -> Result<Option<String>, ApiError> {
        match self.string(key, 64)? {
            None => Ok(None),
            Some(text) => millis_from_iso(&text)
                .map(|millis| Some(iso_from_millis(millis)))
                .ok_or_else(|| wrong_type(key, "带时区的 ISO 8601 时间")),
        }
    }

    pub fn string_list(&self, key: &str, max_items: usize, max_chars: usize) -> Result<Option<Vec<String>>, ApiError> {
        let items = match self.array(key)? {
            None => return Ok(None),
            Some(items) => items,
        };
        if items.len() > max_items {
            return Err(ApiError::invalid(format!("字段 {key} 最多 {max_items} 项")).with("field", Value::String(key.to_string())));
        }
        let mut list = Vec::with_capacity(items.len());
        for item in items {
            match item.as_str().map(str::trim) {
                Some(text) if !text.is_empty() && text.chars().count() <= max_chars => list.push(text.to_string()),
                _ => return Err(wrong_type(key, "非空字符串数组")),
            }
        }
        Ok(Some(list))
    }
}

/// 引用类标识（resource_id、template_id、operation_id 等）：1—128 位字母数字与 . _ : -。
pub fn valid_ref(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':'))
}

pub fn required_ref(fields: &Fields<'_>, keys: &[&'static str]) -> Result<String, ApiError> {
    let key = keys[0];
    let value = fields
        .string_any(keys, 128)?
        .ok_or_else(|| ApiError::invalid(format!("字段 {key} 必填")).with("field", Value::String(key.to_string())))?;
    if !valid_ref(&value) {
        return Err(ApiError::invalid(format!("字段 {key} 只能含字母、数字与 . _ : -")).with("field", Value::String(key.to_string())));
    }
    Ok(value)
}

/// 服务地址：https；http 只允许回环地址。不接受地址里带账号密码。
pub fn validate_service_url(text: &str, key: &str) -> Result<(), ApiError> {
    let invalid = |reason: &str| ApiError::invalid(format!("字段 {key} {reason}")).with("field", Value::String(key.to_string()));
    if text.len() > 2048 || text.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(invalid("不是有效地址"));
    }
    let (scheme, rest) = text.split_once("://").ok_or_else(|| invalid("必须以 https:// 开头"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(invalid("缺少主机名"));
    }
    if authority.contains('@') {
        return Err(invalid("不能在地址里携带账号或密码"));
    }
    let host = authority_host(authority);
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(()),
        "http" if matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]") => Ok(()),
        _ => Err(invalid("必须是 https 地址（http 只允许本机回环）")),
    }
}

fn authority_host(authority: &str) -> String {
    if authority.starts_with('[') {
        return authority.split(']').next().map(|head| format!("{head}]")).unwrap_or_default().to_ascii_lowercase();
    }
    authority.split(':').next().unwrap_or("").to_ascii_lowercase()
}

/// 给管理员看的地址：只留协议、主机与端口，路径和查询（常含令牌）一律遮掉。
pub fn display_url(text: &str) -> String {
    match text.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            let hidden = if rest.len() > authority.len() { "/…" } else { "" };
            format!("{}://{}{}", scheme.to_ascii_lowercase(), authority.to_ascii_lowercase(), hidden)
        }
        None => "（地址格式无法显示）".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_fields_are_rejected_by_name() {
        let body = json!({"username": "a", "role": "admin"});
        let error = fields(&body, &["username", "password"]).err().unwrap();
        assert_eq!(error.code, "CONTROL_REQUEST_INVALID");
        assert_eq!(error.extra["field"], "role");
    }

    #[test]
    fn service_urls_hide_paths_and_refuse_credentials() {
        assert!(validate_service_url("https://panel.example.invalid/api", "base_url").is_ok());
        assert!(validate_service_url("http://127.0.0.1:3000", "base_url").is_ok());
        assert!(validate_service_url("http://panel.example.invalid", "base_url").is_err());
        assert!(validate_service_url("https://user:pass@panel.example.invalid", "base_url").is_err());
        assert_eq!(display_url("https://Sub.Example.invalid/link/abcdef?token=1"), "https://sub.example.invalid/…");
    }
}
