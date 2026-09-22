//! Remnawave 后端管理接口的最小适配（迁自 Node 基线 services/control/remnawave/）。
//!
//! 契约固定在基线已核对的 backend 3.4.3 / node 3.4.1 / contract 3.4.13：用户创建、读取、按用户名读取、
//! 改额度、停用、启用与节点列表。请求只经注入的 `HttpTransport`；地址与管理令牌来自服务端加密配置。
//! 响应里的 vlessUuid、trojanPassword、ssPassword、subscriptionUrl 等秘密只投影成「是否存在」，不向上层传。

use serde_json::{json, Value};

use crate::http::{CancelToken, HttpRequest, HttpTransport, TransportFailure};
use crate::sha256_hex;

pub const AUTHORITY_REF: &str = "remnawave-backend-3.4.3";
pub const RESET_PERIODS: [&str; 5] = ["NO_RESET", "DAY", "WEEK", "MONTH", "MONTH_ROLLING"];
pub const USER_STATUSES: [&str; 4] = ["ACTIVE", "DISABLED", "LIMITED", "EXPIRED"];

pub fn contract() -> Value {
    json!({
        "backend_tag": "3.4.3",
        "backend_commit": "f8ad8ad3410252215ca7b2e429d157bd275ec564",
        "node_tag": "3.4.1",
        "node_commit": "44912631321664dbd5822e9bf8d96766ccff7c93",
        "contract_package": "3.4.13",
        "licence": "AGPL-3.0-only",
    })
}

#[derive(Debug, Clone)]
pub struct AuthorityError {
    pub code: &'static str,
    pub status: Option<u16>,
    pub retryable: bool,
    /// 只进日志。
    pub detail: String,
}

impl AuthorityError {
    pub fn new(code: &'static str, status: Option<u16>, retryable: bool, detail: impl Into<String>) -> AuthorityError {
        AuthorityError { code, status, retryable, detail: detail.into() }
    }
}

#[derive(Debug, Clone)]
pub struct UserRead {
    pub http_status: u16,
    pub projected: Value,
}

/// 应用用户在权威侧的用户名：可读前缀（字母数字，最多 14 位）+ user_ref 的 SHA-256 前 20 位，最长 36。
/// 不同 user_ref 即使去掉符号后相同（tenant.a / tenant/a），摘要也不同。
pub fn provider_username(user_ref: &str) -> String {
    let digest = &sha256_hex(user_ref.as_bytes())[..20];
    let prefix: String = user_ref.chars().filter(char::is_ascii_alphanumeric).take(14).collect();
    let head = if prefix.is_empty() { "u".to_string() } else { prefix };
    let candidate: String = format!("{head}_{digest}").chars().take(36).collect();
    candidate
}

fn encode_component(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn number(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_f64().filter(|item| item.is_finite() && item.fract() == 0.0).map(|item| item as i64))
}

fn text_or_null(value: &Value, key: &str) -> Value {
    match value.get(key).and_then(Value::as_str) {
        Some(text) if !text.is_empty() => json!(text),
        _ => Value::Null,
    }
}

pub fn project_user(user: &Value) -> Value {
    let traffic = user.get("userTraffic").cloned().unwrap_or(Value::Null);
    let squads: Vec<Value> = user
        .get("activeInternalSquads")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string).or_else(|| item.get("uuid").and_then(Value::as_str).map(str::to_string)))
                .map(Value::String)
                .collect()
        })
        .unwrap_or_default();
    let present = |key: &str| user.get(key).map(|value| !value.is_null() && value != "").unwrap_or(false);
    json!({
        "id": user.get("id").cloned().unwrap_or(Value::Null),
        "username": user.get("username").cloned().unwrap_or(Value::Null),
        "status": user.get("status").cloned().unwrap_or(Value::Null),
        "trafficLimitBytes": user.get("trafficLimitBytes").and_then(number),
        "trafficLimitStrategy": user.get("trafficLimitStrategy").cloned().unwrap_or(Value::Null),
        "expireAt": text_or_null(user, "expireAt"),
        "lastTrafficResetAt": text_or_null(user, "lastTrafficResetAt"),
        "createdAt": text_or_null(user, "createdAt"),
        "updatedAt": text_or_null(user, "updatedAt"),
        "subRevokedAt": text_or_null(user, "subRevokedAt"),
        "usedTrafficBytes": traffic.get("usedTrafficBytes").and_then(number),
        "lifetimeUsedTrafficBytes": traffic.get("lifetimeUsedTrafficBytes").and_then(number),
        "onlineAt": text_or_null(&traffic, "onlineAt"),
        "firstConnectedAt": text_or_null(&traffic, "firstConnectedAt"),
        "lastConnectedNodeUuid": text_or_null(&traffic, "lastConnectedNodeUuid"),
        "activeInternalSquads": squads,
        "secrets_present": {
            "vlessUuid": present("vlessUuid"),
            "trojanPassword": present("trojanPassword"),
            "ssPassword": present("ssPassword"),
            "subscriptionUrl": present("subscriptionUrl"),
        },
    })
}

pub fn project_node(node: &Value) -> Value {
    json!({
        "uuid": node.get("uuid").cloned().unwrap_or(Value::Null),
        "id": node.get("id").cloned().unwrap_or(Value::Null),
        "name": node.get("name").cloned().unwrap_or(Value::Null),
        "isConnected": node.get("isConnected").and_then(Value::as_bool) == Some(true),
        "isDisabled": node.get("isDisabled").and_then(Value::as_bool) == Some(true),
        "isTrafficTrackingActive": node.get("isTrafficTrackingActive").and_then(Value::as_bool) == Some(true),
        "trafficUsedBytes": node.get("trafficUsedBytes").and_then(number),
        "trafficLimitBytes": node.get("trafficLimitBytes").and_then(number),
        "trafficResetDay": node.get("trafficResetDay").cloned().unwrap_or(Value::Null),
        "consumptionMultiplier": node.get("consumptionMultiplier").cloned().unwrap_or(Value::Null),
        "providerUuid": node.get("providerUuid").cloned().unwrap_or(Value::Null),
    })
}

/// 用户响应的结构校验，规则同基线 parseUserEnvelope。
pub fn parse_user_envelope(body: &Value) -> Result<&Value, AuthorityError> {
    let invalid = |reason: &str| AuthorityError::new("INVALID_RESPONSE", None, false, reason.to_string());
    let user = body.get("response").filter(|value| value.is_object()).ok_or_else(|| invalid("response user is missing"))?;
    match user.get("id").and_then(Value::as_i64) {
        Some(id) if id > 0 => {}
        _ => return Err(invalid("numeric id is missing")),
    }
    if !user.get("status").and_then(Value::as_str).map(|status| USER_STATUSES.contains(&status)).unwrap_or(false) {
        return Err(invalid("user status is unknown"));
    }
    if !user.get("trafficLimitBytes").and_then(Value::as_f64).map(|limit| limit.is_finite() && limit >= 0.0).unwrap_or(false) {
        return Err(invalid("trafficLimitBytes is invalid"));
    }
    if let Some(strategy) = user.get("trafficLimitStrategy").and_then(Value::as_str).filter(|item| !item.is_empty()) {
        if !RESET_PERIODS.contains(&strategy) {
            return Err(AuthorityError::new("UNSUPPORTED", None, false, format!("trafficLimitStrategy {strategy} is unsupported")));
        }
    }
    if !user
        .get("userTraffic")
        .and_then(|traffic| traffic.get("usedTrafficBytes"))
        .and_then(Value::as_f64)
        .map(f64::is_finite)
        .unwrap_or(false)
    {
        return Err(invalid("userTraffic.usedTrafficBytes is missing"));
    }
    Ok(user)
}

fn map_http_error(status: u16, path: &str) -> AuthorityError {
    let detail = format!("Remnawave {path} 回 HTTP {status}");
    match status {
        401 => AuthorityError::new("AUTHORITY_UNAUTHORIZED", Some(status), false, detail),
        403 => AuthorityError::new("AUTHORITY_FORBIDDEN", Some(status), false, detail),
        404 => AuthorityError::new("AUTHORITY_NOT_FOUND", Some(status), false, detail),
        409 => AuthorityError::new("AUTHORITY_CONFLICT", Some(status), false, detail),
        429 => AuthorityError::new("AUTHORITY_RATE_LIMITED", Some(status), true, detail),
        _ if status >= 500 => AuthorityError::new("AUTHORITY_UNAVAILABLE", Some(status), true, detail),
        _ => AuthorityError::new("AUTHORITY_REQUEST_FAILED", Some(status), false, detail),
    }
}

pub struct Remnawave<'a> {
    transport: &'a dyn HttpTransport,
    cancel: &'a CancelToken,
    base_url: String,
    token: String,
    timeout_ms: u64,
}

impl<'a> Remnawave<'a> {
    pub fn new(transport: &'a dyn HttpTransport, cancel: &'a CancelToken, base_url: &str, token: &str, timeout_ms: u64) -> Remnawave<'a> {
        Remnawave {
            transport,
            cancel,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            timeout_ms,
        }
    }

    /// 一次调用：固定 Bearer 鉴权头与 JSON；状态码不是预期值就按基线映射错误码。
    pub fn request(&self, method: &str, path: &str, body: Option<&Value>, expected: u16) -> Result<(u16, Value), AuthorityError> {
        let mut request = HttpRequest::new(method, format!("{}{}", self.base_url, path), self.timeout_ms)
            .header("authorization", format!("Bearer {}", self.token))
            .header("accept", "application/json");
        if let Some(body) = body {
            request = request.json_body(body);
        }
        let response = self.transport.send(&request, self.cancel).map_err(|error| match error.kind {
            TransportFailure::Cancelled => AuthorityError::new("AUTHORITY_CANCELLED", None, false, error.detail),
            TransportFailure::Timeout => AuthorityError::new("AUTHORITY_TIMEOUT", None, true, error.detail),
            _ => AuthorityError::new("AUTHORITY_UNAVAILABLE", None, true, error.detail),
        })?;
        if response.status != expected {
            return Err(map_http_error(response.status, path));
        }
        let parsed = response.json().unwrap_or_else(|| json!({"raw": true}));
        Ok((response.status, parsed))
    }

    fn user_call(&self, method: &str, path: &str, body: Option<&Value>, expected: u16) -> Result<UserRead, AuthorityError> {
        let (status, parsed) = self.request(method, path, body, expected)?;
        let user = parse_user_envelope(&parsed)?;
        Ok(UserRead { http_status: status, projected: project_user(user) })
    }

    pub fn create_user(&self, username: &str, expire_at: &str, limit_bytes: i64, strategy: &str, squads: Option<&[String]>) -> Result<UserRead, AuthorityError> {
        if limit_bytes <= 0 {
            return Err(AuthorityError::new("LIMIT_REQUIRED", None, false, "product allocation must send a positive trafficLimitBytes; upstream 0 means unlimited"));
        }
        if !RESET_PERIODS.contains(&strategy) {
            return Err(AuthorityError::new("UNSUPPORTED", None, false, format!("trafficLimitStrategy {strategy} is unsupported")));
        }
        let mut body = json!({
            "username": username,
            "expireAt": expire_at,
            "trafficLimitBytes": limit_bytes,
            "trafficLimitStrategy": strategy,
        });
        if let Some(squads) = squads {
            body["activeInternalSquads"] = json!(squads);
        }
        self.user_call("POST", "/api/users", Some(&body), 201)
    }

    pub fn get_user(&self, id: i64) -> Result<UserRead, AuthorityError> {
        let id = safe_user_id(id)?;
        self.user_call("GET", &format!("/api/users/{id}"), None, 200)
    }

    pub fn get_by_username(&self, username: &str) -> Result<UserRead, AuthorityError> {
        self.user_call("GET", &format!("/api/users/by-username/{}", encode_component(username)), None, 200)
    }

    pub fn update_limit(&self, id: i64, limit_bytes: i64) -> Result<UserRead, AuthorityError> {
        let id = safe_user_id(id)?;
        if limit_bytes <= 0 {
            return Err(AuthorityError::new("LIMIT_REQUIRED", None, false, "product changeLimit cannot send 0/unlimited"));
        }
        self.user_call("PATCH", "/api/users", Some(&json!({"id": id, "trafficLimitBytes": limit_bytes})), 200)
    }

    pub fn disable_user(&self, id: i64) -> Result<UserRead, AuthorityError> {
        let id = safe_user_id(id)?;
        self.user_call("POST", &format!("/api/users/{id}/actions/disable"), None, 200)
    }

    pub fn enable_user(&self, id: i64) -> Result<UserRead, AuthorityError> {
        let id = safe_user_id(id)?;
        self.user_call("POST", &format!("/api/users/{id}/actions/enable"), None, 200)
    }

    pub fn list_nodes(&self) -> Result<Vec<Value>, AuthorityError> {
        let (_, parsed) = self.request("GET", "/api/nodes", None, 200)?;
        let nodes = parsed
            .get("response")
            .and_then(Value::as_array)
            .ok_or_else(|| AuthorityError::new("INVALID_RESPONSE", None, false, "nodes list is not response[]"))?;
        Ok(nodes.iter().map(project_node).collect())
    }
}

pub fn safe_user_id(id: i64) -> Result<i64, AuthorityError> {
    if id <= 0 || id > 9_007_199_254_740_991 {
        return Err(AuthorityError::new("INVALID_PROVIDER_USER_ID", None, false, "provider user id must be a safe positive integer"));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_usernames_do_not_collide_after_stripping_symbols() {
        let a = provider_username("tenant.a");
        let b = provider_username("tenant/a");
        assert_ne!(a, b);
        assert!(a.starts_with("tenanta_"));
        assert!(a.len() <= 36);
        assert!(provider_username("管理").starts_with("u_"));
    }

    #[test]
    fn user_envelopes_are_checked_and_secrets_projected_away() {
        let body = json!({"response": {
            "id": 101, "username": "u_1", "status": "ACTIVE", "trafficLimitBytes": 1000, "trafficLimitStrategy": "MONTH",
            "vlessUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "subscriptionUrl": "https://sub.example.invalid/x",
            "userTraffic": {"usedTrafficBytes": 10}
        }});
        let user = parse_user_envelope(&body).unwrap();
        let projected = project_user(user);
        assert_eq!(projected["usedTrafficBytes"], 10);
        assert_eq!(projected["secrets_present"]["vlessUuid"], true);
        assert!(!projected.to_string().contains("aaaaaaaa-aaaa"));
        assert!(!projected.to_string().contains("sub.example.invalid"));
        let broken = json!({"response": {"id": 999, "status": "ACTIVE"}});
        assert_eq!(parse_user_envelope(&broken).err().unwrap().code, "INVALID_RESPONSE");
        let odd = json!({"response": {"id": 1, "status": "ACTIVE", "trafficLimitBytes": 1, "trafficLimitStrategy": "YEAR", "userTraffic": {"usedTrafficBytes": 0}}});
        assert_eq!(parse_user_envelope(&odd).err().unwrap().code, "UNSUPPORTED");
    }
}
