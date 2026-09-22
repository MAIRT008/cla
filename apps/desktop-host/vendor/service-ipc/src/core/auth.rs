//! 授权 envelope。上游 `auth.rs` 只比对一句所有客户端都知道的固定 `X-IPC-Magic` 文本，这不是用户认证；
//! 产品服务改为核对宿主用安装时下发的链接密钥签出的 HMAC-SHA256 envelope，
//! envelope 只含执行所需字段：不可预测 operation、环境、固定命令、计划/分配版本、载荷摘要与期限。
//! 密码、API Key、完整 YAML 与代理凭据都不进 envelope。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::core::command::ServiceCommand;
use crate::core::structure::ServiceError;

/// 宿主签出的 envelope 默认两分钟有效；服务拒绝声明期限超过五分钟的 envelope。
pub const ENVELOPE_TTL_MS: i64 = 120_000;
pub const ENVELOPE_MAX_TTL_MS: i64 = 300_000;
const CLOCK_SKEW_MS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub operation_id: String,
    pub command: String,
    pub environment_ref: String,
    pub plan_version: Option<String>,
    pub assignment_version: Option<String>,
    pub payload_sha256: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub mac: String,
}

pub struct EnvelopeDraft<'a> {
    pub business_operation_id: &'a str,
    pub command: ServiceCommand,
    pub environment_ref: &'a str,
    pub payload: &'a Value,
    pub now_ms: i64,
    pub authorization_expires_at_ms: Option<i64>,
}

/// 与 serde_json 是否开启 preserve_order 无关的规范化编码：对象键逐层排序。
/// 宿主与服务各自编译，只有这样两边算出的摘要和 MAC 才一定一致。
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|key| format!("{}:{}", Value::String(key.to_string()), canonical_json(&map[key.as_str()])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => format!("[{}]", items.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_raw(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).as_slice().to_vec()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&sha256_raw(bytes))
}

/// RFC 2104 HMAC-SHA256。
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256_raw(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    let mut outer = Vec::with_capacity(96);
    for byte in block {
        inner.push(byte ^ 0x36);
        outer.push(byte ^ 0x5c);
    }
    inner.extend_from_slice(message);
    outer.extend_from_slice(&sha256_raw(&inner));
    to_hex(&sha256_raw(&outer))
}

pub fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes().zip(right.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

pub fn random_hex(bytes: usize) -> Result<String, ServiceError> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer)
        .map_err(|error| ServiceError::new("RANDOM_UNAVAILABLE", format!("系统安全随机源不可用：{error}")))?;
    Ok(to_hex(&buffer))
}

/// 链接密钥文件是 64 个以上的十六进制字符；读出后按字节使用。
pub fn parse_link_key(text: &str) -> Result<Vec<u8>, ServiceError> {
    let trimmed = text.trim();
    let invalid = || ServiceError::new("LINK_KEY_INVALID", "服务链接密钥格式不对");
    if trimmed.len() < 64 || trimmed.len() % 2 != 0 {
        return Err(invalid());
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&trimmed[index..index + 2], 16).map_err(|_| invalid()))
        .collect()
}

pub fn payload_digest(payload: &Value) -> String {
    sha256_hex(canonical_json(payload).as_bytes())
}

/// 业务 operation_id 映射成服务侧 operation：同一业务重试得到同一值，没有链接密钥的一方猜不出来。
pub fn operation_id_for(key: &[u8], business_operation_id: &str, command: ServiceCommand) -> String {
    let mac = hmac_sha256_hex(key, format!("operation|{}|{}", command.name(), business_operation_id).as_bytes());
    format!("op-{}", &mac[..40])
}

fn valid_operation_id(value: &str) -> bool {
    value.len() == 43 && value.starts_with("op-") && value[3..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn material(envelope: &Envelope) -> String {
    canonical_json(&json!({
        "operation_id": envelope.operation_id,
        "command": envelope.command,
        "environment_ref": envelope.environment_ref,
        "plan_version": envelope.plan_version,
        "assignment_version": envelope.assignment_version,
        "payload_sha256": envelope.payload_sha256,
        "issued_at_ms": envelope.issued_at_ms,
        "expires_at_ms": envelope.expires_at_ms,
    }))
}

pub fn sign_envelope(key: &[u8], draft: &EnvelopeDraft<'_>) -> Result<Envelope, ServiceError> {
    if key.len() < 32 {
        return Err(ServiceError::new("LINK_KEY_INVALID", "服务链接密钥太短"));
    }
    let mut expires_at_ms = draft.now_ms + ENVELOPE_TTL_MS;
    if let Some(limit) = draft.authorization_expires_at_ms {
        expires_at_ms = expires_at_ms.min(limit);
    }
    if expires_at_ms <= draft.now_ms {
        return Err(ServiceError::new("AUTHORIZATION_EXPIRED", "本地授权已过期，不能再签发服务 envelope"));
    }
    let text = |field: &str| draft.payload.get(field).and_then(Value::as_str).map(str::to_string);
    let mut envelope = Envelope {
        operation_id: operation_id_for(key, draft.business_operation_id, draft.command),
        command: draft.command.name().to_string(),
        environment_ref: draft.environment_ref.to_string(),
        plan_version: text("plan_version"),
        assignment_version: text("assignment_version"),
        payload_sha256: payload_digest(draft.payload),
        issued_at_ms: draft.now_ms,
        expires_at_ms,
        mac: String::new(),
    };
    envelope.mac = hmac_sha256_hex(key, material(&envelope).as_bytes());
    Ok(envelope)
}

/// 核对签名与字段绑定；期限单独判断，好让已完成操作的同内容重放仍能取回原回执。
pub fn verify_envelope(key: &[u8], envelope: &Envelope, command: ServiceCommand, payload: &Value) -> Result<(), ServiceError> {
    if key.len() < 32 {
        return Err(ServiceError::new("LINK_KEY_INVALID", "服务没有可用的链接密钥"));
    }
    if !constant_time_eq(&envelope.mac, &hmac_sha256_hex(key, material(envelope).as_bytes())) {
        return Err(ServiceError::new("AUTHORIZATION_INVALID", "授权 envelope 的签名不对"));
    }
    if envelope.command != command.name() {
        return Err(ServiceError::new("AUTHORIZATION_COMMAND_MISMATCH", "envelope 签发给了另一个命令"));
    }
    if !valid_operation_id(&envelope.operation_id) {
        return Err(ServiceError::new("AUTHORIZATION_INVALID", "operation_id 不是宿主签发的形状"));
    }
    if envelope.expires_at_ms <= envelope.issued_at_ms || envelope.expires_at_ms - envelope.issued_at_ms > ENVELOPE_MAX_TTL_MS {
        return Err(ServiceError::new("AUTHORIZATION_INVALID", "envelope 期限不合法"));
    }
    if envelope.payload_sha256 != payload_digest(payload) {
        return Err(ServiceError::new("AUTHORIZATION_PAYLOAD_MISMATCH", "载荷与授权时的摘要不一致"));
    }
    let field = |name: &str| payload.get(name).and_then(Value::as_str);
    if field("environment_ref") != Some(envelope.environment_ref.as_str()) {
        return Err(ServiceError::new("ENVIRONMENT_MISMATCH", "载荷环境与授权环境不一致"));
    }
    if field("plan_version") != envelope.plan_version.as_deref() || field("assignment_version") != envelope.assignment_version.as_deref() {
        return Err(ServiceError::new("PLAN_VERSION_MISMATCH", "载荷的计划或分配版本与授权不一致"));
    }
    Ok(())
}

pub fn envelope_expired(envelope: &Envelope, now_ms: i64) -> bool {
    now_ms >= envelope.expires_at_ms || now_ms + CLOCK_SKEW_MS < envelope.issued_at_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"synthetic-link-key-0123456789abcdef-0123456789";

    #[test]
    fn hmac_matches_the_rfc_4231_vector_and_canonical_json_ignores_key_order() {
        assert_eq!(
            hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let left = json!({"b": 1, "a": {"y": [1, {"d": true, "c": null}], "x": "\"q\""}});
        let right = json!({"a": {"x": "\"q\"", "y": [1, {"c": null, "d": true}]}, "b": 1});
        assert_eq!(canonical_json(&left), canonical_json(&right));
        assert_eq!(canonical_json(&left), r#"{"a":{"x":"\"q\"","y":[1,{"c":null,"d":true}]},"b":1}"#);
        assert_eq!(parse_link_key(&"ab".repeat(32)).unwrap(), vec![0xab; 32]);
        assert!(parse_link_key("abc").is_err());
    }

    #[test]
    fn envelopes_bind_command_payload_environment_and_versions() {
        let payload = json!({"environment_ref": "env-a", "plan_version": "plan:v3:daily:abc", "assignment_version": "v3", "expected_config_sha256": "0".repeat(64)});
        let draft = EnvelopeDraft {
            business_operation_id: "apply-1",
            command: ServiceCommand::ApplyConfig,
            environment_ref: "env-a",
            payload: &payload,
            now_ms: 1_000_000,
            authorization_expires_at_ms: Some(1_060_000),
        };
        let envelope = sign_envelope(KEY, &draft).unwrap();
        assert_eq!(envelope.expires_at_ms, 1_060_000, "不会比本地授权活得更久");
        assert!(verify_envelope(KEY, &envelope, ServiceCommand::ApplyConfig, &payload).is_ok());
        assert!(!envelope_expired(&envelope, 1_059_999));
        assert!(envelope_expired(&envelope, 1_060_000));

        let wrong_key = verify_envelope(b"another-synthetic-link-key-0123456789abcdef", &envelope, ServiceCommand::ApplyConfig, &payload);
        assert_eq!(wrong_key.unwrap_err().code, "AUTHORIZATION_INVALID");
        assert_eq!(verify_envelope(KEY, &envelope, ServiceCommand::StartCore, &payload).unwrap_err().code, "AUTHORIZATION_COMMAND_MISMATCH");
        let mut tampered = payload.clone();
        tampered["expected_config_sha256"] = json!("1".repeat(64));
        assert_eq!(verify_envelope(KEY, &envelope, ServiceCommand::ApplyConfig, &tampered).unwrap_err().code, "AUTHORIZATION_PAYLOAD_MISMATCH");
        let mut forged = envelope.clone();
        forged.environment_ref = "env-b".to_string();
        assert_eq!(verify_envelope(KEY, &forged, ServiceCommand::ApplyConfig, &payload).unwrap_err().code, "AUTHORIZATION_INVALID");

        assert_eq!(operation_id_for(KEY, "apply-1", ServiceCommand::ApplyConfig), envelope.operation_id, "同一业务重试得到同一 operation");
        assert_ne!(operation_id_for(KEY, "apply-1", ServiceCommand::ValidateConfig), envelope.operation_id);
        assert_eq!(envelope.operation_id.len(), 43);
    }
}
