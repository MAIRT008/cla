//! IPC 线上结构。上游 `structure.rs` 的 `ClashConfig`（任意 core_path/config_path）与 `WriterConfig` 已删除：
//! 产品服务不接受调用方给出的程序路径、配置目录或日志目录。
//!
//! 服务 pipe 每个连接一问一答：4 字节大端长度 + JSON。不再经 kode-bridge 的 HTTP 服务端，
//! 因为它不暴露 pipe 句柄，服务拿不到 Windows 给出的客户端进程身份。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

use crate::core::auth::Envelope;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceError {
    pub code: String,
    pub reason: String,
}

impl ServiceError {
    pub fn new(code: &str, reason: impl Into<String>) -> ServiceError {
        ServiceError { code: code.to_string(), reason: reason.into() }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.reason)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRequest {
    pub product_id: String,
    pub protocol: String,
    pub envelope: Option<Envelope>,
    pub payload: Value,
}

/// `ok` 只表示本命令的业务结论成立；阶段细节、实际回读与缺测都在 `receipt` 里。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceReply {
    pub ok: bool,
    pub code: Option<String>,
    pub reason: Option<String>,
    pub receipt: Value,
}

impl ServiceReply {
    pub fn success(receipt: Value) -> ServiceReply {
        ServiceReply { ok: true, code: None, reason: None, receipt }
    }

    pub fn failure(error: &ServiceError, receipt: Value) -> ServiceReply {
        ServiceReply { ok: false, code: Some(error.code.clone()), reason: Some(error.reason.clone()), receipt }
    }

    pub fn rejected(error: &ServiceError) -> ServiceReply {
        ServiceReply::failure(error, json!({"side_effects": false}))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRequest {
    pub command: String,
    pub request: ServiceRequest,
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ServiceError> {
    let body = serde_json::to_vec(value).map_err(|_| ServiceError::new("FRAME_INVALID", "服务消息无法序列化"))?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(ServiceError::new("FRAME_TOO_LARGE", "服务消息超过长度上限"));
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn frame_length(header: [u8; 4]) -> Result<usize, ServiceError> {
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ServiceError::new("FRAME_INVALID", "服务消息长度不合法"));
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_reject_empty_or_oversized_lengths() {
        let request = WireRequest {
            command: "Handshake".to_string(),
            request: ServiceRequest { product_id: "p".to_string(), protocol: "v".to_string(), envelope: None, payload: json!({}) },
        };
        let frame = encode_frame(&request).unwrap();
        let length = frame_length([frame[0], frame[1], frame[2], frame[3]]).unwrap();
        assert_eq!(length, frame.len() - 4);
        let decoded: WireRequest = serde_json::from_slice(&frame[4..]).unwrap();
        assert_eq!(decoded.command, "Handshake");
        assert_eq!(frame_length([0, 0, 0, 0]).unwrap_err().code, "FRAME_INVALID");
        assert_eq!(frame_length(((MAX_FRAME_BYTES + 1) as u32).to_be_bytes()).unwrap_err().code, "FRAME_INVALID");
    }
}
