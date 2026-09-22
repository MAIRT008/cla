//! 产品网络服务的宿主侧链接。命名空间常量来自 `steward-service-ipc`，客户端与服务端共用一份；
//! 改写类命令由宿主在本地授权通过后，用安装器下发的链接密钥签出最小 envelope 再发给服务。
//! 这里只做读取与签名转发：状态读取从不触发安装、修复或重装。

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};
use steward_service_ipc::core::auth::{sign_envelope, EnvelopeDraft};
use steward_service_ipc::core::paths::{forbidden_marker, STATE_DIR_NAME};
use steward_service_ipc::{ServiceCommand, ServiceError, ServiceReply, ServiceRequest, PRODUCT_APP_ID, PROTOCOL, SERVICE_PIPE};

pub use steward_service_ipc::{CORE_PIPE, TEST_SERVICE_PIPE};

pub const PRODUCT_PIPE: &str = SERVICE_PIPE;

pub fn assert_product_pipe(pipe: &str) -> Result<(), String> {
    if let Some(marker) = forbidden_marker(pipe) {
        return Err(format!("SERVICE_IDENTITY_DENIED: refusing upstream identity {marker}"));
    }
    if pipe != SERVICE_PIPE {
        return Err("SERVICE_IDENTITY_DENIED: service pipe is not the product identity".into());
    }
    Ok(())
}

pub fn product_identity(windows_user: &str) -> Value {
    json!({
        "app_id": PRODUCT_APP_ID,
        "service_pipe": SERVICE_PIPE,
        "windows_user": windows_user
    })
}

/// 页面能看到的服务描述：身份与协议，没有 secret、没有内核地址。
pub fn service_descriptor(link: &ServiceLink) -> Value {
    let status = if link.key.is_some() { "READY" } else { "UNAVAILABLE" };
    json!({
        "app_id": PRODUCT_APP_ID,
        "service_pipe": SERVICE_PIPE,
        "protocol": PROTOCOL,
        "link": status,
        "link_code": link.key_error,
    })
}

pub trait ServiceClient: Send + Sync {
    fn call(&self, command: ServiceCommand, request: &ServiceRequest) -> Result<ServiceReply, ServiceError>;
}

pub struct PipeServiceClient;

impl ServiceClient for PipeServiceClient {
    fn call(&self, command: ServiceCommand, request: &ServiceRequest) -> Result<ServiceReply, ServiceError> {
        steward_service_ipc::client::call(command, request, Duration::from_secs(30))
    }
}

pub struct ServiceLink {
    client: Box<dyn ServiceClient>,
    key: Option<Vec<u8>>,
    key_error: Option<String>,
}

fn product_link_key() -> Result<Vec<u8>, String> {
    let program_data = std::env::var_os("ProgramData")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "SERVICE_LINK_UNAVAILABLE".to_string())?;
    let paths = steward_service_ipc::ServicePaths::rooted(PathBuf::from(program_data).join(STATE_DIR_NAME), PathBuf::new());
    let text = std::fs::read_to_string(paths.host_link_key()).map_err(|_| "SERVICE_LINK_UNAVAILABLE".to_string())?;
    steward_service_ipc::core::auth::parse_link_key(&text).map_err(|error| error.code)
}

impl ServiceLink {
    /// 链接密钥由安装器写在服务状态目录里，只有批准用户可读；读不到就如实标不可用。
    pub fn product() -> ServiceLink {
        ServiceLink::new(Box::new(PipeServiceClient), product_link_key())
    }

    pub fn new(client: Box<dyn ServiceClient>, key: Result<Vec<u8>, String>) -> ServiceLink {
        match key {
            Ok(key) => ServiceLink { client, key: Some(key), key_error: None },
            Err(code) => ServiceLink { client, key: None, key_error: Some(code) },
        }
    }

    pub fn link_ready(&self) -> bool {
        self.key.is_some()
    }

    fn request(envelope: Option<steward_service_ipc::Envelope>, payload: Value) -> ServiceRequest {
        ServiceRequest { product_id: PRODUCT_APP_ID.to_string(), protocol: PROTOCOL.to_string(), envelope, payload }
    }

    pub fn read(&self, command: ServiceCommand, payload: Value) -> Result<ServiceReply, ServiceError> {
        self.client.call(command, &ServiceLink::request(None, payload))
    }

    pub fn write(
        &self,
        command: ServiceCommand,
        business_operation_id: &str,
        payload: Value,
        now_ms: i64,
        authorization_expires_at_ms: Option<i64>,
    ) -> Result<ServiceReply, ServiceError> {
        let key = self.key.as_ref().ok_or_else(|| {
            ServiceError::new(self.key_error.as_deref().unwrap_or("SERVICE_LINK_UNAVAILABLE"), "本机没有可用的服务链接密钥")
        })?;
        let environment_ref = payload.get("environment_ref").and_then(Value::as_str).unwrap_or_default().to_string();
        let envelope = sign_envelope(
            key,
            &EnvelopeDraft {
                business_operation_id,
                command,
                environment_ref: &environment_ref,
                payload: &payload,
                now_ms,
                authorization_expires_at_ms,
            },
        )?;
        self.client.call(command, &ServiceLink::request(Some(envelope), payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_product_pipe_is_accepted() {
        assert!(assert_product_pipe(PRODUCT_PIPE).is_ok());
        let upstream = format!(r"\\.\pipe\{}-{}-service", "clash", "verge");
        assert!(assert_product_pipe(&upstream).unwrap_err().starts_with("SERVICE_IDENTITY_DENIED"));
        assert!(assert_product_pipe(TEST_SERVICE_PIPE).is_err(), "测试 pipe 不能当正式服务");
        assert!(CORE_PIPE.contains("ai-environmental-steward"));
    }
}
