//! 内核控制客户端（新增）。经 kode-bridge 0.4.0 的 `IpcHttpClient` 走产品内核 pipe（HTTP over named pipe），
//! 不手写 HTTP/1.1 解析：状态码、响应体边界、超时都由该库处理。secret 以 Bearer 头发送；
//! pipe 本身已由 `LISTEN_NAMEDPIPE_SDDL` 收窄到 LocalSystem。

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kode_bridge::{ClientConfig, IpcHttpClient};
use serde_json::{json, Value};
use tokio::runtime::Handle;

use crate::core::network::CoreController;
use crate::core::paths::CORE_PIPE;
use crate::core::structure::ServiceError;

const MAX_BODY_CHARS: usize = 8 * 1024 * 1024;

pub struct PipeController {
    handle: Handle,
    secret: Arc<Mutex<String>>,
    timeout: Duration,
}

impl PipeController {
    pub fn new(handle: Handle, secret: Arc<Mutex<String>>) -> PipeController {
        PipeController { handle, secret, timeout: Duration::from_secs(10) }
    }

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<(u16, String), ServiceError> {
        let secret = self.secret.lock().map(|value| value.clone()).unwrap_or_default();
        let timeout = self.timeout;
        let method = method.to_string();
        let path = path.to_string();
        self.handle.block_on(async move {
            let unreachable = |detail: String| ServiceError::new("CORE_CONTROLLER_UNREACHABLE", detail);
            let client = IpcHttpClient::with_config(
                CORE_PIPE,
                ClientConfig {
                    default_timeout: timeout,
                    max_retries: 1,
                    retry_delay: Duration::from_millis(50),
                    enable_pooling: false,
                    ..Default::default()
                },
            )
            .map_err(|error| unreachable(error.to_string()))?;
            let builder = match method.as_str() {
                "GET" => client.get(&path),
                "PUT" => client.put(&path),
                "DELETE" => client.delete(&path),
                _ => return Err(ServiceError::new("CORE_CONTROLLER_METHOD", "不支持的内核接口方法")),
            };
            let mut builder = builder.header("Authorization", format!("Bearer {secret}")).timeout(timeout);
            if let Some(value) = body.as_ref() {
                builder = builder.json_body(value);
            }
            let response = builder.send().await.map_err(|error| unreachable(error.to_string()))?;
            let status = response.status();
            let text = if status == 204 { String::new() } else { response.body().map_err(|error| unreachable(error.to_string()))? };
            if text.len() > MAX_BODY_CHARS {
                return Err(ServiceError::new("CORE_CONTROLLER_BODY_TOO_LARGE", "内核接口响应超过上限"));
            }
            Ok((status, text))
        })
    }

    fn get_json(&self, path: &str) -> Result<Value, ServiceError> {
        let (status, text) = self.request("GET", path, None)?;
        if !(200..300).contains(&status) {
            return Err(ServiceError::new("CORE_CONTROLLER_STATUS", format!("内核接口 {path} 返回 {status}")));
        }
        serde_json::from_str(&text).map_err(|_| ServiceError::new("CORE_CONTROLLER_INVALID_JSON", format!("内核接口 {path} 返回的不是 JSON")))
    }
}

impl CoreController for PipeController {
    fn version(&self) -> Result<Value, ServiceError> {
        self.get_json("/version")
    }

    /// 按服务自有配置目录里的绝对路径加载；内核只接受其 home 目录下的安全路径。
    fn load_config(&self, config_path: &Path) -> Result<u16, ServiceError> {
        let body = json!({"path": config_path.to_string_lossy()});
        self.request("PUT", "/configs?force=true", Some(body)).map(|(status, _)| status)
    }

    fn general(&self) -> Result<Value, ServiceError> {
        self.get_json("/configs")
    }

    fn rules(&self) -> Result<Value, ServiceError> {
        self.get_json("/rules")
    }

    fn proxies(&self) -> Result<Value, ServiceError> {
        self.get_json("/proxies")
    }

    fn connections(&self) -> Result<Value, ServiceError> {
        self.get_json("/connections")
    }

    fn close_connections(&self) -> Result<u16, ServiceError> {
        self.request("DELETE", "/connections", None).map(|(status, _)| status)
    }
}
