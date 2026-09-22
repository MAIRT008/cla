//! 出站 HTTP 的唯一入口。模型提供方、Remnawave 与订阅拉取都经 `HttpTransport`，
//! 产品路径是 `UreqTransport`（阻塞调用，跑在 axum 的 blocking 线程池里），测试注入脚本化实现。
//!
//! 取消：页面断开请求时 main.rs 置位 `CancelToken`。发请求前、收到响应后各检查一次；
//! 已经发出的单次调用由超时兜底，不强行中断套接字。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> CancelToken {
        CancelToken(Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u64,
}

impl HttpRequest {
    pub fn new(method: &str, url: impl Into<String>, timeout_ms: u64) -> HttpRequest {
        HttpRequest { method: method.to_string(), url: url.into(), headers: Vec::new(), body: None, timeout_ms }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> HttpRequest {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    pub fn json_body(mut self, body: &serde_json::Value) -> HttpRequest {
        self.headers.push(("content-type".to_string(), "application/json".to_string()));
        self.body = Some(body.to_string().into_bytes());
        self
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportFailure {
    Timeout,
    Cancelled,
    Connect,
    Other,
}

/// `detail` 只进日志，且写入前经日志脱敏；不回给页面。
#[derive(Clone, Debug)]
pub struct TransportError {
    pub kind: TransportFailure,
    pub detail: String,
}

impl TransportError {
    pub fn new(kind: TransportFailure, detail: impl Into<String>) -> TransportError {
        TransportError { kind, detail: detail.into() }
    }
}

pub trait HttpTransport: Send + Sync {
    fn send(&self, request: &HttpRequest, cancel: &CancelToken) -> Result<HttpResponse, TransportError>;
}

/// 单次响应正文上限。模型回复、Remnawave JSON 与订阅文件都远小于它。
pub const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

pub struct UreqTransport;

fn map_ureq_error(error: ureq::Error) -> TransportError {
    match error {
        ureq::Error::Timeout(_) => TransportError::new(TransportFailure::Timeout, "请求超时"),
        ureq::Error::HostNotFound => TransportError::new(TransportFailure::Connect, "主机名无法解析"),
        ureq::Error::ConnectionFailed => TransportError::new(TransportFailure::Connect, "无法建立连接"),
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => TransportError::new(TransportFailure::Timeout, "请求超时"),
        ureq::Error::Io(io) => TransportError::new(TransportFailure::Connect, format!("网络读写失败：{io}")),
        other => TransportError::new(TransportFailure::Other, format!("HTTP 客户端错误：{other}")),
    }
}

impl HttpTransport for UreqTransport {
    fn send(&self, request: &HttpRequest, cancel: &CancelToken) -> Result<HttpResponse, TransportError> {
        if cancel.is_cancelled() {
            return Err(TransportError::new(TransportFailure::Cancelled, "调用方已取消"));
        }
        // 不跟随重定向：Authorization 头不能被带到另一台主机。
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(request.timeout_ms.max(1))))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let agent = ureq::Agent::new_with_config(config);
        let url = request.url.as_str();
        let outcome = match request.method.as_str() {
            "GET" => {
                let mut builder = agent.get(url);
                for (name, value) in &request.headers {
                    builder = builder.header(name.as_str(), value.as_str());
                }
                builder.call()
            }
            "POST" | "PATCH" | "PUT" => {
                let mut builder = match request.method.as_str() {
                    "POST" => agent.post(url),
                    "PATCH" => agent.patch(url),
                    _ => agent.put(url),
                };
                for (name, value) in &request.headers {
                    builder = builder.header(name.as_str(), value.as_str());
                }
                match &request.body {
                    Some(bytes) => builder.send(bytes.as_slice()),
                    None => builder.send_empty(),
                }
            }
            other => {
                return Err(TransportError::new(TransportFailure::Other, format!("不支持的请求方法 {other}")));
            }
        };
        let mut response = outcome.map_err(map_ureq_error)?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(map_ureq_error)?;
        if cancel.is_cancelled() {
            return Err(TransportError::new(TransportFailure::Cancelled, "响应到达时调用方已取消"));
        }
        Ok(HttpResponse { status, content_type, body })
    }
}
