//! 默认浏览器诊断：宿主在 127.0.0.1 的随机端口开一次性监听，用系统默认浏览器打开带一次性令牌的诊断页，
//! 只收一份同源、令牌、大小与期限都合规的回传，交给 WebView 里的诊断核心按会话校验。
//!
//! - 只绑回环地址；页面路径带 128 位随机令牌；Host 必须是 `127.0.0.1:<端口>`（挡 DNS 重绑定），
//!   回传的 Origin 必须是本监听的源；请求头 16 KiB、正文 64 KiB 封顶；只收第一份回传；到期或关闭即停。
//! - 页面里的会话参数（会话引用、一次性 nonce、任务与环境）由宿主注入，页面自己不能改目标。
//! - 打开浏览器只打开本监听的页面地址，调用方给不了别的 URL。
//! - 同一时间只有一个监听；再开一个会先关掉旧的。
//!
//! 本机没有 cargo/rustc，这个模块尚未编译。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::commands::{iso_from_millis, now_millis};

const PAGE: &str = include_str!("../../diag/index.html");
const SESSION_PLACEHOLDER: &str = "__STEWARD_DIAG_SESSION__";
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_TTL_MS: i64 = 10 * 60 * 1000;
const MAX_TTL_MS: i64 = 15 * 60 * 1000;
const MAX_ICE_SERVERS: usize = 4;

/// 打开 URL 的方式：产品用系统默认浏览器，测试与注入宿主不打开任何东西。
pub trait UrlOpener: Send + Sync {
    fn open(&self, url: &str) -> Result<(), String>;
}

/// 系统默认浏览器（Windows ShellExecuteW）。
pub struct SystemBrowser;

/// 不打开浏览器：注入宿主用它，任何打开请求都如实失败。
pub struct NoBrowser;

impl UrlOpener for NoBrowser {
    fn open(&self, _url: &str) -> Result<(), String> {
        Err("BROWSER_DIAG_UNSUPPORTED: this host does not open browsers".into())
    }
}

#[cfg(windows)]
mod shell_ffi {
    use std::ffi::c_void;

    #[link(name = "shell32")]
    extern "system" {
        pub fn ShellExecuteW(
            hwnd: *mut c_void,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show_cmd: i32,
        ) -> *mut c_void;
    }
}

#[cfg(windows)]
impl UrlOpener for SystemBrowser {
    fn open(&self, url: &str) -> Result<(), String> {
        if !url.starts_with("http://127.0.0.1:") {
            return Err("BROWSER_DIAG_URL_REFUSED: only the local diagnostic page can be opened".into());
        }
        let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(std::iter::once(0)).collect() };
        let operation = wide("open");
        let file = wide(url);
        // SW_SHOWNORMAL = 1；返回值大于 32 表示成功。
        let result = unsafe { shell_ffi::ShellExecuteW(std::ptr::null_mut(), operation.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), 1) };
        if result as isize > 32 {
            Ok(())
        } else {
            Err(format!("BROWSER_DIAG_LAUNCH_FAILED: ShellExecuteW returned {}", result as isize))
        }
    }
}

#[cfg(not(windows))]
impl UrlOpener for SystemBrowser {
    fn open(&self, _url: &str) -> Result<(), String> {
        Err("BROWSER_DIAG_UNSUPPORTED: opening the default browser is implemented for Windows only".into())
    }
}

struct Shared {
    session: Mutex<Option<Value>>,
    report: Mutex<Option<Value>>,
    stop: AtomicBool,
}

struct Listener {
    listener_ref: String,
    token: String,
    origin: String,
    task_ref: String,
    environment_ref: String,
    expires_ms: i64,
    shared: Arc<Shared>,
}

pub struct BrowserDiag {
    active: Mutex<Option<Listener>>,
    opener: Box<dyn UrlOpener>,
}

impl BrowserDiag {
    pub fn new(opener: Box<dyn UrlOpener>) -> BrowserDiag {
        BrowserDiag { active: Mutex::new(None), opener }
    }
}

fn text(payload: &Value, field: &str) -> Result<String, String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .map(str::to_string)
        .ok_or_else(|| format!("NATIVE_PAYLOAD_INVALID: {field} is required"))
}

fn busy() -> String {
    "BROWSER_DIAG_BUSY: the listener state is unavailable".to_string()
}

/// 开一次性监听。默认浏览器在宿主上运行，所以只接受本安装的环境。
pub fn listen(diag: &BrowserDiag, host_environment: &str, anchor: &Path, payload: &Value) -> Result<Value, String> {
    let task_ref = text(payload, "task_ref")?;
    let environment_ref = text(payload, "environment_ref")?;
    if environment_ref != host_environment {
        return Err(format!("BROWSER_DIAG_ENVIRONMENT_MISMATCH: the default browser runs in {host_environment}, not {environment_ref}"));
    }
    let ttl = payload.get("ttl_ms").and_then(Value::as_i64).unwrap_or(DEFAULT_TTL_MS).clamp(10_000, MAX_TTL_MS);
    let mut active = diag.active.lock().map_err(|_| busy())?;
    if let Some(previous) = active.take() {
        previous.shared.stop.store(true, Ordering::SeqCst);
    }
    let socket = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    socket.set_nonblocking(true).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let port = socket.local_addr().map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?.port();
    let token = crate::workspace::random_hex(anchor);
    let listener_ref = format!("browser-diag-{}", &crate::workspace::random_hex(anchor)[..16]);
    let origin = format!("http://127.0.0.1:{port}");
    let expires_ms = now_millis() + ttl;
    let shared = Arc::new(Shared { session: Mutex::new(None), report: Mutex::new(None), stop: AtomicBool::new(false) });
    let server = Server {
        page_path: format!("/diag/{token}"),
        report_path: format!("/diag/{token}/report"),
        origin: origin.clone(),
        host: format!("127.0.0.1:{port}"),
        expires_ms,
        shared: shared.clone(),
    };
    std::thread::spawn(move || server.run(socket));
    *active = Some(Listener {
        listener_ref: listener_ref.clone(),
        token,
        origin: origin.clone(),
        task_ref,
        environment_ref,
        expires_ms,
        shared,
    });
    Ok(json!({"ok": true, "listener_ref": listener_ref, "origin": origin, "expires_at": iso_from_millis(expires_ms)}))
}

/// STUN/TURN 服务器只收 `stun:`/`turns:`/`turn:` 地址，最多四个；凭据字段一律丢弃。
fn ice_servers(value: Option<&Value>) -> Value {
    let mut out = Vec::new();
    for item in value.and_then(Value::as_array).cloned().unwrap_or_default() {
        let urls: Vec<String> = match item.get("urls") {
            Some(Value::String(url)) => vec![url.clone()],
            Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).map(str::to_string).collect(),
            _ => Vec::new(),
        };
        let urls: Vec<String> = urls
            .into_iter()
            .filter(|url| url.len() <= 256 && (url.starts_with("stun:") || url.starts_with("turn:") || url.starts_with("turns:")))
            .collect();
        if !urls.is_empty() && out.len() < MAX_ICE_SERVERS {
            out.push(json!({"urls": urls}));
        }
    }
    Value::Array(out)
}

/// 把诊断核心建好的会话交给监听，并用默认浏览器打开本监听的页面。
pub fn launch(diag: &BrowserDiag, payload: &Value) -> Result<Value, String> {
    let listener_ref = text(payload, "listener_ref")?;
    let session = payload.get("session").and_then(Value::as_object).ok_or("NATIVE_PAYLOAD_INVALID: session must be an object")?;
    let url = {
        let active = diag.active.lock().map_err(|_| busy())?;
        let listener = active
            .as_ref()
            .filter(|item| item.listener_ref == listener_ref)
            .ok_or_else(|| format!("BROWSER_DIAG_UNKNOWN: {listener_ref} is not the active listener"))?;
        if now_millis() >= listener.expires_ms || listener.shared.stop.load(Ordering::SeqCst) {
            return Err(format!("BROWSER_DIAG_EXPIRED: {listener_ref} has already closed"));
        }
        let mut injected = Map::new();
        for field in ["session_ref", "session_nonce", "script_version"] {
            let value = session
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 128)
                .ok_or_else(|| format!("NATIVE_PAYLOAD_INVALID: session.{field} is required"))?;
            injected.insert(field.to_string(), json!(value));
        }
        for (field, expected) in [("task_ref", &listener.task_ref), ("environment_ref", &listener.environment_ref)] {
            if session.get(field).and_then(Value::as_str) != Some(expected.as_str()) {
                return Err(format!("NATIVE_PAYLOAD_INVALID: session.{field} does not match the listener"));
            }
            injected.insert(field.to_string(), json!(expected));
        }
        let profile = session.get("profile_ref").filter(|value| value.is_string()).cloned().unwrap_or(Value::Null);
        injected.insert("profile_ref".to_string(), profile);
        injected.insert("ice_servers".to_string(), ice_servers(session.get("ice_servers")));
        injected.insert("report_path".to_string(), json!(format!("/diag/{}/report", listener.token)));
        *listener.shared.session.lock().map_err(|_| busy())? = Some(Value::Object(injected));
        format!("{}/diag/{}", listener.origin, listener.token)
    };
    diag.opener.open(&url)?;
    Ok(json!({"ok": true, "listener_ref": listener_ref, "launched": true}))
}

/// 取回传：收到了就原样交给页面（核心再按会话校验），没收到回报等待或已过期。
pub fn receive(diag: &BrowserDiag, payload: &Value) -> Result<Value, String> {
    let listener_ref = text(payload, "listener_ref")?;
    let active = diag.active.lock().map_err(|_| busy())?;
    let listener = active
        .as_ref()
        .filter(|item| item.listener_ref == listener_ref)
        .ok_or_else(|| format!("BROWSER_DIAG_UNKNOWN: {listener_ref} is not the active listener"))?;
    if let Some(report) = listener.shared.report.lock().map_err(|_| busy())?.clone() {
        return Ok(json!({
            "ok": true,
            "status": "RECEIVED",
            "origin": report["origin"],
            "body": report["body"],
            "received_at": report["received_at"],
        }));
    }
    if now_millis() >= listener.expires_ms || listener.shared.stop.load(Ordering::SeqCst) {
        return Ok(json!({"ok": true, "status": "EXPIRED"}));
    }
    Ok(json!({"ok": true, "status": "WAITING", "expires_at": iso_from_millis(listener.expires_ms)}))
}

pub fn close(diag: &BrowserDiag, payload: &Value) -> Result<Value, String> {
    let listener_ref = text(payload, "listener_ref")?;
    let mut active = diag.active.lock().map_err(|_| busy())?;
    let matches = active.as_ref().map(|item| item.listener_ref == listener_ref).unwrap_or(false);
    if matches {
        if let Some(listener) = active.take() {
            listener.shared.stop.store(true, Ordering::SeqCst);
        }
    }
    Ok(json!({"ok": true, "closed": matches}))
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// 读一个请求；头或正文超限、格式不对都按状态码拒绝，不继续读。
fn read_request<R: Read>(stream: &mut R) -> Result<Request, u16> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    // 头的长度按结束符（含 \r\n\r\n）算；先认出结束符也要先过长度检查，不能让最后一块把上限带过去。
    let header_end = loop {
        if let Some(end) = find_header_end(&buffer) {
            if end + 4 > MAX_HEADER_BYTES {
                return Err(431);
            }
            break end;
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(431);
        }
        let read = stream.read(&mut chunk).map_err(|_| 408u16)?;
        if read == 0 {
            return Err(400);
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = std::str::from_utf8(&buffer[..header_end]).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(400u16)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(400u16)?.to_string();
    let target = parts.next().ok_or(400u16)?;
    let path = target.split('?').next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length = headers
        .iter()
        .find(|(key, _)| key == "content-length")
        .map(|(_, value)| value.parse::<usize>().map_err(|_| 400u16))
        .transpose()?
        .unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err(413);
    }
    let mut body: Vec<u8> = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).map_err(|_| 408u16)?;
        if read == 0 {
            return Err(400);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Ok(Request { method, path, headers, body })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// 注入页面的会话 JSON：`<`、`>`、`&` 转成 \u 转义，内容里再出现什么也关不掉 script 标签。
fn inject(session: &Value) -> String {
    let text = serde_json::to_string(session).unwrap_or_else(|_| "{}".to_string());
    let escaped = text.replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026");
    PAGE.replace(SESSION_PLACEHOLDER, &escaped)
}

struct Server {
    page_path: String,
    report_path: String,
    origin: String,
    host: String,
    expires_ms: i64,
    shared: Arc<Shared>,
}

impl Server {
    fn run(self, socket: TcpListener) {
        while !self.shared.stop.load(Ordering::SeqCst) && now_millis() < self.expires_ms {
            match socket.accept() {
                Ok((stream, _)) => self.handle(stream),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        self.shared.stop.store(true, Ordering::SeqCst);
    }

    fn handle(&self, mut stream: TcpStream) {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        match read_request(&mut stream) {
            Ok(request) => {
                let (status, content_type, body) = self.route(&request);
                write_response(&mut stream, status, content_type, &body);
            }
            Err(status) => write_response(&mut stream, status, "text/plain; charset=utf-8", b""),
        }
    }

    fn route(&self, request: &Request) -> (u16, &'static str, Vec<u8>) {
        let plain = "text/plain; charset=utf-8";
        if request.header("host") != Some(self.host.as_str()) {
            return (421, plain, Vec::new());
        }
        if request.method == "GET" && request.path == self.page_path {
            let session = match self.shared.session.lock() {
                Ok(guard) => guard.clone(),
                Err(_) => None,
            };
            return match session {
                Some(session) => (200, "text/html; charset=utf-8", inject(&session).into_bytes()),
                None => (409, plain, Vec::new()),
            };
        }
        if request.method == "POST" && request.path == self.report_path {
            if request.header("origin") != Some(self.origin.as_str()) {
                return (403, plain, Vec::new());
            }
            let json_body = request.header("content-type").map(|value| value.to_ascii_lowercase().starts_with("application/json")).unwrap_or(false);
            if !json_body {
                return (415, plain, Vec::new());
            }
            let parsed: Value = match serde_json::from_slice::<Value>(&request.body) {
                Ok(value @ Value::Object(_)) => value,
                _ => return (400, plain, Vec::new()),
            };
            let mut report = match self.shared.report.lock() {
                Ok(guard) => guard,
                Err(_) => return (409, plain, Vec::new()),
            };
            if report.is_some() {
                return (409, plain, Vec::new());
            }
            *report = Some(json!({"origin": self.origin, "body": parsed, "received_at": iso_from_millis(now_millis())}));
            return (204, plain, Vec::new());
        }
        (404, plain, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Mutex as StdMutex;

    struct RecordingOpener {
        opened: Arc<StdMutex<Vec<String>>>,
    }

    impl UrlOpener for RecordingOpener {
        fn open(&self, url: &str) -> Result<(), String> {
            self.opened.lock().unwrap().push(url.to_string());
            Ok(())
        }
    }

    fn exchange(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn a_listener_serves_one_session_and_accepts_one_same_origin_report() {
        let opened = Arc::new(StdMutex::new(Vec::new()));
        let diag = BrowserDiag::new(Box::new(RecordingOpener { opened: opened.clone() }));
        let anchor = std::env::temp_dir();
        assert!(listen(&diag, "windows-host", &anchor, &json!({"task_ref": "diag-1", "environment_ref": "wsl-ubuntu"})).unwrap_err().starts_with("BROWSER_DIAG_ENVIRONMENT_MISMATCH"));
        let listened = listen(&diag, "windows-host", &anchor, &json!({"task_ref": "diag-1", "environment_ref": "windows-host"})).unwrap();
        let listener_ref = listened["listener_ref"].as_str().unwrap().to_string();
        let origin = listened["origin"].as_str().unwrap().to_string();
        let port: u16 = origin.rsplit(':').next().unwrap().parse().unwrap();
        assert!(!listened.to_string().contains("/diag/"), "令牌不回给调用方");

        let session = json!({
            "session_ref": "diag-session-1",
            "session_nonce": "nonce-1",
            "script_version": "diag-sample-v1",
            "task_ref": "diag-1",
            "environment_ref": "windows-host",
            "ice_servers": [{"urls": ["stun:stun.synthetic.invalid:3478", "http://evil.invalid"], "credential": "x"}]
        });
        let mut wrong = session.clone();
        wrong["task_ref"] = json!("diag-2");
        assert!(launch(&diag, &json!({"listener_ref": listener_ref, "session": wrong})).is_err(), "会话必须对上监听的任务");
        launch(&diag, &json!({"listener_ref": listener_ref, "session": session})).unwrap();
        let url = opened.lock().unwrap()[0].clone();
        let path = url.strip_prefix(&origin).unwrap().to_string();
        let host = format!("127.0.0.1:{port}");

        let page = exchange(port, &format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"));
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
        assert!(page.contains("nonce-1") && !page.contains(SESSION_PLACEHOLDER));
        assert!(page.contains("stun:stun.synthetic.invalid:3478") && !page.contains("evil.invalid") && !page.contains("\"credential\""));
        assert!(exchange(port, &format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")).starts_with("HTTP/1.1 421"), "Host 不对就拒绝");
        assert!(exchange(port, &format!("GET /diag/guess HTTP/1.1\r\nHost: {host}\r\n\r\n")).starts_with("HTTP/1.1 404"));

        let body = r#"{"session_ref":"diag-session-1","sample":{"platform":{"timezone":"UTC"}}}"#;
        let post = |origin_header: &str, content: &str| {
            exchange(
                port,
                &format!(
                    "POST {path}/report HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin_header}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{content}",
                    content.len()
                ),
            )
        };
        assert!(post("http://evil.invalid", body).starts_with("HTTP/1.1 403"), "别的源不收");
        assert_eq!(receive(&diag, &json!({"listener_ref": listener_ref})).unwrap()["status"], "WAITING");
        assert!(post(&origin, body).starts_with("HTTP/1.1 204"));
        assert!(post(&origin, body).starts_with("HTTP/1.1 409"), "只收一份");
        let received = receive(&diag, &json!({"listener_ref": listener_ref})).unwrap();
        assert_eq!(received["status"], "RECEIVED");
        assert_eq!(received["origin"], origin.as_str());
        assert_eq!(received["body"]["sample"]["platform"]["timezone"], "UTC");

        let oversized = format!(
            "POST {path}/report HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert!(exchange(port, &oversized).starts_with("HTTP/1.1 413"));
        assert_eq!(close(&diag, &json!({"listener_ref": listener_ref})).unwrap()["closed"], true);
        assert!(receive(&diag, &json!({"listener_ref": listener_ref})).is_err(), "关掉后监听不再存在");
    }

    /// 总长正好 `total` 字节、以 \r\n\r\n 结尾的请求头。
    fn header_of(total: usize) -> Vec<u8> {
        let head = "GET /diag/x HTTP/1.1\r\nHost: 127.0.0.1:1\r\nX-Pad: ";
        let mut text = String::from(head);
        text.push_str(&"a".repeat(total - head.len() - 4));
        text.push_str("\r\n\r\n");
        assert_eq!(text.len(), total);
        text.into_bytes()
    }

    #[test]
    fn the_header_limit_holds_even_when_the_terminator_arrives_in_the_read_that_crosses_it() {
        let mut exact = std::io::Cursor::new(header_of(MAX_HEADER_BYTES));
        assert!(read_request(&mut exact).is_ok(), "正好 16 KiB 的头照常接受");
        for total in [MAX_HEADER_BYTES + 1, MAX_HEADER_BYTES + 1616, MAX_HEADER_BYTES + 4000, 3 * 4096 + 4100] {
            let mut request = std::io::Cursor::new(header_of(total));
            assert_eq!(read_request(&mut request).err(), Some(431), "{total} 字节的头必须拒绝");
        }
    }
}
