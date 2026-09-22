//! 宿主托管的本地控制端：定位本产品资源里的控制端程序、启动、就绪握手、失败回报与退出；
//! 以及登录会话材料在保险库里的保存、读取与清除。
//!
//! 边界：
//! - 可执行文件只来自本产品资源目录，不搜索 PATH，不依赖当前工作目录；
//! - 只管理自己 spawn 出来的那个子进程句柄，不按进程名结束任何进程，也不停外部配置的控制端；
//! - 首启凭据由宿主从系统安全随机源生成，经子进程 stdin 交付，只留在宿主内存里，不写日志、不给页面；
//! - 就绪 = 控制端 stdout 回报 ready 且 /health 的服务名、协议版本、实例引用都对得上。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::commands::{iso_from_millis, now_millis, parse_iso_millis};

pub const CONTROL_SERVICE: &str = "ai-steward-control";
pub const CONTROL_PROTOCOL: &str = "steward-control-1";
const READY_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_GRACE: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const SESSION_FILE: &str = "control-session.json";

pub fn control_executable_name() -> String {
    format!("{CONTROL_SERVICE}{}", std::env::consts::EXE_SUFFIX)
}

pub enum ControlMode {
    /// 本产品资源里的控制端，由宿主启动与退出。
    Managed { executable: PathBuf, state_dir: PathBuf, log_dir: PathBuf },
    /// 明确配置的外部控制端：只做握手，不启动、不停止。
    External { base_url: String, log_dir: PathBuf },
    /// 连控制端在哪都确定不了（例如没有产品资源目录）；如实回报，不合成地址。
    Unavailable { code: String, reason: String },
}

struct ManagedProcess {
    child: Child,
    stdin: Option<ChildStdin>,
}

struct HostLog {
    path: PathBuf,
    file: Option<std::fs::File>,
    failure: Option<String>,
}

impl HostLog {
    fn open(log_dir: &Path) -> HostLog {
        let stamp = iso_from_millis(now_millis()).replace(['-', ':', '.'], "");
        let path = log_dir.join(format!("host-control-{stamp}-{}.log", std::process::id()));
        let opened = std::fs::create_dir_all(log_dir)
            .and_then(|_| std::fs::OpenOptions::new().append(true).create_new(true).open(&path));
        match opened {
            Ok(file) => HostLog { path, file: Some(file), failure: None },
            Err(error) => HostLog { path, file: None, failure: Some(format!("宿主日志无法创建：{error}")) },
        }
    }

    fn write(&mut self, event: &str, fields: Value) {
        let line = format!("{}\n", json!({"at": iso_from_millis(now_millis()), "event": event, "fields": fields}));
        let failed = match self.file.as_mut() {
            Some(file) => file.write_all(line.as_bytes()).and_then(|_| file.flush()).err(),
            None => return,
        };
        if let Some(error) = failed {
            if self.failure.is_none() {
                self.failure = Some(format!("宿主日志写入失败：{error}"));
            }
        }
    }
}

pub enum Handshake {
    Ready { listen: String, instance_ref: String, protocol: String, log_file: Value, log_status: Value },
    Failed { code: String, reason: String, log_file: Value, exit_code: Value },
    Other,
}

/// 控制端 stdout 的一行：只认 ready / failed 两种事件，其余当普通输出。
pub fn parse_handshake(line: &str) -> Handshake {
    let value: Value = match serde_json::from_str(line.trim()) {
        Ok(value) => value,
        Err(_) => return Handshake::Other,
    };
    let text = |field: &str| value.get(field).and_then(Value::as_str).unwrap_or("").to_string();
    match value.get("event").and_then(Value::as_str) {
        Some("ready") => Handshake::Ready {
            listen: text("listen"),
            instance_ref: text("instance_ref"),
            protocol: text("protocol"),
            log_file: value.get("log_file").cloned().unwrap_or(Value::Null),
            log_status: value.get("log_status").cloned().unwrap_or(Value::Null),
        },
        Some("failed") => Handshake::Failed {
            code: text("code"),
            reason: text("reason"),
            log_file: value.get("log_file").cloned().unwrap_or(Value::Null),
            exit_code: value.get("exit_code").cloned().unwrap_or(Value::Null),
        },
        _ => Handshake::Other,
    }
}

pub struct HttpReply {
    pub status: u16,
    pub body: Value,
}

/// 回环 HTTP/1.1 请求，Connection: close，读到连接关闭为止。只给握手与首启转交用。
pub fn http_request(address: &str, method: &str, path: &str, headers: &[(&str, &str)], body: Option<&Value>) -> Result<HttpReply, String> {
    let mut stream = TcpStream::connect(address).map_err(|error| format!("无法连接控制端 {address}：{error}"))?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT)).map_err(|error| error.to_string())?;
    stream.set_write_timeout(Some(HTTP_TIMEOUT)).map_err(|error| error.to_string())?;
    let payload = body.map(Value::to_string).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n",
        payload.len()
    );
    if body.is_some() {
        request.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&payload);
    stream.write_all(request.as_bytes()).map_err(|error| format!("向控制端发送请求失败：{error}"))?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|error| format!("读取控制端响应失败：{error}"))?;
    parse_http_reply(&raw)
}

pub fn parse_http_reply(raw: &[u8]) -> Result<HttpReply, String> {
    let text = String::from_utf8_lossy(raw);
    let (head, rest) = text.split_once("\r\n\r\n").ok_or("控制端响应不完整")?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or("控制端响应缺少状态码")?;
    let chunked = head.lines().any(|line| {
        let lowered = line.to_ascii_lowercase();
        lowered.starts_with("transfer-encoding:") && lowered.contains("chunked")
    });
    let body_text = if chunked { decode_chunked(rest) } else { rest.to_string() };
    let body = if body_text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body_text).unwrap_or(Value::Null)
    };
    Ok(HttpReply { status, body })
}

fn decode_chunked(mut rest: &str) -> String {
    let mut output = String::new();
    while let Some((size_line, after)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if size == 0 || after.len() < size {
            break;
        }
        output.push_str(&after[..size]);
        rest = after[size..].trim_start_matches("\r\n");
    }
    output
}

fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("系统安全随机源不可用：{error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// 自由文本里 32 位以上连续的十六进制/Base64 串一律遮盖。
fn redact_line(text: &str) -> String {
    let mut output = String::new();
    let mut run = String::new();
    for ch in text.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '_' | '-') {
            run.push(ch);
            continue;
        }
        output.push_str(if run.len() >= 32 { "[REDACTED]" } else { &run });
        run.clear();
        output.push(ch);
    }
    output.pop();
    output
}

pub struct ControlSupervisor {
    mode: ControlMode,
    status: Mutex<Value>,
    address: Mutex<Option<String>>,
    setup_token: Mutex<Option<String>>,
    process: Mutex<Option<ManagedProcess>>,
    host_log: Mutex<Option<HostLog>>,
    stopping: AtomicBool,
}

impl ControlSupervisor {
    pub fn new(mode: ControlMode) -> Arc<ControlSupervisor> {
        let (mode_name, log_dir) = match &mode {
            ControlMode::Managed { log_dir, .. } => ("managed", Some(log_dir.clone())),
            ControlMode::External { log_dir, .. } => ("external", Some(log_dir.clone())),
            ControlMode::Unavailable { .. } => ("unavailable", None),
        };
        let initial = match &mode {
            ControlMode::Unavailable { code, reason } => json!({
                "status": "failed",
                "mode": mode_name,
                "error": {"code": code, "reason": reason}
            }),
            _ => json!({"status": "not_started", "mode": mode_name, "error": Value::Null}),
        };
        Arc::new(ControlSupervisor {
            mode,
            status: Mutex::new(initial),
            address: Mutex::new(None),
            setup_token: Mutex::new(None),
            process: Mutex::new(None),
            host_log: Mutex::new(log_dir.map(|dir| HostLog::open(&dir))),
            stopping: AtomicBool::new(false),
        })
    }

    /// 在后台线程里启动与握手，不阻塞窗口创建。页面在 starting 期间可以轮询 ControlStatus。
    pub fn start(self: &Arc<Self>) {
        if matches!(self.mode, ControlMode::Unavailable { .. }) {
            return;
        }
        self.update(json!({"status": "starting"}));
        let supervisor = Arc::clone(self);
        std::thread::spawn(move || match &supervisor.mode {
            ControlMode::Managed { executable, state_dir, .. } => supervisor.launch_managed(executable, state_dir),
            ControlMode::External { base_url, .. } => supervisor.connect_external(base_url),
            ControlMode::Unavailable { .. } => {}
        });
    }

    /// 给页面看的状态：不含首启凭据，也不含任何会话材料。
    pub fn status(&self) -> Value {
        let mut value = self.status.lock().map(|slot| slot.clone()).unwrap_or_else(|_| json!({"status": "failed"}));
        if let Ok(slot) = self.host_log.lock() {
            if let Some(log) = slot.as_ref() {
                value["host_log"] = json!(log.path.to_string_lossy());
                value["host_log_status"] = json!(if log.failure.is_none() { "ok" } else { "failed" });
            }
        }
        if let ControlMode::Managed { state_dir, .. } = &self.mode {
            value["log_dir"] = json!(state_dir.join("logs").to_string_lossy());
        }
        value
    }

    /// 只有握手通过才回报地址；失败或启动中一律 None，不回报占位地址。
    pub fn ready_base_url(&self) -> Option<String> {
        self.address.lock().ok().and_then(|slot| slot.clone()).map(|address| format!("http://{address}"))
    }

    fn log(&self, event: &str, fields: Value) {
        if let Ok(mut slot) = self.host_log.lock() {
            if let Some(log) = slot.as_mut() {
                log.write(event, fields);
            }
        }
    }

    fn update(&self, patch: Value) {
        if let (Ok(mut slot), Some(fields)) = (self.status.lock(), patch.as_object()) {
            if let Some(target) = slot.as_object_mut() {
                for (key, item) in fields {
                    target.insert(key.clone(), item.clone());
                }
            }
        }
    }

    fn fail(&self, code: &str, reason: &str, extra: Value) {
        self.log("control.failed", json!({"code": code, "reason": redact_line(reason), "extra": extra}));
        if let Ok(mut slot) = self.address.lock() {
            *slot = None;
        }
        self.update(json!({"status": "failed", "error": {"code": code, "reason": redact_line(reason)}, "failure": extra}));
    }

    fn launch_managed(self: &Arc<Self>, executable: &Path, state_dir: &Path) {
        self.log("control.launch.begin", json!({"executable": executable.to_string_lossy(), "state_dir": state_dir.to_string_lossy()}));
        if !executable.is_file() {
            return self.fail(
                "CONTROL_EXECUTABLE_MISSING",
                &format!("安装内容里没有控制端程序：{}", executable.to_string_lossy()),
                Value::Null,
            );
        }
        if let Err(error) = std::fs::create_dir_all(state_dir) {
            return self.fail("CONTROL_STATE_DIR_UNAVAILABLE", &format!("控制端状态目录无法创建：{error}"), Value::Null);
        }
        let token = match random_token() {
            Ok(token) => token,
            Err(reason) => return self.fail("CONTROL_RANDOM_UNAVAILABLE", &reason, Value::Null),
        };
        let mut command = Command::new(executable);
        command
            .arg("--state-dir")
            .arg(state_dir)
            .arg("--bootstrap-stdin")
            .current_dir(state_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => return self.fail("CONTROL_START_FAILED", &format!("控制端进程无法启动：{error}"), Value::Null),
        };
        self.log("control.process.spawned", json!({"pid": child.id()}));

        let mut stdin = child.stdin.take();
        let delivered = match stdin.as_mut() {
            Some(pipe) => writeln!(pipe, "{}", json!({"setup_token": token})).and_then(|_| pipe.flush()).is_ok(),
            None => false,
        };
        if let Some(stderr) = child.stderr.take() {
            let supervisor = Arc::clone(self);
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines() {
                    match line {
                        Ok(text) => supervisor.log("control.stderr", json!({"line": redact_line(&text)})),
                        Err(_) => break,
                    }
                }
            });
        }
        let (sender, receiver) = mpsc::channel::<String>();
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(text) = line else { break };
                    if sender.send(text).is_err() {
                        break;
                    }
                }
            });
        }
        if let Ok(mut slot) = self.process.lock() {
            *slot = Some(ManagedProcess { child, stdin });
        }
        if !delivered {
            self.stop_process();
            return self.fail("CONTROL_START_FAILED", "无法向控制端交付首启材料", Value::Null);
        }

        let deadline = Instant::now() + READY_TIMEOUT;
        let outcome = loop {
            match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line) => match parse_handshake(&line) {
                    Handshake::Other => self.log("control.stdout", json!({"line": redact_line(&line)})),
                    other => break Some(other),
                },
                Err(mpsc::RecvTimeoutError::Timeout) => break None,
                Err(mpsc::RecvTimeoutError::Disconnected) => break Some(Handshake::Other),
            }
        };
        match outcome {
            Some(Handshake::Ready { listen, instance_ref, protocol, log_file, log_status }) => {
                self.update(json!({"log_file": log_file, "log_status": log_status}));
                if protocol != CONTROL_PROTOCOL {
                    self.stop_process();
                    return self.fail(
                        "CONTROL_PROTOCOL_INCOMPATIBLE",
                        &format!("控制端协议版本 {protocol} 与宿主要求的 {CONTROL_PROTOCOL} 不一致"),
                        json!({"instance_ref": instance_ref}),
                    );
                }
                if let Err(reason) = self.verify_health(&listen, Some(instance_ref.as_str())) {
                    self.stop_process();
                    return self.fail("CONTROL_HANDSHAKE_FAILED", &reason, json!({"listen": listen}));
                }
                if let Ok(mut slot) = self.setup_token.lock() {
                    *slot = Some(token);
                }
                if let Ok(mut slot) = self.address.lock() {
                    *slot = Some(listen.clone());
                }
                self.update(json!({
                    "status": "ready",
                    "base_url": format!("http://{listen}"),
                    "instance_ref": instance_ref,
                    "protocol": protocol,
                    "error": Value::Null
                }));
                self.log("control.ready", json!({"listen": listen, "instance_ref": instance_ref}));
            }
            Some(Handshake::Failed { code, reason, log_file, exit_code }) => {
                let exit = self.wait_exit(STOP_GRACE);
                self.update(json!({"log_file": log_file}));
                return self.fail(&code, &reason, json!({"exit_code": exit.or(exit_code.as_i64().map(|value| value as i32))}));
            }
            Some(_) => {
                let exit = self.wait_exit(STOP_GRACE);
                return self.fail("CONTROL_START_FAILED", "控制端在就绪之前退出，详见宿主日志与控制端日志", json!({"exit_code": exit}));
            }
            None => {
                self.stop_process();
                return self.fail("CONTROL_START_TIMEOUT", "控制端在限定时间内没有就绪", Value::Null);
            }
        }

        // 就绪之后继续守着 stdout：管道关闭说明子进程退出了，除非是宿主自己在停，否则如实报失败。
        while let Ok(line) = receiver.recv() {
            self.log("control.stdout", json!({"line": redact_line(&line)}));
        }
        if !self.stopping.load(Ordering::SeqCst) {
            let exit = self.wait_exit(Duration::from_secs(2));
            self.fail("CONTROL_EXITED", "控制端进程意外退出，详见控制端日志", json!({"exit_code": exit}));
        }
    }

    fn connect_external(&self, base_url: &str) {
        self.log("control.external.begin", json!({"base_url": base_url}));
        let address = match base_url.strip_prefix("http://").map(|rest| rest.trim_end_matches('/')) {
            Some(address) if !address.is_empty() && !address.contains('/') => address.to_string(),
            _ => {
                return self.fail(
                    "CONTROL_EXTERNAL_UNSUPPORTED",
                    "外部控制端地址须为 http://主机:端口（本版只支持同机回环部署）",
                    json!({"base_url": base_url}),
                );
            }
        };
        match self.verify_health(&address, None) {
            Ok(instance_ref) => {
                if let Ok(mut slot) = self.address.lock() {
                    *slot = Some(address.clone());
                }
                self.update(json!({
                    "status": "ready",
                    "base_url": format!("http://{address}"),
                    "instance_ref": instance_ref,
                    "protocol": CONTROL_PROTOCOL,
                    "error": Value::Null
                }));
                self.log("control.ready", json!({"listen": address, "external": true}));
            }
            Err(reason) => self.fail("CONTROL_HANDSHAKE_FAILED", &reason, json!({"base_url": base_url})),
        }
    }

    /// 核对 /health 的服务名、协议版本与实例引用，返回实例引用。
    fn verify_health(&self, address: &str, expected_instance: Option<&str>) -> Result<String, String> {
        let reply = http_request(address, "GET", "/health", &[], None)?;
        if reply.status != 200 {
            return Err(format!("控制端健康检查返回 {}", reply.status));
        }
        let service = reply.body.get("service").and_then(Value::as_str);
        let protocol = reply.body.get("protocol").and_then(Value::as_str);
        let instance = reply.body.get("instance_ref").and_then(Value::as_str).unwrap_or("");
        if service != Some(CONTROL_SERVICE) {
            return Err("健康检查回报的不是本产品控制端".to_string());
        }
        if protocol != Some(CONTROL_PROTOCOL) {
            return Err(format!("控制端协议版本 {} 与宿主要求的 {CONTROL_PROTOCOL} 不一致", protocol.unwrap_or("未知")));
        }
        if let Some(expected) = expected_instance {
            if instance != expected {
                return Err("健康检查的实例引用与启动握手不一致，端口上可能不是本次启动的控制端".to_string());
            }
        }
        Ok(instance.to_string())
    }

    fn wait_exit(&self, grace: Duration) -> Option<i32> {
        let deadline = Instant::now() + grace;
        loop {
            let polled = match self.process.lock() {
                Ok(mut slot) => match slot.as_mut() {
                    Some(process) => process.child.try_wait(),
                    None => return None,
                },
                Err(_) => return None,
            };
            match polled {
                Ok(Some(status)) => return status.code(),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                _ => return None,
            }
        }
    }

    /// 只结束自己启动的那个子进程：先关 stdin 让它优雅退出，宽限期后仍在才 kill 这个句柄。
    fn stop_process(&self) {
        let taken = self.process.lock().ok().and_then(|mut slot| slot.take());
        let mut process = match taken {
            Some(process) => process,
            None => return,
        };
        drop(process.stdin.take());
        let deadline = Instant::now() + STOP_GRACE;
        let exited = loop {
            match process.child.try_wait() {
                Ok(Some(status)) => break Some(status.code()),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                _ => break None,
            }
        };
        match exited {
            Some(code) => self.log("control.process.stopped", json!({"exit_code": code})),
            None => {
                let killed = process.child.kill().is_ok();
                let _ = process.child.wait();
                self.log("control.process.killed", json!({"killed": killed}));
            }
        }
    }

    /// 应用真正退出时调用。外部控制端不受影响。
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Ok(mut slot) = self.address.lock() {
            *slot = None;
        }
        if let Ok(mut slot) = self.setup_token.lock() {
            *slot = None;
        }
        if matches!(self.mode, ControlMode::Managed { .. }) {
            self.stop_process();
            self.update(json!({"status": "stopped"}));
        }
    }

    /// 首启提交：宿主附上本次启动交付给控制端的一次性凭据后转交。凭据不出宿主。
    pub fn setup_admin(&self, username: &str, password: &str) -> Result<Value, String> {
        let address = match self.address.lock().ok().and_then(|slot| slot.clone()) {
            Some(address) => address,
            None => return Ok(json!({"ok": false, "code": "CONTROL_NOT_READY", "reason": "控制端尚未就绪，暂时不能完成首启"})),
        };
        if !matches!(self.mode, ControlMode::Managed { .. }) {
            return Ok(json!({
                "ok": false,
                "code": "CONTROL_SETUP_NOT_MANAGED",
                "reason": "外部控制端的首次初始化须在控制端所在机器上用它自己的首启凭据完成"
            }));
        }
        let token = match self.setup_token.lock().ok().and_then(|slot| slot.clone()) {
            Some(token) => token,
            None => {
                return Ok(json!({
                    "ok": false,
                    "code": "CONTROL_SETUP_TOKEN_UNAVAILABLE",
                    "reason": "本次启动的首启凭据已经用过；如控制端仍未初始化，请重启应用"
                }));
            }
        };
        let reply = match http_request(
            &address,
            "POST",
            "/api/setup/admin",
            &[("X-Steward-Setup-Token", token.as_str())],
            Some(&json!({"username": username, "password": password})),
        ) {
            Ok(reply) => reply,
            Err(reason) => return Ok(json!({"ok": false, "code": "CONTROL_UNREACHABLE", "reason": reason})),
        };
        let request_ref = reply.body.get("request_ref").cloned().unwrap_or(Value::Null);
        self.log("control.setup.submitted", json!({"status": reply.status, "request_ref": request_ref}));
        if reply.status == 201 || reply.status == 409 {
            if let Ok(mut slot) = self.setup_token.lock() {
                *slot = None;
            }
        }
        if reply.status == 201 {
            return Ok(json!({"ok": true, "status": 201, "user": reply.body.get("user").cloned().unwrap_or(Value::Null)}));
        }
        Ok(json!({
            "ok": false,
            "status": reply.status,
            "code": reply.body.get("code").cloned().unwrap_or_else(|| json!("CONTROL_SETUP_FAILED")),
            "reason": reply.body.get("reason").cloned().unwrap_or_else(|| json!("控制端拒绝了首启请求")),
            "request_ref": request_ref
        }))
    }
}

fn session_path(vault_root: &Path) -> PathBuf {
    vault_root.join(SESSION_FILE)
}

/// 读回保存的会话；过期或文件损坏就删掉并回报没有会话，由页面走登录。
pub fn session_load(vault_root: &Path, now_ms: i64) -> Result<Value, String> {
    let path = session_path(vault_root);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(json!({"ok": true, "session": Value::Null})),
        Err(error) => return Err(format!("NATIVE_IO_FAILED: {error}")),
    };
    let parsed: Option<Value> = serde_json::from_str(&text).ok();
    let session = parsed.as_ref().and_then(|value| {
        let token = value.get("access_token").and_then(Value::as_str)?;
        let expires_at = value.get("expires_at").and_then(Value::as_str)?;
        let user_ref = value.get("user_ref").and_then(Value::as_str)?;
        Some((token.to_string(), expires_at.to_string(), user_ref.to_string()))
    });
    match session {
        None => {
            let _ = std::fs::remove_file(&path);
            Ok(json!({"ok": true, "session": Value::Null, "discarded": "SESSION_FILE_INVALID"}))
        }
        Some((_, expires_at, _)) if parse_iso_millis(&expires_at).map(|deadline| deadline <= now_ms).unwrap_or(true) => {
            let _ = std::fs::remove_file(&path);
            Ok(json!({"ok": true, "session": Value::Null, "expired": true}))
        }
        Some((access_token, expires_at, user_ref)) => Ok(json!({
            "ok": true,
            "session": {"access_token": access_token, "expires_at": expires_at, "user_ref": user_ref}
        })),
    }
}

pub fn session_save(vault_root: &Path, payload: &Value, now_ms: i64) -> Result<Value, String> {
    let field = |name: &str| payload.get(name).and_then(Value::as_str).unwrap_or("").to_string();
    let access_token = field("access_token");
    let expires_at = field("expires_at");
    let user_ref = field("user_ref");
    if access_token.len() < 16 || access_token.len() > 512 || access_token.chars().any(char::is_whitespace) {
        return Err("NATIVE_PAYLOAD_INVALID: access_token is malformed".into());
    }
    if user_ref.is_empty() || user_ref.len() > 128 {
        return Err("NATIVE_PAYLOAD_INVALID: user_ref is malformed".into());
    }
    match parse_iso_millis(&expires_at) {
        Some(deadline) if deadline > now_ms => {}
        _ => return Err("NATIVE_PAYLOAD_INVALID: expires_at must be a future instant".into()),
    }
    std::fs::create_dir_all(vault_root).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let path = session_path(vault_root);
    let staging = vault_root.join(format!("{SESSION_FILE}.tmp"));
    let document = json!({"access_token": access_token, "expires_at": expires_at, "user_ref": user_ref, "saved_at": iso_from_millis(now_ms)});
    std::fs::write(&staging, document.to_string()).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    std::fs::rename(&staging, &path).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(json!({"ok": true, "expires_at": expires_at, "user_ref": user_ref}))
}

pub fn session_clear(vault_root: &Path) -> Result<Value, String> {
    let path = session_path(vault_root);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(json!({"ok": true, "cleared": true})),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({"ok": true, "cleared": false})),
        Err(error) => Err(format!("NATIVE_IO_FAILED: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("ai-steward-host-tests")
            .join(format!("{label}-{}-{}", std::process::id(), now_millis()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn handshake_lines_are_classified() {
        match parse_handshake(r#"{"event":"ready","listen":"127.0.0.1:50123","instance_ref":"ctl-1","protocol":"steward-control-1"}"#) {
            Handshake::Ready { listen, protocol, .. } => {
                assert_eq!(listen, "127.0.0.1:50123");
                assert_eq!(protocol, CONTROL_PROTOCOL);
            }
            _ => panic!("ready 行没有被识别"),
        }
        assert!(matches!(
            parse_handshake(r#"{"event":"failed","code":"CONTROL_STORE_CORRUPT","reason":"x","exit_code":3}"#),
            Handshake::Failed { .. }
        ));
        assert!(matches!(parse_handshake("plain text"), Handshake::Other));
    }

    #[test]
    fn http_replies_are_parsed_including_chunked_bodies() {
        let plain = parse_http_reply(b"HTTP/1.1 201 Created\r\ncontent-length: 17\r\n\r\n{\"initialized\":1}").unwrap();
        assert_eq!(plain.status, 201);
        assert_eq!(plain.body["initialized"], 1);
        let chunked = parse_http_reply(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n2\r\n1}\r\n0\r\n\r\n").unwrap();
        assert_eq!(chunked.body["a"], 1);
        let empty = parse_http_reply(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(empty.status, 204);
        assert!(empty.body.is_null());
    }

    #[test]
    fn a_missing_executable_fails_with_a_logged_code() {
        let root = scratch("missing-exe");
        let supervisor = ControlSupervisor::new(ControlMode::Managed {
            executable: root.join("control").join(control_executable_name()),
            state_dir: root.join("control-state"),
            log_dir: root.join("logs"),
        });
        supervisor.launch_managed(&root.join("control").join(control_executable_name()), &root.join("control-state"));
        let status = supervisor.status();
        assert_eq!(status["status"], "failed");
        assert_eq!(status["error"]["code"], "CONTROL_EXECUTABLE_MISSING");
        assert!(supervisor.ready_base_url().is_none(), "失败时不回报地址");
        let host_log = status["host_log"].as_str().unwrap();
        assert!(std::fs::read_to_string(host_log).unwrap().contains("CONTROL_EXECUTABLE_MISSING"));
    }

    #[test]
    fn unavailable_mode_reports_its_reason_and_setup_is_refused() {
        let supervisor = ControlSupervisor::new(ControlMode::Unavailable {
            code: "CONTROL_NOT_CONFIGURED".into(),
            reason: "没有产品资源目录".into(),
        });
        supervisor.start();
        assert_eq!(supervisor.status()["error"]["code"], "CONTROL_NOT_CONFIGURED");
        let refused = supervisor.setup_admin("admin", "synthetic-Admin-Passw0rd").unwrap();
        assert_eq!(refused["code"], "CONTROL_NOT_READY");
    }

    #[test]
    fn sessions_round_trip_and_expire() {
        let vault = scratch("session");
        let now = 1_789_000_000_000;
        assert!(session_load(&vault, now).unwrap()["session"].is_null());
        let expires = iso_from_millis(now + 60_000);
        session_save(&vault, &json!({"access_token": "a".repeat(64), "expires_at": expires, "user_ref": "usr-1"}), now).unwrap();
        assert_eq!(session_load(&vault, now).unwrap()["session"]["user_ref"], "usr-1");
        assert!(session_save(&vault, &json!({"access_token": "short", "expires_at": expires, "user_ref": "usr-1"}), now).is_err());
        let expired = session_load(&vault, now + 60_000).unwrap();
        assert!(expired["session"].is_null());
        assert_eq!(expired["expired"], true);
        assert!(!session_path(&vault).exists(), "过期会话被删除");
        assert_eq!(session_clear(&vault).unwrap()["cleared"], false);
    }

    #[test]
    fn redaction_masks_long_runs() {
        assert_eq!(redact_line(&format!("token {} end", "ab".repeat(20))), "token [REDACTED] end");
    }
}
