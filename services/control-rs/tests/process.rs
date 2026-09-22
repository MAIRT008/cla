//! 可执行程序级测试：真的启动 ai-steward-control，只绑定回环端口。
//! 覆盖启动失败的三类现场（参数/库/端口）各自非零退出并留下日志，以及托管模式的就绪握手与优雅退出。
//!
//! 本机不运行进程和监听器，这些用例已写未运行，只在异机验收时执行。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

const SETUP_TOKEN: &str = "5e7a0c0ffee00000000000000000000000000000000000000000000000000002";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_ai-steward-control")
}

fn fresh_state_dir(label: &str) -> PathBuf {
    let unique = format!(
        "{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    );
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("control-rs-process").join(unique);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn first_json_line(stdout: &[u8]) -> Value {
    let text = String::from_utf8_lossy(stdout);
    let line = text.lines().find(|line| line.trim_start().starts_with('{')).expect("stdout 没有握手行");
    serde_json::from_str(line).unwrap()
}

fn log_text(state_dir: &Path) -> String {
    let mut combined = String::new();
    for entry in std::fs::read_dir(state_dir.join("logs")).expect("必须留下日志目录") {
        combined.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap());
    }
    combined
}

#[test]
fn missing_state_dir_exits_with_the_config_code() {
    let output = Command::new(binary()).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let line = first_json_line(&output.stdout);
    assert_eq!(line["event"], "failed");
    assert_eq!(line["code"], "CONTROL_CONFIG_INVALID");
}

#[test]
fn a_missing_config_file_exits_non_zero_and_is_logged() {
    let dir = fresh_state_dir("missing-config");
    let output = Command::new(binary())
        .arg("--state-dir")
        .arg(&dir)
        .arg("--config")
        .arg(dir.join("does-not-exist.json"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(first_json_line(&output.stdout)["code"], "CONTROL_CONFIG_INVALID");
    let log = log_text(&dir);
    assert!(log.contains("startup.begin") && log.contains("CONTROL_CONFIG_INVALID"));
}

#[test]
fn a_corrupt_database_exits_non_zero_and_is_logged() {
    let dir = fresh_state_dir("corrupt");
    let garbage = b"synthetic garbage that is not a sqlite file".repeat(128);
    std::fs::write(dir.join("control.sqlite3"), &garbage).unwrap();
    let output = Command::new(binary()).arg("--state-dir").arg(&dir).output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    let line = first_json_line(&output.stdout);
    assert_eq!(line["stage"], "store");
    assert!(line["log_file"].as_str().unwrap().contains("logs"));
    assert!(log_text(&dir).contains("store.open.failed"));
    assert_eq!(std::fs::read(dir.join("control.sqlite3")).unwrap(), garbage, "损坏的库原样保留");
}

#[test]
fn an_occupied_port_exits_non_zero_and_is_logged() {
    let dir = fresh_state_dir("port-conflict");
    let holder = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = holder.local_addr().unwrap().port();
    let config = dir.join("control.json");
    std::fs::write(&config, format!("{{\"bind\": \"127.0.0.1:{port}\"}}")).unwrap();
    let output = Command::new(binary())
        .arg("--state-dir")
        .arg(&dir)
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    drop(holder);
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(first_json_line(&output.stdout)["code"], "CONTROL_BIND_FAILED");
    assert!(log_text(&dir).contains("CONTROL_BIND_FAILED"));
}

#[test]
fn a_non_loopback_bind_is_refused() {
    let dir = fresh_state_dir("public-bind");
    let output = Command::new(binary())
        .arg("--state-dir")
        .arg(&dir)
        .arg("--bind")
        .arg("0.0.0.0:0")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(first_json_line(&output.stdout)["code"], "CONTROL_BIND_NOT_LOOPBACK");
}

#[test]
fn managed_start_hands_shakes_serves_health_and_stops_when_the_host_closes_stdin() {
    let dir = fresh_state_dir("managed");
    let mut child = Command::new(binary())
        .arg("--state-dir")
        .arg(&dir)
        .arg("--bootstrap-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{{\"setup_token\": \"{SETUP_TOKEN}\"}}").unwrap();
    stdin.flush().unwrap();

    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let ready: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(ready["event"], "ready", "{line}");
    assert_eq!(ready["protocol"], "steward-control-1");
    let listen = ready["listen"].as_str().unwrap().to_string();
    assert!(listen.starts_with("127.0.0.1:"));
    assert!(!line.contains(SETUP_TOKEN), "握手行不得回显首启凭据");

    let mut stream = TcpStream::connect(&listen).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(stream, "GET /health HTTP/1.1\r\nHost: {listen}\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    let health: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(health["instance_ref"], ready["instance_ref"]);

    drop(stdin);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0), "宿主关闭 stdin 后优雅退出");
    let log = log_text(&dir);
    for event in ["startup.begin", "config.loaded", "store.open.ok", "setup.state", "listen.bound", "shutdown.requested", "process.exit"] {
        assert!(log.contains(event), "日志缺少 {event}");
    }
    assert!(!log.contains(SETUP_TOKEN));
    assert!(!dir.join("setup-token").exists(), "托管模式不把首启凭据写成文件");
}

#[test]
fn standalone_start_writes_a_one_time_setup_token_file() {
    let dir = fresh_state_dir("standalone");
    let mut child = Command::new(binary())
        .arg("--state-dir")
        .arg(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let ready: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(ready["event"], "ready", "{line}");
    let token = std::fs::read_to_string(dir.join("setup-token")).unwrap();
    assert_eq!(token.trim().len(), 64);
    assert!(!log_text(&dir).contains(token.trim()), "日志只记凭据文件位置，不记内容");
    child.kill().unwrap();
    let _ = child.wait();
}
