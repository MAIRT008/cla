//! 集成测试共用夹具。全部合成：账号、密码、模型 Key、Remnawave 令牌与订阅都是测试值；
//! 出站 HTTP 只进 `ScriptedTransport`，不开套接字；秘密保护用确定性实现，不调用 DPAPI。
//!
//! 本机没有 cargo/rustc，这些夹具与用例已写未编译、未运行。

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use ai_steward_control::config::ControlConfig;
use ai_steward_control::http::{CancelToken, HttpRequest, HttpResponse, HttpTransport, TransportError, TransportFailure};
use ai_steward_control::logging::Logger;
use ai_steward_control::router::{handle, ApiRequest, ApiResponse, SETUP_TOKEN_HEADER};
use ai_steward_control::secrets::SecretProtector;
use ai_steward_control::{random_hex, sha256_hex, App, ControlError, Dependencies};
use serde_json::{json, Value};

pub const SETUP_TOKEN: &str = "5e7a0c0ffee00000000000000000000000000000000000000000000000000003";
pub const ADMIN_PASSWORD: &str = "synthetic-Admin-Passw0rd";
pub const MEMBER_PASSWORD: &str = "synthetic-Member-Passw0rd";
pub const START_MS: i64 = 1_789_000_000_000;
pub const MODEL_KEY: &str = "sk-synthetic-model-key-000111222";
pub const REMNAWAVE_TOKEN: &str = "synthetic-remnawave-admin-token";
pub const REMNAWAVE_URL: &str = "https://remnawave.synthetic.invalid";

pub fn fresh_state_dir(label: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("control-rs-rc2")
        .join(format!("{label}-{}", random_hex(6).unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 确定性秘密保护：按用途派生的密钥流异或，外加用途与明文的完整性标签。
/// 只用于测试注入，证明「库里只有密文、跨用途与篡改都读不出」；它不是产品保护方式。
pub struct TestProtector;

fn keystream(purpose: &str, length: usize) -> Vec<u8> {
    let mut stream = Vec::with_capacity(length);
    let mut counter = 0u32;
    while stream.len() < length {
        let block = sha256_hex(format!("{purpose}#{counter}").as_bytes());
        stream.extend(block.as_bytes());
        counter += 1;
    }
    stream.truncate(length);
    stream
}

impl SecretProtector for TestProtector {
    fn kind(&self) -> &'static str {
        "test-deterministic"
    }

    fn protect(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, ControlError> {
        let mut output = b"TP1".to_vec();
        output.extend(sha256_hex(&[purpose.as_bytes(), plaintext].concat()).as_bytes()[..16].iter());
        output.extend(plaintext.iter().zip(keystream(purpose, plaintext.len())).map(|(byte, key)| byte ^ key));
        Ok(output)
    }

    fn unprotect(&self, ciphertext: &[u8], purpose: &str) -> Result<Vec<u8>, ControlError> {
        if ciphertext.len() < 19 || &ciphertext[..3] != b"TP1" {
            return Err(ControlError::new("CONTROL_SECRET_UNREADABLE", "not a test ciphertext"));
        }
        let body = &ciphertext[19..];
        let plaintext: Vec<u8> = body.iter().zip(keystream(purpose, body.len())).map(|(byte, key)| byte ^ key).collect();
        let tag = sha256_hex(&[purpose.as_bytes(), plaintext.as_slice()].concat());
        if tag.as_bytes()[..16] != ciphertext[3..19] {
            return Err(ControlError::new("CONTROL_SECRET_UNREADABLE", "tag mismatch"));
        }
        Ok(plaintext)
    }
}

#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub url: String,
    pub authorization: Option<String>,
    pub body: Option<Value>,
}

type Handler = Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync>;

/// 记录每一次出站请求，并交给当前脚本回答。默认脚本回「不允许出站」。
pub struct ScriptedTransport {
    pub calls: Mutex<Vec<Recorded>>,
    handler: Mutex<Handler>,
}

impl ScriptedTransport {
    pub fn new() -> Arc<ScriptedTransport> {
        Arc::new(ScriptedTransport {
            calls: Mutex::new(Vec::new()),
            handler: Mutex::new(Box::new(|_: &HttpRequest| Err(TransportError::new(TransportFailure::Connect, "offline test: no script")))),
        })
    }

    pub fn script(&self, handler: impl Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync + 'static) {
        *self.handler.lock().unwrap() = Box::new(handler);
    }

    pub fn calls(&self) -> Vec<Recorded> {
        self.calls.lock().unwrap().clone()
    }
}

impl HttpTransport for ScriptedTransport {
    fn send(&self, request: &HttpRequest, cancel: &CancelToken) -> Result<HttpResponse, TransportError> {
        self.calls.lock().unwrap().push(Recorded {
            method: request.method.clone(),
            url: request.url.clone(),
            authorization: request.header_value("authorization").map(str::to_string),
            body: request.body.as_ref().and_then(|bytes| serde_json::from_slice(bytes).ok()),
        });
        if cancel.is_cancelled() {
            return Err(TransportError::new(TransportFailure::Cancelled, "cancelled"));
        }
        let handler = self.handler.lock().unwrap();
        (*handler)(request)
    }
}

pub fn json_response(status: u16, body: Value) -> Result<HttpResponse, TransportError> {
    Ok(HttpResponse { status, content_type: Some("application/json".to_string()), body: body.to_string().into_bytes() })
}

pub fn text_response(status: u16, body: &str) -> Result<HttpResponse, TransportError> {
    Ok(HttpResponse { status, content_type: Some("text/plain".to_string()), body: body.as_bytes().to_vec() })
}

pub struct Harness {
    pub app: App,
    pub now: Arc<AtomicI64>,
    pub dir: PathBuf,
    pub transport: Arc<ScriptedTransport>,
}

pub fn open_app(dir: &Path, now: &Arc<AtomicI64>, transport: &Arc<ScriptedTransport>) -> Result<App, ControlError> {
    let config = ControlConfig::for_state_dir(dir.to_path_buf());
    let logger = Arc::new(Logger::create(&config.log_dir(), &format!("ctl-test-{}", random_hex(4).unwrap())));
    let source = now.clone();
    let transport: Arc<dyn HttpTransport> = transport.clone();
    App::open_with(
        config,
        logger,
        Box::new(move || source.load(Ordering::SeqCst)),
        Dependencies { protector: Box::new(TestProtector), transport },
    )
}

impl Harness {
    pub fn new(label: &str) -> Harness {
        let dir = fresh_state_dir(label);
        let now = Arc::new(AtomicI64::new(START_MS));
        let transport = ScriptedTransport::new();
        let app = open_app(&dir, &now, &transport).unwrap();
        app.set_setup_token(SETUP_TOKEN);
        Harness { app, now, dir, transport }
    }

    /// 同一状态目录重新打开（模拟重启），沿用同一个时钟与传输。
    pub fn reopen(self) -> Harness {
        let Harness { app, now, dir, transport } = self;
        drop(app);
        let app = open_app(&dir, &now, &transport).unwrap();
        Harness { app, now, dir, transport }
    }

    pub fn advance(&self, millis: i64) {
        self.now.fetch_add(millis, Ordering::SeqCst);
    }

    pub fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.dir.join("control.sqlite3")).unwrap()
    }

    pub fn call(&self, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> ApiResponse {
        let mut request = ApiRequest::new(method, path);
        if let Some(token) = token {
            request = request.header("authorization", &format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        handle(&self.app, &request)
    }

    pub fn setup_admin(&self) -> String {
        let created = handle(
            &self.app,
            &ApiRequest::new("POST", "/api/setup/admin")
                .header(SETUP_TOKEN_HEADER, SETUP_TOKEN)
                .json(&json!({"username": "admin", "password": ADMIN_PASSWORD})),
        );
        assert_eq!(created.status, 201, "{:?}", body(&created));
        self.login("admin", ADMIN_PASSWORD)
    }

    pub fn login(&self, username: &str, password: &str) -> String {
        let response = self.call("POST", "/api/auth/login", None, Some(json!({"username": username, "password": password})));
        assert_eq!(response.status, 200, "{:?}", body(&response));
        body(&response)["access_token"].as_str().unwrap().to_string()
    }

    /// 管理员经 HTTP 路由建普通用户，返回 (user_ref, 该用户的会话令牌)。
    pub fn create_member(&self, admin: &str, username: &str) -> (String, String) {
        let created = self.call("POST", "/api/admin/users", Some(admin), Some(json!({"username": username, "password": MEMBER_PASSWORD})));
        assert_eq!(created.status, 201, "{:?}", body(&created));
        let user_ref = body(&created)["user"]["user_ref"].as_str().unwrap().to_string();
        (user_ref, self.login(username, MEMBER_PASSWORD))
    }

    pub fn log_text(&self) -> String {
        std::fs::read_to_string(self.app.logger.path()).unwrap_or_default()
    }

    pub fn database_bytes(&self) -> Vec<u8> {
        let mut bytes = std::fs::read(self.dir.join("control.sqlite3")).unwrap_or_default();
        if let Ok(wal) = std::fs::read(self.dir.join("control.sqlite3-wal")) {
            bytes.extend(wal);
        }
        bytes
    }
}

pub fn body(response: &ApiResponse) -> Value {
    response.json_body().unwrap_or(Value::Null)
}

pub fn contains_bytes(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle.as_bytes())
}

// ---------------------------------------------------------------- 资源、模板、分配的合成数据

pub fn template_body(template_id: &str, version: &str, protected: &str) -> Value {
    json!({
        "template_id": template_id,
        "published": true,
        "version": version,
        "template": {
            "version": version,
            "claude_domains": ["claude.ai", "anthropic.com"],
            "claude_processes": ["claude.exe"],
            "managed_browser_processes": [],
            "protected_process_paths": [protected],
            "lan_cidrs": ["192.168.0.0/16"],
            "control_plane": {"login": [{"host": "login.synthetic.invalid", "outbound": "DIRECT"}]},
            "udp_policy": "REJECT",
            "ipv6_policy": "FOLLOW",
            "dns": {"enable": true, "nameserver": ["https://dns.synthetic.invalid/dns-query"]},
        },
    })
}

pub fn put_resource(h: &Harness, admin: &str, id: &str, role: &str, host: &str) {
    let saved = h.call(
        "PUT",
        "/api/admin/resources",
        Some(admin),
        Some(json!({"resource_id": id, "role": role, "host": host, "port": 1080, "sharing": if role == "front" { "shared" } else { "dedicated" }})),
    );
    assert_eq!(saved.status, 200, "{:?}", body(&saved));
}

/// 建资源、模板、候选分配并发布；返回发布结果。
pub fn publish_single(h: &Harness, admin: &str, user_ref: &str, a_resource: &str) -> Value {
    put_resource(h, admin, "res-front", "front", "front.synthetic.invalid");
    put_resource(h, admin, a_resource, "A", &format!("{a_resource}.synthetic.invalid"));
    let template = h.call("PUT", "/api/admin/templates", Some(admin), Some(template_body("managed", "template-v1", "C:/Program Files/Claude/claude.exe")));
    assert_eq!(template.status, 200, "{:?}", body(&template));
    let saved = h.call(
        "POST",
        "/api/admin/assignments",
        Some(admin),
        Some(json!({
            "userRef": user_ref,
            "accountClass": "free",
            "allowedModes": ["daily_single_ip"],
            "resources": ["res-front", a_resource],
            "roles": {"A": a_resource},
            "validUntil": "2027-01-01T00:00:00.000Z",
            "templateId": "managed",
        })),
    );
    assert_eq!(saved.status, 200, "{:?}", body(&saved));
    let published = h.call("POST", "/api/admin/assignments/publish", Some(admin), Some(json!({"userRef": user_ref})));
    assert_eq!(published.status, 200, "{:?}", body(&published));
    body(&published)
}

// ---------------------------------------------------------------- Remnawave 合成权威

#[derive(Clone, Debug)]
pub struct SimUser {
    pub id: i64,
    pub username: String,
    pub status: String,
    pub limit: i64,
    pub used: i64,
    pub strategy: String,
    pub expire_at: String,
    pub sub_revoked_at: Option<String>,
}

#[derive(Default)]
pub struct AuthorityState {
    pub next_id: i64,
    pub users: HashMap<i64, SimUser>,
    pub backend_available: bool,
    pub pool_exhausted: bool,
    pub drop_disable_response: bool,
}

/// Remnawave 后端的合成替身：只实现本服务调用的七条路由，响应形状取自 fixtures/control/authoritySim.mjs。
pub struct AuthoritySim {
    pub state: Mutex<AuthorityState>,
}

impl AuthoritySim {
    pub fn new() -> Arc<AuthoritySim> {
        Arc::new(AuthoritySim { state: Mutex::new(AuthorityState { next_id: 101, backend_available: true, ..AuthorityState::default() }) })
    }

    fn user_json(user: &SimUser) -> Value {
        json!({"response": {
            "id": user.id,
            "username": user.username,
            "status": user.status,
            "trafficLimitBytes": user.limit,
            "trafficLimitStrategy": user.strategy,
            "expireAt": user.expire_at,
            "subRevokedAt": user.sub_revoked_at,
            "vlessUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "trojanPassword": "synthetic-trojan-pass",
            "subscriptionUrl": format!("https://sub.synthetic.invalid/{}", user.username),
            "activeInternalSquads": [],
            "userTraffic": {"usedTrafficBytes": user.used, "lifetimeUsedTrafficBytes": user.used},
        }})
    }

    pub fn consume(&self, id: i64, bytes: i64) {
        let mut state = self.state.lock().unwrap();
        if let Some(user) = state.users.get_mut(&id) {
            user.used += bytes;
            if user.limit > 0 && user.used >= user.limit && user.status == "ACTIVE" {
                user.status = "LIMITED".to_string();
            }
        }
    }

    pub fn respond(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let expected = format!("Bearer {REMNAWAVE_TOKEN}");
        if request.header_value("authorization") != Some(expected.as_str()) {
            return json_response(401, json!({"message": "Unauthorized", "errorCode": "A001"}));
        }
        let mut state = self.state.lock().unwrap();
        if !state.backend_available {
            return json_response(503, json!({"message": "backend unavailable", "errorCode": "E500"}));
        }
        let path = request.url.strip_prefix(REMNAWAVE_URL).unwrap_or("").to_string();
        let body: Value = request.body.as_ref().and_then(|bytes| serde_json::from_slice(bytes).ok()).unwrap_or(Value::Null);
        let id_of = |prefix: &str, suffix: &str| path.strip_prefix(prefix).and_then(|rest| rest.strip_suffix(suffix)).and_then(|text| text.parse::<i64>().ok());
        match request.method.as_str() {
            "POST" if path == "/api/users" => {
                let username = body["username"].as_str().unwrap_or("").to_string();
                if state.users.values().any(|user| user.username == username) {
                    return json_response(409, json!({"message": "User already exists", "errorCode": "A019"}));
                }
                let id = state.next_id;
                state.next_id += 1;
                let user = SimUser {
                    id,
                    username,
                    status: "ACTIVE".to_string(),
                    limit: body["trafficLimitBytes"].as_i64().unwrap_or(0),
                    used: 0,
                    strategy: body["trafficLimitStrategy"].as_str().unwrap_or("NO_RESET").to_string(),
                    expire_at: body["expireAt"].as_str().unwrap_or("").to_string(),
                    sub_revoked_at: None,
                };
                state.users.insert(id, user.clone());
                json_response(201, AuthoritySim::user_json(&user))
            }
            "PATCH" if path == "/api/users" => {
                let id = body["id"].as_i64().unwrap_or(0);
                match state.users.get_mut(&id) {
                    Some(user) => {
                        if let Some(limit) = body["trafficLimitBytes"].as_i64() {
                            user.limit = limit;
                            if user.status == "LIMITED" && user.used < limit {
                                user.status = "ACTIVE".to_string();
                            }
                        }
                        json_response(200, AuthoritySim::user_json(user))
                    }
                    None => json_response(404, json!({"message": "User not found", "errorCode": "A025"})),
                }
            }
            "GET" if path.starts_with("/api/users/by-username/") => {
                let username = path.trim_start_matches("/api/users/by-username/").to_string();
                match state.users.values().find(|user| user.username == username) {
                    Some(user) => json_response(200, AuthoritySim::user_json(user)),
                    None => json_response(404, json!({"message": "User not found", "errorCode": "A025"})),
                }
            }
            "POST" if path.ends_with("/actions/disable") => {
                let id = id_of("/api/users/", "/actions/disable").unwrap_or(0);
                let drop_response = state.drop_disable_response;
                match state.users.get_mut(&id) {
                    Some(user) => {
                        user.status = "DISABLED".to_string();
                        if drop_response {
                            return Err(TransportError::new(TransportFailure::Connect, "synthetic lost response after disable"));
                        }
                        json_response(200, AuthoritySim::user_json(user))
                    }
                    None => json_response(404, json!({"message": "User not found", "errorCode": "A025"})),
                }
            }
            "POST" if path.ends_with("/actions/enable") => {
                let id = id_of("/api/users/", "/actions/enable").unwrap_or(0);
                match state.users.get_mut(&id) {
                    Some(user) => {
                        user.status = "ACTIVE".to_string();
                        json_response(200, AuthoritySim::user_json(user))
                    }
                    None => json_response(404, json!({"message": "User not found", "errorCode": "A025"})),
                }
            }
            "GET" if path == "/api/nodes" => {
                let exhausted = state.pool_exhausted;
                json_response(200, json!({"response": [{
                    "uuid": "11111111-1111-4111-8111-111111111111", "id": 1, "name": "synthetic-node",
                    "isConnected": true, "isDisabled": false, "isTrafficTrackingActive": true,
                    "trafficLimitBytes": if exhausted { 1 } else { 0 }, "trafficUsedBytes": if exhausted { 1 } else { 0 },
                }]}))
            }
            "GET" if path.starts_with("/api/users/") => {
                let id = id_of("/api/users/", "").unwrap_or(0);
                match state.users.get(&id) {
                    Some(user) => json_response(200, AuthoritySim::user_json(user)),
                    None => json_response(404, json!({"message": "User not found", "errorCode": "A025"})),
                }
            }
            _ => json_response(404, json!({"message": "Not Found", "errorCode": "A404"})),
        }
    }
}

/// 把合成权威接到脚本化传输上，并由管理员配置配额适配（地址与令牌经加密保存）。
pub fn attach_authority(h: &Harness, admin: &str) -> Arc<AuthoritySim> {
    let authority = AuthoritySim::new();
    let responder = authority.clone();
    h.transport.script(move |request| responder.respond(request));
    let saved = h.call(
        "PUT",
        "/api/admin/quota-adapter",
        Some(admin),
        Some(json!({"kind": "remnawave", "enabled": true, "base_url": REMNAWAVE_URL, "token": REMNAWAVE_TOKEN, "timeout_ms": 5000})),
    );
    assert_eq!(saved.status, 200, "{:?}", body(&saved));
    authority
}
