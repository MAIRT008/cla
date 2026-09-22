//! 进程内路由 + 数据库测试：不监听端口、不启动进程，数据只落在 cargo 给集成测试的
//! CARGO_TARGET_TMPDIR 下，不碰用户目录。账号、密码与凭据全部是合成值。
//!
//! 本机没有 cargo/rustc，这些用例已写未运行，异机验收时执行：
//!     cargo test --manifest-path services/control-rs/Cargo.toml

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Barrier};

use ai_steward_control::config::ControlConfig;
use ai_steward_control::logging::Logger;
use ai_steward_control::router::{handle, ApiRequest, ApiResponse, SETUP_TOKEN_HEADER};
use ai_steward_control::{auth, random_hex, App, ControlError};
use serde_json::{json, Value};

const SETUP_TOKEN: &str = "5e7a0c0ffee00000000000000000000000000000000000000000000000000001";
const ADMIN_PASSWORD: &str = "synthetic-Admin-Passw0rd";
const START_MS: i64 = 1_789_000_000_000;

fn fresh_state_dir(label: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("control-rs-tests")
        .join(format!("{label}-{}", random_hex(6).unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_app(state_dir: &Path, now: &Arc<AtomicI64>) -> Result<App, ControlError> {
    let config = ControlConfig::for_state_dir(state_dir.to_path_buf());
    let logger = Arc::new(Logger::create(&config.log_dir(), &format!("ctl-test-{}", random_hex(4).unwrap())));
    let source = now.clone();
    App::open(config, logger, Box::new(move || source.load(Ordering::SeqCst)))
}

fn started(label: &str) -> (App, Arc<AtomicI64>, PathBuf) {
    let dir = fresh_state_dir(label);
    let now = Arc::new(AtomicI64::new(START_MS));
    let app = open_app(&dir, &now).unwrap();
    app.set_setup_token(SETUP_TOKEN);
    (app, now, dir)
}

fn body(response: &ApiResponse) -> Value {
    response.json_body().unwrap_or(Value::Null)
}

fn setup(app: &App, username: &str, password: &str) -> ApiResponse {
    handle(
        app,
        &ApiRequest::new("POST", "/api/setup/admin")
            .header(SETUP_TOKEN_HEADER, SETUP_TOKEN)
            .json(&json!({"username": username, "password": password})),
    )
}

fn login(app: &App, username: &str, password: &str) -> ApiResponse {
    handle(app, &ApiRequest::new("POST", "/api/auth/login").json(&json!({"username": username, "password": password})))
}

fn me(app: &App, token: &str) -> ApiResponse {
    handle(app, &ApiRequest::new("GET", "/api/auth/me").header("authorization", &format!("Bearer {token}")))
}

fn logout(app: &App, token: &str) -> ApiResponse {
    handle(app, &ApiRequest::new("POST", "/api/auth/logout").header("authorization", &format!("Bearer {token}")))
}

fn token_of(response: &ApiResponse) -> String {
    body(response)["access_token"].as_str().unwrap().to_string()
}

fn sql(dir: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(dir.join("control.sqlite3")).unwrap()
}

#[test]
fn empty_store_reports_uninitialized_then_first_admin_can_log_in() {
    let (app, _now, dir) = started("first-start");
    let status = handle(&app, &ApiRequest::new("GET", "/api/setup/status"));
    assert_eq!(status.status, 200);
    assert_eq!(body(&status), json!({"initialized": false}));

    let created = setup(&app, "  Admin.Ops ", ADMIN_PASSWORD);
    assert_eq!(created.status, 201, "{:?}", body(&created));
    assert_eq!(body(&created)["user"]["username"], "admin.ops", "用户名由服务端规范化");
    assert_eq!(body(&created)["user"]["role"], "admin");
    assert!(body(&created).get("access_token").is_none(), "首启只建管理员，不直接签发会话");

    let status = handle(&app, &ApiRequest::new("GET", "/api/setup/status"));
    assert_eq!(body(&status), json!({"initialized": true}));

    let stored: String = sql(&dir)
        .query_row("SELECT password_hash FROM control_users WHERE username = 'admin.ops'", [], |row| row.get(0))
        .unwrap();
    assert!(stored.starts_with("$argon2id$"), "库里存的是 Argon2id PHC 串");
    assert!(!stored.contains(ADMIN_PASSWORD));

    let signed_in = login(&app, "ADMIN.OPS", ADMIN_PASSWORD);
    assert_eq!(signed_in.status, 200, "{:?}", body(&signed_in));
    let token = token_of(&signed_in);
    assert_eq!(token.len(), 64);
    assert_eq!(body(&signed_in)["user"]["role"], "admin");
    assert!(body(&signed_in)["expires_at"].as_str().unwrap().ends_with('Z'));

    let token_rows: i64 = sql(&dir)
        .query_row("SELECT COUNT(*) FROM control_sessions WHERE token_sha256 = ?1", [auth::token_digest(&token)], |row| row.get(0))
        .unwrap();
    assert_eq!(token_rows, 1, "库里只存令牌摘要");
    let plain_rows: i64 = sql(&dir)
        .query_row("SELECT COUNT(*) FROM control_sessions WHERE token_sha256 = ?1", [&token], |row| row.get(0))
        .unwrap();
    assert_eq!(plain_rows, 0, "令牌明文不入库");

    let identity = me(&app, &token);
    assert_eq!(identity.status, 200);
    assert_eq!(body(&identity)["username"], "admin.ops");
    assert_eq!(body(&identity)["role"], "admin");
    assert_eq!(body(&identity)["status"], "ACTIVE");
}

#[test]
fn second_setup_is_rejected_and_the_existing_admin_is_untouched() {
    let (app, _now, _dir) = started("second-setup");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    app.set_setup_token(SETUP_TOKEN);
    let again = setup(&app, "admin", "another-Synthetic-Passw0rd");
    assert_eq!(again.status, 409);
    assert_eq!(body(&again)["code"], "CONTROL_SETUP_CONFLICT");
    assert!(body(&again)["request_ref"].as_str().unwrap().starts_with("req-"));
    let other = setup(&app, "intruder", "another-Synthetic-Passw0rd");
    assert_eq!(other.status, 409, "换个用户名同样不能再建管理员");
    assert_eq!(login(&app, "admin", ADMIN_PASSWORD).status, 200, "原密码仍然有效");
    assert_eq!(login(&app, "admin", "another-Synthetic-Passw0rd").status, 401, "没有被第二次初始化覆盖");
    assert_eq!(login(&app, "intruder", "another-Synthetic-Passw0rd").status, 401);
}

#[test]
fn two_connections_racing_the_first_setup_create_exactly_one_admin() {
    let dir = fresh_state_dir("setup-race");
    let now = Arc::new(AtomicI64::new(START_MS));
    let first = open_app(&dir, &now).unwrap();
    let second = open_app(&dir, &now).unwrap();
    first.set_setup_token(SETUP_TOKEN);
    second.set_setup_token(SETUP_TOKEN);
    let barrier = Barrier::new(2);
    let statuses: Vec<u16> = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            setup(&first, "admin-a", ADMIN_PASSWORD).status
        });
        let b = scope.spawn(|| {
            barrier.wait();
            setup(&second, "admin-b", ADMIN_PASSWORD).status
        });
        vec![a.join().unwrap(), b.join().unwrap()]
    });
    let mut sorted = statuses.clone();
    sorted.sort();
    assert_eq!(sorted, vec![201, 409], "两条连接同时初始化，恰好一条成功：{statuses:?}");
    let users: i64 = sql(&dir).query_row("SELECT COUNT(*) FROM control_users", [], |row| row.get(0)).unwrap();
    let setups: i64 = sql(&dir).query_row("SELECT COUNT(*) FROM control_setup", [], |row| row.get(0)).unwrap();
    assert_eq!((users, setups), (1, 1));
}

#[test]
fn setup_requires_the_host_delivered_token() {
    let dir = fresh_state_dir("setup-token");
    let now = Arc::new(AtomicI64::new(START_MS));
    let app = open_app(&dir, &now).unwrap();
    let request = ApiRequest::new("POST", "/api/setup/admin").json(&json!({"username": "admin", "password": ADMIN_PASSWORD}));
    let without_pending = handle(&app, &request.clone().header(SETUP_TOKEN_HEADER, SETUP_TOKEN));
    assert_eq!(without_pending.status, 403, "没有宿主交付的凭据时一律拒绝");

    app.set_setup_token(SETUP_TOKEN);
    let missing = handle(&app, &request);
    assert_eq!(missing.status, 403);
    assert_eq!(body(&missing)["code"], "CONTROL_SETUP_TOKEN_INVALID");
    let wrong = handle(&app, &request.clone().header(SETUP_TOKEN_HEADER, &"0".repeat(64)));
    assert_eq!(wrong.status, 403);
    let status = handle(&app, &ApiRequest::new("GET", "/api/setup/status"));
    assert_eq!(body(&status), json!({"initialized": false}), "凭据不对时什么都没建");

    let role_injected = handle(
        &app,
        &ApiRequest::new("POST", "/api/setup/admin")
            .header(SETUP_TOKEN_HEADER, SETUP_TOKEN)
            .json(&json!({"username": "admin", "password": ADMIN_PASSWORD, "role": "user", "user_ref": "usr-chosen"})),
    );
    assert_eq!(role_injected.status, 400, "页面提交的角色与用户引用不构成授权");

    let weak = setup(&app, "admin", "short");
    assert_eq!(weak.status, 400);
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    assert!(!app.setup_token_pending(), "首启成功后凭据作废");
}

#[test]
fn wrong_password_and_unknown_user_get_the_same_rejection() {
    let (app, _now, _dir) = started("wrong-password");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    let wrong = login(&app, "admin", "synthetic-Wrong-Passw0rd");
    let unknown = login(&app, "nobody", "synthetic-Wrong-Passw0rd");
    assert_eq!(wrong.status, 401);
    assert_eq!(unknown.status, 401);
    assert_eq!(body(&wrong)["code"], "AUTH_LOGIN_REJECTED");
    assert_eq!(body(&wrong)["code"], body(&unknown)["code"]);
    assert_eq!(body(&wrong)["reason"], body(&unknown)["reason"], "拒绝原因不暴露账号是否存在");
    assert!(body(&wrong).get("access_token").is_none());
}

#[test]
fn expired_sessions_no_longer_yield_an_identity() {
    let (app, now, _dir) = started("expiry");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    let token = token_of(&login(&app, "admin", ADMIN_PASSWORD));
    now.store(START_MS + app.config.session_ttl_ms - 1, Ordering::SeqCst);
    assert_eq!(me(&app, &token).status, 200);
    now.store(START_MS + app.config.session_ttl_ms, Ordering::SeqCst);
    let expired = me(&app, &token);
    assert_eq!(expired.status, 401);
    assert_eq!(body(&expired)["code"], "AUTH_SESSION_INVALID");
}

#[test]
fn logout_revokes_only_that_session_and_repeats_without_side_effects() {
    let (app, _now, dir) = started("logout");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    let first = token_of(&login(&app, "admin", ADMIN_PASSWORD));
    let second = token_of(&login(&app, "admin", ADMIN_PASSWORD));
    assert_eq!(logout(&app, &first).status, 204);
    assert_eq!(me(&app, &first).status, 401, "注销后令牌不可用");
    assert_eq!(me(&app, &second).status, 200, "另一条会话不受影响");
    assert_eq!(logout(&app, &first).status, 204, "重复注销仍回 204");
    let users: i64 = sql(&dir).query_row("SELECT COUNT(*) FROM control_users", [], |row| row.get(0)).unwrap();
    let revoked: i64 = sql(&dir)
        .query_row("SELECT COUNT(*) FROM control_sessions WHERE revoked_at IS NOT NULL", [], |row| row.get(0))
        .unwrap();
    assert_eq!((users, revoked), (1, 1), "注销不删用户，重复注销不多撤销");
    assert_eq!(login(&app, "admin", ADMIN_PASSWORD).status, 200, "注销后仍能重新登录");
    let missing = handle(&app, &ApiRequest::new("POST", "/api/auth/logout"));
    assert_eq!(missing.status, 401);
}

#[test]
fn restart_keeps_the_account_and_live_sessions() {
    let (app, now, dir) = started("restart");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    let token = token_of(&login(&app, "admin", ADMIN_PASSWORD));
    let revoked = token_of(&login(&app, "admin", ADMIN_PASSWORD));
    assert_eq!(logout(&app, &revoked).status, 204);
    drop(app);

    let reopened = open_app(&dir, &now).unwrap();
    assert!(!reopened.store.created_now());
    assert_eq!(body(&handle(&reopened, &ApiRequest::new("GET", "/api/setup/status"))), json!({"initialized": true}));
    assert_eq!(me(&reopened, &token).status, 200, "重启后有效会话仍有效");
    assert_eq!(me(&reopened, &revoked).status, 401, "重启不会复活已注销的会话");
    assert_eq!(login(&reopened, "admin", ADMIN_PASSWORD).status, 200);
    reopened.set_setup_token(SETUP_TOKEN);
    assert_eq!(setup(&reopened, "admin", ADMIN_PASSWORD).status, 409, "重启后仍不能重复初始化");
}

#[test]
fn corrupt_database_is_refused_and_left_byte_for_byte() {
    let dir = fresh_state_dir("corrupt");
    let database = dir.join("control.sqlite3");
    let garbage = b"this is not a sqlite database, it is synthetic garbage used to simulate corruption".repeat(64);
    std::fs::write(&database, &garbage).unwrap();
    let now = Arc::new(AtomicI64::new(START_MS));
    let error = open_app(&dir, &now).err().expect("损坏的库必须拒绝打开");
    assert!(
        matches!(error.code, "CONTROL_STORE_CORRUPT" | "CONTROL_STORE_READ_FAILED"),
        "应报库损坏或读库失败，实际 {error}"
    );
    assert_eq!(std::fs::read(&database).unwrap(), garbage, "不得当成空库重建或改写");
}

#[test]
fn an_empty_or_foreign_database_file_is_not_treated_as_a_fresh_install() {
    let empty_dir = fresh_state_dir("empty-file");
    std::fs::write(empty_dir.join("control.sqlite3"), b"").unwrap();
    let now = Arc::new(AtomicI64::new(START_MS));
    let empty = open_app(&empty_dir, &now).err().expect("已存在的空文件不是新装");
    assert_eq!(empty.code, "CONTROL_STORE_UNRECOGNIZED");

    let foreign_dir = fresh_state_dir("foreign");
    {
        let connection = sql(&foreign_dir);
        connection
            .execute_batch("CREATE TABLE control_users (user_ref TEXT PRIMARY KEY NOT NULL, payload_json TEXT NOT NULL);")
            .unwrap();
    }
    let foreign = open_app(&foreign_dir, &now).err().expect("旧 Node 控制端的库不能被接管");
    assert_eq!(foreign.code, "CONTROL_STORE_UNRECOGNIZED");
    let tables: i64 = sql(&foreign_dir)
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'control_meta'", [], |row| row.get(0))
        .unwrap();
    assert_eq!(tables, 0, "拒绝时不往别人的库里建表");
}

#[test]
fn disabled_users_cannot_log_in_or_keep_their_session() {
    let (app, _now, dir) = started("disabled");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    let token = token_of(&login(&app, "admin", ADMIN_PASSWORD));
    sql(&dir).execute("UPDATE control_users SET status = 'DISABLED'", []).unwrap();
    assert_eq!(me(&app, &token).status, 401);
    let refused = login(&app, "admin", ADMIN_PASSWORD);
    assert_eq!(refused.status, 401);
    assert_eq!(body(&refused)["code"], "AUTH_LOGIN_REJECTED");
}

#[test]
fn repeated_failures_back_off_and_recover() {
    let (app, now, _dir) = started("throttle");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    for _ in 0..app.config.login_free_failures {
        assert_eq!(login(&app, "admin", "synthetic-Wrong-Passw0rd").status, 401);
    }
    assert_eq!(login(&app, "admin", "synthetic-Wrong-Passw0rd").status, 401);
    let throttled = login(&app, "admin", ADMIN_PASSWORD);
    assert_eq!(throttled.status, 429, "退避期内正确密码也要等");
    assert_eq!(body(&throttled)["code"], "AUTH_THROTTLED");
    assert!(body(&throttled)["retry_after_ms"].as_i64().unwrap() > 0);
    now.store(START_MS + app.config.login_backoff_base_ms, Ordering::SeqCst);
    assert_eq!(login(&app, "admin", ADMIN_PASSWORD).status, 200, "退避结束后恢复");
}

/// RC2：业务路由已迁移。未配置、未分配时如实回「不可用 / 未分配 / 未知」，不伪造资源、额度或模型能力。
#[test]
fn business_routes_require_a_session_and_never_fake_success_when_unconfigured() {
    let (app, _now, dir) = started("unconfigured-business");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    let admin_token = token_of(&login(&app, "admin", ADMIN_PASSWORD));

    let anonymous = handle(&app, &ApiRequest::new("GET", "/api/ai/capabilities"));
    assert_eq!(anonymous.status, 401);
    let get = |path: &str| handle(&app, &ApiRequest::new("GET", path).header("authorization", &format!("Bearer {admin_token}")));
    let capabilities = get("/api/ai/capabilities");
    assert_eq!(capabilities.status, 200);
    assert!(body(&capabilities)["tasks"].as_object().unwrap().values().all(|task| task["status"] == "UNAVAILABLE"), "没有模型配置就不可用");
    let assignment = get("/api/network/assignment");
    assert!(body(&assignment)["assignment"].is_null() && body(&assignment)["quota"].is_null(), "不伪造资源或额度");
    let quota = get("/api/network/quota");
    assert_eq!(body(&quota)["code"], "AUTHORITY_UNCONFIGURED");
    assert_eq!(body(&quota)["quota"]["status"], "UNKNOWN");
    let credentials = get("/api/network/credentials");
    assert!(body(&credentials)["credentials"].as_object().unwrap().is_empty());
    let resources = get("/api/admin/resources");
    assert_eq!(body(&resources)["resources"], serde_json::json!([]));
    for path in ["/api/ai/capabilities", "/api/network/assignment", "/api/network/quota", "/api/network/credentials", "/api/admin/resources"] {
        assert_ne!(body(&get(path))["code"], "CONTROL_CAPABILITY_NOT_MIGRATED", "{path}");
    }

    let member_hash = auth::hash_password("synthetic-Member-Passw0rd").unwrap();
    sql(&dir)
        .execute(
            "INSERT INTO control_users (user_ref, username, password_hash, role, status, created_at, updated_at) VALUES ('usr-member', 'member', ?1, 'user', 'ACTIVE', 'now', 'now')",
            [member_hash],
        )
        .unwrap();
    let member_token = token_of(&login(&app, "member", "synthetic-Member-Passw0rd"));
    assert_eq!(body(&me(&app, &member_token))["role"], "user", "角色来自服务端");
    let forbidden = handle(&app, &ApiRequest::new("GET", "/api/admin/resources").header("authorization", &format!("Bearer {member_token}")));
    assert_eq!(forbidden.status, 403);
    assert_eq!(body(&forbidden)["code"], "CONTROL_FORBIDDEN");
}

#[test]
fn health_reports_the_instance_without_secrets_or_users() {
    let (app, _now, _dir) = started("health");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    let health = handle(&app, &ApiRequest::new("GET", "/health"));
    assert_eq!(health.status, 200);
    let value = body(&health);
    assert_eq!(value["protocol"], "steward-control-1");
    assert_eq!(value["service"], "ai-steward-control");
    assert_eq!(value["instance_ref"], app.instance_ref.as_str());
    let text = value.to_string();
    for forbidden in ["admin", SETUP_TOKEN, "argon2", "password", "users"] {
        assert!(!text.contains(forbidden), "健康检查不得带出 {forbidden}");
    }
    assert!(health.header_value("x-request-ref").unwrap().starts_with("req-"));
}

#[test]
fn browser_origins_are_checked_before_state_changing_requests() {
    let (app, _now, _dir) = started("origins");
    let preflight = handle(
        &app,
        &ApiRequest::new("OPTIONS", "/api/auth/login").header("origin", "http://tauri.localhost"),
    );
    assert_eq!(preflight.status, 204);
    assert_eq!(preflight.header_value("access-control-allow-origin"), Some("http://tauri.localhost"));
    assert_eq!(preflight.header_value("access-control-allow-private-network"), Some("true"));
    let denied_preflight = handle(&app, &ApiRequest::new("OPTIONS", "/api/auth/login").header("origin", "https://evil.example"));
    assert_eq!(denied_preflight.status, 403);
    let denied = handle(
        &app,
        &ApiRequest::new("POST", "/api/auth/login")
            .header("origin", "https://evil.example")
            .json(&json!({"username": "admin", "password": ADMIN_PASSWORD})),
    );
    assert_eq!(denied.status, 403);
    assert_eq!(body(&denied)["code"], "CONTROL_ORIGIN_DENIED");
    let plain_text = handle(
        &app,
        &ApiRequest {
            method: "POST".into(),
            path: "/api/auth/login".into(),
            headers: vec![("content-type".into(), "text/plain".into())],
            body: json!({"username": "admin", "password": ADMIN_PASSWORD}).to_string().into_bytes(),
        },
    );
    assert_eq!(plain_text.status, 415, "非 JSON 的简单请求不进入登录逻辑");
}

#[test]
fn the_run_log_records_the_flow_without_passwords_or_tokens() {
    let (app, _now, _dir) = started("log-redaction");
    assert_eq!(setup(&app, "admin", ADMIN_PASSWORD).status, 201);
    assert_eq!(login(&app, "admin", "synthetic-Wrong-Passw0rd").status, 401);
    let token = token_of(&login(&app, "admin", ADMIN_PASSWORD));
    assert_eq!(logout(&app, &token).status, 204);
    let text = std::fs::read_to_string(app.logger.path()).unwrap();
    for event in ["store.open.ok", "setup.admin.created", "auth.login.rejected", "auth.login.accepted", "auth.logout"] {
        assert!(text.contains(event), "日志缺少 {event}");
    }
    for secret in [ADMIN_PASSWORD, "synthetic-Wrong-Passw0rd", token.as_str(), SETUP_TOKEN, "$argon2id$"] {
        assert!(!text.contains(secret), "日志里出现了秘密：{secret}");
    }
    assert_eq!(app.logger.status(), "ok");
    for line in text.lines() {
        let parsed: Value = serde_json::from_str(line).unwrap();
        assert!(parsed["instance_ref"].is_string() && parsed["event"].is_string());
    }
}

#[test]
fn each_start_writes_a_new_log_file_instead_of_overwriting() {
    let dir = fresh_state_dir("log-files");
    let now = Arc::new(AtomicI64::new(START_MS));
    let first = open_app(&dir, &now).unwrap();
    let first_path = first.logger.path().to_path_buf();
    drop(first);
    let second = open_app(&dir, &now).unwrap();
    assert_ne!(first_path, second.logger.path());
    assert!(first_path.exists(), "上一轮日志保留");
    assert!(std::fs::read_to_string(&first_path).unwrap().contains("store.open.ok"));
}
