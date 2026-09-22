//! 与 HTTP 框架无关的路由。所有错误回 `{code, reason, request_ref}`，并在响应头带 X-Request-Ref，
//! 与日志里的同一次请求对得上。
//!
//! 未认证可达：健康检查、首启状态与首启、登录、身份、注销。其余 `/api/*` 先认证（401），
//! `/api/admin/*` 再由服务端角色判定（403），然后进入 `ROUTES` 里登记的业务处理；
//! 不在表里的路径回 404，不再有「未迁移」的 501。

use serde_json::{json, Map, Value};

use crate::api::ApiError;
use crate::auth::{self, bearer_token, normalize_username, token_digest, validate_password, verify_password};
use crate::http::CancelToken;
use crate::store::{NewUser, SessionIdentity};
use crate::{
    admin_users, ai, assignments, events, probes, quota, resources, iso_from_millis, random_hex, sha256_hex, App, ControlError,
    PROTOCOL_VERSION, SERVICE_NAME, SERVICE_VERSION,
};

pub const SETUP_TOKEN_HEADER: &str = "x-steward-setup-token";
const MAX_BODY_BYTES: usize = 16 * 1024;
const BUSINESS_BODY_BYTES: usize = 64 * 1024;
const AI_TURN_BODY_BYTES: usize = 256 * 1024;
const SUBSCRIPTION_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ApiRequest {
    pub fn new(method: &str, path: &str) -> ApiRequest {
        ApiRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> ApiRequest {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn json(mut self, value: &Value) -> ApiRequest {
        self.headers.push(("content-type".to_string(), "application/json".to_string()));
        self.body = value.to_string().into_bytes();
        self
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ApiResponse {
    pub fn json(status: u16, value: Value) -> ApiResponse {
        ApiResponse {
            status,
            headers: vec![("content-type".to_string(), "application/json; charset=utf-8".to_string())],
            body: value.to_string().into_bytes(),
        }
    }

    fn empty(status: u16) -> ApiResponse {
        ApiResponse { status, headers: Vec::new(), body: Vec::new() }
    }

    pub fn error(status: u16, code: &str, reason: &str, request_ref: &str) -> ApiResponse {
        ApiResponse::json(status, json!({"code": code, "reason": reason, "request_ref": request_ref}))
    }

    /// 带秘密材料的响应（个人凭据）不许被任何缓存留下。
    pub fn no_store(mut self) -> ApiResponse {
        self.headers.push(("cache-control".to_string(), "no-store".to_string()));
        self
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn json_body(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

/// 数据库与随机源一类内部失败：细节写日志，对外只给脱敏说明和请求引用。
fn internal(app: &App, request_ref: &str, event: &str, error: &ControlError) -> ApiResponse {
    app.logger.error(event, Some(request_ref), json!({"code": error.code, "detail": error.reason}));
    let reason = match error.code {
        "CONTROL_STORE_READ_FAILED" => "控制端数据库读取失败，详见控制端日志",
        "CONTROL_STORE_WRITE_FAILED" => "控制端数据库写入失败，详见控制端日志",
        "CONTROL_STORE_CORRUPT" => "控制端数据库已损坏，详见控制端日志",
        "CONTROL_RANDOM_UNAVAILABLE" => "系统安全随机源不可用，详见控制端日志",
        _ => "控制端内部错误，详见控制端日志",
    };
    ApiResponse::error(500, error.code, reason, request_ref)
}

fn new_request_ref() -> String {
    match random_hex(6) {
        Ok(hex) => format!("req-{hex}"),
        Err(_) => "req-unavailable".to_string(),
    }
}

pub fn handle(app: &App, request: &ApiRequest) -> ApiResponse {
    handle_with_cancel(app, request, &CancelToken::new())
}

/// `cancel` 在页面断开请求时由 main.rs 置位；外部调用据此停在最近的检查点。
pub fn handle_with_cancel(app: &App, request: &ApiRequest, cancel: &CancelToken) -> ApiResponse {
    let request_ref = new_request_ref();
    let (path, query) = match request.path.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (request.path.clone(), String::new()),
    };
    let method = request.method.to_ascii_uppercase();
    let origin = request.header_value("origin").map(str::to_string);
    let origin_allowed = origin
        .as_deref()
        .map(|value| app.config.allowed_origins.iter().any(|allowed| allowed == value));

    let mut response = if method == "OPTIONS" {
        preflight(app, &request_ref, origin_allowed)
    } else if origin_allowed == Some(false) && method != "GET" {
        app.logger.warn("request.origin_denied", Some(&request_ref), json!({"method": method, "path": path, "origin": origin}));
        ApiResponse::error(403, "CONTROL_ORIGIN_DENIED", "请求来源不在控制端允许的页面来源内", &request_ref)
    } else {
        route(app, request, &method, &path, &query, &request_ref, cancel)
    };

    response.headers.push(("x-request-ref".to_string(), request_ref));
    if let (Some(value), Some(true)) = (origin, origin_allowed) {
        response.headers.push(("access-control-allow-origin".to_string(), value));
        response.headers.push(("access-control-expose-headers".to_string(), "x-request-ref".to_string()));
        response.headers.push(("vary".to_string(), "origin".to_string()));
    }
    response
}

fn preflight(app: &App, request_ref: &str, origin_allowed: Option<bool>) -> ApiResponse {
    if origin_allowed != Some(true) {
        app.logger.warn("request.preflight_denied", Some(request_ref), json!({}));
        return ApiResponse::error(403, "CONTROL_ORIGIN_DENIED", "请求来源不在控制端允许的页面来源内", request_ref);
    }
    let mut response = ApiResponse::empty(204);
    response.headers.push(("access-control-allow-methods".to_string(), "GET, POST, PUT, OPTIONS".to_string()));
    response.headers.push(("access-control-allow-headers".to_string(), "authorization, content-type, accept".to_string()));
    response.headers.push(("access-control-max-age".to_string(), "600".to_string()));
    // Chromium 的私有网络访问预检：WebView 页面访问回环控制端时要求显式放行。
    response.headers.push(("access-control-allow-private-network".to_string(), "true".to_string()));
    response
}

/// 未认证即可到达的路径。
const PUBLIC_ROUTES: &[(&str, &str)] = &[
    ("GET", "/health"),
    ("GET", "/api/setup/status"),
    ("POST", "/api/setup/admin"),
    ("POST", "/api/auth/login"),
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/logout"),
];

/// 认证后的业务路由。页面与适配器调用的每一条都必须在这里，且在 `dispatch` 里有同方法分支。
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/admin/users"),
    ("POST", "/api/admin/users"),
    ("POST", "/api/admin/users/status"),
    ("POST", "/api/admin/users/password-reset"),
    ("GET", "/api/admin/sessions"),
    ("POST", "/api/admin/sessions/revoke"),
    ("GET", "/api/ai/capabilities"),
    ("POST", "/api/ai/turn"),
    ("GET", "/api/admin/model-config"),
    ("PUT", "/api/admin/model-config"),
    ("GET", "/api/admin/resources"),
    ("PUT", "/api/admin/resources"),
    ("GET", "/api/admin/templates"),
    ("PUT", "/api/admin/templates"),
    ("GET", "/api/admin/subscriptions"),
    ("PUT", "/api/admin/subscriptions"),
    ("POST", "/api/admin/subscriptions/refresh"),
    ("GET", "/api/admin/assignments"),
    ("POST", "/api/admin/assignments"),
    ("POST", "/api/admin/assignments/publish"),
    ("POST", "/api/admin/assignments/revoke"),
    ("GET", "/api/admin/credentials"),
    ("PUT", "/api/admin/credentials"),
    ("POST", "/api/admin/credentials/revoke"),
    ("GET", "/api/network/assignment"),
    ("GET", "/api/network/credentials"),
    ("POST", "/api/network/receipts"),
    ("GET", "/api/network/quota"),
    ("GET", "/api/network/events"),
    ("POST", "/api/network/events"),
    ("POST", "/api/admin/quota/allocate"),
    ("POST", "/api/admin/quota/limit"),
    ("POST", "/api/admin/quota/suspend"),
    ("POST", "/api/admin/quota/resume"),
    ("GET", "/api/admin/quota/usage"),
    ("GET", "/api/admin/quota/pool"),
    ("GET", "/api/admin/quota-adapter"),
    ("PUT", "/api/admin/quota-adapter"),
    ("GET", "/api/admin/events"),
    ("GET", "/api/admin/service-state"),
    ("GET", "/api/admin/probe-services"),
    ("PUT", "/api/admin/probe-services"),
    ("POST", "/api/admin/probe-services/remove"),
    ("GET", "/api/network/probe-services"),
];

fn route(app: &App, request: &ApiRequest, method: &str, path: &str, query: &str, request_ref: &str, cancel: &CancelToken) -> ApiResponse {
    match (method, path) {
        ("GET", "/health") => health(app),
        ("GET", "/api/setup/status") => setup_status(app, request_ref),
        ("POST", "/api/setup/admin") => setup_admin(app, request, request_ref),
        ("POST", "/api/auth/login") => login(app, request, request_ref),
        ("GET", "/api/auth/me") => me(app, request, request_ref),
        ("POST", "/api/auth/logout") => logout(app, request, request_ref),
        _ if PUBLIC_ROUTES.iter().any(|(_, known)| *known == path) => {
            ApiResponse::error(405, "CONTROL_METHOD_NOT_ALLOWED", "该接口不支持这个请求方法", request_ref)
        }
        _ if path.starts_with("/api/") => authenticated(app, request, method, path, query, request_ref, cancel),
        _ => ApiResponse::error(404, "CONTROL_NOT_FOUND", "控制端没有这个接口", request_ref),
    }
}

/// 认证后的请求上下文。业务模块只经它拿身份、正文、查询参数、时间与取消令牌。
pub struct Ctx<'a> {
    pub app: &'a App,
    pub request: &'a ApiRequest,
    pub identity: SessionIdentity,
    pub method: &'a str,
    pub path: &'a str,
    pub request_ref: &'a str,
    pub cancel: &'a CancelToken,
    query: Vec<(String, String)>,
    body_limit: usize,
}

impl<'a> Ctx<'a> {
    pub fn now(&self) -> i64 {
        self.app.now()
    }

    pub fn actor(&self) -> &str {
        &self.identity.user_ref
    }

    pub fn is_admin(&self) -> bool {
        self.identity.role == "admin"
    }

    pub fn query(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.is_empty())
    }

    /// JSON 对象正文。Content-Type 必须是 application/json；上限随路由而定。
    pub fn body(&self) -> Result<Value, ApiError> {
        let content_type = self.request.header_value("content-type").unwrap_or("").to_ascii_lowercase();
        if !content_type.starts_with("application/json") {
            return Err(ApiError::new(415, "CONTROL_REQUEST_INVALID", "请求正文必须是 application/json"));
        }
        if self.request.body.len() > self.body_limit {
            return Err(ApiError::new(413, "CONTROL_REQUEST_INVALID", "请求正文过大"));
        }
        serde_json::from_slice::<Value>(&self.request.body)
            .ok()
            .filter(Value::is_object)
            .ok_or_else(|| ApiError::invalid("请求正文不是有效的 JSON 对象"))
    }

    pub fn info(&self, event: &str, fields: Value) {
        self.app.logger.info(event, Some(self.request_ref), fields);
    }

    pub fn warn(&self, event: &str, fields: Value) {
        self.app.logger.warn(event, Some(self.request_ref), fields);
    }

    pub fn error(&self, event: &str, fields: Value) {
        self.app.logger.error(event, Some(self.request_ref), fields);
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok().and_then(|pair| u8::from_str_radix(pair, 16).ok());
                match hex {
                    Some(value) => {
                        output.push(value);
                        index += 3;
                    }
                    None => {
                        output.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

pub fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (percent_decode(key), percent_decode(value)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

fn body_limit_for(path: &str) -> usize {
    match path {
        "/api/ai/turn" => AI_TURN_BODY_BYTES,
        "/api/admin/subscriptions/refresh" => SUBSCRIPTION_BODY_BYTES,
        _ => BUSINESS_BODY_BYTES,
    }
}

fn authenticated(app: &App, request: &ApiRequest, method: &str, path: &str, query: &str, request_ref: &str, cancel: &CancelToken) -> ApiResponse {
    let identity = match authenticate(app, request, request_ref) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if path.starts_with("/api/admin/") && identity.role != "admin" {
        app.logger.warn("request.forbidden", Some(request_ref), json!({"user_ref": identity.user_ref, "path": path}));
        return ApiResponse::error(403, "CONTROL_FORBIDDEN", "该操作需要管理员权限", request_ref);
    }
    let ctx = Ctx {
        app,
        request,
        identity,
        method,
        path,
        request_ref,
        cancel,
        query: parse_query(query),
        body_limit: body_limit_for(path),
    };
    let outcome = dispatch(&ctx);
    let response = match outcome {
        Ok(response) => response,
        Err(error) => error_response(&ctx, error),
    };
    let code = response.json_body().and_then(|body| body.get("code").and_then(Value::as_str).map(str::to_string));
    let fields = json!({"method": method, "path": path, "user_ref": ctx.identity.user_ref, "status": response.status, "code": code});
    if response.status >= 500 {
        ctx.error("request.completed", fields);
    } else if response.status >= 400 {
        ctx.warn("request.completed", fields);
    } else {
        ctx.info("request.completed", fields);
    }
    response
}

fn dispatch(ctx: &Ctx<'_>) -> Result<ApiResponse, ApiError> {
    match (ctx.method, ctx.path) {
        ("GET", "/api/admin/users") => admin_users::list(ctx),
        ("POST", "/api/admin/users") => admin_users::create(ctx),
        ("POST", "/api/admin/users/status") => admin_users::set_status(ctx),
        ("POST", "/api/admin/users/password-reset") => admin_users::reset_password(ctx),
        ("GET", "/api/admin/sessions") => admin_users::list_sessions(ctx),
        ("POST", "/api/admin/sessions/revoke") => admin_users::revoke_sessions(ctx),
        ("GET", "/api/ai/capabilities") => ai::capabilities(ctx),
        ("POST", "/api/ai/turn") => ai::turn(ctx),
        ("GET", "/api/admin/model-config") => ai::get_model_config(ctx),
        ("PUT", "/api/admin/model-config") => ai::put_model_config(ctx),
        ("GET", "/api/admin/resources") => resources::list_resources(ctx),
        ("PUT", "/api/admin/resources") => resources::put_resource(ctx),
        ("GET", "/api/admin/templates") => resources::list_templates(ctx),
        ("PUT", "/api/admin/templates") => resources::put_template(ctx),
        ("GET", "/api/admin/subscriptions") => resources::list_subscriptions(ctx),
        ("PUT", "/api/admin/subscriptions") => resources::put_subscription(ctx),
        ("POST", "/api/admin/subscriptions/refresh") => resources::refresh_subscription(ctx),
        ("GET", "/api/admin/assignments") => assignments::admin_view(ctx),
        ("POST", "/api/admin/assignments") => assignments::allocate(ctx),
        ("POST", "/api/admin/assignments/publish") => assignments::publish(ctx),
        ("POST", "/api/admin/assignments/revoke") => assignments::revoke(ctx),
        ("GET", "/api/admin/credentials") => assignments::admin_list_credentials(ctx),
        ("PUT", "/api/admin/credentials") => assignments::admin_put_credential(ctx),
        ("POST", "/api/admin/credentials/revoke") => assignments::admin_revoke_credential(ctx),
        ("GET", "/api/network/assignment") => assignments::network_assignment(ctx),
        ("GET", "/api/network/credentials") => assignments::network_credentials(ctx),
        ("POST", "/api/network/receipts") => assignments::save_receipt(ctx),
        ("GET", "/api/network/quota") => quota::network_quota(ctx),
        ("GET", "/api/network/events") => events::list_mine(ctx),
        ("POST", "/api/network/events") => events::receive(ctx),
        ("POST", "/api/admin/quota/allocate") => quota::allocate(ctx),
        ("POST", "/api/admin/quota/limit") => quota::change_limit(ctx),
        ("POST", "/api/admin/quota/suspend") => quota::suspend(ctx),
        ("POST", "/api/admin/quota/resume") => quota::resume(ctx),
        ("GET", "/api/admin/quota/usage") => quota::usage(ctx),
        ("GET", "/api/admin/quota/pool") => quota::pool(ctx),
        ("GET", "/api/admin/quota-adapter") => quota::get_adapter(ctx),
        ("PUT", "/api/admin/quota-adapter") => quota::put_adapter(ctx),
        ("GET", "/api/admin/events") => events::admin_list(ctx),
        ("GET", "/api/admin/service-state") => quota::service_state(ctx),
        ("GET", "/api/admin/probe-services") => probes::list(ctx),
        ("PUT", "/api/admin/probe-services") => probes::put(ctx),
        ("POST", "/api/admin/probe-services/remove") => probes::remove(ctx),
        ("GET", "/api/network/probe-services") => probes::network_view(ctx),
        (_, path) if ROUTES.iter().any(|(_, known)| *known == path) => {
            Err(ApiError::new(405, "CONTROL_METHOD_NOT_ALLOWED", "该接口不支持这个请求方法"))
        }
        _ => Err(ApiError::new(404, "CONTROL_NOT_FOUND", "控制端没有这个接口")),
    }
}

/// 业务错误转响应。内部故障只回脱敏说明，细节进日志；其余错误原样带上码、原因与附加字段。
fn error_response(ctx: &Ctx<'_>, error: ApiError) -> ApiResponse {
    let reason = if error.is_internal() {
        ctx.error("request.internal_error", json!({"path": ctx.path, "code": error.code, "detail": error.reason}));
        "控制端内部错误，详见控制端日志".to_string()
    } else {
        error.reason.clone()
    };
    let mut body = Map::new();
    for (key, value) in error.extra {
        body.insert(key, value);
    }
    body.insert("code".to_string(), Value::String(error.code));
    body.insert("reason".to_string(), Value::String(reason));
    body.insert("request_ref".to_string(), Value::String(ctx.request_ref.to_string()));
    ApiResponse::json(error.status, Value::Object(body))
}

fn health(app: &App) -> ApiResponse {
    ApiResponse::json(
        200,
        json!({
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "protocol": PROTOCOL_VERSION,
            "instance_ref": app.instance_ref,
            "status": "ready",
            "started_at": app.started_at,
            "log_status": app.logger.status(),
        }),
    )
}

fn read_json(request: &ApiRequest, request_ref: &str) -> Result<Value, ApiResponse> {
    let content_type = request.header_value("content-type").unwrap_or("").to_ascii_lowercase();
    if !content_type.starts_with("application/json") {
        return Err(ApiResponse::error(415, "CONTROL_REQUEST_INVALID", "请求正文必须是 application/json", request_ref));
    }
    if request.body.len() > MAX_BODY_BYTES {
        return Err(ApiResponse::error(413, "CONTROL_REQUEST_INVALID", "请求正文过大", request_ref));
    }
    serde_json::from_slice::<Value>(&request.body)
        .ok()
        .filter(Value::is_object)
        .ok_or_else(|| ApiResponse::error(400, "CONTROL_REQUEST_INVALID", "请求正文不是有效的 JSON 对象", request_ref))
}

/// 只接受 username 与 password 两个字符串字段；角色、用户引用等页面输入一律拒收。
fn credentials(body: &Value, request_ref: &str) -> Result<(String, String), ApiResponse> {
    let object = body.as_object().ok_or_else(|| ApiResponse::error(400, "CONTROL_REQUEST_INVALID", "请求正文不是 JSON 对象", request_ref))?;
    if object.keys().any(|key| key != "username" && key != "password") {
        return Err(ApiResponse::error(400, "CONTROL_REQUEST_INVALID", "请求只接受 username 与 password", request_ref));
    }
    let username = object.get("username").and_then(Value::as_str);
    let password = object.get("password").and_then(Value::as_str);
    match (username, password) {
        (Some(username), Some(password)) => Ok((username.to_string(), password.to_string())),
        _ => Err(ApiResponse::error(400, "CONTROL_REQUEST_INVALID", "username 与 password 都是必填字符串", request_ref)),
    }
}

fn user_json(user_ref: &str, username: &str, role: &str, status: &str) -> Value {
    json!({"user_ref": user_ref, "username": username, "role": role, "status": status})
}

fn setup_status(app: &App, request_ref: &str) -> ApiResponse {
    match app.store.is_initialized() {
        Ok(initialized) => ApiResponse::json(200, json!({"initialized": initialized})),
        Err(error) => internal(app, request_ref, "setup.status.failed", &error),
    }
}

fn setup_admin(app: &App, request: &ApiRequest, request_ref: &str) -> ApiResponse {
    match app.store.is_initialized() {
        Ok(true) => {
            app.logger.warn("setup.admin.conflict", Some(request_ref), json!({"stage": "precheck"}));
            return ApiResponse::error(409, "CONTROL_SETUP_CONFLICT", "控制端已经完成首次初始化，不能重复创建管理员", request_ref);
        }
        Ok(false) => {}
        Err(error) => return internal(app, request_ref, "setup.admin.failed", &error),
    }
    let presented = request.header_value(SETUP_TOKEN_HEADER).unwrap_or("");
    if presented.is_empty() || !app.setup_token_matches(presented) {
        app.logger.warn("setup.admin.token_rejected", Some(request_ref), json!({"presented": !presented.is_empty(), "pending": app.setup_token_pending()}));
        return ApiResponse::error(403, "CONTROL_SETUP_TOKEN_INVALID", "首启凭据缺失或不匹配；请从本应用的首启页面发起", request_ref);
    }
    let body = match read_json(request, request_ref) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (raw_username, password) = match credentials(&body, request_ref) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let username = match normalize_username(&raw_username) {
        Ok(username) => username,
        Err(error) => return ApiResponse::error(400, error.code, &error.reason, request_ref),
    };
    if let Err(error) = validate_password(&password, &app.config) {
        return ApiResponse::error(400, error.code, &error.reason, request_ref);
    }
    let password_hash = match auth::hash_password(&password) {
        Ok(hash) => hash,
        Err(error) => return internal(app, request_ref, "setup.admin.failed", &error),
    };
    let user_ref = match random_hex(8) {
        Ok(hex) => format!("usr-{hex}"),
        Err(error) => return internal(app, request_ref, "setup.admin.failed", &error),
    };
    let admin = NewUser { user_ref: user_ref.clone(), username: username.clone(), password_hash, role: "admin" };
    match app.store.initialize_admin(&admin, (app.clock)()) {
        Ok(()) => {
            app.retire_setup_token();
            app.logger.info("setup.admin.created", Some(request_ref), json!({"user_ref": user_ref}));
            ApiResponse::json(201, json!({"initialized": true, "user": user_json(&user_ref, &username, "admin", "ACTIVE")}))
        }
        Err(error) if error.code == "CONTROL_SETUP_CONFLICT" => {
            app.logger.warn("setup.admin.conflict", Some(request_ref), json!({"stage": "commit"}));
            ApiResponse::error(409, error.code, &error.reason, request_ref)
        }
        Err(error) => internal(app, request_ref, "setup.admin.failed", &error),
    }
}

fn login(app: &App, request: &ApiRequest, request_ref: &str) -> ApiResponse {
    let body = match read_json(request, request_ref) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (raw_username, password) = match credentials(&body, request_ref) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let now = (app.clock)();
    let normalized = normalize_username(&raw_username).ok();
    let throttle_key = normalized.clone().unwrap_or_else(|| raw_username.trim().to_ascii_lowercase());
    let subject = sha256_hex(throttle_key.as_bytes())[..12].to_string();
    if let Err(retry_after_ms) = app.throttle.check(&throttle_key, now) {
        app.logger.warn("auth.login.throttled", Some(request_ref), json!({"subject": subject, "retry_after_ms": retry_after_ms}));
        return ApiResponse::json(
            429,
            json!({"code": "AUTH_THROTTLED", "reason": "登录失败次数过多，请稍后再试", "retry_after_ms": retry_after_ms, "request_ref": request_ref}),
        );
    }
    let user = match normalized.as_deref() {
        Some(username) => match app.store.find_user_by_username(username) {
            Ok(user) => user,
            Err(error) => return internal(app, request_ref, "auth.login.failed", &error),
        },
        None => None,
    };
    // 账号不存在时也跑一次同成本的校验，拒绝结果与耗时不暴露账号是否存在。
    let (accepted, cause) = match &user {
        Some(record) => {
            let verified = verify_password(&password, &record.password_hash);
            match (verified, record.status.as_str()) {
                (true, "ACTIVE") => (true, "accepted"),
                (true, _) => (false, "user_disabled"),
                (false, _) => (false, "password_mismatch"),
            }
        }
        None => {
            let _ = verify_password(&password, app.dummy_password_hash());
            (false, "unknown_user")
        }
    };
    let record = match (accepted, user) {
        (true, Some(record)) => record,
        _ => {
            app.throttle.record_failure(&throttle_key, now, &app.config);
            app.logger.warn("auth.login.rejected", Some(request_ref), json!({"subject": subject, "cause": cause}));
            return ApiResponse::error(401, "AUTH_LOGIN_REJECTED", "账号或密码不正确，或该账号当前不可用", request_ref);
        }
    };
    let token = match auth::new_session_token() {
        Ok(token) => token,
        Err(error) => return internal(app, request_ref, "auth.login.failed", &error),
    };
    let session_ref = match random_hex(8) {
        Ok(hex) => format!("ses-{hex}"),
        Err(error) => return internal(app, request_ref, "auth.login.failed", &error),
    };
    let expires_at_ms = now + app.config.session_ttl_ms;
    if let Err(error) = app.store.create_session(&token_digest(&token), &session_ref, &record.user_ref, now, expires_at_ms) {
        return internal(app, request_ref, "auth.login.failed", &error);
    }
    app.throttle.clear(&throttle_key);
    let expires_at = iso_from_millis(expires_at_ms);
    app.logger.info(
        "auth.login.accepted",
        Some(request_ref),
        json!({"user_ref": record.user_ref, "session_ref": session_ref, "role": record.role, "expires_at": expires_at}),
    );
    ApiResponse::json(
        200,
        json!({
            "access_token": token,
            "expires_at": expires_at,
            "user": user_json(&record.user_ref, &record.username, &record.role, &record.status),
        }),
    )
}

/// 取得当前请求的有效会话；无效时直接给出 401 响应。
fn authenticate(app: &App, request: &ApiRequest, request_ref: &str) -> Result<SessionIdentity, ApiResponse> {
    let token = match bearer_token(request.header_value("authorization")) {
        Some(token) => token,
        None => return Err(ApiResponse::error(401, "AUTH_SESSION_INVALID", "没有有效的登录会话，请重新登录", request_ref)),
    };
    match app.store.session_identity(&token_digest(token), (app.clock)()) {
        Ok(Some(identity)) => Ok(identity),
        Ok(None) => {
            app.logger.info("auth.session.rejected", Some(request_ref), json!({"path": request.path.split('?').next().unwrap_or("")}));
            Err(ApiResponse::error(401, "AUTH_SESSION_INVALID", "登录会话已失效、已注销或账号已停用，请重新登录", request_ref))
        }
        Err(error) => Err(internal(app, request_ref, "auth.session.failed", &error)),
    }
}

fn me(app: &App, request: &ApiRequest, request_ref: &str) -> ApiResponse {
    match authenticate(app, request, request_ref) {
        Ok(identity) => ApiResponse::json(
            200,
            json!({
                "user_ref": identity.user_ref,
                "username": identity.username,
                "role": identity.role,
                "status": identity.status,
                "expires_at": iso_from_millis(identity.expires_at_ms),
            }),
        ),
        Err(response) => response,
    }
}

/// 只撤销本次请求携带的那一条会话，不动用户、额度或业务记录；重复注销同样回 204。
fn logout(app: &App, request: &ApiRequest, request_ref: &str) -> ApiResponse {
    let token = match bearer_token(request.header_value("authorization")) {
        Some(token) => token,
        None => return ApiResponse::error(401, "AUTH_SESSION_INVALID", "没有可注销的登录会话", request_ref),
    };
    match app.store.revoke_session(&token_digest(token), (app.clock)()) {
        Ok(revoked) => {
            app.logger.info("auth.logout", Some(request_ref), json!({"revoked": revoked}));
            ApiResponse::empty(204)
        }
        Err(error) => internal(app, request_ref, "auth.logout.failed", &error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_strings_are_decoded() {
        let parsed = parse_query("user_ref=usr-1%3Ab&note=a+b&empty=&flag");
        assert_eq!(parsed[0], ("user_ref".to_string(), "usr-1:b".to_string()));
        assert_eq!(parsed[1].1, "a b");
        assert_eq!(parsed[2].1, "");
        assert_eq!(parsed[3], ("flag".to_string(), String::new()));
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn every_business_route_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for route in ROUTES {
            assert!(seen.insert(*route), "重复登记 {route:?}");
        }
    }
}
