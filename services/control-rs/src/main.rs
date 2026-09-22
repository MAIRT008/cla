//! 控制端可执行入口。
//!
//! 顺序：解析参数 → 建本轮日志 → 读配置 → 打开数据库 → 准备首启凭据 → 绑定回环监听 → 就绪握手。
//! 每一步失败都先写日志，再在 stdout 打一行 `{"event":"failed",...}` 并以非零码退出：
//! 2 参数/配置，3 数据库，4 监听，5 其他。
//!
//! 由宿主托管时带 `--bootstrap-stdin`：首行从 stdin 读宿主生成的一次性首启凭据；
//! 之后 stdin 关闭（宿主退出或主动停止）即优雅退出。独立运行时首启凭据写到 state 目录的 setup-token 文件。

use std::io::{BufRead, Write};
use std::sync::Arc;

use ai_steward_control::config::ControlConfig;
use ai_steward_control::logging::{redact_text, Logger};
use ai_steward_control::router::{handle_with_cancel, ApiRequest, ApiResponse};
use ai_steward_control::{random_hex, system_clock, App, CancelToken, ControlError, PROTOCOL_VERSION, SERVICE_NAME, SERVICE_VERSION};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use serde_json::{json, Value};

const EXIT_CONFIG: i32 = 2;
const EXIT_STORE: i32 = 3;
const EXIT_BIND: i32 = 4;
const EXIT_OTHER: i32 = 5;

fn main() {
    std::process::exit(run());
}

/// 就绪/失败握手写 stdout，一行一个 JSON；宿主只认这两种事件。
fn emit(line: Value) {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn fail(logger: Option<&Logger>, stage: &str, exit_code: i32, error: &ControlError) -> i32 {
    if let Some(logger) = logger {
        logger.error("process.exit", None, json!({"stage": stage, "exit_code": exit_code, "code": error.code, "detail": error.reason}));
    }
    emit(json!({
        "event": "failed",
        "stage": stage,
        "code": error.code,
        "reason": redact_text(&error.reason),
        "exit_code": exit_code,
        "log_file": logger.map(|item| item.path().to_string_lossy().to_string()),
        "log_status": logger.map(|item| item.status()),
    }));
    exit_code
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let instance_ref = match random_hex(12) {
        Ok(hex) => format!("ctl-{hex}"),
        Err(error) => return fail(None, "random", EXIT_OTHER, &error),
    };
    let mut config = match ControlConfig::from_args(&args) {
        Ok(config) => config,
        Err(error) => {
            let code = if error.code == "CONTROL_BIND_NOT_LOOPBACK" { EXIT_BIND } else { EXIT_CONFIG };
            return fail(None, "arguments", code, &error);
        }
    };

    let logger = Arc::new(Logger::create(&config.log_dir(), &instance_ref));
    let panic_logger = logger.clone();
    std::panic::set_hook(Box::new(move |info| {
        panic_logger.error("process.panic", None, json!({"detail": redact_text(&info.to_string())}));
    }));
    logger.info(
        "startup.begin",
        None,
        json!({
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "protocol": PROTOCOL_VERSION,
            "pid": std::process::id(),
            "state_dir": config.state_dir.to_string_lossy(),
            "managed": config.bootstrap_stdin,
        }),
    );

    if let Err(error) = config.load_file() {
        let code = if error.code == "CONTROL_BIND_NOT_LOOPBACK" { EXIT_BIND } else { EXIT_CONFIG };
        return fail(Some(&*logger), "config", code, &error);
    }
    logger.info(
        "config.loaded",
        None,
        json!({
            "config_file": config.config_path.as_ref().map(|path| path.to_string_lossy().to_string()),
            "bind": config.bind.to_string(),
            "session_ttl_ms": config.session_ttl_ms,
            "password_min_chars": config.password_min_chars,
            "login_free_failures": config.login_free_failures,
            "allowed_origins": config.allowed_origins,
        }),
    );

    // 托管模式下首启凭据由宿主经 stdin 交付，必须在打开数据库之前读掉这一行。
    let delivered = if config.bootstrap_stdin {
        match read_bootstrap_line() {
            Ok(token) => Some(token),
            Err(error) => return fail(Some(&*logger), "bootstrap", EXIT_CONFIG, &error),
        }
    } else {
        None
    };

    let app = match App::open(config, logger.clone(), system_clock()) {
        Ok(app) => Arc::new(app),
        Err(error) => return fail(Some(&*logger), "store", EXIT_STORE, &error),
    };

    match app.store.is_initialized() {
        Ok(true) => {
            app.retire_setup_token();
            logger.info("setup.state", None, json!({"initialized": true}));
        }
        Ok(false) => {
            if let Err(error) = prepare_setup_token(&app, delivered) {
                return fail(Some(&*logger), "setup", EXIT_OTHER, &error);
            }
        }
        Err(error) => return fail(Some(&*logger), "store", EXIT_STORE, &error),
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            return fail(Some(&*logger), "runtime", EXIT_OTHER, &ControlError::new("CONTROL_RUNTIME_FAILED", error.to_string()));
        }
    };
    let (exit_code, outcome) = runtime.block_on(serve(app.clone()));
    match outcome {
        Ok(()) => {
            logger.info("process.exit", None, json!({"exit_code": 0}));
            0
        }
        Err((stage, error)) => fail(Some(&*logger), stage, exit_code, &error),
    }
}

fn read_bootstrap_line() -> Result<String, ControlError> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| ControlError::new("CONTROL_BOOTSTRAP_INVALID", format!("无法从宿主读取首启凭据：{error}")))?;
    let value: Value = serde_json::from_str(line.trim())
        .map_err(|_| ControlError::new("CONTROL_BOOTSTRAP_INVALID", "宿主交付的首启材料不是 JSON"))?;
    let token = value
        .get("setup_token")
        .and_then(Value::as_str)
        .filter(|token| token.len() >= 32 && token.chars().all(|ch| ch.is_ascii_hexdigit()))
        .ok_or_else(|| ControlError::new("CONTROL_BOOTSTRAP_INVALID", "宿主交付的首启凭据缺失或格式不对"))?;
    Ok(token.to_string())
}

fn prepare_setup_token(app: &App, delivered: Option<String>) -> Result<(), ControlError> {
    match delivered {
        Some(token) => {
            app.set_setup_token(&token);
            app.logger.info("setup.state", None, json!({"initialized": false, "bootstrap_source": "host_stdin"}));
        }
        None => {
            let token = random_hex(32)?;
            let path = app.config.setup_token_path();
            std::fs::write(&path, format!("{token}\n")).map_err(|error| {
                ControlError::new("CONTROL_SETUP_TOKEN_WRITE_FAILED", format!("首启凭据文件无法写入：{error}"))
            })?;
            app.set_setup_token(&token);
            app.logger.info(
                "setup.state",
                None,
                json!({"initialized": false, "bootstrap_source": "state_file", "bootstrap_file": path.to_string_lossy()}),
            );
        }
    }
    Ok(())
}

async fn serve(app: Arc<App>) -> (i32, Result<(), (&'static str, ControlError)>) {
    let listener = match tokio::net::TcpListener::bind(app.config.bind).await {
        Ok(listener) => listener,
        Err(error) => {
            let failure = ControlError::new("CONTROL_BIND_FAILED", format!("无法监听 {}：{error}", app.config.bind));
            return (EXIT_BIND, Err(("bind", failure)));
        }
    };
    let local = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => return (EXIT_BIND, Err(("bind", ControlError::new("CONTROL_BIND_FAILED", error.to_string())))),
    };
    app.logger.info("listen.bound", None, json!({"listen": local.to_string()}));
    emit(json!({
        "event": "ready",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "protocol": PROTOCOL_VERSION,
        "instance_ref": app.instance_ref,
        "listen": local.to_string(),
        "log_file": app.logger.path().to_string_lossy(),
        "log_status": app.logger.status(),
    }));

    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<&'static str>();
    // 独立运行时没有停止通道：发送端一直留在这里，服务运行到进程被结束为止。
    let mut idle_sender = Some(stop_sender);
    if app.config.bootstrap_stdin {
        if let Some(sender) = idle_sender.take() {
            std::thread::spawn(move || {
                let stdin = std::io::stdin();
                let mut line = String::new();
                loop {
                    line.clear();
                    match stdin.lock().read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if line.trim() == "stop" => break,
                        Ok(_) => {}
                    }
                }
                let _ = sender.send("host_channel_closed");
            });
        }
    }
    let shutdown_app = app.clone();
    let shutdown = async move {
        let reason = stop_receiver.await.unwrap_or("stop_channel_dropped");
        shutdown_app.logger.info("shutdown.requested", None, json!({"reason": reason}));
    };

    let router = axum::Router::new().fallback(dispatch).with_state(app.clone());
    let served = axum::serve(listener, router).with_graceful_shutdown(shutdown).await;
    drop(idle_sender);
    match served {
        Ok(()) => (0, Ok(())),
        Err(error) => (EXIT_OTHER, Err(("serve", ControlError::new("CONTROL_SERVE_FAILED", error.to_string())))),
    }
}

/// 页面在请求处理完之前断开时，axum 丢弃处理 future；守卫随之置位取消令牌，
/// 正在 blocking 线程里做外部调用的业务在下一个检查点停下（模型回 AI_ABORTED，配额回 AUTHORITY_CANCELLED）。
struct CancelOnDrop {
    token: CancelToken,
    finished: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.finished {
            self.token.cancel();
        }
    }
}

/// 把 axum 请求翻译成框架无关的 ApiRequest。SQLite、Argon2 与出站 HTTP 都是阻塞调用，放到 blocking 线程池里跑。
/// 路径带上查询串（管理接口用 `?user_ref=`），由路由自己拆分。
async fn dispatch(State(app): State<Arc<App>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let request = ApiRequest {
        method: method.as_str().to_string(),
        path: uri.path_and_query().map(|value| value.as_str().to_string()).unwrap_or_else(|| uri.path().to_string()),
        headers: headers
            .iter()
            .filter_map(|(name, value)| value.to_str().ok().map(|text| (name.as_str().to_string(), text.to_string())))
            .collect(),
        body: body.to_vec(),
    };
    let mut guard = CancelOnDrop { token: CancelToken::new(), finished: false };
    let cancel = guard.token.clone();
    let worker = app.clone();
    let outcome = tokio::task::spawn_blocking(move || handle_with_cancel(&worker, &request, &cancel)).await;
    guard.finished = true;
    let response = match outcome {
        Ok(response) => response,
        Err(error) => {
            app.logger.error("request.worker_failed", None, json!({"detail": error.to_string()}));
            ApiResponse::error(500, "CONTROL_INTERNAL", "控制端处理请求时异常，详见控制端日志", "req-unavailable")
        }
    };
    let mut builder = axum::http::Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(Body::from(response.body)).unwrap_or_else(|_| {
        let mut fallback = Response::new(Body::empty());
        *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        fallback
    })
}
