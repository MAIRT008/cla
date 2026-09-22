//! 启动参数与配置文件。状态目录必须显式给出绝对路径，不依赖当前工作目录；
//! 监听地址只允许回环，本单不提供公网监听设置。

use std::net::SocketAddr;
use std::path::PathBuf;

use serde_json::Value;

use crate::ControlError;

/// Tauri v2 在 Windows 上的 WebView 来源；页面经 fetch 调控制端时要过 CORS。
pub const DEFAULT_ALLOWED_ORIGINS: &[&str] = &["http://tauri.localhost", "https://tauri.localhost", "tauri://localhost"];

#[derive(Debug, Clone)]
pub struct ControlConfig {
    pub state_dir: PathBuf,
    pub config_path: Option<PathBuf>,
    pub bind: SocketAddr,
    pub bootstrap_stdin: bool,
    pub session_ttl_ms: i64,
    pub password_min_chars: usize,
    pub login_free_failures: u32,
    pub login_backoff_base_ms: i64,
    pub login_backoff_max_ms: i64,
    pub login_failure_window_ms: i64,
    pub allowed_origins: Vec<String>,
}

fn invalid(reason: impl Into<String>) -> ControlError {
    ControlError::new("CONTROL_CONFIG_INVALID", reason)
}

impl ControlConfig {
    /// 技术默认值：会话 12 小时，密码至少 12 个字符，连续失败 5 次后按 1 秒起翻倍退避、封顶 5 分钟，
    /// 15 分钟内无新失败则清零。均可由配置文件覆盖。
    pub fn for_state_dir(state_dir: PathBuf) -> ControlConfig {
        ControlConfig {
            state_dir,
            config_path: None,
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            bootstrap_stdin: false,
            session_ttl_ms: 12 * 60 * 60 * 1000,
            password_min_chars: 12,
            login_free_failures: 5,
            login_backoff_base_ms: 1_000,
            login_backoff_max_ms: 5 * 60 * 1000,
            login_failure_window_ms: 15 * 60 * 1000,
            allowed_origins: DEFAULT_ALLOWED_ORIGINS.iter().map(|item| item.to_string()).collect(),
        }
    }

    pub fn database_path(&self) -> PathBuf {
        self.state_dir.join("control.sqlite3")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.state_dir.join("logs")
    }

    pub fn setup_token_path(&self) -> PathBuf {
        self.state_dir.join("setup-token")
    }

    /// `--state-dir <绝对路径>` 必填；`--config <文件>`、`--bind <回环地址:端口>`、`--bootstrap-stdin` 可选。
    pub fn from_args(args: &[String]) -> Result<ControlConfig, ControlError> {
        let mut state_dir: Option<PathBuf> = None;
        let mut config_path: Option<PathBuf> = None;
        let mut bind: Option<String> = None;
        let mut bootstrap_stdin = false;
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            let value = || args.get(index + 1).cloned().ok_or_else(|| invalid(format!("{flag} 缺少取值")));
            match flag {
                "--state-dir" => {
                    state_dir = Some(PathBuf::from(value()?));
                    index += 2;
                }
                "--config" => {
                    config_path = Some(PathBuf::from(value()?));
                    index += 2;
                }
                "--bind" => {
                    bind = Some(value()?);
                    index += 2;
                }
                "--bootstrap-stdin" => {
                    bootstrap_stdin = true;
                    index += 1;
                }
                other => return Err(invalid(format!("不认识的启动参数 {other}"))),
            }
        }
        let state_dir = state_dir.ok_or_else(|| invalid("必须用 --state-dir 指定状态目录"))?;
        if !state_dir.is_absolute() {
            return Err(invalid("--state-dir 必须是绝对路径，控制端不依赖当前工作目录"));
        }
        let mut config = ControlConfig::for_state_dir(state_dir);
        config.config_path = config_path;
        config.bootstrap_stdin = bootstrap_stdin;
        if let Some(text) = bind {
            config.bind = parse_bind(&text)?;
        }
        Ok(config)
    }

    /// 读取配置文件。文件缺失、无法解析或含未知字段都算配置错误，不回落默认值。
    pub fn load_file(&mut self) -> Result<(), ControlError> {
        let path = match &self.config_path {
            Some(path) => path.clone(),
            None => return Ok(()),
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|error| invalid(format!("配置文件 {} 无法读取：{error}", path.to_string_lossy())))?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|error| invalid(format!("配置文件 {} 不是有效 JSON：{error}", path.to_string_lossy())))?;
        self.apply_json(&value)
    }

    pub fn apply_json(&mut self, value: &Value) -> Result<(), ControlError> {
        let object = value.as_object().ok_or_else(|| invalid("配置文件顶层必须是对象"))?;
        for (key, item) in object {
            match key.as_str() {
                "bind" => {
                    let text = item.as_str().ok_or_else(|| invalid("bind 必须是字符串"))?;
                    self.bind = parse_bind(text)?;
                }
                "session_ttl_seconds" => {
                    let seconds = ranged(item, key, 300, 30 * 24 * 60 * 60)?;
                    self.session_ttl_ms = seconds * 1000;
                }
                "password_min_chars" => self.password_min_chars = ranged(item, key, 8, 128)? as usize,
                "login_free_failures" => self.login_free_failures = ranged(item, key, 1, 20)? as u32,
                "login_backoff_base_ms" => self.login_backoff_base_ms = ranged(item, key, 100, 60_000)?,
                "login_backoff_max_ms" => self.login_backoff_max_ms = ranged(item, key, 1_000, 24 * 60 * 60 * 1000)?,
                "login_failure_window_ms" => self.login_failure_window_ms = ranged(item, key, 60_000, 24 * 60 * 60 * 1000)?,
                "allowed_origins" => {
                    let items = item.as_array().ok_or_else(|| invalid("allowed_origins 必须是字符串数组"))?;
                    let mut origins = Vec::new();
                    for origin in items {
                        let text = origin.as_str().ok_or_else(|| invalid("allowed_origins 必须是字符串数组"))?;
                        if text == "*" || text.is_empty() {
                            return Err(invalid("allowed_origins 不接受通配或空来源"));
                        }
                        origins.push(text.to_string());
                    }
                    self.allowed_origins = origins;
                }
                other => return Err(invalid(format!("配置文件含未知字段 {other}"))),
            }
        }
        if self.login_backoff_max_ms < self.login_backoff_base_ms {
            return Err(invalid("login_backoff_max_ms 不能小于 login_backoff_base_ms"));
        }
        Ok(())
    }
}

fn ranged(item: &Value, key: &str, min: i64, max: i64) -> Result<i64, ControlError> {
    let number = item.as_i64().ok_or_else(|| invalid(format!("{key} 必须是整数")))?;
    if number < min || number > max {
        return Err(invalid(format!("{key} 须在 {min} 到 {max} 之间")));
    }
    Ok(number)
}

fn parse_bind(text: &str) -> Result<SocketAddr, ControlError> {
    let address: SocketAddr = text
        .parse()
        .map_err(|_| invalid(format!("监听地址 {text} 不是 IP:端口 形式")))?;
    if !address.ip().is_loopback() {
        return Err(ControlError::new("CONTROL_BIND_NOT_LOOPBACK", format!("监听地址 {text} 不是回环地址；本版只允许同机回环部署")));
    }
    Ok(address)
}
