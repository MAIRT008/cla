//! 本应用控制端。可执行程序（main.rs）与进程内测试共用这里的配置、数据库与路由。
//! 路由不依赖 HTTP 框架：`router::handle` 吃一个 `ApiRequest`，吐一个 `ApiResponse`，
//! main.rs 只负责把 axum 的请求翻译过来。
//!
//! 外部依赖只有两个注入点：秘密保护器（产品路径是当前用户 DPAPI）与出站 HTTP 传输
//! （产品路径是 ureq）。测试注入确定性保护器与脚本化传输，本机不向真实模型或配额服务发请求。

pub mod admin_users;
pub mod ai;
pub mod api;
pub mod assignments;
pub mod auth;
pub mod config;
pub mod events;
pub mod http;
pub mod logging;
pub mod probes;
pub mod provider;
pub mod quota;
pub mod redact;
pub mod remnawave;
pub mod resources;
pub mod router;
pub mod secrets;
pub mod store;

use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

pub use config::ControlConfig;
pub use http::{CancelToken, HttpTransport};
pub use logging::Logger;
pub use router::{handle, handle_with_cancel, ApiRequest, ApiResponse};
pub use secrets::SecretProtector;
pub use store::Store;

pub const SERVICE_NAME: &str = "ai-steward-control";
pub const PROTOCOL_VERSION: &str = "steward-control-1";
pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 带稳定错误码的失败。`reason` 面向使用者，已脱敏；细节只进日志。
#[derive(Debug, Clone)]
pub struct ControlError {
    pub code: &'static str,
    pub reason: String,
}

impl ControlError {
    pub fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Self { code, reason: reason.into() }
    }
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.reason)
    }
}

pub type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Box::new(now_millis)
}

pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or_default()
}

/// UTC 毫秒转 ISO 8601，算法与宿主 commands.rs 的 iso_from_millis 相同。
pub fn iso_from_millis(millis: i64) -> String {
    let total_seconds = millis.div_euclid(1000);
    let sub = millis.rem_euclid(1000);
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = if month_position < 10 { month_position + 3 } else { month_position - 9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60,
        sub
    )
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn digits(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

/// 解析 ISO 8601 / RFC 3339 时间为 UTC 毫秒：`YYYY-MM-DD`（按 UTC 零点），
/// 或 `YYYY-MM-DDTHH:MM[:SS[.fff]]` 加 `Z` / `±HH:MM`。其他写法一律不认，返回 None。
pub fn millis_from_iso(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.len() < 10 || !text.is_ascii() {
        return None;
    }
    let year = digits(&text[0..4])?;
    if &text[4..5] != "-" || &text[7..8] != "-" {
        return None;
    }
    let month = digits(&text[5..7])?;
    let day = digits(&text[8..10])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if text.len() == 10 {
        return Some(days * 86_400_000);
    }
    let separator = &text[10..11];
    if separator != "T" && separator != "t" && separator != " " {
        return None;
    }
    let rest = &text[11..];
    let zone_at = rest.find(|ch: char| ch == 'Z' || ch == 'z' || ch == '+' || ch == '-')?;
    let (clock, zone) = rest.split_at(zone_at);
    let mut parts = clock.split(':');
    let hour = digits(parts.next()?)?;
    let minute = digits(parts.next()?)?;
    let (second, fraction_ms) = match parts.next() {
        None => (0, 0),
        Some(seconds) => match seconds.split_once('.') {
            None => (digits(seconds)?, 0),
            Some((whole, fraction)) => {
                let whole = digits(whole)?;
                digits(fraction)?;
                let padded = format!("{fraction:0<3}");
                (whole, digits(&padded[0..3])?)
            }
        },
    };
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let offset_minutes = if zone.eq_ignore_ascii_case("z") {
        0
    } else {
        let sign = if zone.starts_with('-') { -1 } else { 1 };
        let (offset_hour, offset_minute) = zone[1..].split_once(':')?;
        sign * (digits(offset_hour)? * 60 + digits(offset_minute)?)
    };
    let local = days * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1000 + fraction_ms;
    Some(local - offset_minutes * 60_000)
}

/// 系统安全随机源（getrandom）取 `bytes` 个字节，转成小写十六进制。
pub fn random_hex(bytes: usize) -> Result<String, ControlError> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer)
        .map_err(|error| ControlError::new("CONTROL_RANDOM_UNAVAILABLE", format!("系统安全随机源不可用：{error}")))?;
    Ok(to_hex(&buffer))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    to_hex(Sha256::digest(bytes).as_slice())
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 键按字典序重排后的紧凑 JSON，用于幂等签名与操作摘要；与字段书写顺序无关。
pub fn canonical_json(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut copy = Map::new();
                for key in keys {
                    copy.insert(key.clone(), sorted(&map[key.as_str()]));
                }
                Value::Object(copy)
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    sorted(value).to_string()
}

/// 定长比较，避免按前缀逐字节提前返回。
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let a = left.as_bytes();
    let b = right.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 外部能力的注入点。产品路径用 `production()`；测试注入确定性实现。
pub struct Dependencies {
    pub protector: Box<dyn SecretProtector>,
    pub transport: Arc<dyn HttpTransport>,
}

impl Dependencies {
    pub fn production() -> Dependencies {
        Dependencies {
            protector: secrets::system_protector(),
            transport: Arc::new(http::UreqTransport),
        }
    }
}

/// 一次运行的服务实例：配置、数据库、日志、首启凭据摘要、登录退避与外部能力都挂在这里。
pub struct App {
    pub config: ControlConfig,
    pub store: Store,
    pub logger: Arc<Logger>,
    pub instance_ref: String,
    pub started_at: String,
    pub clock: Clock,
    pub throttle: auth::LoginThrottle,
    pub protector: Box<dyn SecretProtector>,
    pub transport: Arc<dyn HttpTransport>,
    setup_token_sha256: Mutex<Option<String>>,
    dummy_password_hash: String,
}

impl App {
    /// 打开数据库并用产品路径的外部能力（DPAPI、ureq）。库损坏、不是本服务的库或版本过新都直接失败。
    pub fn open(config: ControlConfig, logger: Arc<Logger>, clock: Clock) -> Result<App, ControlError> {
        App::open_with(config, logger, clock, Dependencies::production())
    }

    /// 同 `open`，外部能力由调用方给出。RC1 库在这里按事务升级到当前结构版本。
    pub fn open_with(config: ControlConfig, logger: Arc<Logger>, clock: Clock, dependencies: Dependencies) -> Result<App, ControlError> {
        let database = config.database_path();
        logger.info("store.open.begin", None, json!({"path": database.to_string_lossy()}));
        let store = match Store::open(&database, &*clock) {
            Ok(store) => store,
            Err(error) => {
                logger.error("store.open.failed", None, json!({"code": error.code, "detail": error.reason}));
                return Err(error);
            }
        };
        let initialized = store.is_initialized()?;
        logger.info(
            "store.open.ok",
            None,
            json!({
                "initialized": initialized,
                "created": store.created_now(),
                "schema_version": store::SCHEMA_VERSION,
                "migrated_from": store.migrated_from(),
                "secret_protector": dependencies.protector.kind(),
            }),
        );
        let dummy_password_hash = auth::hash_password("steward-timing-equalizer")?;
        Ok(App {
            instance_ref: logger.instance_ref().to_string(),
            started_at: iso_from_millis(clock()),
            config,
            store,
            logger,
            clock,
            throttle: auth::LoginThrottle::default(),
            protector: dependencies.protector,
            transport: dependencies.transport,
            setup_token_sha256: Mutex::new(None),
            dummy_password_hash,
        })
    }

    /// 首启凭据只留摘要；明文由宿主控制通道或 state 目录里的一次性文件交付。
    pub fn set_setup_token(&self, token: &str) {
        if let Ok(mut slot) = self.setup_token_sha256.lock() {
            *slot = Some(sha256_hex(token.as_bytes()));
        }
    }

    pub fn setup_token_matches(&self, candidate: &str) -> bool {
        let expected = match self.setup_token_sha256.lock() {
            Ok(slot) => slot.clone(),
            Err(_) => None,
        };
        match expected {
            Some(expected) => constant_time_eq(&expected, &sha256_hex(candidate.as_bytes())),
            None => false,
        }
    }

    pub fn setup_token_pending(&self) -> bool {
        self.setup_token_sha256.lock().map(|slot| slot.is_some()).unwrap_or(false)
    }

    /// 首启完成后作废凭据，并删掉独立运行时写出的凭据文件。
    pub fn retire_setup_token(&self) {
        if let Ok(mut slot) = self.setup_token_sha256.lock() {
            *slot = None;
        }
        let path = self.config.setup_token_path();
        if path.exists() {
            if let Err(error) = std::fs::remove_file(&path) {
                self.logger.warn("setup.token_file.remove_failed", None, json!({"path": path.to_string_lossy(), "detail": error.to_string()}));
            }
        }
    }

    pub fn dummy_password_hash(&self) -> &str {
        &self.dummy_password_hash
    }

    pub fn now(&self) -> i64 {
        (self.clock)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trips_and_accepts_offsets() {
        let millis = 1_789_000_000_123;
        assert_eq!(millis_from_iso(&iso_from_millis(millis)), Some(millis));
        assert_eq!(millis_from_iso("2027-01-01"), millis_from_iso("2027-01-01T00:00:00.000Z"));
        assert_eq!(millis_from_iso("2027-01-01T08:00:00+08:00"), millis_from_iso("2027-01-01T00:00:00Z"));
        assert_eq!(millis_from_iso("2027-01-01T00:00Z"), millis_from_iso("2027-01-01T00:00:00Z"));
        assert!(millis_from_iso("2027-13-01T00:00:00Z").is_none());
        assert!(millis_from_iso("not a date").is_none());
        assert!(millis_from_iso("2027-01-01T00:00:00").is_none(), "没有时区的时间不猜");
    }

    #[test]
    fn canonical_json_ignores_key_order() {
        let left: Value = serde_json::from_str(r#"{"b":1,"a":{"d":[1,{"z":1,"y":2}],"c":null}}"#).unwrap();
        let right: Value = serde_json::from_str(r#"{"a":{"c":null,"d":[1,{"y":2,"z":1}]},"b":1}"#).unwrap();
        assert_eq!(canonical_json(&left), canonical_json(&right));
    }
}
