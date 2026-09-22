//! 账号规范化、密码哈希（Argon2id，盐取自系统安全随机源）、会话令牌与登录失败退避。

use std::collections::HashMap;
use std::sync::Mutex;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;

use crate::config::ControlConfig;
use crate::{random_hex, sha256_hex, ControlError};

const PASSWORD_MAX_BYTES: usize = 1024;
const SALT_BYTES: usize = 16;

/// 服务端统一规范化：去首尾空白、ASCII 小写；3—64 位，只含 a-z 0-9 . _ -，以字母或数字开头。
/// 不做 Unicode 归一，避免同形字符造出两个看起来相同的账号。
pub fn normalize_username(input: &str) -> Result<String, ControlError> {
    let normalized = input.trim().to_ascii_lowercase();
    let length_ok = (3..=64).contains(&normalized.len());
    let charset_ok = normalized
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-'));
    let first_ok = normalized.chars().next().map(|ch| ch.is_ascii_alphanumeric()).unwrap_or(false);
    if !(length_ok && charset_ok && first_ok) {
        return Err(ControlError::new(
            "CONTROL_REQUEST_INVALID",
            "账号须为 3—64 位字母、数字或 . _ -，并以字母或数字开头",
        ));
    }
    Ok(normalized)
}

pub fn validate_password(password: &str, config: &ControlConfig) -> Result<(), ControlError> {
    let chars = password.chars().count();
    if chars < config.password_min_chars || password.len() > PASSWORD_MAX_BYTES || password.trim().is_empty() {
        return Err(ControlError::new(
            "CONTROL_REQUEST_INVALID",
            format!("密码至少 {} 个字符，且不能全是空白", config.password_min_chars),
        ));
    }
    Ok(())
}

/// PHC 字符串形式的 Argon2id 哈希。盐由 getrandom 从系统安全随机源取得。
pub fn hash_password(password: &str) -> Result<String, ControlError> {
    let mut salt = [0u8; SALT_BYTES];
    getrandom::fill(&mut salt)
        .map_err(|error| ControlError::new("CONTROL_RANDOM_UNAVAILABLE", format!("系统安全随机源不可用：{error}")))?;
    let hashed: PasswordHash = Argon2::default()
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|error| ControlError::new("CONTROL_PASSWORD_HASH_FAILED", format!("密码哈希失败：{error}")))?;
    Ok(hashed.to_string())
}

pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// 256 位随机会话令牌；库里只存它的 SHA-256。
pub fn new_session_token() -> Result<String, ControlError> {
    random_hex(32)
}

pub fn token_digest(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

pub fn bearer_token(authorization: Option<&str>) -> Option<&str> {
    let value = authorization?.trim();
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy)]
struct FailureWindow {
    failures: u32,
    window_started_ms: i64,
    blocked_until_ms: i64,
}

/// 按规范化后的账号记连续失败次数，超过免罚次数后按指数退避。
/// 只在内存里：进程重启清零，这是「有限退避」的有意取舍，已写入 README。
#[derive(Default)]
pub struct LoginThrottle {
    entries: Mutex<HashMap<String, FailureWindow>>,
}

impl LoginThrottle {
    /// 仍在退避期内时返回还需等待的毫秒数。
    pub fn check(&self, key: &str, now_ms: i64) -> Result<(), i64> {
        let entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return Ok(()),
        };
        match entries.get(key) {
            Some(window) if window.blocked_until_ms > now_ms => Err(window.blocked_until_ms - now_ms),
            _ => Ok(()),
        }
    }

    pub fn record_failure(&self, key: &str, now_ms: i64, config: &ControlConfig) {
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return,
        };
        if entries.len() > 1024 {
            entries.retain(|_, window| now_ms - window.window_started_ms < config.login_failure_window_ms || window.blocked_until_ms > now_ms);
        }
        let window = entries.entry(key.to_string()).or_insert(FailureWindow {
            failures: 0,
            window_started_ms: now_ms,
            blocked_until_ms: 0,
        });
        if now_ms - window.window_started_ms >= config.login_failure_window_ms && window.blocked_until_ms <= now_ms {
            window.failures = 0;
            window.window_started_ms = now_ms;
        }
        window.failures += 1;
        if window.failures > config.login_free_failures {
            let exponent = (window.failures - config.login_free_failures - 1).min(20);
            let delay = config
                .login_backoff_base_ms
                .saturating_mul(1i64 << exponent)
                .min(config.login_backoff_max_ms);
            window.blocked_until_ms = now_ms + delay;
        }
    }

    pub fn clear(&self, key: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn usernames_are_normalized_on_the_server() {
        assert_eq!(normalize_username("  Admin.Ops ").unwrap(), "admin.ops");
        assert!(normalize_username("ab").is_err());
        assert!(normalize_username("-admin").is_err());
        assert!(normalize_username("管理员").is_err());
    }

    #[test]
    fn password_hash_is_argon2id_and_salted() {
        let first = hash_password("synthetic-Passw0rd!").unwrap();
        let second = hash_password("synthetic-Passw0rd!").unwrap();
        assert!(first.starts_with("$argon2id$"));
        assert_ne!(first, second, "每次哈希都换新盐");
        assert!(verify_password("synthetic-Passw0rd!", &first));
        assert!(!verify_password("synthetic-Passw0rd?", &first));
    }

    #[test]
    fn throttle_backs_off_after_free_failures() {
        let config = ControlConfig::for_state_dir(PathBuf::from("unused"));
        let throttle = LoginThrottle::default();
        for _ in 0..config.login_free_failures {
            throttle.record_failure("admin", 1_000, &config);
            assert!(throttle.check("admin", 1_000).is_ok());
        }
        throttle.record_failure("admin", 1_000, &config);
        assert_eq!(throttle.check("admin", 1_000), Err(config.login_backoff_base_ms));
        assert!(throttle.check("admin", 1_000 + config.login_backoff_base_ms).is_ok());
        throttle.clear("admin");
        assert!(throttle.check("admin", 1_000).is_ok());
    }
}
