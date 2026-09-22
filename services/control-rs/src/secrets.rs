//! 可恢复秘密（模型 Key、Remnawave 地址与管理令牌、订阅链接、个人接入凭据）的保存。
//!
//! 数据库只存密文与引用：`control_secrets.ciphertext` 由 `SecretProtector` 生成，
//! 业务表只保存 `secret_ref`。产品路径在 Windows 上用当前用户范围的 DPAPI（CryptProtectData），
//! 以 `ai-steward-control/secret/<用途>` 作为附加熵，把密文绑定到用途：换一个用途读同一段密文会失败。
//! 其他平台没有接入系统保护能力，写秘密直接报 CONTROL_SECRET_PROTECTION_UNAVAILABLE，不退回明文或固定密钥。
//!
//! 读取失败（密文被改、换了保护方式、跨用途）一律回 CONTROL_SECRET_UNREADABLE，不回显密文或明文。

use rusqlite::{params, Connection, OptionalExtension};

use crate::store::{read_failed, write_failed};
use crate::{iso_from_millis, random_hex, ControlError};

pub trait SecretProtector: Send + Sync {
    /// 写进 `control_secrets.protector` 的保护方式名。读取时方式不符即拒绝。
    fn kind(&self) -> &'static str;
    fn protect(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, ControlError>;
    fn unprotect(&self, ciphertext: &[u8], purpose: &str) -> Result<Vec<u8>, ControlError>;
}

pub fn system_protector() -> Box<dyn SecretProtector> {
    #[cfg(windows)]
    return Box::new(dpapi::DpapiProtector);
    #[cfg(not(windows))]
    return Box::new(UnavailableProtector);
}

/// 没有系统保护能力的平台。
pub struct UnavailableProtector;

impl SecretProtector for UnavailableProtector {
    fn kind(&self) -> &'static str {
        "unavailable"
    }

    fn protect(&self, _plaintext: &[u8], _purpose: &str) -> Result<Vec<u8>, ControlError> {
        Err(ControlError::new(
            "CONTROL_SECRET_PROTECTION_UNAVAILABLE",
            "本平台没有接入系统秘密保护能力，拒绝保存秘密",
        ))
    }

    fn unprotect(&self, _ciphertext: &[u8], _purpose: &str) -> Result<Vec<u8>, ControlError> {
        Err(ControlError::new(
            "CONTROL_SECRET_PROTECTION_UNAVAILABLE",
            "本平台没有接入系统秘密保护能力，无法读取秘密",
        ))
    }
}

#[cfg(windows)]
mod dpapi {
    use std::ptr;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    use super::SecretProtector;
    use crate::ControlError;

    const ENTROPY_PREFIX: &str = "ai-steward-control/secret/";

    /// 当前 Windows 用户范围（不带 CRYPTPROTECT_LOCAL_MACHINE），禁止弹任何界面。
    pub struct DpapiProtector;

    fn input_blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: bytes.len() as u32, pbData: bytes.as_ptr() as *mut u8 }
    }

    /// 复制系统分配的输出缓冲区后立即用 LocalFree 释放。
    fn take_output(output: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        if output.pbData.is_null() {
            return Vec::new();
        }
        let copied = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
        unsafe {
            LocalFree(output.pbData as _);
        }
        copied
    }

    impl SecretProtector for DpapiProtector {
        fn kind(&self) -> &'static str {
            "windows-dpapi-current-user"
        }

        fn protect(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, ControlError> {
            let entropy_text = format!("{ENTROPY_PREFIX}{purpose}");
            let input = input_blob(plaintext);
            let entropy = input_blob(entropy_text.as_bytes());
            let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
            let ok = unsafe {
                CryptProtectData(&input, ptr::null(), &entropy, ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            };
            if ok == 0 {
                return Err(ControlError::new(
                    "CONTROL_SECRET_PROTECT_FAILED",
                    format!("DPAPI 加密失败：{}", std::io::Error::last_os_error()),
                ));
            }
            Ok(take_output(output))
        }

        fn unprotect(&self, ciphertext: &[u8], purpose: &str) -> Result<Vec<u8>, ControlError> {
            let entropy_text = format!("{ENTROPY_PREFIX}{purpose}");
            let input = input_blob(ciphertext);
            let entropy = input_blob(entropy_text.as_bytes());
            let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
            let ok = unsafe {
                CryptUnprotectData(&input, ptr::null_mut(), &entropy, ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            };
            if ok == 0 {
                return Err(ControlError::new(
                    "CONTROL_SECRET_UNREADABLE",
                    format!("DPAPI 解密失败：{}", std::io::Error::last_os_error()),
                ));
            }
            Ok(take_output(output))
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretMeta {
    pub secret_ref: String,
    pub version: i64,
    pub updated_at: String,
    pub protector: String,
}

/// 写入或轮换一个秘密。`existing` 指向同一用途的旧引用时原地轮换（版本号加一，引用不变）；
/// 否则新建引用。调用方在一个写事务里调用它，与业务表的引用更新一起提交。
pub fn put_secret(
    connection: &Connection,
    protector: &dyn SecretProtector,
    existing: Option<&str>,
    purpose: &str,
    plaintext: &[u8],
    now_ms: i64,
) -> Result<String, ControlError> {
    let ciphertext = protector.protect(plaintext, purpose)?;
    let now = iso_from_millis(now_ms);
    if let Some(secret_ref) = existing {
        let changed = connection
            .execute(
                "UPDATE control_secrets SET ciphertext = ?1, protector = ?2, version = version + 1, updated_at = ?3 WHERE secret_ref = ?4 AND purpose = ?5",
                params![ciphertext, protector.kind(), now, secret_ref, purpose],
            )
            .map_err(write_failed)?;
        if changed == 1 {
            return Ok(secret_ref.to_string());
        }
    }
    let secret_ref = format!("sec-{}", random_hex(12)?);
    connection
        .execute(
            "INSERT INTO control_secrets (secret_ref, purpose, protector, ciphertext, version, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
            params![secret_ref, purpose, protector.kind(), ciphertext, now],
        )
        .map_err(write_failed)?;
    Ok(secret_ref)
}

/// 解出明文。用途、保护方式、密文任一不符都回 CONTROL_SECRET_UNREADABLE。
pub fn read_secret(
    connection: &Connection,
    protector: &dyn SecretProtector,
    secret_ref: &str,
    purpose: &str,
) -> Result<Vec<u8>, ControlError> {
    let row: Option<(String, String, Vec<u8>)> = connection
        .query_row(
            "SELECT purpose, protector, ciphertext FROM control_secrets WHERE secret_ref = ?1",
            params![secret_ref],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(read_failed)?;
    let (stored_purpose, stored_protector, ciphertext) =
        row.ok_or_else(|| ControlError::new("CONTROL_SECRET_MISSING", "秘密引用在库里不存在"))?;
    if stored_purpose != purpose {
        return Err(ControlError::new("CONTROL_SECRET_UNREADABLE", "秘密的用途与读取方不符"));
    }
    if stored_protector != protector.kind() {
        return Err(ControlError::new(
            "CONTROL_SECRET_UNREADABLE",
            format!("秘密由 {stored_protector} 保护，当前保护方式是 {}", protector.kind()),
        ));
    }
    protector
        .unprotect(&ciphertext, purpose)
        .map_err(|error| ControlError::new("CONTROL_SECRET_UNREADABLE", error.reason))
}

pub fn read_secret_text(
    connection: &Connection,
    protector: &dyn SecretProtector,
    secret_ref: &str,
    purpose: &str,
) -> Result<String, ControlError> {
    let bytes = read_secret(connection, protector, secret_ref, purpose)?;
    String::from_utf8(bytes).map_err(|_| ControlError::new("CONTROL_SECRET_UNREADABLE", "秘密解密后不是 UTF-8 文本"))
}

pub fn delete_secret(connection: &Connection, secret_ref: &str) -> Result<(), ControlError> {
    connection
        .execute("DELETE FROM control_secrets WHERE secret_ref = ?1", params![secret_ref])
        .map(|_| ())
        .map_err(write_failed)
}

pub fn secret_meta(connection: &Connection, secret_ref: Option<&str>) -> Result<Option<SecretMeta>, ControlError> {
    let secret_ref = match secret_ref {
        Some(value) => value,
        None => return Ok(None),
    };
    connection
        .query_row(
            "SELECT secret_ref, version, updated_at, protector FROM control_secrets WHERE secret_ref = ?1",
            params![secret_ref],
            |row| {
                Ok(SecretMeta {
                    secret_ref: row.get(0)?,
                    version: row.get(1)?,
                    updated_at: row.get(2)?,
                    protector: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(read_failed)
}
