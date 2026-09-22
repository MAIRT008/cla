//! 服务状态与受管配置文件（新增，取代上游 `desired.rs` 的 desired-state 文件与调用方给出的 config_path）。

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::auth::{parse_link_key, sha256_hex};
use crate::core::config::MAX_CONFIG_BYTES;
use crate::core::network::{ConfigStore, StateStore};
use crate::core::paths::{is_within, valid_user_sid, ServicePaths};
use crate::core::structure::ServiceError;

fn io_error(code: &str, error: std::io::Error) -> ServiceError {
    ServiceError::new(code, error.to_string())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ServiceError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_error("SERVICE_STATE_UNWRITABLE", error))?;
    }
    let staging = path.with_extension("tmp");
    fs::write(&staging, bytes).map_err(|error| io_error("SERVICE_STATE_UNWRITABLE", error))?;
    fs::rename(&staging, path).map_err(|error| io_error("SERVICE_STATE_UNWRITABLE", error))
}

pub struct FileStateStore {
    path: PathBuf,
}

impl FileStateStore {
    pub fn new(paths: &ServicePaths) -> FileStateStore {
        FileStateStore { path: paths.runtime_state() }
    }
}

impl StateStore for FileStateStore {
    fn load(&self) -> Result<Option<Value>, ServiceError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| ServiceError::new("SERVICE_STATE_CORRUPT", "服务状态文件无法解析")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error("SERVICE_STATE_UNREADABLE", error)),
        }
    }

    fn save(&self, state: &Value) -> Result<(), ServiceError> {
        let bytes = serde_json::to_vec_pretty(state).map_err(|_| ServiceError::new("SERVICE_STATE_UNWRITABLE", "服务状态无法序列化"))?;
        write_atomic(&self.path, &bytes)
    }
}

/// 安装器写下的批准记录：哪个本机用户可以连服务 pipe、该用户的产品网络状态根在哪、宿主程序在哪。
/// `host_executable` 是安装器规范化后的受保护路径，服务按它核对 pipe 客户端进程。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRecord {
    pub approved_user_sid: String,
    pub network_root: String,
    pub host_executable: String,
    pub installed_at_ms: i64,
    pub service_version: String,
}

pub fn read_install_record(paths: &ServicePaths) -> Result<Option<InstallRecord>, ServiceError> {
    match fs::read(paths.install_record()) {
        Ok(bytes) => {
            let record: InstallRecord = serde_json::from_slice(&bytes)
                .map_err(|_| ServiceError::new("INSTALL_RECORD_INVALID", "安装记录无法解析"))?;
            if !valid_user_sid(&record.approved_user_sid)
                || !Path::new(&record.network_root).is_absolute()
                || !Path::new(&record.host_executable).is_absolute()
            {
                return Err(ServiceError::new("INSTALL_RECORD_INVALID", "安装记录里的用户、网络根或宿主程序不合法"));
            }
            Ok(Some(record))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error("INSTALL_RECORD_UNREADABLE", error)),
    }
}

pub fn write_install_record(paths: &ServicePaths, record: &InstallRecord) -> Result<(), ServiceError> {
    let bytes = serde_json::to_vec_pretty(record).map_err(|_| ServiceError::new("INSTALL_RECORD_INVALID", "安装记录无法序列化"))?;
    write_atomic(&paths.install_record(), &bytes)
}

pub fn read_link_key(paths: &ServicePaths) -> Result<Vec<u8>, ServiceError> {
    let text = fs::read_to_string(paths.host_link_key()).map_err(|error| io_error("LINK_KEY_UNAVAILABLE", error))?;
    parse_link_key(&text)
}

pub struct FileConfigStore {
    configs_dir: PathBuf,
    draft_root: Option<PathBuf>,
}

impl FileConfigStore {
    pub fn new(paths: &ServicePaths, install: Option<&InstallRecord>) -> FileConfigStore {
        FileConfigStore {
            configs_dir: paths.configs_dir(),
            draft_root: install.map(|record| PathBuf::from(&record.network_root).join("drafts")),
        }
    }
}

impl ConfigStore for FileConfigStore {
    fn approved_draft_root(&self) -> Option<PathBuf> {
        self.draft_root.clone()
    }

    /// 词法核对之后再按真实路径复核：用户可写目录里的链接或联接指到别处就拒绝。
    fn read_draft(&self, draft: &Path) -> Result<Vec<u8>, ServiceError> {
        let root = self.draft_root.as_ref().ok_or_else(|| ServiceError::new("DRAFT_ROOT_UNAPPROVED", "没有批准的草稿目录"))?;
        let real_root = fs::canonicalize(root).map_err(|error| io_error("DRAFT_UNREADABLE", error))?;
        let real_draft = fs::canonicalize(draft).map_err(|error| io_error("DRAFT_UNREADABLE", error))?;
        if !is_within(&real_root, &real_draft) {
            return Err(ServiceError::new("DRAFT_PATH_REJECTED", "草稿真实路径不在批准目录下"));
        }
        let metadata = fs::metadata(&real_draft).map_err(|error| io_error("DRAFT_UNREADABLE", error))?;
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES as u64 {
            return Err(ServiceError::new("DRAFT_PATH_REJECTED", "草稿不是大小合规的普通文件"));
        }
        fs::read(&real_draft).map_err(|error| io_error("DRAFT_UNREADABLE", error))
    }

    fn store(&self, sha256: &str, bytes: &[u8]) -> Result<PathBuf, ServiceError> {
        let path = self.configs_dir.join(format!("{sha256}.yaml"));
        if sha256_hex(bytes) != sha256 {
            return Err(ServiceError::new("CONFIG_DIGEST_MISMATCH", "保存前摘要复核不一致"));
        }
        if let Ok(existing) = fs::read(&path) {
            if sha256_hex(&existing) == sha256 {
                return Ok(path);
            }
        }
        write_atomic(&path, bytes)?;
        Ok(path)
    }

    fn stored_path(&self, sha256: &str) -> Option<PathBuf> {
        let path = self.configs_dir.join(format!("{sha256}.yaml"));
        let bytes = fs::read(&path).ok()?;
        (sha256_hex(&bytes) == sha256).then_some(path)
    }
}
