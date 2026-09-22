//! 控制端持久库（SQLite，WAL）。用户、会话、首启状态与全部业务记录在同一个库里。
//!
//! 打开规则：
//! - 文件不存在：在一个事务里建 v1 结构、叠加 v2、v3 迁移，直接落成当前版本；
//! - 文件已存在：先做 quick_check，再核对 control_meta 的归属与版本；
//!   损坏、不是 SQLite、不是本服务的库、版本比程序新，一律拒绝启动，绝不当成空库重建或覆盖；
//! - v1（RC1）或 v2（RC2/RC3）库：在原路径用一个 IMMEDIATE 事务逐级升级到当前版本。迁移只建新表、改版本号，
//!   不动已有表里的数据；任一步失败整体回滚，库保持原版本且服务不启动。
//!
//! 业务模块经 `read` / `write` 拿到连接或 IMMEDIATE 事务，自己写 SQL；
//! 外部 HTTP 调用不得在这两个闭包里进行，避免长时间占住数据库句柄。

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{params, Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior};

use crate::{iso_from_millis, ControlError};

pub const SCHEMA_OWNER: &str = "ai-steward-control";
pub const SCHEMA_VERSION: i64 = 3;

/// RC1 的结构，原样保留；新库也先建它，再叠加 v2。
const SCHEMA_V1: &str = "
CREATE TABLE control_meta (
  key TEXT PRIMARY KEY NOT NULL,
  value TEXT NOT NULL
);
CREATE TABLE control_users (
  user_ref TEXT PRIMARY KEY NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE control_setup (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
  admin_user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  initialized_at TEXT NOT NULL
);
CREATE TABLE control_sessions (
  token_sha256 TEXT PRIMARY KEY NOT NULL,
  session_ref TEXT NOT NULL UNIQUE,
  user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  created_at TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  revoked_at TEXT
);
CREATE INDEX control_sessions_user_ref ON control_sessions (user_ref);
";

/// v1 → v2：业务表。用户、会话、唯一键、状态与幂等键由约束守住；
/// 可变的业务形状（分配快照、额度快照、回执）沿 Node 基线用 JSON payload 保存。
pub const MIGRATION_V2: &str = "
CREATE TABLE control_secrets (
  secret_ref TEXT PRIMARY KEY NOT NULL,
  purpose TEXT NOT NULL,
  protector TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE control_model_policies (
  task_type TEXT PRIMARY KEY NOT NULL CHECK (task_type IN ('cleanup', 'network_diagnosis', 'daily_analysis')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  provider TEXT NOT NULL CHECK (provider IN ('openai-compatible')),
  base_url TEXT,
  model TEXT,
  policy_version TEXT NOT NULL,
  max_model_calls INTEGER NOT NULL CHECK (max_model_calls >= 1),
  max_total_tokens INTEGER NOT NULL CHECK (max_total_tokens >= 1),
  max_output_tokens INTEGER NOT NULL CHECK (max_output_tokens >= 1),
  timeout_ms INTEGER NOT NULL CHECK (timeout_ms >= 1000),
  secret_ref TEXT REFERENCES control_secrets (secret_ref),
  verification TEXT NOT NULL CHECK (verification IN ('NOT_TESTED', 'CALL_SUCCEEDED', 'CALL_FAILED')),
  last_error_code TEXT,
  last_call_at TEXT,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL REFERENCES control_users (user_ref)
);
CREATE TABLE control_ai_tasks (
  task_ref TEXT PRIMARY KEY NOT NULL,
  user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  task_type TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE control_ai_turns (
  task_ref TEXT NOT NULL REFERENCES control_ai_tasks (task_ref),
  turn_ref TEXT NOT NULL,
  signature TEXT NOT NULL,
  http_status INTEGER NOT NULL,
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (task_ref, turn_ref)
);
CREATE TABLE control_ai_usage_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_ref TEXT NOT NULL REFERENCES control_ai_tasks (task_ref),
  turn_ref TEXT NOT NULL,
  user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  task_type TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  policy_identity TEXT NOT NULL,
  status TEXT NOT NULL,
  total_tokens INTEGER,
  usage_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (task_ref, turn_ref)
);
CREATE TABLE control_resources (
  resource_id TEXT PRIMARY KEY NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('front', 'A', 'B')),
  kind TEXT NOT NULL CHECK (kind IN ('socks5')),
  host TEXT NOT NULL,
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  sharing TEXT NOT NULL CHECK (sharing IN ('shared', 'dedicated')),
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
  expires_at TEXT,
  credential_ref TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  updated_at TEXT NOT NULL
);
CREATE TABLE control_templates (
  template_id TEXT PRIMARY KEY NOT NULL,
  version TEXT NOT NULL,
  numeric_version INTEGER NOT NULL CHECK (numeric_version >= 1),
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED')),
  published INTEGER NOT NULL CHECK (published IN (0, 1)),
  template_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE control_template_versions (
  template_id TEXT NOT NULL REFERENCES control_templates (template_id),
  numeric_version INTEGER NOT NULL,
  version TEXT NOT NULL,
  template_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (template_id, numeric_version)
);
CREATE TABLE control_subscription_sources (
  source_id TEXT PRIMARY KEY NOT NULL,
  format TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'DISABLED', 'ACTIVE', 'FAILED', 'UNSUPPORTED')),
  url_secret_ref TEXT REFERENCES control_secrets (secret_ref),
  url_display TEXT,
  version INTEGER NOT NULL CHECK (version >= 1),
  refreshed_at TEXT,
  proxy_count INTEGER NOT NULL DEFAULT 0,
  proxy_names_json TEXT NOT NULL DEFAULT '[]',
  error TEXT,
  http_status INTEGER,
  content_type TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE control_assignment_candidates (
  user_ref TEXT PRIMARY KEY NOT NULL REFERENCES control_users (user_ref),
  assignment_version INTEGER NOT NULL CHECK (assignment_version >= 1),
  payload_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE control_assignments (
  user_ref TEXT PRIMARY KEY NOT NULL REFERENCES control_users (user_ref),
  assignment_version INTEGER NOT NULL CHECK (assignment_version >= 1),
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
  payload_json TEXT NOT NULL,
  published_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE control_publish_receipts (
  receipt_id TEXT PRIMARY KEY NOT NULL,
  user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  assignment_version INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (user_ref, assignment_version)
);
CREATE TABLE control_apply_receipts (
  user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  operation_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  received_at TEXT NOT NULL,
  PRIMARY KEY (user_ref, operation_id)
);
CREATE TABLE control_credentials (
  credential_ref TEXT NOT NULL,
  user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  secret_ref TEXT UNIQUE REFERENCES control_secrets (secret_ref),
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
  version INTEGER NOT NULL CHECK (version >= 1),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (credential_ref, user_ref),
  CHECK ((status = 'ACTIVE') = (secret_ref IS NOT NULL))
);
CREATE TABLE control_quota_adapter (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
  kind TEXT NOT NULL CHECK (kind IN ('remnawave')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  base_url_secret_ref TEXT REFERENCES control_secrets (secret_ref),
  base_url_display TEXT,
  token_secret_ref TEXT REFERENCES control_secrets (secret_ref),
  timeout_ms INTEGER NOT NULL CHECK (timeout_ms >= 1000),
  verification TEXT NOT NULL CHECK (verification IN ('NOT_TESTED', 'CALL_SUCCEEDED', 'CALL_FAILED')),
  last_error_code TEXT,
  last_call_at TEXT,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL REFERENCES control_users (user_ref)
);
CREATE TABLE control_provider_bindings (
  user_ref TEXT PRIMARY KEY NOT NULL REFERENCES control_users (user_ref),
  provider_user_id INTEGER NOT NULL UNIQUE CHECK (provider_user_id > 0),
  username TEXT NOT NULL UNIQUE,
  authority_ref TEXT NOT NULL,
  squad_uuid TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE control_quota_operations (
  operation_id TEXT PRIMARY KEY NOT NULL,
  user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  kind TEXT NOT NULL CHECK (kind IN ('AllocateUserAccess', 'ChangeLimit', 'SuspendUserAccess', 'ResumeUserAccess')),
  digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETED')),
  result_json TEXT,
  error_code TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  CHECK ((status = 'COMPLETED') = (result_json IS NOT NULL))
);
CREATE TABLE control_quota_snapshots (
  user_ref TEXT PRIMARY KEY NOT NULL REFERENCES control_users (user_ref),
  payload_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE control_pool_snapshots (
  pool_id TEXT PRIMARY KEY NOT NULL,
  payload_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE control_network_events (
  event_ref TEXT PRIMARY KEY NOT NULL,
  user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  payload_json TEXT NOT NULL,
  received_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX control_network_events_user_ref ON control_network_events (user_ref, event_ref);
CREATE TABLE control_event_receipts (
  event_ref TEXT PRIMARY KEY NOT NULL REFERENCES control_network_events (event_ref),
  user_ref TEXT NOT NULL REFERENCES control_users (user_ref),
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'ACCEPTED', 'RECORDED', 'CONFIRMED')),
  payload_json TEXT NOT NULL
);
";

/// v2 → v3：分环境探测服务配置（RC4）。一行一个环境，配置按 JSON 存，版本号防覆盖。
pub const MIGRATION_V3: &str = "
CREATE TABLE control_probe_services (
  environment_ref TEXT PRIMARY KEY NOT NULL,
  config_json TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
";

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub user_ref: String,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub user_ref: String,
    pub username: String,
    pub password_hash: String,
    pub role: &'static str,
}

#[derive(Debug, Clone)]
pub struct SessionIdentity {
    pub user_ref: String,
    pub username: String,
    pub role: String,
    pub status: String,
    pub expires_at_ms: i64,
    pub session_ref: String,
}

pub struct Store {
    path: PathBuf,
    created_now: bool,
    migrated_from: Option<i64>,
    connection: Mutex<Connection>,
}

fn failure(code: &'static str, error: rusqlite::Error) -> ControlError {
    match error.sqlite_error_code() {
        Some(ErrorCode::NotADatabase) | Some(ErrorCode::DatabaseCorrupt) => {
            ControlError::new("CONTROL_STORE_CORRUPT", format!("控制端数据库已损坏或不是 SQLite 文件：{error}"))
        }
        _ => ControlError::new(code, format!("控制端数据库操作失败：{error}")),
    }
}

pub fn read_failed(error: rusqlite::Error) -> ControlError {
    failure("CONTROL_STORE_READ_FAILED", error)
}

pub fn write_failed(error: rusqlite::Error) -> ControlError {
    failure("CONTROL_STORE_WRITE_FAILED", error)
}

/// 唯一键、主键、CHECK 或外键被数据库拒绝。
pub fn is_constraint(error: &rusqlite::Error) -> bool {
    error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation)
}

impl Store {
    pub fn open(path: &Path, clock: &dyn Fn() -> i64) -> Result<Store, ControlError> {
        let existed = path.exists();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                ControlError::new("CONTROL_STORE_OPEN_FAILED", format!("无法创建数据库目录：{error}"))
            })?;
        }
        let mut connection = Connection::open(path).map_err(|error| failure("CONTROL_STORE_OPEN_FAILED", error))?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| failure("CONTROL_STORE_OPEN_FAILED", error))?;
        let mut migrated_from = None;
        if existed {
            let version = verify_existing(&connection)?;
            if version < SCHEMA_VERSION {
                migrate_to_current(&mut connection, clock())?;
                migrated_from = Some(version);
            }
        } else {
            create_schema(&connection, clock)?;
        }
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|error| failure("CONTROL_STORE_OPEN_FAILED", error))?;
        Ok(Store {
            path: path.to_path_buf(),
            created_now: !existed,
            migrated_from,
            connection: Mutex::new(connection),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn created_now(&self) -> bool {
        self.created_now
    }

    /// 本次打开时从哪个旧版本升级而来；没有升级为 None。
    pub fn migrated_from(&self) -> Option<i64> {
        self.migrated_from
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, ControlError> {
        self.connection
            .lock()
            .map_err(|_| ControlError::new("CONTROL_STORE_READ_FAILED", "控制端数据库句柄不可用"))
    }

    /// 只读访问。闭包内不得发起外部调用。错误类型由闭包决定，只要能从 ControlError 转换。
    pub fn read<T, E: From<ControlError>>(&self, work: impl FnOnce(&Connection) -> Result<T, E>) -> Result<T, E> {
        let connection = self.lock().map_err(E::from)?;
        work(&*connection)
    }

    /// 一个 IMMEDIATE 事务；闭包返回错误或提交失败时整体回滚。闭包内不得发起外部调用。
    pub fn write<T, E: From<ControlError>>(&self, work: impl FnOnce(&Transaction<'_>) -> Result<T, E>) -> Result<T, E> {
        let mut connection = self.lock().map_err(E::from)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| E::from(write_failed(error)))?;
        let value = work(&transaction)?;
        transaction.commit().map_err(|error| E::from(write_failed(error)))?;
        Ok(value)
    }

    pub fn schema_version(&self) -> Result<i64, ControlError> {
        let connection = self.lock()?;
        let text: String = connection
            .query_row("SELECT value FROM control_meta WHERE key = 'schema_version'", [], |row| row.get(0))
            .map_err(read_failed)?;
        text.parse::<i64>()
            .map_err(|_| ControlError::new("CONTROL_STORE_UNRECOGNIZED", "数据库结构版本缺失或无法识别"))
    }

    pub fn is_initialized(&self) -> Result<bool, ControlError> {
        let connection = self.lock()?;
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM control_setup", [], |row| row.get(0))
            .map_err(read_failed)?;
        Ok(count > 0)
    }

    /// 首次初始化在一个 IMMEDIATE 事务里完成：已有首启记录就回 CONTROL_SETUP_CONFLICT，
    /// control_setup 的单行主键再兜一层，两条连接同时提交也只有一条成功。
    pub fn initialize_admin(&self, admin: &NewUser, now_ms: i64) -> Result<(), ControlError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(write_failed)?;
        let existing: i64 = transaction
            .query_row("SELECT COUNT(*) FROM control_setup", [], |row| row.get(0))
            .map_err(read_failed)?;
        if existing > 0 {
            return Err(ControlError::new("CONTROL_SETUP_CONFLICT", "控制端已经完成首次初始化，不能重复创建管理员"));
        }
        let now = iso_from_millis(now_ms);
        transaction
            .execute(
                "INSERT INTO control_users (user_ref, username, password_hash, role, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 'ACTIVE', ?5, ?5)",
                params![admin.user_ref, admin.username, admin.password_hash, admin.role, now],
            )
            .map_err(|error| conflict_or(error, "CONTROL_STORE_WRITE_FAILED"))?;
        transaction
            .execute(
                "INSERT INTO control_setup (singleton, admin_user_ref, initialized_at) VALUES (1, ?1, ?2)",
                params![admin.user_ref, now],
            )
            .map_err(|error| conflict_or(error, "CONTROL_STORE_WRITE_FAILED"))?;
        transaction.commit().map_err(|error| conflict_or(error, "CONTROL_STORE_WRITE_FAILED"))
    }

    pub fn find_user_by_username(&self, username: &str) -> Result<Option<UserRecord>, ControlError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT user_ref, username, password_hash, role, status FROM control_users WHERE username = ?1",
                params![username],
                |row| {
                    Ok(UserRecord {
                        user_ref: row.get(0)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        role: row.get(3)?,
                        status: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(read_failed)
    }

    pub fn create_session(
        &self,
        token_sha256: &str,
        session_ref: &str,
        user_ref: &str,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<(), ControlError> {
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO control_sessions (token_sha256, session_ref, user_ref, created_at, expires_at_ms, revoked_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                params![token_sha256, session_ref, user_ref, iso_from_millis(now_ms), expires_at_ms],
            )
            .map(|_| ())
            .map_err(write_failed)
    }

    /// 未撤销、未过期、用户仍为 ACTIVE 才算有效会话；任何一项不满足都返回 None。
    pub fn session_identity(&self, token_sha256: &str, now_ms: i64) -> Result<Option<SessionIdentity>, ControlError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT u.user_ref, u.username, u.role, u.status, s.expires_at_ms, s.session_ref
                   FROM control_sessions s JOIN control_users u ON u.user_ref = s.user_ref
                  WHERE s.token_sha256 = ?1 AND s.revoked_at IS NULL AND s.expires_at_ms > ?2 AND u.status = 'ACTIVE'",
                params![token_sha256, now_ms],
                |row| {
                    Ok(SessionIdentity {
                        user_ref: row.get(0)?,
                        username: row.get(1)?,
                        role: row.get(2)?,
                        status: row.get(3)?,
                        expires_at_ms: row.get(4)?,
                        session_ref: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(read_failed)
    }

    /// 只撤销这一条会话；已撤销或不存在时不改任何数据，返回 false。
    pub fn revoke_session(&self, token_sha256: &str, now_ms: i64) -> Result<bool, ControlError> {
        let connection = self.lock()?;
        connection
            .execute(
                "UPDATE control_sessions SET revoked_at = ?1 WHERE token_sha256 = ?2 AND revoked_at IS NULL",
                params![iso_from_millis(now_ms), token_sha256],
            )
            .map(|changed| changed > 0)
            .map_err(write_failed)
    }
}

fn conflict_or(error: rusqlite::Error, code: &'static str) -> ControlError {
    if is_constraint(&error) {
        return ControlError::new("CONTROL_SETUP_CONFLICT", "控制端已经完成首次初始化，不能重复创建管理员");
    }
    failure(code, error)
}

fn enable_wal(connection: &Connection) -> Result<(), ControlError> {
    let mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|error| failure("CONTROL_STORE_OPEN_FAILED", error))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(ControlError::new("CONTROL_STORE_OPEN_FAILED", format!("数据库未能进入 WAL 模式（当前 {mode}）")));
    }
    Ok(())
}

/// 新库：v1 结构、v2 与 v3 迁移和版本标记在同一个事务里，与「旧库逐级升级」得到逐表相同的结构。
fn create_schema(connection: &Connection, clock: &dyn Fn() -> i64) -> Result<(), ControlError> {
    enable_wal(connection)?;
    let script = format!(
        "BEGIN IMMEDIATE;{SCHEMA_V1}{MIGRATION_V2}{MIGRATION_V3}INSERT INTO control_meta (key, value) VALUES ('schema_owner', '{SCHEMA_OWNER}'), ('schema_version', '{SCHEMA_VERSION}'), ('created_at', '{}');COMMIT;",
        iso_from_millis(clock())
    );
    connection
        .execute_batch(&script)
        .map_err(|error| failure("CONTROL_STORE_OPEN_FAILED", error))
}

/// 已存在的库：返回它的结构版本（1 到当前版本之间）。
fn verify_existing(connection: &Connection) -> Result<i64, ControlError> {
    let check: String = connection
        .pragma_query_value(None, "quick_check", |row| row.get(0))
        .map_err(read_failed)?;
    if check != "ok" {
        return Err(ControlError::new("CONTROL_STORE_CORRUPT", format!("控制端数据库完整性检查未通过：{check}")));
    }
    let has_meta: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'control_meta'",
            [],
            |row| row.get(0),
        )
        .map_err(read_failed)?;
    if has_meta == 0 {
        return Err(ControlError::new(
            "CONTROL_STORE_UNRECOGNIZED",
            "状态目录里已有数据库文件，但不是本控制端的库；不会覆盖或重建，请核对状态目录",
        ));
    }
    let owner: Option<String> = connection
        .query_row("SELECT value FROM control_meta WHERE key = 'schema_owner'", [], |row| row.get(0))
        .optional()
        .map_err(read_failed)?;
    if owner.as_deref() != Some(SCHEMA_OWNER) {
        return Err(ControlError::new(
            "CONTROL_STORE_UNRECOGNIZED",
            "数据库归属标记不符；不会覆盖或重建，请核对状态目录",
        ));
    }
    let version: Option<String> = connection
        .query_row("SELECT value FROM control_meta WHERE key = 'schema_version'", [], |row| row.get(0))
        .optional()
        .map_err(read_failed)?;
    let version = match version.as_deref().and_then(|text| text.parse::<i64>().ok()) {
        Some(value) if (1..=SCHEMA_VERSION).contains(&value) => value,
        Some(value) if value > SCHEMA_VERSION => {
            return Err(ControlError::new(
                "CONTROL_STORE_VERSION_UNSUPPORTED",
                format!("数据库结构版本 {value} 比本程序支持的 {SCHEMA_VERSION} 新"),
            ));
        }
        _ => {
            return Err(ControlError::new("CONTROL_STORE_UNRECOGNIZED", "数据库结构版本缺失或无法识别"));
        }
    };
    enable_wal(connection)?;
    Ok(version)
}

/// 旧库逐级升到当前版本（v1 → v2 → v3）。事务内再读一次版本：另一个进程已经升级完就什么都不做。
/// 任一步失败时事务随 `Transaction` 析构回滚，库保持原版本。
fn migrate_to_current(connection: &mut Connection, now_ms: i64) -> Result<(), ControlError> {
    let migration_failed = |error: rusqlite::Error| {
        ControlError::new("CONTROL_STORE_MIGRATION_FAILED", format!("数据库升级到 v{SCHEMA_VERSION} 失败，已回滚：{error}"))
    };
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(migration_failed)?;
    let current: String = transaction
        .query_row("SELECT value FROM control_meta WHERE key = 'schema_version'", [], |row| row.get(0))
        .map_err(migration_failed)?;
    if current == SCHEMA_VERSION.to_string() {
        return Ok(());
    }
    let steps: &[(&str, &str)] = match current.as_str() {
        "1" => &[("migrated_v2_at", MIGRATION_V2), ("migrated_v3_at", MIGRATION_V3)],
        "2" => &[("migrated_v3_at", MIGRATION_V3)],
        _ => return Err(ControlError::new("CONTROL_STORE_UNRECOGNIZED", "数据库结构版本缺失或无法识别")),
    };
    for (_, script) in steps {
        transaction.execute_batch(script).map_err(migration_failed)?;
    }
    transaction
        .execute(
            "UPDATE control_meta SET value = ?1 WHERE key = 'schema_version'",
            params![SCHEMA_VERSION.to_string()],
        )
        .map_err(migration_failed)?;
    for (marker, _) in steps {
        transaction
            .execute(
                "INSERT INTO control_meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![marker, iso_from_millis(now_ms)],
            )
            .map_err(migration_failed)?;
    }
    transaction.commit().map_err(migration_failed)
}
