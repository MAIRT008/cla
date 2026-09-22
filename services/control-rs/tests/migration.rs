//! 数据库版本迁移：RC1（v1）库在原路径事务升级到 v2。
//! v1 库用 RC1 的建表语句在测试里直接造出来，模拟已经跑过 RC1 的状态目录。
//!
//! 本机没有 cargo/rustc，这些用例已写未运行。

mod common;

use std::sync::atomic::AtomicI64;
use std::sync::Arc;

use ai_steward_control::auth::{hash_password, token_digest};
use ai_steward_control::store::SCHEMA_VERSION;
use common::*;
use serde_json::json;

/// RC1 store.rs 的建表语句原文。
const RC1_SCHEMA: &str = "
CREATE TABLE control_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
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

const LIVE_TOKEN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REVOKED_TOKEN: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// 造一个 RC1 库：管理员一名、有效会话一条、已注销会话一条。
fn rc1_state_dir(label: &str, extra_sql: &str) -> std::path::PathBuf {
    let dir = fresh_state_dir(label);
    let connection = rusqlite::Connection::open(dir.join("control.sqlite3")).unwrap();
    connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get::<_, String>(0)).unwrap();
    connection.execute_batch(RC1_SCHEMA).unwrap();
    connection
        .execute_batch("INSERT INTO control_meta (key, value) VALUES ('schema_owner', 'ai-steward-control'), ('schema_version', '1'), ('created_at', '2026-09-16T00:00:00.000Z');")
        .unwrap();
    connection
        .execute(
            "INSERT INTO control_users (user_ref, username, password_hash, role, status, created_at, updated_at) VALUES ('usr-rc1admin', 'admin', ?1, 'admin', 'ACTIVE', 'x', 'x')",
            [hash_password(ADMIN_PASSWORD).unwrap()],
        )
        .unwrap();
    connection.execute("INSERT INTO control_setup (singleton, admin_user_ref, initialized_at) VALUES (1, 'usr-rc1admin', 'x')", []).unwrap();
    connection
        .execute(
            "INSERT INTO control_sessions (token_sha256, session_ref, user_ref, created_at, expires_at_ms, revoked_at) VALUES (?1, 'ses-live', 'usr-rc1admin', 'x', ?2, NULL)",
            rusqlite::params![token_digest(LIVE_TOKEN), START_MS + 3_600_000],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO control_sessions (token_sha256, session_ref, user_ref, created_at, expires_at_ms, revoked_at) VALUES (?1, 'ses-revoked', 'usr-rc1admin', 'x', ?2, 'y')",
            rusqlite::params![token_digest(REVOKED_TOKEN), START_MS + 3_600_000],
        )
        .unwrap();
    if !extra_sql.is_empty() {
        connection.execute_batch(extra_sql).unwrap();
    }
    dir
}

fn schema_rows(connection: &rusqlite::Connection) -> Vec<(String, String)> {
    let mut statement = connection
        .prepare("SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap();
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    rows.map(Result::unwrap).collect()
}

fn version_of(dir: &std::path::Path) -> String {
    rusqlite::Connection::open(dir.join("control.sqlite3"))
        .unwrap()
        .query_row("SELECT value FROM control_meta WHERE key = 'schema_version'", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn a_rc1_database_is_upgraded_in_place_keeping_admin_and_live_sessions() {
    let dir = rc1_state_dir("upgrade", "");
    let now = Arc::new(AtomicI64::new(START_MS));
    let transport = ScriptedTransport::new();
    let app = open_app(&dir, &now, &transport).expect("v1 库必须能升级打开");
    assert_eq!(app.store.migrated_from(), Some(1));
    assert_eq!(app.store.schema_version().unwrap(), SCHEMA_VERSION);
    assert!(app.logger.path().exists());
    let log = std::fs::read_to_string(app.logger.path()).unwrap();
    assert!(log.contains("\"migrated_from\":1"), "升级记进本轮日志");

    let h = Harness { app, now, dir: dir.clone(), transport };
    let me = h.call("GET", "/api/auth/me", Some(LIVE_TOKEN), None);
    assert_eq!(me.status, 200, "RC1 的有效会话升级后仍有效");
    assert_eq!(body(&me)["user_ref"], "usr-rc1admin");
    assert_eq!(h.call("GET", "/api/auth/me", Some(REVOKED_TOKEN), None).status, 401, "已注销的不会复活");
    assert_eq!(h.login("admin", ADMIN_PASSWORD).len(), 64, "RC1 管理员密码不变");
    let status = h.call("GET", "/api/setup/status", None, None);
    assert_eq!(body(&status), json!({"initialized": true}));

    let users = h.call("GET", "/api/admin/users", Some(LIVE_TOKEN), None);
    assert_eq!(users.status, 200, "升级后的业务表可用");
    assert_eq!(body(&users)["users"].as_array().unwrap().len(), 1);

    let h = h.reopen();
    assert_eq!(h.app.store.migrated_from(), None, "第二次打开不再迁移");
    assert_eq!(version_of(&h.dir), SCHEMA_VERSION.to_string());
    assert_eq!(h.call("GET", "/api/auth/me", Some(LIVE_TOKEN), None).status, 200);
}

#[test]
fn a_fresh_database_and_an_upgraded_one_have_the_same_schema() {
    let fresh = Harness::new("fresh-schema");
    let upgraded_dir = rc1_state_dir("upgraded-schema", "");
    let now = Arc::new(AtomicI64::new(START_MS));
    let transport = ScriptedTransport::new();
    let upgraded = open_app(&upgraded_dir, &now, &transport).unwrap();
    drop(upgraded);
    let fresh_rows = schema_rows(&fresh.sql());
    let upgraded_rows = schema_rows(&rusqlite::Connection::open(upgraded_dir.join("control.sqlite3")).unwrap());
    let normalize = |rows: Vec<(String, String)>| -> Vec<(String, String)> {
        rows.into_iter().map(|(name, sql)| (name, sql.split_whitespace().collect::<Vec<_>>().join(" "))).collect()
    };
    assert_eq!(normalize(fresh_rows), normalize(upgraded_rows));
}

#[test]
fn a_failing_migration_rolls_back_and_leaves_v1_intact() {
    // 预先占用 v2 要建的表名，迫使迁移中途失败。
    let dir = rc1_state_dir("rollback", "CREATE TABLE control_resources (resource_id TEXT PRIMARY KEY NOT NULL, payload_json TEXT NOT NULL);");
    let before_users: i64 = rusqlite::Connection::open(dir.join("control.sqlite3"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM control_users", [], |row| row.get(0))
        .unwrap();
    let now = Arc::new(AtomicI64::new(START_MS));
    let transport = ScriptedTransport::new();
    let error = open_app(&dir, &now, &transport).err().expect("迁移失败必须拒绝启动");
    assert_eq!(error.code, "CONTROL_STORE_MIGRATION_FAILED");
    assert_eq!(version_of(&dir), "1", "失败后版本号不变");
    let connection = rusqlite::Connection::open(dir.join("control.sqlite3")).unwrap();
    let secrets_table: i64 = connection
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'control_secrets'", [], |row| row.get(0))
        .unwrap();
    assert_eq!(secrets_table, 0, "迁移里先建的表随事务回滚");
    let after_users: i64 = connection.query_row("SELECT COUNT(*) FROM control_users", [], |row| row.get(0)).unwrap();
    let live: i64 = connection
        .query_row("SELECT COUNT(*) FROM control_sessions WHERE revoked_at IS NULL", [], |row| row.get(0))
        .unwrap();
    assert_eq!((before_users, after_users, live), (1, 1, 1), "管理员与会话原样保留");
}

#[test]
fn newer_or_foreign_databases_are_refused_without_changes() {
    let newer = rc1_state_dir("newer", "UPDATE control_meta SET value = '99' WHERE key = 'schema_version';");
    let now = Arc::new(AtomicI64::new(START_MS));
    let transport = ScriptedTransport::new();
    assert_eq!(open_app(&newer, &now, &transport).err().unwrap().code, "CONTROL_STORE_VERSION_UNSUPPORTED");
    assert_eq!(version_of(&newer), "99");

    let foreign = rc1_state_dir("foreign-owner", "UPDATE control_meta SET value = 'someone-else' WHERE key = 'schema_owner';");
    assert_eq!(open_app(&foreign, &now, &transport).err().unwrap().code, "CONTROL_STORE_UNRECOGNIZED");
    assert_eq!(version_of(&foreign), "1", "不是本服务的库不升级");
}
