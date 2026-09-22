//! 应用用户与会话管理（管理员）。
//!
//! 首版只有一个管理员角色与普通用户角色：这里只能新建普通用户，启停、重置密码与撤销会话的目标
//! 也只能是普通用户，不能借此停用或改写管理员。停用与重置密码在同一个事务里撤销该用户全部会话，
//! 不删除用户、额度、分配或事件记录。任何读取都不返回密码哈希、会话令牌或令牌摘要。

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::api::{fields, ApiError};
use crate::auth::{hash_password, normalize_username, validate_password};
use crate::router::{ApiResponse, Ctx};
use crate::store::{is_constraint, read_failed, write_failed};
use crate::{iso_from_millis, random_hex, ControlError};

pub struct UserRow {
    pub user_ref: String,
    pub username: String,
    pub role: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl UserRow {
    fn view(&self, active_sessions: Option<i64>) -> Value {
        let mut value = json!({
            "user_ref": self.user_ref,
            "username": self.username,
            "role": self.role,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        });
        if let Some(count) = active_sessions {
            value["active_sessions"] = json!(count);
        }
        value
    }
}

pub fn find_user(connection: &Connection, user_ref: &str) -> Result<Option<UserRow>, ControlError> {
    connection
        .query_row(
            "SELECT user_ref, username, role, status, created_at, updated_at FROM control_users WHERE user_ref = ?1",
            params![user_ref],
            |row| {
                Ok(UserRow {
                    user_ref: row.get(0)?,
                    username: row.get(1)?,
                    role: row.get(2)?,
                    status: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(read_failed)
}

/// 被管理的对象必须存在。业务分配与额度对任何角色的用户都可用，所以这里不限角色。
pub fn existing_user(connection: &Connection, user_ref: &str) -> Result<UserRow, ApiError> {
    find_user(connection, user_ref)?.ok_or_else(|| ApiError::new(404, "CONTROL_USER_NOT_FOUND", "没有这个应用用户"))
}

/// 启停、重置密码、撤销会话的目标必须是普通用户。
fn managed_user(connection: &Connection, user_ref: &str) -> Result<UserRow, ApiError> {
    let user = existing_user(connection, user_ref)?;
    if user.role != "user" {
        return Err(ApiError::new(403, "CONTROL_ADMIN_TARGET_DENIED", "管理员账号不能在这里停用、重置或撤销会话"));
    }
    Ok(user)
}

/// 撤销该用户仍未撤销的全部会话，返回撤销条数。
fn revoke_user_sessions(connection: &Connection, user_ref: &str, now_ms: i64) -> Result<usize, ControlError> {
    connection
        .execute(
            "UPDATE control_sessions SET revoked_at = ?1 WHERE user_ref = ?2 AND revoked_at IS NULL",
            params![iso_from_millis(now_ms), user_ref],
        )
        .map_err(write_failed)
}

pub fn list(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let now = ctx.now();
    let users = ctx.app.store.read(|connection| -> Result<Vec<Value>, ControlError> {
        let mut statement = connection
            .prepare(
                "SELECT u.user_ref, u.username, u.role, u.status, u.created_at, u.updated_at,
                        (SELECT COUNT(*) FROM control_sessions s WHERE s.user_ref = u.user_ref AND s.revoked_at IS NULL AND s.expires_at_ms > ?1)
                   FROM control_users u ORDER BY u.created_at, u.username",
            )
            .map_err(read_failed)?;
        let rows = statement
            .query_map(params![now], |row| {
                let user = UserRow {
                    user_ref: row.get(0)?,
                    username: row.get(1)?,
                    role: row.get(2)?,
                    status: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                };
                let active: i64 = row.get(6)?;
                Ok(user.view(Some(active)))
            })
            .map_err(read_failed)?;
        let collected: Result<Vec<Value>, rusqlite::Error> = rows.collect();
        collected.map_err(read_failed)
    })?;
    Ok(ApiResponse::json(200, json!({"users": users})))
}

pub fn create(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["username", "password"])?;
    let username = normalize_username(&input.required_string("username", 256)?)?;
    let password = input
        .raw_string("password", 4096)?
        .ok_or_else(|| ApiError::invalid("字段 password 必填"))?;
    validate_password(&password, &ctx.app.config)?;
    let password_hash = hash_password(&password)?;
    let user_ref = format!("usr-{}", random_hex(8)?);
    let now = iso_from_millis(ctx.now());
    ctx.app.store.write(|transaction| -> Result<(), ApiError> {
        transaction
            .execute(
                "INSERT INTO control_users (user_ref, username, password_hash, role, status, created_at, updated_at) VALUES (?1, ?2, ?3, 'user', 'ACTIVE', ?4, ?4)",
                params![user_ref, username, password_hash, now],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    ApiError::new(409, "CONTROL_USER_CONFLICT", "这个账号名已被使用")
                } else {
                    ApiError::from(write_failed(error))
                }
            })?;
        Ok(())
    })?;
    ctx.info("admin.user.created", json!({"actor": ctx.actor(), "user_ref": user_ref}));
    Ok(ApiResponse::json(
        201,
        json!({"user": {"user_ref": user_ref, "username": username, "role": "user", "status": "ACTIVE", "created_at": now, "updated_at": now, "active_sessions": 0}}),
    ))
}

pub fn set_status(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["user_ref", "status"])?;
    let user_ref = input.required_string("user_ref", 128)?;
    let status = input.required_string("status", 16)?;
    if status != "ACTIVE" && status != "DISABLED" {
        return Err(ApiError::invalid("status 只能是 ACTIVE 或 DISABLED").with("field", json!("status")));
    }
    let now_ms = ctx.now();
    let now = iso_from_millis(now_ms);
    let (user, revoked) = ctx.app.store.write(|transaction| -> Result<(UserRow, usize), ApiError> {
        let user = managed_user(transaction, &user_ref)?;
        if user.status != status {
            transaction
                .execute(
                    "UPDATE control_users SET status = ?1, updated_at = ?2 WHERE user_ref = ?3",
                    params![status, now, user_ref],
                )
                .map_err(write_failed)?;
        }
        let revoked = if status == "DISABLED" { revoke_user_sessions(transaction, &user_ref, now_ms)? } else { 0 };
        let updated = find_user(transaction, &user_ref)?.unwrap_or(user);
        Ok((updated, revoked))
    })?;
    ctx.info("admin.user.status", json!({"actor": ctx.actor(), "user_ref": user_ref, "status": status, "revoked_sessions": revoked}));
    Ok(ApiResponse::json(200, json!({"user": user.view(None), "revoked_sessions": revoked})))
}

pub fn reset_password(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["user_ref", "password"])?;
    let user_ref = input.required_string("user_ref", 128)?;
    let password = input
        .raw_string("password", 4096)?
        .ok_or_else(|| ApiError::invalid("字段 password 必填"))?;
    validate_password(&password, &ctx.app.config)?;
    let password_hash = hash_password(&password)?;
    let now_ms = ctx.now();
    let now = iso_from_millis(now_ms);
    let (username, revoked) = ctx.app.store.write(|transaction| -> Result<(String, usize), ApiError> {
        let user = managed_user(transaction, &user_ref)?;
        transaction
            .execute(
                "UPDATE control_users SET password_hash = ?1, updated_at = ?2 WHERE user_ref = ?3",
                params![password_hash, now, user_ref],
            )
            .map_err(write_failed)?;
        let revoked = revoke_user_sessions(transaction, &user_ref, now_ms)?;
        Ok((user.username, revoked))
    })?;
    ctx.app.throttle.clear(&username);
    ctx.info("admin.user.password_reset", json!({"actor": ctx.actor(), "user_ref": user_ref, "revoked_sessions": revoked}));
    Ok(ApiResponse::json(200, json!({"user_ref": user_ref, "password_reset": true, "revoked_sessions": revoked, "updated_at": now})))
}

pub fn list_sessions(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let user_ref = ctx
        .query("user_ref")
        .ok_or_else(|| ApiError::invalid("查询参数 user_ref 必填"))?
        .to_string();
    let now = ctx.now();
    let (user, sessions) = ctx.app.store.read(|connection| -> Result<(UserRow, Vec<Value>), ApiError> {
        let user = existing_user(connection, &user_ref)?;
        let mut statement = connection
            .prepare(
                "SELECT session_ref, created_at, expires_at_ms, revoked_at FROM control_sessions WHERE user_ref = ?1 ORDER BY created_at DESC LIMIT 200",
            )
            .map_err(read_failed)?;
        let rows = statement
            .query_map(params![user_ref], |row| {
                let session_ref: String = row.get(0)?;
                let created_at: String = row.get(1)?;
                let expires_at_ms: i64 = row.get(2)?;
                let revoked_at: Option<String> = row.get(3)?;
                let status = if revoked_at.is_some() {
                    "REVOKED"
                } else if expires_at_ms <= now {
                    "EXPIRED"
                } else {
                    "ACTIVE"
                };
                Ok(json!({
                    "session_ref": session_ref,
                    "status": status,
                    "created_at": created_at,
                    "expires_at": iso_from_millis(expires_at_ms),
                    "revoked_at": revoked_at,
                }))
            })
            .map_err(read_failed)?;
        let collected: Result<Vec<Value>, rusqlite::Error> = rows.collect();
        let sessions = collected.map_err(read_failed)?;
        Ok((user, sessions))
    })?;
    Ok(ApiResponse::json(200, json!({"user_ref": user.user_ref, "username": user.username, "sessions": sessions})))
}

pub fn revoke_sessions(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["user_ref", "session_ref"])?;
    let user_ref = input.string("user_ref", 128)?;
    let session_ref = input.string("session_ref", 128)?;
    let now_ms = ctx.now();
    let now = iso_from_millis(now_ms);
    let (target, owner, revoked) = match (user_ref, session_ref) {
        (Some(user_ref), None) => ctx.app.store.write(|transaction| -> Result<(Value, String, usize), ApiError> {
            managed_user(transaction, &user_ref)?;
            let revoked = revoke_user_sessions(transaction, &user_ref, now_ms)?;
            Ok((json!({"user_ref": user_ref}), user_ref.clone(), revoked))
        })?,
        (None, Some(session_ref)) => ctx.app.store.write(|transaction| -> Result<(Value, String, usize), ApiError> {
            let owner: Option<String> = transaction
                .query_row("SELECT user_ref FROM control_sessions WHERE session_ref = ?1", params![session_ref], |row| row.get(0))
                .optional()
                .map_err(read_failed)?;
            let owner = owner.ok_or_else(|| ApiError::new(404, "CONTROL_SESSION_NOT_FOUND", "没有这个会话"))?;
            managed_user(transaction, &owner)?;
            let revoked = transaction
                .execute(
                    "UPDATE control_sessions SET revoked_at = ?1 WHERE session_ref = ?2 AND revoked_at IS NULL",
                    params![now, session_ref],
                )
                .map_err(write_failed)?;
            Ok((json!({"session_ref": session_ref}), owner, revoked))
        })?,
        _ => return Err(ApiError::invalid("user_ref 与 session_ref 必须且只能给一个")),
    };
    ctx.info("admin.sessions.revoked", json!({"actor": ctx.actor(), "user_ref": owner, "revoked": revoked}));
    Ok(ApiResponse::json(200, json!({"target": target, "user_ref": owner, "revoked": revoked, "revoked_at": now})))
}
