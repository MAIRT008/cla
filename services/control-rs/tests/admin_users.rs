//! 应用用户与会话管理：创建、唯一性、停用、重置密码、会话查看与撤销、权限边界，以及重启后读回。
//!
//! 本机没有 cargo/rustc，这些用例已写未运行。

mod common;

use ai_steward_control::router::ROUTES;
use common::*;
use serde_json::json;

#[test]
fn admin_creates_a_normal_user_who_can_log_in_and_the_list_never_carries_hashes() {
    let h = Harness::new("users-create");
    let admin = h.setup_admin();
    let created = h.call("POST", "/api/admin/users", Some(&admin), Some(json!({"username": " Member.One ", "password": MEMBER_PASSWORD})));
    assert_eq!(created.status, 201, "{:?}", body(&created));
    assert_eq!(body(&created)["user"]["username"], "member.one");
    assert_eq!(body(&created)["user"]["role"], "user", "只能建普通用户");
    let member = h.login("member.one", MEMBER_PASSWORD);
    assert_eq!(body(&h.call("GET", "/api/auth/me", Some(&member), None))["role"], "user");

    let listed = h.call("GET", "/api/admin/users", Some(&admin), None);
    let text = body(&listed).to_string();
    assert!(!text.contains("argon2") && !text.contains("password"), "列表不带密码哈希");
    let users = body(&listed)["users"].as_array().unwrap().clone();
    assert_eq!(users.len(), 2);
    assert_eq!(users.iter().find(|user| user["username"] == "member.one").unwrap()["active_sessions"], 1);

    let duplicate = h.call("POST", "/api/admin/users", Some(&admin), Some(json!({"username": "MEMBER.one", "password": MEMBER_PASSWORD})));
    assert_eq!(duplicate.status, 409);
    assert_eq!(body(&duplicate)["code"], "CONTROL_USER_CONFLICT");

    let self_promoted = h.call("POST", "/api/admin/users", Some(&admin), Some(json!({"username": "sneaky", "password": MEMBER_PASSWORD, "role": "admin"})));
    assert_eq!(self_promoted.status, 400, "客户端不能自封管理员");
    assert_eq!(body(&self_promoted)["field"], "role");
    let weak = h.call("POST", "/api/admin/users", Some(&admin), Some(json!({"username": "weak", "password": "short"})));
    assert_eq!(weak.status, 400, "与首启同一套密码规则");

    let h = h.reopen();
    assert_eq!(h.login("member.one", MEMBER_PASSWORD).len(), 64, "重启后账号仍在");
}

#[test]
fn normal_users_get_403_on_every_admin_route() {
    let h = Harness::new("users-forbidden");
    let admin = h.setup_admin();
    let (_, member) = h.create_member(&admin, "member");
    for (method, path) in ROUTES.iter().filter(|(_, path)| path.starts_with("/api/admin/")) {
        let body_value = if *method == "GET" { None } else { Some(json!({})) };
        let response = h.call(method, path, Some(&member), body_value);
        assert_eq!(response.status, 403, "{method} {path}");
        assert_eq!(body(&response)["code"], "CONTROL_FORBIDDEN");
    }
    let anonymous = h.call("GET", "/api/admin/users", None, None);
    assert_eq!(anonymous.status, 401);
}

#[test]
fn disabling_a_user_revokes_sessions_and_blocks_login_without_deleting_records() {
    let h = Harness::new("users-disable");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    let second = h.login("member", MEMBER_PASSWORD);
    let disabled = h.call("POST", "/api/admin/users/status", Some(&admin), Some(json!({"user_ref": member_ref, "status": "DISABLED"})));
    assert_eq!(disabled.status, 200, "{:?}", body(&disabled));
    assert_eq!(body(&disabled)["revoked_sessions"], 2);
    assert_eq!(h.call("GET", "/api/auth/me", Some(&member), None).status, 401, "旧会话失效");
    assert_eq!(h.call("GET", "/api/network/assignment", Some(&second), None).status, 401);
    let refused = h.call("POST", "/api/auth/login", None, Some(json!({"username": "member", "password": MEMBER_PASSWORD})));
    assert_eq!(refused.status, 401);
    let rows: i64 = h.sql().query_row("SELECT COUNT(*) FROM control_users WHERE user_ref = ?1", [&member_ref], |row| row.get(0)).unwrap();
    assert_eq!(rows, 1, "停用不删用户");

    let again = h.call("POST", "/api/admin/users/status", Some(&admin), Some(json!({"user_ref": member_ref, "status": "DISABLED"})));
    assert_eq!(body(&again)["revoked_sessions"], 0, "重复停用幂等");
    let enabled = h.call("POST", "/api/admin/users/status", Some(&admin), Some(json!({"user_ref": member_ref, "status": "ACTIVE"})));
    assert_eq!(body(&enabled)["user"]["status"], "ACTIVE");
    assert_eq!(h.call("GET", "/api/auth/me", Some(&member), None).status, 401, "重新启用不复活旧会话");
    assert_eq!(h.login("member", MEMBER_PASSWORD).len(), 64);

    let admin_ref = body(&h.call("GET", "/api/auth/me", Some(&admin), None))["user_ref"].as_str().unwrap().to_string();
    let target_admin = h.call("POST", "/api/admin/users/status", Some(&admin), Some(json!({"user_ref": admin_ref, "status": "DISABLED"})));
    assert_eq!(target_admin.status, 403, "管理员账号不能在这里被停用");
    assert_eq!(body(&target_admin)["code"], "CONTROL_ADMIN_TARGET_DENIED");
    let missing = h.call("POST", "/api/admin/users/status", Some(&admin), Some(json!({"user_ref": "usr-missing", "status": "DISABLED"})));
    assert_eq!(missing.status, 404);
}

#[test]
fn password_reset_replaces_the_password_and_revokes_existing_sessions() {
    let h = Harness::new("users-reset");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    let new_password = "synthetic-Reset-Passw0rd";
    let reset = h.call("POST", "/api/admin/users/password-reset", Some(&admin), Some(json!({"user_ref": member_ref, "password": new_password})));
    assert_eq!(reset.status, 200, "{:?}", body(&reset));
    assert_eq!(body(&reset)["revoked_sessions"], 1);
    assert!(!body(&reset).to_string().contains(new_password));
    assert_eq!(h.call("GET", "/api/auth/me", Some(&member), None).status, 401);
    let old = h.call("POST", "/api/auth/login", None, Some(json!({"username": "member", "password": MEMBER_PASSWORD})));
    assert_eq!(old.status, 401, "旧密码失效");
    assert_eq!(h.login("member", new_password).len(), 64);
    let log = h.log_text();
    assert!(!log.contains(new_password) && !log.contains(MEMBER_PASSWORD), "日志不记密码");
}

#[test]
fn sessions_are_listed_without_tokens_and_revoked_idempotently() {
    let h = Harness::new("users-sessions");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    let other = h.login("member", MEMBER_PASSWORD);
    let listed = h.call("GET", &format!("/api/admin/sessions?user_ref={member_ref}"), Some(&admin), None);
    assert_eq!(listed.status, 200, "{:?}", body(&listed));
    let sessions = body(&listed)["sessions"].as_array().unwrap().clone();
    assert_eq!(sessions.len(), 2);
    let text = body(&listed).to_string();
    assert!(!text.contains(&member) && !text.contains(&other), "不回令牌");
    assert!(!text.contains("token"), "不回令牌摘要字段");

    let session_ref = sessions[0]["session_ref"].as_str().unwrap().to_string();
    let one = h.call("POST", "/api/admin/sessions/revoke", Some(&admin), Some(json!({"session_ref": session_ref})));
    assert_eq!(body(&one)["revoked"], 1);
    let repeat = h.call("POST", "/api/admin/sessions/revoke", Some(&admin), Some(json!({"session_ref": session_ref})));
    assert_eq!(repeat.status, 200);
    assert_eq!(body(&repeat)["revoked"], 0, "重复撤销幂等");
    let still = [member.as_str(), other.as_str()].iter().filter(|token| h.call("GET", "/api/auth/me", Some(**token), None).status == 200).count();
    assert_eq!(still, 1, "按会话撤销只撤这一条");

    let all = h.call("POST", "/api/admin/sessions/revoke", Some(&admin), Some(json!({"user_ref": member_ref})));
    assert_eq!(body(&all)["revoked"], 1);
    assert_eq!(h.call("GET", "/api/auth/me", Some(&member), None).status, 401);
    assert_eq!(h.call("GET", "/api/auth/me", Some(&other), None).status, 401);
    let both = h.call("POST", "/api/admin/sessions/revoke", Some(&admin), Some(json!({"user_ref": member_ref, "session_ref": session_ref})));
    assert_eq!(both.status, 400, "两个目标只能给一个");
    let listed_after = h.call("GET", &format!("/api/admin/sessions?user_ref={member_ref}"), Some(&admin), None);
    assert!(body(&listed_after)["sessions"].as_array().unwrap().iter().all(|session| session["status"] == "REVOKED"));
}

#[test]
fn unknown_api_paths_need_a_session_and_are_not_found_rather_than_not_migrated() {
    let h = Harness::new("users-unknown");
    let admin = h.setup_admin();
    assert_eq!(h.call("GET", "/api/whatever", None, None).status, 401);
    let unknown = h.call("GET", "/api/whatever", Some(&admin), None);
    assert_eq!(unknown.status, 404);
    assert_eq!(body(&unknown)["code"], "CONTROL_NOT_FOUND");
    let wrong_method = h.call("DELETE", "/api/admin/users", Some(&admin), None);
    assert_eq!(wrong_method.status, 405);
    for (method, path) in ROUTES {
        let body_value = if *method == "GET" { None } else { Some(json!({})) };
        let response = h.call(method, path, Some(&admin), body_value);
        assert!(![404, 405, 501].contains(&response.status), "{method} {path} 落入 {}", response.status);
        assert_ne!(body(&response)["code"], "CONTROL_CAPABILITY_NOT_MIGRATED");
    }
}
