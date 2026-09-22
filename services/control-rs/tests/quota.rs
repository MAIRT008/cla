//! 配额适配：Remnawave 合成权威经注入传输接入。核对请求形状、身份唯一、操作幂等、写后回读、
//! 陈旧快照、停用/恢复与池状态。本机不向任何真实 Remnawave 发请求。
//!
//! 本机没有 cargo/rustc，这些用例已写未运行。

mod common;

use common::*;
use serde_json::json;

const GB_250: i64 = 250_000_000_000;

fn allocate(h: &Harness, admin: &str, user_ref: &str, operation_id: &str, limit: i64) -> serde_json::Value {
    let response = h.call(
        "POST",
        "/api/admin/quota/allocate",
        Some(admin),
        Some(json!({"userRef": user_ref, "operation_id": operation_id, "limitBytes": limit, "period": "MONTH", "expireAt": "2027-01-01T00:00:00.000Z"})),
    );
    assert_eq!(response.status, 200, "{:?}", body(&response));
    body(&response)
}

#[test]
fn the_adapter_is_configured_write_only_and_calls_carry_the_fixed_contract() {
    let h = Harness::new("quota-contract");
    let admin = h.setup_admin();
    let (member_ref, _) = h.create_member(&admin, "member");

    let unconfigured = h.call("POST", "/api/admin/quota/allocate", Some(&admin), Some(json!({"userRef": member_ref, "operation_id": "op-x", "limitBytes": 1000, "expireAt": "2027-01-01T00:00:00Z"})));
    assert_eq!(unconfigured.status, 503, "没配权威时不伪造结果");
    assert_eq!(body(&unconfigured)["code"], "AUTHORITY_UNCONFIGURED");
    assert!(h.transport.calls().is_empty(), "未配置时不发任何请求");

    let authority = attach_authority(&h, &admin);
    let view = h.call("GET", "/api/admin/quota-adapter", Some(&admin), None);
    let text = body(&view).to_string();
    assert_eq!(body(&view)["adapter"]["configured"], true);
    assert_eq!(body(&view)["adapter"]["token_present"], true);
    assert_eq!(body(&view)["adapter"]["verification"], "NOT_TESTED", "保存配置不等于验证过");
    assert!(!text.contains(REMNAWAVE_TOKEN), "令牌只写不读");
    assert!(!contains_bytes(&h.database_bytes(), REMNAWAVE_TOKEN), "库里只有密文");

    let first = allocate(&h, &admin, &member_ref, "alloc-1", 1000);
    let calls = h.transport.calls();
    assert_eq!(calls[0].method, "POST");
    assert_eq!(calls[0].url, format!("{REMNAWAVE_URL}/api/users"));
    assert_eq!(calls[0].authorization.as_deref(), Some(format!("Bearer {REMNAWAVE_TOKEN}").as_str()));
    let sent = calls[0].body.clone().unwrap();
    assert_eq!(sent["trafficLimitBytes"], 1000);
    assert_eq!(sent["trafficLimitStrategy"], "MONTH");
    assert!(sent.get("operation_id").is_none(), "幂等键不外发");
    assert_eq!(first["created"], true);
    let provider_id = first["binding"]["provider_user_id"].as_i64().unwrap();
    assert!(authority.state.lock().unwrap().users.contains_key(&provider_id));
    assert!(!first.to_string().contains("aaaaaaaa-aaaa"), "权威侧秘密只投影成存在性");
    assert_eq!(first["projected"]["secrets_present"]["vlessUuid"], true);
    assert_eq!(body(&h.call("GET", "/api/admin/quota-adapter", Some(&admin), None))["adapter"]["verification"], "CALL_SUCCEEDED");

    let log = h.log_text();
    assert!(!log.contains(REMNAWAVE_TOKEN) && !log.contains("remnawave.synthetic.invalid/api"), "日志不记令牌");

    let unlimited = h.call("POST", "/api/admin/quota/allocate", Some(&admin), Some(json!({"userRef": member_ref, "operation_id": "zero", "limitBytes": 0, "expireAt": "2027-01-01T00:00:00Z"})));
    assert_eq!(unlimited.status, 400);
    assert_eq!(body(&unlimited)["code"], "LIMIT_REQUIRED");
}

#[test]
fn operations_are_idempotent_and_identities_stay_one_to_one() {
    let h = Harness::new("quota-idempotent");
    let admin = h.setup_admin();
    let (alice_ref, _) = h.create_member(&admin, "alice");
    let (bob_ref, _) = h.create_member(&admin, "bob");
    let authority = attach_authority(&h, &admin);
    let first = allocate(&h, &admin, &alice_ref, "same-op", 1000);
    let replay = allocate(&h, &admin, &alice_ref, "same-op", 1000);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["binding"]["provider_user_id"], first["binding"]["provider_user_id"]);
    assert_eq!(authority.state.lock().unwrap().users.len(), 1, "重试不多建权威用户");

    let mismatch = h.call("POST", "/api/admin/quota/allocate", Some(&admin), Some(json!({"userRef": alice_ref, "operation_id": "same-op", "limitBytes": 2000, "expireAt": "2027-01-01T00:00:00Z"})));
    assert_eq!(mismatch.status, 409);
    assert_eq!(body(&mismatch)["code"], "QUOTA_OPERATION_MISMATCH");

    let again = allocate(&h, &admin, &alice_ref, "second-op", 1000);
    assert_eq!(again["created"], false, "已有绑定只回读，不再新建");

    let bob = allocate(&h, &admin, &bob_ref, "alloc-bob", 1000);
    assert_ne!(bob["binding"]["provider_user_id"], first["binding"]["provider_user_id"]);
    let stolen = h.sql().execute(
        "UPDATE control_provider_bindings SET provider_user_id = ?1 WHERE user_ref = ?2",
        rusqlite::params![first["binding"]["provider_user_id"].as_i64().unwrap(), bob_ref],
    );
    assert!(stolen.is_err(), "数据库唯一键拒绝两个应用用户绑到同一权威身份");

    let h = h.reopen();
    let admin = h.login("admin", ADMIN_PASSWORD);
    let replay_after_restart = allocate(&h, &admin, &alice_ref, "same-op", 1000);
    assert_eq!(replay_after_restart["replayed"], true, "操作回执落库，重启后仍幂等");
}

#[test]
fn limits_suspension_and_resume_are_read_back_from_the_authority() {
    let h = Harness::new("quota-lifecycle");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    publish_single(&h, &admin, &member_ref, "res-a-member");
    let authority = attach_authority(&h, &admin);
    let allocated = allocate(&h, &admin, &member_ref, "alloc", 1000);
    let provider_id = allocated["binding"]["provider_user_id"].as_i64().unwrap();

    authority.consume(provider_id, 1000);
    let limited = h.call("GET", "/api/network/quota", Some(&member), None);
    assert_eq!(body(&limited)["quota"]["status"], "LIMITED");
    assert_eq!(body(&limited)["view"]["next_action"], "KEEP_APPROVED_DIRECT_STOP_PROXY");
    let still_limited = h.call("POST", "/api/admin/quota/resume", Some(&admin), Some(json!({"userRef": member_ref, "operation_id": "resume-early"})));
    assert_eq!(body(&still_limited)["code"], "STILL_LIMITED");

    let raised = h.call("POST", "/api/admin/quota/limit", Some(&admin), Some(json!({"userRef": member_ref, "operation_id": "raise", "limit_value": 250, "limit_unit": "GB"})));
    assert_eq!(raised.status, 200, "{:?}", body(&raised));
    assert_eq!(body(&raised)["effective"], true, "以回读到的额度为准");
    assert_eq!(body(&raised)["snapshot"]["limit_bytes"], GB_250);

    let suspended = h.call(
        "POST",
        "/api/admin/quota/suspend",
        Some(&admin),
        Some(json!({"userRef": member_ref, "operation_id": "suspend", "nodeEffect": {"accepted": true, "verified_disconnect": "VERIFIED"}})),
    );
    assert_eq!(suspended.status, 200, "{:?}", body(&suspended));
    assert_eq!(body(&suspended)["snapshot"]["status"], "DISABLED");
    assert_eq!(body(&suspended)["node_effect"]["verified_disconnect"], "UNKNOWN", "节点断连效果不能由调用方声明");
    let credentials = h.call("GET", "/api/network/credentials", Some(&member), None);
    assert_eq!(body(&credentials)["code"], "QUOTA_DISABLED", "停用后不再下发个人凭据");

    let resumed = h.call("POST", "/api/admin/quota/resume", Some(&admin), Some(json!({"userRef": member_ref, "operation_id": "resume"})));
    assert_eq!(resumed.status, 200, "{:?}", body(&resumed));
    assert_eq!(body(&resumed)["restored_roles"]["A"], "res-a-member", "恢复原绑定");
    assert_eq!(body(&resumed)["snapshot"]["status"], "ACTIVE");

    let other_user = h.call("POST", "/api/admin/quota/limit", Some(&member), Some(json!({"userRef": member_ref, "operation_id": "steal", "limitBytes": 1})));
    assert_eq!(other_user.status, 403);

    let _ = h.call("POST", "/api/admin/assignments/revoke", Some(&admin), Some(json!({"userRef": member_ref})));
    let revoked_resume = h.call("POST", "/api/admin/quota/resume", Some(&admin), Some(json!({"userRef": member_ref, "operation_id": "resume-revoked"})));
    assert_eq!(revoked_resume.status, 409);
    assert_eq!(body(&revoked_resume)["code"], "ASSIGNMENT_REVOKED", "撤销的分配不能恢复");
}

#[test]
fn a_lost_disable_response_is_recovered_by_reading_back_without_a_second_call() {
    let h = Harness::new("quota-lost-response");
    let admin = h.setup_admin();
    let (member_ref, _) = h.create_member(&admin, "member");
    let authority = attach_authority(&h, &admin);
    allocate(&h, &admin, &member_ref, "alloc", 1000);
    authority.state.lock().unwrap().drop_disable_response = true;
    let first = h.call("POST", "/api/admin/quota/suspend", Some(&admin), Some(json!({"userRef": member_ref, "operation_id": "suspend-lost"})));
    assert_eq!(first.status, 503);
    authority.state.lock().unwrap().drop_disable_response = false;
    let retry = h.call("POST", "/api/admin/quota/suspend", Some(&admin), Some(json!({"userRef": member_ref, "operation_id": "suspend-lost"})));
    assert_eq!(retry.status, 200, "{:?}", body(&retry));
    assert_eq!(body(&retry)["replayed"], true);
    assert_eq!(body(&retry)["snapshot"]["status"], "DISABLED");
    let disables = h.transport.calls().iter().filter(|call| call.url.ends_with("/actions/disable")).count();
    assert_eq!(disables, 1, "结果未知时先回读，不二次停用");
}

#[test]
fn authority_outages_keep_the_last_snapshot_marked_stale() {
    let h = Harness::new("quota-stale");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    let authority = attach_authority(&h, &admin);
    allocate(&h, &admin, &member_ref, "alloc", 5000);
    let provider_id = authority.state.lock().unwrap().users.keys().copied().next().unwrap();
    authority.consume(provider_id, 2000);
    let live = h.call("GET", "/api/network/quota", Some(&member), None);
    assert_eq!(body(&live)["quota"]["used_bytes"], 2000);
    assert_eq!(body(&live)["stale"], false);

    authority.state.lock().unwrap().backend_available = false;
    let stale = h.call("GET", "/api/network/quota", Some(&member), None);
    assert_eq!(body(&stale)["quota"]["used_bytes"], 2000, "不回零");
    assert_eq!(body(&stale)["quota"]["stale"], true);
    assert_eq!(body(&stale)["quota"]["authority_status"], "OFFLINE");
    assert_eq!(body(&stale)["quota"]["node_new_limit_judgment"], "UNAVAILABLE");
    assert_eq!(body(&stale)["code"], "AUTHORITY_UNAVAILABLE");

    let disabled = h.call("PUT", "/api/admin/quota-adapter", Some(&admin), Some(json!({"enabled": false})));
    assert_eq!(body(&disabled)["adapter"]["configured"], false);
    let unconfigured = h.call("GET", "/api/network/quota", Some(&member), None);
    assert_eq!(body(&unconfigured)["code"], "AUTHORITY_UNCONFIGURED");
    assert_eq!(body(&unconfigured)["quota"]["used_bytes"], 2000);

    h.advance(-10 * 365 * 24 * 3_600_000);
    let h = h.reopen();
    let member = h.login("member", MEMBER_PASSWORD);
    let after = h.call("GET", "/api/network/quota", Some(&member), None);
    assert_eq!(body(&after)["quota"]["used_bytes"], 2000, "改时钟、重启都不清账");

    let (fresh_ref, fresh) = h.create_member(&h.login("admin", ADMIN_PASSWORD), "fresh");
    let _ = fresh_ref;
    let never = h.call("GET", "/api/network/quota", Some(&fresh), None);
    assert_eq!(body(&never)["quota"]["status"], "UNKNOWN", "没有快照时是未知，不是零也不是无限");
    assert_eq!(body(&never)["quota"]["unlimited"], false);
}

#[test]
fn pool_exhaustion_is_reported_separately_from_user_limits() {
    let h = Harness::new("quota-pool");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    let authority = attach_authority(&h, &admin);
    allocate(&h, &admin, &member_ref, "alloc", GB_250);
    authority.state.lock().unwrap().pool_exhausted = true;
    let pool = h.call("GET", "/api/admin/quota/pool", Some(&admin), None);
    assert_eq!(body(&pool)["snapshot"]["exhausted"], true);
    assert_eq!(body(&pool)["snapshot"]["user_quota_sum_is_not_pool"], true);
    assert_eq!(body(&pool)["snapshot"]["shared_subscription_balance"]["status"], "UNKNOWN");
    assert_ne!(body(&h.call("GET", "/api/network/quota", Some(&member), None))["quota"]["status"], "LIMITED", "池耗尽不算用户超额");

    authority.state.lock().unwrap().backend_available = false;
    let offline = h.call("GET", "/api/admin/quota/pool", Some(&admin), None);
    assert_eq!(body(&offline)["ok"], false);
    assert_eq!(body(&offline)["snapshot"]["stale"], true);
    assert_eq!(body(&offline)["snapshot"]["exhausted"], true, "回最后一次池快照");

    let state = h.call("GET", "/api/admin/service-state", Some(&admin), None);
    assert_eq!(body(&state)["adapter_configured"], true);
    assert_eq!(body(&state)["secret_protection"], "test-deterministic");
    assert_eq!(body(&state)["schema_version"], "3");
}
