//! 秘密落盘与读取失败的安全表现，日志脱敏，以及最小网络事件。
//!
//! 本机没有 cargo/rustc，这些用例已写未运行。

mod common;

use common::*;
use serde_json::{json, Value};

fn credential_setup(h: &Harness) -> (String, String) {
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    publish_single(h, &admin, &member_ref, "res-a-member");
    for credential_ref in ["cred-res-front", "cred-res-a-member"] {
        let saved = h.call(
            "PUT",
            "/api/admin/credentials",
            Some(&admin),
            Some(json!({"user_ref": member_ref, "credential_ref": credential_ref, "username": "member-proxy", "password": "synthetic-proxy-secret-77"})),
        );
        assert_eq!(saved.status, 200);
    }
    (admin, member)
}

#[test]
fn tampered_or_misplaced_ciphertext_fails_safely_without_echo() {
    let h = Harness::new("secrets-tamper");
    let (admin, member) = credential_setup(&h);
    assert_eq!(body(&h.call("GET", "/api/network/credentials", Some(&member), None))["status"], "AVAILABLE");

    let connection = h.sql();
    let (secret_ref, mut ciphertext): (String, Vec<u8>) = connection
        .query_row(
            "SELECT secret_ref, ciphertext FROM control_secrets WHERE purpose LIKE 'personal_credential:%:cred-res-front'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xFF;
    connection
        .execute("UPDATE control_secrets SET ciphertext = ?1 WHERE secret_ref = ?2", rusqlite::params![ciphertext, secret_ref])
        .unwrap();
    drop(connection);
    let tampered = h.call("GET", "/api/network/credentials", Some(&member), None);
    assert_eq!(tampered.status, 200);
    let value = body(&tampered);
    assert!(value["credentials"].get("cred-res-front").is_none());
    assert!(value["withheld"].as_array().unwrap().iter().any(|item| item["credential_ref"] == "cred-res-front" && item["reason"] == "CONTROL_SECRET_UNREADABLE"));
    assert!(!value.to_string().contains("TP1"), "不回显密文");
    assert!(h.log_text().contains("network.credentials.unreadable"), "读取失败记日志");

    h.sql().execute("UPDATE control_secrets SET protector = 'windows-dpapi-current-user' WHERE purpose LIKE 'personal_credential:%cred-res-a-member'", []).unwrap();
    let wrong_protector = body(&h.call("GET", "/api/network/credentials", Some(&member), None));
    assert!(wrong_protector["credentials"].as_object().unwrap().is_empty(), "保护方式不符同样读不出");

    configure_model(&h, &admin);
    h.sql()
        .execute(
            "UPDATE control_secrets SET ciphertext = (SELECT ciphertext FROM control_secrets WHERE purpose LIKE 'subscription_url:%' LIMIT 1) WHERE purpose = 'model_api_key:cleanup' AND EXISTS (SELECT 1 FROM control_secrets WHERE purpose LIKE 'subscription_url:%')",
            [],
        )
        .unwrap();
    let copied: i64 = h.sql().query_row("SELECT COUNT(*) FROM control_secrets WHERE purpose LIKE 'subscription_url:%'", [], |row| row.get(0)).unwrap();
    assert_eq!(copied, 1, "跨用途复制的前提：库里有另一用途的密文");
    let turn = h.call(
        "POST",
        "/api/ai/turn",
        Some(&member),
        Some(json!({"task_ref": "task-s", "task_type": "cleanup", "turn_ref": "t1", "prompt_version": "cleanup-v1", "prompt_body": "p", "tool_catalog_version": "cleanup-tools-v1", "messages": []})),
    );
    assert_eq!(turn.status, 503, "{:?}", body(&turn));
    assert_eq!(body(&turn)["reason"], "MODEL_SECRET_UNREADABLE", "跨用途密文读不出，不当成可用");
    assert!(h.transport.calls().is_empty(), "读不出 Key 就不调模型");
}

fn configure_model(h: &Harness, admin: &str) {
    let saved = h.call(
        "PUT",
        "/api/admin/model-config",
        Some(admin),
        Some(json!({"task_type": "cleanup", "enabled": true, "base_url": "https://model.synthetic.invalid/v1", "model": "m", "policy_version": "p1", "api_key": MODEL_KEY})),
    );
    assert_eq!(saved.status, 200);
    let source = h.call(
        "PUT",
        "/api/admin/subscriptions",
        Some(admin),
        Some(json!({"source_id": "src-copy", "url": "https://sub.synthetic.invalid/other-purpose-secret"})),
    );
    assert_eq!(source.status, 200);
}

#[test]
fn logs_stay_free_of_every_secret_the_admin_entered() {
    let h = Harness::new("secrets-logs");
    let (admin, member) = credential_setup(&h);
    configure_model(&h, &admin);
    let _ = attach_authority(&h, &admin);
    let _ = h.call("GET", "/api/network/credentials", Some(&member), None);
    let _ = h.call("GET", "/api/admin/quota-adapter", Some(&admin), None);
    let log = h.log_text();
    for secret in ["synthetic-proxy-secret-77", MODEL_KEY, REMNAWAVE_TOKEN, "other-purpose-secret", ADMIN_PASSWORD, MEMBER_PASSWORD, member.as_str(), admin.as_str()] {
        assert!(!log.contains(secret), "日志里出现了秘密 {secret}");
    }
    for line in log.lines() {
        let parsed: Value = serde_json::from_str(line).unwrap();
        assert!(parsed["event"].is_string());
    }
    assert!(log.contains("admin.credential.saved") && log.contains("admin.model_config.saved") && log.contains("request.completed"));
}

#[test]
fn minimal_events_are_deduplicated_owned_and_stripped() {
    let h = Harness::new("events");
    let admin = h.setup_admin();
    let (alice_ref, alice) = h.create_member(&admin, "alice");
    let (_, bob) = h.create_member(&admin, "bob");
    let first = h.call(
        "POST",
        "/api/network/events",
        Some(&alice),
        Some(json!({"event_ref": "evt-1", "kind": "WRONG_ROUTE", "classification": "WRONG_ROUTE", "count": 1, "first_at": "2026-09-13T17:00:00.000Z", "last_at": "2026-09-13T17:00:00.000Z", "protection_status": "ACCEPTED", "raw_log_excerpt": "full line with details"})),
    );
    assert_eq!(body(&first), json!({"status": "RECORDED", "event_ref": "evt-1", "duplicate": false}));
    let duplicate = h.call(
        "POST",
        "/api/network/events",
        Some(&alice),
        Some(json!({"event_ref": "evt-1", "kind": "WRONG_ROUTE", "count": 3, "last_at": "2026-09-13T18:00:00.000Z", "protection_status": "CONFIRMED"})),
    );
    assert_eq!(body(&duplicate)["duplicate"], true);
    let downgrade = h.call(
        "POST",
        "/api/network/events",
        Some(&alice),
        Some(json!({"event_ref": "evt-1", "count": 2, "last_at": "2026-09-13T17:30:00.000Z", "protection_status": "PENDING"})),
    );
    assert_eq!(downgrade.status, 200);

    let listed = h.call("GET", "/api/network/events", Some(&alice), None);
    let events = body(&listed)["events"].as_array().unwrap().clone();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["count"], 3, "计数取大");
    assert_eq!(events[0]["first_at"], "2026-09-13T17:00:00.000Z");
    assert_eq!(events[0]["last_at"], "2026-09-13T18:00:00.000Z", "末次时间不倒退");
    assert_eq!(events[0]["protection_status"], "CONFIRMED", "保护状态只前进");
    assert!(events[0].get("raw_log_excerpt").is_none(), "白名单外字段不落库");
    assert!(!body(&listed).to_string().contains("full line"));

    assert!(body(&h.call("GET", "/api/network/events", Some(&bob), None))["events"].as_array().unwrap().is_empty(), "看不到别人的事件");
    let steal = h.call("POST", "/api/network/events", Some(&bob), Some(json!({"event_ref": "evt-1", "kind": "WRONG_ROUTE"})));
    assert_eq!(steal.status, 403, "event_ref 属于别人");
    let impersonate = h.call("POST", "/api/network/events", Some(&bob), Some(json!({"event_ref": "evt-2", "user_ref": alice_ref})));
    assert_eq!(impersonate.status, 403, "普通用户不能替别人提交");

    let secret = h.call("POST", "/api/network/events", Some(&alice), Some(json!({"event_ref": "evt-secret", "vlessUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})));
    assert_eq!(secret.status, 400);
    assert_eq!(body(&secret)["code"], "EVENT_SECRET_REJECTED");
    let nested = h.call("POST", "/api/network/events", Some(&alice), Some(json!({"event_ref": "evt-nested", "kind": {"yaml": "x"}})));
    assert_eq!(nested.status, 400);
    let rows: i64 = h.sql().query_row("SELECT COUNT(*) FROM control_network_events", [], |row| row.get(0)).unwrap();
    assert_eq!(rows, 1, "被拒的事件不落库");

    let by_admin = h.call("POST", "/api/network/events", Some(&admin), Some(json!({"event_ref": "evt-admin", "user_ref": alice_ref, "kind": "PROTECTION_TRIGGERED"})));
    assert_eq!(by_admin.status, 200, "管理员可代指定用户登记");
    let admin_view = h.call("GET", &format!("/api/admin/events?user_ref={alice_ref}"), Some(&admin), None);
    assert_eq!(body(&admin_view)["events"].as_array().unwrap().len(), 2);
    let receipt: String = h.sql().query_row("SELECT status FROM control_event_receipts WHERE event_ref = 'evt-1'", [], |row| row.get(0)).unwrap();
    assert_eq!(receipt, "ACCEPTED");

    let h = h.reopen();
    let alice = h.login("alice", MEMBER_PASSWORD);
    assert_eq!(body(&h.call("GET", "/api/network/events", Some(&alice), None))["events"].as_array().unwrap().len(), 2, "重启后读回");
}
