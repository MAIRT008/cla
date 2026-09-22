//! 资源、模板、订阅、分配、发布、撤销、应用回执与个人凭据换取。
//!
//! 本机没有 cargo/rustc，这些用例已写未运行。

mod common;

use common::*;
use serde_json::{json, Value};

#[test]
fn resources_are_versioned_validated_and_survive_restart() {
    let h = Harness::new("resources");
    let admin = h.setup_admin();
    put_resource(&h, &admin, "res-a-1", "A", "exit-a.synthetic.invalid");
    let updated = h.call(
        "PUT",
        "/api/admin/resources",
        Some(&admin),
        Some(json!({"resource_id": "res-a-1", "role": "A", "host": "exit-a2.synthetic.invalid", "expires_at": "2027-01-01T08:00:00+08:00", "status": "DISABLED"})),
    );
    assert_eq!(updated.status, 200, "{:?}", body(&updated));
    assert_eq!(body(&updated)["resource"]["version"], 2);
    assert_eq!(body(&updated)["resource"]["expires_at"], "2027-01-01T00:00:00.000Z", "时间统一成 UTC");
    assert_eq!(body(&updated)["created"], false);
    let bad_role = h.call("PUT", "/api/admin/resources", Some(&admin), Some(json!({"resource_id": "res-x", "role": "C", "host": "x.invalid"})));
    assert_eq!(bad_role.status, 400);
    let with_password = h.call("PUT", "/api/admin/resources", Some(&admin), Some(json!({"resource_id": "res-x", "role": "A", "host": "x.invalid", "password": "p"})));
    assert_eq!(with_password.status, 400, "资源不收代理密码");

    let h = h.reopen();
    let listed = h.call("GET", "/api/admin/resources", Some(&h.login("admin", ADMIN_PASSWORD)), None);
    let resources = body(&listed)["resources"].as_array().unwrap().clone();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["host"], "exit-a2.synthetic.invalid");
    assert_eq!(resources[0]["status"], "DISABLED");
}

#[test]
fn templates_report_error_positions_keep_history_and_published_assignments_stay_frozen() {
    let h = Harness::new("templates");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    let broken = h.call(
        "PUT",
        "/api/admin/templates",
        Some(&admin),
        Some(json!({"template_id": "managed", "template": {"control_plane": {"login": [{"host": 7}]}}})),
    );
    assert_eq!(broken.status, 400);
    assert_eq!(body(&broken)["code"], "TEMPLATE_INVALID");
    assert_eq!(body(&broken)["path"], "template.control_plane.login[0].host");
    let secret = h.call("PUT", "/api/admin/templates", Some(&admin), Some(json!({"template_id": "managed", "template": {"dns": {"doh_token": "x"}}})));
    assert_eq!(body(&secret)["code"], "TEMPLATE_SECRET_REJECTED");

    let published = publish_single(&h, &admin, &member_ref, "res-a-member");
    assert_eq!(published["ok"], true, "{published:?}");
    let v2 = h.call("PUT", "/api/admin/templates", Some(&admin), Some(template_body("managed", "template-v2", "C:/Other/claude.exe")));
    assert_eq!(body(&v2)["template"]["numeric_version"], 2);
    let history: i64 = h.sql().query_row("SELECT COUNT(*) FROM control_template_versions WHERE template_id = 'managed'", [], |row| row.get(0)).unwrap();
    assert_eq!(history, 2);
    let seen = h.call("GET", "/api/network/assignment", Some(&member), None);
    assert_eq!(body(&seen)["assignment"]["template_version"], "template-v1", "模板升级不改已发布分配");
    assert_eq!(body(&seen)["assignment"]["template"]["protected_process_paths"], json!(["C:/Program Files/Claude/claude.exe"]));
}

#[test]
fn the_record_version_is_the_only_template_version_that_reaches_assignments() {
    let h = Harness::new("template-version");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    put_resource(&h, &admin, "res-front", "front", "front.synthetic.invalid");
    put_resource(&h, &admin, "res-a-version", "A", "res-a-version.synthetic.invalid");

    let mut lagging = template_body("managed", "row-v9", "C:/Program Files/Claude/claude.exe");
    lagging["template"]["version"] = json!("body-v1");
    let saved = h.call("PUT", "/api/admin/templates", Some(&admin), Some(lagging));
    assert_eq!(saved.status, 200, "{:?}", body(&saved));
    assert_eq!(body(&saved)["template"]["version"], "row-v9");
    assert_eq!(body(&saved)["template"]["template"]["version"], "row-v9", "正文滞后的版本被记录版本覆盖");

    let mut unversioned = template_body("managed", "unused", "C:/Program Files/Claude/claude.exe");
    unversioned.as_object_mut().unwrap().remove("version");
    unversioned["template"].as_object_mut().unwrap().remove("version");
    let second = h.call("PUT", "/api/admin/templates", Some(&admin), Some(unversioned));
    assert_eq!(second.status, 200, "{:?}", body(&second));
    assert_eq!(body(&second)["template"]["version"], "template-v2");
    assert_eq!(body(&second)["template"]["template"]["version"], "template-v2", "正文缺版本时补上记录版本");
    let history: String = h
        .sql()
        .query_row("SELECT template_json FROM control_template_versions WHERE template_id = 'managed' AND numeric_version = 2", [], |row| row.get(0))
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&history).unwrap()["version"], "template-v2", "历史版本按记录版本保存");

    h.sql()
        .execute("UPDATE control_templates SET template_json = json_set(template_json, '$.version', 'body-v0') WHERE template_id = 'managed'", [])
        .unwrap();
    let listed = h.call("GET", "/api/admin/templates", Some(&admin), None);
    assert_eq!(body(&listed)["templates"][0]["template"]["version"], "template-v2", "规则生效前保存的滞后正文，读出时同样按记录版本");

    let allocated = h.call(
        "POST",
        "/api/admin/assignments",
        Some(&admin),
        Some(json!({
            "userRef": member_ref,
            "accountClass": "free",
            "allowedModes": ["daily_single_ip"],
            "resources": ["res-front", "res-a-version"],
            "roles": {"A": "res-a-version"},
            "validUntil": "2027-01-01T00:00:00.000Z",
            "templateId": "managed",
        })),
    );
    assert_eq!(allocated.status, 200, "{:?}", body(&allocated));
    let published = h.call("POST", "/api/admin/assignments/publish", Some(&admin), Some(json!({"userRef": member_ref})));
    assert_eq!(published.status, 200, "{:?}", body(&published));
    let seen = h.call("GET", "/api/network/assignment", Some(&member), None);
    assert_eq!(body(&seen)["assignment"]["template_version"], "template-v2", "分配版本取记录版本");
    assert_eq!(body(&seen)["assignment"]["template"]["version"], "template-v2", "分配冻结的正文版本与分配版本一致");
}

#[test]
fn subscription_urls_are_write_only_and_refresh_results_are_recorded_honestly() {
    let h = Harness::new("subscriptions");
    let admin = h.setup_admin();
    let url = "https://sub.synthetic.invalid/link/synthetic-subscription-secret-0042?flag=clash";
    let saved = h.call("PUT", "/api/admin/subscriptions", Some(&admin), Some(json!({"source_id": "src-1", "format": "clash-yaml", "url": url})));
    assert_eq!(saved.status, 200, "{:?}", body(&saved));
    assert_eq!(body(&saved)["source"]["url_present"], true);
    assert_eq!(body(&saved)["source"]["url_display"], "https://sub.synthetic.invalid/…");
    let listed = h.call("GET", "/api/admin/subscriptions", Some(&admin), None);
    assert!(!body(&listed).to_string().contains("synthetic-subscription-secret"), "列表不回订阅链接");
    assert!(!contains_bytes(&h.database_bytes(), "synthetic-subscription-secret"), "库里没有明文链接");

    let yaml = ["proxies:", "  - {name: node-a, type: socks5, server: a.synthetic.invalid, port: 1080, password: synthetic-proxy-pass}", ""].join("\n");
    let yaml_for_script = yaml.clone();
    h.transport.script(move |request| {
        assert!(request.url.contains("synthetic-subscription-secret"), "刷新时才解出完整链接");
        text_response(200, &yaml_for_script)
    });
    let refreshed = h.call("POST", "/api/admin/subscriptions/refresh", Some(&admin), Some(json!({"source_id": "src-1"})));
    assert_eq!(refreshed.status, 200);
    assert_eq!(body(&refreshed)["ok"], true, "{:?}", body(&refreshed));
    assert_eq!(body(&refreshed)["source"]["proxy_count"], 1);
    assert_eq!(body(&refreshed)["proxies"][0]["server"], "a.synthetic.invalid");
    assert!(!body(&refreshed).to_string().contains("synthetic-proxy-pass"), "代理密码不外传");
    assert_eq!(h.transport.calls().len(), 1);

    h.transport.script(|_| text_response(503, "down"));
    let failed = h.call("POST", "/api/admin/subscriptions/refresh", Some(&admin), Some(json!({"source_id": "src-1"})));
    assert_eq!(body(&failed)["ok"], false);
    assert_eq!(body(&failed)["code"], "SOURCE_FETCH_FAILED");
    assert_eq!(body(&failed)["http_status"], 503);
    assert_eq!(body(&failed)["source"]["status"], "FAILED", "HTTP 失败不能标 ACTIVE");
    assert_eq!(body(&failed)["source"]["proxy_count"], 1, "保留上一次成功的解析结果");

    let _ = h.call("PUT", "/api/admin/subscriptions", Some(&admin), Some(json!({"source_id": "src-2", "format": "v2ray-base64"})));
    let unsupported = h.call("POST", "/api/admin/subscriptions/refresh", Some(&admin), Some(json!({"source_id": "src-2", "body": "dm1lc3M6Ly8="})));
    assert_eq!(body(&unsupported)["code"], "UNSUPPORTED");
    assert_eq!(body(&unsupported)["source"]["status"], "UNSUPPORTED");
    let _ = h.call("PUT", "/api/admin/subscriptions", Some(&admin), Some(json!({"source_id": "src-3"})));
    let no_proxies = h.call("POST", "/api/admin/subscriptions/refresh", Some(&admin), Some(json!({"source_id": "src-3", "body": "rules: []"})));
    assert_eq!(body(&no_proxies)["code"], "UNSUPPORTED");
    let empty = h.call("POST", "/api/admin/subscriptions/refresh", Some(&admin), Some(json!({"source_id": "src-3"})));
    assert_eq!(empty.status, 400, "没有内容也没有链接");
    let missing = h.call("POST", "/api/admin/subscriptions/refresh", Some(&admin), Some(json!({"source_id": "src-none", "body": yaml})));
    assert_eq!(missing.status, 404);

    let cleared = h.call("PUT", "/api/admin/subscriptions", Some(&admin), Some(json!({"source_id": "src-1", "clear_url": true})));
    assert_eq!(body(&cleared)["source"]["url_present"], false);
    let secrets: i64 = h.sql().query_row("SELECT COUNT(*) FROM control_secrets WHERE purpose = 'subscription_url:src-1'", [], |row| row.get(0)).unwrap();
    assert_eq!(secrets, 0, "清除后密文也删除");
}

#[test]
fn candidates_are_not_visible_until_published_and_revocation_is_visible() {
    let h = Harness::new("assignments");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    put_resource(&h, &admin, "res-front", "front", "front.synthetic.invalid");
    put_resource(&h, &admin, "res-a", "A", "a.synthetic.invalid");

    let no_template = h.call(
        "POST",
        "/api/admin/assignments",
        Some(&admin),
        Some(json!({"userRef": member_ref, "allowedModes": ["daily_single_ip"], "resources": ["res-a"], "roles": {"A": "res-a"}, "validUntil": "2027-01-01T00:00:00Z"})),
    );
    assert_eq!(no_template.status, 409, "没有已发布模板时不回退到内置样例");
    assert_eq!(body(&no_template)["code"], "TEMPLATE_UNAVAILABLE");
    let _ = h.call("PUT", "/api/admin/templates", Some(&admin), Some(template_body("managed", "template-v1", "C:/Claude/claude.exe")));

    let wrong_role = h.call(
        "POST",
        "/api/admin/assignments",
        Some(&admin),
        Some(json!({"userRef": member_ref, "allowedModes": ["daily_single_ip"], "roles": {"A": "res-front"}, "validUntil": "2027-01-01T00:00:00Z"})),
    );
    assert_eq!(body(&wrong_role)["code"], "ROLE_MISMATCH");
    let unknown_resource = h.call(
        "POST",
        "/api/admin/assignments",
        Some(&admin),
        Some(json!({"userRef": member_ref, "allowedModes": ["daily_single_ip"], "roles": {"A": "res-nope"}, "validUntil": "2027-01-01T00:00:00Z"})),
    );
    assert_eq!(unknown_resource.status, 404);
    let unknown_user = h.call(
        "POST",
        "/api/admin/assignments",
        Some(&admin),
        Some(json!({"userRef": "usr-ghost", "allowedModes": ["daily_single_ip"], "roles": {"A": "res-a"}, "validUntil": "2027-01-01T00:00:00Z"})),
    );
    assert_eq!(unknown_user.status, 404);

    let forged = h.call(
        "POST",
        "/api/admin/assignments",
        Some(&admin),
        Some(json!({
            "userRef": member_ref,
            "allowedModes": ["daily_single_ip", "claude_dual_ip"],
            "resources": [{"resource_id": "res-a", "host": "attacker.invalid", "status": "ACTIVE"}, "res-front"],
            "roles": {"A": "res-a"},
            "validUntil": "2027-01-01T00:00:00Z",
            "templateId": "managed",
        })),
    );
    assert_eq!(forged.status, 200, "{:?}", body(&forged));
    assert_eq!(body(&forged)["assignment"]["resources"]["res-a"]["host"], "a.synthetic.invalid", "资源属性只取服务端记录");
    assert_eq!(body(&forged)["ready"], false, "要双 IP 但没有 B");
    assert!(body(&forged)["validation"]["issues"].as_array().unwrap().contains(&json!("DUAL_IP_REQUIRES_B")));
    let not_ready = h.call("POST", "/api/admin/assignments/publish", Some(&admin), Some(json!({"userRef": member_ref})));
    assert_eq!(body(&not_ready)["ok"], false);
    assert!(body(&h.call("GET", "/api/network/assignment", Some(&member), None))["assignment"].is_null(), "未发布的候选不下发");

    let saved = h.call(
        "POST",
        "/api/admin/assignments",
        Some(&admin),
        Some(json!({"userRef": member_ref, "allowedModes": ["daily_single_ip"], "resources": ["res-front", "res-a"], "roles": {"A": "res-a"}, "validUntil": "2027-01-01T00:00:00Z", "templateId": "managed"})),
    );
    assert_eq!(body(&saved)["assignment"]["assignment_version"], 2);
    let published = h.call("POST", "/api/admin/assignments/publish", Some(&admin), Some(json!({"userRef": member_ref})));
    assert_eq!(body(&published)["ok"], true, "{:?}", body(&published));
    assert_eq!(body(&published)["receipt"]["receipt_id"], format!("published:{member_ref}:2"));
    let seen = h.call("GET", "/api/network/assignment", Some(&member), None);
    assert_eq!(body(&seen)["assignment"]["status"], "ACTIVE");
    assert_eq!(body(&seen)["assignment"]["resource_refs"]["front"], "res-front");

    // 发布后再存一版候选（改 A 的主机）：已发布版本不变；发布需要显式确认。
    put_resource(&h, &admin, "res-a", "A", "a-moved.synthetic.invalid");
    let _ = h.call(
        "POST",
        "/api/admin/assignments",
        Some(&admin),
        Some(json!({"userRef": member_ref, "allowedModes": ["daily_single_ip"], "resources": ["res-front", "res-a"], "roles": {"A": "res-a"}, "validUntil": "2027-01-01T00:00:00Z", "templateId": "managed"})),
    );
    assert_eq!(body(&h.call("GET", "/api/network/assignment", Some(&member), None))["assignment"]["resources"]["res-a"]["host"], "a.synthetic.invalid");
    let sensitive = h.call("POST", "/api/admin/assignments/publish", Some(&admin), Some(json!({"userRef": member_ref})));
    assert_eq!(body(&sensitive)["code"], "SENSITIVE_CHANGE_CONFIRMATION_REQUIRED");
    let confirmed = h.call("POST", "/api/admin/assignments/publish", Some(&admin), Some(json!({"userRef": member_ref, "confirmation": {"confirmed": true}})));
    assert_eq!(body(&confirmed)["ok"], true);
    assert_eq!(body(&confirmed)["sensitive"], true);
    let view = h.call("GET", &format!("/api/admin/assignments?user_ref={member_ref}"), Some(&admin), None);
    assert!(body(&view)["candidate"].is_null(), "发布后候选清空");
    assert_eq!(body(&view)["published"]["assignment_version"], 3);

    let revoked = h.call("POST", "/api/admin/assignments/revoke", Some(&admin), Some(json!({"user_ref": member_ref})));
    assert_eq!(body(&revoked)["assignment"]["status"], "REVOKED");
    let h = h.reopen();
    let member = h.login("member", MEMBER_PASSWORD);
    let after = h.call("GET", "/api/network/assignment", Some(&member), None);
    assert_eq!(body(&after)["assignment"]["revoked"], true, "撤销在重启后仍可见，客户端据此停用缓存配置");
}

fn credentials_of(h: &Harness, token: &str) -> Value {
    let response = h.call("GET", "/api/network/credentials", Some(token), None);
    assert_eq!(response.status, 200);
    assert_eq!(response.header_value("cache-control"), Some("no-store"));
    body(&response)
}

#[test]
fn personal_credentials_are_issued_only_to_their_owner_under_a_valid_assignment() {
    let h = Harness::new("credentials");
    let admin = h.setup_admin();
    let (alice_ref, alice) = h.create_member(&admin, "alice");
    let (bob_ref, bob) = h.create_member(&admin, "bob");
    let (_, carol) = h.create_member(&admin, "carol");
    publish_single(&h, &admin, &alice_ref, "res-a-alice");
    let _ = h.call(
        "POST",
        "/api/admin/assignments",
        Some(&admin),
        Some(json!({"userRef": bob_ref, "allowedModes": ["daily_single_ip"], "resources": ["res-front", "res-a-alice"], "roles": {"A": "res-a-alice"}, "validUntil": "2027-01-01T00:00:00Z", "templateId": "managed"})),
    );
    let _ = h.call("POST", "/api/admin/assignments/publish", Some(&admin), Some(json!({"userRef": bob_ref})));
    for (user_ref, name) in [(&alice_ref, "alice"), (&bob_ref, "bob")] {
        for credential_ref in ["cred-res-front", "cred-res-a-alice"] {
            let saved = h.call(
                "PUT",
                "/api/admin/credentials",
                Some(&admin),
                Some(json!({"user_ref": user_ref, "credential_ref": credential_ref, "username": format!("{name}-{credential_ref}"), "password": format!("synthetic-pass-{name}-{credential_ref}")})),
            );
            assert_eq!(saved.status, 200, "{:?}", body(&saved));
            assert!(!body(&saved).to_string().contains("synthetic-pass"), "保存响应不回显");
        }
    }
    assert!(!contains_bytes(&h.database_bytes(), "synthetic-pass-alice"), "库里只有密文");

    let alice_view = credentials_of(&h, &alice);
    assert_eq!(alice_view["status"], "AVAILABLE");
    assert_eq!(alice_view["credentials"]["cred-res-a-alice"]["username"], "alice-cred-res-a-alice");
    assert!(!alice_view.to_string().contains("bob-"), "拿不到别人的凭据");
    let bob_view = credentials_of(&h, &bob);
    assert_eq!(bob_view["credentials"]["cred-res-front"]["password"], "synthetic-pass-bob-cred-res-front");
    let carol_view = credentials_of(&h, &carol);
    assert_eq!(carol_view["code"], "ASSIGNMENT_NOT_FOUND");
    assert!(carol_view["credentials"].as_object().unwrap().is_empty(), "未分配不下发");

    let listed = h.call("GET", &format!("/api/admin/credentials?user_ref={alice_ref}"), Some(&admin), None);
    assert!(!body(&listed).to_string().contains("synthetic-pass"), "管理列表也不回显");
    assert_eq!(h.call("GET", "/api/admin/credentials?user_ref=x", Some(&alice), None).status, 403);

    let _ = h.call("POST", "/api/admin/credentials/revoke", Some(&admin), Some(json!({"user_ref": alice_ref, "credential_ref": "cred-res-front"})));
    let after_revoke = credentials_of(&h, &alice);
    assert!(after_revoke["credentials"].get("cred-res-front").is_none());
    assert!(after_revoke["withheld"].as_array().unwrap().iter().any(|item| item["reason"] == "CREDENTIAL_REVOKED"));

    let _ = h.call("PUT", "/api/admin/resources", Some(&admin), Some(json!({"resource_id": "res-a-alice", "role": "A", "host": "res-a-alice.synthetic.invalid", "status": "DISABLED"})));
    let disabled = credentials_of(&h, &bob);
    assert!(disabled["credentials"].get("cred-res-a-alice").is_none(), "资源停用后不再下发");

    let _ = h.call("POST", "/api/admin/assignments/revoke", Some(&admin), Some(json!({"userRef": bob_ref})));
    let revoked = credentials_of(&h, &bob);
    assert_eq!(revoked["code"], "ASSIGNMENT_REVOKED");
    assert!(revoked["credentials"].as_object().unwrap().is_empty());

    h.advance(365 * 24 * 3_600_000 * 2);
    let expired_admin = h.login("admin", ADMIN_PASSWORD);
    let _ = expired_admin;
    let alice_again = h.login("alice", MEMBER_PASSWORD);
    let expired = credentials_of(&h, &alice_again);
    assert_eq!(expired["code"], "ASSIGNMENT_EXPIRED", "分配到期后不下发");

    let log = h.log_text();
    assert!(!log.contains("synthetic-pass"), "日志不记凭据");
}

#[test]
fn apply_receipts_are_idempotent_per_user_and_drop_secret_fields() {
    let h = Harness::new("receipts");
    let admin = h.setup_admin();
    let (member_ref, member) = h.create_member(&admin, "member");
    let receipt = json!({"operation_id": "op-1", "overall": "APPLIED_VERIFIED", "yaml": "proxies: [password: x]", "expected": {"yaml": "x", "version": 3}, "core_secret": "synthetic-core"});
    let first = h.call("POST", "/api/network/receipts", Some(&member), Some(receipt.clone()));
    assert_eq!(body(&first), json!({"status": "RECORDED", "operation_id": "op-1"}));
    let again = h.call("POST", "/api/network/receipts", Some(&member), Some(receipt));
    assert_eq!(again.status, 200);
    let (count, payload): (i64, String) = h
        .sql()
        .query_row("SELECT COUNT(*), MAX(payload_json) FROM control_apply_receipts WHERE user_ref = ?1", [&member_ref], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap();
    assert_eq!(count, 1, "同一 operation_id 只留一条");
    assert!(!payload.contains("synthetic-core") && !payload.contains("proxies"), "配置正文与内核密钥不落库");
    assert!(payload.contains("APPLIED_VERIFIED"));
    let missing = h.call("POST", "/api/network/receipts", Some(&member), Some(json!({"overall": "x"})));
    assert_eq!(missing.status, 400);
}
