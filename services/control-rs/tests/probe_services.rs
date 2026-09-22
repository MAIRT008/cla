//! 分环境探测服务配置：管理员登记、校验、版本、删除；普通用户只拿到地址。
//!
//! 本机没有 cargo/rustc，这些用例已写未运行。

mod common;

use common::*;
use serde_json::json;

#[test]
fn administrators_register_probe_services_per_environment_and_members_only_see_addresses() {
    let h = Harness::new("probe-services");
    let admin = h.setup_admin();
    let (_member_ref, member) = h.create_member(&admin, "member");

    let host = json!({
        "environment_ref": "windows-host",
        "echo_url": "https://echo.synthetic.invalid/ip",
        "doh_url": "https://dns.synthetic.invalid/dns-query",
        "probe_base_url": "https://probe.synthetic.invalid",
        "stun_urls": ["stun:stun.synthetic.invalid:3478"],
        "client_kind": "webview"
    });
    let saved = h.call("PUT", "/api/admin/probe-services", Some(&admin), Some(host.clone()));
    assert_eq!(saved.status, 200, "{:?}", body(&saved));
    assert_eq!(body(&saved)["probe_services"]["version"], 1);
    let guest = h.call(
        "PUT",
        "/api/admin/probe-services",
        Some(&admin),
        Some(json!({"environment_ref": "wsl-ubuntu", "echo_url": "https://echo-wsl.synthetic.invalid/ip", "client_kind": "wsl-cli", "webrtc": false})),
    );
    assert_eq!(guest.status, 200, "{:?}", body(&guest));

    for bad in [
        json!({"environment_ref": "Windows Host", "echo_url": "https://echo.synthetic.invalid"}),
        json!({"environment_ref": "windows-host"}),
        json!({"environment_ref": "windows-host", "echo_url": "http://echo.synthetic.invalid"}),
        json!({"environment_ref": "windows-host", "echo_url": "https://user:secret@echo.synthetic.invalid"}),
        json!({"environment_ref": "windows-host", "echo_url": "https://echo.synthetic.invalid", "stun_urls": ["turn:relay.synthetic.invalid"]}),
        json!({"environment_ref": "windows-host", "echo_url": "https://echo.synthetic.invalid", "client_kind": "browser"}),
        json!({"environment_ref": "windows-host", "echo_url": "https://echo.synthetic.invalid", "api_key": "x"}),
    ] {
        let refused = h.call("PUT", "/api/admin/probe-services", Some(&admin), Some(bad.clone()));
        assert_eq!(refused.status, 400, "应拒绝 {bad}");
    }

    let mut stale = host.clone();
    stale["expected_version"] = json!(0);
    let conflict = h.call("PUT", "/api/admin/probe-services", Some(&admin), Some(stale));
    assert_eq!(conflict.status, 409, "按版本防覆盖");
    assert_eq!(body(&conflict)["current_version"], 1);

    assert_eq!(h.call("GET", "/api/admin/probe-services", Some(&member), None).status, 403, "普通用户进不了管理接口");
    let view = h.call("GET", "/api/network/probe-services", Some(&member), None);
    assert_eq!(view.status, 200, "{:?}", body(&view));
    let environments = body(&view)["environments"].clone();
    assert_eq!(environments["windows-host"]["echo_url"], "https://echo.synthetic.invalid/ip");
    assert_eq!(environments["windows-host"]["stun_urls"], json!(["stun:stun.synthetic.invalid:3478"]));
    assert_eq!(environments["wsl-ubuntu"]["webrtc"], false);
    assert!(environments["windows-host"].get("version").is_none() && environments["windows-host"].get("updated_by").is_none(), "只给地址");
    assert_eq!(h.call("GET", "/api/network/probe-services", None, None).status, 401);

    let h = h.reopen();
    let admin = h.login("admin", ADMIN_PASSWORD);
    let listed = body(&h.call("GET", "/api/admin/probe-services", Some(&admin), None));
    assert_eq!(listed["probe_services"].as_array().unwrap().len(), 2, "重启后配置仍在");
    let removed = h.call("POST", "/api/admin/probe-services/remove", Some(&admin), Some(json!({"environment_ref": "wsl-ubuntu"})));
    assert_eq!(removed.status, 200);
    assert_eq!(h.call("POST", "/api/admin/probe-services/remove", Some(&admin), Some(json!({"environment_ref": "wsl-ubuntu"}))).status, 404);
    let member = h.login("member", MEMBER_PASSWORD);
    let after = body(&h.call("GET", "/api/network/probe-services", Some(&member), None));
    assert!(after["environments"].get("wsl-ubuntu").is_none(), "删掉的环境不再下发");
}
