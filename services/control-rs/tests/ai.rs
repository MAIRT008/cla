//! 服务器模型配置与 AI 路由。提供方由脚本化传输扮演，核对发出的 Chat Completions 请求形状与各类回复的映射。
//! 本机不向任何真实模型端点发请求。
//!
//! 本机没有 cargo/rustc，这些用例已写未运行。

mod common;

use ai_steward_control::http::CancelToken;
use ai_steward_control::router::{handle_with_cancel, ApiRequest};
use common::*;
use serde_json::{json, Value};

const PROMPT_BODY: &str = "synthetic cleanup prompt body that must never reach logs";

fn configure(h: &Harness, admin: &str, calls: i64) -> Value {
    let saved = h.call(
        "PUT",
        "/api/admin/model-config",
        Some(admin),
        Some(json!({
            "task_type": "cleanup",
            "enabled": true,
            "base_url": "https://model.synthetic.invalid/v1/",
            "model": "synthetic-server-model",
            "policy_version": "policy-cleanup-v7",
            "max_model_calls": calls,
            "max_total_tokens": 64000,
            "api_key": MODEL_KEY,
        })),
    );
    assert_eq!(saved.status, 200, "{:?}", body(&saved));
    body(&saved)
}

fn turn_body(task_ref: &str, turn_ref: &str, text: &str) -> Value {
    json!({
        "task_ref": task_ref,
        "task_type": "cleanup",
        "turn_ref": turn_ref,
        "prompt_version": "cleanup-v1",
        "prompt_body": PROMPT_BODY,
        "tool_catalog_version": "cleanup-tools-v1",
        "messages": [{"role": "user", "content": text}],
    })
}

fn configure_daily(h: &Harness, admin: &str) {
    let saved = h.call(
        "PUT",
        "/api/admin/model-config",
        Some(admin),
        Some(json!({
            "task_type": "daily_analysis",
            "enabled": true,
            "base_url": "https://model.synthetic.invalid/v1/",
            "model": "synthetic-daily-model",
            "policy_version": "policy-daily-v2",
            "api_key": MODEL_KEY,
        })),
    );
    assert_eq!(saved.status, 200, "{:?}", body(&saved));
    assert_eq!(body(&saved)["task"]["status"], "AVAILABLE");
}

fn daily_turn_body(task_ref: &str, turn_ref: &str, text: &str) -> Value {
    json!({
        "task_ref": task_ref,
        "task_type": "daily_analysis",
        "turn_ref": turn_ref,
        "prompt_version": "daily-analysis-v1",
        "prompt_body": "synthetic daily analysis prompt body",
        "tool_catalog_version": "daily-analysis-tools-v1",
        "messages": [{"role": "user", "content": text}],
    })
}

fn task_ledger(h: &Harness, task_ref: &str) -> Value {
    let sql = h.sql();
    let task_type: String = sql.query_row("SELECT task_type FROM control_ai_tasks WHERE task_ref = ?1", [task_ref], |row| row.get(0)).unwrap();
    let turns: i64 = sql.query_row("SELECT COUNT(*) FROM control_ai_turns WHERE task_ref = ?1", [task_ref], |row| row.get(0)).unwrap();
    let (events, tokens, types): (i64, i64, String) = sql
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(total_tokens), 0), COALESCE(GROUP_CONCAT(DISTINCT task_type), '') FROM control_ai_usage_events WHERE task_ref = ?1",
            [task_ref],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    json!({"task_type": task_type, "turns": turns, "usage_events": events, "total_tokens": tokens, "usage_task_types": types})
}

fn policy_states(h: &Harness, admin: &str) -> Value {
    let config = body(&h.call("GET", "/api/admin/model-config", Some(admin), None));
    let mut states = serde_json::Map::new();
    for task_type in ["cleanup", "daily_analysis"] {
        let task = &config["tasks"][task_type];
        states.insert(
            task_type.to_string(),
            json!({"verification": task["verification"], "last_error_code": task["last_error_code"], "last_call_at": task["last_call_at"]}),
        );
    }
    Value::Object(states)
}

fn ok_completion() -> Value {
    json!({
        "id": "chatcmpl-synthetic",
        "choices": [{"index": 0, "message": {
            "role": "assistant",
            "content": "plan ready; see C:\\Users\\someone\\secret.txt",
            "tool_calls": [{"id": "call-1", "type": "function", "function": {"name": "DiscoverEnvironment", "arguments": "{\"scan_id\":\"scan-1\"}"}}],
        }}],
        "usage": {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150},
    })
}

#[test]
fn model_keys_are_write_only_and_saving_is_not_verification() {
    let h = Harness::new("ai-config");
    let admin = h.setup_admin();
    let (_, member) = h.create_member(&admin, "member");
    let before = h.call("GET", "/api/ai/capabilities", Some(&member), None);
    assert_eq!(body(&before)["tasks"]["cleanup"]["status"], "UNAVAILABLE");
    assert_eq!(body(&before)["tasks"]["cleanup"]["reason"], "MODEL_NOT_CONFIGURED");

    let saved = configure(&h, &admin, 8);
    assert_eq!(saved["task"]["secret_present"], true);
    assert_eq!(saved["task"]["verification"], "NOT_TESTED");
    assert!(!saved.to_string().contains(MODEL_KEY));
    let listed = h.call("GET", "/api/admin/model-config", Some(&admin), None);
    assert!(!body(&listed).to_string().contains(MODEL_KEY), "读取不回显 Key");
    assert_eq!(body(&listed)["tasks"]["network_diagnosis"]["configured"], false);
    assert!(!contains_bytes(&h.database_bytes(), MODEL_KEY), "库里只有密文");

    let capabilities = h.call("GET", "/api/ai/capabilities", Some(&member), None);
    let cleanup = body(&capabilities)["tasks"]["cleanup"].clone();
    assert_eq!(cleanup["status"], "AVAILABLE");
    assert_eq!(cleanup["catalog_version"], "cleanup-tools-v1");
    let text = body(&capabilities).to_string();
    assert!(!text.contains("model.synthetic.invalid") && !text.contains("synthetic-server-model"), "普通用户看不到端点与模型");
    assert_eq!(h.call("GET", "/api/admin/model-config", Some(&member), None).status, 403);

    let rotated = h.call("PUT", "/api/admin/model-config", Some(&admin), Some(json!({"task_type": "cleanup", "api_key": "sk-synthetic-rotated-key-999"})));
    assert_eq!(body(&rotated)["task"]["secret_version"], 2, "轮换原地加版本");
    let cleared = h.call("PUT", "/api/admin/model-config", Some(&admin), Some(json!({"task_type": "cleanup", "clear_api_key": true})));
    assert_eq!(body(&cleared)["task"]["reason"], "MODEL_SECRET_MISSING");
    let disabled = h.call("PUT", "/api/admin/model-config", Some(&admin), Some(json!({"task_type": "cleanup", "enabled": false})));
    assert_eq!(body(&disabled)["task"]["reason"], "MODEL_DISABLED");
    let first_save_without_version = h.call("PUT", "/api/admin/model-config", Some(&admin), Some(json!({"task_type": "daily_analysis", "enabled": true})));
    assert_eq!(first_save_without_version.status, 400);
    let insecure = h.call("PUT", "/api/admin/model-config", Some(&admin), Some(json!({"task_type": "daily_analysis", "policy_version": "p1", "base_url": "http://model.synthetic.invalid"})));
    assert_eq!(insecure.status, 400, "远端模型地址必须 https");
}

#[test]
fn a_turn_uses_only_server_side_model_settings_and_parses_tool_calls() {
    let h = Harness::new("ai-turn");
    let admin = h.setup_admin();
    let (_, member) = h.create_member(&admin, "member");
    configure(&h, &admin, 8);
    h.transport.script(|_| json_response(200, ok_completion()));

    let smuggled = {
        let mut value = turn_body("task-1", "turn-1", "hello");
        value["model"] = json!("client-chosen-model");
        value["base_url"] = json!("https://attacker.invalid");
        value
    };
    let rejected = h.call("POST", "/api/ai/turn", Some(&member), Some(smuggled));
    assert_eq!(rejected.status, 400, "客户端不能决定模型或端点");
    let wrong_version = {
        let mut value = turn_body("task-1", "turn-1", "hello");
        value["prompt_version"] = json!("cleanup-v0");
        value
    };
    assert_eq!(body(&h.call("POST", "/api/ai/turn", Some(&member), Some(wrong_version)))["code"], "CONTROL_PROTOCOL_MISMATCH");
    assert!(h.transport.calls().is_empty());

    let response = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-1", "turn-1", "Bearer synthetic-inline-token please")));
    assert_eq!(response.status, 200, "{:?}", body(&response));
    let value = body(&response);
    assert_eq!(value["status"], "OK");
    assert_eq!(value["model_policy_version"], "policy-cleanup-v7");
    assert_eq!(value["usage"]["total_tokens"], 150);
    assert_eq!(value["assistant"]["tool_calls"][0]["function"]["name"], "DiscoverEnvironment");
    assert!(value["assistant"]["content"].as_str().unwrap().contains("[LOCAL_PATH]"), "回复在交回客户端前脱敏");

    let calls = h.transport.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].url, "https://model.synthetic.invalid/v1/chat/completions");
    assert_eq!(calls[0].authorization.as_deref(), Some(format!("Bearer {MODEL_KEY}").as_str()));
    let sent = calls[0].body.clone().unwrap();
    assert_eq!(sent["model"], "synthetic-server-model");
    assert_eq!(sent["tool_choice"], "auto");
    assert_eq!(sent["stream"], false);
    assert_eq!(sent["max_completion_tokens"], 4096);
    assert_eq!(sent["messages"][0], json!({"role": "system", "content": PROMPT_BODY}));
    let tool_names: Vec<&str> = sent["tools"].as_array().unwrap().iter().map(|tool| tool["function"]["name"].as_str().unwrap()).collect();
    assert_eq!(tool_names, vec!["DiscoverEnvironment", "InspectObject", "BuildActionPlan", "ExecuteConfirmedPlan", "RecheckAction"]);

    let config = h.call("GET", "/api/admin/model-config", Some(&admin), None);
    assert_eq!(body(&config)["tasks"]["cleanup"]["verification"], "CALL_SUCCEEDED", "真实调用成功后才标记");

    let replay = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-1", "turn-1", "Bearer synthetic-inline-token please")));
    assert_eq!(body(&replay), value, "同一 turn 重放原结果");
    assert_eq!(h.transport.calls().len(), 1, "重放不再调模型");
    let changed = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-1", "turn-1", "different")));
    assert_eq!(changed.status, 409);
    assert_eq!(body(&changed)["code"], "CONTROL_TURN_REPLAY_MISMATCH");

    let (_, intruder) = h.create_member(&admin, "intruder");
    let stolen = h.call("POST", "/api/ai/turn", Some(&intruder), Some(turn_body("task-1", "turn-9", "x")));
    assert_eq!(stolen.status, 403);
    assert_eq!(body(&stolen)["code"], "CONTROL_TASK_DENIED");

    let log = h.log_text();
    for secret in [PROMPT_BODY, MODEL_KEY, "synthetic-inline-token", "plan ready"] {
        assert!(!log.contains(secret), "日志里出现了 {secret}");
    }
    assert!(log.contains("ai.turn.finished"));

    let h = h.reopen();
    let member = h.login("member", MEMBER_PASSWORD);
    let after_restart = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-1", "turn-1", "Bearer synthetic-inline-token please")));
    assert_eq!(body(&after_restart)["usage"]["total_tokens"], 150, "turn 记录落库，重启后仍可重放");
}

#[test]
fn an_existing_task_ref_rejects_cross_type_turns_and_keeps_its_first_task_type() {
    let h = Harness::new("ai-task-type");
    let admin = h.setup_admin();
    let (_, member) = h.create_member(&admin, "member");
    configure(&h, &admin, 3);
    configure_daily(&h, &admin);
    h.transport.script(|_| json_response(200, ok_completion()));

    let first = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-t", "t1", "first")));
    assert_eq!(first.status, 200, "{:?}", body(&first));
    let ledger = task_ledger(&h, "task-t");
    assert_eq!(ledger, json!({"task_type": "cleanup", "turns": 1, "usage_events": 1, "total_tokens": 150, "usage_task_types": "cleanup"}));
    h.advance(60_000);
    let policies = policy_states(&h, &admin);
    assert_eq!(policies["cleanup"]["verification"], "CALL_SUCCEEDED");
    assert_eq!(policies["daily_analysis"]["verification"], "NOT_TESTED");

    for turn_ref in ["t2", "t1"] {
        let crossed = h.call("POST", "/api/ai/turn", Some(&member), Some(daily_turn_body("task-t", turn_ref, "switch")));
        assert_eq!(crossed.status, 409, "新回合与已有回合都不能换类型：{turn_ref}");
        assert_eq!(body(&crossed)["code"], "CONTROL_TASK_TYPE_MISMATCH");
        let text = body(&crossed).to_string();
        for hidden in ["model.synthetic.invalid", "synthetic-server-model", "synthetic-daily-model", "policy-", MODEL_KEY] {
            assert!(!text.contains(hidden), "拒绝不回显服务端配置：{hidden}");
        }
    }
    assert_eq!(h.transport.calls().len(), 1, "被拒请求不调模型");
    assert_eq!(task_ledger(&h, "task-t"), ledger, "被拒请求不改任务类型、不写 turn 与用量");
    assert_eq!(policy_states(&h, &admin), policies, "被拒请求不动任一策略的验证状态");

    let second = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-t", "t2", "second")));
    assert_eq!(second.status, 200, "{:?}", body(&second));
    let second_body = body(&second);
    let replay = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-t", "t2", "second")));
    assert_eq!(body(&replay), second_body, "同类型重放原结果");
    let changed = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-t", "t2", "changed")));
    assert_eq!(changed.status, 409);
    assert_eq!(body(&changed)["code"], "CONTROL_TURN_REPLAY_MISMATCH");
    assert_eq!(h.transport.calls().len(), 2);
    let third = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-t", "t3", "third")));
    assert_eq!(third.status, 200, "被拒的跨类型请求没有占用预算");
    let exhausted = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-t", "t4", "fourth")));
    assert_eq!(exhausted.status, 429);
    assert_eq!(body(&exhausted)["code"], "AI_BUDGET_EXHAUSTED");
    let escape = h.call("POST", "/api/ai/turn", Some(&member), Some(daily_turn_body("task-t", "t4", "fourth")));
    assert_eq!(body(&escape)["code"], "CONTROL_TASK_TYPE_MISMATCH", "换类型不能改用另一份预算");
    assert_eq!(h.transport.calls().len(), 3);

    let (_, intruder) = h.create_member(&admin, "intruder");
    for request in [turn_body("task-t", "t9", "x"), daily_turn_body("task-t", "t9", "x")] {
        let denied = h.call("POST", "/api/ai/turn", Some(&intruder), Some(request));
        assert_eq!(denied.status, 403);
        assert_eq!(body(&denied)["code"], "CONTROL_TASK_DENIED");
        assert!(!body(&denied).to_string().contains("cleanup"), "跨用户拒绝不透露任务类型");
    }
    assert_eq!(h.transport.calls().len(), 3);

    let ledger = task_ledger(&h, "task-t");
    assert_eq!(ledger, json!({"task_type": "cleanup", "turns": 3, "usage_events": 3, "total_tokens": 450, "usage_task_types": "cleanup"}));
    let policies = policy_states(&h, &admin);
    let h = h.reopen();
    let member = h.login("member", MEMBER_PASSWORD);
    let admin = h.login("admin", ADMIN_PASSWORD);
    h.advance(60_000);
    let crossed = h.call("POST", "/api/ai/turn", Some(&member), Some(daily_turn_body("task-t", "t5", "after restart")));
    assert_eq!(crossed.status, 409, "重开数据库后仍按首次类型拒绝");
    assert_eq!(body(&crossed)["code"], "CONTROL_TASK_TYPE_MISMATCH");
    assert_eq!(h.transport.calls().len(), 3);
    assert_eq!(task_ledger(&h, "task-t"), ledger);
    assert_eq!(policy_states(&h, &admin), policies);
    let replay = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-t", "t2", "second")));
    assert_eq!(body(&replay), second_body, "重启后同类型重放不受影响");

    let fresh = h.call("POST", "/api/ai/turn", Some(&member), Some(daily_turn_body("task-d", "t1", "daily")));
    assert_eq!(fresh.status, 200, "新任务按自己的类型正常调用：{:?}", body(&fresh));
    assert_eq!(task_ledger(&h, "task-d")["task_type"], "daily_analysis");
    assert_eq!(h.transport.calls().len(), 4);
}

#[test]
fn budgets_stop_further_model_calls() {
    let h = Harness::new("ai-budget");
    let admin = h.setup_admin();
    let (_, member) = h.create_member(&admin, "member");
    configure(&h, &admin, 2);
    h.transport.script(|_| json_response(200, ok_completion()));
    for turn in ["t1", "t2"] {
        assert_eq!(h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-b", turn, turn))).status, 200);
    }
    let exhausted = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-b", "t3", "t3")));
    assert_eq!(exhausted.status, 429);
    assert_eq!(body(&exhausted)["code"], "AI_BUDGET_EXHAUSTED");
    assert_eq!(h.transport.calls().len(), 2);

    h.transport.script(|_| json_response(500, json!({"error": "synthetic outage"})));
    let failed = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-c", "t1", "x")));
    assert_eq!(body(&failed)["code"], "AI_PROVIDER_UNAVAILABLE");
    h.transport.script(|_| json_response(200, ok_completion()));
    let after_unknown = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-c", "t2", "y")));
    assert_eq!(after_unknown.status, 429, "用量未知的一次失败按耗尽处理（与 Node 基线相同）");
}

#[test]
fn provider_failures_map_to_ai_errors_without_ending_the_application_session() {
    let h = Harness::new("ai-errors");
    let admin = h.setup_admin();
    let (_, member) = h.create_member(&admin, "member");
    configure(&h, &admin, 8);
    let cases: Vec<(&str, u16, &str)> = vec![("401", 502, "AI_AUTH_FAILED"), ("403", 502, "AI_AUTH_FAILED"), ("429", 429, "AI_RATE_LIMITED"), ("503", 502, "AI_PROVIDER_UNAVAILABLE"), ("400", 502, "AI_TRANSPORT_UNKNOWN")];
    for (index, (upstream, status, code)) in cases.into_iter().enumerate() {
        let upstream_status: u16 = upstream.parse().unwrap();
        h.transport.script(move |_| json_response(upstream_status, json!({"error": {"message": "synthetic"}})));
        let response = h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body(&format!("task-e{index}"), "t1", "x")));
        assert_eq!(response.status, status, "上游 {upstream}");
        assert_eq!(body(&response)["code"], code);
        assert_eq!(body(&response)["status"], "FAILED");
        assert_ne!(response.status, 401, "HTTP 401 只留给本应用会话失效");
        assert_eq!(h.call("GET", "/api/auth/me", Some(&member), None).status, 200, "会话不受提供方错误影响");
    }
    h.transport.script(|_| json_response(200, json!({"not": "a completion"})));
    assert_eq!(body(&h.call("POST", "/api/ai/turn", Some(&member), Some(turn_body("task-bad", "t1", "x"))))["code"], "AI_TRANSPORT_UNKNOWN");

    h.transport.script(|_| json_response(200, ok_completion()));
    let cancel = CancelToken::new();
    cancel.cancel();
    let cancelled = handle_with_cancel(
        &h.app,
        &ApiRequest::new("POST", "/api/ai/turn").header("authorization", &format!("Bearer {member}")).json(&turn_body("task-cancel", "t1", "x")),
        &cancel,
    );
    assert_eq!(body(&cancelled)["code"], "AI_ABORTED");
    assert_eq!(body(&cancelled)["retryable"], false);

    let unconfigured = h.call(
        "POST",
        "/api/ai/turn",
        Some(&member),
        Some(json!({"task_ref": "task-n", "task_type": "daily_analysis", "turn_ref": "t1", "prompt_version": "daily-analysis-v1", "prompt_body": "p", "tool_catalog_version": "daily-analysis-tools-v1", "messages": []})),
    );
    assert_eq!(unconfigured.status, 503);
    assert_eq!(body(&unconfigured)["code"], "AI_UNAVAILABLE");
    assert_eq!(body(&unconfigured)["reason"], "MODEL_NOT_CONFIGURED");
    assert_eq!(h.call("POST", "/api/ai/turn", None, Some(turn_body("task-z", "t1", "x"))).status, 401);
}
