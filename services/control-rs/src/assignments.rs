//! 每用户分配、发布、撤销、应用回执与个人凭据换取（迁自 Node 基线 assignmentService.mjs、
//! networkRoutes.mjs，校验规则逐条对应 src/core/network/assignment.mjs 的 validateAssignment）。
//!
//! 与基线的一处有意差异：基线 allocate 直接覆盖用户唯一的分配记录，新保存的 DRAFT 会顶掉已发布版本，
//! 普通用户随即读到未发布的草稿。这里候选与已发布分表保存：保存只写候选，发布才替换已发布版本，
//! `/api/network/assignment` 只返回已发布（含已撤销）记录。
//!
//! 资源一律按 resource_id 从服务端资源表解析，请求里夹带的主机、端口、状态等属性不被采信。
//!
//! 个人凭据：`(credential_ref, user_ref)` 一条，内容（username/password）加密保存。只有当前认证用户
//! 自己的、ACTIVE 的凭据，且其已发布分配有效、未撤销未到期、额度未停用、对应资源仍可用时才下发。
//! 共享上游秘密不进这张表，所以任何路径都下发不了。

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::admin_users::existing_user;
use crate::api::{fields, required_ref, valid_ref, ApiError};
use crate::quota::{load_snapshot, public_quota};
use crate::resources::{load_resource, resource_usable, template_for_assignment};
use crate::router::{ApiResponse, Ctx};
use crate::secrets::{delete_secret, put_secret, read_secret_text, secret_meta};
use crate::store::{read_failed, write_failed};
use crate::{iso_from_millis, millis_from_iso, ControlError};

pub const MODES: [&str; 3] = ["daily_single_ip", "claude_single_ip", "claude_dual_ip"];
pub const CLASSIFICATION_VERSION: &str = "product-v1";
const ACCOUNT_CLASSES: [&str; 4] = ["free", "pro", "max_5x", "max_20x"];

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str).filter(|item| !item.is_empty())
}

fn is_expired(expires_at: Option<&str>, now_ms: i64) -> bool {
    match expires_at.and_then(millis_from_iso) {
        Some(end) => now_ms >= end,
        None => false,
    }
}

fn resource_of<'a>(assignment: &'a Value, reference: Option<&str>) -> Option<&'a Value> {
    let reference = reference?;
    assignment.get("resources").and_then(|resources| resources.get(reference))
}

fn resource_status(resource: Option<&Value>, now_ms: i64) -> String {
    match resource {
        None => "MISSING".to_string(),
        Some(resource) => match text(resource, "status") {
            Some(status) if status != "ACTIVE" => status.to_string(),
            _ if is_expired(text(resource, "expires_at"), now_ms) => "EXPIRED".to_string(),
            _ => "ACTIVE".to_string(),
        },
    }
}

/// 与 src/core/network/assignment.mjs 的 validateAssignment 同一组规则与返回字段。
pub fn validate_assignment(assignment: Option<&Value>, environment: Option<&str>, now_ms: i64) -> Value {
    let now = iso_from_millis(now_ms);
    let assignment = match assignment.filter(|value| value.is_object()) {
        Some(value) => value,
        None => {
            return json!({"ok": false, "code": "ASSIGNMENT_INVALID", "reason": "assignment is required", "issues": ["MISSING_ASSIGNMENT"]});
        }
    };
    let mut issues: Vec<&str> = Vec::new();
    if text(assignment, "user_ref").is_none() {
        issues.push("MISSING_USER");
    }
    if assignment.get("assignment_version").and_then(Value::as_i64).unwrap_or(0) == 0 {
        issues.push("MISSING_VERSION");
    }
    if text(assignment, "status") == Some("REVOKED") || assignment.get("revoked").and_then(Value::as_bool) == Some(true) {
        issues.push("REVOKED");
    }
    if is_expired(text(assignment, "valid_until"), now_ms) || text(assignment, "status") == Some("EXPIRED") {
        issues.push("EXPIRED");
    }
    if let Some(start) = text(assignment, "valid_from").and_then(millis_from_iso) {
        if now_ms < start {
            issues.push("NOT_YET_VALID");
        }
    }
    let assigned_environment = text(assignment, "environment_ref");
    if let (Some(assigned), Some(current)) = (assigned_environment, environment) {
        if assigned != current {
            issues.push("ENVIRONMENT_MISMATCH");
        }
    }
    let allowed: Vec<String> = assignment
        .get("allowed_modes")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).filter(|mode| MODES.contains(mode)).map(str::to_string).collect())
        .unwrap_or_default();
    if allowed.is_empty() {
        issues.push("NO_ALLOWED_MODES");
    }
    let roles = assignment.get("roles").cloned().unwrap_or(Value::Null);
    let refs = assignment.get("resource_refs").cloned().unwrap_or(Value::Null);
    let a_ref = text(&roles, "A").or_else(|| text(&refs, "exit_a")).map(str::to_string);
    let b_ref = text(&roles, "B").or_else(|| text(&refs, "exit_b")).map(str::to_string);
    let front_ref = text(&refs, "front").map(str::to_string);
    let exit_a = resource_of(assignment, a_ref.as_deref());
    let exit_b = resource_of(assignment, b_ref.as_deref());
    let front = resource_of(assignment, front_ref.as_deref());
    let a_status = resource_status(exit_a, now_ms);
    let b_status = resource_status(exit_b, now_ms);
    let front_status = if front.is_some() { resource_status(front, now_ms) } else { "OPTIONAL".to_string() };
    if a_status != "ACTIVE" {
        issues.push("EXIT_A_UNAVAILABLE");
    }
    if front.is_some() && front_status != "ACTIVE" {
        issues.push("FRONT_UNAVAILABLE");
    }
    let dual_allowed = allowed.iter().any(|mode| mode == "claude_dual_ip");
    if dual_allowed && exit_b.is_none() {
        issues.push("DUAL_IP_REQUIRES_B");
    }
    if dual_allowed && exit_b.is_some() && b_status != "ACTIVE" {
        issues.push("EXIT_B_UNAVAILABLE");
    }
    let ok = issues.iter().all(|issue| *issue == "DUAL_IP_REQUIRES_B" || *issue == "EXIT_B_UNAVAILABLE");
    let code = if ok {
        "ASSIGNMENT_VALID"
    } else if issues.contains(&"REVOKED") {
        "ASSIGNMENT_REVOKED"
    } else if issues.contains(&"EXPIRED") {
        "ASSIGNMENT_EXPIRED"
    } else if issues.contains(&"EXIT_A_UNAVAILABLE") {
        "RESOURCE_UNAVAILABLE"
    } else {
        "ASSIGNMENT_INVALID"
    };
    let reason = if ok { "assignment is usable".to_string() } else { issues.join(",") };
    json!({
        "ok": ok,
        "code": code,
        "reason": reason,
        "issues": issues,
        "user_ref": text(assignment, "user_ref"),
        "environment_ref": assigned_environment.or(environment),
        "assignment_version": assignment.get("assignment_version").cloned().unwrap_or(Value::Null),
        "template_version": assignment.get("template_version").cloned().unwrap_or(Value::Null),
        "classification_version": assignment.get("classification_version").cloned().unwrap_or(Value::Null),
        "allowed_modes": allowed,
        "dual_ip_ready": dual_allowed && a_status == "ACTIVE" && b_status == "ACTIVE",
        "resources": {
            "A": {"ref": a_ref, "status": a_status, "sharing": exit_a.and_then(|item| text(item, "sharing")), "role": "A"},
            "B": {"ref": b_ref, "status": if exit_b.is_some() { b_status.clone() } else { "MISSING".to_string() }, "sharing": exit_b.and_then(|item| text(item, "sharing")), "role": "B"},
            "front": {"ref": front_ref, "status": if front.is_some() { front_status.clone() } else { "MISSING".to_string() }},
        },
        "observed_at": now,
    })
}

fn ready(validation: &Value) -> bool {
    let ok = validation.get("ok").and_then(Value::as_bool) == Some(true);
    let dual_requested = validation
        .get("allowed_modes")
        .and_then(Value::as_array)
        .map(|modes| modes.iter().any(|mode| mode.as_str() == Some("claude_dual_ip")))
        .unwrap_or(false);
    ok && (!dual_requested || validation.get("dual_ip_ready").and_then(Value::as_bool) == Some(true))
}

const PUBLIC_TEMPLATE_KEYS: [&str; 11] = [
    "version", "claude_domains", "claude_processes", "managed_browser_processes", "protected_process_paths", "lan_cidrs",
    "loopback_endpoints", "control_plane", "udp_policy", "ipv6_policy", "dns",
];

fn public_template(template: Option<&Value>) -> Value {
    let template = match template.and_then(Value::as_object) {
        Some(map) => map,
        None => return Value::Null,
    };
    let mut copy = Map::new();
    for key in PUBLIC_TEMPLATE_KEYS {
        let fallback = match key {
            "claude_domains" | "claude_processes" | "managed_browser_processes" | "protected_process_paths" | "lan_cidrs" | "loopback_endpoints" => json!([]),
            "control_plane" => json!({}),
            _ => Value::Null,
        };
        copy.insert(key.to_string(), template.get(key).cloned().unwrap_or(fallback));
    }
    Value::Object(copy)
}

/// 与基线 publicAssignment 同一组字段；资源只给地址、角色、状态与 credential_ref。
pub fn public_assignment(assignment: Option<&Value>) -> Value {
    let assignment = match assignment.filter(|value| value.is_object()) {
        Some(value) => value,
        None => return Value::Null,
    };
    let mut resources = Map::new();
    if let Some(map) = assignment.get("resources").and_then(Value::as_object) {
        for (key, resource) in map {
            let mut public = Map::new();
            for field in ["resource_id", "role", "sharing", "status", "expires_at", "host", "port", "credential_ref", "kind"] {
                public.insert(field.to_string(), resource.get(field).cloned().unwrap_or(Value::Null));
            }
            resources.insert(key.clone(), Value::Object(public));
        }
    }
    let field = |key: &str| assignment.get(key).cloned().unwrap_or(Value::Null);
    json!({
        "user_ref": field("user_ref"),
        "assignment_version": field("assignment_version"),
        "environment_ref": field("environment_ref"),
        "allowed_modes": field("allowed_modes"),
        "account_class": field("account_class"),
        "roles": field("roles"),
        "resource_refs": field("resource_refs"),
        "resources": resources,
        "valid_until": field("valid_until"),
        "status": field("status"),
        "revoked": assignment.get("revoked").and_then(Value::as_bool) == Some(true),
        "template_id": field("template_id"),
        "template_version": field("template_version"),
        "classification_version": field("classification_version"),
        "published": assignment.get("published").and_then(Value::as_bool) == Some(true),
        "published_at": field("published_at"),
        "revoked_at": field("revoked_at"),
        "template": public_template(assignment.get("template")),
    })
}

struct Published {
    payload: Value,
}

fn load_candidate(connection: &Connection, user_ref: &str) -> Result<Option<Value>, ControlError> {
    let payload: Option<String> = connection
        .query_row("SELECT payload_json FROM control_assignment_candidates WHERE user_ref = ?1", params![user_ref], |row| row.get(0))
        .optional()
        .map_err(read_failed)?;
    Ok(payload.and_then(|text| serde_json::from_str(&text).ok()))
}

fn load_published(connection: &Connection, user_ref: &str) -> Result<Option<Published>, ControlError> {
    let payload: Option<String> = connection
        .query_row("SELECT payload_json FROM control_assignments WHERE user_ref = ?1", params![user_ref], |row| row.get(0))
        .optional()
        .map_err(read_failed)?;
    Ok(payload.and_then(|text| serde_json::from_str(&text).ok()).map(|payload| Published { payload }))
}

/// 恢复额度等流程读取的「当前已发布分配」。
pub fn published_assignment(connection: &Connection, user_ref: &str) -> Result<Option<Value>, ControlError> {
    Ok(load_published(connection, user_ref)?.map(|item| item.payload))
}

fn user_target(input: &crate::api::Fields<'_>) -> Result<String, ApiError> {
    required_ref(input, &["userRef", "user_ref"])
}

/// 保存候选分配（POST /api/admin/assignments）。请求字段沿用基线：userRef、environmentRef、accountClass、
/// allowedModes、resources、roles、validUntil、templateId；另接受 user_ref。
pub fn allocate(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(
        &body,
        &["userRef", "user_ref", "environmentRef", "accountClass", "allowedModes", "resources", "roles", "validUntil", "templateId", "validFrom"],
    )?;
    let user_ref = user_target(&input)?;
    let environment_ref = input.string("environmentRef", 128)?;
    let account_class = input.string("accountClass", 32)?;
    if let Some(class) = &account_class {
        if !ACCOUNT_CLASSES.contains(&class.as_str()) {
            return Err(ApiError::new(400, "ASSIGNMENT_INVALID", "accountClass 只能是 free、pro、max_5x 或 max_20x").with("field", json!("accountClass")));
        }
    }
    let allowed_modes = input.string_list("allowedModes", 3, 32)?.unwrap_or_default();
    if let Some(unknown) = allowed_modes.iter().find(|mode| !MODES.contains(&mode.as_str())) {
        return Err(ApiError::new(400, "MODE_NOT_ALLOWED", format!("不认识的方案 {unknown}")).with("field", json!("allowedModes")));
    }
    let valid_until = input
        .instant("validUntil")?
        .ok_or_else(|| ApiError::new(400, "ASSIGNMENT_INVALID", "validUntil 必填").with("field", json!("validUntil")))?;
    let valid_from = input.instant("validFrom")?;
    let template_id = input.string("templateId", 128)?;
    let roles_input = input.object("roles")?.ok_or_else(|| ApiError::new(400, "ASSIGNMENT_INVALID", "roles 必填，至少给出 A").with("field", json!("roles")))?;
    let mut roles = Map::new();
    for (key, value) in roles_input {
        if !matches!(key.as_str(), "A" | "B" | "front") {
            return Err(ApiError::new(400, "ASSIGNMENT_INVALID", format!("roles 不接受 {key}")).with("field", json!("roles")));
        }
        match value.as_str() {
            Some(reference) if valid_ref(reference) => {
                roles.insert(key.clone(), json!(reference));
            }
            None if value.is_null() => {}
            _ => return Err(ApiError::new(400, "ASSIGNMENT_INVALID", format!("roles.{key} 必须是资源编号")).with("field", json!("roles"))),
        }
    }
    let a_ref = roles.get("A").and_then(Value::as_str).map(str::to_string).ok_or_else(|| {
        ApiError::new(400, "ASSIGNMENT_INVALID", "roles.A 必填").with("field", json!("roles"))
    })?;
    let mut resource_ids: Vec<String> = Vec::new();
    for item in input.array("resources")?.cloned().unwrap_or_default() {
        let reference = match &item {
            Value::String(reference) => reference.clone(),
            Value::Object(map) => map.get("resource_id").and_then(Value::as_str).unwrap_or("").to_string(),
            _ => String::new(),
        };
        if !valid_ref(&reference) {
            return Err(ApiError::new(400, "ASSIGNMENT_INVALID", "resources 只能是资源编号数组").with("field", json!("resources")));
        }
        if !resource_ids.contains(&reference) {
            resource_ids.push(reference);
        }
    }
    for reference in roles.values().filter_map(Value::as_str) {
        if !resource_ids.iter().any(|item| item == reference) {
            resource_ids.push(reference.to_string());
        }
    }
    let now_ms = ctx.now();
    let now = iso_from_millis(now_ms);
    let (record, validation) = ctx.app.store.write(|transaction| -> Result<(Value, Value), ApiError> {
        existing_user(transaction, &user_ref)?;
        let mut resources = Map::new();
        for reference in &resource_ids {
            let resource = load_resource(transaction, reference)?
                .ok_or_else(|| ApiError::new(404, "RESOURCE_NOT_FOUND", format!("没有资源 {reference}")).with("resource_id", json!(reference)))?;
            let mut snapshot = Map::new();
            for field in ["resource_id", "role", "kind", "host", "port", "sharing", "status", "expires_at", "credential_ref", "version"] {
                snapshot.insert(field.to_string(), resource.get(field).cloned().unwrap_or(Value::Null));
            }
            resources.insert(reference.clone(), Value::Object(snapshot));
        }
        for (role, reference) in roles.iter() {
            let actual = resources.get(reference.as_str().unwrap_or("")).and_then(|resource| text(resource, "role")).unwrap_or("");
            if actual != role.as_str() {
                return Err(ApiError::new(400, "ROLE_MISMATCH", format!("资源 {} 的角色是 {actual}，不能用作 {role}", reference.as_str().unwrap_or(""))).with("field", json!("roles")));
            }
        }
        let front_ref = roles
            .get("front")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| resources.values().find(|resource| text(resource, "role") == Some("front")).and_then(|resource| text(resource, "resource_id")).map(str::to_string));
        let template = template_for_assignment(transaction, template_id.as_deref())?;
        let candidate_version: Option<i64> = transaction
            .query_row("SELECT assignment_version FROM control_assignment_candidates WHERE user_ref = ?1", params![user_ref], |row| row.get(0))
            .optional()
            .map_err(read_failed)?;
        let published_version: Option<i64> = transaction
            .query_row("SELECT assignment_version FROM control_assignments WHERE user_ref = ?1", params![user_ref], |row| row.get(0))
            .optional()
            .map_err(read_failed)?;
        let version = candidate_version.unwrap_or(0).max(published_version.unwrap_or(0)) + 1;
        let record = json!({
            "user_ref": user_ref,
            "environment_ref": environment_ref,
            "account_class": account_class,
            "assignment_version": version,
            "allowed_modes": allowed_modes,
            "roles": Value::Object(roles.clone()),
            "resource_refs": {"front": front_ref, "exit_a": a_ref, "exit_b": roles.get("B").cloned().unwrap_or(Value::Null)},
            "resources": Value::Object(resources),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "status": "DRAFT",
            "revoked": false,
            "published": false,
            "template_id": template["template_id"],
            "template_version": template["version"],
            "classification_version": CLASSIFICATION_VERSION,
            "template": template["template"],
            "saved_at": now,
            "saved_by": ctx.actor(),
        });
        transaction
            .execute(
                "INSERT INTO control_assignment_candidates (user_ref, assignment_version, payload_json, updated_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(user_ref) DO UPDATE SET assignment_version = excluded.assignment_version, payload_json = excluded.payload_json, updated_at = excluded.updated_at",
                params![user_ref, version, record.to_string(), now],
            )
            .map_err(write_failed)?;
        let validation = validate_assignment(Some(&record), environment_ref.as_deref(), now_ms);
        Ok((record, validation))
    })?;
    ctx.info("admin.assignment.saved", json!({"actor": ctx.actor(), "user_ref": user_ref, "assignment_version": record["assignment_version"], "valid": validation["ok"]}));
    Ok(ApiResponse::json(
        200,
        json!({"ok": true, "assignment": public_assignment(Some(&record)), "validation": validation, "ready": ready(&validation)}),
    ))
}

/// GET /api/admin/assignments?user_ref=&environment_ref=：候选与已发布并列，校验针对候选（没有候选时针对已发布）。
pub fn admin_view(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let user_ref = ctx.query("user_ref").ok_or_else(|| ApiError::invalid("查询参数 user_ref 必填"))?.to_string();
    let environment = ctx.query("environment_ref").map(str::to_string);
    let now_ms = ctx.now();
    let (candidate, published, receipt) = ctx.app.store.read(|connection| -> Result<(Option<Value>, Option<Value>, Option<Value>), ApiError> {
        existing_user(connection, &user_ref)?;
        let receipt: Option<String> = connection
            .query_row(
                "SELECT payload_json FROM control_publish_receipts WHERE user_ref = ?1 ORDER BY assignment_version DESC LIMIT 1",
                params![user_ref],
                |row| row.get(0),
            )
            .optional()
            .map_err(read_failed)?;
        Ok((load_candidate(connection, &user_ref)?, published_assignment(connection, &user_ref)?, receipt.and_then(|text| serde_json::from_str(&text).ok())))
    })?;
    let subject = candidate.as_ref().or(published.as_ref());
    let validation = validate_assignment(subject, environment.as_deref(), now_ms);
    Ok(ApiResponse::json(
        200,
        json!({
            "user_ref": user_ref,
            "candidate": public_assignment(candidate.as_ref()),
            "published": public_assignment(published.as_ref()),
            "assignment": public_assignment(subject),
            "validation": validation,
            "ready": ready(&validation),
            "last_receipt": receipt,
        }),
    ))
}

/// 敏感变更：出口 A 的引用、A 的主机或受保护进程路径变化（与基线 sensitiveChange 同一判据）。
fn sensitive_change(previous: Option<&Value>, next: &Value) -> bool {
    let previous = match previous {
        Some(value) => value,
        None => return false,
    };
    let a_of = |assignment: &Value| -> (Option<String>, Option<String>) {
        let reference = assignment.get("roles").and_then(|roles| text(roles, "A")).map(str::to_string);
        let host = reference
            .as_deref()
            .and_then(|key| assignment.get("resources").and_then(|resources| resources.get(key)))
            .and_then(|resource| text(resource, "host"))
            .map(str::to_string);
        (reference, host)
    };
    let protected = |assignment: &Value| assignment.get("template").and_then(|template| template.get("protected_process_paths")).cloned().unwrap_or_else(|| json!([]));
    let loopback = |assignment: &Value| assignment.get("template").and_then(|template| template.get("loopback_endpoints")).cloned().unwrap_or_else(|| json!([]));
    a_of(previous) != a_of(next) || protected(previous) != protected(next) || loopback(previous) != loopback(next)
}

pub fn publish(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["userRef", "user_ref", "environmentRef", "confirmation", "receiptId"])?;
    let user_ref = user_target(&input)?;
    let environment = input.string("environmentRef", 128)?;
    let confirmed = input.object("confirmation")?.and_then(|map| map.get("confirmed")).and_then(Value::as_bool) == Some(true);
    let receipt_id = input.string("receiptId", 128)?;
    if let Some(id) = &receipt_id {
        if !valid_ref(id) {
            return Err(ApiError::invalid("receiptId 只能含字母、数字与 . _ : -").with("field", json!("receiptId")));
        }
    }
    let now_ms = ctx.now();
    let now = iso_from_millis(now_ms);
    let outcome = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        existing_user(transaction, &user_ref)?;
        let candidate = load_candidate(transaction, &user_ref)?
            .ok_or_else(|| ApiError::new(404, "ASSIGNMENT_NOT_FOUND", "该用户没有待发布的候选分配"))?;
        let check_environment = environment.clone().or_else(|| text(&candidate, "environment_ref").map(str::to_string));
        let validation = validate_assignment(Some(&candidate), check_environment.as_deref(), now_ms);
        if !ready(&validation) {
            let code = validation["code"].as_str().filter(|code| *code != "ASSIGNMENT_VALID").unwrap_or("ASSIGNMENT_NOT_READY").to_string();
            return Ok(json!({"ok": false, "code": code, "ready": false, "validation": validation, "assignment": public_assignment(Some(&candidate))}));
        }
        let previous = published_assignment(transaction, &user_ref)?;
        let mut next = candidate.clone();
        next["status"] = json!("ACTIVE");
        next["revoked"] = json!(false);
        next["published"] = json!(true);
        next["published_at"] = json!(now);
        next["published_by"] = json!(ctx.actor());
        let sensitive = sensitive_change(previous.as_ref(), &next);
        if sensitive && !confirmed {
            return Ok(json!({
                "ok": false,
                "code": "SENSITIVE_CHANGE_CONFIRMATION_REQUIRED",
                "ready": true,
                "sensitive": true,
                "validation": validation,
                "assignment": public_assignment(Some(&next)),
            }));
        }
        let version = next["assignment_version"].as_i64().unwrap_or(0);
        transaction
            .execute(
                "INSERT INTO control_assignments (user_ref, assignment_version, status, payload_json, published_at, revoked_at) VALUES (?1, ?2, 'ACTIVE', ?3, ?4, NULL)
                 ON CONFLICT(user_ref) DO UPDATE SET assignment_version = excluded.assignment_version, status = 'ACTIVE', payload_json = excluded.payload_json,
                        published_at = excluded.published_at, revoked_at = NULL",
                params![user_ref, version, next.to_string(), now],
            )
            .map_err(write_failed)?;
        transaction
            .execute("DELETE FROM control_assignment_candidates WHERE user_ref = ?1", params![user_ref])
            .map_err(write_failed)?;
        let receipt_id = receipt_id.clone().unwrap_or_else(|| format!("published:{user_ref}:{version}"));
        let receipt = json!({
            "receipt_id": receipt_id,
            "user_ref": user_ref,
            "assignment_version": version,
            "template_version": next["template_version"],
            "published_at": now,
            "sensitive": sensitive,
            "confirmed": confirmed,
            "client_applied": false,
        });
        transaction
            .execute(
                "INSERT INTO control_publish_receipts (receipt_id, user_ref, assignment_version, payload_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![receipt_id, user_ref, version, receipt.to_string(), now],
            )
            .map_err(|error| {
                if crate::store::is_constraint(&error) {
                    ApiError::new(409, "ASSIGNMENT_INVALID", "这个分配版本已经发布过，或回执编号已被使用")
                } else {
                    ApiError::from(write_failed(error))
                }
            })?;
        Ok(json!({
            "ok": true,
            "ready": true,
            "validation": validation,
            "sensitive": sensitive,
            "assignment": public_assignment(Some(&next)),
            "receipt": {"receipt_id": receipt_id, "assignment_version": version, "published_at": now},
        }))
    })?;
    ctx.info(
        "admin.assignment.publish",
        json!({"actor": ctx.actor(), "user_ref": user_ref, "ok": outcome["ok"], "code": outcome.get("code"), "sensitive": outcome.get("sensitive")}),
    );
    Ok(ApiResponse::json(200, outcome))
}

pub fn revoke(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["userRef", "user_ref"])?;
    let user_ref = user_target(&input)?;
    let now = iso_from_millis(ctx.now());
    let assignment = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        existing_user(transaction, &user_ref)?;
        let mut payload = published_assignment(transaction, &user_ref)?
            .ok_or_else(|| ApiError::new(404, "ASSIGNMENT_NOT_FOUND", "该用户没有已发布的分配"))?;
        if text(&payload, "status") != Some("REVOKED") {
            payload["status"] = json!("REVOKED");
            payload["revoked"] = json!(true);
            payload["published"] = json!(false);
            payload["revoked_at"] = json!(now);
            payload["revoked_by"] = json!(ctx.actor());
            transaction
                .execute(
                    "UPDATE control_assignments SET status = 'REVOKED', payload_json = ?1, revoked_at = ?2 WHERE user_ref = ?3",
                    params![payload.to_string(), now, user_ref],
                )
                .map_err(write_failed)?;
        }
        Ok(payload)
    })?;
    ctx.info("admin.assignment.revoked", json!({"actor": ctx.actor(), "user_ref": user_ref, "assignment_version": assignment["assignment_version"]}));
    Ok(ApiResponse::json(200, json!({"ok": true, "assignment": public_assignment(Some(&assignment))})))
}

/// 普通用户读取自己的已发布分配与额度快照；候选草稿不下发。
pub fn network_assignment(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let actor = ctx.actor().to_string();
    let (assignment, snapshot) = ctx.app.store.read(|connection| -> Result<(Option<Value>, Option<Value>), ControlError> {
        Ok((published_assignment(connection, &actor)?, load_snapshot(connection, &actor)?))
    })?;
    Ok(ApiResponse::json(
        200,
        json!({"user_ref": actor, "assignment": public_assignment(assignment.as_ref()), "quota": public_quota(snapshot.as_ref())}),
    ))
}

const RECEIPT_SECRET_KEYS: [&str; 10] = ["yaml", "core_secret", "password", "passwd", "secret", "token", "credential", "authorization", "cookie", "api_key"];

fn strip_receipt(value: &Value, depth: usize) -> Value {
    if depth > 8 {
        return Value::Null;
    }
    match value {
        Value::Object(map) => {
            let mut copy = Map::new();
            for (key, child) in map {
                let lowered = key.to_ascii_lowercase();
                if RECEIPT_SECRET_KEYS.iter().any(|part| lowered.contains(part)) {
                    continue;
                }
                copy.insert(key.clone(), strip_receipt(child, depth + 1));
            }
            Value::Object(copy)
        }
        Value::Array(items) => Value::Array(items.iter().map(|item| strip_receipt(item, depth + 1)).collect()),
        other => other.clone(),
    }
}

/// 客户端应用回执：按 (当前用户, operation_id) 幂等保存；配置正文、内核密钥等秘密字段一律丢弃。
pub fn save_receipt(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let operation_id = body
        .get("operation_id")
        .and_then(Value::as_str)
        .filter(|id| valid_ref(id))
        .ok_or_else(|| ApiError::invalid("operation_id 必填，且只能含字母、数字与 . _ : -").with("field", json!("operation_id")))?
        .to_string();
    let mut receipt = strip_receipt(&body, 0);
    receipt["user_ref"] = json!(ctx.actor());
    let actor = ctx.actor().to_string();
    let now = iso_from_millis(ctx.now());
    ctx.app.store.write(|transaction| -> Result<(), ControlError> {
        transaction
            .execute(
                "INSERT INTO control_apply_receipts (user_ref, operation_id, payload_json, received_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(user_ref, operation_id) DO UPDATE SET payload_json = excluded.payload_json, received_at = excluded.received_at",
                params![actor, operation_id, receipt.to_string(), now],
            )
            .map_err(write_failed)?;
        Ok(())
    })?;
    ctx.info("network.receipt.recorded", json!({"user_ref": actor, "operation_id": operation_id}));
    Ok(ApiResponse::json(200, json!({"status": "RECORDED", "operation_id": operation_id})))
}

// ---------------------------------------------------------------- 个人凭据

fn credential_purpose(user_ref: &str, credential_ref: &str) -> String {
    format!("personal_credential:{user_ref}:{credential_ref}")
}

pub fn admin_list_credentials(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let user_ref = ctx.query("user_ref").ok_or_else(|| ApiError::invalid("查询参数 user_ref 必填"))?.to_string();
    let credentials = ctx.app.store.read(|connection| -> Result<Vec<Value>, ApiError> {
        existing_user(connection, &user_ref)?;
        let mut statement = connection
            .prepare("SELECT credential_ref, status, version, secret_ref, updated_at FROM control_credentials WHERE user_ref = ?1 ORDER BY credential_ref")
            .map_err(read_failed)?;
        let rows = statement
            .query_map(params![user_ref], |row| {
                let credential_ref: String = row.get(0)?;
                let status: String = row.get(1)?;
                let version: i64 = row.get(2)?;
                let secret_ref: Option<String> = row.get(3)?;
                let updated_at: String = row.get(4)?;
                Ok((credential_ref, status, version, secret_ref, updated_at))
            })
            .map_err(read_failed)?;
        let collected: Result<Vec<_>, rusqlite::Error> = rows.collect();
        let mut views = Vec::new();
        for (credential_ref, status, version, secret_ref, updated_at) in collected.map_err(read_failed)? {
            let present = secret_meta(connection, secret_ref.as_deref())?.is_some();
            views.push(json!({"credential_ref": credential_ref, "status": status, "version": version, "secret_present": present, "updated_at": updated_at}));
        }
        Ok(views)
    })?;
    Ok(ApiResponse::json(200, json!({"user_ref": user_ref, "credentials": credentials})))
}

pub fn admin_put_credential(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["user_ref", "credential_ref", "username", "password"])?;
    let user_ref = required_ref(&input, &["user_ref"])?;
    let credential_ref = required_ref(&input, &["credential_ref"])?;
    let username = input
        .raw_string("username", 256)?
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| ApiError::new(400, "CREDENTIAL_INVALID", "username 必填").with("field", json!("username")))?;
    let password = input.raw_string("password", 1024)?;
    let material = json!({"username": username, "password": password});
    let now_ms = ctx.now();
    let now = iso_from_millis(now_ms);
    let protector = ctx.app.protector.as_ref();
    let view = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        existing_user(transaction, &user_ref)?;
        let existing: Option<(Option<String>, i64)> = transaction
            .query_row(
                "SELECT secret_ref, version FROM control_credentials WHERE credential_ref = ?1 AND user_ref = ?2",
                params![credential_ref, user_ref],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(read_failed)?;
        let previous_secret = existing.as_ref().and_then(|(secret, _)| secret.clone());
        let secret_ref = put_secret(
            transaction,
            protector,
            previous_secret.as_deref(),
            &credential_purpose(&user_ref, &credential_ref),
            material.to_string().as_bytes(),
            now_ms,
        )?;
        let version = existing.as_ref().map(|(_, version)| *version).unwrap_or(0) + 1;
        transaction
            .execute(
                "INSERT INTO control_credentials (credential_ref, user_ref, secret_ref, status, version, created_at, updated_at) VALUES (?1, ?2, ?3, 'ACTIVE', ?4, ?5, ?5)
                 ON CONFLICT(credential_ref, user_ref) DO UPDATE SET secret_ref = excluded.secret_ref, status = 'ACTIVE', version = excluded.version, updated_at = excluded.updated_at",
                params![credential_ref, user_ref, secret_ref, version, now],
            )
            .map_err(write_failed)?;
        Ok(json!({"credential_ref": credential_ref, "status": "ACTIVE", "version": version, "secret_present": true, "updated_at": now}))
    })?;
    ctx.info("admin.credential.saved", json!({"actor": ctx.actor(), "user_ref": user_ref, "credential_ref": credential_ref, "version": view["version"]}));
    Ok(ApiResponse::json(200, json!({"ok": true, "user_ref": user_ref, "credential": view})))
}

pub fn admin_revoke_credential(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let body = ctx.body()?;
    let input = fields(&body, &["user_ref", "credential_ref"])?;
    let user_ref = required_ref(&input, &["user_ref"])?;
    let credential_ref = required_ref(&input, &["credential_ref"])?;
    let now = iso_from_millis(ctx.now());
    let view = ctx.app.store.write(|transaction| -> Result<Value, ApiError> {
        existing_user(transaction, &user_ref)?;
        let existing: Option<(Option<String>, i64)> = transaction
            .query_row(
                "SELECT secret_ref, version FROM control_credentials WHERE credential_ref = ?1 AND user_ref = ?2",
                params![credential_ref, user_ref],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(read_failed)?;
        let (secret_ref, version) = existing.ok_or_else(|| ApiError::new(404, "CREDENTIAL_NOT_FOUND", "该用户没有这条凭据"))?;
        transaction
            .execute(
                "UPDATE control_credentials SET status = 'REVOKED', secret_ref = NULL, updated_at = ?1 WHERE credential_ref = ?2 AND user_ref = ?3",
                params![now, credential_ref, user_ref],
            )
            .map_err(write_failed)?;
        if let Some(secret_ref) = secret_ref {
            delete_secret(transaction, &secret_ref)?;
        }
        Ok(json!({"credential_ref": credential_ref, "status": "REVOKED", "version": version, "secret_present": false, "updated_at": now}))
    })?;
    ctx.info("admin.credential.revoked", json!({"actor": ctx.actor(), "user_ref": user_ref, "credential_ref": credential_ref}));
    Ok(ApiResponse::json(200, json!({"ok": true, "user_ref": user_ref, "credential": view})))
}

/// GET /api/network/credentials：只下发当前认证用户在有效已发布分配里用得到的个人凭据。
pub fn network_credentials(ctx: &Ctx) -> Result<ApiResponse, ApiError> {
    let actor = ctx.actor().to_string();
    let now_ms = ctx.now();
    let protector = ctx.app.protector.as_ref();
    let (status, code, credentials, withheld) = ctx.app.store.read(|connection| -> Result<(String, Option<String>, Map<String, Value>, Vec<Value>), ControlError> {
        let mut credentials = Map::new();
        let mut withheld = Vec::new();
        let assignment = match published_assignment(connection, &actor)? {
            Some(assignment) => assignment,
            None => return Ok(("UNAVAILABLE".to_string(), Some("ASSIGNMENT_NOT_FOUND".to_string()), credentials, withheld)),
        };
        let validation = validate_assignment(Some(&assignment), None, now_ms);
        if validation["ok"].as_bool() != Some(true) {
            let code = validation["code"].as_str().unwrap_or("ASSIGNMENT_INVALID").to_string();
            return Ok(("UNAVAILABLE".to_string(), Some(code), credentials, withheld));
        }
        let quota_status = load_snapshot(connection, &actor)?.and_then(|snapshot| text(&snapshot, "status").map(str::to_string));
        if matches!(quota_status.as_deref(), Some("DISABLED") | Some("EXPIRED")) {
            return Ok(("UNAVAILABLE".to_string(), Some(format!("QUOTA_{}", quota_status.unwrap_or_default())), credentials, withheld));
        }
        let mut references: Vec<(String, String)> = Vec::new();
        if let Some(resources) = assignment.get("resources").and_then(Value::as_object) {
            for (resource_id, snapshot) in resources {
                if let Some(credential_ref) = text(snapshot, "credential_ref") {
                    references.push((resource_id.clone(), credential_ref.to_string()));
                }
            }
        }
        for (resource_id, credential_ref) in references {
            if credentials.contains_key(&credential_ref) {
                continue;
            }
            let live = load_resource(connection, &resource_id)?;
            let usable = live.as_ref().map(|resource| resource_usable(resource, now_ms)).unwrap_or(false);
            if !usable {
                withheld.push(json!({"credential_ref": credential_ref, "reason": "RESOURCE_UNAVAILABLE"}));
                continue;
            }
            let row: Option<(String, Option<String>)> = connection
                .query_row(
                    "SELECT status, secret_ref FROM control_credentials WHERE credential_ref = ?1 AND user_ref = ?2",
                    params![credential_ref, actor],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(read_failed)?;
            let secret_ref = match row {
                Some((status, Some(secret_ref))) if status == "ACTIVE" => secret_ref,
                Some(_) => {
                    withheld.push(json!({"credential_ref": credential_ref, "reason": "CREDENTIAL_REVOKED"}));
                    continue;
                }
                None => {
                    withheld.push(json!({"credential_ref": credential_ref, "reason": "CREDENTIAL_NOT_ISSUED"}));
                    continue;
                }
            };
            match read_secret_text(connection, protector, &secret_ref, &credential_purpose(&actor, &credential_ref))
                .ok()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            {
                Some(material) if material.get("username").and_then(Value::as_str).is_some() => {
                    credentials.insert(credential_ref, json!({"username": material["username"], "password": material["password"]}));
                }
                _ => withheld.push(json!({"credential_ref": credential_ref, "reason": "CONTROL_SECRET_UNREADABLE"})),
            }
        }
        let status = if credentials.is_empty() { "UNAVAILABLE" } else { "AVAILABLE" };
        Ok((status.to_string(), None, credentials, withheld))
    })?;
    let unreadable = withheld.iter().filter(|item| item["reason"] == "CONTROL_SECRET_UNREADABLE").count();
    if unreadable > 0 {
        ctx.error("network.credentials.unreadable", json!({"user_ref": actor, "count": unreadable}));
    }
    ctx.info(
        "network.credentials.issued",
        json!({"user_ref": actor, "status": status, "code": code, "issued": credentials.len(), "withheld": withheld.len()}),
    );
    Ok(ApiResponse::json(
        200,
        json!({"user_ref": actor, "status": status, "code": code, "credentials": credentials, "withheld": withheld}),
    )
    .no_store())
}
