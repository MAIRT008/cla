//! 宿主网络业务操作到产品服务固定命令的包装（RC3）。
//!
//! 页面只看到 ReadNetworkState / ApplyNetworkPlan / ProtectEnvironment / NetworkLifecycle 这些业务操作；
//! 宿主按本地授权记录核对环境与计划版本、解析受管 YAML、核对摘要，把草稿写进产品网络状态根，
//! 再给服务发送带 envelope 的固定命令。服务只接受该根下的规范化路径与匹配的 SHA-256。
//! 回执原样透传服务的分阶段结果，外层 `ok` 只在服务确认时为真。

use std::path::PathBuf;

use serde_json::{json, Value};
use steward_service_ipc::core::auth::sha256_hex;
use steward_service_ipc::core::config::inspect_managed_yaml;
use steward_service_ipc::{ServiceCommand, ServiceError, ServiceReply};

use crate::commands::{now_millis, parse_iso_millis, HostState};
use crate::service_ipc::{product_identity, service_descriptor};

const OBSERVE_INCLUDES: [&str; 3] = ["config", "connections", "logs"];

fn text<'a>(payload: &'a Value, field: &str) -> Result<&'a str, String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or_else(|| format!("NATIVE_PAYLOAD_INVALID: {field} is required"))
}

fn grant_expiry(grant: Option<&Value>) -> Option<i64> {
    grant.and_then(|record| record.get("expires_at")).and_then(Value::as_str).and_then(parse_iso_millis)
}

fn declared_environment<'a>(state: &HostState, payload: &'a Value) -> Result<&'a str, String> {
    let environment_ref = text(payload, "environment_ref")?;
    if environment_ref != state.environment_ref {
        return Err(format!(
            "NATIVE_AUTHORIZATION_TARGET_MISMATCH: this install runs {} but the payload targets {environment_ref}",
            state.environment_ref
        ));
    }
    Ok(environment_ref)
}

fn service_result(state: &HostState, command: ServiceCommand, outcome: Result<ServiceReply, ServiceError>) -> Value {
    match outcome {
        Ok(reply) => json!({
            "ok": reply.ok,
            "code": reply.code,
            "reason": reply.reason,
            "command": command.name(),
            "identity": product_identity(&state.windows_user),
            "factory": state.factory,
            "receipt": reply.receipt,
        }),
        Err(error) => json!({
            "ok": false,
            "code": error.code,
            "reason": error.reason,
            "command": command.name(),
            "identity": product_identity(&state.windows_user),
            "factory": state.factory,
            "receipt": {"side_effects": false},
        }),
    }
}

/// 只读：握手核对服务身份与协议，再取实际运行记录。服务不可达时如实回报，不触发安装或修复。
pub fn read_network_state(state: &HostState, payload: &Value) -> Result<Value, String> {
    let environment_ref = declared_environment(state, payload)?;
    let include: Vec<&str> = payload
        .get("include")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).filter(|item| OBSERVE_INCLUDES.contains(item)).collect())
        .unwrap_or_default();
    let service = service_descriptor(&state.network);
    let handshake = match state.network.read(ServiceCommand::Handshake, json!({})) {
        Ok(reply) => reply,
        Err(error) => {
            return Ok(json!({
                "ok": false,
                "code": error.code,
                "reason": error.reason,
                "identity": product_identity(&state.windows_user),
                "factory": state.factory,
                "service": service,
                "runtime": {
                    "service": {"status": "UNREACHABLE", "code": error.code},
                    "missing": ["service", "core", "config", "readback", "protection", "emergency"],
                },
            }))
        }
    };
    let receipt = &handshake.receipt;
    let product = receipt.get("product_id").and_then(Value::as_str);
    let protocol = receipt.get("protocol").and_then(Value::as_str);
    if !handshake.ok || product != Some(steward_service_ipc::PRODUCT_APP_ID) || protocol != Some(steward_service_ipc::PROTOCOL) {
        return Ok(json!({
            "ok": false,
            "code": "SERVICE_IDENTITY_MISMATCH",
            "identity": product_identity(&state.windows_user),
            "factory": state.factory,
            "service": service,
            "runtime": {"service": {"status": "IDENTITY_MISMATCH"}, "missing": ["core", "config", "readback", "protection", "emergency"]},
        }));
    }
    let observed = state.network.read(ServiceCommand::ObserveRuntime, json!({"environment_ref": environment_ref, "include": include}));
    let mut result = service_result(state, ServiceCommand::ObserveRuntime, observed);
    result["service"] = service;
    result["handshake"] = handshake.receipt;
    if let Some(runtime) = result.get("receipt").cloned() {
        result["runtime"] = runtime;
    }
    Ok(result)
}

fn draft_path(state: &HostState, operation_id: &str) -> PathBuf {
    state.network_root.join("drafts").join(format!("{}.yaml", &sha256_hex(operation_id.as_bytes())[..32]))
}

pub fn apply_network_plan(state: &HostState, payload: &Value, grant: Option<&Value>) -> Result<Value, String> {
    let operation_id = text(payload, "operation_id")?;
    let environment_ref = declared_environment(state, payload)?;
    let plan_ref = text(payload, "plan_ref")?;
    let plan_version = text(payload, "plan_version")?;
    let assignment_version = text(payload, "assignment_version")?;
    let expected = text(payload, "expected_config_sha256")?;
    let yaml = payload
        .get("yaml")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("NATIVE_PAYLOAD_INVALID: yaml is required")?;
    if !plan_version.starts_with(&format!("plan:{assignment_version}:")) {
        return Err("NATIVE_PAYLOAD_INVALID: plan_version does not belong to assignment_version".into());
    }
    let actual = sha256_hex(yaml.as_bytes());
    if actual != expected {
        return Ok(json!({"ok": false, "code": "CONFIG_DIGEST_MISMATCH", "receipt": {"side_effects": false, "stages": {"downloaded": {"status": "FAILED", "code": "CONFIG_DIGEST_MISMATCH"}}}}));
    }
    if let Err(error) = inspect_managed_yaml(yaml) {
        return Ok(json!({"ok": false, "code": error.code, "reason": error.reason, "receipt": {"side_effects": false, "stages": {"validated": {"status": "FAILED", "code": error.code, "step": "host_mapping"}}}}));
    }
    if !state.network.link_ready() {
        return Ok(service_result(state, ServiceCommand::ApplyConfig, Err(ServiceError::new("SERVICE_LINK_UNAVAILABLE", "本机没有可用的服务链接密钥"))));
    }
    let draft = draft_path(state, operation_id);
    if let Some(parent) = draft.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    }
    std::fs::write(&draft, yaml.as_bytes()).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let service_payload = json!({
        "environment_ref": environment_ref,
        "plan_ref": plan_ref,
        "plan_version": plan_version,
        "assignment_version": assignment_version,
        "expected_config_sha256": expected,
        "draft_path": draft.to_string_lossy(),
    });
    let expiry = grant_expiry(grant);
    let validated = state.network.write(ServiceCommand::ValidateConfig, operation_id, service_payload.clone(), now_millis(), expiry);
    let validation = service_result(state, ServiceCommand::ValidateConfig, validated);
    if validation["ok"] != json!(true) {
        let _ = std::fs::remove_file(&draft);
        return Ok(validation);
    }
    let applied = state.network.write(ServiceCommand::ApplyConfig, operation_id, service_payload, now_millis(), expiry);
    let _ = std::fs::remove_file(&draft);
    let mut result = service_result(state, ServiceCommand::ApplyConfig, applied);
    result["validation"] = validation["receipt"].clone();
    Ok(result)
}

fn closes_existing(reason_code: &str) -> bool {
    matches!(reason_code, "WRONG_ROUTE" | "PROTECTION_FAILED")
}

/// 先确认新连接阻断；只有服务回读确认生效且原因是在途风险时，才另外关闭既有受管连接，两份回执分开给。
pub fn protect_environment(state: &HostState, payload: &Value, grant: Option<&Value>) -> Result<Value, String> {
    let operation_id = text(payload, "operation_id")?;
    let environment_ref = declared_environment(state, payload)?;
    let reason_code = text(payload, "reason_code")?;
    if text(payload, "action")? != "block_new" {
        return Err("NATIVE_PAYLOAD_INVALID: ProtectEnvironment only accepts block_new".into());
    }
    let processes = payload.get("processes").and_then(Value::as_array).cloned().unwrap_or_default();
    if processes.is_empty() {
        return Ok(json!({
            "ok": false,
            "code": "EMPTY_PROCESS_SCOPE",
            "protection": {"requested": false, "effective": false, "new_connections_restricted": false, "status": "FAILED", "reason": "EMPTY_PROCESS_SCOPE"},
            "close_existing": {"status": "SKIPPED", "reason": "PROTECTION_NOT_REQUESTED"},
        }));
    }
    let expiry = grant_expiry(grant);
    let ensured = state.network.write(
        ServiceCommand::EnsureProtection,
        operation_id,
        json!({
            "environment_ref": environment_ref,
            "action": "block_new",
            "processes": processes,
            "loopback_policy": payload.get("loopback_policy").cloned().unwrap_or(Value::Null),
            "reason_code": reason_code,
        }),
        now_millis(),
        expiry,
    );
    let protection = service_result(state, ServiceCommand::EnsureProtection, ensured);
    let effective = protection["ok"] == json!(true) && protection["receipt"]["new_connections_restricted"] == json!(true);
    let close_existing = if !effective {
        json!({"status": "SKIPPED", "reason": "PROTECTION_NOT_EFFECTIVE"})
    } else if !closes_existing(reason_code) {
        json!({"status": "SKIPPED", "reason": "NOT_REQUESTED"})
    } else {
        let closed = state.network.write(
            ServiceCommand::CloseManagedConnections,
            operation_id,
            json!({"environment_ref": environment_ref, "reason_code": reason_code}),
            now_millis(),
            expiry,
        );
        service_result(state, ServiceCommand::CloseManagedConnections, closed)
    };
    let code = if effective { Value::Null } else { protection["code"].clone() };
    Ok(json!({
        "ok": effective,
        "code": code,
        "identity": product_identity(&state.windows_user),
        "factory": state.factory,
        "protection": protection["receipt"],
        "close_existing": close_existing,
    }))
}

/// 生命周期动作：恢复 last-valid、维护窗口停启内核、显式停止管理。窗口关闭与界面退出不经过这里。
pub fn network_lifecycle(state: &HostState, payload: &Value, grant: Option<&Value>) -> Result<Value, String> {
    let operation_id = text(payload, "operation_id")?;
    let environment_ref = declared_environment(state, payload)?;
    let event = text(payload, "event")?;
    let (command, service_payload) = match event {
        "restore_last_valid" => (
            ServiceCommand::RestoreLastValid,
            json!({"environment_ref": environment_ref, "reason_code": payload.get("reason_code").and_then(Value::as_str).unwrap_or("LIFECYCLE_RESTORE")}),
        ),
        "maintenance_start" => (
            ServiceCommand::StopCoreForMaintenance,
            json!({"environment_ref": environment_ref, "maintenance_ref": operation_id}),
        ),
        "maintenance_end" => (ServiceCommand::StartCore, json!({"environment_ref": environment_ref})),
        "stop_management" => {
            let processes = payload.get("processes").and_then(Value::as_array).cloned().unwrap_or_default();
            (
                ServiceCommand::EnsureProtection,
                json!({"environment_ref": environment_ref, "action": "release_owned", "processes": processes, "reason_code": "STOP_MANAGEMENT"}),
            )
        }
        other => return Err(format!("NATIVE_PAYLOAD_INVALID: unsupported network lifecycle event {other}")),
    };
    let outcome = state.network.write(command, operation_id, service_payload, now_millis(), grant_expiry(grant));
    let mut result = service_result(state, command, outcome);
    result["event"] = json!(event);
    Ok(result)
}
