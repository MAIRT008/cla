use std::path::PathBuf;

use serde_json::{json, Map, Value};

use crate::control_process::ControlSupervisor;
use crate::confirm::ConfirmationPrompt;
use crate::roots::{AuthorizedRoot, RootKind, Scope};
use crate::service_ipc::{assert_product_pipe, product_identity, service_descriptor, ServiceLink, PRODUCT_PIPE};
use crate::workspace;

pub struct HostState {
    pub windows_user: String,
    /// 产品网络服务链接：Mihomo、受管配置与 WFP 都归服务所有，宿主只签 envelope 转发固定命令。
    pub network: ServiceLink,
    /// 产品网络状态根：宿主在这里写配置草稿，服务按安装时批准的路径读取并核对摘要。
    pub network_root: PathBuf,
    pub factory: &'static str,
    /// 已授权的工作区根目录；所有文件与记录操作都收窄在这里面。
    pub workspace_root: PathBuf,
    /// 本产品控制端：宿主托管或明确配置的外部实例；握手通过前不回报地址。
    pub control: std::sync::Arc<ControlSupervisor>,
    /// 产品运行配置：页面自己没有安装信息，这些只能由宿主给出。
    pub environment_ref: String,
    /// 真实发现的输入：当前用户的实际位置与注册表只读视图。环境声明每次按它与授权登记现场生成。
    pub discovery: crate::discovery::Discovery,
    /// 授权保险库：在受限工作区之外，受限原生桥的任何文件操作都到不了这里。
    pub vault_root: PathBuf,
    /// 保险库互斥锁：校验与一次性消费必须在同一把锁内完成。
    pub vault_lock: std::sync::Mutex<()>,
    /// 本地用户确认通道：授权只能由它签发。
    pub confirm: Box<dyn ConfirmationPrompt>,
    /// 默认浏览器诊断的一次性回环监听；同一时间只有一个。
    pub browser_diag: crate::browser_diag::BrowserDiag,
    /// 已开启的应急第二浏览器会话。
    pub emergency: std::sync::Mutex<std::collections::BTreeMap<String, Value>>,
    /// 本地日志目录：宿主、控制端、产品网络服务；只读列举与读取，写只进应用日志与导出包。
    pub logs: crate::logs::LogDirs,
    /// 本进程的应用日志：页面流程失败与原生操作失败都记在这里。
    pub app_log: crate::logs::AppLog,
    /// 打开日志目录与导出包目录。
    pub folders: Box<dyn crate::logs::FolderOpener>,
    /// 危急系统通知：只按固定枚举取宿主自己的文案，窗口可见时不另弹。
    pub notices: Box<dyn crate::lifecycle::NoticeSink>,
}

fn text(payload: &Value, field: &str) -> Result<String, String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("NATIVE_PAYLOAD_INVALID: {field} is required"))
}

/// 应用自有产物目录：workspace_owned 范围只能写这些前缀，不能拿来改用户对象。
const OWNED_PREFIXES: &[&str] = &["records/", "backups/", "exports/", "audit/", "reports/", "state/"];

fn requires_authorization(op: &str) -> bool {
    matches!(
        op,
        "ApplyNetworkPlan"
            | "ProtectEnvironment"
            | "NetworkLifecycle"
            | "FileWrite"
            | "FileRemove"
            | "FileCopy"
            | "DirIsolate"
            | "DirRestore"
            | "RecordSave"
            | "BackupSave"
            | "DbMutate"
            | "DbRestore"
            | "EmergencyOpen"
            | "EmergencyClose"
    )
}

fn scope_ops(scope: &str) -> Option<&'static [&'static str]> {
    match scope {
        "emergency_session" => Some(&["EmergencyOpen", "EmergencyClose"]),
        "single_confirmation" => Some(&[
            "FileWrite", "FileRemove", "FileCopy", "DirIsolate", "DirRestore", "DbMutate", "DbRestore",
        ]),
        "workspace_owned" => Some(&["FileWrite", "FileRemove", "FileCopy", "RecordSave", "BackupSave"]),
        "preauthorized_protection" => Some(&["ApplyNetworkPlan", "ProtectEnvironment", "NetworkLifecycle"]),
        "stop_management" => Some(&["NetworkLifecycle"]),
        _ => None,
    }
}

/// 一次确认只覆盖一次原生写：用掉即作废，不能跨动作也不能重放。
fn scope_is_single_use(scope: &str) -> bool {
    matches!(scope, "single_confirmation" | "emergency_session" | "stop_management")
}

fn scope_requires(scope: &str) -> &'static [&'static str] {
    match scope {
        "single_confirmation" => &[
            "plan_ref", "plan_version", "action_id", "action", "native_op", "target", "expected_sha256", "expires_at",
        ],
        "workspace_owned" => &["expires_at"],
        "emergency_session" => &["session_ref", "native_op", "expires_at"],
        "preauthorized_protection" => &["environment_ref", "expires_at"],
        "stop_management" => &["environment_ref", "native_op", "expires_at"],
        _ => &[],
    }
}

/// 载荷里指向被改对象的字段，与契约的 TARGET_FIELDS 一一对应。
fn target_path<'a>(op: &str, payload: &'a Value) -> Option<&'a str> {
    let field = match op {
        "FileWrite" | "FileRemove" | "DbMutate" | "DbRestore" => "path",
        "FileCopy" | "DirIsolate" => "from",
        "DirRestore" => "target_path",
        "BackupSave" => "payload_path",
        _ => return None,
    };
    payload.get(field).and_then(Value::as_str)
}

pub(crate) fn parse_iso_millis(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let part = |from: usize, to: usize| -> Option<i64> { text.get(from..to)?.parse::<i64>().ok() };
    let year = part(0, 4)?;
    let month = part(5, 7)?;
    let day = part(8, 10)?;
    let hour = part(11, 13)?;
    let minute = part(14, 16)?;
    let second = part(17, 19)?;
    let millis = if bytes.len() >= 23 && bytes[19] == b'.' { part(20, 23).unwrap_or(0) } else { 0 };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = if shifted >= 0 { shifted } else { shifted - 399 } / 400;
    let year_of_era = shifted - era * 400;
    let month_position = (month + 9) % 12;
    let day_of_year = (153 * month_position + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some((days * 86_400 + hour * 3_600 + minute * 60 + second) * 1_000 + millis)
}

pub(crate) fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or_default()
}

/// 确认目标的当前指纹：目录按树、记录级数据库改写按逻辑状态（含 WAL 里已提交的内容）、其余按文件字节。
fn target_fingerprint(scope: &Scope, kind: Option<&str>, path: &str) -> Option<String> {
    match kind {
        Some("isolate_directory") => workspace::fingerprint_directory(scope, path).ok(),
        Some("cc_provider_delete") | Some("cookie_delete") => workspace::fingerprint_database(scope, path).ok(),
        _ => workspace::fingerprint_file(scope, path).ok(),
    }
}

fn fingerprint_matches(scope: &Scope, target: &str, grant: &Value) -> Result<(), String> {
    let kind = grant.get("target").and_then(|value| value.get("kind")).and_then(Value::as_str);
    let actual = target_fingerprint(scope, kind, target);
    let expected = grant.get("expected_sha256").and_then(Value::as_str);
    match (expected, actual.as_deref()) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(format!("NATIVE_OBJECT_DRIFTED: {target} is present but the authorization expects it absent")),
        (Some(_), None) => Err(format!("NATIVE_OBJECT_DRIFTED: {target} is missing since the confirmation")),
        (Some(left), Some(right)) if left == right => Ok(()),
        _ => Err(format!("NATIVE_OBJECT_DRIFTED: {target} changed after the confirmation")),
    }
}

/// 载荷里任何路径字段指向真实根（`roots/…`）。
fn touches_real(payload: &Value) -> bool {
    let real = |value: &Value| value.as_str().map(Scope::is_real).unwrap_or(false);
    ["path", "from", "to", "isolation_path", "target_path", "payload_path"]
        .iter()
        .any(|field| payload.get(*field).map(real).unwrap_or(false))
        || payload.get("prefixes").and_then(Value::as_array).map(|items| items.iter().any(real)).unwrap_or(false)
}

/// 碰到真实根时才读授权登记；登记被篡改就报错，不退回「全都允许」或「全都忽略」。
fn roots_for(state: &HostState, payload: &Value) -> Result<Vec<AuthorizedRoot>, String> {
    if touches_real(payload) {
        crate::roots::load(&state.vault_root)
    } else {
        Ok(Vec::new())
    }
}

/// 只接受宿主自己签发的授权引用：记录从工作区读出，范围、动作、对象、
/// 指纹与期限全部按**记录里的**内容核对。调用方传来的授权内容一律不作数。
fn authorize(state: &HostState, scope_paths: &Scope, op: &str, payload: &Value, authorization_ref: Option<&str>) -> Result<Option<Value>, String> {
    if !requires_authorization(op) {
        return Ok(None);
    }
    // 真实根只能作为单次确认绑定的那一个目标出现：复制与隔离的去向、恢复的来源都必须在工作区里。
    let secondary = match op {
        "FileCopy" | "DirIsolate" => payload.get("to"),
        "DirRestore" => payload.get("isolation_path"),
        "BackupSave" => payload.get("payload_path"),
        _ => None,
    };
    if secondary.and_then(Value::as_str).map(Scope::is_real).unwrap_or(false) {
        return Err(format!("NATIVE_AUTHORIZATION_TARGET_MISMATCH: {op} may only touch a real path as its confirmed target"));
    }
    let reference = authorization_ref
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("NATIVE_AUTHORIZATION_REQUIRED: {op} requires a reference issued by steward_user_confirm"))?;
    // 校验与消费必须在同一把锁里完成，否则两个并发调用会用掉同一条一次性授权。
    let _guard = state
        .vault_lock
        .lock()
        .map_err(|_| "NATIVE_AUTHORIZATION_STORE_BUSY: the authorization vault is unavailable".to_string())?;
    let grant = workspace::authorization_load(&state.vault_root, reference)?
        .ok_or_else(|| format!("NATIVE_AUTHORIZATION_UNKNOWN: {reference} was never issued by this host"))?;
    if grant.get("confirmed").and_then(Value::as_bool) != Some(true) {
        return Err(format!("NATIVE_AUTHORIZATION_UNKNOWN: {reference} carries no local confirmation"));
    }
    let scope = grant.get("scope").and_then(Value::as_str).unwrap_or_default();
    let ops = scope_ops(scope).ok_or_else(|| format!("NATIVE_AUTHORIZATION_SCOPE_INVALID: unknown authorization scope {scope}"))?;
    if !ops.contains(&op) {
        return Err(format!("NATIVE_AUTHORIZATION_SCOPE_INVALID: scope {scope} does not cover {op}"));
    }
    for field in scope_requires(scope) {
        let present = match *field {
            "expected_sha256" => grant.get(*field).is_some(),
            _ => grant.get(*field).map(|value| !value.is_null() && value.as_str() != Some("")).unwrap_or(false),
        };
        if !present {
            return Err(format!("NATIVE_AUTHORIZATION_SCOPE_INVALID: scope {scope} requires {field}"));
        }
    }
    let expires = grant.get("expires_at").and_then(Value::as_str).unwrap_or_default();
    match parse_iso_millis(expires) {
        None => return Err(format!("NATIVE_AUTHORIZATION_SCOPE_INVALID: expires_at {expires} is not an instant")),
        Some(deadline) if now_millis() >= deadline => {
            return Err(format!("NATIVE_AUTHORIZATION_EXPIRED: authorization {reference} expired at {expires}"));
        }
        Some(_) => {}
    }
    let target = target_path(op, payload);
    if scope == "workspace_owned" {
        if let Some(path) = target {
            if !OWNED_PREFIXES.iter().any(|prefix| path.starts_with(prefix)) {
                return Err(format!("NATIVE_AUTHORIZATION_TARGET_MISMATCH: scope {scope} may not touch {path}"));
            }
        }
        if touches_real(payload) {
            return Err(format!("NATIVE_AUTHORIZATION_TARGET_MISMATCH: scope {scope} may not touch an authorized real root"));
        }
    }
    if scope == "single_confirmation" {
        let granted = grant.get("target").and_then(|value| value.get("path")).and_then(Value::as_str);
        let matched = matches!((granted, target), (Some(left), Some(right)) if left == right);
        if !matched {
            return Err(format!(
                "NATIVE_AUTHORIZATION_TARGET_MISMATCH: authorization covers {} but the payload targets {}",
                granted.unwrap_or("<none>"),
                target.unwrap_or("<none>")
            ));
        }
        fingerprint_matches(scope_paths, target.unwrap_or_default(), &grant)?;
    }
    if scope == "preauthorized_protection" || scope == "stop_management" {
        let granted = grant.get("environment_ref").and_then(Value::as_str);
        let requested = payload.get("environment_ref").and_then(Value::as_str);
        if granted.is_none() || granted != requested {
            return Err(format!(
                "NATIVE_AUTHORIZATION_TARGET_MISMATCH: authorization covers {} but the payload targets {}",
                granted.unwrap_or("<none>"),
                requested.unwrap_or("<none>")
            ));
        }
    }
    // 显式停止管理会撤本产品保护：只能用单独确认的 stop_management 授权，预授权保护不能拿来做这件事。
    if op == "NetworkLifecycle" {
        let stopping = payload.get("event").and_then(Value::as_str) == Some("stop_management");
        if stopping != (scope == "stop_management") {
            return Err(format!("NATIVE_AUTHORIZATION_SCOPE_INVALID: scope {scope} does not cover this network lifecycle event"));
        }
    }
    if scope == "emergency_session" {
        let granted = grant.get("session_ref").and_then(Value::as_str);
        let requested = payload.get("session_id").and_then(Value::as_str);
        if granted != requested {
            return Err(format!(
                "NATIVE_AUTHORIZATION_TARGET_MISMATCH: authorization covers session {} but the payload targets {}",
                granted.unwrap_or("<none>"),
                requested.unwrap_or("<none>")
            ));
        }
    }
    // 一次确认绑定的是一个精确原生操作：拿 json_set 的确认去调 FileRemove 不成立。
    if scope_is_single_use(scope) {
        let bound = grant.get("native_op").and_then(Value::as_str).unwrap_or_default();
        if bound != op {
            return Err(format!("NATIVE_AUTHORIZATION_OP_MISMATCH: authorization covers {bound} but {op} was requested"));
        }
        workspace::authorization_consume(&state.vault_root, reference, op, &iso_from_millis(now_millis()))?;
    }
    Ok(Some(grant))
}

/// 单次确认用短窗口；范围授权用当班时长。
fn scope_validity_millis(scope: &str) -> i64 {
    match scope {
        "workspace_owned" | "preauthorized_protection" => 12 * 60 * 60 * 1000,
        _ => 2 * 60 * 60 * 1000,
    }
}

pub(crate) fn iso_from_millis(millis: i64) -> String {
    let total_seconds = millis.div_euclid(1000);
    let sub = millis.rem_euclid(1000);
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = if month_position < 10 { month_position + 3 } else { month_position - 9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60,
        sub
    )
}

/// 本地用户确认：这是唯一的授权来源。
/// 目标指纹由宿主自己测量；调用方给的 expected_sha256 只作为「我以为的样子」参与比对，
/// 对不上就当场拒绝，不进入记录。
pub fn user_confirm(state: &HostState, request: &Value) -> Result<Value, String> {
    assert_product_pipe(PRODUCT_PIPE)?;
    let scope = request
        .get("scope")
        .and_then(Value::as_str)
        .ok_or("NATIVE_PAYLOAD_INVALID: scope is required")?;
    if scope_ops(scope).is_none() {
        return Err(format!("NATIVE_AUTHORIZATION_SCOPE_INVALID: unknown authorization scope {scope}"));
    }

    let _guard = state
        .vault_lock
        .lock()
        .map_err(|_| "NATIVE_AUTHORIZATION_STORE_BUSY: the authorization vault is unavailable".to_string())?;

    // 范围授权可以复用还没过期的那一条，首次范围授权不必每次都打扰用户。
    if matches!(scope, "workspace_owned" | "preauthorized_protection")
        && request.get("reuse").and_then(Value::as_bool) == Some(true)
    {
        if let Some(existing) = latest_reusable(state, scope, request)? {
            return Ok(existing);
        }
    }

    // 一次性范围必须点名它覆盖的那一个原生操作，且该操作确实属于这个范围。
    if scope_is_single_use(scope) {
        let native_op = request
            .get("native_op")
            .and_then(Value::as_str)
            .ok_or("NATIVE_PAYLOAD_INVALID: native_op is required for a single-use confirmation")?;
        if !scope_ops(scope).map(|ops| ops.contains(&native_op)).unwrap_or(false) {
            return Err(format!("NATIVE_AUTHORIZATION_SCOPE_INVALID: scope {scope} does not cover {native_op}"));
        }
    }

    let mut record = Map::new();
    record.insert("scope".into(), json!(scope));
    record.insert("consumed_at".into(), Value::Null);
    for field in ["plan_ref", "plan_version", "action_id", "action", "native_op", "environment_ref", "session_ref"] {
        if let Some(value) = request.get(field) {
            record.insert(field.into(), value.clone());
        }
    }

    let mut observed: Option<String> = None;
    if scope == "single_confirmation" {
        let target = request
            .get("target")
            .ok_or("NATIVE_PAYLOAD_INVALID: target is required for a single confirmation")?;
        let path = target
            .get("path")
            .and_then(Value::as_str)
            .ok_or("NATIVE_PAYLOAD_INVALID: target.path is required")?;
        let roots = if Scope::is_real(path) { crate::roots::load(&state.vault_root)? } else { Vec::new() };
        let scope_paths = Scope { workspace: &state.workspace_root, roots: &roots };
        observed = target_fingerprint(&scope_paths, target.get("kind").and_then(Value::as_str), path);
        if Scope::is_real(path) {
            // 真实对象在确认框里显示宿主解析出的实际位置，用户看到的是自己电脑上的路径。
            let shown = scope_paths.resolve(path).map(|resolved| resolved.to_string_lossy().to_string()).map_err(|error| error.to_string())?;
            record.insert("real_path".into(), json!(shown));
        }
        let claimed = request.get("expected_sha256").and_then(Value::as_str);
        if claimed.is_some() && claimed != observed.as_deref() {
            return Err(format!("NATIVE_OBJECT_DRIFTED: {path} does not look the way this confirmation describes"));
        }
        record.insert("target".into(), target.clone());
        record.insert(
            "expected_sha256".into(),
            observed.clone().map(Value::String).unwrap_or(Value::Null),
        );
    }

    let issued_at = now_millis();
    let ttl = request
        .get("validity_ms")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| scope_validity_millis(scope));
    let expires_at = iso_from_millis(issued_at + ttl);

    // 窗口里的正文由宿主自己按已测得的事实拼出来。
    // 调用方的说明单列一行并标明未经核实，不能替代上面任何一项。
    let body = format!(
        "范围：{}\n动作：{}\n原生操作：{}\n目标：{}\n目标当前指纹：{}\n计划：{} 版本 {}\n有效期至：{}\n\n调用方说明（未经本机核实）：{}",
        scope,
        record.get("action").and_then(Value::as_str).unwrap_or("（无）"),
        record.get("native_op").and_then(Value::as_str).unwrap_or("（无）"),
        record
            .get("real_path")
            .and_then(Value::as_str)
            .or_else(|| record.get("target").and_then(|value| value.get("path")).and_then(Value::as_str))
            .unwrap_or("（本次不针对单个对象）"),
        observed.clone().unwrap_or_else(|| "对象当前不存在".to_string()),
        record.get("plan_ref").and_then(Value::as_str).unwrap_or("（无）"),
        record.get("plan_version").map(|value| value.to_string()).unwrap_or_else(|| "（无）".into()),
        expires_at,
        request.get("summary").and_then(Value::as_str).unwrap_or("（调用方未提供说明）")
    );
    let prompt = json!({
        "title": "确认本次处理",
        "body": body,
        "scope": scope,
        "native_op": record.get("native_op").cloned().unwrap_or(Value::Null),
        "target": record.get("target").cloned().unwrap_or(Value::Null),
        "observed_sha256": observed,
        "action": record.get("action").cloned().unwrap_or(Value::Null),
        "expires_at": expires_at,
        "caller_summary": request.get("summary").cloned().unwrap_or(Value::Null)
    });
    if !state.confirm.ask(&prompt)? {
        return Err("NATIVE_CONFIRMATION_DECLINED: the local user did not confirm this operation".into());
    }

    record.insert("confirmed".into(), json!(true));
    record.insert("issued_at".into(), json!(iso_from_millis(issued_at)));
    record.insert("expires_at".into(), json!(expires_at));
    record.insert("issued_by".into(), json!(product_identity(&state.windows_user)));

    let stored = workspace::authorization_issue(&state.vault_root, &record)?;
    Ok(json!({
        "ok": true,
        "authorization_ref": stored.get("authorization_ref").cloned().unwrap_or(Value::Null),
        "scope": scope,
        "expires_at": stored.get("expires_at").cloned().unwrap_or(Value::Null),
        "expected_sha256": stored.get("expected_sha256").cloned().unwrap_or(Value::Null)
    }))
}

fn latest_reusable(state: &HostState, scope: &str, request: &Value) -> Result<Option<Value>, String> {
    let rows = workspace::authorizations_list(&state.vault_root)?;
    let wanted_environment = request.get("environment_ref").and_then(Value::as_str);
    let found = rows.iter().rev().find(|row| {
        row.get("scope").and_then(Value::as_str) == Some(scope)
            && row.get("confirmed").and_then(Value::as_bool) == Some(true)
            && row
                .get("expires_at")
                .and_then(Value::as_str)
                .and_then(parse_iso_millis)
                .map(|deadline| now_millis() < deadline)
                .unwrap_or(false)
            && (wanted_environment.is_none() || row.get("environment_ref").and_then(Value::as_str) == wanted_environment)
    });
    Ok(found.map(|row| {
        json!({
            "ok": true,
            "authorization_ref": row.get("authorization_ref").cloned().unwrap_or(Value::Null),
            "scope": scope,
            "expires_at": row.get("expires_at").cloned().unwrap_or(Value::Null),
            "reused": true
        })
    }))
}

/// 现场发现 + 授权登记 → 环境声明。登记被篡改时不给扫描范围，并把原因带给页面。
pub fn discovery_view(state: &HostState) -> Value {
    let discovered = crate::discovery::discover(&state.discovery);
    let (roots, roots_error) = match crate::roots::load(&state.vault_root) {
        Ok(roots) => (roots, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let mut environment = crate::discovery::environment_declaration(&discovered, &roots);
    if let Some(error) = &roots_error {
        environment["status"] = json!("ROOTS_UNAVAILABLE");
        environment["roots_error"] = json!(error);
    }
    let authorized: Vec<Value> = roots.iter().map(AuthorizedRoot::to_value).collect();
    json!({
        "ok": true,
        "discovered": discovered,
        "environment": environment,
        "authorized_roots": authorized,
    })
}

fn requested_roots(payload: &Value) -> Result<Vec<String>, String> {
    let items = payload
        .get("root_refs")
        .and_then(Value::as_array)
        .ok_or("NATIVE_PAYLOAD_INVALID: root_refs is required")?;
    if items.is_empty() || items.len() > 64 {
        return Err("NATIVE_PAYLOAD_INVALID: root_refs must name 1 to 64 roots".into());
    }
    let mut refs: Vec<String> = Vec::new();
    for item in items {
        let reference = item
            .as_str()
            .filter(|value| crate::roots::valid_root_ref(value))
            .ok_or("NATIVE_PAYLOAD_INVALID: root_refs holds an invalid root reference")?;
        if !refs.iter().any(|existing| existing == reference) {
            refs.push(reference.to_string());
        }
    }
    Ok(refs)
}

/// 登记被篡改时，新的本地确认可以覆盖它：旧内容不可信，也不再使用。
fn existing_roots(state: &HostState) -> Result<(Vec<AuthorizedRoot>, bool), String> {
    match crate::roots::load(&state.vault_root) {
        Ok(roots) => Ok((roots, false)),
        Err(error) if error.starts_with("NATIVE_ROOTS_TAMPERED") => Ok((Vec::new(), true)),
        Err(error) => Err(error),
    }
}

/// 授权扫描范围：路径由宿主此刻重新发现、自己测得，确认框里显示的就是它；页面只能点名根引用。
fn authorize_roots(state: &HostState, payload: &Value) -> Result<Value, String> {
    let refs = requested_roots(payload)?;
    let discovered = crate::discovery::discover(&state.discovery);
    let candidates = discovered.get("candidates").and_then(Value::as_array).cloned().unwrap_or_default();
    let authorized_at = iso_from_millis(now_millis());
    let mut chosen: Vec<AuthorizedRoot> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    for reference in &refs {
        let candidate = candidates
            .iter()
            .find(|item| item.get("root_ref").and_then(Value::as_str) == Some(reference.as_str()))
            .ok_or_else(|| format!("NATIVE_ROOT_UNAVAILABLE: {reference} was not discovered on this machine"))?;
        if candidate.get("authorizable").and_then(Value::as_bool) != Some(true) {
            let reason = candidate
                .get("reason")
                .and_then(Value::as_str)
                .or_else(|| candidate.get("status").and_then(Value::as_str))
                .unwrap_or("unsupported");
            return Err(format!("NATIVE_ROOT_UNAVAILABLE: {reference} cannot be authorized ({reason})"));
        }
        let field = |name: &str| candidate.get(name).and_then(Value::as_str).unwrap_or_default().to_string();
        let kind = RootKind::parse(&field("kind")).ok_or("NATIVE_ROOT_UNAVAILABLE: discovery returned an unknown root kind")?;
        let path = field("path");
        lines.push(format!("• {}：{}", field("label"), path));
        chosen.push(AuthorizedRoot {
            root_ref: reference.clone(),
            path: PathBuf::from(&path),
            kind,
            client_ref: field("client_ref"),
            category: field("category"),
            environment_ref: field("environment_ref"),
            authorized_at: authorized_at.clone(),
        });
    }
    let body = format!(
        "允许本应用只读扫描下面这些位置：\n{}\n\n扫描只读取、不修改。清理或修改其中任何对象，仍会逐项请你确认。授权可以随时撤销。",
        lines.join("\n")
    );
    let prompt = json!({"title": "授权扫描范围", "body": body, "scope": "authorized_roots", "roots": refs});
    if !state.confirm.ask(&prompt)? {
        return Err("NATIVE_CONFIRMATION_DECLINED: the local user did not authorize these locations".into());
    }
    let _guard = state
        .vault_lock
        .lock()
        .map_err(|_| "NATIVE_AUTHORIZATION_STORE_BUSY: the authorization vault is unavailable".to_string())?;
    let (existing, replaced) = existing_roots(state)?;
    let next = crate::roots::merged(&existing, &chosen);
    crate::roots::save(&state.vault_root, &next)?;
    let views: Vec<Value> = next.iter().map(AuthorizedRoot::to_value).collect();
    Ok(json!({"ok": true, "authorized_roots": views, "replaced_tampered_registry": replaced}))
}

/// 撤销只收窄权限，不需要再弹确认；被篡改的登记直接清空。
fn revoke_roots(state: &HostState, payload: &Value) -> Result<Value, String> {
    let refs = requested_roots(payload)?;
    let _guard = state
        .vault_lock
        .lock()
        .map_err(|_| "NATIVE_AUTHORIZATION_STORE_BUSY: the authorization vault is unavailable".to_string())?;
    let (existing, replaced) = existing_roots(state)?;
    let next = crate::roots::without(&existing, &refs);
    crate::roots::save(&state.vault_root, &next)?;
    let views: Vec<Value> = next.iter().map(AuthorizedRoot::to_value).collect();
    Ok(json!({"ok": true, "authorized_roots": views, "revoked": refs, "replaced_tampered_registry": replaced}))
}

/// 宿主这一侧没有接上的能力如实列出来。探测服务地址由控制端按环境下发，页面自己核对，不在这里判断。
fn unimplemented_capabilities(state: &HostState, view: &Value) -> Vec<String> {
    let mut missing = Vec::new();
    // WSL 发行版只登记、不扫描：客体采集器本版没有实现。
    let wsl_listed = view["discovered"]
        .get("environments")
        .and_then(Value::as_array)
        .map(|items| items.iter().any(|item| item.get("kind").and_then(Value::as_str) == Some("wsl")))
        .unwrap_or(false);
    if wsl_listed {
        missing.push("environment.wsl_scan".to_string());
    }
    if !state.network.link_ready() {
        missing.push("network.service_link".to_string());
    }
    missing
}

pub fn dispatch(state: &HostState, op: &str, payload: &Value, authorization_ref: Option<&str>) -> Result<Value, String> {
    assert_product_pipe(PRODUCT_PIPE)?;
    let identity = product_identity(&state.windows_user);
    let roots = roots_for(state, payload)?;
    let scope = Scope { workspace: &state.workspace_root, roots: &roots };
    let grant = authorize(state, &scope, op, payload, authorization_ref)?;
    match op {
        "ReadNetworkState" => crate::network_runtime::read_network_state(state, payload),
        "ApplyNetworkPlan" => crate::network_runtime::apply_network_plan(state, payload, grant.as_ref()),
        "ProtectEnvironment" => crate::network_runtime::protect_environment(state, payload, grant.as_ref()),
        "NetworkLifecycle" => crate::network_runtime::network_lifecycle(state, payload, grant.as_ref()),
        "DescribeCapabilities" => {
            // 页面自己没有安装信息：控制端、受管内核、环境与 Windows 用户都由宿主给出。
            // 环境清单与声明按现场发现与授权登记生成，不读工作区里任何人都能写的文件。
            let view = discovery_view(state);
            Ok(json!({
                "ok": true,
                "contract": "steward-bridge-1",
                "identity": identity,
                "factory": state.factory,
                "groups": ["meta", "network", "files", "records", "databases", "emergency", "control", "session", "discovery", "browser_diag", "logs", "notify"],
                "unimplemented": unimplemented_capabilities(state, &view),
                "product": {
                    "control_base_url": state.control.ready_base_url(),
                    "control": state.control.status(),
                    "network_service": service_descriptor(&state.network),
                    "windows_user": state.windows_user,
                    "environment_ref": state.environment_ref,
                    "environments": view["discovered"]["environments"],
                    "environment": view["environment"],
                    "log_root": state.logs.host.to_string_lossy()
                }
            }))
        }
        "LogSources" => Ok(crate::logs::log_sources(&state.logs)),
        "LogRead" => crate::logs::log_read(&state.logs, &text(payload, "source_ref")?),
        "AppLogAppend" => crate::logs::app_log_append(&state.app_log, payload),
        "LogExportWrite" => crate::logs::export_write(&state.logs, payload),
        "LogOpenFolder" => crate::logs::open_folder(&state.logs, state.folders.as_ref(), payload),
        "NotifyCritical" => crate::lifecycle::notify_critical(state.notices.as_ref(), payload),
        "DiscoverEnvironment" => Ok(discovery_view(state)),
        "AuthorizeRoots" => authorize_roots(state, payload),
        "RevokeRoots" => revoke_roots(state, payload),
        "BrowserDiagListen" => crate::browser_diag::listen(&state.browser_diag, &state.environment_ref, &state.vault_root, payload),
        "BrowserDiagLaunch" => crate::browser_diag::launch(&state.browser_diag, payload),
        "BrowserDiagReceive" => crate::browser_diag::receive(&state.browser_diag, payload),
        "BrowserDiagClose" => crate::browser_diag::close(&state.browser_diag, payload),
        "ControlStatus" => Ok(json!({"ok": true, "control": state.control.status()})),
        "ControlSetupAdmin" => state.control.setup_admin(&text(payload, "username")?, &text(payload, "password")?),
        "SessionLoad" => crate::control_process::session_load(&state.vault_root, now_millis()),
        "SessionSave" => crate::control_process::session_save(&state.vault_root, payload, now_millis()),
        "SessionClear" => crate::control_process::session_clear(&state.vault_root),
        "FileRead" => workspace::file_read(&scope, &text(payload, "path")?),
        "FileWrite" => {
            workspace::file_write(&scope, &text(payload, "path")?, &text(payload, "bytes")?)
        }
        "FileRemove" => {
            workspace::file_remove(&scope, &text(payload, "path")?)
        }
        "FileCopy" => {
            workspace::file_copy(&scope, &text(payload, "from")?, &text(payload, "to")?)
        }
        "FileExists" => workspace::file_exists(&scope, &text(payload, "path")?),
        "FileWalk" => {
            let prefixes = payload
                .get("prefixes")
                .and_then(Value::as_array)
                .cloned()
                .ok_or("NATIVE_PAYLOAD_INVALID: prefixes is required")?;
            workspace::file_walk(&scope, &prefixes)
        }
        "DirIsolate" => {
            workspace::dir_isolate(&scope, &text(payload, "from")?, &text(payload, "to")?)
        }
        "DirPreviewRestore" => workspace::dir_preview_restore(
            &scope,
            &text(payload, "isolation_path")?,
            &text(payload, "target_path")?,
        ),
        "DirRestore" => {
            workspace::dir_restore(
                &scope,
                &text(payload, "isolation_path")?,
                &text(payload, "target_path")?,
            )
        }
        "RecordsLoad" => workspace::records_load(&state.workspace_root),
        "RecordSave" => {
            let stored = payload.get("payload").cloned().ok_or("NATIVE_PAYLOAD_INVALID: payload is required")?;
            workspace::record_save(
                &state.workspace_root,
                &text(payload, "type")?,
                &text(payload, "id")?,
                &stored,
                &text(payload, "now")?,
            )
        }
        "BackupSave" => {
            let metadata = payload.get("metadata").cloned().ok_or("NATIVE_PAYLOAD_INVALID: metadata is required")?;
            workspace::backup_save(
                &state.workspace_root,
                &text(payload, "backup_ref")?,
                &text(payload, "action_id")?,
                &text(payload, "payload_path")?,
                &metadata,
                &text(payload, "now")?,
            )
        }
        "EmergencyHosts" => Ok(json!({"ok": true, "hosts": crate::host::emergency_candidates(&state.windows_user)})),
        "EmergencyOpen" => crate::host::emergency_open(state, payload, grant.as_ref()),
        "EmergencyClose" => crate::host::emergency_close(state, payload, grant.as_ref()),
        "DbInspect" => workspace::db_inspect(&scope, &text(payload, "path")?, &text(payload, "kind")?),
        "DbMutate" => {
            let selector = payload.get("selector").cloned().ok_or("NATIVE_PAYLOAD_INVALID: selector is required")?;
            workspace::db_mutate(&scope, &text(payload, "path")?, &text(payload, "kind")?, &selector)
        }
        "DbFingerprint" => Ok(json!({"ok": true, "sha256": workspace::fingerprint_database(&scope, &text(payload, "path")?)?})),
        "DbSnapshot" => workspace::db_snapshot(&scope, &text(payload, "path")?),
        "DbSimulate" => {
            let selector = payload.get("selector").cloned().ok_or("NATIVE_PAYLOAD_INVALID: selector is required")?;
            let prior = payload.get("prior_mutations").and_then(Value::as_array).cloned().unwrap_or_default();
            workspace::db_simulate(&scope, &text(payload, "path")?, &text(payload, "kind")?, &selector, &prior)
        }
        "DbPreviewRestore" => {
            let selector = payload.get("selector").cloned().ok_or("NATIVE_PAYLOAD_INVALID: selector is required")?;
            workspace::db_preview_restore(
                &scope,
                &text(payload, "path")?,
                &text(payload, "kind")?,
                &selector,
                &text(payload, "backup_bytes")?,
            )
        }
        "DbRestore" => {
            let selector = payload.get("selector").cloned().ok_or("NATIVE_PAYLOAD_INVALID: selector is required")?;
            workspace::db_restore(
                &scope,
                &text(payload, "path")?,
                &text(payload, "kind")?,
                &selector,
                &text(payload, "backup_bytes")?,
            )
        }
        _ => Err(format!("NATIVE_OP_UNKNOWN: unsupported op {op}")),
    }
}

/// 页面经 Tauri 进来的每个原生操作：失败的一律在本机应用日志里留一行（操作名与错误码），界面没起来也照记。
pub fn dispatch_logged(state: &HostState, op: &str, payload: &Value, authorization_ref: Option<&str>) -> Result<Value, String> {
    let outcome = dispatch(state, op, payload, authorization_ref);
    crate::logs::record_outcome(&state.app_log, op, &outcome);
    outcome
}

#[cfg(feature = "tauri")]
#[tauri::command]
pub fn steward_request(op: String, payload: Value, authorization_ref: Option<String>, state: tauri::State<HostState>) -> Result<Value, String> {
    dispatch_logged(&state, &op, &payload, authorization_ref.as_deref())
}

/// 授权的唯一来源：本地用户确认。AI 工具集合里没有这个命令。
#[cfg(feature = "tauri")]
#[tauri::command]
pub fn steward_user_confirm(request: Value, state: tauri::State<HostState>) -> Result<Value, String> {
    user_confirm(&state, &request)
}
