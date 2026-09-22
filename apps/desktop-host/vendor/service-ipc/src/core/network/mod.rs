//! 产品网络服务状态机（新增，取代上游 `desired.rs`/`status.rs`/`runtime.rs` 的 desired-state 与状态快照）。
//!
//! 服务拥有 Mihomo 进程、受管配置文件、内核控制接口与 WFP 保护；这里只放业务顺序与判定，
//! 进程、内核接口、校验器、保护、文件与时钟都经注入端口，离线测试替换 I/O 而不替换这些判定。
//!
//! - 配置阶段分开记：downloaded（草稿读到且摘要一致）→ validated（Mapping 核对 + 固定内核校验）
//!   → applied（`PUT /configs` 204）→ verified（同一服务实例、同一内核进程、固定内核版本、模式/TUN/IPv6/规则/出口实际回读一致，
//!   且受管路径已在本内核报告的 TUN 接口上打开并回读）。只有 verified 才提交 active；回读失败时 active 置空，expected 单独保存。
//! - 保护分两层：批准程序的 WFP 阻断一直在；受管路径（只放行经本内核 TUN 接口的连接）只在 verified 之后打开，
//!   加载配置、停内核、回读失败、内核实例变化或服务重启前都先关上。
//! - 应急配置（含应急浏览器规则）只作临时 active，不写入 last-valid；到期由服务常驻的 `tick` 结束，不依赖宿主或页面存活。
//! - 服务重启只恢复保护、关受管路径，不自动加载 last-valid：服务手里没有可离线核验的未撤销授权材料，由客户端取得当前权威状态后显式恢复。
//! - 改写类命令先把意图落盘再执行，执行后再落一次；第二次落盘失败外层不算成功，重启后按实际回读对账，同一 operation 不再重放。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::core::auth::{canonical_json, envelope_expired, random_hex, sha256_hex, verify_envelope, Envelope};
use crate::core::command::ServiceCommand;
use crate::core::config::{compare_readback, inspect_managed_yaml, ManagedFacts, ReadbackCheck};
use crate::core::paths::{is_within, KERNEL_VERSION, PRODUCT_APP_ID, PROTOCOL, SERVICE_PIPE_OWNER_SID};
use crate::core::structure::{ServiceError, ServiceReply, ServiceRequest};

#[cfg(test)]
mod tests;

const MAX_OPERATIONS: usize = 256;
const MAX_PROCESSES: usize = 64;
const MAX_VALIDATED: usize = 8;
const MAX_INDETERMINATE: usize = 32;
const VALIDATION_REUSE_MS: i64 = 10 * 60 * 1000;
const LOG_TAIL_LINES: usize = 200;
const BROWSER_START_SKEW_MS: i64 = 5_000;
/// 应急配置已生效却没有打开的会话绑定它时，最多保留这么久就换回基线。
pub const EMERGENCY_UNBOUND_TTL_MS: i64 = 10 * 60 * 1000;
const MAX_LOOPBACK_ENDPOINTS: usize = 64;
const LOOPBACK_ENDPOINT_FIELDS: [&str; 5] = ["source_process_path", "transport", "address", "port", "purpose"];

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

pub trait StateStore: Send + Sync {
    fn load(&self) -> Result<Option<Value>, ServiceError>;
    fn save(&self, state: &Value) -> Result<(), ServiceError>;
}

pub trait ConfigStore: Send + Sync {
    /// 安装时批准的宿主草稿目录；没有安装记录就是 None，服务拒绝任何草稿。
    fn approved_draft_root(&self) -> Option<PathBuf>;
    fn read_draft(&self, draft: &Path) -> Result<Vec<u8>, ServiceError>;
    /// 按摘要保存到服务自有的内核配置目录，返回内核可加载的绝对路径。
    fn store(&self, sha256: &str, bytes: &[u8]) -> Result<PathBuf, ServiceError>;
    fn stored_path(&self, sha256: &str) -> Option<PathBuf>;
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CoreStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub started_at_ms: Option<i64>,
    pub restart_count: u32,
    pub last_exit: Option<String>,
    pub gave_up: bool,
}

pub trait CoreProcess: Send + Sync {
    fn binary_present(&self) -> bool;
    fn start(&self, config_path: &Path) -> Result<CoreStatus, ServiceError>;
    fn stop(&self) -> Result<(), ServiceError>;
    /// 看门狗有限重启时加载的配置；只在基线配置回读通过后更新，应急配置不进这里。
    fn set_restart_config(&self, config_path: &Path);
    fn status(&self) -> CoreStatus;
    fn log_tail(&self, max_lines: usize) -> Vec<String>;
}

/// 内核控制接口；每个方法返回内核的原始 JSON，不做任何补全。
pub trait CoreController: Send + Sync {
    fn version(&self) -> Result<Value, ServiceError>;
    fn load_config(&self, config_path: &Path) -> Result<u16, ServiceError>;
    fn general(&self) -> Result<Value, ServiceError>;
    fn rules(&self) -> Result<Value, ServiceError>;
    fn proxies(&self) -> Result<Value, ServiceError>;
    fn connections(&self) -> Result<Value, ServiceError>;
    fn close_connections(&self) -> Result<u16, ServiceError>;
}

pub trait KernelValidator: Send + Sync {
    fn validate(&self, config_path: &Path) -> Result<(), ServiceError>;
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtectionOutcome {
    /// 回读时本产品该类过滤器全部在、且层/条件/动作/权重/标记都符合定义的程序。基线要求阻断（v4 与 v6）与当前策略点名的回环端点 permit 都在。
    pub installed: Vec<String>,
    pub missing: Vec<String>,
    /// 键在但语义与本产品定义不符的程序；一律算未覆盖。
    pub mismatched: Vec<String>,
    /// 本环境里不属于当前回环策略的本产品回环 permit（策略缩减留下的旧端点、历史「全回环放行」），或无法枚举时的标记；有残留就不算覆盖。
    pub residual: Vec<String>,
    pub created: usize,
    pub removed: usize,
    pub rolled_back: bool,
    pub code: Option<String>,
    pub native_status: Option<i64>,
}

impl ProtectionOutcome {
    pub fn covers(&self, processes: &[String]) -> bool {
        !processes.is_empty()
            && self.residual.is_empty()
            && processes.iter().all(|wanted| self.installed.iter().any(|item| item.eq_ignore_ascii_case(wanted)))
    }
}

pub trait ProtectionBackend: Send + Sync {
    /// 批准程序的保护基线：硬阻断 + 策略点名的精确回环端点 permit；不在策略里的本环境回环 permit 一并删除。
    fn ensure(&self, environment_ref: &str, processes: &[String], loopback: &LoopbackPolicy) -> ProtectionOutcome;
    /// 回读完整集合：阻断、策略里的端点 permit（含策略摘要）与残留回环 permit。
    fn read(&self, environment_ref: &str, processes: &[String], loopback: &LoopbackPolicy) -> ProtectionOutcome;
    /// 撤掉本产品在该环境拥有的阻断、回环 permit 与受管路径。
    fn release(&self, environment_ref: &str, processes: &[String]) -> ProtectionOutcome;
    /// 把内核实际报告的 TUN 设备名换成接口 LUID。
    fn resolve_interface(&self, alias: &str) -> Result<u64, ServiceError>;
    /// 受管路径：只放行批准程序经该 LUID 接口发出的新连接。
    fn open_managed_path(&self, environment_ref: &str, processes: &[String], interface_luid: u64) -> ProtectionOutcome;
    fn read_managed_path(&self, environment_ref: &str, processes: &[String], interface_luid: u64) -> ProtectionOutcome;
    fn close_managed_path(&self, environment_ref: &str, processes: &[String]) -> ProtectionOutcome;
}

/// 模板批准的一个本机回环端点：发起程序、协议、单个回环地址、单端口与用途。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopbackEndpoint {
    pub source_process_path: String,
    pub transport: String,
    pub address: String,
    pub port: u16,
    pub purpose: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackAddress {
    /// 主机字节序：WFP 的 FWP_UINT32 地址条件按主机字节序比较。
    V4(u32),
    V6([u8; 16]),
}

/// 单个精确回环地址：IPv4 只收 127.0.0.0/8 内的规范写法，IPv6 只收 `::1`；通配、网段、范围与主机名都不是地址。
pub fn loopback_address(text: &str) -> Option<LoopbackAddress> {
    if text == "::1" {
        return Some(LoopbackAddress::V6(std::net::Ipv6Addr::LOCALHOST.octets()));
    }
    let address: std::net::Ipv4Addr = text.parse().ok()?;
    (address.is_loopback() && address.to_string() == text).then(|| LoopbackAddress::V4(u32::from(address)))
}

/// 回环放行策略：模板版本、端点清单与服务按规范形式算出的摘要。空清单表示回环全拦。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoopbackPolicy {
    pub template_version: Option<String>,
    pub endpoints: Vec<LoopbackEndpoint>,
    pub digest: String,
}

impl LoopbackPolicy {
    /// 端点按规范顺序排序后连同模板版本一起取摘要；清单顺序不影响摘要，版本或任何字段变了摘要就变。
    pub fn new(template_version: Option<String>, mut endpoints: Vec<LoopbackEndpoint>) -> LoopbackPolicy {
        endpoints.sort_by(|left, right| {
            (left.source_process_path.to_lowercase(), &left.transport, &left.address, left.port, &left.purpose)
                .cmp(&(right.source_process_path.to_lowercase(), &right.transport, &right.address, right.port, &right.purpose))
        });
        let digest = sha256_hex(canonical_json(&json!({"template_version": template_version, "endpoints": endpoints})).as_bytes());
        LoopbackPolicy { template_version, endpoints, digest }
    }

    fn view(&self) -> Value {
        json!({"template_version": self.template_version, "digest": self.digest, "endpoints": self.endpoints})
    }
}

/// 进程身份：PID、创建时间与程序完整路径，三者从同一个进程句柄读出。PID 会被系统复用，单独的 PID 不是身份。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub image_path: String,
    pub created_at_ms: i64,
}

impl ProcessIdentity {
    pub fn same_process(&self, other: &ProcessIdentity) -> bool {
        self.pid == other.pid
            && self.created_at_ms == other.created_at_ms
            && normalize_image_path(&self.image_path) == normalize_image_path(&other.image_path)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TerminateOutcome {
    Terminated,
    NotRunning,
    IdentityMismatch(ProcessIdentity),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum TerminationJudgement {
    NotRunning,
    Mismatch(ProcessIdentity),
    Proceed,
}

/// 结束前的核验：当前占着这个 PID 的进程必须与记录的创建时间和程序路径都一致。
pub fn judge_termination(expected: &ProcessIdentity, actual: Option<&ProcessIdentity>) -> TerminationJudgement {
    match actual {
        None => TerminationJudgement::NotRunning,
        Some(actual) if expected.same_process(actual) => TerminationJudgement::Proceed,
        Some(actual) => TerminationJudgement::Mismatch(actual.clone()),
    }
}

pub trait ProcessProbe: Send + Sync {
    /// 返回给定绝对程序路径里当前仍在运行的那些。
    fn running(&self, paths: &[String]) -> Result<Vec<String>, ServiceError>;
    fn identify(&self, pid: u32) -> Result<Option<ProcessIdentity>, ServiceError>;
    /// 实现必须在同一个句柄上读身份、调 `judge_termination`，一致才结束。
    fn terminate(&self, expected: &ProcessIdentity) -> TerminateOutcome;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedProcessEnd {
    Terminated,
    AlreadyGone,
    IdentityMismatch,
    RecordCorrupt,
    Failed(String),
}

impl OwnedProcessEnd {
    /// 只有确认结束或进程已不在时，记录才算处理完；核验失败保留记录作证据。
    pub fn record_resolved(&self) -> bool {
        matches!(self, OwnedProcessEnd::Terminated | OwnedProcessEnd::AlreadyGone)
    }

    pub fn code(&self) -> String {
        match self {
            OwnedProcessEnd::Terminated => "TERMINATED".to_string(),
            OwnedProcessEnd::AlreadyGone => "ALREADY_GONE".to_string(),
            OwnedProcessEnd::IdentityMismatch => "PROCESS_IDENTITY_MISMATCH".to_string(),
            OwnedProcessEnd::RecordCorrupt => "PROCESS_RECORD_CORRUPT".to_string(),
            OwnedProcessEnd::Failed(code) => code.clone(),
        }
    }
}

/// 按持久化的所有权记录结束本产品进程（遗留内核、旧服务实例）。记录读不懂就不结束任何进程。
pub fn end_owned_process(probe: &dyn ProcessProbe, record: &[u8]) -> OwnedProcessEnd {
    let identity = match serde_json::from_slice::<ProcessIdentity>(record) {
        Ok(identity) if identity.pid != 0 && !identity.image_path.is_empty() => identity,
        _ => return OwnedProcessEnd::RecordCorrupt,
    };
    match probe.terminate(&identity) {
        TerminateOutcome::Terminated => OwnedProcessEnd::Terminated,
        TerminateOutcome::NotRunning => OwnedProcessEnd::AlreadyGone,
        TerminateOutcome::IdentityMismatch(_) => OwnedProcessEnd::IdentityMismatch,
        TerminateOutcome::Failed(code) => OwnedProcessEnd::Failed(code),
    }
}

pub fn normalize_image_path(path: &str) -> String {
    let trimmed = path.trim().trim_matches('"');
    let local = trimmed.strip_prefix(r"\\?\").unwrap_or(trimmed);
    local.replace('/', "\\").to_lowercase()
}

/// 安装记录批准的调用方：宿主程序可以驱动全部命令；服务程序自己只能握手（新实例判断旧实例是否健康）。
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    pub host_image: Option<String>,
    pub service_image: Option<String>,
}

/// Windows 从 pipe 连接给出的客户端进程，不由请求自报。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerProcess {
    pub pid: u32,
    pub image_path: Option<String>,
}

pub fn authorize_peer(policy: &PeerPolicy, command: ServiceCommand, peer: Option<&PeerProcess>) -> Result<(), ServiceError> {
    let image = peer
        .and_then(|process| process.image_path.as_deref())
        .map(normalize_image_path)
        .ok_or_else(|| ServiceError::new("PEER_IDENTITY_UNAVAILABLE", "无法从 Windows 取得 pipe 客户端进程身份"))?;
    let approved = |expected: &Option<String>| expected.as_deref().map(|value| normalize_image_path(value) == image).unwrap_or(false);
    if approved(&policy.host_image) {
        return Ok(());
    }
    if command == ServiceCommand::Handshake && approved(&policy.service_image) {
        return Ok(());
    }
    if policy.host_image.is_none() {
        return Err(ServiceError::new("HOST_IDENTITY_UNAPPROVED", "服务没有安装时批准的宿主程序"));
    }
    Err(ServiceError::new("PEER_NOT_PRODUCT_HOST", "pipe 客户端不是安装记录里的本产品宿主"))
}

/// 客户端认证服务端：发送前读取 pipe 对象的所有者 SID（`GetSecurityInfo`，Microsoft 明确列出支持命名管道句柄）。
/// 服务以 LocalSystem 创建 pipe 并在安全描述符里显式声明所有者 SY；非管理员进程不能把自己建的 pipe 所有者设成 LocalSystem，
/// 抢先占用服务 pipe 名或另建实例（ACL 已不给批准用户建实例权限）都会在这里被拒。
pub fn authorize_service_server(owner_sid: Option<&str>) -> Result<(), ServiceError> {
    match owner_sid {
        None => Err(ServiceError::new("SERVICE_SERVER_IDENTITY_UNAVAILABLE", "读不到服务 pipe 的所有者")),
        Some(sid) if sid == SERVICE_PIPE_OWNER_SID => Ok(()),
        Some(_) => Err(ServiceError::new("SERVICE_SERVER_NOT_PRODUCT_SERVICE", "服务 pipe 的所有者不是 LocalSystem，不是本产品服务创建的")),
    }
}

pub struct Backends {
    pub clock: Box<dyn Clock>,
    pub state: Box<dyn StateStore>,
    pub configs: Box<dyn ConfigStore>,
    pub core: Box<dyn CoreProcess>,
    pub controller: Box<dyn CoreController>,
    pub validator: Box<dyn KernelValidator>,
    pub protection: Box<dyn ProtectionBackend>,
    pub processes: Box<dyn ProcessProbe>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Verification {
    pub status: String,
    pub checks: Vec<ReadbackCheck>,
    pub checked_at_ms: Option<i64>,
    pub service_instance_id: Option<String>,
    pub core_pid: Option<u32>,
    pub kernel_version: Option<String>,
    pub config_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastValid {
    pub config_sha256: String,
    pub environment_ref: String,
    pub plan_ref: String,
    pub plan_version: String,
    pub assignment_version: String,
    pub facts: ManagedFacts,
    pub verified_at_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectionRecord {
    pub processes: Vec<String>,
    pub requested: bool,
    pub effective: bool,
    pub checked_at_ms: i64,
    pub code: Option<String>,
    /// 最近一次保护请求带来的回环策略。旧记录没有这一项，按空清单（回环全拦）读入。
    #[serde(default)]
    pub loopback: LoopbackPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ManagedPathRecord {
    pub open: bool,
    pub interface_alias: Option<String>,
    pub interface_luid: Option<u64>,
    pub core_pid: Option<u32>,
    pub service_instance_id: Option<String>,
    pub config_sha256: Option<String>,
    pub checked_at_ms: i64,
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyRecord {
    pub session_ref: String,
    pub environment_ref: String,
    pub browser_process: String,
    pub expires_at_ms: i64,
    pub opened_at_ms: i64,
    pub open: bool,
    pub config_sha256: String,
    pub closed_at_ms: Option<i64>,
    pub route_rules_present_after_close: Option<bool>,
    #[serde(default)]
    pub browser: Option<ProcessIdentity>,
    #[serde(default)]
    pub close_reason: Option<String>,
    #[serde(default)]
    pub close_code: Option<String>,
    #[serde(default)]
    pub browser_stopped: Option<bool>,
    #[serde(default)]
    pub closed_safely: bool,
    #[serde(default)]
    pub close_indeterminate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedConfig {
    pub sha256: String,
    pub facts: ManagedFacts,
    pub at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    pub operation_id: String,
    pub command: String,
    pub request_digest: String,
    pub reply: ServiceReply,
    pub at_ms: i64,
}

/// 改写开始前落盘的意图；执行完成并再次落盘后清掉。服务重启时还在，说明结果没有落盘，按实际回读对账。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOperation {
    pub operation_id: String,
    pub command: String,
    pub request_digest: String,
    pub environment_ref: Option<String>,
    pub action: Option<String>,
    pub processes: Vec<String>,
    pub session_ref: Option<String>,
    pub started_at_ms: i64,
    #[serde(default)]
    pub reconciled_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeState {
    pub schema: u32,
    pub environment_ref: Option<String>,
    pub expected_config_sha256: Option<String>,
    pub active_config_sha256: Option<String>,
    pub plan_ref: Option<String>,
    pub plan_version: Option<String>,
    pub assignment_version: Option<String>,
    pub active_facts: Option<ManagedFacts>,
    pub verification: Verification,
    pub last_valid: Option<LastValid>,
    pub emergency_config: Option<LastValid>,
    pub core_should_run: bool,
    pub last_failure_code: Option<String>,
    pub protection: BTreeMap<String, ProtectionRecord>,
    pub managed_path: BTreeMap<String, ManagedPathRecord>,
    pub emergency: BTreeMap<String, EmergencyRecord>,
    pub validated: Vec<ValidatedConfig>,
    pub operations: Vec<OperationRecord>,
    pub pending: Option<PendingOperation>,
    pub indeterminate: Vec<PendingOperation>,
    pub updated_at_ms: i64,
}

type Outcome = Result<Value, (ServiceError, Value)>;

struct Prepared {
    environment_ref: String,
    plan_ref: String,
    plan_version: String,
    assignment_version: String,
    sha256: String,
    facts: ManagedFacts,
    config_path: PathBuf,
}

struct Readback {
    checks: Vec<ReadbackCheck>,
    core: CoreStatus,
    kernel_version: Option<String>,
    general: Value,
}

struct Verified {
    verified: bool,
    checks: Vec<ReadbackCheck>,
    core: CoreStatus,
    kernel_version: Option<String>,
}

struct Retired {
    rules_present: bool,
    core_stopped: bool,
    baseline_restored: bool,
    code: Option<String>,
}

fn rejected(error: ServiceError) -> (ServiceError, Value) {
    (error, json!({"side_effects": false}))
}

fn with_stages(error: ServiceError, stages: &Map<String, Value>, side_effects: bool) -> (ServiceError, Value) {
    (error, json!({"side_effects": side_effects, "stages": stages}))
}

fn text<'a>(payload: &'a Value, field: &str) -> Result<&'a str, ServiceError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or_else(|| ServiceError::new("PAYLOAD_INVALID", format!("{field} 必填")))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/'))
        || path.starts_with(r"\\")
}

fn process_scope(payload: &Value) -> Result<Vec<String>, ServiceError> {
    let items = payload.get("processes").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut scope: Vec<String> = Vec::new();
    for item in items {
        let path = item.as_str().ok_or_else(|| ServiceError::new("PROCESS_SCOPE_INVALID", "进程必须是绝对程序路径"))?;
        if !is_absolute_windows_path(path) || path.contains("..") {
            return Err(ServiceError::new("PROCESS_SCOPE_INVALID", "进程必须是绝对程序路径"));
        }
        if !scope.iter().any(|existing| existing.eq_ignore_ascii_case(path)) {
            scope.push(path.to_string());
        }
    }
    if scope.is_empty() {
        return Err(ServiceError::new("EMPTY_PROCESS_SCOPE", "保护范围里没有批准的程序"));
    }
    if scope.len() > MAX_PROCESSES {
        return Err(ServiceError::new("PROCESS_SCOPE_INVALID", "保护范围超过上限"));
    }
    Ok(scope)
}

/// 保护请求里的回环策略。缺失按空清单（回环全拦）；给了就逐项核对，任何一项不合法整个请求拒绝，不挑着装。
fn loopback_policy(payload: &Value, scope: &[String]) -> Result<LoopbackPolicy, ServiceError> {
    let invalid = |reason: &str| ServiceError::new("LOOPBACK_POLICY_INVALID", reason);
    let policy = match payload.get("loopback_policy") {
        None | Some(Value::Null) => return Ok(LoopbackPolicy::new(None, Vec::new())),
        Some(Value::Object(map)) => map,
        Some(_) => return Err(invalid("loopback_policy 必须是对象")),
    };
    let template_version = match policy.get("template_version") {
        None | Some(Value::Null) => None,
        Some(Value::String(version)) if !version.is_empty() && version.len() <= 128 => Some(version.clone()),
        Some(_) => return Err(invalid("template_version 必须是不超过 128 字符的非空文本")),
    };
    let items = match policy.get("endpoints") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => return Err(invalid("endpoints 必须是数组")),
    };
    if items.len() > MAX_LOOPBACK_ENDPOINTS {
        return Err(invalid("回环端点超过上限"));
    }
    let mut endpoints: Vec<LoopbackEndpoint> = Vec::new();
    for item in items {
        let map = item.as_object().ok_or_else(|| invalid("回环端点必须是对象"))?;
        if map.keys().any(|key| !LOOPBACK_ENDPOINT_FIELDS.contains(&key.as_str())) {
            return Err(invalid("回环端点含不认识的字段"));
        }
        let field = |name: &str| map.get(name).and_then(Value::as_str).unwrap_or_default().to_string();
        let port = map
            .get("port")
            .and_then(Value::as_u64)
            .filter(|port| (1..=65_535).contains(port))
            .ok_or_else(|| invalid("端口必须是 1—65535 的单个整数，不接受范围或通配"))?;
        let endpoint = LoopbackEndpoint {
            source_process_path: field("source_process_path"),
            transport: field("transport"),
            address: field("address"),
            port: port as u16,
            purpose: field("purpose"),
        };
        if !scope.iter().any(|path| path.eq_ignore_ascii_case(&endpoint.source_process_path)) {
            return Err(invalid("回环端点的发起程序不在本次批准程序里"));
        }
        if endpoint.transport != "tcp" && endpoint.transport != "udp" {
            return Err(invalid("协议只能是 tcp 或 udp"));
        }
        if loopback_address(&endpoint.address).is_none() {
            return Err(invalid("地址只能是单个精确回环地址（127.x.y.z 或 ::1）"));
        }
        let purpose_ok = endpoint.purpose.len() <= 64
            && endpoint.purpose.bytes().next().map(|first| first.is_ascii_lowercase()).unwrap_or(false)
            && endpoint.purpose.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !purpose_ok {
            return Err(invalid("用途必须是小写标识"));
        }
        let duplicate = endpoints.iter().any(|existing| {
            existing.source_process_path.eq_ignore_ascii_case(&endpoint.source_process_path)
                && existing.transport == endpoint.transport
                && existing.address == endpoint.address
                && existing.port == endpoint.port
        });
        if duplicate {
            return Err(invalid("回环端点重复"));
        }
        endpoints.push(endpoint);
    }
    Ok(LoopbackPolicy::new(template_version, endpoints))
}

fn file_name_of(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_ascii_lowercase()
}

fn clear_active(state: &mut RuntimeState) {
    state.active_config_sha256 = None;
    state.active_facts = None;
    state.plan_ref = None;
    state.plan_version = None;
    state.assignment_version = None;
}

fn pending_for(command: ServiceCommand, envelope: &Envelope, digest: &str, payload: &Value, now: i64) -> PendingOperation {
    let field = |name: &str| payload.get(name).and_then(Value::as_str).map(str::to_string);
    PendingOperation {
        operation_id: envelope.operation_id.clone(),
        command: command.name().to_string(),
        request_digest: digest.to_string(),
        environment_ref: field("environment_ref"),
        action: field("action"),
        processes: payload
            .get("processes")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default(),
        session_ref: field("session_ref"),
        started_at_ms: now,
        reconciled_at_ms: None,
    }
}

/// 上一实例留下的意图：结果没有落盘。不重放，只把状态往保守一侧对齐，真实结论交给启动恢复的实际回读。
fn reconcile_pending(state: &mut RuntimeState, now: i64) {
    let Some(mut pending) = state.pending.take() else {
        return;
    };
    pending.reconciled_at_ms = Some(now);
    match (pending.command.as_str(), pending.action.as_deref(), pending.environment_ref.clone()) {
        ("EnsureProtection", Some("block_new"), Some(environment_ref)) => {
            let record = state.protection.entry(environment_ref).or_default();
            for path in &pending.processes {
                if !record.processes.iter().any(|existing| existing.eq_ignore_ascii_case(path)) {
                    record.processes.push(path.clone());
                }
            }
            record.requested = true;
            record.effective = false;
            record.code = Some("RECONCILE_PENDING".to_string());
            // 没落盘的请求可能缩减了回环策略；两份策略的交集至少不比空清单宽，按空清单恢复，等客户端按当前模板重新请求。
            record.loopback = LoopbackPolicy::default();
        }
        ("EnsureProtection", _, Some(environment_ref)) => {
            if let Some(record) = state.protection.get_mut(&environment_ref) {
                record.requested = true;
                record.effective = false;
                record.code = Some("RELEASE_INDETERMINATE".to_string());
            }
        }
        ("OpenEmergencyRoute", _, _) | ("CloseEmergencyRoute", _, _) => {
            if let Some(session) = pending.session_ref.as_ref().and_then(|reference| state.emergency.get_mut(reference)) {
                session.close_indeterminate = true;
            }
        }
        _ => {}
    }
    if matches!(
        pending.command.as_str(),
        "ApplyConfig" | "StartCore" | "RestoreLastValid" | "StopCoreForMaintenance" | "OpenEmergencyRoute" | "CloseEmergencyRoute"
    ) {
        clear_active(state);
        state.verification = Verification { status: "UNKNOWN".to_string(), ..Verification::default() };
        state.last_failure_code = Some("OPERATION_INDETERMINATE".to_string());
    }
    state.indeterminate.push(pending);
    let excess = state.indeterminate.len().saturating_sub(MAX_INDETERMINATE);
    state.indeterminate.drain(..excess);
}

/// 卸载时用户明确选择停止管理并恢复原网络：先把没落盘的意图按启动时的规则对账进待定历史（否则下次启动会把它对账成「已请求」），
/// 再把全部保护请求作废（`requested=false`、`effective=false`，标记 `UNINSTALL_REVOKED`）。批准程序清单、回环策略、配置、
/// last-valid 与回执都保留；重装后要等用户重新确认「启用监测与保护」才会再请求保护。返回作废前仍在请求的环境数。
pub fn revoke_protection_for_uninstall(state: &mut RuntimeState, now_ms: i64) -> usize {
    reconcile_pending(state, now_ms);
    let mut revoked = 0;
    for record in state.protection.values_mut() {
        if record.requested {
            revoked += 1;
        }
        record.requested = false;
        record.effective = false;
        record.checked_at_ms = now_ms;
        record.code = Some("UNINSTALL_REVOKED".to_string());
    }
    revoked
}

/// 卸载助手用：读出已保存的服务状态，作废保护请求后写回。没有状态文件就没有要作废的请求；读不出、解析不了或写不进都如实报错。
pub fn revoke_saved_protection(store: &dyn StateStore, now_ms: i64) -> Result<usize, ServiceError> {
    let Some(value) = store.load()? else {
        return Ok(0);
    };
    let mut state = serde_json::from_value::<RuntimeState>(value).map_err(|_| ServiceError::new("SERVICE_STATE_CORRUPT", "服务状态文件无法解析"))?;
    let revoked = revoke_protection_for_uninstall(&mut state, now_ms);
    let value = serde_json::to_value(&state).map_err(|_| ServiceError::new("SERVICE_STATE_UNWRITABLE", "服务状态无法序列化"))?;
    store.save(&value)?;
    Ok(revoked)
}

fn persist_failed(reply: &ServiceReply, side_effects: bool, error: &ServiceError, operation_id: &str) -> ServiceReply {
    let mut receipt = if reply.receipt.is_object() { reply.receipt.clone() } else { json!({}) };
    receipt["state_persisted"] = json!(false);
    receipt["state_error"] = json!(error.code);
    receipt["inner_ok"] = json!(reply.ok);
    receipt["inner_code"] = json!(reply.code);
    receipt["side_effects"] = json!(side_effects);
    receipt["recovery"] = json!({"status": "RECONCILE_ON_RESTART", "operation_id": operation_id});
    ServiceReply::failure(
        &ServiceError::new("STATE_PERSIST_FAILED", "改写已执行或已尝试，但服务状态没有落盘；服务重启后按实际回读对账，不重放"),
        receipt,
    )
}

pub struct NetworkService {
    backends: Backends,
    instance_id: String,
    started_at_ms: i64,
    state: Mutex<RuntimeState>,
    operation_lock: Mutex<()>,
}

impl NetworkService {
    pub fn open(backends: Backends) -> Result<NetworkService, ServiceError> {
        let mut state = match backends.state.load()? {
            Some(value) => serde_json::from_value::<RuntimeState>(value)
                .map_err(|_| ServiceError::new("SERVICE_STATE_CORRUPT", "服务状态文件无法解析"))?,
            None => RuntimeState { schema: 1, ..RuntimeState::default() },
        };
        let started_at_ms = backends.clock.now_ms();
        reconcile_pending(&mut state, started_at_ms);
        let instance_id = format!("svc-{}", random_hex(12)?);
        Ok(NetworkService { backends, instance_id, started_at_ms, state: Mutex::new(state), operation_lock: Mutex::new(()) })
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    fn now(&self) -> i64 {
        self.backends.clock.now_ms()
    }

    fn snapshot(&self) -> RuntimeState {
        self.state.lock().map(|guard| guard.clone()).unwrap_or_default()
    }

    fn update<T>(&self, work: impl FnOnce(&mut RuntimeState) -> T) -> Result<T, ServiceError> {
        let mut guard = self.state.lock().map_err(|_| ServiceError::new("SERVICE_STATE_UNAVAILABLE", "服务状态锁已损坏"))?;
        Ok(work(&mut guard))
    }

    fn persist(&self) -> Result<(), ServiceError> {
        let now = self.now();
        let value = self.update(|state| {
            state.updated_at_ms = now;
            serde_json::to_value(&*state)
        })?;
        let value = value.map_err(|_| ServiceError::new("SERVICE_STATE_UNWRITABLE", "服务状态无法序列化"))?;
        self.backends.state.save(&value)
    }

    /// 服务 pipe 的入口：先按 Windows 给出的客户端进程核对安装记录里的宿主，再走 `handle`。
    pub fn handle_peer(
        &self,
        command: ServiceCommand,
        request: &ServiceRequest,
        link_key: &[u8],
        policy: &PeerPolicy,
        peer: Option<&PeerProcess>,
    ) -> ServiceReply {
        if let Err(error) = authorize_peer(policy, command, peer) {
            return ServiceReply::rejected(&error);
        }
        self.handle(command, request, link_key)
    }

    /// 命令入口：先核对产品与协议，改写类命令再核对 envelope、做幂等重放判定，落意图后串行执行。
    pub fn handle(&self, command: ServiceCommand, request: &ServiceRequest, link_key: &[u8]) -> ServiceReply {
        if request.product_id != PRODUCT_APP_ID {
            return ServiceReply::rejected(&ServiceError::new("PRODUCT_IDENTITY_MISMATCH", "请求不是本产品宿主发出的"));
        }
        if request.protocol != PROTOCOL {
            return ServiceReply::rejected(&ServiceError::new("PROTOCOL_MISMATCH", "服务协议版本不一致"));
        }
        if !command.requires_envelope() {
            return match command {
                ServiceCommand::Handshake => ServiceReply::success(self.handshake()),
                ServiceCommand::ObserveRuntime => self.reply(self.observe(&request.payload)),
                ServiceCommand::ReadProtection => self.reply(self.read_protection(&request.payload)),
                _ => ServiceReply::rejected(&ServiceError::new("COMMAND_UNSUPPORTED", "未知命令")),
            };
        }
        let envelope = match &request.envelope {
            Some(envelope) => envelope,
            None => return ServiceReply::rejected(&ServiceError::new("AUTHORIZATION_REQUIRED", "改写类命令必须带宿主签发的授权")),
        };
        if let Err(error) = verify_envelope(link_key, envelope, command, &request.payload) {
            return ServiceReply::rejected(&error);
        }
        let _serial = match self.operation_lock.lock() {
            Ok(guard) => guard,
            Err(_) => return ServiceReply::rejected(&ServiceError::new("SERVICE_BUSY", "服务串行锁已损坏")),
        };
        let digest = sha256_hex(canonical_json(&json!({"command": command.name(), "payload": request.payload})).as_bytes());
        let snapshot = self.snapshot();
        if snapshot.indeterminate.iter().any(|item| item.operation_id == envelope.operation_id) {
            return ServiceReply::failure(
                &ServiceError::new("OPERATION_INDETERMINATE", "这次操作在上一个服务实例里没有落盘完成；先读实际状态，再用新的 operation 发起"),
                json!({"side_effects": Value::Null, "recovery": {"status": "RECONCILED_ON_RESTART"}}),
            );
        }
        if let Some(prior) = snapshot.operations.into_iter().find(|record| record.operation_id == envelope.operation_id) {
            if prior.request_digest != digest {
                return ServiceReply::rejected(&ServiceError::new("OPERATION_CONFLICT", "同一 operation 带了不同内容"));
            }
            let mut replay = prior.reply;
            if let Value::Object(map) = &mut replay.receipt {
                map.insert("replayed".to_string(), json!(true));
            }
            return replay;
        }
        let now = self.now();
        if envelope_expired(envelope, now) {
            return ServiceReply::rejected(&ServiceError::new("AUTHORIZATION_EXPIRED", "授权 envelope 已过期"));
        }
        let pending = pending_for(command, envelope, &digest, &request.payload, now);
        let _ = self.update(|state| state.pending = Some(pending));
        if let Err(error) = self.persist() {
            let _ = self.update(|state| state.pending = None);
            return ServiceReply::failure(
                &ServiceError::new("SERVICE_STATE_UNWRITABLE", "服务状态写不进磁盘，改写类命令在执行前拒绝"),
                json!({"side_effects": false, "state_error": error.code}),
            );
        }
        let reply = self.reply(self.execute(command, &request.payload));
        let side_effects = reply.receipt.get("side_effects").and_then(Value::as_bool).unwrap_or(false);
        let recorded = OperationRecord {
            operation_id: envelope.operation_id.clone(),
            command: command.name().to_string(),
            request_digest: digest,
            reply: reply.clone(),
            at_ms: self.now(),
        };
        let keep_record = reply.ok || side_effects;
        let _ = self.update(|state| {
            state.pending = None;
            if keep_record {
                state.operations.push(recorded);
                let excess = state.operations.len().saturating_sub(MAX_OPERATIONS);
                state.operations.drain(..excess);
            }
        });
        match self.persist() {
            Ok(()) => reply,
            Err(error) => {
                let wrapped = persist_failed(&reply, side_effects, &error, &envelope.operation_id);
                let stored = wrapped.clone();
                let operation_id = envelope.operation_id.clone();
                let _ = self.update(|state| {
                    if let Some(record) = state.operations.iter_mut().rev().find(|record| record.operation_id == operation_id) {
                        record.reply = stored;
                    }
                });
                wrapped
            }
        }
    }

    fn reply(&self, outcome: Outcome) -> ServiceReply {
        match outcome {
            Ok(receipt) => ServiceReply::success(receipt),
            Err((error, receipt)) => ServiceReply::failure(&error, receipt),
        }
    }

    fn execute(&self, command: ServiceCommand, payload: &Value) -> Outcome {
        match command {
            ServiceCommand::ValidateConfig => self.validate_config(payload),
            ServiceCommand::ApplyConfig => self.apply_config(payload),
            ServiceCommand::EnsureProtection => self.ensure_protection(payload),
            ServiceCommand::CloseManagedConnections => self.close_managed_connections(payload),
            ServiceCommand::StartCore => self.start_core(payload),
            ServiceCommand::StopCoreForMaintenance => self.stop_core_for_maintenance(payload),
            ServiceCommand::RestoreLastValid => self.restore_last_valid(payload),
            ServiceCommand::OpenEmergencyRoute => self.open_emergency_route(payload),
            ServiceCommand::CloseEmergencyRoute => self.close_emergency_route(payload),
            _ => Err(rejected(ServiceError::new("COMMAND_UNSUPPORTED", "该命令不经执行路径"))),
        }
    }

    pub fn handshake(&self) -> Value {
        json!({
            "product_id": PRODUCT_APP_ID,
            "protocol": PROTOCOL,
            "service_instance_id": self.instance_id,
            "service_version": crate::VERSION,
            "started_at_ms": self.started_at_ms,
            "core_binary_present": self.backends.core.binary_present(),
            "expected_kernel_version": KERNEL_VERSION,
        })
    }

    fn protection_scope(&self, state: &RuntimeState, environment_ref: &str) -> Vec<String> {
        state.protection.get(environment_ref).map(|record| record.processes.clone()).unwrap_or_default()
    }

    fn live_protection(&self, state: &RuntimeState, environment_ref: &str) -> (Option<ProtectionRecord>, ProtectionOutcome, bool) {
        let record = state.protection.get(environment_ref).cloned();
        let processes = record.as_ref().map(|item| item.processes.clone()).unwrap_or_default();
        if processes.is_empty() {
            return (record, ProtectionOutcome::default(), false);
        }
        let loopback = record.as_ref().map(|item| item.loopback.clone()).unwrap_or_default();
        let live = self.backends.protection.read(environment_ref, &processes, &loopback);
        let effective = record.as_ref().map(|item| item.requested).unwrap_or(false) && live.covers(&processes);
        (record, live, effective)
    }

    /// 受管路径的实际回读：只用本记录里的接口 LUID 核对 permit 是否还在并覆盖全部批准程序。
    fn managed_path_view(&self, state: &RuntimeState, environment_ref: &str) -> Value {
        let record = state.managed_path.get(environment_ref).cloned().unwrap_or_default();
        let processes = self.protection_scope(state, environment_ref);
        let live = match (record.interface_luid, processes.is_empty()) {
            (Some(luid), false) => Some(self.backends.protection.read_managed_path(environment_ref, &processes, luid)),
            _ => None,
        };
        let open = live.as_ref().map(|outcome| outcome.covers(&processes)).unwrap_or(false);
        let core = self.backends.core.status();
        let status = if open {
            "OPEN"
        } else if record.code.as_deref() == Some("MANAGED_PATH_REQUIRES_TUN") {
            "NO_TUN"
        } else {
            "CLOSED"
        };
        json!({
            "status": status,
            "open": open,
            "current": open && core.running && core.pid == record.core_pid && record.service_instance_id.as_deref() == Some(self.instance_id.as_str()),
            "interface": record.interface_alias,
            "missing": live.as_ref().map(|outcome| outcome.missing.clone()).unwrap_or_default(),
            "mismatched": live.as_ref().map(|outcome| outcome.mismatched.clone()).unwrap_or_default(),
            "code": record.code,
        })
    }

    /// 加载配置、停内核、回读失败或实例变化前先关受管路径；批准程序只剩阻断。
    fn close_managed_path(&self, environment_ref: &str) -> bool {
        let snapshot = self.snapshot();
        let processes = self.protection_scope(&snapshot, environment_ref);
        let luid = snapshot.managed_path.get(environment_ref).and_then(|record| record.interface_luid).unwrap_or(0);
        let closed = processes.is_empty() || {
            let outcome = self.backends.protection.close_managed_path(environment_ref, &processes);
            let live = self.backends.protection.read_managed_path(environment_ref, &processes, luid);
            outcome.code.is_none() && live.installed.is_empty() && live.mismatched.is_empty()
        };
        let now = self.now();
        let _ = self.update(|state| {
            if let Some(record) = state.managed_path.get_mut(environment_ref) {
                record.open = !closed;
                record.checked_at_ms = now;
                if !closed {
                    record.code = Some("MANAGED_PATH_CLOSE_UNCONFIRMED".to_string());
                }
            }
        });
        closed
    }

    /// 其余回读全部成立后才打开受管路径，接口只认本内核实例回读报告的 TUN 设备。
    fn open_managed_path(&self, environment_ref: &str, facts: &ManagedFacts, readback: &Readback, config_sha256: &str) -> Option<ReadbackCheck> {
        let now = self.now();
        if !facts.tun_enable {
            let _ = self.update(|state| {
                let record = state.managed_path.entry(environment_ref.to_string()).or_default();
                record.open = false;
                record.config_sha256 = Some(config_sha256.to_string());
                record.checked_at_ms = now;
                record.code = Some("MANAGED_PATH_REQUIRES_TUN".to_string());
            });
            return None;
        }
        let processes = self.protection_scope(&self.snapshot(), environment_ref);
        let alias = readback
            .general
            .get("tun")
            .and_then(|tun| tun.get("device"))
            .and_then(Value::as_str)
            .filter(|device| !device.is_empty())
            .map(str::to_string);
        let attempt: Result<u64, ServiceError> = match alias.as_deref() {
            None => Err(ServiceError::new("TUN_DEVICE_UNREPORTED", "内核回读没有报告 TUN 设备名，无法确定受管接口")),
            Some(device) => self.backends.protection.resolve_interface(device).and_then(|luid| {
                let opened = self.backends.protection.open_managed_path(environment_ref, &processes, luid);
                let live = self.backends.protection.read_managed_path(environment_ref, &processes, luid);
                if opened.code.is_none() && live.covers(&processes) {
                    Ok(luid)
                } else {
                    self.backends.protection.close_managed_path(environment_ref, &processes);
                    Err(ServiceError::new(opened.code.as_deref().unwrap_or("MANAGED_PATH_NOT_EFFECTIVE"), "受管路径没有覆盖全部批准程序"))
                }
            }),
        };
        let ok = attempt.is_ok();
        let code = attempt.as_ref().err().map(|error| error.code.clone());
        let luid = attempt.as_ref().ok().copied();
        let pid = readback.core.pid;
        let instance = self.instance_id.clone();
        let _ = self.update(|state| {
            let record = state.managed_path.entry(environment_ref.to_string()).or_default();
            record.open = ok;
            record.interface_alias = alias.clone();
            record.interface_luid = luid;
            record.core_pid = pid;
            record.service_instance_id = Some(instance);
            record.config_sha256 = Some(config_sha256.to_string());
            record.checked_at_ms = now;
            record.code = code.clone();
        });
        Some(ReadbackCheck {
            name: "managed_path".to_string(),
            ok,
            expected: json!({"interface": alias, "programs": processes.len()}),
            actual: json!({"open": ok, "code": code}),
        })
    }

    fn prepare_config(&self, payload: &Value, stages: &mut Map<String, Value>) -> Result<Prepared, ServiceError> {
        let environment_ref = text(payload, "environment_ref")?.to_string();
        let plan_ref = text(payload, "plan_ref")?.to_string();
        let plan_version = text(payload, "plan_version")?.to_string();
        let assignment_version = text(payload, "assignment_version")?.to_string();
        let expected = text(payload, "expected_config_sha256")?.to_string();
        let draft = text(payload, "draft_path")?;
        if !is_sha256(&expected) {
            return Err(ServiceError::new("PAYLOAD_INVALID", "expected_config_sha256 必须是小写 SHA-256"));
        }
        if !plan_version.starts_with(&format!("plan:{assignment_version}:")) {
            return Err(ServiceError::new("PLAN_VERSION_MISMATCH", "计划版本不属于这个分配版本"));
        }
        let root = self
            .backends
            .configs
            .approved_draft_root()
            .ok_or_else(|| ServiceError::new("DRAFT_ROOT_UNAPPROVED", "服务没有安装时批准的宿主草稿目录"))?;
        let draft_path = PathBuf::from(draft);
        let yaml_file = draft_path.extension().map(|ext| ext.eq_ignore_ascii_case("yaml")).unwrap_or(false);
        if !yaml_file || !is_within(&root, &draft_path) {
            stages.insert("downloaded".into(), json!({"status": "FAILED", "code": "DRAFT_PATH_REJECTED"}));
            return Err(ServiceError::new("DRAFT_PATH_REJECTED", "草稿不在批准的产品网络状态根下"));
        }
        let bytes = match self.backends.configs.read_draft(&draft_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                stages.insert("downloaded".into(), json!({"status": "FAILED", "code": error.code}));
                return Err(error);
            }
        };
        let sha256 = sha256_hex(&bytes);
        if sha256 != expected {
            stages.insert("downloaded".into(), json!({"status": "FAILED", "code": "CONFIG_DIGEST_MISMATCH"}));
            return Err(ServiceError::new("CONFIG_DIGEST_MISMATCH", "草稿内容与期望摘要不一致"));
        }
        stages.insert("downloaded".into(), json!({"status": "OK", "sha256": sha256, "bytes": bytes.len()}));

        let now = self.now();
        let cached = self
            .snapshot()
            .validated
            .into_iter()
            .find(|item| item.sha256 == sha256 && now - item.at_ms <= VALIDATION_REUSE_MS);
        if let (Some(cached), Some(path)) = (cached.clone(), self.backends.configs.stored_path(&sha256)) {
            stages.insert("validated".into(), json!({"status": "OK", "reused_at_ms": cached.at_ms, "rules": cached.facts.rules.len()}));
            return Ok(Prepared { environment_ref, plan_ref, plan_version, assignment_version, sha256, facts: cached.facts, config_path: path });
        }
        let facts = match std::str::from_utf8(&bytes).map_err(|_| ServiceError::new("CONFIG_INVALID", "受管配置不是 UTF-8")).and_then(inspect_managed_yaml) {
            Ok(facts) => facts,
            Err(error) => {
                stages.insert("validated".into(), json!({"status": "FAILED", "code": error.code, "step": "mapping"}));
                return Err(error);
            }
        };
        let config_path = match self.backends.configs.store(&sha256, &bytes) {
            Ok(path) => path,
            Err(error) => {
                stages.insert("validated".into(), json!({"status": "FAILED", "code": error.code, "step": "store"}));
                return Err(error);
            }
        };
        if let Err(error) = self.backends.validator.validate(&config_path) {
            stages.insert("validated".into(), json!({"status": "FAILED", "code": error.code, "step": "kernel"}));
            return Err(error);
        }
        stages.insert("validated".into(), json!({"status": "OK", "rules": facts.rules.len(), "kernel_validated": true}));
        let record = ValidatedConfig { sha256: sha256.clone(), facts: facts.clone(), at_ms: now };
        let _ = self.update(|state| {
            state.validated.retain(|item| item.sha256 != record.sha256);
            state.validated.push(record);
            let excess = state.validated.len().saturating_sub(MAX_VALIDATED);
            state.validated.drain(..excess);
        });
        Ok(Prepared { environment_ref, plan_ref, plan_version, assignment_version, sha256, facts, config_path })
    }

    fn validate_config(&self, payload: &Value) -> Outcome {
        let mut stages = Map::new();
        match self.prepare_config(payload, &mut stages) {
            Ok(prepared) => Ok(json!({
                "command": "ValidateConfig",
                "stages": stages,
                "config_sha256": prepared.sha256,
                "rules": prepared.facts.rules.len(),
                "side_effects": false,
            })),
            Err(error) => Err(with_stages(error, &stages, false)),
        }
    }

    /// 内核接口实际回读；读不到的一项不补期望值。同时核对回读前后是同一个内核进程。
    fn readback(&self, facts: &ManagedFacts, pid_before: Option<u32>) -> Readback {
        let controller = &self.backends.controller;
        let version = controller.version().ok().and_then(|body| body.get("version").cloned()).unwrap_or(Value::Null);
        let general = controller.general().unwrap_or(Value::Null);
        let rules = controller.rules().unwrap_or(Value::Null);
        let proxies = controller.proxies().unwrap_or(Value::Null);
        let mut checks = compare_readback(facts, &version, &general, &rules, &proxies);
        let after = self.backends.core.status();
        checks.push(ReadbackCheck {
            name: "core_instance".to_string(),
            ok: after.running && pid_before.is_some() && after.pid == pid_before,
            expected: json!(pid_before),
            actual: json!(after.pid),
        });
        Readback { checks, core: after, kernel_version: version.as_str().map(str::to_string), general }
    }

    fn record_verification(&self, sha256: &str, checks: Vec<ReadbackCheck>, core: &CoreStatus, kernel_version: Option<String>) -> bool {
        let verified = !checks.is_empty() && checks.iter().all(|item| item.ok);
        let verification = Verification {
            status: if verified { "VERIFIED" } else { "VERIFY_FAILED" }.to_string(),
            checks,
            checked_at_ms: Some(self.now()),
            service_instance_id: Some(self.instance_id.clone()),
            core_pid: core.pid,
            kernel_version,
            config_sha256: Some(sha256.to_string()),
        };
        let _ = self.update(|state| {
            state.verification = verification;
            state.last_failure_code = if verified { None } else { Some("VERIFY_FAILED".to_string()) };
        });
        verified
    }

    /// 已加载配置的完整核验：内核回读 + 受管路径。任何一项不成立都保持受管路径关闭。
    fn verify_loaded(&self, environment_ref: &str, sha256: &str, facts: &ManagedFacts, pid_before: Option<u32>) -> Verified {
        let mut readback = self.readback(facts, pid_before);
        if readback.checks.iter().all(|item| item.ok) {
            if let Some(check) = self.open_managed_path(environment_ref, facts, &readback, sha256) {
                readback.checks.push(check);
            }
        } else if facts.tun_enable {
            readback.checks.push(ReadbackCheck {
                name: "managed_path".to_string(),
                ok: false,
                expected: json!("OPEN"),
                actual: json!("NOT_OPENED_READBACK_FAILED"),
            });
        }
        let verified = self.record_verification(sha256, readback.checks.clone(), &readback.core, readback.kernel_version.clone());
        if !verified {
            self.close_managed_path(environment_ref);
        }
        Verified { verified, checks: readback.checks, core: readback.core, kernel_version: readback.kernel_version }
    }

    fn commit_restored(&self, last: &LastValid, verified: bool) {
        let _ = self.update(|state| {
            state.environment_ref = Some(last.environment_ref.clone());
            state.expected_config_sha256 = Some(last.config_sha256.clone());
            state.core_should_run = true;
            state.emergency_config = None;
            if verified {
                state.active_config_sha256 = Some(last.config_sha256.clone());
                state.active_facts = Some(last.facts.clone());
                state.plan_ref = Some(last.plan_ref.clone());
                state.plan_version = Some(last.plan_version.clone());
                state.assignment_version = Some(last.assignment_version.clone());
            } else {
                clear_active(state);
            }
        });
    }

    fn apply_config(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?.to_string();
        let mut stages = Map::new();
        let snapshot = self.snapshot();
        let (_, live, protected) = self.live_protection(&snapshot, &environment_ref);
        stages.insert(
            "protection".into(),
            json!({"status": if protected { "OK" } else { "FAILED" }, "effective": protected, "missing": live.missing, "mismatched": live.mismatched}),
        );
        if !protected {
            return Err(with_stages(ServiceError::new("PROTECTION_NOT_READY", "应用受管配置前必须先确认本环境保护已生效"), &stages, false));
        }
        let prepared = match self.prepare_config(payload, &mut stages) {
            Ok(prepared) => prepared,
            Err(error) => return Err(with_stages(error, &stages, false)),
        };
        let before = self.backends.core.status();
        if snapshot.environment_ref.as_deref().map(|current| current != prepared.environment_ref).unwrap_or(false) && before.running {
            return Err(with_stages(ServiceError::new("ENVIRONMENT_MISMATCH", "内核正在运行另一个环境的受管配置"), &stages, false));
        }
        let previous_current = self.verification_current(&snapshot, &before);
        let path_closed = self.close_managed_path(&prepared.environment_ref);
        stages.insert("managed_path_closed".into(), json!({"status": if path_closed { "OK" } else { "UNCONFIRMED" }}));

        let mut side_effects = false;
        if before.running {
            stages.insert("core".into(), json!({"status": "RUNNING", "pid": before.pid}));
        } else {
            if !self.backends.core.binary_present() {
                stages.insert("core".into(), json!({"status": "FAILED", "code": "CORE_BINARY_MISSING"}));
                return Err(with_stages(ServiceError::new("CORE_BINARY_MISSING", "固定版本内核程序不在产品目录"), &stages, false));
            }
            match self.backends.core.start(&prepared.config_path) {
                Ok(started) => {
                    side_effects = true;
                    stages.insert("core".into(), json!({"status": "STARTED", "pid": started.pid}));
                }
                Err(error) => {
                    stages.insert("core".into(), json!({"status": "FAILED", "code": error.code}));
                    let _ = self.update(|state| state.last_failure_code = Some(error.code.clone()));
                    return Err(with_stages(error, &stages, false));
                }
            }
        }
        let pid_before = self.backends.core.status().pid;
        match self.backends.controller.load_config(&prepared.config_path) {
            Ok(204) => {
                side_effects = true;
                stages.insert("applied".into(), json!({"status": "ACCEPTED", "http_status": 204, "note": "204 只表示内核接受，不是生效证明"}));
            }
            Ok(status) => {
                stages.insert("applied".into(), json!({"status": "FAILED", "code": "LOAD_FAILED", "http_status": status}));
                // 内核拒绝时仍在跑加载前的配置：加载前的回读仍属于当前实例，才重新回读它并恢复受管路径。
                let kept = match (previous_current && before.running, snapshot.active_config_sha256.clone(), snapshot.active_facts.clone()) {
                    (true, Some(sha), Some(facts)) => self.verify_loaded(&prepared.environment_ref, &sha, &facts, before.pid).verified,
                    _ => false,
                };
                let _ = self.update(|state| {
                    state.expected_config_sha256 = Some(prepared.sha256.clone());
                    state.last_failure_code = Some("LOAD_FAILED".to_string());
                    if !kept {
                        clear_active(state);
                    }
                });
                stages.insert("previous_active".into(), json!({"kept": kept}));
                return Err(with_stages(ServiceError::new("LOAD_FAILED", "内核拒绝加载受管配置"), &stages, side_effects));
            }
            Err(error) => {
                stages.insert("applied".into(), json!({"status": "UNKNOWN", "code": error.code}));
                let _ = self.update(|state| {
                    state.expected_config_sha256 = Some(prepared.sha256.clone());
                    clear_active(state);
                    state.verification = Verification { status: "UNKNOWN".to_string(), ..Verification::default() };
                    state.last_failure_code = Some(error.code.clone());
                });
                return Err(with_stages(error, &stages, true));
            }
        }

        let verified = self.verify_loaded(&prepared.environment_ref, &prepared.sha256, &prepared.facts, pid_before);
        stages.insert(
            "verified".into(),
            json!({"status": if verified.verified { "VERIFIED" } else { "VERIFY_FAILED" }, "checks": verified.checks}),
        );
        let emergency = !prepared.facts.emergency_processes.is_empty();
        let now = self.now();
        let previous_last_valid = snapshot.last_valid.as_ref().map(|item| item.config_sha256.clone());
        let _ = self.update(|state| {
            state.environment_ref = Some(prepared.environment_ref.clone());
            state.expected_config_sha256 = Some(prepared.sha256.clone());
            if verified.verified {
                state.core_should_run = true;
                state.active_config_sha256 = Some(prepared.sha256.clone());
                state.active_facts = Some(prepared.facts.clone());
                state.plan_ref = Some(prepared.plan_ref.clone());
                state.plan_version = Some(prepared.plan_version.clone());
                state.assignment_version = Some(prepared.assignment_version.clone());
                let record = LastValid {
                    config_sha256: prepared.sha256.clone(),
                    environment_ref: prepared.environment_ref.clone(),
                    plan_ref: prepared.plan_ref.clone(),
                    plan_version: prepared.plan_version.clone(),
                    assignment_version: prepared.assignment_version.clone(),
                    facts: prepared.facts.clone(),
                    verified_at_ms: now,
                };
                if emergency {
                    state.emergency_config = Some(record);
                } else {
                    state.last_valid = Some(record);
                    state.emergency_config = None;
                }
            } else {
                clear_active(state);
            }
        });
        if verified.verified && !emergency {
            self.backends.core.set_restart_config(&prepared.config_path);
        }
        let state = self.snapshot();
        let receipt = json!({
            "command": "ApplyConfig",
            "overall": if verified.verified { "VERIFIED" } else { "VERIFY_FAILED" },
            "config_class": if emergency { "EMERGENCY_TEMPORARY" } else { "BASELINE" },
            "stages": stages,
            "environment_ref": prepared.environment_ref,
            "plan_ref": prepared.plan_ref,
            "plan_version": prepared.plan_version,
            "assignment_version": prepared.assignment_version,
            "expected_config_sha256": prepared.sha256,
            "active_config_sha256": state.active_config_sha256,
            "last_valid_config_ref": state.last_valid.as_ref().map(|item| item.config_sha256.clone()),
            "emergency_config_ref": state.emergency_config.as_ref().map(|item| item.config_sha256.clone()),
            "managed_path": self.managed_path_view(&state, &prepared.environment_ref),
            "service_instance_id": self.instance_id,
            "core_pid": verified.core.pid,
            "core_version": verified.kernel_version,
            "requires_restore": !verified.verified && previous_last_valid.map(|sha| sha != prepared.sha256).unwrap_or(false),
            "side_effects": true,
        });
        if verified.verified {
            Ok(receipt)
        } else {
            Err((ServiceError::new("VERIFY_FAILED", "实际回读与受管配置不一致，active 置空，last-valid 未更新"), receipt))
        }
    }

    fn ensure_protection(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?.to_string();
        let action = text(payload, "action").map_err(rejected)?;
        let reason_code = text(payload, "reason_code").map_err(rejected)?.to_string();
        let requested = process_scope(payload).map_err(rejected)?;
        match action {
            "block_new" => {
                let loopback = loopback_policy(payload, &requested).map_err(rejected)?;
                self.block_new(&environment_ref, requested, loopback, &reason_code)
            }
            "release_owned" => self.release_owned(&environment_ref, &reason_code),
            _ => Err(rejected(ServiceError::new("PROTECTION_ACTION_UNSUPPORTED", "保护动作只接受 block_new 或 release_owned"))),
        }
    }

    /// 程序范围只增不减；回环策略按本次请求整份替换，缩减的端点在 ensure 里删掉。
    fn block_new(&self, environment_ref: &str, requested: Vec<String>, loopback: LoopbackPolicy, reason_code: &str) -> Outcome {
        let snapshot = self.snapshot();
        let mut processes = self.protection_scope(&snapshot, environment_ref);
        for path in requested {
            if !processes.iter().any(|existing| existing.eq_ignore_ascii_case(&path)) {
                processes.push(path);
            }
        }
        let outcome = self.backends.protection.ensure(environment_ref, &processes, &loopback);
        let live = self.backends.protection.read(environment_ref, &processes, &loopback);
        let effective = live.covers(&processes);
        let code = if effective { None } else { Some(outcome.code.clone().unwrap_or_else(|| "PROTECTION_NOT_EFFECTIVE".to_string())) };
        let now = self.now();
        let record = ProtectionRecord {
            processes: processes.clone(),
            requested: true,
            effective,
            checked_at_ms: now,
            code: code.clone(),
            loopback: loopback.clone(),
        };
        let _ = self.update(|state| {
            state.protection.insert(environment_ref.to_string(), record);
        });
        let os_readback = if effective {
            "PRESENT"
        } else if live.installed.is_empty() {
            "MISSING"
        } else {
            "PARTIAL"
        };
        let receipt = json!({
            "command": "EnsureProtection",
            "action": "block_new",
            "environment_ref": environment_ref,
            "reason_code": reason_code,
            "requested": true,
            "effective": effective,
            "new_connections_restricted": effective,
            "os_readback": os_readback,
            "processes": processes,
            "loopback_policy": loopback.view(),
            "installed": live.installed,
            "missing": live.missing,
            "mismatched": live.mismatched,
            "residual": live.residual,
            "created": outcome.created,
            "removed": outcome.removed,
            "rolled_back": outcome.rolled_back,
            "native_status": outcome.native_status,
            "checked_at_ms": now,
            "side_effects": true,
        });
        match code {
            None => Ok(receipt),
            Some(code) => Err((ServiceError::new(&code, "本产品过滤器没有覆盖全部批准程序"), receipt)),
        }
    }

    /// 显式停止管理：先证明受保护业务已暂停，再关受管路径、停内核，最后只撤本产品在该环境拥有的过滤器。
    fn release_owned(&self, environment_ref: &str, reason_code: &str) -> Outcome {
        let snapshot = self.snapshot();
        let record = snapshot
            .protection
            .get(environment_ref)
            .cloned()
            .ok_or_else(|| rejected(ServiceError::new("PROTECTION_RECORD_MISSING", "这个环境没有本产品的保护记录")))?;
        let running = self.backends.processes.running(&record.processes).map_err(rejected)?;
        if !running.is_empty() {
            return Err((
                ServiceError::new("PROTECTED_BUSINESS_RUNNING", "受保护程序仍在运行，不能撤保护"),
                json!({"side_effects": false, "running": running}),
            ));
        }
        self.close_managed_path(environment_ref);
        let mut core_stopped = false;
        if self.backends.core.status().running {
            if let Err(error) = self.backends.core.stop() {
                return Err((error, json!({"side_effects": true, "business_paused": true, "core_stopped": false})));
            }
            core_stopped = true;
        }
        let outcome = self.backends.protection.release(environment_ref, &record.processes);
        let live = self.backends.protection.read(environment_ref, &record.processes, &LoopbackPolicy::default());
        let path_live = self.backends.protection.read_managed_path(environment_ref, &record.processes, 0);
        let released = live.installed.is_empty()
            && live.mismatched.is_empty()
            && live.residual.is_empty()
            && path_live.installed.is_empty()
            && path_live.mismatched.is_empty();
        let now = self.now();
        let _ = self.update(|state| {
            state.core_should_run = false;
            if core_stopped {
                clear_active(state);
                state.emergency_config = None;
                state.verification = Verification { status: "NOT_RUN".to_string(), ..Verification::default() };
            }
            state.protection.insert(
                environment_ref.to_string(),
                ProtectionRecord {
                    processes: record.processes.clone(),
                    requested: !released,
                    effective: live.covers(&record.processes),
                    checked_at_ms: now,
                    code: outcome.code.clone(),
                    loopback: record.loopback.clone(),
                },
            );
        });
        let receipt = json!({
            "command": "EnsureProtection",
            "action": "release_owned",
            "environment_ref": environment_ref,
            "reason_code": reason_code,
            "business_paused": true,
            "core_stopped": core_stopped,
            "released": released,
            "removed": outcome.removed,
            "remaining": live.installed,
            "remaining_mismatched": live.mismatched,
            "remaining_residual": live.residual,
            "side_effects": true,
        });
        if released {
            Ok(receipt)
        } else {
            Err((ServiceError::new("PROTECTION_RELEASE_INCOMPLETE", "仍有本产品过滤器没有撤掉"), receipt))
        }
    }

    fn read_protection(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?;
        let snapshot = self.snapshot();
        let (record, live, effective) = self.live_protection(&snapshot, environment_ref);
        Ok(json!({
            "environment_ref": environment_ref,
            "requested": record.as_ref().map(|item| item.requested).unwrap_or(false),
            "effective": effective,
            "new_connections_restricted": effective,
            "processes": record.as_ref().map(|item| item.processes.clone()).unwrap_or_default(),
            "loopback_policy": record.as_ref().map(|item| item.loopback.view()).unwrap_or(Value::Null),
            "installed": live.installed,
            "missing": live.missing,
            "mismatched": live.mismatched,
            "residual": live.residual,
            "managed_path": self.managed_path_view(&snapshot, environment_ref),
            "checked_at_ms": self.now(),
            "side_effects": false,
        }))
    }

    fn close_managed_connections(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?;
        let reason_code = text(payload, "reason_code").map_err(rejected)?;
        let snapshot = self.snapshot();
        let (_, _, effective) = self.live_protection(&snapshot, environment_ref);
        if !effective {
            return Err((
                ServiceError::new("PROTECTION_NOT_EFFECTIVE", "新连接阻断未确认前不关闭既有连接，关闭连接不能替代保护"),
                json!({"side_effects": false, "new_connections_restricted": false, "closed_existing": false}),
            ));
        }
        if !self.backends.core.status().running {
            return Err((
                ServiceError::new("CORE_NOT_RUNNING", "内核没有运行，没有受管连接可关"),
                json!({"side_effects": false, "new_connections_restricted": true, "closed_existing": false}),
            ));
        }
        match self.backends.controller.close_connections() {
            Ok(204) => Ok(json!({
                "command": "CloseManagedConnections",
                "reason_code": reason_code,
                "closed_existing": true,
                "http_status": 204,
                "new_connections_restricted": true,
                "side_effects": true,
            })),
            Ok(status) => Err((
                ServiceError::new("CLOSE_CONNECTIONS_FAILED", "内核没有确认关闭既有连接"),
                json!({"closed_existing": false, "http_status": status, "new_connections_restricted": true, "side_effects": true}),
            )),
            Err(error) => Err((error, json!({"closed_existing": false, "new_connections_restricted": true, "side_effects": true}))),
        }
    }

    fn last_valid_for(&self, snapshot: &RuntimeState, environment_ref: &str) -> Result<(LastValid, PathBuf), (ServiceError, Value)> {
        let last = snapshot
            .last_valid
            .clone()
            .filter(|item| item.environment_ref == environment_ref)
            .ok_or_else(|| rejected(ServiceError::new("LAST_VALID_MISSING", "这个环境没有经回读确认的 last-valid 配置")))?;
        let path = self
            .backends
            .configs
            .stored_path(&last.config_sha256)
            .ok_or_else(|| rejected(ServiceError::new("LAST_VALID_UNAVAILABLE", "last-valid 配置文件已不在服务目录")))?;
        Ok((last, path))
    }

    fn start_core(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?;
        let snapshot = self.snapshot();
        let (last, path) = self.last_valid_for(&snapshot, environment_ref)?;
        let (_, _, effective) = self.live_protection(&snapshot, environment_ref);
        if !effective {
            return Err(rejected(ServiceError::new("PROTECTION_NOT_READY", "启动内核前必须先确认保护已生效")));
        }
        let core = self.backends.core.status();
        if core.running {
            let readback = if self.verification_current(&snapshot, &core) { snapshot.verification.status.clone() } else { "STALE_INSTANCE".to_string() };
            return Ok(json!({"command": "StartCore", "already_running": true, "readback": readback, "side_effects": false}));
        }
        if !self.backends.core.binary_present() {
            return Err(rejected(ServiceError::new("CORE_BINARY_MISSING", "固定版本内核程序不在产品目录")));
        }
        self.close_managed_path(environment_ref);
        let started = self.backends.core.start(&path).map_err(rejected)?;
        let verified = self.verify_loaded(environment_ref, &last.config_sha256, &last.facts, started.pid);
        self.commit_restored(&last, verified.verified);
        self.backends.core.set_restart_config(&path);
        let state = self.snapshot();
        let receipt = json!({
            "command": "StartCore",
            "started": true,
            "core_pid": verified.core.pid,
            "config_ref": last.config_sha256,
            "readback": if verified.verified { "VERIFIED" } else { "VERIFY_FAILED" },
            "checks": verified.checks,
            "managed_path": self.managed_path_view(&state, environment_ref),
            "requires_business_recheck": true,
            "side_effects": true,
        });
        if verified.verified {
            Ok(receipt)
        } else {
            Err((ServiceError::new("VERIFY_FAILED", "内核已启动但实际回读与 last-valid 不一致"), receipt))
        }
    }

    /// 维护停内核的服务端门槛：先实际回读保护，未覆盖全部批准程序就不停；停之前先关受管路径。
    fn stop_core_for_maintenance(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?;
        let maintenance_ref = text(payload, "maintenance_ref").map_err(rejected)?;
        let snapshot = self.snapshot();
        let (record, live, effective) = self.live_protection(&snapshot, environment_ref);
        if !effective {
            return Err((
                ServiceError::new("PROTECTION_NOT_EFFECTIVE", "保护没有覆盖全部批准程序，维护不停止内核"),
                json!({
                    "command": "StopCoreForMaintenance",
                    "maintenance_ref": maintenance_ref,
                    "core_stopped": false,
                    "protection_retained": false,
                    "protection_requested": record.map(|item| item.requested).unwrap_or(false),
                    "missing": live.missing,
                    "mismatched": live.mismatched,
                    "side_effects": false,
                }),
            ));
        }
        let path_closed = self.close_managed_path(environment_ref);
        if let Err(error) = self.backends.core.stop() {
            return Err((
                error,
                json!({"command": "StopCoreForMaintenance", "maintenance_ref": maintenance_ref, "core_stopped": false, "protection_retained": true, "managed_path_closed": path_closed, "side_effects": true}),
            ));
        }
        let _ = self.update(|state| {
            state.core_should_run = false;
            clear_active(state);
            state.emergency_config = None;
            state.verification = Verification { status: "NOT_RUN".to_string(), ..Verification::default() };
        });
        let (_, after, retained) = self.live_protection(&self.snapshot(), environment_ref);
        let receipt = json!({
            "command": "StopCoreForMaintenance",
            "maintenance_ref": maintenance_ref,
            "core_stopped": true,
            "protection_retained": retained,
            "managed_path_closed": path_closed,
            "missing": after.missing,
            "side_effects": true,
        });
        if retained {
            Ok(receipt)
        } else {
            Err((ServiceError::new("PROTECTION_LOST_AFTER_STOP", "内核已停，但停后回读保护不完整"), receipt))
        }
    }

    fn restore_last_valid(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?.to_string();
        let reason_code = text(payload, "reason_code").map_err(rejected)?.to_string();
        self.restore_inner(&environment_ref, &reason_code)
    }

    /// 保护先恢复，再关受管路径、加载 last-valid 并回读；是否放行业务仍由客户端按当前分配复核。
    fn restore_inner(&self, environment_ref: &str, reason_code: &str) -> Outcome {
        let snapshot = self.snapshot();
        let (last, path) = self.last_valid_for(&snapshot, environment_ref)?;
        let record = snapshot.protection.get(environment_ref).cloned().unwrap_or_default();
        if !record.requested || record.processes.is_empty() {
            return Err(rejected(ServiceError::new("PROTECTION_NOT_READY", "没有可恢复的保护范围，不加载受管配置")));
        }
        self.backends.protection.ensure(environment_ref, &record.processes, &record.loopback);
        let live = self.backends.protection.read(environment_ref, &record.processes, &record.loopback);
        let effective = live.covers(&record.processes);
        let now = self.now();
        let _ = self.update(|state| {
            if let Some(item) = state.protection.get_mut(environment_ref) {
                item.effective = effective;
                item.checked_at_ms = now;
            }
        });
        if !effective {
            return Err((
                ServiceError::new("PROTECTION_NOT_READY", "保护没有恢复，不加载 last-valid"),
                json!({"side_effects": true, "protection_effective": false, "missing": live.missing, "mismatched": live.mismatched, "residual": live.residual}),
            ));
        }
        self.close_managed_path(environment_ref);
        let before = self.backends.core.status();
        let pid_before = if before.running {
            match self.backends.controller.load_config(&path) {
                Ok(204) => before.pid,
                Ok(status) => {
                    let _ = self.update(clear_active);
                    return Err((ServiceError::new("LOAD_FAILED", "内核拒绝重新加载 last-valid"), json!({"side_effects": true, "http_status": status})));
                }
                Err(error) => {
                    let _ = self.update(clear_active);
                    return Err((error, json!({"side_effects": true})));
                }
            }
        } else {
            if !self.backends.core.binary_present() {
                return Err((ServiceError::new("CORE_BINARY_MISSING", "固定版本内核程序不在产品目录"), json!({"side_effects": true})));
            }
            match self.backends.core.start(&path) {
                Ok(started) => started.pid,
                Err(error) => return Err((error, json!({"side_effects": true}))),
            }
        };
        let verified = self.verify_loaded(environment_ref, &last.config_sha256, &last.facts, pid_before);
        self.commit_restored(&last, verified.verified);
        self.backends.core.set_restart_config(&path);
        let state = self.snapshot();
        let receipt = json!({
            "command": "RestoreLastValid",
            "reason_code": reason_code,
            "protection_effective": true,
            "restored_config_ref": last.config_sha256,
            "plan_version": last.plan_version,
            "assignment_version": last.assignment_version,
            "readback": if verified.verified { "VERIFIED" } else { "VERIFY_FAILED" },
            "checks": verified.checks,
            "managed_path": self.managed_path_view(&state, environment_ref),
            "requires_business_recheck": true,
            "side_effects": true,
        });
        if verified.verified {
            Ok(receipt)
        } else {
            Err((ServiceError::new("VERIFY_FAILED", "last-valid 重新加载后回读不一致"), receipt))
        }
    }

    fn verification_current(&self, state: &RuntimeState, core: &CoreStatus) -> bool {
        state.verification.status == "VERIFIED"
            && state.verification.service_instance_id.as_deref() == Some(self.instance_id.as_str())
            && core.running
            && state.verification.core_pid == core.pid
    }

    fn open_emergency_route(&self, payload: &Value) -> Outcome {
        match payload.get("phase").and_then(Value::as_str).unwrap_or("prepare") {
            "prepare" => self.prepare_emergency_route(payload),
            "bind_browser" => self.bind_emergency_browser(payload),
            _ => Err(rejected(ServiceError::new("PAYLOAD_INVALID", "应急路径只接受 prepare 或 bind_browser"))),
        }
    }

    fn prepare_emergency_route(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?;
        let session_ref = text(payload, "session_ref").map_err(rejected)?;
        let browser = text(payload, "browser_process").map_err(rejected)?.to_ascii_lowercase();
        let expires_at_ms = payload
            .get("expires_at_ms")
            .and_then(Value::as_i64)
            .ok_or_else(|| rejected(ServiceError::new("PAYLOAD_INVALID", "expires_at_ms 必填")))?;
        if browser.contains(['\\', '/']) || !browser.ends_with(".exe") || browser.len() > 64 {
            return Err(rejected(ServiceError::new("EMERGENCY_HOST_INVALID", "应急浏览器只按程序名识别")));
        }
        let now = self.now();
        if expires_at_ms <= now {
            return Err(rejected(ServiceError::new("EMERGENCY_EXPIRED", "应急期限已过")));
        }
        let snapshot = self.snapshot();
        if snapshot.emergency.get(session_ref).map(|session| session.open).unwrap_or(false) {
            return Err(rejected(ServiceError::new("EMERGENCY_SESSION_EXISTS", "这个应急会话已经打开")));
        }
        let core = self.backends.core.status();
        if snapshot.environment_ref.as_deref() != Some(environment_ref) || !self.verification_current(&snapshot, &core) {
            return Err(rejected(ServiceError::new("CONFIG_NOT_VERIFIED", "当前受管配置没有在本服务实例上回读确认，不能建立应急路径")));
        }
        let facts = snapshot
            .active_facts
            .clone()
            .ok_or_else(|| rejected(ServiceError::new("CONFIG_NOT_VERIFIED", "没有已回读的受管配置事实")))?;
        if !facts.emergency_processes.iter().any(|item| item.eq_ignore_ascii_case(&browser)) {
            return Err(rejected(ServiceError::new("EMERGENCY_ROUTE_ABSENT", "已生效配置里没有这个浏览器的应急规则")));
        }
        let claude_constrained = matches!(facts.claude_member.as_deref(), Some("PROXY-A") | Some("REJECT"))
            && !facts.claude_processes.is_empty()
            && !facts.claude_processes.iter().any(|item| item.eq_ignore_ascii_case(&browser));
        if !claude_constrained {
            return Err(rejected(ServiceError::new("CLAUDE_CONSTRAINT_UNPROVEN", "不能证明 Claude 仍受固定 A 或阻断约束")));
        }
        let (record, _, effective) = self.live_protection(&snapshot, environment_ref);
        if record.map(|item| item.processes.iter().any(|path| file_name_of(path) == browser)).unwrap_or(false) {
            return Err(rejected(ServiceError::new("EMERGENCY_HOST_PROTECTED", "受保护程序不能充当应急浏览器")));
        }
        if !effective {
            return Err(rejected(ServiceError::new("PROTECTION_NOT_EFFECTIVE", "保护未生效时不建立应急路径")));
        }
        let marker = format!("process-name,{browser})");
        let scope: Vec<Value> = facts
            .rules
            .iter()
            .filter(|rule| rule.rule_type == "AND" && rule.payload.to_ascii_lowercase().contains(&marker))
            .map(|rule| json!({"payload": rule.payload, "outbound": rule.proxy}))
            .collect();
        let config_sha256 = snapshot.active_config_sha256.clone().unwrap_or_default();
        let session = EmergencyRecord {
            session_ref: session_ref.to_string(),
            environment_ref: environment_ref.to_string(),
            browser_process: browser.clone(),
            expires_at_ms,
            opened_at_ms: now,
            open: true,
            config_sha256: config_sha256.clone(),
            closed_at_ms: None,
            route_rules_present_after_close: None,
            browser: None,
            close_reason: None,
            close_code: None,
            browser_stopped: None,
            closed_safely: false,
            close_indeterminate: false,
        };
        let _ = self.update(|state| {
            state.emergency.insert(session_ref.to_string(), session);
        });
        Ok(json!({
            "command": "OpenEmergencyRoute",
            "phase": "prepare",
            "session_ref": session_ref,
            "browser_process": browser,
            "route_ready": true,
            "claude_constrained": true,
            "protection_effective": true,
            "emergency_scope": scope,
            "expires_at_ms": expires_at_ms,
            "expiry_enforced_by": "network_service",
            "config_ref": config_sha256,
            "side_effects": true,
        }))
    }

    /// 宿主启动浏览器后回报 PID；服务自己从系统读出创建时间与程序路径，之后结束浏览器只认这份身份。
    fn bind_emergency_browser(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?;
        let session_ref = text(payload, "session_ref").map_err(rejected)?;
        let pid = payload
            .get("browser_pid")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| rejected(ServiceError::new("PAYLOAD_INVALID", "browser_pid 必填")))?;
        let snapshot = self.snapshot();
        let session = snapshot
            .emergency
            .get(session_ref)
            .cloned()
            .filter(|session| session.open && session.environment_ref == environment_ref)
            .ok_or_else(|| rejected(ServiceError::new("EMERGENCY_SESSION_UNKNOWN", "没有这个打开的应急会话")))?;
        if session.browser.is_some() {
            return Err(rejected(ServiceError::new("EMERGENCY_BROWSER_ALREADY_BOUND", "这个会话已经绑定过浏览器进程")));
        }
        let identity = self
            .backends
            .processes
            .identify(pid)
            .map_err(rejected)?
            .ok_or_else(|| rejected(ServiceError::new("EMERGENCY_BROWSER_NOT_RUNNING", "回报的浏览器进程已经不在")))?;
        if file_name_of(&identity.image_path) != session.browser_process {
            return Err(rejected(ServiceError::new("EMERGENCY_BROWSER_MISMATCH", "回报的进程不是会话批准的浏览器程序")));
        }
        if identity.created_at_ms + BROWSER_START_SKEW_MS < session.opened_at_ms {
            return Err(rejected(ServiceError::new("EMERGENCY_BROWSER_MISMATCH", "回报的进程早于应急会话创建，不是这次启动的浏览器")));
        }
        let bound = identity.clone();
        let _ = self.update(|state| {
            if let Some(item) = state.emergency.get_mut(session_ref) {
                item.browser = Some(bound);
            }
        });
        Ok(json!({
            "command": "OpenEmergencyRoute",
            "phase": "bind_browser",
            "session_ref": session_ref,
            "bound": true,
            "browser_pid": identity.pid,
            "browser_program": file_name_of(&identity.image_path),
            "side_effects": true,
        }))
    }

    fn close_emergency_route(&self, payload: &Value) -> Outcome {
        let _environment_ref = text(payload, "environment_ref").map_err(rejected)?;
        let session_ref = text(payload, "session_ref").map_err(rejected)?;
        self.end_emergency(session_ref, "USER_CLOSED")
    }

    /// 让内核不再运行应急配置：能换回并回读基线就换回，否则停内核。受管路径在此之前已经关上。
    fn retire_emergency_config(&self, environment_ref: &str) -> Retired {
        let snapshot = self.snapshot();
        let core = self.backends.core.status();
        let active_is_emergency = match (&snapshot.emergency_config, &snapshot.active_config_sha256) {
            (Some(emergency), Some(active)) => &emergency.config_sha256 == active,
            _ => false,
        };
        if !active_is_emergency || !core.running {
            if !core.running || snapshot.emergency_config.is_some() && !active_is_emergency {
                let _ = self.update(|state| state.emergency_config = None);
            }
            return Retired { rules_present: false, core_stopped: false, baseline_restored: false, code: None };
        }
        self.close_managed_path(environment_ref);
        if let Ok((last, path)) = self.last_valid_for(&snapshot, environment_ref) {
            if let Ok(204) = self.backends.controller.load_config(&path) {
                let verified = self.verify_loaded(environment_ref, &last.config_sha256, &last.facts, core.pid);
                if verified.verified {
                    self.commit_restored(&last, true);
                    return Retired { rules_present: false, core_stopped: false, baseline_restored: true, code: None };
                }
            }
        }
        match self.backends.core.stop() {
            Ok(()) => {
                let _ = self.update(|state| {
                    clear_active(state);
                    state.emergency_config = None;
                    state.core_should_run = false;
                    state.verification = Verification { status: "NOT_RUN".to_string(), ..Verification::default() };
                });
                Retired { rules_present: false, core_stopped: true, baseline_restored: false, code: Some("EMERGENCY_BASELINE_UNAVAILABLE".to_string()) }
            }
            Err(error) => Retired { rules_present: true, core_stopped: false, baseline_restored: false, code: Some(error.code) },
        }
    }

    /// 结束应急会话（用户关闭或到期）：先关受管路径，再按核验过的身份结束浏览器，最后回收应急规则。
    /// 规则仍在或浏览器没能结束时不标成已关闭；浏览器身份从没绑定时会话关闭但不算安全关闭。
    fn end_emergency(&self, session_ref: &str, reason: &str) -> Outcome {
        let snapshot = self.snapshot();
        let session = snapshot
            .emergency
            .get(session_ref)
            .cloned()
            .ok_or_else(|| rejected(ServiceError::new("EMERGENCY_SESSION_UNKNOWN", "没有这个应急会话")))?;
        if !session.open {
            return Ok(json!({
                "command": "CloseEmergencyRoute",
                "session_ref": session_ref,
                "closed": true,
                "already_closed": true,
                "closed_safely": session.closed_safely,
                "route_rules_present": session.route_rules_present_after_close,
                "requires_config_reapply": false,
                "side_effects": false,
            }));
        }
        let environment_ref = session.environment_ref.clone();
        let emergency_active = match (&snapshot.emergency_config, &snapshot.active_config_sha256) {
            (Some(emergency), Some(active)) => &emergency.config_sha256 == active,
            _ => false,
        };
        if emergency_active {
            self.close_managed_path(&environment_ref);
        }
        let (browser_stopped, termination) = match &session.browser {
            Some(identity) => match self.backends.processes.terminate(identity) {
                TerminateOutcome::Terminated => (Some(true), "TERMINATED".to_string()),
                TerminateOutcome::NotRunning => (Some(true), "NOT_RUNNING".to_string()),
                TerminateOutcome::IdentityMismatch(_) => (Some(true), "IDENTITY_MISMATCH_NOT_KILLED".to_string()),
                TerminateOutcome::Failed(code) => (Some(false), code),
            },
            None => (None, "BROWSER_UNBOUND".to_string()),
        };
        let retired = self.retire_emergency_config(&environment_ref);
        let closed = !retired.rules_present && browser_stopped != Some(false);
        let closed_safely = closed && browser_stopped == Some(true);
        let code = if closed_safely {
            None
        } else if retired.rules_present {
            Some(retired.code.clone().unwrap_or_else(|| "EMERGENCY_RULES_PRESENT".to_string()))
        } else if browser_stopped == Some(false) {
            Some(termination.clone())
        } else {
            Some("EMERGENCY_BROWSER_UNBOUND".to_string())
        };
        let now = self.now();
        let _ = self.update(|state| {
            if let Some(item) = state.emergency.get_mut(session_ref) {
                if closed {
                    item.open = false;
                    item.closed_at_ms = Some(now);
                }
                item.close_reason = Some(reason.to_string());
                item.browser_stopped = browser_stopped;
                item.route_rules_present_after_close = Some(retired.rules_present);
                item.closed_safely = closed_safely;
                item.close_code = code.clone();
                item.close_indeterminate = false;
            }
        });
        let state = self.snapshot();
        let receipt = json!({
            "command": "CloseEmergencyRoute",
            "session_ref": session_ref,
            "reason": reason,
            "closed": closed,
            "closed_safely": closed_safely,
            "browser_termination": termination,
            "browser_stopped": browser_stopped,
            "route_rules_present": retired.rules_present,
            "requires_config_reapply": retired.rules_present,
            "baseline_restored": retired.baseline_restored,
            "core_stopped": retired.core_stopped,
            "managed_path": self.managed_path_view(&state, &environment_ref),
            "side_effects": true,
        });
        match code {
            None => Ok(receipt),
            Some(code) => Err((ServiceError::new(&code, "应急会话没有安全关闭"), receipt)),
        }
    }

    /// 服务常驻的周期动作，不经 IPC、不依赖宿主或页面：应急到期、无会话绑定的应急配置、内核实例变化后的受管路径。
    pub fn tick(&self) -> Value {
        let _serial = match self.operation_lock.lock() {
            Ok(guard) => guard,
            Err(_) => return json!({"code": "SERVICE_BUSY", "actions": []}),
        };
        let now = self.now();
        let mut actions: Vec<Value> = Vec::new();

        let expired: Vec<String> = self
            .snapshot()
            .emergency
            .values()
            .filter(|session| session.open && session.expires_at_ms <= now)
            .map(|session| session.session_ref.clone())
            .collect();
        for session_ref in expired {
            let (ok, code, receipt) = match self.end_emergency(&session_ref, "EXPIRED") {
                Ok(receipt) => (true, None, receipt),
                Err((error, receipt)) => (false, Some(error.code), receipt),
            };
            actions.push(json!({"action": "emergency_expired", "session_ref": session_ref, "ok": ok, "code": code, "receipt": receipt}));
        }

        let snapshot = self.snapshot();
        if let (Some(emergency), Some(active)) = (snapshot.emergency_config.clone(), snapshot.active_config_sha256.clone()) {
            let bound = snapshot.emergency.values().any(|session| session.open && session.config_sha256 == active);
            if emergency.config_sha256 == active && !bound && emergency.verified_at_ms + EMERGENCY_UNBOUND_TTL_MS <= now {
                self.close_managed_path(&emergency.environment_ref);
                let retired = self.retire_emergency_config(&emergency.environment_ref);
                actions.push(json!({
                    "action": "emergency_config_unbound_expired",
                    "environment_ref": emergency.environment_ref,
                    "rules_present": retired.rules_present,
                    "baseline_restored": retired.baseline_restored,
                    "core_stopped": retired.core_stopped,
                    "code": retired.code,
                }));
            }
        }

        let snapshot = self.snapshot();
        let core = self.backends.core.status();
        for (environment_ref, record) in snapshot.managed_path.iter().filter(|(_, record)| record.open) {
            let same_instance = record.service_instance_id.as_deref() == Some(self.instance_id.as_str());
            if core.running && record.core_pid == core.pid && same_instance {
                continue;
            }
            self.close_managed_path(environment_ref);
            let baseline = snapshot
                .last_valid
                .clone()
                .filter(|last| &last.environment_ref == environment_ref && record.config_sha256.as_deref() == Some(last.config_sha256.as_str()));
            let reverified = match (core.running && same_instance, baseline) {
                (true, Some(last)) => {
                    let verified = self.verify_loaded(environment_ref, &last.config_sha256, &last.facts, core.pid).verified;
                    self.commit_restored(&last, verified);
                    verified
                }
                _ => {
                    let _ = self.update(clear_active);
                    false
                }
            };
            actions.push(json!({"action": "managed_path_instance_changed", "environment_ref": environment_ref, "core_running": core.running, "reverified": reverified}));
        }

        if actions.is_empty() {
            return json!({"actions": []});
        }
        let persisted = self.persist();
        json!({"actions": actions, "state_persisted": persisted.is_ok(), "state_error": persisted.err().map(|error| error.code)})
    }

    /// 实际运行记录：actual 字段只放本次从进程、内核接口与保护回读得到的值，读不到的列入 missing。
    pub fn observe(&self, payload: &Value) -> Outcome {
        let environment_ref = text(payload, "environment_ref").map_err(rejected)?;
        let include: Vec<String> = payload
            .get("include")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        let snapshot = self.snapshot();
        let core = self.backends.core.status();
        let now = self.now();
        let mut missing: Vec<&str> = Vec::new();
        let kernel_version = if core.running {
            match self.backends.controller.version() {
                Ok(body) => body.get("version").cloned().unwrap_or(Value::Null),
                Err(_) => {
                    missing.push("core.kernel_version");
                    Value::Null
                }
            }
        } else {
            Value::Null
        };
        let current = self.verification_current(&snapshot, &core);
        let readback_status = if snapshot.verification.status.is_empty() {
            "NOT_RUN".to_string()
        } else if snapshot.verification.status == "VERIFIED" && !current {
            "STALE_INSTANCE".to_string()
        } else {
            snapshot.verification.status.clone()
        };
        let (record, live, effective) = self.live_protection(&snapshot, environment_ref);
        let emergency: Vec<Value> = snapshot
            .emergency
            .values()
            .filter(|item| item.environment_ref == environment_ref)
            .map(|item| {
                json!({
                    "session_ref": item.session_ref,
                    "browser_process": item.browser_process,
                    "open": item.open,
                    "expired": item.expires_at_ms <= now,
                    "expires_at_ms": item.expires_at_ms,
                    "browser_bound": item.browser.is_some(),
                    "closed_safely": item.closed_safely,
                    "close_code": item.close_code,
                    "close_indeterminate": item.close_indeterminate,
                    "route_rules_present_after_close": item.route_rules_present_after_close,
                })
            })
            .collect();
        let indeterminate: Vec<Value> = snapshot
            .indeterminate
            .iter()
            .map(|item| json!({"operation_id": item.operation_id, "command": item.command}))
            .collect();
        let mut receipt = json!({
            "service": {
                "status": "RUNNING",
                "product_id": PRODUCT_APP_ID,
                "protocol": PROTOCOL,
                "service_instance_id": self.instance_id,
                "service_version": crate::VERSION,
                "started_at_ms": self.started_at_ms,
            },
            "core": {
                "running": core.running,
                "pid": core.pid,
                "started_at_ms": core.started_at_ms,
                "restart_count": core.restart_count,
                "last_exit": core.last_exit,
                "gave_up": core.gave_up,
                "binary_present": self.backends.core.binary_present(),
                "kernel_version": kernel_version,
                "expected_kernel_version": KERNEL_VERSION,
            },
            "config": {
                "environment_ref": snapshot.environment_ref,
                "expected_config_sha256": snapshot.expected_config_sha256,
                "active_config_sha256": snapshot.active_config_sha256,
                "plan_ref": snapshot.plan_ref,
                "plan_version": snapshot.plan_version,
                "assignment_version": snapshot.assignment_version,
                "last_valid_config_ref": snapshot.last_valid.as_ref().map(|item| item.config_sha256.clone()),
                "last_valid_plan_version": snapshot.last_valid.as_ref().map(|item| item.plan_version.clone()),
                "emergency_config_ref": snapshot.emergency_config.as_ref().map(|item| item.config_sha256.clone()),
            },
            "readback": {
                "status": readback_status,
                "current": current,
                "checks": snapshot.verification.checks,
                "checked_at_ms": snapshot.verification.checked_at_ms,
            },
            "protection": {
                "environment_ref": environment_ref,
                "requested": record.as_ref().map(|item| item.requested).unwrap_or(false),
                "effective": effective,
                "new_connections_restricted": effective,
                "processes": record.as_ref().map(|item| item.processes.clone()).unwrap_or_default(),
                "loopback_policy": record.as_ref().map(|item| item.loopback.view()).unwrap_or(Value::Null),
                "installed": live.installed,
                "missing": live.missing,
                "mismatched": live.mismatched,
                "residual": live.residual,
                "managed_path": self.managed_path_view(&snapshot, environment_ref),
            },
            "emergency": emergency,
            "recovery": {
                "pending": snapshot.pending.as_ref().map(|item| item.operation_id.clone()),
                "indeterminate": indeterminate,
            },
            "last_failure_code": snapshot.last_failure_code,
            "observed_at_ms": now,
            "side_effects": false,
        });
        if include.iter().any(|item| item == "config") {
            if core.running {
                let general = self.backends.controller.general();
                let rules = self.backends.controller.rules();
                let proxies = self.backends.controller.proxies();
                if general.is_err() {
                    missing.push("actual.general");
                }
                if rules.is_err() {
                    missing.push("actual.rules");
                }
                if proxies.is_err() {
                    missing.push("actual.proxies");
                }
                receipt["actual"] = json!({
                    "general": general.ok().map(|body| project_general(&body)),
                    "rules": rules.ok().and_then(|body| body.get("rules").cloned()),
                    "proxies": proxies.ok().map(|body| project_proxies(&body)),
                });
            } else {
                missing.push("actual.config");
            }
        }
        if include.iter().any(|item| item == "connections") {
            let body = if core.running { self.backends.controller.connections().ok() } else { None };
            match body {
                Some(body) => receipt["connections"] = project_connections(&body),
                None => missing.push("connections"),
            }
        }
        if include.iter().any(|item| item == "logs") {
            receipt["logs"] = json!(self.backends.core.log_tail(LOG_TAIL_LINES));
        }
        receipt["missing"] = json!(missing);
        Ok(receipt)
    }

    /// 服务进程启动后的恢复：把记录里要求的保护逐环境补回并回读，关掉上一实例留下的受管路径。
    /// 不自动加载 last-valid：服务无法离线证明它仍未撤销、未过期，等客户端取得当前权威状态后显式恢复。
    pub fn recover_after_start(&self) -> Value {
        let _serial = match self.operation_lock.lock() {
            Ok(guard) => guard,
            Err(_) => return json!({"code": "SERVICE_BUSY"}),
        };
        let snapshot = self.snapshot();
        let mut protection = Vec::new();
        for (environment_ref, record) in snapshot.protection.iter().filter(|(_, record)| record.requested) {
            self.backends.protection.ensure(environment_ref, &record.processes, &record.loopback);
            let live = self.backends.protection.read(environment_ref, &record.processes, &record.loopback);
            let effective = live.covers(&record.processes);
            let now = self.now();
            let _ = self.update(|state| {
                if let Some(item) = state.protection.get_mut(environment_ref) {
                    item.effective = effective;
                    item.checked_at_ms = now;
                }
            });
            protection.push(json!({"environment_ref": environment_ref, "effective": effective, "missing": live.missing, "mismatched": live.mismatched, "residual": live.residual, "loopback_digest": record.loopback.digest}));
        }
        let mut paths = Vec::new();
        for environment_ref in snapshot.protection.keys() {
            let closed = self.close_managed_path(environment_ref);
            paths.push(json!({"environment_ref": environment_ref, "closed": closed}));
        }
        let _ = self.update(|state| {
            clear_active(state);
            state.emergency_config = None;
            state.verification = Verification { status: "NOT_RUN".to_string(), ..Verification::default() };
        });
        let persisted = self.persist();
        let indeterminate: Vec<Value> = snapshot
            .indeterminate
            .iter()
            .map(|item| json!({"operation_id": item.operation_id, "command": item.command}))
            .collect();
        json!({
            "protection": protection,
            "managed_path": paths,
            "core": {
                "started": false,
                "skipped": "AWAITING_CURRENT_AUTHORITY",
                "last_valid_config_ref": snapshot.last_valid.as_ref().map(|item| item.config_sha256.clone()),
                "requires_client_restore": snapshot.last_valid.is_some(),
            },
            "indeterminate": indeterminate,
            "state_persisted": persisted.is_ok(),
            "state_error": persisted.err().map(|error| error.code),
            "service_instance_id": self.instance_id,
        })
    }
}

fn project_general(body: &Value) -> Value {
    json!({
        "mode": body.get("mode"),
        "tun": body.get("tun").map(|tun| json!({"enable": tun.get("enable"), "stack": tun.get("stack"), "device": tun.get("device")})),
        "ipv6": body.get("ipv6"),
        "port": body.get("port"),
        "socks-port": body.get("socks-port"),
        "mixed-port": body.get("mixed-port"),
        "find-process-mode": body.get("find-process-mode"),
        "log-level": body.get("log-level"),
    })
}

fn project_proxies(body: &Value) -> Value {
    let mut projected = Map::new();
    if let Some(table) = body.get("proxies").and_then(Value::as_object) {
        for (name, item) in table {
            projected.insert(
                name.clone(),
                json!({"name": name, "type": item.get("type"), "now": item.get("now"), "all": item.get("all")}),
            );
        }
    }
    json!({"proxies": projected})
}

fn project_connections(body: &Value) -> Value {
    let connections: Vec<Value> = body
        .get("connections")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let metadata = item.get("metadata").cloned().unwrap_or(Value::Null);
                    json!({
                        "id": item.get("id"),
                        "metadata": {
                            "network": metadata.get("network"),
                            "type": metadata.get("type"),
                            "host": metadata.get("host"),
                            "destinationIP": metadata.get("destinationIP"),
                            "destinationPort": metadata.get("destinationPort"),
                            "process": metadata.get("process"),
                            "processPath": metadata.get("processPath"),
                        },
                        "chains": item.get("chains"),
                        "rule": item.get("rule"),
                        "rulePayload": item.get("rulePayload"),
                        "upload": item.get("upload"),
                        "download": item.get("download"),
                        "start": item.get("start"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "downloadTotal": body.get("downloadTotal"),
        "uploadTotal": body.get("uploadTotal"),
        "connections": connections,
    })
}
