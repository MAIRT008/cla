//! 有状态替身只扮演 I/O：进程、内核接口、固定内核校验、WFP、文件、时钟与进程身份。
//! 配置阶段、授权、宿主身份、幂等、落盘、恢复、保护、受管路径与应急判定都走 `NetworkService` 的真实代码。
//! 本机没有 cargo/rustc，这些用例已写未运行。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::*;
use crate::core::auth::{sign_envelope, EnvelopeDraft};
use crate::core::config::{kernel_rule_payload, SAMPLE_MANAGED_YAML};

const KEY: &[u8] = b"synthetic-service-link-key-0123456789abcdef";
const ENV: &str = "env-host";
const CLAUDE: &str = r"C:\Program Files\Claude\claude.exe";
const BROWSER: &str = r"C:\Program Files\Mozilla Firefox\firefox.exe";
const EXTRA: &str = r"C:\Program Files\Claude\claude-helper.exe";
const HOST: &str = r"C:\Program Files\AI Environmental Steward\ai-environmental-steward.exe";
const SERVICE: &str = r"C:\Program Files\AI Environmental Steward\ai-environmental-steward-service.exe";
const TUN_LUID: u64 = 0x2a;
const EMERGENCY_RULE: &str = "  - AND,((PROCESS-NAME,firefox.exe),(DOMAIN-SUFFIX,support.example)),EMERGENCY-EGRESS\n";

#[derive(Default)]
struct World {
    now: i64,
    persisted: Option<Value>,
    saves: usize,
    fail_saves_from: Option<usize>,
    drafts: BTreeMap<PathBuf, Vec<u8>>,
    stored: BTreeMap<String, Vec<u8>>,
    binary_present: bool,
    core_running: bool,
    core_pid: u32,
    next_pid: u32,
    restart_config: Option<PathBuf>,
    loaded: Option<String>,
    validator_fails: bool,
    load_status: u16,
    drop_rules: bool,
    tun_device: Option<String>,
    interfaces: BTreeMap<String, u64>,
    filters: BTreeSet<(String, String)>,
    permits: BTreeMap<(String, String), u64>,
    loopback: BTreeMap<String, LoopbackPolicy>,
    fail_process: Option<String>,
    running_business: Vec<String>,
    processes: BTreeMap<u32, ProcessIdentity>,
    terminate_fails: bool,
    killed: Vec<u32>,
    calls: Vec<String>,
}

type Shared = Arc<Mutex<World>>;

fn draft_root() -> PathBuf {
    std::env::temp_dir().join("steward-network").join("drafts")
}

fn core_root() -> PathBuf {
    std::env::temp_dir().join("steward-service").join("core").join("configs")
}

struct FakeClock(Shared);
impl Clock for FakeClock {
    fn now_ms(&self) -> i64 {
        self.0.lock().unwrap().now
    }
}

struct FakeState(Shared);
impl StateStore for FakeState {
    fn load(&self) -> Result<Option<Value>, ServiceError> {
        Ok(self.0.lock().unwrap().persisted.clone())
    }
    fn save(&self, state: &Value) -> Result<(), ServiceError> {
        let mut world = self.0.lock().unwrap();
        world.saves += 1;
        if world.fail_saves_from.map(|from| world.saves >= from).unwrap_or(false) {
            return Err(ServiceError::new("SERVICE_STATE_UNWRITABLE", "synthetic disk full"));
        }
        world.persisted = Some(state.clone());
        Ok(())
    }
}

struct FakeConfigs(Shared);
impl ConfigStore for FakeConfigs {
    fn approved_draft_root(&self) -> Option<PathBuf> {
        Some(draft_root())
    }
    fn read_draft(&self, draft: &Path) -> Result<Vec<u8>, ServiceError> {
        self.0.lock().unwrap().drafts.get(draft).cloned().ok_or_else(|| ServiceError::new("DRAFT_UNREADABLE", "missing"))
    }
    fn store(&self, sha256: &str, bytes: &[u8]) -> Result<PathBuf, ServiceError> {
        self.0.lock().unwrap().stored.insert(sha256.to_string(), bytes.to_vec());
        Ok(core_root().join(format!("{sha256}.yaml")))
    }
    fn stored_path(&self, sha256: &str) -> Option<PathBuf> {
        self.0.lock().unwrap().stored.contains_key(sha256).then(|| core_root().join(format!("{sha256}.yaml")))
    }
}

fn stored_text(world: &World, path: &Path) -> Option<String> {
    let sha = path.file_stem()?.to_string_lossy().to_string();
    world.stored.get(&sha).map(|bytes| String::from_utf8_lossy(bytes).to_string())
}

struct FakeCore(Shared);
impl CoreProcess for FakeCore {
    fn binary_present(&self) -> bool {
        self.0.lock().unwrap().binary_present
    }
    fn start(&self, config_path: &Path) -> Result<CoreStatus, ServiceError> {
        let mut world = self.0.lock().unwrap();
        world.calls.push("core.start".into());
        world.core_running = true;
        world.core_pid = world.next_pid;
        world.next_pid += 1;
        world.loaded = stored_text(&world, config_path);
        Ok(CoreStatus { running: true, pid: Some(world.core_pid), ..CoreStatus::default() })
    }
    fn stop(&self) -> Result<(), ServiceError> {
        let mut world = self.0.lock().unwrap();
        world.calls.push("core.stop".into());
        world.core_running = false;
        world.loaded = None;
        Ok(())
    }
    fn set_restart_config(&self, config_path: &Path) {
        self.0.lock().unwrap().restart_config = Some(config_path.to_path_buf());
    }
    fn status(&self) -> CoreStatus {
        let world = self.0.lock().unwrap();
        CoreStatus { running: world.core_running, pid: world.core_running.then_some(world.core_pid), ..CoreStatus::default() }
    }
    fn log_tail(&self, _max_lines: usize) -> Vec<String> {
        vec!["[TCP] synthetic --> claude.ai match ProcessName(claude.exe) using CLAUDE-FIXED[EXIT-A]".into()]
    }
}

struct FakeController(Shared);
impl FakeController {
    fn facts(&self) -> Result<crate::core::config::ManagedFacts, ServiceError> {
        let world = self.0.lock().unwrap();
        if !world.core_running {
            return Err(ServiceError::new("CORE_CONTROLLER_UNREACHABLE", "core pipe closed"));
        }
        let text = world.loaded.clone().ok_or_else(|| ServiceError::new("CORE_CONTROLLER_UNREACHABLE", "nothing loaded"))?;
        drop(world);
        inspect_managed_yaml(&text)
    }
}
impl CoreController for FakeController {
    fn version(&self) -> Result<Value, ServiceError> {
        if !self.0.lock().unwrap().core_running {
            return Err(ServiceError::new("CORE_CONTROLLER_UNREACHABLE", "core pipe closed"));
        }
        Ok(json!({"meta": true, "version": "v1.19.30"}))
    }
    fn load_config(&self, config_path: &Path) -> Result<u16, ServiceError> {
        let mut world = self.0.lock().unwrap();
        world.calls.push("core.load".into());
        if !world.core_running {
            return Err(ServiceError::new("CORE_CONTROLLER_UNREACHABLE", "core pipe closed"));
        }
        if world.load_status != 204 {
            return Ok(world.load_status);
        }
        world.loaded = stored_text(&world, config_path);
        Ok(204)
    }
    fn general(&self) -> Result<Value, ServiceError> {
        let facts = self.facts()?;
        let device = self.0.lock().unwrap().tun_device.clone();
        Ok(json!({"mode": facts.mode, "tun": {"enable": facts.tun_enable, "stack": "system", "device": device}, "ipv6": facts.ipv6, "mixed-port": 0}))
    }
    fn rules(&self) -> Result<Value, ServiceError> {
        let facts = self.facts()?;
        let drop_rules = self.0.lock().unwrap().drop_rules;
        let count = if drop_rules { 2 } else { facts.rules.len() };
        let rules: Vec<Value> = facts
            .rules
            .iter()
            .take(count)
            .enumerate()
            .map(|(index, rule)| json!({"index": index, "type": rule.rule_type, "payload": kernel_rule_payload(rule).unwrap_or_default(), "proxy": rule.proxy, "size": -1}))
            .collect();
        Ok(json!({"rules": rules}))
    }
    fn proxies(&self) -> Result<Value, ServiceError> {
        let facts = self.facts()?;
        let mut table = serde_json::Map::new();
        for name in facts.group_names.iter().chain(facts.proxy_names.iter()) {
            table.insert(name.clone(), json!({"name": name, "type": "Selector", "now": facts.claude_member}));
        }
        Ok(json!({"proxies": table}))
    }
    fn connections(&self) -> Result<Value, ServiceError> {
        self.facts()?;
        Ok(json!({"downloadTotal": 10, "uploadTotal": 5, "connections": [{"id": "c1", "metadata": {"host": "claude.ai", "process": "claude.exe"}, "chains": ["EXIT-A", "PROXY-A", "CLAUDE-FIXED"], "upload": 5, "download": 10}]}))
    }
    fn close_connections(&self) -> Result<u16, ServiceError> {
        let mut world = self.0.lock().unwrap();
        world.calls.push("core.close".into());
        Ok(204)
    }
}

struct FakeValidator(Shared);
impl KernelValidator for FakeValidator {
    fn validate(&self, _config_path: &Path) -> Result<(), ServiceError> {
        let mut world = self.0.lock().unwrap();
        world.calls.push("validate".into());
        if world.validator_fails {
            return Err(ServiceError::new("CONFIG_KERNEL_REJECTED", "mihomo -t rejected the configuration"));
        }
        Ok(())
    }
}

struct FakeProtection(Shared);
impl ProtectionBackend for FakeProtection {
    fn ensure(&self, environment_ref: &str, processes: &[String], loopback: &LoopbackPolicy) -> ProtectionOutcome {
        let mut world = self.0.lock().unwrap();
        world.calls.push("protect.ensure".into());
        let mut created = Vec::new();
        for process in processes {
            let key = (environment_ref.to_string(), process.to_ascii_lowercase());
            if world.fail_process.as_deref().map(|item| item.eq_ignore_ascii_case(process)).unwrap_or(false) {
                for item in &created {
                    world.filters.remove(item);
                }
                return ProtectionOutcome { created: 0, rolled_back: true, code: Some("NATIVE_FILTER_ADD_FAILED".into()), native_status: Some(-2144796671), ..ProtectionOutcome::default() };
            }
            if world.filters.insert(key.clone()) {
                created.push(key);
            }
        }
        world.loopback.insert(environment_ref.to_string(), loopback.clone());
        ProtectionOutcome { created: created.len(), ..ProtectionOutcome::default() }
    }
    /// 替身的回环语义：装着的端点多于当前策略算残留；策略摘要对不上时带端点的程序算不符。
    fn read(&self, environment_ref: &str, processes: &[String], loopback: &LoopbackPolicy) -> ProtectionOutcome {
        let world = self.0.lock().unwrap();
        let (mut installed, missing): (Vec<String>, Vec<String>) = processes
            .iter()
            .cloned()
            .partition(|process| world.filters.contains(&(environment_ref.to_string(), process.to_ascii_lowercase())));
        let present = world.loopback.get(environment_ref).cloned().unwrap_or_default();
        let residual: Vec<String> = present
            .endpoints
            .iter()
            .filter(|endpoint| !loopback.endpoints.contains(endpoint))
            .map(|endpoint| format!("{}|{}|{}", endpoint.transport, endpoint.address, endpoint.port))
            .collect();
        let mut mismatched = Vec::new();
        if !loopback.endpoints.is_empty() && present.digest != loopback.digest {
            let (stale, kept): (Vec<String>, Vec<String>) =
                installed.into_iter().partition(|process| loopback.endpoints.iter().any(|endpoint| endpoint.source_process_path.eq_ignore_ascii_case(process)));
            installed = kept;
            mismatched = stale;
        }
        ProtectionOutcome { installed, missing, mismatched, residual, ..ProtectionOutcome::default() }
    }
    fn release(&self, environment_ref: &str, processes: &[String]) -> ProtectionOutcome {
        let mut world = self.0.lock().unwrap();
        world.calls.push("protect.release".into());
        let mut removed = 0;
        for process in processes {
            let key = (environment_ref.to_string(), process.to_ascii_lowercase());
            if world.filters.remove(&key) {
                removed += 1;
            }
            if world.permits.remove(&key).is_some() {
                removed += 1;
            }
        }
        if let Some(policy) = world.loopback.remove(environment_ref) {
            removed += policy.endpoints.len();
        }
        ProtectionOutcome { removed, ..ProtectionOutcome::default() }
    }
    fn resolve_interface(&self, alias: &str) -> Result<u64, ServiceError> {
        self.0.lock().unwrap().interfaces.get(alias).copied().ok_or_else(|| ServiceError::new("MANAGED_INTERFACE_NOT_FOUND", "no such interface"))
    }
    fn open_managed_path(&self, environment_ref: &str, processes: &[String], interface_luid: u64) -> ProtectionOutcome {
        let mut world = self.0.lock().unwrap();
        world.calls.push("path.open".into());
        for process in processes {
            world.permits.insert((environment_ref.to_string(), process.to_ascii_lowercase()), interface_luid);
        }
        ProtectionOutcome { created: processes.len(), ..ProtectionOutcome::default() }
    }
    fn read_managed_path(&self, environment_ref: &str, processes: &[String], interface_luid: u64) -> ProtectionOutcome {
        let world = self.0.lock().unwrap();
        let mut outcome = ProtectionOutcome::default();
        for process in processes {
            match world.permits.get(&(environment_ref.to_string(), process.to_ascii_lowercase())) {
                Some(luid) if *luid == interface_luid => outcome.installed.push(process.clone()),
                Some(_) => outcome.mismatched.push(process.clone()),
                None => outcome.missing.push(process.clone()),
            }
        }
        outcome
    }
    fn close_managed_path(&self, environment_ref: &str, processes: &[String]) -> ProtectionOutcome {
        let mut world = self.0.lock().unwrap();
        world.calls.push("path.close".into());
        let mut removed = 0;
        for process in processes {
            if world.permits.remove(&(environment_ref.to_string(), process.to_ascii_lowercase())).is_some() {
                removed += 1;
            }
        }
        ProtectionOutcome { removed, ..ProtectionOutcome::default() }
    }
}

struct FakeProbe(Shared);
impl ProcessProbe for FakeProbe {
    fn running(&self, paths: &[String]) -> Result<Vec<String>, ServiceError> {
        let world = self.0.lock().unwrap();
        Ok(paths.iter().filter(|path| world.running_business.iter().any(|item| item.eq_ignore_ascii_case(path))).cloned().collect())
    }
    fn identify(&self, pid: u32) -> Result<Option<ProcessIdentity>, ServiceError> {
        Ok(self.0.lock().unwrap().processes.get(&pid).cloned())
    }
    fn terminate(&self, expected: &ProcessIdentity) -> TerminateOutcome {
        let mut world = self.0.lock().unwrap();
        world.calls.push("process.terminate".into());
        let actual = world.processes.get(&expected.pid).cloned();
        match judge_termination(expected, actual.as_ref()) {
            TerminationJudgement::NotRunning => TerminateOutcome::NotRunning,
            TerminationJudgement::Mismatch(actual) => TerminateOutcome::IdentityMismatch(actual),
            TerminationJudgement::Proceed if world.terminate_fails => TerminateOutcome::Failed("PROCESS_TERMINATE_FAILED_5".into()),
            TerminationJudgement::Proceed => {
                world.processes.remove(&expected.pid);
                world.killed.push(expected.pid);
                TerminateOutcome::Terminated
            }
        }
    }
}

fn new_world() -> Shared {
    let mut interfaces = BTreeMap::new();
    interfaces.insert("Meta".to_string(), TUN_LUID);
    Arc::new(Mutex::new(World {
        now: 1_800_000_000_000,
        binary_present: true,
        next_pid: 4100,
        load_status: 204,
        tun_device: Some("Meta".to_string()),
        interfaces,
        ..World::default()
    }))
}

fn open(world: &Shared) -> NetworkService {
    NetworkService::open(Backends {
        clock: Box::new(FakeClock(world.clone())),
        state: Box::new(FakeState(world.clone())),
        configs: Box::new(FakeConfigs(world.clone())),
        core: Box::new(FakeCore(world.clone())),
        controller: Box::new(FakeController(world.clone())),
        validator: Box::new(FakeValidator(world.clone())),
        protection: Box::new(FakeProtection(world.clone())),
        processes: Box::new(FakeProbe(world.clone())),
    })
    .unwrap()
}

fn calls(world: &Shared) -> Vec<String> {
    world.lock().unwrap().calls.clone()
}

fn count(world: &Shared, call: &str) -> usize {
    calls(world).iter().filter(|item| *item == call).count()
}

fn position(made: &[String], call: &str) -> usize {
    made.iter().position(|item| item == call).unwrap_or(usize::MAX)
}

fn advance(world: &Shared, millis: i64) {
    world.lock().unwrap().now += millis;
}

fn fail_saves_after(world: &Shared, successful: usize) {
    let mut guard = world.lock().unwrap();
    guard.fail_saves_from = Some(guard.saves + successful + 1);
}

fn heal_disk(world: &Shared) {
    world.lock().unwrap().fail_saves_from = None;
}

fn reboot(world: &Shared) {
    let mut guard = world.lock().unwrap();
    guard.filters.clear();
    guard.permits.clear();
    guard.loopback.clear();
    guard.core_running = false;
    guard.loaded = None;
    guard.calls.clear();
}

fn draft(world: &Shared, name: &str, yaml: &str) -> (String, String) {
    let path = draft_root().join(format!("{name}.yaml"));
    world.lock().unwrap().drafts.insert(path.clone(), yaml.as_bytes().to_vec());
    (path.to_string_lossy().to_string(), sha256_hex(yaml.as_bytes()))
}

fn apply_payload(path: &str, sha: &str) -> Value {
    json!({
        "environment_ref": ENV,
        "plan_ref": "plan-ref-1",
        "plan_version": "plan:v7:claude_single_ip:abc123",
        "assignment_version": "v7",
        "expected_config_sha256": sha,
        "draft_path": path,
    })
}

fn signed_with(key: &[u8], world: &Shared, business: &str, command: ServiceCommand, payload: Value) -> ServiceRequest {
    let now = world.lock().unwrap().now;
    let environment_ref = payload["environment_ref"].as_str().unwrap().to_string();
    let envelope = sign_envelope(
        key,
        &EnvelopeDraft { business_operation_id: business, command, environment_ref: &environment_ref, payload: &payload, now_ms: now, authorization_expires_at_ms: None },
    )
    .unwrap();
    ServiceRequest { product_id: PRODUCT_APP_ID.into(), protocol: PROTOCOL.into(), envelope: Some(envelope), payload }
}

fn signed(world: &Shared, business: &str, command: ServiceCommand, payload: Value) -> ServiceRequest {
    signed_with(KEY, world, business, command, payload)
}

fn run(service: &NetworkService, world: &Shared, business: &str, command: ServiceCommand, payload: Value) -> ServiceReply {
    service.handle(command, &signed(world, business, command, payload), KEY)
}

fn protect(service: &NetworkService, world: &Shared, business: &str, environment_ref: &str, processes: &[&str]) -> ServiceReply {
    run(service, world, business, ServiceCommand::EnsureProtection, json!({"environment_ref": environment_ref, "action": "block_new", "processes": processes, "reason_code": "APPLY_PRECONDITION"}))
}

fn apply(service: &NetworkService, world: &Shared, business: &str, yaml: &str) -> ServiceReply {
    let (path, sha) = draft(world, business, yaml);
    run(service, world, business, ServiceCommand::ApplyConfig, apply_payload(&path, &sha))
}

fn restore(service: &NetworkService, world: &Shared, business: &str) -> ServiceReply {
    run(service, world, business, ServiceCommand::RestoreLastValid, json!({"environment_ref": ENV, "reason_code": "CLIENT_RECHECKED"}))
}

fn observe(service: &NetworkService, include: &[&str]) -> Value {
    let request = ServiceRequest { product_id: PRODUCT_APP_ID.into(), protocol: PROTOCOL.into(), envelope: None, payload: json!({"environment_ref": ENV, "include": include}) };
    let reply = service.handle(ServiceCommand::ObserveRuntime, &request, KEY);
    assert!(reply.ok, "{reply:?}");
    reply.receipt
}

/// 基线配置：不含应急浏览器规则，回读通过后才会成为 last-valid。
fn baseline() -> String {
    SAMPLE_MANAGED_YAML.replace(EMERGENCY_RULE, "")
}

fn second_config() -> String {
    baseline().replace("MATCH,GENERAL-EGRESS", "DOMAIN,status.example,DIRECT\n  - MATCH,GENERAL-EGRESS")
}

fn permit(world: &Shared) -> Option<u64> {
    world.lock().unwrap().permits.get(&(ENV.to_string(), CLAUDE.to_ascii_lowercase())).copied()
}

fn firefox(pid: u32, created_at_ms: i64) -> ProcessIdentity {
    ProcessIdentity { pid, image_path: BROWSER.to_string(), created_at_ms }
}

#[test]
fn baseline_fixture_is_not_an_emergency_config() {
    assert!(SAMPLE_MANAGED_YAML.contains(EMERGENCY_RULE));
    assert!(inspect_managed_yaml(&baseline()).unwrap().emergency_processes.is_empty());
    assert_eq!(inspect_managed_yaml(SAMPLE_MANAGED_YAML).unwrap().emergency_processes, vec!["firefox.exe".to_string()]);
}

#[test]
fn validation_failure_neither_starts_nor_loads_the_core() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    world.lock().unwrap().validator_fails = true;
    let reply = apply(&service, &world, "a1", &baseline());
    assert!(!reply.ok);
    assert_eq!(reply.code.as_deref(), Some("CONFIG_KERNEL_REJECTED"));
    assert_eq!(reply.receipt["stages"]["downloaded"]["status"], "OK");
    assert_eq!(reply.receipt["stages"]["validated"]["status"], "FAILED");
    assert_eq!(reply.receipt["side_effects"], false);
    let made = calls(&world);
    assert!(!made.contains(&"core.start".to_string()) && !made.contains(&"core.load".to_string()), "{made:?}");
    assert_eq!(observe(&service, &[])["config"]["last_valid_config_ref"], Value::Null);
}

#[test]
fn a_rejected_load_does_not_commit_active_or_last_valid() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    world.lock().unwrap().load_status = 400;
    let reply = apply(&service, &world, "a1", &baseline());
    assert_eq!(reply.code.as_deref(), Some("LOAD_FAILED"));
    assert_eq!(reply.receipt["stages"]["applied"]["status"], "FAILED");
    assert!(reply.receipt["stages"].get("verified").is_none(), "没有加载就没有回读结论");
    let runtime = observe(&service, &[]);
    assert_eq!(runtime["config"]["active_config_sha256"], Value::Null);
    assert_eq!(runtime["config"]["last_valid_config_ref"], Value::Null);
    assert_eq!(runtime["last_failure_code"], "LOAD_FAILED");
    assert_eq!(permit(&world), None, "没有回读确认就没有受管路径");
}

#[test]
fn verify_failed_leaves_active_unknown_keeps_expected_and_the_previous_last_valid() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    let first = apply(&service, &world, "a1", &baseline());
    assert!(first.ok, "{first:?}");
    assert_eq!(first.receipt["overall"], "VERIFIED");
    let first_sha = first.receipt["expected_config_sha256"].clone();

    world.lock().unwrap().drop_rules = true;
    let second = apply(&service, &world, "a2", &second_config());
    assert!(!second.ok);
    assert_eq!(second.code.as_deref(), Some("VERIFY_FAILED"));
    assert_eq!(second.receipt["stages"]["applied"]["http_status"], 204, "204 已拿到");
    assert_eq!(second.receipt["stages"]["verified"]["status"], "VERIFY_FAILED", "204 不能单独算生效");
    assert_eq!(second.receipt["requires_restore"], true);
    assert_eq!(second.receipt["active_config_sha256"], Value::Null, "失败配置不能被提升为 active");
    let runtime = observe(&service, &[]);
    assert_eq!(runtime["config"]["active_config_sha256"], Value::Null, "内核已加载新配置，旧 active 也不能再证明对应当前内核");
    assert_eq!(runtime["config"]["plan_version"], Value::Null);
    assert_eq!(runtime["config"]["expected_config_sha256"], second.receipt["expected_config_sha256"], "期望值单独保存");
    assert_eq!(runtime["config"]["last_valid_config_ref"], first_sha, "last-valid 仍是上一份回读确认的配置");
    assert_eq!(runtime["readback"]["status"], "VERIFY_FAILED");
    assert_eq!(runtime["protection"]["managed_path"]["status"], "CLOSED", "回读失败时受管路径关闭");
    assert_eq!(permit(&world), None);
}

#[test]
fn a_rejected_load_keeps_the_previous_active_only_when_it_is_reverified_on_the_same_core() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    let first = apply(&service, &world, "a1", &baseline());
    assert!(first.ok);
    world.lock().unwrap().load_status = 400;
    let rejected = apply(&service, &world, "a2", &second_config());
    assert_eq!(rejected.code.as_deref(), Some("LOAD_FAILED"));
    assert_eq!(rejected.receipt["stages"]["previous_active"]["kept"], true);
    let runtime = observe(&service, &[]);
    assert_eq!(runtime["config"]["active_config_sha256"], first.receipt["expected_config_sha256"], "内核拒绝加载，仍在跑的旧配置重新回读通过");
    assert_eq!(runtime["protection"]["managed_path"]["status"], "OPEN");
}

#[test]
fn the_managed_path_opens_only_after_a_verified_readback_on_the_reported_tun_interface() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    assert_eq!(observe(&service, &[])["protection"]["managed_path"]["status"], "CLOSED", "只有阻断：受保护程序此时不能联网");
    let applied = apply(&service, &world, "a1", &baseline());
    assert!(applied.ok, "{applied:?}");
    let made = calls(&world);
    assert!(position(&made, "path.close") < position(&made, "core.load"), "加载前先关受管路径：{made:?}");
    assert!(position(&made, "core.load") < position(&made, "path.open"), "回读通过后才打开：{made:?}");
    assert_eq!(permit(&world), Some(TUN_LUID), "permit 绑定内核报告的 TUN 接口");
    let runtime = observe(&service, &["config"]);
    assert_eq!(runtime["protection"]["managed_path"]["status"], "OPEN");
    assert_eq!(runtime["protection"]["managed_path"]["current"], true);
    assert_eq!(runtime["protection"]["effective"], true, "受管路径打开时阻断仍在");
    assert_eq!(runtime["actual"]["general"]["tun"]["device"], "Meta");

    world.lock().unwrap().tun_device = None;
    let unreported = apply(&service, &world, "a2", &second_config());
    assert_eq!(unreported.code.as_deref(), Some("VERIFY_FAILED"));
    let check = unreported.receipt["stages"]["verified"]["checks"].as_array().unwrap().iter().find(|item| item["name"] == "managed_path").cloned().unwrap();
    assert_eq!(check["ok"], false);
    assert_eq!(check["actual"]["code"], "TUN_DEVICE_UNREPORTED", "识别不出本内核的 TUN 接口就不放行");
    assert_eq!(permit(&world), None);

    world.lock().unwrap().tun_device = Some("Meta".to_string());
    world.lock().unwrap().interfaces.clear();
    let unresolved = restore(&service, &world, "r1");
    assert_eq!(unresolved.code.as_deref(), Some("VERIFY_FAILED"));
    assert_eq!(permit(&world), None, "接口找不到时保持关闭");
    world.lock().unwrap().interfaces.insert("Meta".to_string(), TUN_LUID);
    assert!(restore(&service, &world, "r2").ok);
    assert_eq!(permit(&world), Some(TUN_LUID));
}

#[test]
fn a_core_instance_change_closes_the_managed_path_before_any_reverification() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    assert!(apply(&service, &world, "a1", &baseline()).ok);
    assert!(service.tick()["actions"].as_array().unwrap().is_empty(), "同一实例什么都不做");

    world.lock().unwrap().core_running = false;
    let crashed = service.tick();
    assert_eq!(crashed["actions"][0]["action"], "managed_path_instance_changed");
    assert_eq!(crashed["actions"][0]["reverified"], false);
    assert_eq!(permit(&world), None, "内核异常退出：只剩阻断");
    assert_eq!(observe(&service, &[])["config"]["active_config_sha256"], Value::Null);

    {
        let mut guard = world.lock().unwrap();
        guard.calls.clear();
        guard.core_running = true;
        guard.core_pid = 4200;
    }
    assert!(restore(&service, &world, "r1").ok);
    {
        let mut guard = world.lock().unwrap();
        guard.core_pid = 4300;
        guard.calls.clear();
    }
    let restarted = service.tick();
    let made = calls(&world);
    assert!(position(&made, "path.close") < position(&made, "path.open"), "看门狗换了进程：先关，同实例回读 last-valid 通过后再开：{made:?}");
    assert_eq!(restarted["actions"][0]["reverified"], true);
    assert_eq!(observe(&service, &[])["protection"]["managed_path"]["current"], true);
}

#[test]
fn the_same_operation_replays_its_receipt_and_different_content_conflicts_across_restarts() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    let (path, sha) = draft(&world, "a1", &baseline());
    let request = signed(&world, "a1", ServiceCommand::ApplyConfig, apply_payload(&path, &sha));
    let first = service.handle(ServiceCommand::ApplyConfig, &request, KEY);
    assert!(first.ok, "{first:?}");
    let loads = count(&world, "core.load");

    let replay = service.handle(ServiceCommand::ApplyConfig, &request, KEY);
    assert!(replay.ok);
    assert_eq!(replay.receipt["replayed"], true);
    assert_eq!(replay.receipt["expected_config_sha256"], first.receipt["expected_config_sha256"]);
    assert_eq!(count(&world, "core.load"), loads, "重放不再加载");

    let (other_path, other_sha) = draft(&world, "a1-other", &second_config());
    let conflict = service.handle(ServiceCommand::ApplyConfig, &signed(&world, "a1", ServiceCommand::ApplyConfig, apply_payload(&other_path, &other_sha)), KEY);
    assert_eq!(conflict.code.as_deref(), Some("OPERATION_CONFLICT"));
    assert_eq!(count(&world, "core.load"), loads);

    drop(service);
    advance(&world, 10 * 60 * 1000);
    let reopened = open(&world);
    let after_restart = reopened.handle(ServiceCommand::ApplyConfig, &request, KEY);
    assert!(after_restart.ok, "服务重启后幂等记录仍在：{after_restart:?}");
    assert_eq!(after_restart.receipt["replayed"], true);
}

#[test]
fn apply_requires_confirmed_protection_and_a_partial_install_is_not_effective() {
    let world = new_world();
    let service = open(&world);
    let unprotected = apply(&service, &world, "a0", &baseline());
    assert_eq!(unprotected.code.as_deref(), Some("PROTECTION_NOT_READY"));
    assert!(calls(&world).is_empty(), "保护未确认前不校验、不启动、不加载");

    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    world.lock().unwrap().fail_process = Some(EXTRA.to_string());
    let partial = protect(&service, &world, "p2", ENV, &[CLAUDE, EXTRA]);
    assert!(!partial.ok);
    assert_eq!(partial.receipt["effective"], false);
    assert_eq!(partial.receipt["new_connections_restricted"], false);
    assert_eq!(partial.receipt["os_readback"], "PARTIAL");
    assert_eq!(partial.receipt["rolled_back"], true);
    assert!(world.lock().unwrap().filters.contains(&(ENV.to_string(), CLAUDE.to_ascii_lowercase())), "回滚只撤本次新建，不移除先前有效保护");

    assert!(protect(&service, &world, "p3", "env-wsl", &[CLAUDE]).receipt["created"].as_u64().is_some());
    assert!(world.lock().unwrap().filters.contains(&(ENV.to_string(), CLAUDE.to_ascii_lowercase())), "另一个环境不覆盖本环境");

    let blocked = apply(&service, &world, "a1", &baseline());
    assert_eq!(blocked.code.as_deref(), Some("PROTECTION_NOT_READY"), "批准范围没有全部覆盖就不加载配置");
}

#[test]
fn closing_existing_connections_is_a_separate_receipt_after_protection() {
    let world = new_world();
    let service = open(&world);
    let early = run(&service, &world, "c0", ServiceCommand::CloseManagedConnections, json!({"environment_ref": ENV, "reason_code": "WRONG_ROUTE"}));
    assert_eq!(early.code.as_deref(), Some("PROTECTION_NOT_EFFECTIVE"));
    assert_eq!(early.receipt["closed_existing"], false);
    assert!(!calls(&world).contains(&"core.close".to_string()), "关闭连接不能替代保护");

    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    assert!(apply(&service, &world, "a1", &baseline()).ok);
    let closed = run(&service, &world, "c1", ServiceCommand::CloseManagedConnections, json!({"environment_ref": ENV, "reason_code": "WRONG_ROUTE"}));
    assert!(closed.ok, "{closed:?}");
    assert_eq!(closed.receipt["closed_existing"], true);
    assert_eq!(closed.receipt["new_connections_restricted"], true);
    let runtime = observe(&service, &["connections", "logs", "config"]);
    assert_eq!(runtime["connections"]["connections"][0]["metadata"]["process"], "claude.exe");
    assert_eq!(runtime["actual"]["general"]["tun"]["enable"], true);
    assert!(runtime["logs"].as_array().map(|lines| !lines.is_empty()).unwrap_or(false));
}

#[test]
fn a_service_restart_restores_protection_but_waits_for_current_authority_before_loading_last_valid() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    let applied = apply(&service, &world, "a1", &baseline());
    assert!(applied.ok);
    let old_instance = service.instance_id().to_string();
    drop(service);
    reboot(&world);

    let reopened = open(&world);
    let recovered = reopened.recover_after_start();
    let made = calls(&world);
    assert!(made.contains(&"protect.ensure".to_string()), "保护先恢复：{made:?}");
    assert!(!made.contains(&"core.start".to_string()) && !made.contains(&"core.load".to_string()), "没有可离线核验的授权材料，不自动加载 last-valid：{made:?}");
    assert_eq!(recovered["core"]["started"], false);
    assert_eq!(recovered["core"]["skipped"], "AWAITING_CURRENT_AUTHORITY");
    assert_eq!(recovered["core"]["requires_client_restore"], true);
    let runtime = observe(&reopened, &[]);
    assert_ne!(runtime["service"]["service_instance_id"], old_instance);
    assert_eq!(runtime["protection"]["effective"], true);
    assert_eq!(runtime["protection"]["managed_path"]["status"], "CLOSED");
    assert_eq!(runtime["config"]["active_config_sha256"], Value::Null);
    assert_eq!(runtime["config"]["last_valid_config_ref"], applied.receipt["expected_config_sha256"]);
    assert_eq!(permit(&world), None, "服务重启后受保护程序在客户端复核前不能联网");

    let restored = restore(&reopened, &world, "r1");
    assert!(restored.ok, "客户端按当前分配复核后显式恢复：{restored:?}");
    assert_eq!(restored.receipt["readback"], "VERIFIED");
    assert_eq!(restored.receipt["requires_business_recheck"], true);
    assert_eq!(permit(&world), Some(TUN_LUID));
    let made = calls(&world);
    assert!(position(&made, "protect.ensure") < position(&made, "core.start"), "保护先于内核：{made:?}");

    drop(reopened);
    reboot(&world);
    world.lock().unwrap().fail_process = Some(CLAUDE.to_string());
    let unprotected = open(&world);
    let recovered = unprotected.recover_after_start();
    assert_eq!(recovered["protection"][0]["effective"], false);
    let refused = restore(&unprotected, &world, "r2");
    assert_eq!(refused.code.as_deref(), Some("PROTECTION_NOT_READY"));
    assert!(!calls(&world).contains(&"core.start".to_string()), "保护没恢复就不加载 last-valid");
}

#[test]
fn the_emergency_route_needs_a_verified_temporary_config_and_proves_claude_stays_constrained() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    let far = world.lock().unwrap().now + 30 * 60 * 1000;
    let open_request = |business: &str, browser: &str| {
        json!({"environment_ref": ENV, "session_ref": business, "browser_process": browser, "expires_at_ms": far})
    };
    let before = run(&service, &world, "e0", ServiceCommand::OpenEmergencyRoute, open_request("e0", "firefox.exe"));
    assert_eq!(before.code.as_deref(), Some("CONFIG_NOT_VERIFIED"));

    let base = apply(&service, &world, "a0", &baseline());
    assert!(base.ok);
    let temporary = apply(&service, &world, "a1", SAMPLE_MANAGED_YAML);
    assert!(temporary.ok, "{temporary:?}");
    assert_eq!(temporary.receipt["config_class"], "EMERGENCY_TEMPORARY");
    assert_eq!(temporary.receipt["last_valid_config_ref"], base.receipt["expected_config_sha256"], "含应急规则的临时配置不覆盖 last-valid");
    assert_eq!(temporary.receipt["emergency_config_ref"], temporary.receipt["expected_config_sha256"]);
    assert_eq!(world.lock().unwrap().restart_config.as_ref().and_then(|path| path.file_stem()).map(|stem| stem.to_string_lossy().to_string()), base.receipt["expected_config_sha256"].as_str().map(str::to_string), "看门狗重启只用基线配置");

    let absent = run(&service, &world, "e1", ServiceCommand::OpenEmergencyRoute, open_request("e1", "chrome.exe"));
    assert_eq!(absent.code.as_deref(), Some("EMERGENCY_ROUTE_ABSENT"));
    let opened = run(&service, &world, "e2", ServiceCommand::OpenEmergencyRoute, open_request("e2", "firefox.exe"));
    assert!(opened.ok, "{opened:?}");
    assert_eq!(opened.receipt["route_ready"], true);
    assert_eq!(opened.receipt["claude_constrained"], true);
    assert_eq!(opened.receipt["protection_effective"], true);
    assert_eq!(opened.receipt["expiry_enforced_by"], "network_service");
    let scope = opened.receipt["emergency_scope"].as_array().unwrap();
    assert!(scope.iter().any(|item| item["outbound"] == "EMERGENCY-EGRESS"));
    assert!(scope.iter().any(|item| item["outbound"] == "CLAUDE-FIXED"), "应急浏览器访问 Claude 仍走固定 A");

    let now = world.lock().unwrap().now;
    world.lock().unwrap().processes.insert(5100, firefox(5100, now + 10));
    let bound = run(&service, &world, "e2-bind", ServiceCommand::OpenEmergencyRoute, json!({"environment_ref": ENV, "session_ref": "e2", "phase": "bind_browser", "browser_pid": 5100}));
    assert!(bound.ok, "{bound:?}");
    world.lock().unwrap().processes.insert(5200, ProcessIdentity { pid: 5200, image_path: r"C:\Windows\System32\notepad.exe".into(), created_at_ms: now + 20 });
    let wrong = run(&service, &world, "e2-bind-2", ServiceCommand::OpenEmergencyRoute, json!({"environment_ref": ENV, "session_ref": "e2", "phase": "bind_browser", "browser_pid": 5200}));
    assert_eq!(wrong.code.as_deref(), Some("EMERGENCY_BROWSER_ALREADY_BOUND"));

    let closed = run(&service, &world, "e2-close", ServiceCommand::CloseEmergencyRoute, json!({"environment_ref": ENV, "session_ref": "e2"}));
    assert!(closed.ok, "{closed:?}");
    assert_eq!(closed.receipt["closed_safely"], true);
    assert_eq!(closed.receipt["browser_termination"], "TERMINATED");
    assert_eq!(closed.receipt["route_rules_present"], false);
    assert_eq!(closed.receipt["baseline_restored"], true, "服务自己换回基线配置");
    assert_eq!(closed.receipt["requires_config_reapply"], false);
    assert_eq!(world.lock().unwrap().killed, vec![5100]);
    assert_eq!(observe(&service, &[])["config"]["active_config_sha256"], base.receipt["expected_config_sha256"]);
    assert_eq!(permit(&world), Some(TUN_LUID), "基线回读通过后受管路径重新打开");

    {
        let mut crash = world.lock().unwrap();
        crash.core_pid = crash.next_pid;
        crash.next_pid += 1;
    }
    assert_eq!(observe(&service, &[])["readback"]["status"], "STALE_INSTANCE", "内核换了进程，旧回读不再算数");
    let stale = run(&service, &world, "e3", ServiceCommand::OpenEmergencyRoute, open_request("e3", "firefox.exe"));
    assert_eq!(stale.code.as_deref(), Some("CONFIG_NOT_VERIFIED"));

    let protected_world = new_world();
    let protected_service = open(&protected_world);
    assert!(protect(&protected_service, &protected_world, "p1", ENV, &[CLAUDE, BROWSER]).ok);
    assert!(apply(&protected_service, &protected_world, "a1", SAMPLE_MANAGED_YAML).ok);
    let far = protected_world.lock().unwrap().now + 30 * 60 * 1000;
    let denied = run(&protected_service, &protected_world, "e4", ServiceCommand::OpenEmergencyRoute, json!({"environment_ref": ENV, "session_ref": "e4", "browser_process": "firefox.exe", "expires_at_ms": far}));
    assert_eq!(denied.code.as_deref(), Some("EMERGENCY_HOST_PROTECTED"));
}

fn open_bound_emergency(service: &NetworkService, world: &Shared, session: &str, browser_pid: u32, minutes: i64) -> (Value, Value) {
    assert!(protect(service, world, "p1", ENV, &[CLAUDE]).ok);
    let base = apply(service, world, "base", &baseline());
    assert!(base.ok, "{base:?}");
    let temporary = apply(service, world, "temporary", SAMPLE_MANAGED_YAML);
    assert!(temporary.ok, "{temporary:?}");
    let now = world.lock().unwrap().now;
    let opened = run(service, world, session, ServiceCommand::OpenEmergencyRoute, json!({"environment_ref": ENV, "session_ref": session, "browser_process": "firefox.exe", "expires_at_ms": now + minutes * 60 * 1000}));
    assert!(opened.ok, "{opened:?}");
    world.lock().unwrap().processes.insert(browser_pid, firefox(browser_pid, now + 5));
    let bound = run(service, world, &format!("{session}-bind"), ServiceCommand::OpenEmergencyRoute, json!({"environment_ref": ENV, "session_ref": session, "phase": "bind_browser", "browser_pid": browser_pid}));
    assert!(bound.ok, "{bound:?}");
    (base.receipt, temporary.receipt)
}

#[test]
fn emergency_expiry_is_enforced_by_the_service_tick_without_the_host_or_page() {
    let world = new_world();
    let service = open(&world);
    let (base, _) = open_bound_emergency(&service, &world, "em-1", 5100, 15);
    advance(&world, 14 * 60 * 1000);
    assert!(service.tick()["actions"].as_array().unwrap().is_empty(), "未到期不动");

    advance(&world, 2 * 60 * 1000);
    world.lock().unwrap().calls.clear();
    let ticked = service.tick();
    let action = ticked["actions"][0].clone();
    assert_eq!(action["action"], "emergency_expired");
    assert_eq!(action["ok"], true, "{ticked}");
    let made = calls(&world);
    assert!(position(&made, "path.close") < position(&made, "process.terminate"), "到期先 fail closed：{made:?}");
    assert!(position(&made, "process.terminate") < position(&made, "core.load"), "再结束浏览器、回收规则：{made:?}");
    assert_eq!(world.lock().unwrap().killed, vec![5100]);
    assert_eq!(action["receipt"]["route_rules_present"], false);
    assert_eq!(action["receipt"]["reason"], "EXPIRED");
    let runtime = observe(&service, &[]);
    assert_eq!(runtime["emergency"][0]["open"], false);
    assert_eq!(runtime["emergency"][0]["closed_safely"], true);
    assert_eq!(runtime["config"]["active_config_sha256"], base["expected_config_sha256"]);
    assert_eq!(runtime["config"]["emergency_config_ref"], Value::Null);
    assert!(world.lock().unwrap().loaded.as_deref().unwrap_or_default().contains("CLAUDE-FIXED"), "内核在跑基线配置");
    assert!(!world.lock().unwrap().loaded.as_deref().unwrap_or_default().contains("support.example"), "内核里不再有应急规则");
    assert!(world.lock().unwrap().persisted.as_ref().map(|state| state["emergency"]["em-1"]["closed_safely"] == json!(true)).unwrap_or(false), "回执落盘");
}

#[test]
fn an_expired_session_is_closed_after_the_host_and_service_restart_and_a_reused_pid_is_not_killed() {
    let world = new_world();
    let service = open(&world);
    open_bound_emergency(&service, &world, "em-2", 5100, 15);
    drop(service);
    reboot(&world);
    {
        let mut guard = world.lock().unwrap();
        guard.processes.insert(5100, ProcessIdentity { pid: 5100, image_path: r"C:\Windows\System32\notepad.exe".into(), created_at_ms: guard.now + 60_000 });
    }
    let reopened = open(&world);
    reopened.recover_after_start();
    advance(&world, 16 * 60 * 1000);
    let ticked = reopened.tick();
    let action = ticked["actions"][0].clone();
    assert_eq!(action["action"], "emergency_expired");
    assert_eq!(action["receipt"]["browser_termination"], "IDENTITY_MISMATCH_NOT_KILLED", "PID 已被别的程序复用，不强杀");
    assert!(world.lock().unwrap().killed.is_empty());
    assert!(world.lock().unwrap().processes.contains_key(&5100), "无关进程还在");
    assert_eq!(action["receipt"]["route_rules_present"], false, "服务重启后内核没有自动加载应急配置");
    let runtime = observe(&reopened, &[]);
    assert_eq!(runtime["emergency"][0]["open"], false);

    let late = run(&reopened, &world, "late-close", ServiceCommand::CloseEmergencyRoute, json!({"environment_ref": ENV, "session_ref": "em-2"}));
    assert!(late.ok, "宿主重开后关闭仍能从服务状态找到会话：{late:?}");
    assert_eq!(late.receipt["already_closed"], true);
}

#[test]
fn a_failed_browser_termination_keeps_the_session_open_and_is_not_reported_as_safely_closed() {
    let world = new_world();
    let service = open(&world);
    open_bound_emergency(&service, &world, "em-3", 5100, 15);
    world.lock().unwrap().terminate_fails = true;
    let closed = run(&service, &world, "em-3-close", ServiceCommand::CloseEmergencyRoute, json!({"environment_ref": ENV, "session_ref": "em-3"}));
    assert!(!closed.ok);
    assert_eq!(closed.code.as_deref(), Some("PROCESS_TERMINATE_FAILED_5"));
    assert_eq!(closed.receipt["closed"], false);
    assert_eq!(closed.receipt["closed_safely"], false);
    assert_eq!(observe(&service, &[])["emergency"][0]["open"], true, "没结束浏览器就不标成关闭");

    world.lock().unwrap().terminate_fails = false;
    advance(&world, 16 * 60 * 1000);
    let ticked = service.tick();
    assert_eq!(ticked["actions"][0]["ok"], true, "到期时常驻路径再次尝试：{ticked}");
    assert_eq!(world.lock().unwrap().killed, vec![5100]);
    assert_eq!(permit(&world), Some(TUN_LUID), "应急配置早已换回基线，结束会话时不关已回读的受管路径");
}

#[test]
fn an_emergency_config_without_a_bound_session_is_retired_by_the_tick() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    let base = apply(&service, &world, "base", &baseline());
    assert!(apply(&service, &world, "temporary", SAMPLE_MANAGED_YAML).ok);
    advance(&world, EMERGENCY_UNBOUND_TTL_MS + 1);
    let ticked = service.tick();
    assert_eq!(ticked["actions"][0]["action"], "emergency_config_unbound_expired");
    assert_eq!(ticked["actions"][0]["baseline_restored"], true);
    assert_eq!(observe(&service, &[])["config"]["active_config_sha256"], base.receipt["expected_config_sha256"]);

    let orphan_world = new_world();
    let orphan = open(&orphan_world);
    assert!(protect(&orphan, &orphan_world, "p1", ENV, &[CLAUDE]).ok);
    assert!(apply(&orphan, &orphan_world, "temporary", SAMPLE_MANAGED_YAML).ok);
    advance(&orphan_world, EMERGENCY_UNBOUND_TTL_MS + 1);
    let retired = orphan.tick();
    assert_eq!(retired["actions"][0]["core_stopped"], true, "没有基线可换就停内核，应急规则不留");
    assert!(!orphan_world.lock().unwrap().core_running);
    assert_eq!(observe(&orphan, &[])["protection"]["effective"], true, "停内核不撤阻断");
}

#[test]
fn envelopes_are_checked_before_any_backend_call() {
    let world = new_world();
    let service = open(&world);
    let (path, sha) = draft(&world, "a1", &baseline());
    let payload = apply_payload(&path, &sha);

    let mut unsigned = signed(&world, "a1", ServiceCommand::ApplyConfig, payload.clone());
    unsigned.envelope = None;
    assert_eq!(service.handle(ServiceCommand::ApplyConfig, &unsigned, KEY).code.as_deref(), Some("AUTHORIZATION_REQUIRED"));
    let forged = signed_with(b"attacker-chosen-key-000000000000000000000000", &world, "a1", ServiceCommand::ApplyConfig, payload.clone());
    assert_eq!(service.handle(ServiceCommand::ApplyConfig, &forged, KEY).code.as_deref(), Some("AUTHORIZATION_INVALID"));
    let mut other_product = signed(&world, "a1", ServiceCommand::ApplyConfig, payload.clone());
    other_product.product_id = "another.desktop".into();
    assert_eq!(service.handle(ServiceCommand::ApplyConfig, &other_product, KEY).code.as_deref(), Some("PRODUCT_IDENTITY_MISMATCH"));
    let mut other_protocol = signed(&world, "a1", ServiceCommand::ApplyConfig, payload.clone());
    other_protocol.protocol = "steward-network-service-0".into();
    assert_eq!(service.handle(ServiceCommand::ApplyConfig, &other_protocol, KEY).code.as_deref(), Some("PROTOCOL_MISMATCH"));
    let wrong_command = signed(&world, "a1", ServiceCommand::ValidateConfig, payload.clone());
    assert_eq!(service.handle(ServiceCommand::ApplyConfig, &wrong_command, KEY).code.as_deref(), Some("AUTHORIZATION_COMMAND_MISMATCH"));
    let expired = signed(&world, "a1", ServiceCommand::ApplyConfig, payload.clone());
    advance(&world, 3 * 60 * 1000);
    assert_eq!(service.handle(ServiceCommand::ApplyConfig, &expired, KEY).code.as_deref(), Some("AUTHORIZATION_EXPIRED"));
    let mut escape = payload.clone();
    escape["draft_path"] = json!(std::env::temp_dir().join("elsewhere.yaml").to_string_lossy());
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    let outside = run(&service, &world, "a2", ServiceCommand::ApplyConfig, escape);
    assert_eq!(outside.code.as_deref(), Some("DRAFT_PATH_REJECTED"), "WebView 或宿主都不能指任意文件给服务");
    let made = calls(&world);
    assert!(made.iter().all(|item| item == "protect.ensure"), "授权或路径被拒时不触发后端：{made:?}");
}

#[test]
fn only_the_installed_host_process_may_drive_the_service() {
    let world = new_world();
    let service = open(&world);
    let policy = PeerPolicy { host_image: Some(format!(r"\\?\{HOST}")), service_image: Some(SERVICE.to_string()) };
    let payload = json!({"environment_ref": ENV, "action": "block_new", "processes": [CLAUDE], "reason_code": "APPLY_PRECONDITION"});
    let request = signed(&world, "peer-1", ServiceCommand::EnsureProtection, payload.clone());
    let same_user_tool = PeerProcess { pid: 7001, image_path: Some(r"C:\Users\someone\AppData\Local\Temp\tool.exe".into()) };
    let admin_shell = PeerProcess { pid: 7002, image_path: Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into()) };
    let service_itself = PeerProcess { pid: 7003, image_path: Some(SERVICE.into()) };
    let host = PeerProcess { pid: 7004, image_path: Some(HOST.to_ascii_uppercase()) };

    for (peer, code) in [
        (Some(&same_user_tool), "PEER_NOT_PRODUCT_HOST"),
        (Some(&admin_shell), "PEER_NOT_PRODUCT_HOST"),
        (Some(&service_itself), "PEER_NOT_PRODUCT_HOST"),
        (None, "PEER_IDENTITY_UNAVAILABLE"),
    ] {
        let reply = service.handle_peer(ServiceCommand::EnsureProtection, &request, KEY, &policy, peer);
        assert_eq!(reply.code.as_deref(), Some(code), "同一用户、正确密钥、合法 envelope，调用进程不对就拒绝");
    }
    let read = ServiceRequest { product_id: PRODUCT_APP_ID.into(), protocol: PROTOCOL.into(), envelope: None, payload: json!({"environment_ref": ENV}) };
    assert_eq!(service.handle_peer(ServiceCommand::ObserveRuntime, &read, KEY, &policy, Some(&admin_shell)).code.as_deref(), Some("PEER_NOT_PRODUCT_HOST"));
    assert!(calls(&world).is_empty(), "身份被拒时零后端调用");

    assert!(service.handle_peer(ServiceCommand::Handshake, &read, KEY, &policy, Some(&service_itself)).ok, "新服务实例只能握手判断旧实例是否健康");
    let allowed = service.handle_peer(ServiceCommand::EnsureProtection, &request, KEY, &policy, Some(&host));
    assert!(allowed.ok, "安装记录里的宿主才放行：{allowed:?}");
    assert_eq!(count(&world, "protect.ensure"), 1);

    let unapproved = PeerPolicy { host_image: None, service_image: Some(SERVICE.to_string()) };
    let other = signed(&world, "peer-2", ServiceCommand::EnsureProtection, payload);
    assert_eq!(service.handle_peer(ServiceCommand::EnsureProtection, &other, KEY, &unapproved, Some(&host)).code.as_deref(), Some("HOST_IDENTITY_UNAPPROVED"));
}

#[test]
fn maintenance_refuses_to_stop_the_core_unless_live_protection_covers_every_program() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    assert!(apply(&service, &world, "a1", &baseline()).ok);
    world.lock().unwrap().filters.clear();
    world.lock().unwrap().calls.clear();
    let refused = run(&service, &world, "m0", ServiceCommand::StopCoreForMaintenance, json!({"environment_ref": ENV, "maintenance_ref": "upgrade-0"}));
    assert_eq!(refused.code.as_deref(), Some("PROTECTION_NOT_EFFECTIVE"));
    assert_eq!(refused.receipt["core_stopped"], false);
    assert_eq!(refused.receipt["protection_retained"], false);
    assert_eq!(refused.receipt["side_effects"], false);
    assert!(!calls(&world).contains(&"core.stop".to_string()), "客户端被绕过时服务端也不停内核");
    assert!(world.lock().unwrap().core_running);

    assert!(protect(&service, &world, "p2", ENV, &[CLAUDE]).ok);
    world.lock().unwrap().calls.clear();
    let stopped = run(&service, &world, "m1", ServiceCommand::StopCoreForMaintenance, json!({"environment_ref": ENV, "maintenance_ref": "upgrade-1"}));
    assert!(stopped.ok, "{stopped:?}");
    assert_eq!(stopped.receipt["core_stopped"], true);
    assert_eq!(stopped.receipt["protection_retained"], true, "停内核不等于解除保护");
    let made = calls(&world);
    assert!(position(&made, "path.close") < position(&made, "core.stop"), "先关受管路径再停：{made:?}");
    assert!(!world.lock().unwrap().filters.is_empty());
    assert_eq!(observe(&service, &[])["config"]["active_config_sha256"], Value::Null);
}

#[test]
fn release_requires_paused_business_and_removes_block_and_managed_path() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    assert!(apply(&service, &world, "a1", &baseline()).ok);
    world.lock().unwrap().running_business = vec![CLAUDE.to_string()];
    let release = json!({"environment_ref": ENV, "action": "release_owned", "processes": [CLAUDE], "reason_code": "STOP_MANAGEMENT"});
    let busy = run(&service, &world, "r1", ServiceCommand::EnsureProtection, release.clone());
    assert_eq!(busy.code.as_deref(), Some("PROTECTED_BUSINESS_RUNNING"));
    assert!(!world.lock().unwrap().filters.is_empty(), "业务还在跑就不撤保护");

    world.lock().unwrap().running_business.clear();
    let released = run(&service, &world, "r2", ServiceCommand::EnsureProtection, release);
    assert!(released.ok, "{released:?}");
    assert_eq!(released.receipt["released"], true);
    assert!(world.lock().unwrap().filters.is_empty());
    assert_eq!(permit(&world), None);
    assert_eq!(observe(&service, &[])["protection"]["effective"], false);
}

#[test]
fn start_and_restore_refuse_without_a_verified_last_valid() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    let start = run(&service, &world, "s0", ServiceCommand::StartCore, json!({"environment_ref": ENV}));
    assert_eq!(start.code.as_deref(), Some("LAST_VALID_MISSING"));
    let restored = run(&service, &world, "r0", ServiceCommand::RestoreLastValid, json!({"environment_ref": ENV, "reason_code": "WAKE"}));
    assert_eq!(restored.code.as_deref(), Some("LAST_VALID_MISSING"));
    assert!(!calls(&world).contains(&"core.start".to_string()), "没有 last-valid 就不启动未知默认配置");

    assert!(apply(&service, &world, "a1", &baseline()).ok);
    assert!(run(&service, &world, "m1", ServiceCommand::StopCoreForMaintenance, json!({"environment_ref": ENV, "maintenance_ref": "upgrade-1"})).ok);
    let restarted = run(&service, &world, "s1", ServiceCommand::StartCore, json!({"environment_ref": ENV}));
    assert!(restarted.ok, "{restarted:?}");
    assert_eq!(restarted.receipt["readback"], "VERIFIED");
    assert_eq!(restarted.receipt["managed_path"]["status"], "OPEN");
    assert!(world.lock().unwrap().restart_config.is_some(), "看门狗重启只用回读确认过的配置");

    assert!(run(&service, &world, "m2", ServiceCommand::StopCoreForMaintenance, json!({"environment_ref": ENV, "maintenance_ref": "upgrade-2"})).ok);
    world.lock().unwrap().binary_present = false;
    let missing = run(&service, &world, "s2", ServiceCommand::StartCore, json!({"environment_ref": ENV}));
    assert_eq!(missing.code.as_deref(), Some("CORE_BINARY_MISSING"));
}

#[test]
fn a_write_is_refused_before_any_side_effect_when_its_intent_cannot_be_persisted() {
    let world = new_world();
    let service = open(&world);
    fail_saves_after(&world, 0);
    let refused = protect(&service, &world, "p1", ENV, &[CLAUDE]);
    assert_eq!(refused.code.as_deref(), Some("SERVICE_STATE_UNWRITABLE"));
    assert_eq!(refused.receipt["side_effects"], false);
    assert!(calls(&world).is_empty(), "意图落不了盘就不动 WFP");
    heal_disk(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok, "同一 operation 没有留下记录，磁盘恢复后可以重新发起");
}

#[test]
fn ensure_protection_whose_result_is_not_persisted_is_not_ok_and_reconciles_its_scope_on_restart() {
    let world = new_world();
    let service = open(&world);
    fail_saves_after(&world, 1);
    let unpersisted = protect(&service, &world, "p1", ENV, &[CLAUDE]);
    assert!(!unpersisted.ok, "落盘失败时外层不算成功");
    assert_eq!(unpersisted.code.as_deref(), Some("STATE_PERSIST_FAILED"));
    assert_eq!(unpersisted.receipt["inner_ok"], true);
    assert_eq!(unpersisted.receipt["side_effects"], true);
    assert_eq!(unpersisted.receipt["recovery"]["status"], "RECONCILE_ON_RESTART");
    assert!(!world.lock().unwrap().filters.is_empty(), "过滤器已经装上");

    drop(service);
    heal_disk(&world);
    world.lock().unwrap().calls.clear();
    let reopened = open(&world);
    let recovered = reopened.recover_after_start();
    assert_eq!(recovered["protection"][0]["effective"], true, "意图里的范围并回保护记录，按实际回读确认");
    assert_eq!(recovered["indeterminate"][0]["command"], "EnsureProtection");
    let replay = protect(&reopened, &world, "p1", ENV, &[CLAUDE]);
    assert_eq!(replay.code.as_deref(), Some("OPERATION_INDETERMINATE"), "不盲目重放");
    assert_eq!(count(&world, "protect.ensure"), 1, "只有启动恢复做了一次");
    assert!(protect(&reopened, &world, "p1-new", ENV, &[CLAUDE]).ok);
}

#[test]
fn apply_whose_result_is_not_persisted_is_not_ok_and_is_neither_replayed_nor_auto_restored() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    fail_saves_after(&world, 1);
    let unpersisted = apply(&service, &world, "a1", &baseline());
    assert_eq!(unpersisted.code.as_deref(), Some("STATE_PERSIST_FAILED"));
    assert_eq!(unpersisted.receipt["inner_ok"], true);
    assert_eq!(unpersisted.receipt["overall"], "VERIFIED", "原回执保留，外层不算成功");
    let loads = count(&world, "core.load");

    drop(service);
    heal_disk(&world);
    reboot(&world);
    let reopened = open(&world);
    let recovered = reopened.recover_after_start();
    assert_eq!(recovered["core"]["started"], false);
    let runtime = observe(&reopened, &[]);
    assert_eq!(runtime["config"]["last_valid_config_ref"], Value::Null, "没落盘的 last-valid 不凭内存补");
    assert_eq!(runtime["recovery"]["indeterminate"][0]["command"], "ApplyConfig");
    let (path, sha) = draft(&world, "a1", &baseline());
    let replay = reopened.handle(ServiceCommand::ApplyConfig, &signed(&world, "a1", ServiceCommand::ApplyConfig, apply_payload(&path, &sha)), KEY);
    assert_eq!(replay.code.as_deref(), Some("OPERATION_INDETERMINATE"));
    assert_eq!(count(&world, "core.load"), 0);
    assert_eq!(loads, 1);
}

#[test]
fn maintenance_whose_result_is_not_persisted_is_not_ok_and_the_restart_does_not_start_the_core() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    assert!(apply(&service, &world, "a1", &baseline()).ok);
    fail_saves_after(&world, 1);
    let unpersisted = run(&service, &world, "m1", ServiceCommand::StopCoreForMaintenance, json!({"environment_ref": ENV, "maintenance_ref": "upgrade-1"}));
    assert_eq!(unpersisted.code.as_deref(), Some("STATE_PERSIST_FAILED"));
    assert_eq!(unpersisted.receipt["core_stopped"], true);
    assert_eq!(unpersisted.receipt["protection_retained"], true);

    drop(service);
    heal_disk(&world);
    reboot(&world);
    let reopened = open(&world);
    let recovered = reopened.recover_after_start();
    assert!(!calls(&world).contains(&"core.start".to_string()));
    assert_eq!(recovered["protection"][0]["effective"], true);
    assert_eq!(observe(&reopened, &[])["recovery"]["indeterminate"][0]["command"], "StopCoreForMaintenance");
}

#[test]
fn an_emergency_close_that_is_not_persisted_leaves_the_session_open_for_the_tick() {
    let world = new_world();
    let service = open(&world);
    open_bound_emergency(&service, &world, "em-4", 5100, 15);
    fail_saves_after(&world, 1);
    let unpersisted = run(&service, &world, "em-4-close", ServiceCommand::CloseEmergencyRoute, json!({"environment_ref": ENV, "session_ref": "em-4"}));
    assert_eq!(unpersisted.code.as_deref(), Some("STATE_PERSIST_FAILED"));
    assert_eq!(unpersisted.receipt["inner_ok"], true);

    drop(service);
    heal_disk(&world);
    reboot(&world);
    world.lock().unwrap().processes.insert(5100, firefox(5100, 1_800_000_000_005));
    let reopened = open(&world);
    reopened.recover_after_start();
    let runtime = observe(&reopened, &[]);
    assert_eq!(runtime["emergency"][0]["open"], true, "磁盘上会话仍是打开的");
    assert_eq!(runtime["emergency"][0]["close_indeterminate"], true);
    advance(&world, 16 * 60 * 1000);
    let ticked = reopened.tick();
    assert_eq!(ticked["actions"][0]["action"], "emergency_expired");
    assert_eq!(ticked["actions"][0]["ok"], true);
}

#[test]
fn owned_process_records_end_only_the_process_they_still_identify() {
    let world = new_world();
    let probe = FakeProbe(world.clone());
    let core = ProcessIdentity { pid: 6100, image_path: r"C:\Program Files\AI Environmental Steward\core\mihomo-windows-amd64-v1.19.30.exe".into(), created_at_ms: 1_700_000_000_000 };
    let record = serde_json::to_vec(&core).unwrap();

    world.lock().unwrap().processes.insert(6100, ProcessIdentity { image_path: format!(r"\\?\{}", core.image_path.to_ascii_uppercase()), ..core.clone() });
    let ended = end_owned_process(&probe, &record);
    assert_eq!(ended, OwnedProcessEnd::Terminated, "正确身份才结束");
    assert!(ended.record_resolved());
    assert_eq!(world.lock().unwrap().killed, vec![6100]);

    let gone = end_owned_process(&probe, &record);
    assert_eq!(gone, OwnedProcessEnd::AlreadyGone, "PID 不存在");
    assert!(gone.record_resolved());

    world.lock().unwrap().processes.insert(6100, ProcessIdentity { pid: 6100, image_path: r"C:\Windows\explorer.exe".into(), created_at_ms: 1_700_000_900_000 });
    let reused = end_owned_process(&probe, &record);
    assert_eq!(reused, OwnedProcessEnd::IdentityMismatch, "PID 被另一个程序复用");
    assert!(!reused.record_resolved(), "核验失败保留记录");
    world.lock().unwrap().processes.insert(6100, ProcessIdentity { created_at_ms: core.created_at_ms + 1, ..core.clone() });
    assert_eq!(end_owned_process(&probe, &record), OwnedProcessEnd::IdentityMismatch, "同一程序但创建时间不同也不是原进程");
    assert_eq!(world.lock().unwrap().killed, vec![6100], "复用的 PID 没被结束");

    let terminations = count(&world, "process.terminate");
    for corrupt in [br#"{"pid":6100,"ipc_path":"pipe"}"#.to_vec(), b"not json".to_vec(), br#"{"pid":0,"image_path":"x","created_at_ms":1}"#.to_vec()] {
        let outcome = end_owned_process(&probe, &corrupt);
        assert_eq!(outcome, OwnedProcessEnd::RecordCorrupt, "记录损坏");
        assert!(!outcome.record_resolved());
    }
    assert_eq!(count(&world, "process.terminate"), terminations, "读不懂的记录不触发任何结束动作");
    assert!(world.lock().unwrap().processes.contains_key(&6100));
}

#[test]
fn the_host_accepts_only_a_service_pipe_owned_by_local_system() {
    assert!(authorize_service_server(Some("S-1-5-18")).is_ok(), "本产品服务以 LocalSystem 创建并声明所有者");
    for impostor in ["S-1-5-21-1000-2000-3000-1001", "S-1-5-32-544", "S-1-5-19", "S-1-5-20", "s-1-5-18 ", ""] {
        assert_eq!(authorize_service_server(Some(impostor)).unwrap_err().code, "SERVICE_SERVER_NOT_PRODUCT_SERVICE", "{impostor}");
    }
    assert_eq!(authorize_service_server(None).unwrap_err().code, "SERVICE_SERVER_IDENTITY_UNAVAILABLE");
}

fn oauth_endpoint() -> Value {
    json!({"source_process_path": CLAUDE, "transport": "tcp", "address": "127.0.0.1", "port": 43123, "purpose": "oauth_callback"})
}

fn protect_with_loopback(service: &NetworkService, world: &Shared, business: &str, policy: Value) -> ServiceReply {
    run(
        service,
        world,
        business,
        ServiceCommand::EnsureProtection,
        json!({"environment_ref": ENV, "action": "block_new", "processes": [CLAUDE], "loopback_policy": policy, "reason_code": "APPLY_PRECONDITION"}),
    )
}

fn read_protection_receipt(service: &NetworkService) -> Value {
    let request = ServiceRequest { product_id: PRODUCT_APP_ID.into(), protocol: PROTOCOL.into(), envelope: None, payload: json!({"environment_ref": ENV}) };
    let reply = service.handle(ServiceCommand::ReadProtection, &request, KEY);
    assert!(reply.ok, "{reply:?}");
    reply.receipt
}

#[test]
fn block_new_installs_exactly_the_template_endpoints_and_rejects_anything_broader() {
    let world = new_world();
    let service = open(&world);
    let missing = protect(&service, &world, "p-none", ENV, &[CLAUDE]);
    assert!(missing.ok, "{missing:?}");
    assert_eq!(missing.receipt["loopback_policy"]["endpoints"], json!([]), "请求没带策略按空清单：回环全拦");
    assert!(world.lock().unwrap().loopback[ENV].endpoints.is_empty());

    let granted = protect_with_loopback(&service, &world, "p-oauth", json!({"template_version": "template-v2", "endpoints": [oauth_endpoint()]}));
    assert!(granted.ok, "{granted:?}");
    assert_eq!(granted.receipt["loopback_policy"]["template_version"], "template-v2");
    assert_eq!(granted.receipt["loopback_policy"]["endpoints"][0]["port"], 43123);
    let digest = granted.receipt["loopback_policy"]["digest"].as_str().unwrap().to_string();
    assert_eq!(digest.len(), 64);
    assert_eq!(service.snapshot().protection[ENV].loopback.digest, digest, "记录保存本次策略与摘要");
    assert_eq!(world.lock().unwrap().loopback[ENV].digest, digest, "WFP 后端按同一份策略安装");
    let readback = read_protection_receipt(&service);
    assert_eq!(readback["effective"], true);
    assert_eq!(readback["loopback_policy"]["digest"], digest.as_str());

    let reordered = LoopbackPolicy::new(
        Some("template-v2".into()),
        vec![
            LoopbackEndpoint { source_process_path: CLAUDE.into(), transport: "udp".into(), address: "::1".into(), port: 5353, purpose: "discovery".into() },
            LoopbackEndpoint { source_process_path: CLAUDE.into(), transport: "tcp".into(), address: "127.0.0.1".into(), port: 43123, purpose: "oauth_callback".into() },
        ],
    );
    let ordered = LoopbackPolicy::new(Some("template-v2".into()), reordered.endpoints.iter().rev().cloned().collect());
    assert_eq!(reordered.digest, ordered.digest, "摘要与清单顺序无关");
    assert_ne!(LoopbackPolicy::new(Some("template-v3".into()), ordered.endpoints.clone()).digest, ordered.digest, "模板版本进摘要");

    let broader: Vec<(&str, &str, Value)> = vec![
        ("整个 127.0.0.0/8", "address", json!("127.0.0.0/8")),
        ("通配地址", "address", json!("*")),
        ("主机名", "address", json!("localhost")),
        ("带前导零的地址", "address", json!("127.000.000.001")),
        ("非回环地址", "address", json!("192.168.1.10")),
        ("映射形式的 IPv6", "address", json!("::ffff:127.0.0.1")),
        ("端口范围", "port", json!("43000-43200")),
        ("端口通配", "port", json!("*")),
        ("端口 0", "port", json!(0)),
        ("端口越界", "port", json!(70000)),
        ("协议通配", "transport", json!("any")),
        ("程序不在批准范围", "source_process_path", json!(r"C:\Tools\curl.exe")),
        ("用途为空", "purpose", json!("")),
        ("多出字段", "port_range", json!("43000-43200")),
    ];
    for (label, field, value) in broader {
        let mut endpoint = oauth_endpoint();
        endpoint[field] = value;
        let ensures = count(&world, "protect.ensure");
        let reply = protect_with_loopback(&service, &world, &format!("p-bad-{field}-{ensures}-{label}"), json!({"template_version": "template-v2", "endpoints": [endpoint]}));
        assert!(!reply.ok, "{label}");
        assert_eq!(reply.code.as_deref(), Some("LOOPBACK_POLICY_INVALID"), "{label}");
        assert_eq!(reply.receipt["side_effects"], false, "{label}");
        assert_eq!(count(&world, "protect.ensure"), ensures, "{label}：非法策略不碰 WFP");
    }
    let duplicate = protect_with_loopback(&service, &world, "p-dup", json!({"template_version": "template-v2", "endpoints": [oauth_endpoint(), oauth_endpoint()]}));
    assert_eq!(duplicate.code.as_deref(), Some("LOOPBACK_POLICY_INVALID"), "重复端点");
    assert_eq!(service.snapshot().protection[ENV].loopback.digest, digest, "被拒的请求不改记录");
}

#[test]
fn a_shrunk_policy_replaces_the_record_leftovers_fail_readback_and_restart_reinstalls_the_record() {
    let world = new_world();
    let service = open(&world);
    let helper = json!({"source_process_path": CLAUDE, "transport": "tcp", "address": "127.0.0.1", "port": 43200, "purpose": "helper_ipc"});
    assert!(protect_with_loopback(&service, &world, "p-wide", json!({"template_version": "template-v1", "endpoints": [oauth_endpoint(), helper]})).ok);
    let shrunk = protect_with_loopback(&service, &world, "p-narrow", json!({"template_version": "template-v2", "endpoints": [oauth_endpoint()]}));
    assert!(shrunk.ok, "{shrunk:?}");
    let digest = shrunk.receipt["loopback_policy"]["digest"].as_str().unwrap().to_string();
    assert_eq!(service.snapshot().protection[ENV].loopback.endpoints.len(), 1, "策略整份替换，不与旧清单合并");
    assert_eq!(world.lock().unwrap().loopback[ENV].endpoints.len(), 1);

    let leftover = world.lock().unwrap().loopback[ENV].clone();
    let mut widened = leftover.endpoints.clone();
    widened.push(LoopbackEndpoint { source_process_path: CLAUDE.into(), transport: "tcp".into(), address: "127.0.0.1".into(), port: 7897, purpose: "leftover".into() });
    world.lock().unwrap().loopback.insert(ENV.to_string(), LoopbackPolicy { endpoints: widened, ..leftover });
    let readback = read_protection_receipt(&service);
    assert_eq!(readback["effective"], false, "子层里有策略外的回环 permit，保护不算生效");
    assert_eq!(readback["residual"], json!(["tcp|127.0.0.1|7897"]));

    reboot(&world);
    let restarted = open(&world);
    let recovered = restarted.recover_after_start();
    assert_eq!(recovered["protection"][0]["effective"], true, "{recovered}");
    assert_eq!(recovered["protection"][0]["loopback_digest"], digest.as_str(), "重启按记录里的缩减后策略重装");
    assert_eq!(world.lock().unwrap().loopback[ENV].endpoints.len(), 1);

    world.lock().unwrap().running_business.clear();
    let released = run(&restarted, &world, "stop", ServiceCommand::EnsureProtection, json!({"environment_ref": ENV, "action": "release_owned", "processes": [CLAUDE], "reason_code": "STOP_MANAGEMENT"}));
    assert!(released.ok, "{released:?}");
    assert_eq!(released.receipt["remaining_residual"], json!([]));
    assert!(!world.lock().unwrap().loopback.contains_key(ENV), "停止管理连同回环 permit 一起撤");
}

#[test]
fn an_unpersisted_protection_request_restarts_with_an_empty_loopback_policy() {
    let world = new_world();
    let service = open(&world);
    fail_saves_after(&world, 1);
    let unpersisted = protect_with_loopback(&service, &world, "p-lost", json!({"template_version": "template-v2", "endpoints": [oauth_endpoint()]}));
    assert_eq!(unpersisted.code.as_deref(), Some("STATE_PERSIST_FAILED"));
    drop(service);
    heal_disk(&world);
    let reopened = open(&world);
    assert!(reopened.snapshot().protection[ENV].loopback.endpoints.is_empty(), "结果没落盘的请求可能是一次缩减，按空清单对账");
    let recovered = reopened.recover_after_start();
    assert_eq!(recovered["protection"][0]["effective"], true);
    assert!(world.lock().unwrap().loopback[ENV].endpoints.is_empty(), "启动恢复只装空清单");
}

/// 卸载时选了停止管理但保留数据：卸载助手清掉 WFP 之后作废保护请求。回执、last-valid 与批准程序清单都留着，
/// 重装后服务启动不按旧请求把阻断装回去，要等用户重新确认「启用监测与保护」。
#[test]
fn uninstall_revocation_keeps_reports_but_restart_does_not_reapply_protection() {
    let world = new_world();
    let service = open(&world);
    assert!(protect(&service, &world, "p1", ENV, &[CLAUDE]).ok);
    assert!(apply(&service, &world, "a1", &baseline()).ok);
    drop(service);
    reboot(&world);
    {
        let mut guard = world.lock().unwrap();
        let mut state = guard.persisted.clone().unwrap();
        state["pending"] = json!({
            "operation_id": "op-in-flight",
            "command": "EnsureProtection",
            "request_digest": "digest",
            "environment_ref": "env-wsl",
            "action": "block_new",
            "processes": [BROWSER],
            "session_ref": null,
            "started_at_ms": 1
        });
        guard.persisted = Some(state);
    }
    let before = world.lock().unwrap().persisted.clone().unwrap();

    let revoked = revoke_saved_protection(&FakeState(world.clone()), 1_800_000_100_000).unwrap();
    assert_eq!(revoked, 2, "已记录的保护与没落盘的保护意图都作废");
    let after = world.lock().unwrap().persisted.clone().unwrap();
    for (environment_ref, record) in after["protection"].as_object().unwrap() {
        assert_eq!(record["requested"], false, "{environment_ref}");
        assert_eq!(record["effective"], false, "{environment_ref}");
        assert_eq!(record["code"], "UNINSTALL_REVOKED", "{environment_ref}");
    }
    assert_eq!(after["pending"], Value::Null, "没落盘的意图转入待定历史，下次启动不会再被对账成已请求");
    assert!(after["indeterminate"].as_array().unwrap().iter().any(|item| item["operation_id"] == "op-in-flight"));
    assert_eq!(after["last_valid"], before["last_valid"], "last-valid 保留");
    assert_eq!(after["operations"], before["operations"], "回执保留");
    assert_eq!(after["protection"][ENV]["processes"], before["protection"][ENV]["processes"], "批准程序清单保留，重新启用时照用");

    let reopened = open(&world);
    let recovered = reopened.recover_after_start();
    assert_eq!(recovered["protection"], json!([]), "没有仍在请求的保护");
    assert!(!calls(&world).contains(&"protect.ensure".to_string()), "重装后启动不自动装回保护：{:?}", calls(&world));
    assert!(world.lock().unwrap().filters.is_empty());
    let runtime = observe(&reopened, &[]);
    assert_eq!(runtime["protection"]["requested"], false);
    assert_eq!(runtime["protection"]["effective"], false);

    assert!(protect(&reopened, &world, "p2", ENV, &[CLAUDE]).ok, "用户重新确认启用后照常保护");
    assert!(calls(&world).contains(&"protect.ensure".to_string()));

    assert_eq!(revoke_saved_protection(&FakeState(new_world()), 1).unwrap(), 0, "没有状态文件就没有要作废的请求");
    let unwritable = new_world();
    unwritable.lock().unwrap().persisted = Some(before);
    fail_saves_after(&unwritable, 0);
    assert_eq!(revoke_saved_protection(&FakeState(unwritable.clone()), 1).unwrap_err().code, "SERVICE_STATE_UNWRITABLE", "写不进就如实报错，卸载随后中止");
}
