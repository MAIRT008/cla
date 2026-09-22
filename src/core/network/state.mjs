import {PROOF_SIMULATION, RECORD} from './constants.mjs';
import {nowIso} from './time.mjs';
import {stateId} from './apply.mjs';

export async function readNetworkState(request = {}, ports = {}) {
  const now = nowIso(ports.clock);
  const stored = ports.store?.getRecord?.(stateId(request), RECORD.STATE) || ports.store?.getRecord?.(stateId(request));
  const core = ports.core?.snapshot ? ports.core.snapshot() : null;
  let loaded = stored?.loaded || {loaded_version: null};
  const inconsistencies = [...(loaded.inconsistencies || [])];
  if (ports.core?.getConfigs) {
    const general = await ports.core.getConfigs();
    const rules = await ports.core.getRules();
    const proxies = await ports.core.getProxies();
    const version = await ports.core.getVersion();
    if (general.loaded_version) inconsistencies.push('UNEXPECTED_LOADED_VERSION_FIELD');
    loaded = {
      loaded_version: null,
      kernel_version: version.version || null,
      general: general.general,
      rules: rules.rules || [],
      proxy_names: Object.keys(proxies.proxies || {}),
      inconsistencies,
      core_instance: core,
    };
    if (stored?.expected?.comparable?.rules && rules.rules) {
      const expected = stored.expected.comparable.rules;
      if (expected.length !== rules.rules.length) inconsistencies.push('RULES_MISMATCH');
    }
  }
  const protection = ports.protection?.readback ? await ports.protection.readback() : stored?.protection || {status: 'UNKNOWN'};
  // 产品服务的实际运行记录（服务、核心、配置、回读、保护、应急）；没有服务端口时为 null，不合成。
  const runtime = ports.core?.readRuntime ? await ports.core.readRuntime() : null;
  const quota = request.quotaSnapshot || stored?.quota || {status: 'UNKNOWN'};
  if (quota.authority_status && quota.authority_status !== 'AVAILABLE') {
    quota.node_new_limit_judgment = 'UNAVAILABLE';
  }
  return {
    user_ref: request.user_ref,
    environment_ref: request.environment_ref || stored?.environment_ref || null,
    observed_at: now,
    proof_scope: PROOF_SIMULATION,
    expected: stored?.expected ? {plan_version: stored.expected.plan_version, assignment_version: stored.expected.assignment_version, mode: stored.expected.mode, config_hash: stored.expected.config_hash, matrix: stored.expected.matrix} : null,
    applied: stored?.applied || null,
    loaded,
    verified: stored?.verified || {status: 'UNKNOWN'},
    core_instance: core || stored?.core_instance || null,
    protection,
    runtime,
    emergency: stored?.emergency || null,
    quota,
    protected_process_paths: stored?.protected_process_paths || [],
    loopback_policy: stored?.loopback_policy || {template_version: null, endpoints: []},
    whitelist_active: stored?.mode === 'daily_single_ip',
    environment_unknown: !request.environment_ref && !stored?.environment_ref,
    whole_machine_claim: false,
  };
}
