import {sha256Hex} from '../../adapters/platform/index.mjs';
import {assertModeAllowed, validateAssignment} from './assignment.mjs';
import {
  CLAUDE_DOMAINS,
  DEFAULT_CLAUDE_PROCESSES,
  DEFAULT_MANAGED_BROWSER_PROCESSES,
  GROUP,
  MODES,
  PRODUCT_CLASSIFICATION_VERSION,
  PROOF_SIMULATION,
} from './constants.mjs';
import {fail} from './errors.mjs';
import {loopbackAddressFamily, validateLoopbackEndpoints} from './protectedProcesses.mjs';
import {nowIso} from './time.mjs';
import {activeWhitelist} from './whitelist.mjs';
import {dumpMihomoConfig, parseMihomoConfig} from './yaml.mjs';

function hashText(value) {
  return sha256Hex(value);
}

function templateOf(assignment) {
  if (!assignment?.template || typeof assignment.template !== 'object') {
    throw fail('TEMPLATE_UNAVAILABLE', 'managed template must come from the control assignment');
  }
  return assignment.template;
}

function resource(assignment, role) {
  const ref = assignment.roles?.[role] || assignment.resource_refs?.[role === 'A' ? 'exit_a' : role === 'B' ? 'exit_b' : 'front'];
  return assignment.resources?.[ref] || null;
}

function proxyEntry(name, item, frontName) {
  if (!item) return null;
  const entry = {
    name,
    type: item.kind || 'socks5',
    server: item.host,
    port: item.port,
    credential_ref: item.credential_ref || null,
  };
  if (frontName && name !== GROUP.FRONT) entry['dialer-proxy'] = frontName;
  return entry;
}

function controlRules(template, proxyPaused) {
  const rules = [];
  const plane = template.control_plane || {};
  for (const key of ['login', 'config', 'model', 'quota', 'ticket', 'support']) {
    for (const item of plane[key] || []) {
      if (!item?.host) continue;
      const outbound = item.path || item.outbound || 'DIRECT';
      if (proxyPaused && outbound !== 'DIRECT' && item.over_quota !== true) continue;
      if (proxyPaused && item.over_quota === true) {
        rules.push(`DOMAIN-SUFFIX,${item.host},DIRECT`);
        continue;
      }
      rules.push(`DOMAIN-SUFFIX,${item.host},${outbound}`);
    }
  }
  return rules;
}

function processRules(names, outbound) {
  return names.map((name) => `PROCESS-NAME,${name},${outbound}`);
}

/**
 * 模板回环端点对应的精确规则：程序、单个回环地址、单端口、协议四项同时满足才 DIRECT。
 * 表达不了的路径已在模板校验里拒绝，这里不会静默跳过任何已接受的端点。
 */
export function loopbackEndpointRules(template) {
  const checked = validateLoopbackEndpoints(template?.loopback_endpoints, template?.protected_process_paths || []);
  if (!checked.ok) throw fail('TEMPLATE_INVALID', `${checked.path} ${checked.reason}`, {path: checked.path});
  const rules = [];
  for (const endpoint of checked.endpoints) {
    const processPath = endpoint.source_process_path.replaceAll('/', '\\');
    const address = loopbackAddressFamily(endpoint.address) === 6 ? `IP-CIDR6,${endpoint.address}/128,no-resolve` : `IP-CIDR,${endpoint.address}/32,no-resolve`;
    rules.push(`AND,((PROCESS-PATH,${processPath}),(${address}),(DST-PORT,${endpoint.port}),(NETWORK,${endpoint.transport})),DIRECT`);
  }
  return rules;
}

const LOOPBACK_ENDPOINT_RULE = /^AND,\(\(PROCESS-PATH,[^,]+\),\((IP-CIDR6?),([^,/]+)\/(32|128),no-resolve\),\(DST-PORT,\d{1,5}\),\(NETWORK,(?:tcp|udp)\)\),DIRECT$/;

function isLoopbackEndpointRule(rule) {
  const match = LOOPBACK_ENDPOINT_RULE.exec(String(rule));
  if (!match) return false;
  const family = loopbackAddressFamily(match[2]);
  return (family === 4 && match[1] === 'IP-CIDR' && match[3] === '32') || (family === 6 && match[1] === 'IP-CIDR6' && match[3] === '128');
}

export function expectedRouteMatrix(mode, {whitelistActive = false, proxyPaused = false, emergency = null} = {}) {
  if (!MODES.includes(mode)) throw fail('MODE_NOT_ALLOWED', `mode ${mode} is unknown`);
  const otherExit = mode === 'claude_dual_ip' ? 'B' : 'A';
  const otherGroup = proxyPaused ? GROUP.REJECT : GROUP.GENERAL;
  return {
    mode,
    claude: {outbound: proxyPaused ? GROUP.REJECT : GROUP.CLAUDE, exit: proxyPaused ? null : 'A', fallback: false, rotate: false},
    whitelist: {outbound: GROUP.DIRECT, enabled: Boolean(whitelistActive && mode === 'daily_single_ip' && !emergency?.disable_whitelist)},
    other: {outbound: otherGroup, exit: proxyPaused ? null : otherExit},
    emergency: emergency ? {outbound: GROUP.EMERGENCY, claude_unchanged: true} : null,
    tun_required: mode !== 'daily_single_ip',
    whitelist_retained: true,
    whitelist_active: Boolean(whitelistActive && mode === 'daily_single_ip'),
  };
}

function capabilitiesOf(input) {
  const capabilities = input || {};
  return {
    tcp: capabilities.tcp !== false,
    udp: capabilities.udp || 'REJECT',
    ipv6: capabilities.ipv6 || 'FOLLOW',
    daily_tun: capabilities.daily_tun === true,
    browser: capabilities.browser !== false,
    code: capabilities.code !== false,
    desktop: capabilities.desktop !== false,
    wsl: capabilities.wsl || 'UNKNOWN',
  };
}

function quotaPaused(snapshot) {
  return Boolean(snapshot && ['LIMITED', 'DISABLED', 'EXPIRED'].includes(snapshot.status));
}

export function staticValidateConfig(config, matrix) {
  const issues = [];
  const groups = config['proxy-groups'] || [];
  if (groups.some((group) => ['url-test', 'fallback', 'load-balance', 'relay'].includes(group.type))) {
    issues.push('ROTATING_GROUP_FORBIDDEN');
  }
  if (groups.some((group) => (group.proxies || []).includes(group.name))) issues.push('RECURSIVE_GROUP');
  const rules = config.rules || [];
  if (!rules.length || !String(rules.at(-1)).startsWith('MATCH,')) issues.push('MATCH_NOT_LAST');
  const claudeIndex = rules.findIndex((rule) => String(rule).includes(`,${GROUP.CLAUDE}`) || String(rule).includes(`,${GROUP.REJECT}`) && String(rule).includes('claude'));
  const whitelistIndex = rules.findIndex((rule) => String(rule).endsWith(`,${GROUP.DIRECT}`) && !String(rule).startsWith('IP-CIDR') && !String(rule).startsWith('SRC-IP-CIDR') && !isLoopbackEndpointRule(rule));
  if (claudeIndex >= 0 && whitelistIndex >= 0 && whitelistIndex < claudeIndex) issues.push('WHITELIST_BEFORE_CLAUDE');
  if (matrix.mode === 'claude_dual_ip' && !quotaPausedMatrix(matrix)) {
    const general = groups.find((group) => group.name === GROUP.GENERAL);
    const claude = groups.find((group) => group.name === GROUP.CLAUDE);
    if (general && claude && JSON.stringify(general.proxies) === JSON.stringify(claude.proxies) && matrix.other.exit === 'B') {
      issues.push('DUAL_IP_NOT_SPLIT');
    }
  }
  if (config.tun?.enable && matrix.mode === 'daily_single_ip' && matrix.tun_required) issues.push('TUN_MISMATCH');
  if (!config.tun?.enable && matrix.tun_required) issues.push('TUN_REQUIRED');
  if (config.ipv6 === false && matrix.ipv6_disabled_machine) issues.push('MACHINE_IPV6_DISABLED');
  return issues;
}

function quotaPausedMatrix(matrix) {
  return matrix.claude.outbound === GROUP.REJECT && matrix.other.outbound === GROUP.REJECT;
}

export function compileNetworkPlan({assignment, mode, whitelist, capabilities, emergencyAccess, quotaSnapshot, environmentScope, now, proofScope = PROOF_SIMULATION} = {}) {
  const observedAt = nowIso(typeof now === 'function' ? now : () => now || nowIso());
  const validation = validateAssignment(assignment, environmentScope, observedAt);
  assertModeAllowed(validation, mode);
  const template = templateOf(assignment);
  const caps = capabilitiesOf(capabilities);
  const paused = quotaPaused(quotaSnapshot);
  const whitelistEntries = activeWhitelist(whitelist, mode);
  const matrix = expectedRouteMatrix(mode, {whitelistActive: whitelistEntries.length > 0, proxyPaused: paused, emergency: emergencyAccess});
  const front = resource(assignment, 'front');
  const exitA = resource(assignment, 'A');
  const exitB = resource(assignment, 'B');
  if (mode === 'claude_dual_ip' && !exitB) throw fail('DUAL_IP_REQUIRES_B', 'dual IP requires an active B exit');
  const proxies = [proxyEntry(GROUP.FRONT, front), proxyEntry(GROUP.EXIT_A, exitA, front ? GROUP.FRONT : null), proxyEntry(GROUP.EXIT_B, exitB, front ? GROUP.FRONT : null)].filter(Boolean);
  const generalMember = paused ? GROUP.REJECT : mode === 'claude_dual_ip' ? GROUP.PROXY_B : GROUP.PROXY_A;
  const claudeMember = paused ? GROUP.REJECT : GROUP.PROXY_A;
  const groups = [
    {name: GROUP.PROXY_A, type: 'select', proxies: [GROUP.EXIT_A]},
    ...(exitB ? [{name: GROUP.PROXY_B, type: 'select', proxies: [GROUP.EXIT_B]}] : []),
    {name: GROUP.CLAUDE, type: 'select', proxies: [claudeMember]},
    {name: GROUP.GENERAL, type: 'select', proxies: [generalMember]},
  ];
  const emergencyMember = emergencyMemberOf(emergencyAccess, paused);
  if (emergencyMember && emergencyMember !== GROUP.DIRECT && emergencyMember !== GROUP.REJECT) {
    groups.push({name: GROUP.EMERGENCY, type: 'select', proxies: [emergencyMember]});
  }
  const rules = [];
  for (const cidr of template.lan_cidrs || []) rules.push(`IP-CIDR,${cidr},DIRECT`);
  rules.push(...loopbackEndpointRules(template));
  if (caps.udp === 'REJECT') rules.push(`NETWORK,udp,${GROUP.REJECT}`);
  else if (caps.udp === 'UNKNOWN') {
    /* 未验证承载保持未知，不改走其他出口 */
  }
  const claudeDomains = template.claude_domains || CLAUDE_DOMAINS;
  const claudeProcesses = [...(template.claude_processes || DEFAULT_CLAUDE_PROCESSES), ...(template.managed_browser_processes || DEFAULT_MANAGED_BROWSER_PROCESSES)];
  rules.push(...processRules(claudeProcesses, GROUP.CLAUDE));
  for (const domain of claudeDomains) rules.push(`DOMAIN-SUFFIX,${domain},${GROUP.CLAUDE}`);
  if (emergencyAccess?.targets?.length) {
    if (!emergencyAccess.process) throw fail('EMERGENCY_HOST_UNAVAILABLE', 'emergency rules require a distinguishable process');
    for (const target of emergencyAccess.targets) {
      const match = target.match === 'exact' ? 'DOMAIN' : 'DOMAIN-SUFFIX';
      if (claudeDomains.some((domain) => target.host === domain || target.host.endsWith(`.${domain}`))) {
        rules.push(`AND,((PROCESS-NAME,${emergencyAccess.process}),(${match},${target.host})),${GROUP.CLAUDE}`);
        continue;
      }
      const outbound = emergencyMember === GROUP.DIRECT || emergencyMember === GROUP.REJECT ? emergencyMember : GROUP.EMERGENCY;
      rules.push(`AND,((PROCESS-NAME,${emergencyAccess.process}),(${match},${target.host})),${outbound}`);
    }
  }
  rules.push(...controlRules(template, paused));
  if (matrix.whitelist.enabled) {
    for (const entry of whitelistEntries) {
      rules.push(entry.match === 'exact' ? `DOMAIN,${entry.host},${GROUP.DIRECT}` : `DOMAIN-SUFFIX,${entry.host},${GROUP.DIRECT}`);
    }
  }
  rules.push(`MATCH,${matrix.other.outbound}`);
  const tunEnable = mode === 'daily_single_ip' ? caps.daily_tun === true : true;
  const config = {
    mode: 'rule',
    'log-level': 'info',
    ipv6: caps.ipv6 !== 'DISABLE',
    'find-process-mode': 'always',
    tun: {
      enable: tunEnable,
      stack: 'system',
      'dns-hijack': ['any:53'],
      'auto-route': tunEnable,
      'auto-detect-interface': tunEnable,
    },
    dns: template.dns,
    proxies,
    'proxy-groups': groups,
    rules,
  };
  const yaml = dumpMihomoConfig(config);
  const parsed = parseMihomoConfig(yaml);
  const issues = staticValidateConfig(parsed, {...matrix, ipv6_disabled_machine: caps.ipv6 === 'DISABLE'});
  if (issues.length) throw fail('CONFIG_STATIC_INVALID', issues.join(','), {issues});
  if (!parsed.proxies?.length && !paused) throw fail('CONFIG_STATIC_INVALID', 'proxies were not serializable');
  const planVersion = `plan:${assignment.assignment_version}:${mode}:${hashText(yaml).slice(0, 12)}`;
  return {
    ok: true,
    proof_scope: proofScope,
    plan_version: planVersion,
    assignment_version: assignment.assignment_version,
    template_version: assignment.template_version || null,
    classification_version: assignment.classification_version || PRODUCT_CLASSIFICATION_VERSION,
    user_ref: assignment.user_ref,
    environment_ref: assignment.environment_ref || environmentScope?.environment_ref || environmentScope || null,
    mode,
    matrix,
    capabilities: {
      ...caps,
      coverage: {
        tcp: caps.tcp ? 'DECLARED' : 'REJECTED',
        udp: caps.udp,
        ipv6: caps.ipv6,
        browser: caps.browser ? 'DECLARED' : 'UNKNOWN',
        code: caps.code ? 'DECLARED' : 'UNKNOWN',
        desktop: caps.desktop ? 'DECLARED' : 'UNKNOWN',
        wsl: caps.wsl,
      },
    },
    whitelist: {
      version: whitelist?.version || 0,
      active: matrix.whitelist.enabled,
      retained: true,
      entries: whitelist?.entries || [],
    },
    metering: {
      user_identity: assignment.user_ref,
      point: 'managed_node',
      chain: {
        front: front ? {ref: front.resource_id || assignment.resource_refs?.front, metering: false} : null,
        A: {ref: assignment.roles?.A || assignment.resource_refs?.exit_a, metering: true, role: 'A'},
        B: mode === 'claude_dual_ip' ? {ref: assignment.roles?.B || assignment.resource_refs?.exit_b, metering: true, role: 'B'} : null,
      },
      shared_upstream_secret: false,
    },
    quota: quotaSnapshot
      ? {
        status: quotaSnapshot.status,
        authority_status: quotaSnapshot.authority_status || 'UNKNOWN',
        control_status: quotaSnapshot.control_status || 'UNKNOWN',
        node_new_limit_judgment: quotaSnapshot.authority_status === 'AVAILABLE' ? (quotaSnapshot.node_new_limit_judgment || 'UNKNOWN') : 'UNAVAILABLE',
        observed_at: quotaSnapshot.observed_at || observedAt,
        proxy_paused: paused,
      }
      : {status: 'UNKNOWN', authority_status: 'UNKNOWN', node_new_limit_judgment: 'UNKNOWN', proxy_paused: false},
    emergency: emergencyAccess ? {session_id: emergencyAccess.session_id, expires_at: emergencyAccess.expires_at, claude_protected: true} : null,
    config,
    yaml,
    config_hash: hashText(yaml),
    comparable: comparableFromConfig(parsed),
    observed_at: observedAt,
  };
}

export function comparableFromConfig(config) {
  return {
    mode: config.mode || null,
    ipv6: config.ipv6 !== false,
    tun: {enable: Boolean(config.tun?.enable)},
    groups: (config['proxy-groups'] || []).map((group) => ({name: group.name, type: group.type, proxies: group.proxies || []})),
    rules: (config.rules || []).map((rule, index) => ruleToComparable(rule, index)),
    proxy_names: (config.proxies || []).map((item) => item.name),
  };
}

function emergencyMemberOf(emergencyAccess, paused) {
  if (!emergencyAccess) return null;
  if (paused && emergencyAccess.over_quota_support) return GROUP.DIRECT;
  if (paused) return GROUP.REJECT;
  if (!emergencyAccess.approved_outbound || emergencyAccess.approved_outbound === GROUP.EMERGENCY) return GROUP.PROXY_A;
  return emergencyAccess.approved_outbound;
}

export function ruleToComparable(rule, index) {
  const text = String(rule);
  if (text.startsWith('AND,')) {
    const match = text.match(/^AND,(\(.*\)),([^,]+)$/);
    return {index, type: 'AND', payload: match?.[1] || '', proxy: match?.[2] || ''};
  }
  const parts = text.split(',');
  if (parts[0] === 'MATCH') return {index, type: 'Match', payload: '', proxy: parts[1]};
  return {index, type: parts[0], payload: parts[1] || '', proxy: parts[2] || parts.at(-1)};
}

export function rulesFromComparable(comparable) {
  return (comparable.rules || []).map((rule) => ({index: rule.index, type: mapMihomoType(rule.type), payload: rule.payload, proxy: rule.proxy, size: -1}));
}

function mapMihomoType(type) {
  const mapping = {
    'DOMAIN-SUFFIX': 'DomainSuffix',
    DOMAIN: 'Domain',
    'PROCESS-NAME': 'Process',
    'IP-CIDR': 'IPCIDR',
    NETWORK: 'Network',
    MATCH: 'Match',
    Match: 'Match',
  };
  return mapping[type] || type;
}

export function explainModeChange(currentPlan, candidatePlan) {
  const current = currentPlan?.mode;
  const next = candidatePlan?.mode;
  const claudeExitUnchanged = currentPlan?.matrix?.claude?.exit === candidatePlan?.matrix?.claude?.exit;
  return {
    from: current || null,
    to: next || null,
    claude_exit_unchanged: claudeExitUnchanged,
    other_exit: {from: currentPlan?.matrix?.other?.exit || null, to: candidatePlan?.matrix?.other?.exit || null},
    whitelist: {from_active: Boolean(currentPlan?.whitelist?.active), to_active: Boolean(candidatePlan?.whitelist?.active), retained: true},
    tun: {from: Boolean(currentPlan?.config?.tun?.enable), to: Boolean(candidatePlan?.config?.tun?.enable)},
    may_interrupt: current !== next,
    shares_exit_with_claude: next !== 'claude_dual_ip',
    sensitive_change: !claudeExitUnchanged,
    proof_scope: candidatePlan?.proof_scope || PROOF_SIMULATION,
  };
}

export function publicPlanView(plan) {
  if (!plan) return null;
  return {
    plan_version: plan.plan_version,
    assignment_version: plan.assignment_version,
    mode: plan.mode,
    matrix: plan.matrix,
    whitelist: {version: plan.whitelist?.version, active: plan.whitelist?.active, retained: true, hosts: (plan.whitelist?.entries || []).map((entry) => ({host: entry.host, match: entry.match, enabled: entry.enabled}))},
    capabilities: plan.capabilities,
    metering: {user_identity: plan.metering?.user_identity, point: plan.metering?.point, chain: plan.metering?.chain},
    quota: plan.quota,
    emergency: plan.emergency,
    config_hash: plan.config_hash,
    comparable: plan.comparable,
    yaml: plan.yaml,
    proof_scope: plan.proof_scope,
  };
}
