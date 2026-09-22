export function isAbsoluteWindowsPath(path) {
  return /^(?:[a-zA-Z]:[\\/]|\\\\)/.test(String(path || ''));
}

/** 模板 `loopback_endpoints` 每项只认这五个字段；首版不接受通配、端口范围或网段。 */
export const LOOPBACK_ENDPOINT_FIELDS = Object.freeze(['source_process_path', 'transport', 'address', 'port', 'purpose']);
export const MAX_LOOPBACK_ENDPOINTS = 64;

/**
 * Mihomo 逻辑规则按逗号切子规则载荷、按括号配对找子规则（rules/logic/logic.go、rules/common/base.go）。
 * 程序路径含逗号或括号不配对时，受管配置写不出与 WFP 相同的精确规则，这样的端点在模板校验时就拒绝。
 */
export function expressibleInLogicRule(text) {
  if (String(text).includes(',')) return false;
  let depth = 0;
  for (const char of String(text)) {
    if (char === '(') depth += 1;
    if (char === ')' && --depth < 0) return false;
  }
  return depth === 0;
}

/** 单个精确回环地址：IPv4 只收 127.x.y.z 的规范写法（无前导零），IPv6 只收 `::1`。 */
export function loopbackAddressFamily(address) {
  if (address === '::1') return 6;
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(address));
  if (!match) return null;
  const canonical = match.slice(1).every((octet) => Number(octet) <= 255 && String(Number(octet)) === octet);
  return canonical ? 4 : null;
}

/**
 * 校验模板回环端点。缺失或空清单合法，含义是回环全拦。
 * 任一项不合法时整份清单不合法；调用方按 fail-closed 处理，不挑出「看起来还行」的项。
 */
export function validateLoopbackEndpoints(endpoints, protectedPaths = []) {
  if (endpoints === undefined || endpoints === null) return {ok: true, endpoints: []};
  const invalid = (path, reason) => ({ok: false, code: 'LOOPBACK_ENDPOINTS_INVALID', path, reason, endpoints: []});
  if (!Array.isArray(endpoints)) return invalid('loopback_endpoints', '必须是数组');
  if (endpoints.length > MAX_LOOPBACK_ENDPOINTS) return invalid('loopback_endpoints', `最多 ${MAX_LOOPBACK_ENDPOINTS} 项`);
  const approved = (Array.isArray(protectedPaths) ? protectedPaths : []).map((item) => String(item).toLowerCase());
  const seen = new Set();
  const normalized = [];
  for (const [index, item] of endpoints.entries()) {
    const at = `loopback_endpoints[${index}]`;
    if (!item || typeof item !== 'object' || Array.isArray(item)) return invalid(at, '必须是对象');
    const unknown = Object.keys(item).find((key) => !LOOPBACK_ENDPOINT_FIELDS.includes(key));
    if (unknown) return invalid(`${at}.${unknown}`, '不是认识的字段');
    const source = item.source_process_path;
    if (typeof source !== 'string' || source.length > 512 || !isAbsoluteWindowsPath(source) || source.includes('..')) {
      return invalid(`${at}.source_process_path`, '必须是绝对程序路径');
    }
    if (!expressibleInLogicRule(source)) {
      return invalid(`${at}.source_process_path`, '含逗号或括号不配对，受管配置的逻辑规则无法原样表达');
    }
    if (!approved.includes(source.toLowerCase())) return invalid(`${at}.source_process_path`, '必须属于 protected_process_paths');
    if (item.transport !== 'tcp' && item.transport !== 'udp') return invalid(`${at}.transport`, '只能是 tcp 或 udp');
    if (typeof item.address !== 'string' || !loopbackAddressFamily(item.address)) {
      return invalid(`${at}.address`, '只能是单个精确回环地址（127.x.y.z 或 ::1），不接受通配、范围或网段');
    }
    if (!Number.isInteger(item.port) || item.port < 1 || item.port > 65535) return invalid(`${at}.port`, '必须是 1—65535 的单个整数端口');
    if (typeof item.purpose !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(item.purpose)) {
      return invalid(`${at}.purpose`, '必须是小写标识（字母开头，只含字母数字下划线，最长 64）');
    }
    const identity = `${source.toLowerCase()}|${item.transport}|${item.address}|${item.port}`;
    if (seen.has(identity)) return invalid(at, '与前面的端点重复');
    seen.add(identity);
    normalized.push({source_process_path: source, transport: item.transport, address: item.address, port: item.port, purpose: item.purpose});
  }
  return {ok: true, endpoints: normalized};
}

function scope(rawPaths, templateVersion, rawEndpoints) {
  const processes = [...new Set((Array.isArray(rawPaths) ? rawPaths : []).map(String).filter(isAbsoluteWindowsPath))];
  const checked = validateLoopbackEndpoints(rawEndpoints, processes);
  return {processes, loopback_policy: {template_version: templateVersion ?? null, endpoints: checked.endpoints}};
}

/** 策略版本只认分配的 `template_version`（控制端记录版本）；模板正文里的 `version` 不作数，滞后或缺失都不影响。 */
function scopeOf(source) {
  if (source.template?.protected_process_paths) {
    return scope(source.template.protected_process_paths, source.template_version, source.template.loopback_endpoints);
  }
  if (source.protected_process_paths) {
    return scope(source.protected_process_paths, source.loopback_policy?.template_version, source.loopback_policy?.endpoints);
  }
  if (source.expected?.protected_process_paths) {
    return scope(source.expected.protected_process_paths, source.expected.loopback_policy?.template_version, source.expected.loopback_policy?.endpoints);
  }
  if (source.assignment?.template?.protected_process_paths) {
    const {template, template_version: version} = source.assignment;
    return scope(template.protected_process_paths, version, template.loopback_endpoints);
  }
  return null;
}

/** 批准程序与它们的回环端点取自同一个来源（同一份模板），不跨来源拼接。 */
export function approvedProtectionScope(...sources) {
  for (const source of sources) {
    if (!source) continue;
    const found = scopeOf(source);
    if (found?.processes.length) return found;
  }
  return {processes: [], loopback_policy: {template_version: null, endpoints: []}};
}

export function approvedProcessPaths(...sources) {
  return approvedProtectionScope(...sources).processes;
}

export async function resolveApprovedProtection({state, event, assignment, control, userRef} = {}) {
  let currentAssignment = assignment || null;
  const ref = userRef || state?.user_ref || event?.user_ref;
  if (currentAssignment == null && control?.getAssignment && ref) {
    try {
      const loaded = await control.getAssignment(ref);
      currentAssignment = loaded?.assignment ?? null;
    } catch {
      currentAssignment = null;
    }
  }
  if (currentAssignment) return approvedProtectionScope(currentAssignment);
  return approvedProtectionScope(state, event);
}

export async function resolveApprovedProcessPaths(input = {}) {
  return (await resolveApprovedProtection(input)).processes;
}
