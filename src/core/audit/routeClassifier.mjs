const LEGACY_DOMAINS = [
  'claude.ai',
  'claude.com',
  'anthropic.com',
  'clau.de',
  'claudeusercontent.com',
  'claudemcpclient.com',
  'claudemcpcontent.com',
];

const LEGACY_HELPERS = new Set(['chrome.exe', 'github-mcp-server.exe', 'chrome-native-host.exe']);
const ERROR_OUTCOMES = new Set(['timeout', 'timed_out', 'closed', 'connection_closed', 'error', 'failed']);

function normalizeProcess(value) {
  return String(value || '').split(/[\\/]/).at(-1).toLowerCase();
}

function normalizeHost(value) {
  return String(value || '')
    .trim()
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/:\d+$/, '')
    .replace(/\.$/, '')
    .toLowerCase();
}

function matchesDomain(host, domains) {
  return domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function normalizeExpectedFixedA(fixedA) {
  if (typeof fixedA === 'string') {
    return {route: fixedA, member: null};
  }
  return {route: fixedA?.route || null, member: fixedA?.member || null};
}

function chainParts(record) {
  const chain = Array.isArray(record.chain) ? record.chain : [];
  return {
    route: String(record.route || record.outbound || chain[0] || '').trim(),
    member: String(record.member || chain[1] || '').trim() || null,
  };
}

function scopeFor(record, mapping) {
  const process = normalizeProcess(record.process);
  const host = normalizeHost(record.destination || record.target);
  const domainInScope = matchesDomain(host, mapping.domains || LEGACY_DOMAINS);
  const claudeProcess = process.includes('claude');
  const managedBrowser = new Set((mapping.managedBrowserProcesses || []).map(normalizeProcess));
  const legacyProcess = claudeProcess || LEGACY_HELPERS.has(process);
  const processInScope = mapping.version === 'legacy-v2'
    ? legacyProcess
    : claudeProcess || managedBrowser.has(process);
  return {process, host, inScope: processInScope || domainInScope, domainInScope, processInScope};
}

export function classifyRoute(record, mapping = {}) {
  const version = mapping.version || 'product-v1';
  if (!['legacy-v2', 'product-v1'].includes(version)) {
    throw new Error(`unsupported classification version: ${version}`);
  }
  const normalizedMapping = {...mapping, version};
  const scope = scopeFor(record, normalizedMapping);
  const {route, member} = chainParts(record);
  const outcome = String(record.outcome || '').trim().toLowerCase();
  const expected = normalizeExpectedFixedA(mapping.fixedA);
  const base = {
    classificationVersion: version,
    process: scope.process || null,
    destination: scope.host || null,
    route: route || null,
    member,
    inScope: scope.inScope,
  };

  if (!scope.inScope) {
    return {...base, classification: 'UNKNOWN', reason: 'OUT_OF_SCOPE'};
  }
  if (!route) {
    return {...base, classification: 'UNKNOWN', reason: 'MISSING_ROUTE'};
  }
  if (route.toUpperCase() === 'REJECT') {
    return {...base, classification: 'SAFE_REJECT', reason: 'EXPLICIT_REJECT'};
  }
  // 产品配置在额度暂停时让 CLAUDE-FIXED 只选 REJECT，日志打印为 CLAUDE-FIXED[REJECT]：组内选中拒绝同样是明确拒绝。旧 v2 口径不变。
  if (version === 'product-v1' && member && member.toUpperCase() === 'REJECT') {
    return {...base, classification: 'SAFE_REJECT', reason: 'GROUP_SELECTED_REJECT'};
  }
  if (!expected.route) {
    return {...base, classification: 'UNKNOWN', reason: 'MISSING_EXPECTED_ROUTE'};
  }
  if (route !== expected.route || (expected.member && member && member !== expected.member)) {
    return {...base, classification: 'WRONG_ROUTE', reason: 'UNAPPROVED_ROUTE'};
  }
  if (!outcome) {
    return {...base, classification: 'UNKNOWN', reason: 'MISSING_OUTCOME'};
  }
  if (ERROR_OUTCOMES.has(outcome)) {
    return {...base, classification: 'ROUTE_ERROR', reason: 'FIXED_ROUTE_ERROR'};
  }
  if (expected.member && member !== expected.member) {
    return {...base, classification: 'UNKNOWN', reason: 'MISSING_ROUTE_MEMBER'};
  }
  if (outcome !== 'connected' && outcome !== 'accepted' && outcome !== 'rejected') {
    return {...base, classification: 'UNKNOWN', reason: 'UNRECOGNIZED_OUTCOME'};
  }
  return {
    ...base,
    classification: 'PASS_ROUTE',
    reason: 'EXPECTED_ROUTE_CONNECTED',
    legacyOldProcessObserved: version === 'legacy-v2' && /^claude\.exe\.old\.\d+$/.test(scope.process),
  };
}

/**
 * Mihomo 经 logrus TextFormatter 输出：`time="…" level=info msg="[TCP] 源(进程) --> 目标 … using 组[成员]"`，
 * 含空格的 msg 带引号、内部引号转义为 \"。先取出 msg 正文再解析，否则末尾引号会粘进路由名。
 * 没有 msg= 字段的行（旧 v2 合成样例）按整行解析，结果与此前一致。
 */
function messageOf(source) {
  const quoted = source.match(/\bmsg="((?:[^"\\]|\\.)*)"/);
  if (quoted) return quoted[1].replace(/\\(["\\])/g, '$1');
  return source.match(/\bmsg=(\S+)/)?.[1] ?? source;
}

export function parseRouteLogLine(line) {
  const source = String(line || '');
  const timestamp = source.match(/time="([^"]+)"/)?.[1] || null;
  const message = messageOf(source);
  const process = message.match(/\(([^()]+)\)\s+-->/)?.[1] || null;
  const destination = message.match(/-->\s+([^\s"]+)/)?.[1] || null;
  const using = message.match(/\busing\s+([^\s\[]+)(?:\[([^\]]+)\])?/i);
  const dial = message.match(/\bdial\s+([^\s\[(]+)(?:\[([^\]]+)\])?/i);
  const route = dial?.[1] || using?.[1] || null;
  const member = dial?.[2] || using?.[2] || null;
  const outcome = /timeout|timed out|context deadline exceeded|closed network|connection.*closed|connection refused|network is unreachable|error:/i.test(message)
    ? 'timeout'
    : route
      ? 'connected'
      : '';
  return {timestamp, process, destination, chain: [route, member].filter(Boolean), outcome};
}

export function classifyLogLine(line, mapping) {
  return classifyRoute(parseRouteLogLine(line), mapping);
}
