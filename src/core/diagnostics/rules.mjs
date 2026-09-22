import {RULESET_VERSION, SUGGESTION} from './constants.mjs';
import {parseIPv4, parseIPv6, timezoneMatch} from './parse.mjs';

const WEIGHT = {critical: 60, important: 20, mild: 3};

function keyMissing(checks) {
  return (checks || []).filter((item) => item.required && item.status === 'MISSING');
}

export function mergeRootCauses(issues) {
  const byId = new Map();
  for (const issue of issues || []) {
    const id = issue.root_cause_id || issue.issue_id;
    const current = byId.get(id);
    if (!current) {
      byId.set(id, {...issue, evidence_refs: [...(issue.evidence_refs || [])]});
      continue;
    }
    const rank = {critical: 3, important: 2, mild: 1};
    if ((rank[issue.severity] || 0) > (rank[current.severity] || 0)) {
      byId.set(id, {...issue, evidence_refs: [...new Set([...(current.evidence_refs || []), ...(issue.evidence_refs || [])])]});
    } else {
      current.evidence_refs = [...new Set([...(current.evidence_refs || []), ...(issue.evidence_refs || [])])];
    }
  }
  return [...byId.values()];
}

export function scoreNetwork(issues, {keyChecks = [], retained = []} = {}) {
  const unique = mergeRootCauses(issues);
  const retainedIds = new Set(retained);
  const active = unique.filter((issue) => !issue.closed);
  let mild = 0;
  let other = 0;
  let hasCritical = false;
  let hasImportant = false;
  for (const issue of active) {
    if (retainedIds.has(issue.issue_id) || retainedIds.has(issue.root_cause_id)) {
      // retained still deducts
    }
    if (issue.severity === 'critical') {
      other += WEIGHT.critical;
      hasCritical = true;
    } else if (issue.severity === 'important') {
      other += WEIGHT.important;
      hasImportant = true;
    } else if (issue.severity === 'mild') {
      mild += WEIGHT.mild;
    }
  }
  mild = Math.min(15, mild);
  let score = Math.max(0, 100 - other - mild);
  if (hasCritical) score = Math.min(39, score);
  else if (hasImportant) score = Math.min(79, score);
  const missing = keyMissing(keyChecks);
  return {
    ruleset: RULESET_VERSION,
    candidate: true,
    official_risk_claim: false,
    score: missing.length ? null : score,
    status: missing.length ? 'INCOMPLETE' : 'SCORED',
    has_critical: hasCritical,
    has_important: hasImportant,
    unique_issues: unique,
    missing_key_checks: missing.map((item) => item.check_id),
  };
}

export function classifyIssue(kind, evidence) {
  if (kind === 'PROTECTED_BYPASS_A') return {severity: 'critical', root_cause_id: 'bypass-approved-a', suggestion: SUGGESTION.DIRECT};
  if (kind === 'PROTECTION_FAILED_NEW_CONNECTION') return {severity: 'critical', root_cause_id: 'protection-failed', suggestion: SUGGESTION.DIRECT};
  if (kind === 'FIXED_CHAIN_UNAVAILABLE') return {severity: 'important', root_cause_id: 'fixed-chain', suggestion: SUGGESTION.CONDITIONAL};
  if (kind === 'DNS_PATH_VIOLATION') return {severity: 'important', root_cause_id: evidence?.same_as_bypass ? 'bypass-approved-a' : 'dns-path', suggestion: SUGGESTION.DIRECT};
  if (kind === 'TIMEZONE_MISMATCH') return {severity: 'mild', root_cause_id: 'locale-mismatch', suggestion: SUGGESTION.DIRECT};
  if (kind === 'BROWSER_TIMEZONE_MISMATCH') return {severity: 'mild', root_cause_id: 'locale-mismatch', suggestion: SUGGESTION.DIRECT};
  if (kind === 'WEBRTC_UNAPPROVED_ADDRESS') return {severity: 'important', root_cause_id: 'webrtc-exposure', suggestion: SUGGESTION.CONDITIONAL};
  if (kind === 'LATENCY_BASELINE') return {severity: 'mild', root_cause_id: 'latency', suggestion: SUGGESTION.REFERENCE};
  if (kind === 'INTEL_TAG') return {severity: null, root_cause_id: 'intel-only', suggestion: SUGGESTION.REFERENCE};
  return {severity: 'mild', root_cause_id: kind, suggestion: SUGGESTION.REFERENCE};
}

export function suggestionFor(issue) {
  if (issue.severity === 'critical' || issue.severity === 'important') return issue.supported ? SUGGESTION.DIRECT : SUGGESTION.CONDITIONAL;
  if (!issue.severity) return SUGGESTION.REFERENCE;
  return issue.supported ? SUGGESTION.DIRECT : SUGGESTION.REFERENCE;
}

/** 公网地址：私有、回环、链路本地、运营商 NAT 与 ULA 都不算。 */
function isPublicAddress(address) {
  const v4 = parseIPv4(address);
  if (v4) {
    const [a, b] = v4.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    return true;
  }
  const v6 = parseIPv6(address);
  if (!v6) return false;
  const lower = v6.toLowerCase();
  return !(lower === '::' || lower === '::1' || /^f[cd]/.test(lower) || /^fe[89ab]/.test(lower));
}

/**
 * 默认浏览器回传的规则：时区按分配的期望比，WebRTC 候选里出现分配出口以外的公网地址算暴露。
 * 证据来源标成 default_browser；WebView 自己的取样另标 webview，不当成用户浏览器的证据。
 * 语言只记录不评分：分配里没有期望语言。
 */
export function issuesFromBrowserSample(observation, {expected, task_id} = {}) {
  const issues = [];
  if (observation?.check_id !== 'browser.session-sample' || !observation.actual) return issues;
  const platform = observation.actual.platform;
  if (platform) {
    const match = timezoneMatch({
      iana: platform.timezone,
      offsetMinutes: platform.utc_offset_minutes,
      expectedIana: expected?.timezone,
      expectedOffsetMinutes: expected?.utc_offset_minutes,
    });
    if (match.iana_equal === false) {
      issues.push({
        issue_id: `${task_id}:browser-tz:${observation.evidence_ref}`,
        kind: 'BROWSER_TIMEZONE_MISMATCH',
        evidence_refs: [observation.evidence_ref],
        evidence_source: 'default_browser',
        actual: {timezone: platform.timezone, expected: expected?.timezone || null},
        ...classifyIssue('BROWSER_TIMEZONE_MISMATCH'),
        supported: true,
      });
    }
  }
  const approved = new Set([expected?.A, expected?.B].filter(Boolean));
  const exposed = (observation.actual.ice?.candidates || [])
    .filter((candidate) => !candidate?.mdns && candidate?.address && isPublicAddress(candidate.address) && !approved.has(candidate.address));
  if (approved.size && exposed.length) {
    issues.push({
      issue_id: `${task_id}:browser-webrtc:${observation.evidence_ref}`,
      kind: 'WEBRTC_UNAPPROVED_ADDRESS',
      evidence_refs: [observation.evidence_ref],
      evidence_source: 'default_browser',
      actual: {addresses: [...new Set(exposed.map((candidate) => candidate.address))], candidate_types: [...new Set(exposed.map((candidate) => candidate.type))]},
      ...classifyIssue('WEBRTC_UNAPPROVED_ADDRESS'),
      supported: false,
    });
  }
  return issues;
}

export function issuesFromObservations(observations = [], {expected, task_id} = {}) {
  const issues = [];
  const echo = observations.find((item) => item.check_id === 'exit.echo');
  const actual = echo?.actual;
  const unapprovedExit = echo?.status === 'OBSERVED' && expected?.A && actual && actual !== expected.A && actual !== expected.B;
  if (unapprovedExit) {
    issues.push({
      issue_id: `${task_id}:bypass`,
      kind: 'PROTECTED_BYPASS_A',
      evidence_refs: [echo.evidence_ref],
      ...classifyIssue('PROTECTED_BYPASS_A'),
      supported: true,
    });
  }
  const probe = observations.find((item) => item.check_id === 'dns.probe');
  const approvedResolvers = expected?.dns_resolvers || [];
  const resolver = probe?.actual?.resolver_ip;
  if (probe?.status === 'OBSERVED' && approvedResolvers.length && resolver && !approvedResolvers.includes(resolver)) {
    issues.push({
      issue_id: `${task_id}:dns-path`,
      kind: 'DNS_PATH_VIOLATION',
      evidence_refs: [probe.evidence_ref],
      ...classifyIssue('DNS_PATH_VIOLATION', {same_as_bypass: unapprovedExit}),
      supported: true,
    });
  }
  const kernel = observations.find((item) => item.check_id === 'kernel.state');
  const protection = kernel?.actual?.protection || {};
  if (protection.status === 'FAILED' && protection.new_connections_restricted === false) {
    issues.push({
      issue_id: `${task_id}:protect`,
      kind: 'PROTECTION_FAILED_NEW_CONNECTION',
      evidence_refs: [kernel.evidence_ref],
      ...classifyIssue('PROTECTION_FAILED_NEW_CONNECTION'),
      supported: true,
    });
  } else if (kernel?.actual?.chain_unavailable) {
    issues.push({
      issue_id: `${task_id}:chain`,
      kind: 'FIXED_CHAIN_UNAVAILABLE',
      evidence_refs: [kernel.evidence_ref],
      ...classifyIssue('FIXED_CHAIN_UNAVAILABLE'),
      supported: true,
    });
  }
  const platform = observations.find((item) => item.check_id === 'browser.platform');
  if (platform?.actual?.timezone_match?.iana_equal === false) {
    issues.push({
      issue_id: `${task_id}:tz`,
      kind: 'TIMEZONE_MISMATCH',
      evidence_refs: [platform.evidence_ref],
      evidence_source: platform.actual.client_kind || 'webview',
      ...classifyIssue('TIMEZONE_MISMATCH'),
      supported: true,
    });
  }
  for (const sample of observations.filter((item) => item.check_id === 'browser.session-sample' && !item.stale)) {
    issues.push(...issuesFromBrowserSample(sample, {expected, task_id}));
  }
  return issues;
}
