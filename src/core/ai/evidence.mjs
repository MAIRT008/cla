const SENSITIVE_KEY = /(api[_-]?key|authorization|auth[_-]?token|password|secret|cookie|credential|private[_-]?key|refresh[_-]?token|session)/i;
const SENSITIVE_VALUE = /\b(?:sk-[A-Za-z0-9_-]{8,}|SYNTHETIC_[A-Z0-9_]*(?:TOKEN|SECRET|COOKIE|KEY)[A-Z0-9_]*|Bearer\s+[^\s]+)\b/gi;
const LOCAL_PATH = /(?:[A-Za-z]:\\|\\\\)[^\r\n"']+/g;

export function redactText(value) {
  return String(value ?? '').replace(SENSITIVE_VALUE, '[REDACTED]').replace(LOCAL_PATH, '[LOCAL_PATH]');
}

export function redactForModel(value, key = '') {
  if (SENSITIVE_KEY.test(key)) return '[REDACTED]';
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map((item) => redactForModel(item));
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, redactForModel(child, childKey)]));
}

export function safeJson(value) {
  return JSON.stringify(redactForModel(value));
}

export function cleanupEvidence(scan) {
  return redactForModel({
    scan_id: scan.scan_id,
    source_version: scan.source_version,
    coverage: scan.coverage,
    identities: (scan.identities || []).map((item) => ({identity_ref: item.identity_ref, identity_fingerprint: item.identity_fingerprint, status: item.status || 'UNANSWERED'})),
    object_refs: inspectableObjects(scan).map((item) => item.object_ref),
  });
}

export function inspectableObjects(scan) {
  return (scan.objects || [])
    .filter((item) => item.status === 'found' && item.kind === 'json' && typeof item.object_ref === 'string' && !/(?:^|\/)(?:audit|backup|project)(?:\/|$)/i.test(item.relative_path || ''))
    .map((item) => ({object_ref: item.object_ref, relative_path: item.relative_path, kind: item.kind, identity_refs: item.identity_refs || []}));
}

export function collectObjectRefs(value) {
  const refs = new Set();
  const visit = (item) => {
    if (!item || typeof item !== 'object') return;
    if (Array.isArray(item)) return item.forEach(visit);
    for (const [key, child] of Object.entries(item)) {
      if ((key === 'object_ref' || key === 'objectRef') && typeof child === 'string') refs.add(child);
      else if ((key === 'relative_path' || key === 'relativePath' || key === 'path') && typeof child === 'string' && child.startsWith('input/')) refs.add(child);
      else visit(child);
    }
  };
  visit(value);
  return [...refs].sort();
}

export function dailyEvidence(report) {
  const factRefs = [
    'report.route_result', 'report.coverage_status', 'report.protection_status', 'report.delivery_status',
    'report.route_counts', 'report.coverage_issues', 'report.evidence_limits', 'report.window',
  ];
  return {
    report_id: report.reportId,
    window: {start: report.windowStart, end: report.windowEnd, interval: report.windowInterval},
    classification_version: report.classificationVersion,
    route_result: report.routeResult,
    coverage_status: report.coverageStatus,
    protection_status: report.protectionStatus,
    delivery_status: report.deliveryStatus,
    route_counts: report.routeCounts,
    coverage_issues: report.coverageIssues,
    evidence_limits: report.evidenceLimits,
    fact_refs: factRefs,
  };
}
