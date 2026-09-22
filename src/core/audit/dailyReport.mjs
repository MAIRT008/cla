import {listArchivePaths} from './archive.mjs';
import {iso, localDateKey, localHour} from './time.mjs';

function clone(value) {
  return structuredClone(value);
}

function display(value) {
  return value === null || value === undefined ? 'UNAVAILABLE' : String(value);
}

function hasRouteCounts(value) {
  return !!value && ['passRoute', 'safeReject', 'wrongRoute', 'routeError', 'unknown'].every((key) => Number.isFinite(value[key]));
}

function isValidReport(report) {
  return !!report
    && report.schemaVersion === 1
    && typeof report.reportId === 'string'
    && typeof report.reportDate === 'string'
    && typeof report.timezone === 'string'
    && typeof report.generatedAt === 'string'
    && typeof report.windowStart === 'string'
    && typeof report.windowEnd === 'string'
    && report.windowInterval === 'START_INCLUSIVE_END_EXCLUSIVE'
    && typeof report.classificationVersion === 'string'
    && typeof report.routeResult === 'string'
    && typeof report.coverageStatus === 'string'
    && typeof report.deliveryStatus === 'string'
    && typeof report.protectionStatus === 'string'
    && hasRouteCounts(report.routeCounts)
    && Array.isArray(report.records)
    && report.traffic && typeof report.traffic === 'object'
    && report.quota && typeof report.quota === 'object'
    && report.archive && typeof report.archive === 'object'
    && report.protection && typeof report.protection === 'object'
    && Array.isArray(report.coverageIssues)
    && Array.isArray(report.evidenceLimits)
    && new Date(report.windowEnd) > new Date(report.windowStart);
}

/**
 * 同一流里同一起点就是同一行：前一快照里还没写完换行（甚至没写完内容）的最后一行，与后一快照里的完整行是同一条记录。
 */
function recordKey(record) {
  if (record.sourceStreamId && Number.isFinite(record.byteOffset)) {
    return `stream:${record.sourceStreamId}:${record.byteOffset}`;
  }
  if (record.eventId) return `event:${record.eventId}`;
  if (record.evidenceId) return `evidence:${record.evidenceId}`;
  return `record:${JSON.stringify({timestamp: record.timestamp, classification: record.classification, sourceRef: record.sourceRef, byteOffset: record.byteOffset, destination: record.destination, route: record.route})}`;
}

function routeCounts(records) {
  const counts = {passRoute: 0, safeReject: 0, wrongRoute: 0, routeError: 0, unknown: 0};
  for (const record of records) {
    if (record.classification === 'PASS_ROUTE') counts.passRoute += 1;
    else if (record.classification === 'SAFE_REJECT') counts.safeReject += 1;
    else if (record.classification === 'WRONG_ROUTE') counts.wrongRoute += 1;
    else if (record.classification === 'ROUTE_ERROR') counts.routeError += 1;
    else counts.unknown += 1;
  }
  return counts;
}

function factualProjection(report) {
  return {
    schemaVersion: report.schemaVersion,
    reportId: report.reportId,
    reportDate: report.reportDate,
    timezone: report.timezone,
    generatedAt: report.generatedAt,
    windowStart: report.windowStart,
    windowEnd: report.windowEnd,
    windowInterval: report.windowInterval,
    classificationVersion: report.classificationVersion,
    routeResult: report.routeResult,
    coverageStatus: report.coverageStatus,
    deliveryStatus: report.deliveryStatus,
    protectionStatus: report.protectionStatus,
    routeCounts: report.routeCounts,
    records: report.records,
    traffic: report.traffic,
    quota: report.quota,
    archive: report.archive,
    protection: report.protection,
    collectionEvidence: report.collectionEvidence,
    coverageIssues: report.coverageIssues,
    evidenceLimits: report.evidenceLimits,
  };
}

function standardTraffic(input) {
  return clone(input || {totals: null, coverageIssues: [{code: 'TRAFFIC_UNAVAILABLE'}]});
}

function standardArchive(input) {
  return clone(input || {entries: [], issues: [{code: 'ARCHIVE_UNAVAILABLE'}], restrictedExceptions: []});
}

export function environmentCoverage(collectionEvidence) {
  const declared = Array.isArray(collectionEvidence?.environments) ? collectionEvidence.environments : [];
  const measured = new Set([collectionEvidence?.environmentRef].filter(Boolean));
  for (const item of declared) if (item?.covered === true) measured.add(item.environment_ref);
  return declared.map((item) => ({
    environment_ref: item?.environment_ref || null,
    kind: item?.kind || 'unknown',
    covered: measured.has(item?.environment_ref),
    reason: measured.has(item?.environment_ref) ? null : item?.reason || 'NOT_MEASURED',
  }));
}

function collectionCoverageIssues(collectionEvidence, window, archive) {
  const issues = [];
  if (!collectionEvidence || typeof collectionEvidence !== 'object') {
    return [{code: 'COLLECTION_EVIDENCE_MISSING'}];
  }
  if (typeof collectionEvidence.environmentRef !== 'string' || !collectionEvidence.environmentRef) {
    issues.push({code: 'COLLECTION_ENVIRONMENT_MISSING'});
  }
  if (!Array.isArray(collectionEvidence.sourceRefs) || !collectionEvidence.sourceRefs.length) {
    issues.push({code: 'COLLECTION_SOURCES_MISSING'});
  }
  if (collectionEvidence.continuous !== true) issues.push({code: 'COLLECTION_CONTINUITY_UNPROVEN'});
  for (const environment of environmentCoverage(collectionEvidence)) {
    if (environment.covered === true) continue;
    issues.push({
      code: 'COLLECTION_ENVIRONMENT_NOT_COVERED',
      environment_ref: environment.environment_ref,
      kind: environment.kind,
      reason: environment.reason,
    });
  }
  const coveredStart = Date.parse(collectionEvidence.coverageStart);
  const coveredEnd = Date.parse(collectionEvidence.coverageEnd);
  const windowStart = Date.parse(window.start);
  const windowEnd = Date.parse(window.end);
  if (!Number.isFinite(coveredStart) || !Number.isFinite(coveredEnd) || coveredStart > windowStart || coveredEnd < windowEnd) {
    issues.push({code: 'COLLECTION_WINDOW_NOT_COVERED'});
  }
  for (const gap of collectionEvidence.gaps || []) {
    issues.push(typeof gap === 'string' ? {code: 'COLLECTION_GAP', detail: gap} : gap);
  }
  const archivedSources = new Set((archive.entries || []).map((entry) => entry.sourcePath).filter(Boolean));
  for (const sourceRef of collectionEvidence.sourceRefs || []) {
    if (!archivedSources.has(sourceRef)) issues.push({code: 'COLLECTION_SOURCE_NOT_ARCHIVED', sourceRef});
  }
  return issues;
}

export function evaluateDailyDue(now, reportInventory, timeZone = 'America/Los_Angeles') {
  const date = localDateKey(now, timeZone);
  if (localHour(now, timeZone) < 9) return {due: false, reason: 'BEFORE_0900', date};
  const delivered = (reportInventory || []).some((entry) => entry.date === date && entry.valid === true && entry.hasJson === true && entry.hasMarkdown === true);
  return delivered ? {due: false, reason: 'ALREADY_DELIVERED', date} : {due: true, reason: 'MISSING_OR_INVALID_REPORT', date};
}

export function selectWindow(now, priorValidReport) {
  const end = iso(now);
  const start = priorValidReport?.valid && priorValidReport.windowEnd
    ? iso(priorValidReport.windowEnd)
    : new Date(new Date(end).getTime() - 24 * 60 * 60 * 1000).toISOString();
  return {start, end, interval: 'START_INCLUSIVE_END_EXCLUSIVE'};
}

export function buildDailyReport(input) {
  const timezone = input.timezone || 'America/Los_Angeles';
  const window = input.window || selectWindow(input.now, input.priorValidReport);
  const startMillis = new Date(window.start).getTime();
  const endMillis = new Date(window.end).getTime();
  if (!(endMillis > startMillis)) throw new Error('invalid daily report window');
  const seen = new Map();
  const records = [];
  for (const record of input.records || []) {
    if (record.inScope === false) continue;
    const timestamp = new Date(record.timestamp).getTime();
    if (!Number.isFinite(timestamp) || timestamp < startMillis || timestamp >= endMillis) continue;
    const key = recordKey(record);
    if (seen.has(key)) {
      const index = seen.get(key);
      if ((record.byteEnd ?? -1) > (records[index].byteEnd ?? -1)) records[index] = clone(record);
      continue;
    }
    seen.set(key, records.length);
    records.push(clone(record));
  }
  const traffic = standardTraffic(input.traffic);
  const archive = standardArchive(input.archive);
  const quota = clone(input.quota || {status: 'UNKNOWN'});
  const protection = clone(input.protection || {status: 'UNKNOWN'});
  const collectionEvidence = clone(input.collectionEvidence || null);
  if (collectionEvidence) {
    const coverage = environmentCoverage(collectionEvidence);
    collectionEvidence.environment_coverage = coverage;
    collectionEvidence.whole_machine_claim = coverage.length > 0 && coverage.every((item) => item.covered === true);
  }
  const counts = routeCounts(records);
  const coverageIssues = [
    ...(traffic.coverageIssues || []),
    ...(archive.issues || []),
    ...(archive.restrictedExceptions || []).map((exception) => ({code: 'RESTRICTED_ARCHIVE_EVIDENCE', sourcePath: exception.sourcePath, reason: exception.reason})),
    ...records.filter((record) => record.classification === 'UNKNOWN').map((record) => ({code: record.reason || 'UNKNOWN_ROUTE_EVIDENCE'})),
  ];
  coverageIssues.push(...collectionCoverageIssues(collectionEvidence, window, archive));
  if (!(archive.entries || []).length) coverageIssues.push({code: 'NO_VERIFIED_ARCHIVE_EVIDENCE'});
  const coverageStatus = coverageIssues.length ? 'MONITORING_INCOMPLETE' : 'COMPLETE';
  const routeResult = counts.wrongRoute > 0
    ? 'FAIL'
    : counts.routeError > 0
      ? 'FIXED_ROUTE_ERRORS'
      : coverageStatus === 'COMPLETE'
        ? 'DAILY_PASS'
        : 'MONITORING_INCOMPLETE';
  const reportDate = localDateKey(input.now, timezone);
  const reportId = `audit-${reportDate}-${new Date(window.start).getTime()}-${new Date(window.end).getTime()}`;
  return {
    schemaVersion: 1,
    reportId,
    reportDate,
    timezone,
    generatedAt: iso(input.now),
    windowStart: iso(window.start),
    windowEnd: iso(window.end),
    windowInterval: 'START_INCLUSIVE_END_EXCLUSIVE',
    classificationVersion: input.classificationVersion || 'product-v1',
    routeResult,
    coverageStatus,
    deliveryStatus: 'READY',
    protectionStatus: protection.status || 'UNKNOWN',
    routeCounts: counts,
    records,
    traffic,
    quota,
    archive,
    protection,
    collectionEvidence,
    coverageIssues,
    evidenceLimits: [
      'Route classification is record-scoped.',
      'Local traffic does not replace server quota authority.',
      ...(Array.isArray(input.evidenceLimits) ? input.evidenceLimits : []),
    ],
  };
}

export function serializeReport(report) {
  return JSON.stringify(report, null, 2);
}

export function renderMarkdown(report) {
  const facts = factualProjection(report);
  const totals = report.traffic?.totals || {};
  const archiveEntries = report.archive?.entries || [];
  const archiveIssues = report.archive?.issues || [];
  const restricted = report.archive?.restrictedExceptions || [];
  const coverage = report.coverageIssues || [];
  const protectionEvents = report.protection?.events || [];
  const pendingActions = [];
  if (report.routeResult === 'FAIL') pendingActions.push('Investigate each WRONG_ROUTE evidence record through the approved protection path.');
  if (report.routeResult === 'FIXED_ROUTE_ERRORS') pendingActions.push('Review fixed-route errors without reclassifying them as successful routes.');
  if (report.coverageStatus === 'MONITORING_INCOMPLETE') pendingActions.push('Restore or document the missing audit coverage before declaring a fully covered day.');
  return [
    `# 每日审计 ${report.reportDate}`,
    '',
    '## 1. 范围与时间窗口',
    `- report_id: ${report.reportId}`,
    `- timezone: ${report.timezone}`,
    `- classification_version: ${report.classificationVersion}`,
    `- window: [${report.windowStart}, ${report.windowEnd})`,
    '',
    '## 2. 路由与处置结论',
    `- route_result: ${report.routeResult}`,
    `- coverage_status: ${report.coverageStatus}`,
    `- delivery_status: ${report.deliveryStatus}`,
    `- protection_status: ${report.protectionStatus}`,
    `- counts: PASS_ROUTE=${report.routeCounts.passRoute}, SAFE_REJECT=${report.routeCounts.safeReject}, WRONG_ROUTE=${report.routeCounts.wrongRoute}, ROUTE_ERROR=${report.routeCounts.routeError}, UNKNOWN=${report.routeCounts.unknown}`,
    '',
    '## 3. 本地字节证据',
    `- upload_bytes: ${display(totals.uploadBytes)}`,
    `- download_bytes: ${display(totals.downloadBytes)}`,
    ...(report.traffic?.connectionLines ? [`- connection_lines (log lines, not bytes): total=${report.traffic.connectionLines.total}; claude_related=${report.traffic.connectionLines.claudeRelated}; unattributed_process=${report.traffic.connectionLines.unattributedProcess}; missing_route=${report.traffic.connectionLines.missingRoute}`] : []),
    '',
    '## 4. 服务端配额快照',
    `- quota_source: ${display(report.quota?.source)}`,
    `- quota_status: ${display(report.quota?.status)}`,
    `- quota_used_bytes: ${display(report.quota?.usedBytes)}`,
    `- quota_limit_bytes: ${display(report.quota?.limitBytes)}`,
    `- quota_observed_at: ${display(report.quota?.observedAt || report.quota?.measuredAt)}`,
    '',
    '## 5. 归档与保护证据',
    `- archive_entry_count: ${archiveEntries.length}`,
    `- archive_issue_count: ${archiveIssues.length}`,
    `- restricted_exception_count: ${restricted.length}`,
    ...archiveEntries.map((entry) => `- archive_source: ${display(entry.sourcePath || entry.sourceRef)}; sha256: ${display(entry.sha256)}`),
    ...archiveIssues.map((entry) => `- archive_issue: ${display(entry.code)}; source: ${display(entry.sourcePath)}`),
    ...restricted.map((entry) => `- restricted_exception: ${display(entry.reason)}; source: ${display(entry.sourcePath)}`),
    `- protection_event_count: ${protectionEvents.length}`,
    ...protectionEvents.map((event) => `- protection_event: ${display(event.eventId)}; action: ${display(event.action)}; result: ${display(event.result)}; first_observed_at: ${display(event.firstObservedAt)}; last_observed_at: ${display(event.lastObservedAt)}; count: ${display(event.count)}; effective_at: ${display(event.effectiveAt)}; notified_at: ${display(event.notifiedAt)}; reported: ${display(event.deliveryStatus)}; reported_at: ${display(event.deliveredAt)}; process: ${display(event.process)}; destination: ${display(event.destination)}`),
    '',
    '## 6. 覆盖限制与待办',
    ...(coverage.length ? coverage.map((entry) => `- coverage_issue: ${display(entry.code)}`) : ['- coverage_issue: NONE']),
    `- collection_continuity: ${display(report.collectionEvidence?.continuous === true ? report.collectionEvidence?.status || 'DECLARED' : 'UNPROVEN')}`,
    ...(pendingActions.length ? pendingActions.map((entry) => `- pending_action: ${entry}`) : ['- pending_action: NONE']),
    '',
    `<!-- audit-standard:${encodeURIComponent(JSON.stringify(facts))} -->`,
  ].join('\n');
}

function visibleMarkdownMatchesFacts(text, facts) {
  const visible = String(text).replace(/<!--[\s\S]*?-->/g, '');
  const totals = facts.traffic?.totals || {};
  const required = [
    '## 1. 范围与时间窗口',
    '## 2. 路由与处置结论',
    '## 3. 本地字节证据',
    '## 4. 服务端配额快照',
    '## 5. 归档与保护证据',
    '## 6. 覆盖限制与待办',
    `- report_id: ${facts.reportId}`,
    `- route_result: ${facts.routeResult}`,
    `- coverage_status: ${facts.coverageStatus}`,
    `- upload_bytes: ${display(totals.uploadBytes)}`,
    `- download_bytes: ${display(totals.downloadBytes)}`,
    `- quota_limit_bytes: ${display(facts.quota?.limitBytes)}`,
    `- archive_entry_count: ${(facts.archive?.entries || []).length}`,
    `- collection_continuity: ${display(facts.collectionEvidence?.continuous === true ? facts.collectionEvidence?.status || 'DECLARED' : 'UNPROVEN')}`,
  ];
  return required.every((line) => visible.includes(line));
}

function parseMarkdownReport(text) {
  const match = String(text).match(/<!-- audit-standard:([^>]+) -->/);
  if (!match) return null;
  try {
    const facts = JSON.parse(decodeURIComponent(match[1]));
    return visibleMarkdownMatchesFacts(text, facts) ? facts : null;
  } catch {
    return null;
  }
}

function sameFacts(left, right) {
  return JSON.stringify(factualProjection(left)) === JSON.stringify(factualProjection(right));
}

async function readTextIfPresent(store, relativePath) {
  return (await store.exists(relativePath)) ? store.readText(relativePath) : null;
}

export async function deliverDailyReport(report, {reportRoot = 'reports'} = {}, store) {
  if (!isValidReport(report)) throw new Error('invalid report payload');
  const base = `${reportRoot}/${report.reportDate}`;
  const paths = {json: `${base}/daily-audit.json`, markdown: `${base}/daily-audit.md`};
  let initialState = null;
  let writes = 0;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const [jsonText, markdownText] = await Promise.all([readTextIfPresent(store, paths.json), readTextIfPresent(store, paths.markdown)]);
    let jsonReport = null;
    if (jsonText !== null) {
      try { jsonReport = JSON.parse(jsonText); } catch { jsonReport = null; }
    }
    const markdownReport = markdownText === null ? null : parseMarkdownReport(markdownText);
    const jsonValid = isValidReport(jsonReport);
    const markdownValid = isValidReport(markdownReport);
    if ((jsonText !== null && !jsonValid) || (markdownText !== null && !markdownValid)) {
      return {status: 'FAILED_CORRUPT_HISTORY', paths};
    }
    if (!initialState) initialState = jsonValid || markdownValid ? 'PARTIAL' : 'EMPTY';
    if (jsonValid && markdownValid) {
      if (!sameFacts(jsonReport, markdownReport)) return {status: 'CONFLICT', paths};
      if (writes) return {status: initialState === 'PARTIAL' ? 'REPAIRED_MISSING_MATE' : 'DELIVERED', paths, reportId: jsonReport.reportId};
      return {status: 'ALREADY_DELIVERED', paths, reportId: jsonReport.reportId};
    }
    const existing = jsonValid ? jsonReport : markdownReport;
    const targetPath = existing ? (jsonValid ? paths.markdown : paths.json) : paths.json;
    const contents = existing
      ? (jsonValid ? renderMarkdown(existing) : serializeReport(existing))
      : serializeReport(report);
    try {
      await store.writeText(targetPath, contents, {overwrite: false});
      writes += 1;
    } catch (error) {
      if (error?.code !== 'EEXIST') {
        return {status: 'FAILED_STORAGE_WRITE', paths, code: error?.code || 'WRITE_ERROR', message: error?.message || String(error)};
      }
    }
  }
  return {status: 'FAILED_DELIVERY_RACE', paths};
}

/** 读回某一天已交付的日报：两份都在、都有效且事实一致才算完整有效。到期判断与窗口续接都用它。 */
export async function readDeliveredReport(store, {reportRoot = 'reports', date}) {
  const base = `${reportRoot}/${date}`;
  const paths = {json: `${base}/daily-audit.json`, markdown: `${base}/daily-audit.md`};
  const [jsonText, markdownText] = await Promise.all([readTextIfPresent(store, paths.json), readTextIfPresent(store, paths.markdown)]);
  let jsonReport = null;
  if (jsonText !== null) {
    try { jsonReport = JSON.parse(jsonText); } catch { jsonReport = null; }
  }
  const markdownReport = markdownText === null ? null : parseMarkdownReport(markdownText);
  const jsonValid = isValidReport(jsonReport);
  const markdownValid = isValidReport(markdownReport);
  const valid = jsonValid && markdownValid && sameFacts(jsonReport, markdownReport);
  return {date, paths, hasJson: jsonText !== null, hasMarkdown: markdownText !== null, jsonValid, markdownValid, valid, report: valid ? jsonReport : null};
}

/** 早于 beforeDate 的最近一份完整有效日报；FAIL、MONITORING_INCOMPLETE 同样推进窗口。只往回看有限天数。 */
export async function findPriorValidReport(store, {reportRoot = 'reports', beforeDate = null, maxLookback = 14} = {}) {
  const dates = [...new Set((await listArchivePaths(store, reportRoot))
    .map((entry) => entry.path.slice(reportRoot.length + 1).split('/')[0])
    .filter((date) => /^\d{4}-\d{2}-\d{2}$/.test(date) && (!beforeDate || date < beforeDate)))]
    .sort()
    .reverse()
    .slice(0, maxLookback);
  for (const date of dates) {
    const delivered = await readDeliveredReport(store, {reportRoot, date});
    if (delivered.valid) return {valid: true, date, reportId: delivered.report.reportId, windowEnd: delivered.report.windowEnd};
  }
  return null;
}

export async function appendAiNote(note, {reportRoot = 'reports'} = {}, store) {
  if (!note?.reportId) throw new Error('reportId is required for AI note');
  const timestamp = Date.now();
  const path = `${reportRoot}/ai-notes/${note.reportId}-${timestamp}.json`;
  const record = {
    ...clone(note),
    reportId: note.reportId,
    status: note.status || 'UNKNOWN',
    reason: note.reason || null,
    createdAt: new Date(timestamp).toISOString(),
    affectsStandardFacts: false,
  };
  await store.writeText(path, JSON.stringify(record, null, 2), {overwrite: false});
  return record;
}
