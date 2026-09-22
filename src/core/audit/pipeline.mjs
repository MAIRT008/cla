import {archiveLogs, readArchiveIndex} from './archive.mjs';
import {classifyRoute, parseRouteLogLine} from './routeClassifier.mjs';
import {accumulateTraffic} from './traffic.mjs';
import {buildDailyReport, deliverDailyReport, selectWindow} from './dailyReport.mjs';
import {localDateKey} from './time.mjs';

function decode(bytes) {
  return new TextDecoder().decode(bytes);
}

function replayable(metadata) {
  return metadata?.schemaVersion === 1 && metadata.archivePath && metadata.sourceStreamId && metadata.sha256 && metadata.mapping
    && Number.isFinite(Date.parse(metadata.archivedAt))
    ? metadata : null;
}

const TOP_PROCESSES = 20;

/**
 * 只有 Claude 相关的行才是审计记录；范围外的流量与非连接行不进四类计数，也不算覆盖问题。
 * 所有连接行另记一份来源描述，供日报的连接来源汇总（进程、路由、来源未识别）使用。
 */
function lineEvidence(text, sourceRef, sourceStreamId, mapping, connections) {
  const records = [];
  const matcher = /([^\r\n]*)(\r\n|\n|\r|$)/g;
  let match;
  let offset = 0;
  while ((match = matcher.exec(text)) !== null) {
    const [segment, line, ending] = match;
    if (!segment) break;
    const byteLength = new TextEncoder().encode(segment).byteLength;
    if (line) {
      const parsed = parseRouteLogLine(line);
      const classified = classifyRoute(parsed, mapping);
      if (parsed.destination) {
        connections.push({
          key: `${sourceStreamId}:${offset}`,
          timestamp: parsed.timestamp,
          process: classified.process,
          route: classified.route,
          inScope: classified.inScope,
        });
      }
      if (classified.inScope) {
        records.push({
          ...classified,
          eventId: `${sourceStreamId}:${offset}:${offset + byteLength}`,
          sourceRef,
          sourceStreamId,
          byteOffset: offset,
          byteEnd: offset + byteLength,
          timestamp: parsed.timestamp,
        });
      }
    }
    offset += byteLength;
    if (!ending) break;
  }
  return records;
}

/** 窗口内连接行的来源汇总：按行计数，不是字节；没有进程字段的记为来源未识别。同一流同一起点只算一次。 */
function summarizeConnectionLines(connections, window) {
  const start = Date.parse(window.start);
  const end = Date.parse(window.end);
  const seen = new Set();
  const summary = {basis: 'LOG_LINES_NOT_BYTES', total: 0, claudeRelated: 0, unattributedProcess: 0, missingRoute: 0, byRoute: {}, byProcess: {}};
  const processes = new Map();
  for (const item of connections) {
    const at = Date.parse(item.timestamp);
    if (!Number.isFinite(at) || at < start || at >= end || seen.has(item.key)) continue;
    seen.add(item.key);
    summary.total += 1;
    if (item.inScope) summary.claudeRelated += 1;
    if (!item.process) summary.unattributedProcess += 1;
    else processes.set(item.process, (processes.get(item.process) || 0) + 1);
    if (!item.route) summary.missingRoute += 1;
    else summary.byRoute[item.route] = (summary.byRoute[item.route] || 0) + 1;
  }
  const ranked = [...processes.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  for (const [name, count] of ranked.slice(0, TOP_PROCESSES)) summary.byProcess[name] = count;
  const rest = ranked.slice(TOP_PROCESSES).reduce((sum, [, count]) => sum + count, 0);
  if (rest) summary.otherProcessLines = rest;
  return summary;
}

function rawDate(rawPath, archiveRoot) {
  return rawPath.slice(`${archiveRoot}/`.length).split('/')[0] || '';
}

/**
 * 先做本次归档，再按窗口回放：归档时刻早于窗口起点的快照只含更早的记录，不再读回。
 * 元数据只经索引读取；需要回放的快照读字节并核对哈希。
 */
export async function collectAuditEvidence(request, store, options = {}) {
  const currentArchive = await archiveLogs(request, store, options);
  const window = request.window || selectWindow(request.now, request.priorValidReport);
  const windowStart = Date.parse(window.start);
  const windowDate = localDateKey(window.start);
  const {metadataByArchivePath, rawPaths} = await readArchiveIndex(store, request.archiveRoot);
  const records = [];
  const connections = [];
  const replayIssues = [];
  const historicalEntries = [];
  const verifiedSnapshots = [];
  for (const rawPath of rawPaths) {
    const metadata = replayable(metadataByArchivePath.get(rawPath));
    if (!metadata) {
      if (rawDate(rawPath, request.archiveRoot) >= windowDate) replayIssues.push({sourcePath: rawPath, code: 'ARCHIVE_METADATA_MISSING'});
      continue;
    }
    if (Date.parse(metadata.archivedAt) < windowStart) continue;
    let bytes;
    try {
      bytes = await store.readBytes(rawPath);
    } catch {
      replayIssues.push({sourcePath: rawPath, code: 'ARCHIVE_UNREADABLE'});
      continue;
    }
    const actualHash = await store.sha256(bytes);
    if (actualHash !== metadata.sha256) {
      replayIssues.push({sourcePath: rawPath, code: 'ARCHIVE_INTEGRITY_HASH_MISMATCH', expectedSha256: metadata.sha256, actualSha256: actualHash});
      continue;
    }
    verifiedSnapshots.push({bytes, metadata});
  }
  for (const {bytes, metadata} of verifiedSnapshots.sort((left, right) => {
    const timeOrder = Date.parse(left.metadata.archivedAt) - Date.parse(right.metadata.archivedAt);
    return timeOrder || left.metadata.archivePath.localeCompare(right.metadata.archivePath);
  })) {
    historicalEntries.push({
      sourcePath: metadata.sourcePath,
      archivePath: metadata.archivePath,
      sourceStreamId: metadata.sourceStreamId,
      sha256: metadata.sha256,
      status: metadata.derived ? 'VERIFIED_REDACTED_DERIVATIVE' : 'VERIFIED_HISTORY',
      ...(metadata.derived ? {derived: metadata.derived, sourceSha256: metadata.sourceSha256 || null} : {}),
      mappingVersion: metadata.mapping.version || 'unknown',
    });
    records.push(...lineEvidence(decode(bytes), metadata.archivePath, metadata.sourceStreamId, metadata.mapping, connections));
  }
  let trafficState = request.trafficState || {};
  for (const sample of request.trafficSamples || []) {
    ({state: trafficState} = accumulateTraffic(trafficState, sample));
  }
  const trafficCoverage = [...(trafficState.coverageIssues || [])];
  if (!(request.trafficSamples || []).length) trafficCoverage.push({code: 'NO_COUNTER_SAMPLES'});
  const archive = {
    ...currentArchive,
    entries: historicalEntries,
    issues: [...currentArchive.issues, ...replayIssues],
    historicalEntryCount: historicalEntries.length,
  };
  const requestedCollection = request.collectionEvidence || {};
  const collectionEvidence = {
    environmentRef: requestedCollection.environmentRef || null,
    sourceRefs: requestedCollection.sourceRefs || [...new Set(historicalEntries.map((entry) => entry.sourcePath))],
    coverageStart: requestedCollection.coverageStart || null,
    coverageEnd: requestedCollection.coverageEnd || null,
    continuous: requestedCollection.continuous === true,
    environments: Array.isArray(requestedCollection.environments) ? requestedCollection.environments.map((item) => ({...item})) : [],
    gaps: [...(requestedCollection.gaps || []), ...replayIssues],
    status: requestedCollection.continuous === true ? requestedCollection.status || 'COLLECTOR_EVIDENCE_SUBMITTED' : 'UNPROVEN_CONTINUITY',
  };
  return {
    window,
    archive,
    records,
    trafficState,
    traffic: {
      totals: trafficState.totals || null,
      coverageIssues: trafficCoverage,
      ...(request.trafficDetail || {}),
      connectionLines: summarizeConnectionLines(connections, window),
    },
    quota: request.quota || trafficState.serverQuota || {status: 'UNKNOWN'},
    protection: request.protection || {status: 'UNKNOWN'},
    collectionEvidence,
  };
}

export async function runAuditPipeline(request, store, options = {}) {
  const evidence = await collectAuditEvidence(request, store, options);
  const report = buildDailyReport({
    now: request.now,
    timezone: request.timezone,
    priorValidReport: request.priorValidReport,
    classificationVersion: request.mapping?.version,
    evidenceLimits: request.evidenceLimits,
    ...evidence,
  });
  const delivery = await deliverDailyReport(report, {reportRoot: request.reportRoot || 'reports'}, store);
  return {evidence, report, delivery};
}
