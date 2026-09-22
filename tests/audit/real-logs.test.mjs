import assert from 'node:assert/strict';
import {mkdir, rm} from 'node:fs/promises';
import test from 'node:test';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import * as audit from '../../src/core/audit/index.mjs';
import {FixtureAuditStore} from '../../src/adapters/audit/fixtureStore.mjs';

/**
 * 行格式按仓库内 Mihomo v1.19.30 源码构造：log/log.go 的 logrus TextFormatter（FullTimestamp、纳秒时间），
 * tunnel/tunnel.go 的连接行与拨号失败行，constant/adapters.go 的 Chain.String()（`组[叶子]`）。
 */
function mihomo(time, level, message) {
  return `time="${time}" level=${level} msg="${message.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}
function using(time, process, host, chain, rule = 'DomainSuffix(anthropic.com)') {
  return mihomo(time, 'info', `[TCP] 127.0.0.1:52345(${process}) --> ${host}:443 match ${rule} using ${chain}`);
}
function dialError(time, process, host, proxy, error) {
  return mihomo(time, 'warning', `[TCP] dial ${proxy} (match DomainSuffix/anthropic.com) 127.0.0.1:52346(${process}) --> ${host}:443 error: ${error}`);
}

const PRODUCT = {version: 'product-v1', fixedA: {route: 'CLAUDE-FIXED', member: 'PROXY-A'}, managedBrowserProcesses: ['claude-browser.exe']};
const PASS = (time) => using(time, 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[PROXY-A]');
const WRONG = (time) => using(time, 'claude.exe', 'api.anthropic.com', 'DIRECT');
const encoder = new TextEncoder();

function serviceLogs(files) {
  return {
    async listFiles() {
      return Object.entries(files).map(([name, value]) => (value && typeof value === 'object' && value.status
        ? {path: `service-logs/${name}`, status: value.status, reason: value.reason || null}
        : {path: `service-logs/${name}`, status: 'found', bytes: encoder.encode(value)}));
    },
  };
}

function request(now, extra = {}) {
  return {
    now,
    timezone: 'America/Los_Angeles',
    sourceRoot: 'service-logs',
    archiveRoot: 'archive',
    approvedSourceNames: ['core.log', 'core.1.log'],
    latestSourceNames: ['core.log'],
    optionalSourceNames: ['core.1.log'],
    mapping: PRODUCT,
    reportRoot: 'reports',
    ...extra,
  };
}

async function freshStore(t, label) {
  const root = transientRun('audit', label);
  await mkdir(root, {recursive: true});
  t.after(() => rm(root, {recursive: true, force: true}));
  return new FixtureAuditStore(root);
}

test('FD-04/F09-F12 Mihomo 真实行格式：logrus 引号不粘进路由名，REJECT 仍是 SAFE_REJECT', () => {
  const reject = using('2026-09-17T09:00:00.000000001-07:00', 'claude.exe', 'statsig.anthropic.com', 'REJECT');
  assert.deepEqual(audit.parseRouteLogLine(reject).chain, ['REJECT'], '末尾的 msg 引号不能粘进路由名');
  assert.equal(audit.classifyLogLine(reject, PRODUCT).classification, 'SAFE_REJECT');
  const paused = using('2026-09-17T09:00:00.500000000-07:00', 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[REJECT]');
  assert.equal(audit.classifyLogLine(paused, PRODUCT).classification, 'SAFE_REJECT', '额度暂停时 CLAUDE-FIXED 只选 REJECT：明确拒绝');
  assert.equal(audit.classifyLogLine(paused, {version: 'legacy-v2', fixedA: {route: 'CLAUDE-FIXED', member: 'COX-Fixed-Chain'}}).classification, 'WRONG_ROUTE', '旧 v2 口径不因产品适配而改');
  assert.equal(audit.classifyLogLine(PASS('2026-09-17T09:00:01.123456789-07:00'), PRODUCT).classification, 'PASS_ROUTE');
  assert.equal(audit.classifyLogLine(WRONG('2026-09-17T09:00:02.000000000-07:00'), PRODUCT).classification, 'WRONG_ROUTE');
  const timeout = dialError('2026-09-17T09:00:03.000000000-07:00', 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED', 'dial tcp 203.0.113.10:443: i/o timeout');
  assert.equal(audit.classifyLogLine(timeout, PRODUCT).classification, 'ROUTE_ERROR');
  const quoted = dialError('2026-09-17T09:00:04.000000000-07:00', 'claude.exe', 'claude.ai', 'CLAUDE-FIXED', 'read "tcp": connection closed');
  assert.match(quoted, /\\"tcp\\"/, '样例里确实有转义引号');
  const parsed = audit.parseRouteLogLine(quoted);
  assert.equal(parsed.process, 'claude.exe');
  assert.equal(parsed.destination, 'claude.ai:443');
  assert.equal(audit.classifyRoute(parsed, PRODUCT).classification, 'ROUTE_ERROR');
  assert.equal(parsed.timestamp, '2026-09-17T09:00:04.000000000-07:00');
  assert.equal(new Date(parsed.timestamp).toISOString(), '2026-09-17T16:00:04.000Z', '纳秒时间与时区偏移按实际时刻解析');
});

test('FD-04/F12/A02 只计 Claude 相关记录：范围外流量与非连接行不计数、不算覆盖问题', async (t) => {
  const store = await freshStore(t, 'scope');
  const now = '2026-09-17T17:00:00.000Z';
  const lines = [
    mihomo('2026-09-17T09:00:00.000000000-07:00', 'info', 'Start initial configuration in progress'),
    PASS('2026-09-17T09:10:00.000000000-07:00'),
    using('2026-09-17T09:11:00.000000000-07:00', 'chrome.exe', 'example.com', 'GENERAL-EGRESS[PROXY-B]', 'MATCH'),
    using('2026-09-17T09:12:00.000000000-07:00', 'Code.exe', 'marketplace.visualstudio.com', 'DIRECT', 'DomainSuffix(visualstudio.com)'),
    mihomo('2026-09-17T09:13:00.000000000-07:00', 'info', '[Sniffer] 127.0.0.1:52347(claude.exe) --> claude.ai:443 sniffed'),
  ];
  const result = await audit.runAuditPipeline(request(now, {
    window: {start: '2026-09-17T15:00:00.000Z', end: now},
    collectionEvidence: {environmentRef: 'windows-host', sourceRefs: ['service-logs/core.log'], coverageStart: '2026-09-17T15:00:00.000Z', coverageEnd: now, continuous: true, gaps: []},
  }), store, {sources: serviceLogs({'core.log': lines.join('\n'), 'core.1.log': {status: 'not_found'}})});
  assert.equal(result.report.records.length, 2, '只有两条 Claude 相关记录');
  assert.deepEqual(result.report.routeCounts, {passRoute: 1, safeReject: 0, wrongRoute: 0, routeError: 0, unknown: 1});
  const codes = result.report.coverageIssues.map((item) => item.code);
  assert.deepEqual(codes, ['NO_COUNTER_SAMPLES', 'MISSING_ROUTE'], `没给计数样本照记；范围内解析不出路由的那条如实列出，范围外的不算：${codes}`);
  assert.equal(codes.includes('OUT_OF_SCOPE'), false);
});

test('FD-04/F25-F27/A34 轮转：core.log 转成 core.1.log 后接上同一流标识，同一行不重复计数', async (t) => {
  const store = await freshStore(t, 'rotation');
  const first = ['09:00', '09:10', '09:20'].map((clock) => PASS(`2026-09-17T${clock}:00.000000000-07:00`));
  const rotated = [...first, PASS('2026-09-17T09:30:00.000000000-07:00'), WRONG('2026-09-17T09:40:00.000000000-07:00')];
  const fresh = [PASS('2026-09-17T10:50:00.000000000-07:00'), PASS('2026-09-17T10:55:00.000000000-07:00')];
  const run1 = await audit.archiveLogs(request('2026-09-17T16:30:00.000Z'), store, {sources: serviceLogs({'core.log': first.join('\n'), 'core.1.log': {status: 'not_found'}})});
  assert.equal(run1.status, 'OK', JSON.stringify(run1.issues));
  assert.match(run1.entries[0].archivePath, /\/raw\/core\.snapshot_\d{8}-\d{9}\.log$/, '活动日志按当地时间戳快照命名');

  const now = '2026-09-17T18:30:00.000Z';
  const result = await audit.runAuditPipeline(request(now, {window: {start: '2026-09-17T15:00:00.000Z', end: now}}), store, {
    sources: serviceLogs({'core.log': fresh.join('\n'), 'core.1.log': rotated.join('\n')}),
  });
  const codes = result.evidence.archive.issues.map((item) => item.code);
  assert.equal(codes.includes('SOURCE_ROTATION_GAP'), false, `一次轮转接得上：${codes}`);
  const rotatedEntry = result.evidence.archive.entries.find((entry) => entry.sourcePath === 'service-logs/core.1.log');
  assert.equal(rotatedEntry.sourceStreamId, run1.entries[0].sourceStreamId, 'core.1.log 沿用轮转前 core.log 的流标识');
  assert.equal(result.report.records.length, 7, '3 + 2 + 2 条，轮转前后同一行只算一次');
  assert.equal(result.report.routeCounts.wrongRoute, 1);
  assert.equal(result.report.routeResult, 'FAIL');
});

test('FD-04/A25 两次归档之间轮转两次：记 SOURCE_ROTATION_GAP，日报不声明完整', async (t) => {
  const store = await freshStore(t, 'rotation-gap');
  await audit.archiveLogs(request('2026-09-17T16:30:00.000Z'), store, {
    sources: serviceLogs({'core.log': [PASS('2026-09-17T09:00:00.000000000-07:00')].join('\n'), 'core.1.log': {status: 'not_found'}}),
  });
  const now = '2026-09-17T18:30:00.000Z';
  const result = await audit.runAuditPipeline(request(now, {
    window: {start: '2026-09-17T15:00:00.000Z', end: now},
    collectionEvidence: {environmentRef: 'windows-host', sourceRefs: ['service-logs/core.log'], coverageStart: '2026-09-17T15:00:00.000Z', coverageEnd: now, continuous: true, gaps: []},
  }), store, {
    sources: serviceLogs({
      'core.1.log': PASS('2026-09-17T10:40:00.000000000-07:00'),
      'core.log': PASS('2026-09-17T11:20:00.000000000-07:00'),
    }),
  });
  const gap = result.evidence.archive.issues.find((item) => item.code === 'SOURCE_ROTATION_GAP');
  assert.ok(gap, '上次快照不在任何当前来源的开头，中间那段丢了');
  assert.equal(gap.sourcePath, 'service-logs/core.log');
  assert.equal(result.report.coverageStatus, 'MONITORING_INCOMPLETE');
  assert.ok(result.report.coverageIssues.some((item) => item.code === 'SOURCE_ROTATION_GAP'));
  assert.notEqual(result.report.routeResult, 'DAILY_PASS');
});

test('FD-04/F39/A37 源日志含秘密：原件不进归档，脱敏派生件自带哈希，照样回放出 WRONG_ROUTE', async (t) => {
  const store = await freshStore(t, 'secret');
  const leak = mihomo('2026-09-17T09:05:00.000000000-07:00', 'warning', '[Provider] claude-rules pull error: Get "https://sub.example.com/rules?token=s3cr3t-value": EOF');
  const text = [PASS('2026-09-17T09:00:00.000000000-07:00'), leak, WRONG('2026-09-17T09:06:00.000000000-07:00')].join('\n');
  const now = '2026-09-17T17:00:00.000Z';
  const result = await audit.runAuditPipeline(request(now, {window: {start: '2026-09-17T15:00:00.000Z', end: now}}), store, {
    sources: serviceLogs({'core.log': text, 'core.1.log': {status: 'not_found'}}),
  });
  const exception = result.evidence.archive.restrictedExceptions[0];
  assert.equal(exception.reason, 'SECRET_MATERIAL');
  assert.equal(exception.derivedStatus, 'ARCHIVED_REDACTED');
  assert.notEqual(exception.derivedSha256, exception.sha256, '派生件不冒称与原件字节一致');
  const derived = await store.readText(exception.derivedArchivePath);
  assert.equal(derived.includes('s3cr3t-value'), false);
  assert.match(derived, /token=\[redacted\]/);
  const index = await audit.readArchiveIndex(store, 'archive');
  const metadata = index.metadataByArchivePath.get(exception.derivedArchivePath);
  assert.equal(metadata.derived, 'REDACTED');
  assert.equal(metadata.sourceSha256, exception.sha256);
  assert.equal([...index.metadataByArchivePath.values()].some((item) => item.sha256 === exception.sha256), false, '原件哈希对应的字节没有进归档');
  assert.equal(result.report.routeCounts.wrongRoute, 1, '派生件照样回放，错误出口不被秘密异常藏掉');
  assert.equal(result.report.routeResult, 'FAIL');
  assert.ok(result.report.coverageIssues.some((item) => item.code === 'RESTRICTED_ARCHIVE_EVIDENCE'));
});

test('FD-04/F24/A25 可选来源缺席不算缺口；读不到的来源记 SOURCE_UNREADABLE', async (t) => {
  const store = await freshStore(t, 'sources');
  const ok = await audit.archiveLogs(request('2026-09-17T16:30:00.000Z'), store, {
    sources: serviceLogs({'core.log': PASS('2026-09-17T09:00:00.000000000-07:00'), 'core.1.log': {status: 'not_found'}}),
  });
  assert.equal(ok.status, 'OK');
  assert.equal(ok.collection.status, 'VERIFIED_SNAPSHOTS', '还没轮转时只有 core.log，也能是完整快照');
  const unreadable = await audit.archiveLogs(request('2026-09-17T18:30:00.000Z'), store, {
    sources: serviceLogs({'core.log': PASS('2026-09-17T09:00:00.000000000-07:00'), 'core.1.log': {status: 'unreadable', reason: 'ACCESS_DENIED'}}),
  });
  assert.equal(unreadable.status, 'PARTIAL');
  assert.deepEqual(unreadable.issues.map((item) => [item.code, item.reason]), [['SOURCE_UNREADABLE', 'ACCESS_DENIED']]);
  assert.equal(unreadable.notification, 'ATTENTION');
  const missing = await audit.archiveLogs(request('2026-09-17T20:30:00.000Z'), store, {sources: serviceLogs({'core.1.log': {status: 'not_found'}})});
  assert.ok(missing.issues.some((item) => item.code === 'APPROVED_SOURCE_MISSING' && item.sourcePath === 'core.log'), '必需的 core.log 不在要报');
});

test('FD-04/F28/A26-A27 每轮只数新增部分的 WRONG_ROUTE；归档索引不读回历史字节，回放只读窗口内快照', async (t) => {
  const store = await freshStore(t, 'incremental');
  const rawReads = [];
  const readBytes = store.readBytes.bind(store);
  store.readBytes = async (relative) => {
    if (relative.includes('/raw/')) rawReads.push(relative);
    return readBytes(relative);
  };
  const lines = [];
  const counts = [];
  const hours = ['09', '11', '13', '15'];
  for (const [index, hour] of hours.entries()) {
    lines.push(PASS(`2026-09-17T${hour}:05:00.000000000-07:00`), WRONG(`2026-09-17T${hour}:06:00.000000000-07:00`));
    rawReads.length = 0;
    const run = await audit.archiveLogs(request(`2026-09-17T${16 + index * 2}:30:00.000Z`), store, {
      sources: serviceLogs({'core.log': lines.join('\n'), 'core.1.log': {status: 'not_found'}}),
    });
    counts.push(run.wrongRouteCount);
    assert.ok(rawReads.length <= 2, `第 ${index + 1} 轮只读前一快照与刚写的快照，实际 ${rawReads.length}：${rawReads}`);
  }
  assert.deepEqual(counts, [1, 1, 1, 1], '增长中的活动日志每轮只数新增的那一条');

  const now = '2026-09-17T23:00:00.000Z';
  const evidence = await audit.collectAuditEvidence(request(now, {window: {start: '2026-09-17T21:00:00.000Z', end: now}}), store, {
    sources: serviceLogs({'core.log': lines.join('\n'), 'core.1.log': {status: 'not_found'}}),
  });
  assert.deepEqual(evidence.archive.entries.map((entry) => entry.archivePath.match(/snapshot_(\d{8}-\d{4})/)[1]), ['20260917-1530'], '只回放窗口起点（21:00Z）之后归档的快照：22:30Z 即 LA 15:30 那一份');
});

test('FD-04/F30-F31 读回日报：两份都有效才算交付；找上一份完整有效日报时跳过损坏的', async (t) => {
  const store = await freshStore(t, 'delivered');
  const make = (now) => audit.buildDailyReport({
    now,
    window: {start: new Date(Date.parse(now) - 86400000).toISOString(), end: now},
    records: [],
    traffic: {totals: null, coverageIssues: []},
    archive: {entries: [], issues: []},
  });
  const first = make('2026-09-15T17:00:00.000Z');
  assert.equal((await audit.deliverDailyReport(first, {reportRoot: 'reports'}, store)).status, 'DELIVERED');
  await store.writeText('reports/2026-09-16/daily-audit.json', '{"broken":', {overwrite: false});
  assert.equal((await audit.readDeliveredReport(store, {reportRoot: 'reports', date: '2026-09-16'})).valid, false);
  const delivered = await audit.readDeliveredReport(store, {reportRoot: 'reports', date: '2026-09-15'});
  assert.equal(delivered.valid, true);
  assert.equal(delivered.report.reportId, first.reportId);
  const prior = await audit.findPriorValidReport(store, {reportRoot: 'reports', beforeDate: '2026-09-17'});
  assert.equal(prior.date, '2026-09-15');
  assert.equal(prior.windowEnd, first.windowEnd);
  assert.equal(await audit.findPriorValidReport(store, {reportRoot: 'reports', beforeDate: '2026-09-15'}), null);
});
