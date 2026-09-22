import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const audit = await import('../../src/core/audit/index.mjs').catch(() => null);
const storage = await import('../../src/adapters/audit/fixtureStore.mjs').catch(() => null);

async function makeFixtureRoot(t) {
  const fixtureBase = path.resolve('fixtures/audit');
  await fs.mkdir(fixtureBase, {recursive: true});
  const root = await fs.mkdtemp(path.join(fixtureBase, 't2-run-'));
  if (!root.startsWith(`${fixtureBase}${path.sep}`)) {
    throw new Error(`temporary root escaped fixtures/audit: ${root}`);
  }
  t.after(() => fs.rm(root, {recursive: true, force: true}));
  return root;
}

const LEGACY = {version: 'legacy-v2', fixedA: {route: 'CLAUDE-FIXED', member: 'COX-Fixed-Chain'}};

test('FD-04/F23-F28 archives approved fixture logs by SHA-256 without mutating sources', async (t) => {
  assert.ok(audit && storage, 'T2 audit consumer and fixture store modules must exist');
  const root = await makeFixtureRoot(t);
  const store = new storage.FixtureAuditStore(root);
  const goodLine = 'time="2026-03-08T16:05:00Z" [TCP] (claude.exe) --> api.anthropic.com:443 using CLAUDE-FIXED[COX-Fixed-Chain]';
  const secretLine = 'time="2026-03-08T16:06:00Z" Authorization: Bearer synthetic-secret';
  await store.writeText('source/service_latest.log', goodLine, {overwrite: false});
  await store.writeText('source/rotated.log', goodLine, {overwrite: false});
  await store.writeText('source/secret.log', secretLine, {overwrite: false});
  const sourceBefore = await store.readText('source/service_latest.log');

  const result = await audit.archiveLogs({now: '2026-03-08T16:10:00Z', sourceRoot: 'source', archiveRoot: 'archive', approvedSourceNames: ['service_latest.log', 'rotated.log', 'secret.log'], mapping: LEGACY}, store);
  assert.equal(result.status, 'OK');
  assert.equal(result.newCount, 1);
  assert.equal(result.duplicateCount, 1);
  assert.equal(result.restrictedExceptions.length, 1);
  assert.equal(result.notification, 'ATTENTION');
  assert.equal(await store.readText('source/service_latest.log'), sourceBefore);
  assert.match(result.entries[0].sha256, /^[a-f0-9]{64}$/);
  assert.equal(await store.exists(result.entries[0].archivePath), true);
});

test('FD-04/F29-F44 creates one factual report pair, repairs only a missing mate, and keeps delayed AI notes separate', async (t) => {
  assert.ok(audit && storage, 'T2 audit consumer and fixture store modules must exist');
  const root = await makeFixtureRoot(t);
  const store = new storage.FixtureAuditStore(root);
  const now = '2026-03-08T16:00:00Z';
  assert.equal(audit.planArchive(now, '2026-03-08T14:01:00Z').due, false);
  assert.equal(audit.planArchive(now, '2026-03-08T14:00:00Z').due, true);
  assert.equal(audit.evaluateDailyDue(now, []).due, true);
  assert.equal(audit.selectWindow(now, {valid: true, windowEnd: '2026-03-08T12:00:00Z'}).start, '2026-03-08T12:00:00.000Z');

  const report = audit.buildDailyReport({
    now,
    timezone: 'America/Los_Angeles',
    classificationVersion: 'legacy-v2',
    records: [
      {eventId: 'pass-1', timestamp: '2026-03-08T12:00:00Z', classification: 'PASS_ROUTE', sourceRef: 'a'},
      {eventId: 'pass-1', timestamp: '2026-03-08T12:00:00Z', classification: 'PASS_ROUTE', sourceRef: 'b'},
      {eventId: 'wrong-1', timestamp: '2026-03-08T13:00:00Z', classification: 'WRONG_ROUTE', sourceRef: 'b'},
      {eventId: 'unknown-1', timestamp: '2026-03-08T14:00:00Z', classification: 'UNKNOWN', reason: 'MISSING_ROUTE', sourceRef: 'c'},
    ],
    traffic: {totals: {uploadBytes: 40, downloadBytes: 60}, coverageIssues: []},
    quota: {status: 'STALE', source: 'server', measuredAt: '2026-03-08T11:00:00Z'},
    archive: {entries: [{sha256: 'a'.repeat(64)}], issues: []},
    protection: {status: 'NOT_CONNECTED'},
  });
  assert.equal(report.routeResult, 'FAIL');
  assert.equal(report.coverageStatus, 'MONITORING_INCOMPLETE');
  assert.deepEqual(report.routeCounts, {passRoute: 1, safeReject: 0, wrongRoute: 1, routeError: 0, unknown: 1});
  assert.equal(audit.renderMarkdown(report).includes(report.reportId), true);
  assert.equal(JSON.parse(audit.serializeReport(report)).reportId, report.reportId);

  const firstDelivery = await audit.deliverDailyReport(report, {reportRoot: 'reports'}, store);
  assert.equal(firstDelivery.status, 'DELIVERED');
  await fs.rm(path.join(root, firstDelivery.paths.markdown), {force: true});
  const repaired = await audit.deliverDailyReport(report, {reportRoot: 'reports'}, store);
  assert.equal(repaired.status, 'REPAIRED_MISSING_MATE');
  assert.equal(await store.exists(repaired.paths.markdown), true);
  assert.equal((await audit.deliverDailyReport(report, {reportRoot: 'reports'}, store)).status, 'ALREADY_DELIVERED');

  const note = await audit.appendAiNote({reportId: report.reportId, status: 'FAILED', reason: 'MODEL_UNAVAILABLE'}, {reportRoot: 'reports'}, store);
  assert.equal(note.reportId, report.reportId);
  assert.equal(note.affectsStandardFacts, false);
});

test('FD-04/F02-F06,F09-F13,F23-F37 consumes synthetic logs and counters into an archived report pair', async (t) => {
  assert.ok(audit && storage, 'T2 audit consumer and fixture store modules must exist');
  const root = await makeFixtureRoot(t);
  const store = new storage.FixtureAuditStore(root);
  const now = '2026-03-08T16:00:00Z';
  await store.writeText('source/service_latest.log', [
    'time="2026-03-08T15:00:00Z" [TCP] (claude.exe) --> api.anthropic.com:443 using CLAUDE-FIXED[COX-Fixed-Chain]',
    'time="2026-03-08T15:01:00Z" [TCP] dial DIRECT (match DomainSuffix/anthropic.com) (claude.exe) --> api.anthropic.com:443 error: retry using CLAUDE-FIXED[COX-Fixed-Chain] timeout',
  ].join('\n'), {overwrite: false});
  const result = await audit.runAuditPipeline({
    now,
    sourceRoot: 'source',
    archiveRoot: 'archive',
    approvedSourceNames: ['service_latest.log'],
    mapping: LEGACY,
    trafficState: {
      totals: {uploadBytes: 0, downloadBytes: 0},
      observations: {'core:core-a': {uploadBytes: 100, downloadBytes: 200, resetId: 'boot-1', observedAt: '2026-03-08T14:59:00Z'}},
      coverageIssues: [],
    },
    trafficSamples: [{sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-1', uploadBytes: 140, downloadBytes: 260, observedAt: '2026-03-08T15:02:00Z'}],
    quota: {source: 'server', status: 'ACTIVE', usedBytes: 100, limitBytes: 1000, observedAt: now},
    protection: {status: 'VERIFIED'},
    reportRoot: 'reports',
  }, store);
  assert.equal(result.delivery.status, 'DELIVERED');
  assert.equal(result.evidence.archive.newCount, 1);
  assert.equal(result.evidence.records.length, 2);
  assert.deepEqual(result.report.traffic.totals, {uploadBytes: 40, downloadBytes: 60});
  assert.equal(result.report.routeCounts.wrongRoute, 1);
  assert.equal(result.report.routeResult, 'FAIL');
  assert.equal(await store.exists(result.delivery.paths.json), true);
  assert.match(await store.readText(result.delivery.paths.markdown), /upload_bytes: 40/);
});

test('FD-04/A36 accepts DAILY_PASS only from a complete, source-bound collection window', () => {
  const now = '2026-03-08T16:00:00Z';
  const report = audit.buildDailyReport({
    now,
    window: {start: '2026-03-07T16:00:00Z', end: now},
    records: [{eventId: 'pass-window', timestamp: '2026-03-08T12:00:00Z', classification: 'PASS_ROUTE', sourceRef: 'source/service_latest.log'}],
    traffic: {totals: {uploadBytes: 0, downloadBytes: 0}, coverageIssues: []},
    archive: {entries: [{sourcePath: 'source/service_latest.log', sha256: 'a'.repeat(64)}], issues: [], restrictedExceptions: []},
    collectionEvidence: {
      environmentRef: 'synthetic-core-a',
      sourceRefs: ['source/service_latest.log'],
      coverageStart: '2026-03-07T16:00:00Z',
      coverageEnd: now,
      continuous: true,
      gaps: [],
      status: 'SYNTHETIC_CONTINUOUS_WINDOW',
    },
  });
  assert.equal(report.coverageStatus, 'COMPLETE');
  assert.equal(report.routeResult, 'DAILY_PASS');
});
