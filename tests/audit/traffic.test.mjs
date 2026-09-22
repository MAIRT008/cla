import assert from 'node:assert/strict';
import test from 'node:test';

const audit = await import('../../src/core/audit/index.mjs').catch(() => null);

test('FD-04/F02-F06 accumulates core deltas once and records reset or gaps', () => {
  assert.ok(audit, 'T2 audit consumer module must exist');
  let state = {};
  ({state} = audit.accumulateTraffic(state, {sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-1', uploadBytes: 100, downloadBytes: 200, observedAt: '2026-03-08T15:00:00Z'}));
  let result = audit.accumulateTraffic(state, {sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-1', uploadBytes: 140, downloadBytes: 260, observedAt: '2026-03-08T15:01:00Z'});
  state = result.state;
  assert.deepEqual(result.delta, {uploadBytes: 40, downloadBytes: 60});
  assert.deepEqual(state.totals, {uploadBytes: 40, downloadBytes: 60});

  result = audit.accumulateTraffic(state, {sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-1', uploadBytes: 140, downloadBytes: 260, observedAt: '2026-03-08T15:01:00Z'});
  state = result.state;
  assert.deepEqual(result.delta, {uploadBytes: 0, downloadBytes: 0});
  assert.deepEqual(state.totals, {uploadBytes: 40, downloadBytes: 60});

  result = audit.accumulateTraffic(state, {sourceKind: 'connection', connectionId: 'c-1', coveredByCore: true, uploadBytes: 30, downloadBytes: 50, observedAt: '2026-03-08T15:02:00Z'});
  state = result.state;
  assert.deepEqual(result.delta, {uploadBytes: 0, downloadBytes: 0});
  assert.deepEqual(state.totals, {uploadBytes: 40, downloadBytes: 60});

  result = audit.accumulateTraffic(state, {sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-2', uploadBytes: 5, downloadBytes: 9, observedAt: '2026-03-08T15:03:00Z'});
  assert.deepEqual(result.delta, {uploadBytes: 0, downloadBytes: 0});
  assert.equal(result.status, 'COUNTER_RESET');
  assert.equal(result.state.coverageIssues.at(-1).code, 'COUNTER_RESET');

  result = audit.accumulateTraffic(result.state, {sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-2', uploadBytes: null, downloadBytes: 12, observedAt: '2026-03-08T15:04:00Z'});
  assert.equal(result.status, 'INCOMPLETE');
  assert.equal(result.state.coverageIssues.at(-1).code, 'MISSING_COUNTER');
});

test('FD-04/F05 carries server quota snapshots without rebuilding a client ledger', () => {
  assert.ok(audit, 'T2 audit consumer module must exist');
  const quota = {source: 'server', usedBytes: 900, limitBytes: 1000, measuredAt: '2026-03-08T15:00:00Z'};
  const result = audit.accumulateTraffic({}, {sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-1', uploadBytes: 1, downloadBytes: 2, observedAt: '2026-03-08T15:00:00Z', serverQuota: quota});
  assert.deepEqual(result.state.serverQuota, quota);
  assert.equal(result.state.totals.uploadBytes, 0);
});
