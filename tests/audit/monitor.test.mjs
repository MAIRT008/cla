import assert from 'node:assert/strict';
import test from 'node:test';
import {accumulateTraffic} from '../../src/core/audit/index.mjs';
import {createMonitorJournal, journalCoverage, journalTraffic, mergeJournalEntries} from '../../src/core/audit/monitor.mjs';

const at = (seconds) => new Date(Date.parse('2026-09-18T16:00:00.000Z') + seconds * 1000).toISOString();

function connection(id, {process = 'claude.exe', chains = ['EXIT-A', 'PROXY-A', 'CLAUDE-FIXED'], upload = 0, download = 0} = {}) {
  return {id, metadata: {process, host: 'api.anthropic.com'}, chains, upload, download};
}

function reading(snapshot, extra = {}) {
  return {ok: true, reachable: true, core_running: true, core_instance: '5100:1', snapshot, ...extra};
}

function run(journal, steps) {
  for (const [seconds, value] of steps) journal.tick(at(seconds), value);
  const {finished, current} = journal.take();
  return mergeJournalEntries(finished, current ? [current] : []);
}

test('FD-04/F06/A36 全程每秒观测、没有缺口才声明连续；窗口两端按阈值容差', () => {
  const journal = createMonitorJournal({gapThresholdMs: 10_000});
  const steps = [];
  for (let second = 0; second <= 180; second += 1) steps.push([second, reading({uploadTotal: second * 10, downloadTotal: second * 20, connections: []})]);
  const entries = run(journal, steps);
  assert.equal(entries.length, 4, '0—180 秒跨四个分钟');
  const coverage = journalCoverage(entries, {start: at(0), end: at(180)});
  assert.equal(coverage.continuous, true, JSON.stringify(coverage.gaps));
  assert.equal(coverage.observedTicks, 180, '窗口左闭右开：第 180 秒那一拍不算');
  const wider = journalCoverage(entries, {start: at(-600), end: at(180)});
  assert.equal(wider.continuous, false);
  assert.deepEqual(wider.gaps.map((gap) => [gap.from, gap.reason]), [[at(-600), 'NOT_MONITORED']], '开始监测之前的时段是缺口');
});

test('FD-04/F06/R10 睡眠停顿、服务不可达、内核未运行、应用未运行分别记成带起止的缺口', () => {
  const journal = createMonitorJournal({gapThresholdMs: 10_000, resumeFrom: at(-300)});
  const ok = reading({uploadTotal: 1, downloadTotal: 1, connections: []});
  const steps = [[0, ok], [1, ok], [2, ok], [120, ok], [121, ok]];
  for (let second = 122; second <= 150; second += 1) steps.push([second, {ok: true, reachable: false, code: 'SERVICE_UNREACHABLE'}]);
  steps.push([151, ok], [152, ok]);
  for (let second = 153; second <= 190; second += 1) steps.push([second, {ok: true, reachable: true, core_running: false}]);
  steps.push([191, ok], [192, ok]);
  const entries = run(journal, steps);
  const coverage = journalCoverage(entries, {start: at(-300), end: at(192)});
  assert.equal(coverage.continuous, false);
  const reasons = coverage.gaps.map((gap) => gap.reason);
  assert.deepEqual(reasons, ['APP_NOT_RUNNING', 'MONITOR_PAUSED', 'SERVICE_UNREACHABLE', 'CORE_NOT_RUNNING'], JSON.stringify(coverage.gaps));
  assert.deepEqual([coverage.gaps[0].from, coverage.gaps[0].to], [at(-300), at(0)], '缺口起止是实际没有观测的区间');
  assert.deepEqual([coverage.gaps[1].from, coverage.gaps[1].to], [at(2), at(120)]);
  assert.deepEqual([coverage.gaps[2].from, coverage.gaps[2].to], [at(122), at(151)]);
});

test('RC5 Round 2 FD-04/A36 同一分钟内超过阈值的停顿切断覆盖，首末节拍不能把它桥接成连续；阈值内的间隔照常连续', () => {
  const ok = reading({uploadTotal: 1, downloadTotal: 1, connections: []});
  const paused = run(createMonitorJournal({gapThresholdMs: 10_000}), [[0, ok], [1, ok], [31, ok], [32, ok]]);
  assert.equal(paused.length, 1, '四拍都在同一分钟');
  assert.deepEqual(paused[0].gaps.map((gap) => [gap.from, gap.to, gap.reason]), [[at(1), at(31), 'MONITOR_PAUSED']]);
  const coverage = journalCoverage(paused, {start: at(0), end: at(32)}, {gapThresholdMs: 10_000});
  assert.equal(coverage.continuous, false);
  assert.deepEqual(coverage.gaps.map((gap) => [gap.from, gap.to, gap.reason]), [[at(1), at(31), 'MONITOR_PAUSED']]);

  const short = run(createMonitorJournal({gapThresholdMs: 10_000}), [[0, ok], [1, ok], [9, ok], [10, ok]]);
  assert.deepEqual(short[0].gaps, [], '8 秒间隔没超过阈值，不记停顿');
  assert.equal(journalCoverage(short, {start: at(0), end: at(10)}, {gapThresholdMs: 10_000}).continuous, true);
});

test('FD-04/F03-F04/A22 归属按连接增量：恢复观测后的已有连接只作基线，连续观测中新开的连接全部归属，短连接差额单列', () => {
  const journal = createMonitorJournal({gapThresholdMs: 10_000});
  const entries = run(journal, [
    [0, reading({uploadTotal: 1000, downloadTotal: 5000, connections: [connection('old', {upload: 900, download: 4000})]})],
    [1, reading({uploadTotal: 1100, downloadTotal: 5300, connections: [connection('old', {upload: 950, download: 4200}), connection('new', {upload: 30, download: 60})]})],
    [2, reading({uploadTotal: 1300, downloadTotal: 5700, connections: [
      connection('old', {upload: 950, download: 4200}),
      connection('new', {upload: 40, download: 80}),
      connection('direct', {process: 'Code.exe', chains: ['DIRECT'], upload: 10, download: 10}),
      connection('anon', {process: null, chains: ['EXIT-B', 'PROXY-B', 'GENERAL-EGRESS'], upload: 5, download: 5}),
    ]})],
  ]);
  const attribution = entries[0].attribution;
  assert.deepEqual(attribution.byProcess['claude.exe'], {uploadBytes: 90, downloadBytes: 280}, 'old 的增量 50/200 + new 的 30/60 + 10/20；old 第一次出现只作基线');
  assert.deepEqual(attribution.byEgress.A, {uploadBytes: 90, downloadBytes: 280});
  assert.deepEqual(attribution.byEgress.DIRECT, {uploadBytes: 10, downloadBytes: 10});
  assert.deepEqual(attribution.byEgress.B, {uploadBytes: 5, downloadBytes: 5});
  assert.deepEqual(attribution.byRoute['CLAUDE-FIXED'], {uploadBytes: 90, downloadBytes: 280});
  assert.deepEqual(attribution.unattributedProcess, {uploadBytes: 5, downloadBytes: 5}, '没有进程字段的连接记为来源未识别');
  assert.deepEqual(attribution.shortLivedUnattributed, {uploadBytes: (100 - 80) + (200 - 25), downloadBytes: (300 - 260) + (400 - 35)}, '内核累计增量里连接增量解释不了的部分');
});

test('FD-04/F06/A22 窗口计数交给 accumulateTraffic：前一分钟的计数作基线，内核换实例记 COUNTER_RESET 而不是负数或重复累加', () => {
  const journal = createMonitorJournal({gapThresholdMs: 10_000});
  const steps = [];
  for (let second = 0; second <= 240; second += 1) {
    const restarted = second >= 150;
    steps.push([second, reading({uploadTotal: restarted ? (second - 150) * 3 : second * 5, downloadTotal: restarted ? (second - 150) * 7 : second * 11, connections: []}, {core_instance: restarted ? '5101:2' : '5100:1'})]);
  }
  const entries = run(journal, steps);
  const window = {start: at(60), end: at(240)};
  const {samples} = journalTraffic(entries, window);
  assert.equal(samples[0].baselineKnown, true, '窗口起点前一分钟的计数作已知基线');
  let state = {};
  const statuses = [];
  for (const sample of samples) {
    const result = accumulateTraffic(state, sample);
    state = result.state;
    statuses.push(result.status);
  }
  assert.ok(statuses.includes('COUNTER_RESET'), statuses.join(','));
  assert.ok(state.totals.uploadBytes >= 0 && state.totals.downloadBytes >= 0);
  assert.ok(state.coverageIssues.some((item) => item.code === 'COUNTER_RESET'));
  // 样本取每分钟最后一拍：59 秒（基线）、119 秒、179 秒（新实例）、239 秒。重启前 300；重启那一段记 COUNTER_RESET 不补；之后 (239-179)×3。
  assert.equal(state.totals.uploadBytes, (119 - 59) * 5 + (239 - 179) * 3);
});
