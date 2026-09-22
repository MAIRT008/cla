import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {appendFile, mkdir, readdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {createNativeHostDouble} from './nativeHostDouble.mjs';
import {createBridgeWorkspaceAdapter} from '../../src/adapters/local/bridgeWorkspace.mjs';
import {createBridgeAuditStore} from '../../src/adapters/audit/bridgeStore.mjs';
import {createNativeCorePort, createNativeProtectionPort} from '../../src/adapters/network/nativePorts.mjs';
import {createNetworkController, productAuditMapping} from '../../src/core/network/index.mjs';
import {buildDailyReport, deliverDailyReport} from '../../src/core/audit/index.mjs';
import {createAuditRuntime} from '../../src/adapters/audit/runtime.mjs';
import {journalCoverage} from '../../src/core/audit/monitor.mjs';
import {createDiagnosticExport} from '../../src/adapters/audit/diagnosticExport.mjs';
import {createPageRuntime} from '../ui/page.mjs';
import {composition} from './harness.mjs';
import {PERSISTED_MAX_SESSION, createHostFetch, readyControl, withIdentityRoutes} from './productHost.mjs';

/**
 * RC5 正式链路：宿主替身（站在 Rust 宿主 + logs.rs 的位置）→ 原生网络端口 → 网络核心 → 审计运行时。
 * 内核日志行按仓库内 Mihomo v1.19.30 源码的 logrus 格式构造，连接 chains 按 Mihomo 的「叶子在前、组在后」。
 * 证明的是接线与语义；不证明 Rust 宿主、服务或真实内核已经运行。
 */
const ENV = 'windows-host';
const CLAUDE = 'C:\\Program Files\\Claude\\claude.exe';
const ASSIGNMENT = Object.freeze({
  user_ref: 'user-max',
  environment_ref: ENV,
  assignment_version: 3,
  template_version: 7,
  template: {protected_process_paths: [CLAUDE], managed_browser_processes: ['claude-browser.exe']},
});

function mihomo(time, level, message) {
  return `time="${time}" level=${level} msg="${message.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}
function using(time, process, host, chain) {
  return mihomo(time, 'info', `[TCP] 127.0.0.1:52345(${process}) --> ${host}:443 match DomainSuffix(anthropic.com) using ${chain}`);
}
function localTime(iso) {
  return new Date(Date.parse(iso) - 7 * 3600_000).toISOString().replace('Z', '000000-07:00').replace(/\.(\d{3})000000/, '.$1000000');
}
function good(id, upload = 0, download = 0) {
  return {id, metadata: {process: 'claude.exe', host: 'api.anthropic.com'}, chains: ['EXIT-A', 'PROXY-A', 'CLAUDE-FIXED'], upload, download};
}
function bad(id, upload = 0, download = 0) {
  return {id, metadata: {process: 'claude.exe', host: 'api.anthropic.com'}, chains: ['DIRECT'], upload, download};
}

async function world(t, label, {start, hooks = {}, notices = {}} = {}) {
  const root = transientRun('delivery', `rc5-${label}`);
  await mkdir(root, {recursive: true});
  let now = start;
  const clock = () => now;
  const kernel = {reachable: true, running: true, pid: 5100, startedAt: 1, uploadTotal: 0, downloadTotal: 0, connections: [], tail: [], planVersion: 'plan:3:daily_single_ip:abc', effective: true};
  const protections = [];
  const serviceLogs = path.join(root, 'service-logs');
  const hostLogs = path.join(root, 'host-logs');
  await mkdir(serviceLogs, {recursive: true});
  await mkdir(path.join(root, 'workspace'), {recursive: true});
  const host = createNativeHostDouble({
    workspaceRoot: path.join(root, 'workspace'),
    clock,
    product: {environment_ref: ENV},
    logDirs: {host: hostLogs, control: path.join(root, 'control-logs'), service: serviceLogs},
    hooks,
    notices,
    network: {
      async readState(payload) {
        if (!kernel.reachable) return {service: {status: 'UNREACHABLE'}};
        const include = payload.include || [];
        const runtime = {
          service: {status: 'RUNNING', service_instance_id: 'svc-rc5'},
          core: {running: kernel.running, pid: kernel.running ? kernel.pid : null, started_at_ms: kernel.startedAt, restart_count: 0},
          config: {plan_version: kernel.planVersion, assignment_version: '3'},
          protection: {requested: true, effective: kernel.effective, missing: []},
          readback: {status: 'VERIFIED'},
          missing: [],
        };
        if (include.includes('connections') && kernel.running) {
          runtime.connections = {uploadTotal: kernel.uploadTotal, downloadTotal: kernel.downloadTotal, connections: structuredClone(kernel.connections)};
        }
        if (include.includes('logs')) runtime.logs = [...kernel.tail];
        return runtime;
      },
      async protect(payload) {
        protections.push(structuredClone(payload));
        return {protection: {requested: true, new_connections_restricted: kernel.effective, os_readback: 'VERIFIED'}, close_existing: {status: 'CLOSED', receipt: {closed_existing: true}}};
      },
      async lifecycle() {
        return {ok: false, code: 'LIFECYCLE_NOT_SIMULATED'};
      },
    },
  });
  const invoke = (op, payload, reference) => host.invoke(op, payload, reference);
  const confirm = (request) => host.confirm(request);
  const workspace = await createBridgeWorkspaceAdapter({invoke, confirm, clock});
  const auditStore = createBridgeAuditStore({invoke, confirm, clock});
  const events = {
    online: false,
    delivered: [],
    async deliver(event) {
      if (!this.online) return {delivered: false, code: 'CONTROL_UNREACHABLE'};
      this.delivered.push(structuredClone(event));
      return {delivered: true};
    },
  };
  const control = {
    async getAssignment() { return {ok: true, assignment: structuredClone(ASSIGNMENT)}; },
    async getQuotaSnapshot() { return {ok: true, snapshot: {status: 'ACTIVE'}}; },
  };
  const network = createNetworkController({
    store: workspace,
    control,
    core: createNativeCorePort({invoke, confirm, environmentRef: ENV, clock}),
    protection: createNativeProtectionPort({invoke, confirm, environmentRef: ENV, clock}),
    events,
    clock,
  });
  const runtime = createAuditRuntime({
    invoke,
    confirm,
    auditStore,
    network,
    mapping: productAuditMapping(ASSIGNMENT),
    environmentRef: ENV,
    environments: [{environment_ref: ENV, kind: 'host'}],
    userRef: 'user-max',
    readQuota: async () => ({source: 'server', status: 'ACTIVE', usedBytes: 1234, limitBytes: 5000, observedAt: now}),
    clock,
    timers: {set: () => 0, clear: () => {}},
    appLog: async (level, event, fields) => { await invoke('AppLogAppend', {event, level, fields}); },
    notify: (event, ref) => invoke('NotifyCritical', {event, ref}),
  });
  t.after(async () => { await runtime.idle(); });
  const advance = (seconds) => { now = new Date(Date.parse(now) + seconds * 1000).toISOString(); };
  return {
    root,
    host,
    runtime,
    kernel,
    protections,
    events,
    network,
    auditStore,
    hostLogs,
    serviceLogs,
    advance,
    set(value) { now = value; },
    now: () => now,
    async tickFor(seconds, each = () => {}) {
      for (let index = 0; index < seconds; index += 1) {
        advance(1);
        each(index);
        await runtime.tick();
      }
    },
    async writeCore(lines) {
      await appendFile(path.join(serviceLogs, 'core.log'), lines.map((line) => `${line}\n`).join(''));
    },
  };
}

test('RC5 FD-04/F01 启用前不采集；启用经本地确认，确认框写明采集、自动保护与上报的范围', async (t) => {
  const w = await world(t, 'enable', {start: '2026-09-18T16:30:00.000Z'});
  await w.runtime.start();
  await w.runtime.tick();
  assert.equal(w.host.calls.filter((call) => call.op === 'ReadNetworkState').length, 0, '没启用就不读');
  assert.equal(w.host.calls.filter((call) => call.op === 'LogRead').length, 0, '没启用就不归档');
  const enabled = await w.runtime.enable();
  assert.equal(enabled.ok, true, JSON.stringify(enabled));
  const prompt = w.host.confirmations.find((item) => item.scope === 'preauthorized_protection');
  for (const word of ['采集', '自动保护', '上报', '不发送访问明细']) assert.match(prompt.caller_summary, new RegExp(word));
  assert.equal(enabled.status.enabled, true);
  assert.ok(enabled.status.protection_authorization_expires_at, '显示预授权的到期时刻');
  await w.runtime.tick();
  assert.equal(w.host.calls.filter((call) => call.op === 'ReadNetworkState').length, 1, '每拍一次读取同时取连接、计数与日志');
  assert.ok(await w.auditStore.exists('state/monitor.json'), '启用状态落在应用自己的审计目录');
});

test('RC5 FD-04/F23-F29/A26/A28 真实格式内核日志经宿主只读归档；LA 09:00 后首次唤醒发生在 11:05 时补做日报', async (t) => {
  const w = await world(t, 'schedule', {start: '2026-09-18T15:40:00.000Z'});
  await w.writeCore([
    mihomo(localTime('2026-09-18T15:30:00.000Z'), 'info', 'Start initial configuration in progress'),
    using(localTime('2026-09-18T15:31:00.000Z'), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]'),
    using(localTime('2026-09-18T15:32:00.000Z'), 'chrome.exe', 'example.com', 'GENERAL-EGRESS[EXIT-A]'),
  ]);
  await w.runtime.start();
  assert.equal((await w.runtime.enable()).ok, true);
  await w.runtime.tick();
  await w.runtime.idle();
  const first = w.runtime.status();
  assert.equal(first.last_run.kind, 'ARCHIVE', '08:40 只做到期归档，日报未到期');
  assert.equal(first.last_run.planned.daily.reason, 'BEFORE_0900');
  assert.equal(first.last_run.archive.newCount, 1);
  assert.equal(first.last_run.archive.notification, 'DONT_NOTIFY', '正常归档静默');
  assert.equal(first.alerts.length, 0);
  assert.ok(w.host.calls.some((call) => call.op === 'LogRead'), '内核日志经宿主 LogRead 取得');
  const archived = (await w.auditStore.listPaths('archive')).map((entry) => entry.path);
  assert.ok(archived.some((item) => /\/raw\/core\.snapshot_20260918-084000000\.log$/.test(item)), archived.join('\n'));
  assert.equal(await readFile(path.join(w.serviceLogs, 'core.log'), 'utf8').then((text) => text.split('\n').length), 4, '源日志不改不删');

  await w.tickFor(30);
  await w.runtime.idle();
  assert.equal(w.runtime.status().last_run.started_at, first.last_run.started_at, '两小时未到不重复归档');

  await w.writeCore([using(localTime('2026-09-18T17:00:00.000Z'), 'claude.exe', 'claude.ai', 'CLAUDE-FIXED[EXIT-A]')]);
  w.set('2026-09-18T18:05:00.000Z');
  await w.runtime.tick();
  await w.runtime.idle();
  const status = w.runtime.status();
  assert.equal(status.last_wake.paused_from, '2026-09-18T15:40:30.000Z', '长时间停顿按睡眠恢复处理');
  assert.equal(status.last_run.kind, 'ARCHIVE_AND_DAILY', '11:05 的首次唤醒：到期归档与日报一起做');
  assert.equal(status.last_run.daily.status, 'DELIVERED');
  const report = JSON.parse(await w.auditStore.readText('reports/2026-09-18/daily-audit.json'));
  assert.equal(report.generatedAt, '2026-09-18T18:05:00.000Z');
  assert.equal(report.routeCounts.passRoute, 2, '两条 Claude 相关记录；Chrome 普通流量不计入');
  assert.equal(report.routeCounts.unknown, 0);
  assert.equal(report.routeResult, 'MONITORING_INCOMPLETE', '窗口大部分时间没在监测，不能 DAILY_PASS');
  const reasons = report.collectionEvidence.gaps.map((gap) => gap.reason);
  assert.ok(reasons.includes('MONITOR_PAUSED'), reasons.join(','));
  assert.ok(reasons.includes('NOT_MONITORED'), '启用之前的时段是缺口');
  assert.equal(report.quota.usedBytes, 1234, '日报引用服务端额度快照');
  assert.ok(await w.auditStore.exists('reports/2026-09-18/daily-audit.md'));

  await w.tickFor(3);
  await w.runtime.idle();
  assert.equal(w.runtime.status().last_run.started_at, '2026-09-18T18:05:00.000Z', '双文件已交付，当天不再生成');
  assert.equal(w.runtime.status().scheduler.delivered_date, '2026-09-18');
});

test('RC5 FD-04/F14-F19/A06/A16/A20 实时错误出口：正确链路不报；错误出口立即提示并经预授权保护；同一连接只算一次；后台离线待报、恢复后按同一引用补报', async (t) => {
  const w = await world(t, 'protect', {start: '2026-09-18T17:00:00.000Z'});
  await w.writeCore([using(localTime('2026-09-18T16:59:00.000Z'), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]')]);
  await w.runtime.start();
  await w.runtime.enable();
  w.kernel.connections = [good('ok-1', 10, 20)];
  w.kernel.tail = [using(localTime('2026-09-18T16:59:59.000Z'), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]')];
  await w.tickFor(2);
  await w.runtime.idle();
  assert.equal(w.runtime.status().alerts.length, 0, 'CLAUDE-FIXED[EXIT-A] 与 chains [EXIT-A, PROXY-A, CLAUDE-FIXED] 都是批准路线');
  assert.equal(w.protections.length, 0);

  w.kernel.connections = [good('ok-1', 10, 20), bad('bad-1', 5, 5)];
  w.kernel.tail = [...w.kernel.tail, using(localTime('2026-09-18T17:00:02.000Z'), 'claude.exe', 'api.anthropic.com', 'DIRECT')];
  await w.tickFor(1);
  const raised = w.runtime.status().alerts;
  assert.equal(raised[0].level, 'critical');
  assert.equal(raised[0].kind, 'WRONG_ROUTE', '提示在保护完成之前就出现');
  await w.runtime.idle();
  assert.equal(w.protections.length, 1, '连接快照与日志行是同一次连接，只保护一次');
  assert.deepEqual(w.protections[0].processes, [CLAUDE]);
  assert.equal(w.protections[0].reason_code, 'WRONG_ROUTE');
  assert.equal(w.host.calls.find((call) => call.op === 'ProtectEnvironment').scope, 'preauthorized_protection');

  await w.tickFor(5);
  await w.runtime.idle();
  assert.equal(w.protections.length, 1, '同一连接、同一行后面每拍不再重复处理');
  const [incident] = w.network.listIncidents();
  assert.equal(incident.count, 1);
  assert.equal(incident.protection.status, 'CONFIRMED');
  assert.equal(w.network.listEventOutbox()[0].status, 'PENDING', '后台离线：事件留在本地待报');

  w.kernel.connections = [good('ok-1', 10, 20), bad('bad-2', 1, 1)];
  await w.tickFor(1);
  await w.runtime.idle();
  assert.equal(w.network.listIncidents()[0].count, 2, '同一持续故障归并为一个事件，次数累加');
  assert.equal(w.runtime.status().alerts.filter((item) => item.kind === 'WRONG_ROUTE').length, 1, '不重复弹出多条同样的提示');

  w.events.online = true;
  await w.tickFor(31);
  await w.runtime.idle();
  assert.equal(w.events.delivered.length, 1);
  assert.equal(w.events.delivered[0].event_ref, incident.event_ref, '补报沿用同一事件引用，后台按引用去重');
  assert.equal(w.events.delivered[0].count, 2);
  assert.equal(w.network.listEventOutbox()[0].status, 'DELIVERED');
  assert.equal(w.network.listIncidents()[0].delivery.status, 'DELIVERED');
  assert.match(incident.event_ref, /^[A-Za-z0-9._:-]{1,128}$/);
});

test('RC5 FD-04/F02-F06/F36/A22/A23 日报的本机字节来自内核计数；服务不可达与内核重启如实列为缺口与重置；A/B 与进程归属按连接增量', async (t) => {
  const w = await world(t, 'traffic', {start: '2026-09-18T15:55:00.000Z'});
  const prior = buildDailyReport({now: '2026-09-17T16:00:00.000Z', window: {start: '2026-09-16T15:55:00.000Z', end: '2026-09-18T15:55:00.000Z'}, records: [], traffic: {totals: null, coverageIssues: []}, archive: {entries: [], issues: []}});
  prior.reportDate = '2026-09-17';
  prior.reportId = 'audit-2026-09-17-prior';
  assert.equal((await deliverDailyReport(prior, {reportRoot: 'reports'}, w.auditStore)).status, 'DELIVERED');
  await w.writeCore([using(localTime('2026-09-18T15:56:00.000Z'), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]')]);
  await w.runtime.start();
  await w.runtime.enable();
  await w.runtime.tick();
  await w.runtime.idle();
  let up = 1000;
  await w.tickFor(310, (second) => {
    up += 100;
    w.kernel.uploadTotal = up;
    w.kernel.downloadTotal = up * 2;
    w.kernel.connections = [good('stream', second * 40, second * 80), {id: 'b', metadata: {process: 'Code.exe', host: 'x.example'}, chains: ['EXIT-B', 'PROXY-B', 'GENERAL-EGRESS'], upload: second * 10, download: second * 10}];
    w.kernel.reachable = !(second >= 60 && second < 90);
    if (second === 200) {
      w.kernel.pid = 5101;
      w.kernel.startedAt = 2;
      up = 0;
    }
  });
  await w.runtime.idle();
  const status = w.runtime.status();
  assert.equal(status.last_run.kind, 'ARCHIVE_AND_DAILY', JSON.stringify(status.last_run?.planned));
  const report = JSON.parse(await w.auditStore.readText('reports/2026-09-18/daily-audit.json'));
  assert.equal(report.windowStart, '2026-09-18T15:55:00.000Z', '窗口接上一份完整有效日报的结束时刻');
  assert.ok(report.traffic.totals.uploadBytes > 0);
  assert.notEqual(report.traffic.totals.uploadBytes, report.routeCounts.passRoute, '字节不是日志条数');
  assert.ok(report.traffic.coverageIssues.some((item) => item.code === 'COUNTER_RESET'), '内核重启：累计计数重置记缺口，不补零');
  const gap = report.collectionEvidence.gaps.find((item) => item.reason === 'SERVICE_UNREACHABLE');
  assert.ok(gap, JSON.stringify(report.collectionEvidence.gaps));
  assert.ok(Date.parse(gap.to) - Date.parse(gap.from) >= 25_000, '服务不可达约 30 秒');
  assert.ok(report.traffic.byEgress.A.uploadBytes > 0 && report.traffic.byEgress.B.uploadBytes > 0, 'A/B 分开');
  assert.ok(report.traffic.byProcess['claude.exe'].uploadBytes > 0 && report.traffic.byProcess['code.exe'].uploadBytes > 0);
  assert.equal(report.traffic.attributionBasis, 'CONNECTION_DELTAS_BETWEEN_READS');
  assert.equal(report.coverageStatus, 'MONITORING_INCOMPLETE');
  assert.notEqual(report.routeResult, 'DAILY_PASS');
  assert.equal(report.quota.source, 'server', '本机字节与服务端额度分开记');
});

async function dailyAcrossPause(t, label, pauseSeconds) {
  const w = await world(t, label, {start: '2026-09-18T15:56:30.000Z'});
  const prior = buildDailyReport({now: '2026-09-17T16:00:00.000Z', window: {start: '2026-09-16T15:58:00.000Z', end: '2026-09-18T15:58:00.000Z'}, records: [], traffic: {totals: null, coverageIssues: []}, archive: {entries: [], issues: []}});
  prior.reportDate = '2026-09-17';
  prior.reportId = `audit-2026-09-17-${label}`;
  assert.equal((await deliverDailyReport(prior, {reportRoot: 'reports'}, w.auditStore)).status, 'DELIVERED');
  await w.writeCore([using(localTime('2026-09-18T15:56:00.000Z'), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]')]);
  await w.runtime.start();
  await w.runtime.enable();
  let bytes = 0;
  const feed = () => {
    bytes += 100;
    w.kernel.uploadTotal = bytes;
    w.kernel.downloadTotal = bytes * 2;
    w.kernel.connections = [good('stream', bytes, bytes * 2)];
  };
  await w.tickFor(155, feed);
  await w.runtime.idle();
  assert.equal(w.now(), '2026-09-18T15:59:05.000Z');
  await w.writeCore([using(localTime('2026-09-18T15:59:00.000Z'), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]')]);
  w.advance(pauseSeconds);
  await w.tickFor(120, feed);
  await w.runtime.idle();
  assert.equal(w.runtime.status().last_run.kind, 'ARCHIVE_AND_DAILY', JSON.stringify(w.runtime.status().last_run?.planned));
  return JSON.parse(await w.auditStore.readText('reports/2026-09-18/daily-audit.json'));
}

test('RC5 Round 2 FD-04/A36 同一分钟内停顿 30 秒：日报列出监测停顿缺口、不判 DAILY_PASS；同一场景没有停顿时是 DAILY_PASS', async (t) => {
  const clean = await dailyAcrossPause(t, 'pause-control', 0);
  assert.equal(clean.collectionEvidence.continuous, true, JSON.stringify(clean.collectionEvidence.gaps));
  assert.equal(clean.coverageStatus, 'COMPLETE', JSON.stringify(clean.coverageIssues));
  assert.equal(clean.routeResult, 'DAILY_PASS', '对照：场景本身能通过，下面的失败只来自停顿');

  const paused = await dailyAcrossPause(t, 'pause-in-minute', 29);
  assert.equal(paused.collectionEvidence.continuous, false);
  assert.deepEqual(paused.collectionEvidence.gaps.map((gap) => [gap.from, gap.to, gap.reason]), [['2026-09-18T15:59:05.000Z', '2026-09-18T15:59:35.000Z', 'MONITOR_PAUSED']]);
  assert.equal(paused.coverageStatus, 'MONITORING_INCOMPLETE');
  assert.equal(paused.routeResult, 'MONITORING_INCOMPLETE');
});

test('RC5 Round 2 FD-04/A36 分钟记录写失败：取出的分钟留在缓存里待重试，下次落盘补写；其间别的文件写成功不算恢复，last_tick_at 不推进', async (t) => {
  const hourFile = 'monitor/2026-09-18/07.json';
  let diskFull = true;
  const w = await world(t, 'journal-retry', {
    start: '2026-09-18T14:59:00.000Z',
    hooks: {FileWrite: ({payload}) => (diskFull && payload.path === `audit/${hourFile}` ? {ok: false, code: 'NATIVE_IO_FAILED', reason: 'ENOSPC: no space left on device'} : null)},
  });
  await w.writeCore([using(localTime('2026-09-18T14:58:00.000Z'), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]')]);
  await w.runtime.start();
  await w.runtime.enable();
  const lastTickOnDisk = async () => JSON.parse(await w.auditStore.readText('state/scheduler.json')).last_tick_at ?? null;

  await w.tickFor(1);
  await w.runtime.idle();
  assert.equal(w.runtime.status().storage.status, 'WRITE_FAILED');
  assert.equal(w.runtime.status().storage.path, hourFile);
  assert.equal(await w.auditStore.exists(hourFile), false);
  assert.equal(await lastTickOnDisk(), null, '调度状态照常写成功，但分钟记录没落盘就不推进 last_tick_at');

  await w.tickFor(60);
  await w.runtime.idle();
  assert.equal(w.now(), '2026-09-18T15:00:01.000Z');
  assert.ok(await w.auditStore.exists('monitor/2026-09-18/08.json'), '下一小时的文件照常写');
  assert.equal(await w.auditStore.exists(hourFile), false, '07 点最后一分钟在这次落盘里结束，仍然写不进');
  assert.equal(w.runtime.status().storage.status, 'WRITE_FAILED', '08 点文件与调度状态写成功都不算 07 点恢复');
  assert.equal(await lastTickOnDisk(), null);

  diskFull = false;
  await w.tickFor(60);
  await w.runtime.idle();
  const status = w.runtime.status();
  assert.equal(status.storage.status, 'OK');
  assert.ok(status.storage.recovered_at);
  const earlier = JSON.parse(await w.auditStore.readText(hourFile)).entries;
  assert.deepEqual(earlier.map((entry) => [entry.minute, entry.first_at, entry.last_at, entry.ticks]), [['2026-09-18T14:59:00.000Z', '2026-09-18T14:59:01.000Z', '2026-09-18T14:59:59.000Z', 59]], '已取出的整分钟补写进去，不丢');
  assert.equal(await lastTickOnDisk(), '2026-09-18T15:01:01.000Z', '全部写成功后才推进');
  const later = JSON.parse(await w.auditStore.readText('monitor/2026-09-18/08.json')).entries;
  const coverage = journalCoverage([...earlier, ...later], {start: '2026-09-18T14:59:01.000Z', end: '2026-09-18T15:01:01.000Z'});
  assert.equal(coverage.continuous, true, JSON.stringify(coverage.gaps));
});

function badTo(id, host) {
  return {id, metadata: {process: 'claude.exe', host}, chains: ['DIRECT'], upload: 3, download: 3};
}

test('RC6 FD-04/F17 窗口隐藏时 WRONG_ROUTE 与保护未确认各发一次系统通知；载荷只有固定事件与提示编号；同一故障重复计数不再弹', async (t) => {
  const w = await world(t, 'rc6-notify-hidden', {start: '2026-09-18T17:00:00.000Z', notices: {hidden: true}});
  await w.runtime.start();
  await w.runtime.enable();
  w.kernel.effective = false;
  w.kernel.connections = [bad('bad-1', 5, 5)];
  await w.tickFor(1);
  await w.runtime.idle();
  const requests = w.host.notices.requests;
  assert.deepEqual(requests.map((item) => item.event), ['WRONG_ROUTE', 'PROTECTION_NOT_CONFIRMED']);
  for (const item of requests) assert.deepEqual(Object.keys(item).sort(), ['event', 'ref'], '页面只给固定事件与提示编号，标题正文由宿主定');
  assert.equal(/anthropic|claude\.exe|DIRECT|EXIT-A/.test(JSON.stringify(requests)), false, '目标、进程与路线不进通知');
  const alerts = w.runtime.status().alerts;
  const wrong = alerts.find((item) => item.kind === 'WRONG_ROUTE');
  const unconfirmed = alerts.find((item) => item.kind === 'PROTECTION_NOT_CONFIRMED');
  assert.equal(requests[0].ref, wrong.id);
  assert.equal(requests[1].ref, unconfirmed.id);
  assert.equal(wrong.system_notice.status, 'SHOWN');
  assert.equal(unconfirmed.system_notice.status, 'SHOWN');

  w.kernel.connections = [bad('bad-2', 1, 1)];
  await w.tickFor(1);
  await w.runtime.idle();
  assert.equal(w.runtime.status().alerts.find((item) => item.kind === 'WRONG_ROUTE').count, 2, '同一持续故障只累加次数');
  assert.equal(w.host.notices.requests.length, 2, '重复计数不重复弹系统通知');
});

test('RC6 FD-04/F17 窗口可见时不另弹；通知不可用时记本地错误、危急提示保留、不报已通知；正常归档静默', async (t) => {
  const w = await world(t, 'rc6-notify-fail', {start: '2026-09-18T15:40:00.000Z', notices: {hidden: false}});
  await w.writeCore([using(localTime('2026-09-18T15:39:00.000Z'), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]')]);
  await w.runtime.start();
  await w.runtime.enable();
  await w.runtime.tick();
  await w.runtime.idle();
  assert.equal(w.runtime.status().last_run.kind, 'ARCHIVE');
  assert.equal(w.host.notices.requests.length, 0, '正常归档静默');

  w.kernel.connections = [badTo('bad-visible', 'api.anthropic.com')];
  await w.tickFor(1);
  await w.runtime.idle();
  const visible = w.runtime.status().alerts.find((item) => item.kind === 'WRONG_ROUTE');
  assert.equal(visible.system_notice.status, 'SKIPPED_WINDOW_VISIBLE', '窗口可见时横幅已在，不另弹');

  w.host.notices.hidden = true;
  w.host.notices.fail = 'NOTIFICATION_UNAVAILABLE';
  w.kernel.connections = [badTo('bad-hidden', 'claude.ai')];
  await w.tickFor(1);
  await w.runtime.idle();
  const hidden = w.runtime.status().alerts.find((item) => item.kind === 'WRONG_ROUTE' && item.id !== visible.id);
  assert.ok(hidden, JSON.stringify(w.runtime.status().alerts));
  assert.deepEqual([hidden.system_notice.status, hidden.system_notice.code], ['FAILED', 'NOTIFICATION_UNAVAILABLE']);
  assert.equal(hidden.level, 'critical');
  assert.equal(hidden.acknowledged, false, '页面危急状态保留');
  assert.equal(w.runtime.status().alerts.some((item) => item.system_notice?.status === 'SHOWN'), false, '没弹出的不报已通知');
  const lines = (await readFile(w.host.logs.appLogPath(), 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
  assert.ok(lines.some((line) => line.event === 'monitor.notify_failed' && line.fields.code === 'NOTIFICATION_UNAVAILABLE'));
  assert.ok(lines.some((line) => line.event === 'native.op_failed' && line.fields.op === 'NotifyCritical'));
});

test('RC5 FD-04/F38 诊断包：预览标出访问明细且默认不选；导出逐个脱敏、清单最后写；写失败明说未生成、不留清单', async (t) => {
  let failName = null;
  const w = await world(t, 'export', {
    start: '2026-09-18T18:00:00.000Z',
    hooks: {
      LogExportWrite: ({payload}) => (payload.name === failName ? {ok: false, code: 'LOG_EXPORT_WRITE_FAILED', reason: 'ENOSPC: no space left on device'} : null),
    },
  });
  await mkdir(w.hostLogs, {recursive: true});
  await writeFile(path.join(w.hostLogs, 'host-control-20260918T170000000Z-4242.log'), '{"event":"control.process.spawned","fields":{"header":"Authorization: Bearer abc123secret"}}\n');
  await writeFile(path.join(w.serviceLogs, 'service.log'), '{"event":"ipc.command","fields":{"command":"ObserveRuntime"}}\n');
  await w.writeCore([using(localTime('2026-09-18T17:59:00.000Z'), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]')]);
  const exporter = createDiagnosticExport({invoke: (op, payload, ref) => w.host.invoke(op, payload, ref), clock: w.now, statusSummary: async () => w.runtime.status()});

  const preview = await exporter.preview();
  assert.equal(preview.ok, true);
  const core = preview.items.find((item) => item.source_ref === 'network_core/core.log');
  assert.equal(core.contains_access_history, true);
  assert.equal(core.selected, false, '访问明细默认不选');
  assert.equal((await exporter.create({})).code, 'EXPORT_NOT_CONFIRMED');

  const created = await exporter.create({confirmed: true});
  assert.equal(created.ok, true, JSON.stringify(created));
  const folder = path.join(w.hostLogs, 'exports', created.export_ref);
  const files = await readdir(folder);
  assert.ok(files.includes('manifest.json'));
  assert.equal(files.includes('network_core__core.log'), false);
  const exportedHost = await readFile(path.join(folder, 'host__host-control-20260918T170000000Z-4242.log'), 'utf8');
  assert.equal(exportedHost.includes('abc123secret'), false);
  assert.match(exportedHost, /Authorization: \[redacted\]/);
  const manifest = JSON.parse(await readFile(path.join(folder, 'manifest.json'), 'utf8'));
  const hostEntry = manifest.files.find((item) => item.source_ref.startsWith('host/'));
  assert.equal(hostEntry.derived, 'REDACTED');
  assert.notEqual(hostEntry.sha256, hostEntry.source_sha256, '脱敏件不冒称与原件一致');
  assert.equal(manifest.uploaded, false);
  assert.ok(manifest.excluded.some((item) => item.source_ref === 'network_core/core.log'));
  assert.equal((await exporter.openFolder('export', created.export_ref)).ok, true);
  assert.ok(w.host.logs.opened.includes(folder));

  failName = 'network_service__service.log';
  const failed = await exporter.create({confirmed: true});
  assert.equal(failed.ok, false);
  assert.match(failed.message, /诊断包未生成/);
  assert.equal(failed.code, 'LOG_EXPORT_WRITE_FAILED');
  assert.equal(existsSync(path.join(w.hostLogs, 'exports', failed.export_ref, 'manifest.json')), false, '写失败的包没有清单，不冒充已生成');
});

test('RC5 本地日志：失败的原生操作留一行（操作名与错误码，不记载荷）；运行时自己的失败写进同一个进程日志文件', async (t) => {
  const w = await world(t, 'applog', {start: '2026-09-18T18:00:00.000Z', hooks: {FileWrite: ({payload}) => (payload.path.startsWith('audit/state/') ? {ok: false, code: 'NATIVE_IO_FAILED', reason: 'ENOSPC'} : null)}});
  await w.runtime.start();
  const enabled = await w.runtime.enable();
  assert.equal(enabled.ok, false, '启用状态写不进去就如实失败');
  assert.equal(enabled.code, 'NATIVE_IO_FAILED');
  assert.equal(w.runtime.status().storage.status, 'WRITE_FAILED');
  await w.host.invoke('FileRead', {path: '../outside/secret.txt'});
  const logFile = w.host.logs.appLogPath();
  assert.match(path.basename(logFile), /^app-\d{8}T\d{9}Z-\d+\.log$/);
  const lines = (await readFile(logFile, 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
  assert.ok(lines.some((line) => line.event === 'audit.storage_write_failed' && line.fields.code === 'NATIVE_IO_FAILED'));
  assert.ok(lines.some((line) => line.event === 'native.op_failed' && line.fields.op === 'FileWrite' && line.fields.code === 'NATIVE_IO_FAILED'));
  const outside = lines.find((line) => line.event === 'native.op_failed' && line.fields.op === 'FileRead');
  assert.ok(outside);
  assert.equal(JSON.stringify(lines).includes('secret.txt'), false, '载荷与路径不进日志');
});

test('RC5 正式页面：点「启用监测与保护」经本地确认；错误出口立即出现危急提示条，点「我知道了」收起；诊断包预览、导出与打开目录都走按钮', async (t) => {
  const prepared = await composition('rc5-page');
  const base = transientRun('delivery', 'rc5-page-logs');
  const logDirs = {host: path.join(base, 'host'), control: path.join(base, 'control'), service: path.join(base, 'service')};
  await mkdir(logDirs.service, {recursive: true});
  await mkdir(logDirs.host, {recursive: true});
  await writeFile(path.join(logDirs.service, 'core.log'), `${using(localTime(new Date().toISOString()), 'claude.exe', 'api.anthropic.com', 'CLAUDE-FIXED[EXIT-A]')}\n`);
  await writeFile(path.join(logDirs.host, 'host-control-20260918T000000000Z-1.log'), '{"event":"control.ready","fields":{"cookie":"sid=abcdef"}}\n');
  const kernel = {connections: [good('page-ok', 1, 1)]};
  const protections = [];
  const double = createNativeHostDouble({
    workspaceRoot: prepared.root,
    clock: () => new Date().toISOString(),
    logDirs,
    product: {
      control_base_url: 'https://control.synthetic.invalid',
      windows_user: 'synthetic-user',
      environment_ref: 'windows-host',
      control: readyControl('https://control.synthetic.invalid'),
    },
    session: PERSISTED_MAX_SESSION,
    network: {
      readState: async (payload) => ({
        service: {status: 'RUNNING'},
        core: {running: true, pid: 7100, started_at_ms: 1},
        config: {plan_version: null},
        protection: {requested: true, effective: true},
        ...((payload.include || []).includes('connections') ? {connections: {uploadTotal: 10, downloadTotal: 20, connections: structuredClone(kernel.connections)}} : {}),
        ...((payload.include || []).includes('logs') ? {logs: []} : {}),
      }),
      protect: async (payload) => {
        protections.push(payload);
        return {protection: {requested: true, new_connections_restricted: true}, close_existing: {status: 'CLOSED'}};
      },
    },
  });
  const page = await createPageRuntime('rc5-page-ui', {
    hostPrimitives: {
      __TAURI__: {core: {invoke: (command, args) => {
        if (command === 'steward_user_confirm') return double.confirm(args.request);
        return double.invoke(args.op, args.payload, args.authorizationRef);
      }}},
      fetch: createHostFetch({controlBaseUrl: 'https://control.synthetic.invalid', controlHandler: withIdentityRoutes(prepared), core: prepared.core}),
      navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true, hardwareConcurrency: 8, cookieEnabled: true},
      RTCPeerConnection: null,
    },
  });
  const current = await page.window.__STEWARD_BOOT__;
  const runtime = current.compose.auditRuntime;
  // 页面动作经原生桥往返后才重绘：断言 DOM 前等到条件成立（最多约 1 秒）。
  const until = async (check) => {
    for (let attempt = 0; attempt < 100 && !check(); attempt += 1) await new Promise((resolve) => setTimeout(resolve, 10));
    return check();
  };
  t.after(async () => {
    await current.compose.dispose();
    page.close();
    prepared.close();
  });
  assert.equal(current.session.snapshot().monitor.enabled, false);
  assert.equal(page.document.getElementById('criticalBanner').hidden, true);

  await page.click('monitorEnable');
  assert.ok(await until(() => /已启用/.test(page.text('monitorScope'))), page.text('monitorScope'));
  assert.equal(current.session.snapshot().monitor.enabled, true);
  assert.ok(double.confirmations.some((item) => item.scope === 'preauthorized_protection' && /上报/.test(item.caller_summary)));

  kernel.connections = [good('page-ok', 1, 1), bad('page-bad', 2, 2)];
  await runtime.tick();
  await runtime.idle();
  await page.click('monitorRefresh');
  assert.ok(await until(() => page.document.getElementById('criticalBanner').hidden === false));
  assert.match(page.text('criticalText'), /错误出口/);
  assert.equal(protections.length, 1, '正式装配里的实时检测交给既有预授权保护');
  await page.click('criticalAck');
  assert.ok(await until(() => page.document.getElementById('criticalBanner').hidden === true), '确认后收起');
  assert.match(page.text('monitorAlerts'), /已确认/, '提示仍留在列表里');

  const choices = () => page.document.getElementById('logExportChoices').children.flatMap((label) => label.children).filter((node) => node.tagName === 'INPUT');
  await page.click('logExportPreview');
  assert.ok(await until(() => choices().length > 0));
  const boxes = choices();
  const core = boxes.find((node) => node.dataset.source === 'network_core/core.log');
  assert.equal(core.checked, false, '访问明细默认不选');
  page.document.getElementById('logExportConfirm').checked = true;
  await page.click('logExportCreate');
  assert.ok(await until(() => current.session.snapshot().monitor.export && page.document.getElementById('openExportFolder').disabled === false));
  const exported = current.session.snapshot().monitor.export;
  assert.equal(exported.ok, true, JSON.stringify(exported));
  const folder = path.join(logDirs.host, 'exports', exported.export_ref);
  assert.ok(existsSync(path.join(folder, 'manifest.json')));
  assert.equal((await readFile(path.join(folder, 'host__host-control-20260918T000000000Z-1.log'), 'utf8')).includes('abcdef'), false);
  await page.click('openExportFolder');
  assert.ok(await until(() => double.logs.opened.includes(folder)));
  await page.click('openLogFolder');
  assert.ok(await until(() => double.logs.opened.includes(logDirs.host)));
});
