import assert from 'node:assert/strict';
import path from 'node:path';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {writeFile} from 'node:fs/promises';
import test from 'node:test';
import {FixtureAuditStore} from '../../src/adapters/audit/fixtureStore.mjs';
import {
  accumulateTraffic,
  appendAiNote,
  deliverDailyReport,
  evaluateDailyDue,
  renderMarkdown,
  runAuditPipeline,
  serializeReport,
} from '../../src/core/audit/index.mjs';
import {loadAiNotes, loadAuditReports} from '../../apps/desktop-ui/compose.mjs';
import {composition, confirmedLocalPlan, readWorkspace, scanAndAnswer} from './harness.mjs';

const MAPPING = {version: 'legacy-v2', fixedA: {route: 'CLAUDE-FIXED', member: 'COX-Fixed-Chain'}};
const SETTINGS = 'input/code/settings.json';

function auditRequest(store, now, overrides = {}) {
  return {
    now,
    timezone: 'America/Los_Angeles',
    sourceRoot: 'source',
    archiveRoot: 'archive',
    approvedSourceNames: ['service_latest.log'],
    mapping: MAPPING,
    trafficState: {totals: {uploadBytes: 0, downloadBytes: 0}, observations: {}, coverageIssues: []},
    trafficSamples: [],
    quota: {source: 'server', status: 'ACTIVE', usedBytes: 0, limitBytes: 1000, observedAt: now},
    protection: {status: 'CONFIRMED'},
    collectionEvidence: {environmentRef: 'synthetic-windows', continuous: false, gaps: [{code: 'COLLECTOR_WINDOW_INCOMPLETE'}]},
    reportRoot: 'reports',
    ...overrides,
  };
}

async function auditRoot(label) {
  const root = transientRun('delivery', label);
  return new FixtureAuditStore(path.join(root, 'audit'));
}

test('X12 未知进程与短连接缺测保留，字节来自计量而不是日志条数', async () => {
  const store = await auditRoot('x12');
  await store.writeText('source/service_latest.log', [
    'time="2026-09-13T12:00:00Z" [TCP] (claude.exe) --> api.anthropic.com:443 using CLAUDE-FIXED[COX-Fixed-Chain]',
    'time="2026-09-13T12:01:00Z" [TCP] (unknown.exe) --> example.invalid:443',
    'time="2026-09-13T12:02:00Z" [TCP] dial DIRECT (match DomainSuffix/anthropic.com) (claude.exe) --> api.anthropic.com:443 error: retry using CLAUDE-FIXED[COX-Fixed-Chain] timeout',
  ].join('\n'), {overwrite: false});

  const run = await runAuditPipeline(auditRequest(store, '2026-09-13T16:00:00.000Z', {
    trafficState: {
      totals: {uploadBytes: 0, downloadBytes: 0},
      observations: {'core:core-a': {uploadBytes: 0, downloadBytes: 0, resetId: 'boot-1', observedAt: '2026-09-13T11:00:00Z'}},
      coverageIssues: [],
    },
    trafficSamples: [{sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-1', uploadBytes: 1_000_000, downloadBytes: 5_000_000, observedAt: '2026-09-13T15:00:00Z'}],
  }), store);

  const counts = run.report.routeCounts;
  // RC5：与 Claude 无关的连接行不进四类计数（FD-04 §9.2 只计相关可判记录），改在连接来源汇总里如实列出。
  assert.equal(counts.unknown, 0, '范围外的连接行不冒充 Claude 的未知记录');
  const lines = run.report.traffic.connectionLines;
  assert.equal(lines.basis, 'LOG_LINES_NOT_BYTES');
  assert.equal(lines.total, 3);
  assert.equal(lines.claudeRelated, 2);
  assert.equal(lines.byProcess['unknown.exe'], 1, '未知进程的那一行在来源汇总里可见');
  assert.equal(lines.missingRoute, 1, '没有路由的那一行如实计为缺路由');
  assert.equal(counts.wrongRoute, 1);
  assert.equal(counts.passRoute, 1);
  const totalRecords = Object.values(counts).reduce((sum, value) => sum + value, 0);
  assert.equal(run.report.traffic.totals.uploadBytes, 1_000_000, '字节来自计量样本');
  assert.equal(run.report.traffic.totals.downloadBytes, 5_000_000);
  assert.notEqual(run.report.traffic.totals.uploadBytes, totalRecords, '日志条数不得变成字节');
  assert.ok((run.report.coverageIssues || []).length > 0 || run.report.coverageStatus === 'MONITORING_INCOMPLETE', '缺口必须显示');

  const {state} = accumulateTraffic({totals: {uploadBytes: 0, downloadBytes: 0}, observations: {}, coverageIssues: []}, {
    sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-2', uploadBytes: 10, downloadBytes: 10, observedAt: '2026-09-13T15:30:00Z',
  });
  assert.ok((state.coverageIssues || []).some((issue) => issue.code), '计数器重置或缺测必须记为缺口而不是零');

  const compose = await composition('x12-ab');
  const matrix = (await compose.network.previewModeChange({userRef: 'user-max', environmentRef: compose.env, mode: 'claude_dual_ip'})).plan.matrix;
  assert.equal(matrix.claude.exit, 'A');
  assert.equal(matrix.other.exit, 'B', '双 IP 下同时存在 A 与 B 两条出口');

  const allocated = await compose.handler.handle(new Request('https://application.synthetic.invalid/api/admin/quota/allocate', {
    method: 'POST',
    headers: {'content-type': 'application/json', authorization: 'Bearer token-admin'},
    body: JSON.stringify({userRef: 'user-max', operation_id: 'x12-alloc', limitBytes: 250_000_000_000, period: 'MONTH', expireAt: '2030-01-01T00:00:00.000Z'}),
  }));
  assert.equal(allocated.status, 200);
  const quotaResponse = await compose.handler.handle(new Request('https://application.synthetic.invalid/api/network/quota', {headers: {authorization: 'Bearer token-max'}}));
  const quota = (await quotaResponse.json()).quota;
  assert.equal(quota.split_ab.status, 'UNKNOWN', 'A/B 分布上游不可得时必须保持未知');
  assert.ok(quota.split_ab.reason, '未知必须给出原因');
  assert.equal(quota.upload_bytes.status, 'UNKNOWN');
  assert.equal(quota.download_bytes.status, 'UNKNOWN');
  assert.ok(quota.used_bytes >= 0 && quota.limit_bytes > 0, '总量来自权威快照');
  const serialized = JSON.stringify(run.report.traffic);
  for (const forbidden of ['claude_bytes', 'claudeBytes', 'exit_a_bytes', 'a_bytes']) {
    assert.ok(!serialized.includes(forbidden), `本机总量不得被命名为 ${forbidden}`);
  }
  assert.equal(run.report.traffic.applications ?? null, null, '没有分应用数据时不得编造归属');
  compose.close();
});

test('X13 日报 FAIL 与覆盖不足并列，AI 附注迟到或失败都不改标准事实', async () => {
  const store = await auditRoot('x13');
  await store.writeText('source/service_latest.log',
    'time="2026-09-13T12:00:00Z" [TCP] dial DIRECT (match DomainSuffix/anthropic.com) (claude.exe) --> api.anthropic.com:443 error: retry using CLAUDE-FIXED[COX-Fixed-Chain] timeout',
    {overwrite: false});
  const run = await runAuditPipeline(auditRequest(store, '2026-09-13T16:00:00.000Z'), store);
  assert.equal(run.report.routeResult, 'FAIL');
  assert.equal(run.report.coverageStatus, 'MONITORING_INCOMPLETE');
  assert.equal(run.delivery.status, 'DELIVERED', '非 PASS 结论也算已交付');

  const beforeJson = await store.readText(run.delivery.paths.json);
  const note = await appendAiNote({reportId: run.report.reportId, status: 'LATE', reason: 'AI_TIMEOUT'}, {reportRoot: 'reports'}, store);
  assert.equal(note.affectsStandardFacts, false);
  assert.equal(await store.readText(run.delivery.paths.json), beforeJson, '附注不得改写已交付的标准事实');

  const again = await deliverDailyReport(run.report, {reportRoot: 'reports'}, store);
  assert.equal(again.status, 'ALREADY_DELIVERED', '当天不重复生成原日报');
  const notes = await loadAiNotes(store);
  assert.equal(notes.length, 1);
  const reports = await loadAuditReports(store);
  assert.equal(reports.length, 1);
  assert.equal(reports[0].report.routeCounts.wrongRoute, 1, '附注后计数不变');
});

test('X14 源日志意外含秘密作为异常处理，分类仍由程序唯一实现', async () => {
  const store = await auditRoot('x14');
  await store.writeText('source/service_latest.log', [
    'time="2026-09-13T12:00:00Z" authorization: Bearer sk-synthetic-should-not-be-archived',
    'time="2026-09-13T12:01:00Z" [TCP] (claude.exe) --> api.anthropic.com:443 using CLAUDE-FIXED[COX-Fixed-Chain]',
  ].join('\n'), {overwrite: false});
  const run = await runAuditPipeline(auditRequest(store, '2026-09-13T16:00:00.000Z'), store);

  const exceptions = run.evidence.archive.restrictedExceptions || [];
  assert.ok(exceptions.some((item) => item.reason === 'SECRET_MATERIAL'), '含秘密的源日志必须作为异常单列');
  const archived = await store.listFiles('archive');
  for (const file of archived) {
    const text = new TextDecoder().decode(file.bytes);
    assert.ok(!text.includes('sk-synthetic-should-not-be-archived'), `${file.path} 不得把凭据原样复制进普通归档`);
  }
  assert.equal(run.report.classificationVersion, MAPPING.version, '分类版本由程序给出');
  assert.ok(['FAIL', 'PASS', 'MONITORING_INCOMPLETE'].includes(run.report.routeResult));
});

test('X15 休眠错过 09:00 后首次唤醒补做一次，不补造漏跑日期', async () => {
  const store = await auditRoot('x15');
  const early = evaluateDailyDue('2026-09-13T15:30:00.000Z', [], 'America/Los_Angeles');
  assert.equal(early.due, false);
  assert.equal(early.reason, 'BEFORE_0900');

  const late = evaluateDailyDue('2026-09-13T18:00:00.000Z', [], 'America/Los_Angeles');
  assert.equal(late.due, true, '当地 09:00 后首次唤醒仍然到期');
  assert.equal(late.date, '2026-09-13');

  await store.writeText('source/service_latest.log',
    'time="2026-09-13T12:00:00Z" [TCP] (claude.exe) --> api.anthropic.com:443 using CLAUDE-FIXED[COX-Fixed-Chain]',
    {overwrite: false});
  const run = await runAuditPipeline(auditRequest(store, '2026-09-13T18:00:00.000Z'), store);
  const inventory = [{date: run.report.reportDate, valid: true, hasJson: true, hasMarkdown: true}];
  const repeated = evaluateDailyDue('2026-09-13T19:00:00.000Z', inventory, 'America/Los_Angeles');
  assert.equal(repeated.due, false);
  assert.equal(repeated.reason, 'ALREADY_DELIVERED', '重复唤醒不重复生成');

  const reports = await loadAuditReports(store);
  assert.equal(reports.length, 1, '不为漏跑日期补造报告');
  assert.equal(reports[0].report.reportDate, '2026-09-13');
  assert.equal(await store.readText(run.delivery.paths.markdown), renderMarkdown(run.report));
  assert.equal(await store.readText(run.delivery.paths.json), serializeReport(run.report));

  const compose = await composition('x15-lifecycle');
  const applied = await compose.network.confirmAndApply({
    operation_id: 'x15-apply',
    userRef: 'user-max',
    environmentRef: compose.env,
    mode: 'claude_single_ip',
    authorization: compose.auth('user-max'),
  });
  assert.ok(['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED'].includes(applied.overall));
  const state = await compose.network.readState({userRef: 'user-max', environmentRef: compose.env});
  assert.ok(state.expected?.plan_version, '期望版本可读');
  assert.ok('loaded' in state, '实际加载版本与期望版本分开呈现');
  assert.ok('verified' in state, '回读验证结果单独呈现');

  const restarted = await compose.network.executeLifecycle(
    {user_ref: 'user-max', environment_ref: compose.env, boot_authorized: true, expected: applied.expected || null},
    {type: 'restart'},
  );
  assert.deepEqual(restarted.actions.map((item) => item.action), ['protection_first', 'load_last_valid_unrevoked'], '重启必须保护先于恢复业务');
  assert.equal(restarted.effects.unknown_proxy_released, false, '重启不得先放出未知代理');
  assert.ok(restarted.executed.some((item) => item.action === 'protection_first' && item.status === 'CONFIRMED'));

  const woke = await compose.network.executeLifecycle(
    {user_ref: 'user-max', environment_ref: compose.env, boot_authorized: true},
    {type: 'wake'},
  );
  assert.equal(woke.effects.coverage_gap, true, '休眠唤醒要标出覆盖缺口');

  const upgradeFailed = await compose.network.executeLifecycle(
    {user_ref: 'user-max', environment_ref: compose.env, last_valid_plan: applied.plan_version || 'x15-plan'},
    {type: 'upgrade_failed'},
  );
  assert.deepEqual(upgradeFailed.actions.map((item) => item.action), ['revert_last_valid']);
  assert.equal(upgradeFailed.effects.reverted, true, '升级失败必须回到上一有效配置');
  assert.equal(upgradeFailed.effects.quota_reset, false, '升级失败不得重置额度');
  compose.close();
});

test('X16 恢复时字段已被用户改动：不覆盖外部变更，不清项目与正常账号', async () => {
  const compose = await composition('x16');
  const scan = await scanAndAnswer(compose);
  const {plan} = await confirmedLocalPlan(compose, scan.scan_id);
  const projectBefore = await readWorkspace(compose, 'input/project/references.jsonl');
  const operation = await compose.local.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'x16-operation'});

  const byId = new Map(plan.actions.map((item) => [item.action_id, item]));
  const receipt = operation.receipts.find((item) => item.backup_ref && byId.get(item.action_id)?.relative_path === SETTINGS && byId.get(item.action_id)?.kind === 'json_remove');
  assert.ok(receipt, '需要 settings.json 的可恢复项');
  const action = byId.get(receipt.action_id);

  const touched = JSON.parse(await readWorkspace(compose, SETTINGS));
  touched.env.USER_ADDED_AFTER_CLEANUP = 'keep-me';
  await writeFile(path.join(compose.root, SETTINGS), `${JSON.stringify(touched, null, 2)}\n`, 'utf8');
  const clean = await compose.local.previewRestore({backupRef: receipt.backup_ref});
  assert.equal(clean.recoverable, true, '无关改动不阻断恢复');
  assert.deepEqual(clean.conflicts, []);

  const conflicting = JSON.parse(await readWorkspace(compose, SETTINGS));
  conflicting.env[action.selector.field_path.split('.').at(-1)] = 'written-by-someone-else';
  await writeFile(path.join(compose.root, SETTINGS), `${JSON.stringify(conflicting, null, 2)}\n`, 'utf8');
  const blocked = await compose.local.previewRestore({backupRef: receipt.backup_ref});
  assert.equal(blocked.recoverable, false, '目标已被外部改动时必须停下');
  assert.ok(blocked.conflicts.length > 0, '冲突必须明确');
  compose.local.confirmRestore({previewId: blocked.preview_id, source: 'local-user'});
  await assert.rejects(
    () => compose.local.restoreChange({previewId: blocked.preview_id}),
    (error) => error.code === 'RESTORE_CONFLICT',
    '不得覆盖外部变更',
  );

  const afterAll = JSON.parse(await readWorkspace(compose, SETTINGS));
  assert.equal(afterAll.env.USER_ADDED_AFTER_CLEANUP, 'keep-me');
  assert.equal(afterAll.env[action.selector.field_path.split('.').at(-1)], 'written-by-someone-else');
  assert.equal(await readWorkspace(compose, 'input/project/references.jsonl'), projectBefore, '项目资料不得被清');

  const remaining = operation.receipts.filter((item) => item.status !== 'APPLIED');
  assert.equal(remaining.length, 0);
  assert.ok(operation.receipts.every((item) => item.action_id), '剩余操作按 action_id 逐条可查');

  const uninstalled = await compose.network.executeLifecycle(
    {user_ref: 'user-max', environment_ref: compose.env},
    {type: 'uninstall', settings: [
      {id: 'sysproxy', owned_by: 'this_app', externally_modified: false},
      {id: 'tun-route', owned_by: 'this_app', externally_modified: true},
      {id: 'user-dns', owned_by: 'user', externally_modified: false},
    ]},
  );
  assert.deepEqual(uninstalled.effects.revoked, ['sysproxy'], '卸载只撤销本应用拥有且未被外部改动的设置');
  assert.deepEqual(
    uninstalled.effects.skipped.map((item) => `${item.id}:${item.reason}`).sort(),
    ['tun-route:EXTERNAL_MODIFICATION', 'user-dns:NOT_OWNED'],
    '跳过项必须写明原因',
  );

  const stopped = await compose.network.executeLifecycle(
    {user_ref: 'user-max', environment_ref: compose.env},
    {type: 'stop_management'},
  );
  assert.equal(stopped.effects.requires_explicit_confirm, true, '恢复原网络必须具体确认');
  assert.equal(stopped.effects.claude_unprotected, true, '解除后失去保护要写明');
  compose.close();
});
