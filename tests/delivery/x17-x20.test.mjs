import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import {createApplicationControl, createControlStore} from '../../services/control/index.mjs';
import {adminRequest, createQuotaHarness, handleJson, threeUserResources} from '../../fixtures/control/harness.mjs';
import {createCleanupScript} from '../../fixtures/delivery/aiScripts.mjs';
import {composition, readWorkspace, scanAndAnswer, snapshotBystanders, assertBystandersUnchanged} from './harness.mjs';

const USER = 'user-max';

async function provision(handler, limits = {}) {
  const catalog = threeUserResources();
  for (const item of catalog.resources) await handleJson(handler, adminRequest('/api/admin/resources', {method: 'PUT', body: item}));
  await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {template_id: 'managed', published: true, template: catalog.template}}));
  const ids = {};
  for (const user of catalog.users) {
    await handleJson(handler, adminRequest('/api/admin/assignments', {method: 'POST', body: {
      userRef: user.userRef,
      environmentRef: 'synthetic-windows',
      accountClass: user.accountClass,
      allowedModes: user.allowedModes.filter((mode) => mode !== 'claude_dual_ip' || user.roles.B),
      resources: user.resources,
      roles: user.roles,
      validUntil: '2027-01-01T00:00:00.000Z',
      templateId: 'managed',
    }}));
    await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: user.userRef, environmentRef: 'synthetic-windows'}}));
    const allocated = await handleJson(handler, adminRequest('/api/admin/quota/allocate', {method: 'POST', body: {
      userRef: user.userRef,
      operation_id: `alloc-${user.userRef}`,
      limitBytes: limits[user.userRef] ?? user.limit,
      period: 'MONTH',
      expireAt: '2027-01-01T00:00:00.000Z',
    }}));
    ids[user.userRef] = allocated.body.binding.provider_user_id;
  }
  return ids;
}

test('X17 额度耗尽后只开放明确的支持路径，Claude 仍受保护', async () => {
  const compose = await composition('x17');
  await compose.network.confirmAndApply({
    operation_id: 'x17-apply',
    userRef: USER,
    environmentRef: compose.env,
    mode: 'claude_single_ip',
    authorization: compose.auth(USER),
  });

  const limited = await compose.network.requestEmergency({
    user_ref: USER,
    environment_ref: compose.env,
    mode: 'claude_single_ip',
    purpose: 'support_access',
    duration_minutes: 30,
    targets: [{host: 'anything.example', match: 'subdomains'}],
    quotaSnapshot: {status: 'LIMITED', user_ref: USER},
    template: {control_plane: {support: [{host: 'support.example'}]}},
    confirmation: {confirmed: true, confirmation_id: 'x17-confirm'},
  });
  assert.equal(limited.claude_protected, true, 'Claude 仍受保护');
  assert.equal(limited.quota_limited, true);
  assert.equal(limited.general_emergency, 'INCOMPLETE', '只有支持站点可用不能算普通应急完整通过');
  assert.deepEqual(limited.targets.map((item) => item.host), ['support.example'], '只开放明确的支持路径');
  compose.close();
});

test('X18 AI 离线、模型失败与预算耗尽都保留标准能力', async () => {
  const offline = await composition('x18-offline', {aiAvailable: false});
  assert.equal(offline.createAi({sessionToken: 'token-max', userRef: 'user-max'}), null, 'AI 未配置时不提供会话');
  const scan = await scanAndAnswer(offline);
  const classification = offline.local.classify({scanId: scan.scan_id});
  assert.ok(classification.recommendations.length > 0, '没有 AI 仍能跑标准检查');
  const capabilities = await offline.handler.handle(new Request('https://application.synthetic.invalid/api/ai/capabilities', {headers: {authorization: 'Bearer token-max'}}));
  const body = await capabilities.json();
  assert.equal(body.tasks.cleanup.status, 'UNAVAILABLE', '能力状态来自服务端而不是猜测');
  offline.close();

  const failing = await composition('x18-failed', {aiFailure: true});
  const failingScan = await scanAndAnswer(failing);
  const failingAi = failing.createAi({sessionToken: 'token-max', userRef: 'user-max'});
  const failedTask = await failingAi.startCleanup({scanId: failingScan.scan_id});
  assert.ok(['MODEL_FAILED', 'REMOTE_RESPONSE_UNKNOWN'].includes(failedTask.status), JSON.stringify(failedTask));
  assert.ok(failedTask.lastError, '失败要保留原因');
  assert.equal(failedTask.operationId, null, '模型失败不产生任何执行');
  const stillClassified = failing.local.classify({scanId: failingScan.scan_id});
  assert.ok(stillClassified.recommendations.length > 0, '模型失败后标准结果仍在');
  failing.close();

  let budgetScanId = null;
  const budget = await composition('x18-budget', {
    aiBudgets: {maxTurns: 1, maxToolCalls: 1, maxEvidenceBytes: 64000},
    sdkFetch: createCleanupScript({scanId: () => budgetScanId}),
  });
  const budgetScan = await scanAndAnswer(budget);
  budgetScanId = budgetScan.scan_id;
  const before = await snapshotBystanders(budget);
  const budgetAi = budget.createAi({sessionToken: 'token-max', userRef: 'user-max'});
  const budgetTask = await budgetAi.startCleanup({scanId: budgetScanId});
  assert.equal(budgetTask.status, 'BUDGET_EXHAUSTED', '超预算必须停下而不是无限重试');
  assert.ok(['AI_BUDGET_EXHAUSTED', 'AI_TOOL_BUDGET_EXHAUSTED'].includes(budgetTask.lastError.code));
  assert.equal(budgetTask.operationId, null);
  await assertBystandersUnchanged(assert, budget, before);
  budget.close();
});

test('X19 文件占用与权限不足时逐项失败，其余独立项继续', async () => {
  const compose = await composition('x19', {
    localCapabilities: {
      blocked_paths: ['input/code/user-settings.json'],
      busy_paths: ['input/desktop/settings.json'],
    },
  });
  const before = await snapshotBystanders(compose);
  const scan = await scanAndAnswer(compose);
  const classification = compose.local.classify({scanId: scan.scan_id});
  const plan = await compose.local.buildActionPlan({
    scanId: scan.scan_id,
    recommendationIds: (classification.recommendations || []).map((item) => item.recommendation_id),
  });
  await compose.local.confirmActionPlan({
    planId: plan.plan_id,
    version: plan.version,
    actionIds: plan.actions.map((item) => item.action_id),
    source: 'local-user',
  });
  const operation = await compose.local.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'x19-operation'});
  const byId = new Map(plan.actions.map((item) => [item.action_id, item]));

  const blocked = operation.receipts.filter((item) => byId.get(item.action_id)?.relative_path === 'input/code/user-settings.json');
  const busy = operation.receipts.filter((item) => byId.get(item.action_id)?.relative_path === 'input/desktop/settings.json');
  assert.ok(blocked.length > 0 && busy.length > 0, '需要同时覆盖权限不足与占用两类目标');
  assert.ok(blocked.every((item) => item.status === 'FAILED' && item.code === 'ACCESS_DENIED'), '权限不足必须逐项失败');
  assert.ok(busy.some((item) => item.status === 'FAILED' && item.code === 'OBJECT_BUSY'), '占用的对象必须失败而不是强改');
  assert.ok(busy.every((item) => item.status !== 'APPLIED'), '占用对象的后续动作不得硬闯');
  assert.ok(
    busy.filter((item) => item.status !== 'FAILED').every((item) => item.status === 'DEPENDENCY_BLOCKED' && item.code === 'DEPENDENCY_NOT_APPLIED'),
    '同一对象的依赖动作必须单独记为依赖受阻',
  );
  for (const item of [...blocked, ...busy]) assert.ok(item.code, '失败要有具体原因码');

  const applied = operation.receipts.filter((item) => item.status === 'APPLIED');
  assert.ok(applied.length > 0, '独立的其他项必须继续执行');
  assert.equal(operation.status, 'partial', '部分成功部分失败必须分开记录');
  await assertBystandersUnchanged(assert, compose, before);
  assert.ok(JSON.parse(await readWorkspace(compose, 'input/code/user-settings.json')), '被拒目标保持原样且未被破坏');

  const diskFull = await compose.network.executeLifecycle(
    {user_ref: USER, environment_ref: compose.env},
    {type: 'disk_full'},
  );
  assert.equal(diskFull.effects.protection_retained, true, '磁盘不足不得解除保护');
  assert.equal(diskFull.effects.archive_writes, 'STOPPED', '磁盘不足要停止新归档写入');
  assert.equal(diskFull.effects.evidence_deleted, false, '磁盘不足不得删活动证据');
  assert.deepEqual(diskFull.actions.map((item) => item.action), ['keep_protection_stop_new_archive']);
  compose.close();
});

test('X20 节点重启与资源版本更新后账目连续，一次传输不在两段重复扣量', async () => {
  const harness = await createQuotaHarness('x20');
  const {store, clock, restartTrafficNode} = harness;
  let {handler, authority, quotaAdapter, fetchImpl} = harness;
  const ids = await provision(handler, {'user-jia': 1_000_000});

  authority.ingestByteEvent({eventId: 'hop-shared', userId: ids['user-jia'], bytes: 400, hop: 'admission'});
  const duplicated = authority.ingestByteEvent({eventId: 'hop-shared', userId: ids['user-jia'], bytes: 400, hop: 'metering'});
  assert.equal(duplicated.counted, false, '同一次传输不得在前置和最终出口各扣一次');
  assert.equal(duplicated.reason, 'DUPLICATE_EVENT');
  const nonMetering = authority.ingestByteEvent({eventId: 'hop-relay', userId: ids['user-jia'], bytes: 400, hop: 'relay'});
  assert.equal(nonMetering.counted, false);
  assert.equal(nonMetering.reason, 'NON_METERING_HOP');

  const beforeRestart = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(beforeRestart.body.snapshot.used_bytes, 400);

  const restarted = restartTrafficNode();
  assert.notEqual(restarted.authority, authority, '重启必须换成新的流量节点实例');
  assert.equal(restarted.authority.state.connections.size, 0, '节点内存态真的重建，在途连接不继承');
  assert.equal(
    restarted.authority.ingestByteEvent({eventId: 'hop-shared', userId: ids['user-jia'], bytes: 400, hop: 'metering'}).counted,
    false,
    '去重集合来自服务端账目，不是旧进程内存',
  );
  authority = restarted.authority;
  quotaAdapter = restarted.quotaAdapter;
  fetchImpl = restarted.fetchImpl;
  handler = createApplicationControl({
    store,
    modelPolicies: {},
    secrets: {resolve: () => 'SYNTHETIC_SERVER_KEY'},
    clock,
    quotaAdapter,
    fetchImpl,
  });
  const afterRestart = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(afterRestart.body.snapshot.used_bytes, 400, '流量节点重启不清账');

  const catalog = threeUserResources();
  const jia = catalog.users.find((item) => item.userRef === 'user-jia');
  const beforeVersion = (await handleJson(handler, adminRequest('/api/admin/assignments?user_ref=user-jia&environment_ref=synthetic-windows'))).body.assignment.assignment_version;
  const updated = await handleJson(handler, adminRequest('/api/admin/assignments', {method: 'POST', body: {
    userRef: 'user-jia',
    environmentRef: 'synthetic-windows',
    accountClass: jia.accountClass,
    allowedModes: jia.allowedModes.filter((mode) => mode !== 'claude_dual_ip' || jia.roles.B),
    resources: jia.resources,
    roles: jia.roles,
    validUntil: '2028-01-01T00:00:00.000Z',
    templateId: 'managed',
  }}));
  assert.equal(updated.status, 200, JSON.stringify(updated.body));
  const republished = await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: 'user-jia', environmentRef: 'synthetic-windows'}}));
  assert.equal(republished.status, 200, JSON.stringify(republished.body));
  assert.ok(republished.body.receipt.assignment_version > beforeVersion, '资源版本必须真的更新');
  const afterPublish = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(afterPublish.body.snapshot.used_bytes, 400, '资源版本更新不清账');

  authority.ingestByteEvent({eventId: 'hop-after-publish', userId: ids['user-jia'], bytes: 600, hop: 'metering'});
  const finalView = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(finalView.body.snapshot.used_bytes, 1000, '周期内用量连续累加');

  authority.ingestByteEvent({eventId: 'hop-over-limit', userId: ids['user-jia'], bytes: 1_000_000, hop: 'metering'});
  const limited = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(limited.body.snapshot.status, 'LIMITED', '超额后用户必须进入受限状态');
  const blocked = authority.openConnection({connectionId: 'jia-after-limit', userId: ids['user-jia'], role: 'A'});
  assert.equal(blocked.allowed, false);

  const databasePath = store.databasePath;
  store.close();

  const rebuiltStore = createControlStore({
    databasePath,
    users: [
      {user_ref: 'user-jia', status: 'ACTIVE'},
      {user_ref: 'user-yi', status: 'ACTIVE'},
      {user_ref: 'user-bing', status: 'ACTIVE'},
      {user_ref: 'user-admin', status: 'ACTIVE', role: 'admin'},
    ],
    sessions: [{session_ref: 's-admin', user_ref: 'user-admin', token: 'token-admin', expires_at: '2030-01-01T00:00:00.000Z'}],
  });
  const rebuiltHandler = createApplicationControl({
    store: rebuiltStore,
    modelPolicies: {},
    secrets: {resolve: () => 'SYNTHETIC_SERVER_KEY'},
    clock,
    quotaAdapter,
    fetchImpl,
  });
  const afterRebuild = await handleJson(rebuiltHandler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(afterRebuild.body.snapshot.used_bytes, 1_001_000, '控制节点重建后账目连续');
  assert.equal(afterRebuild.body.snapshot.status, 'LIMITED', '控制节点重建后用户仍受限');
  const rebuiltAssignment = await handleJson(rebuiltHandler, adminRequest('/api/admin/assignments?user_ref=user-jia&environment_ref=synthetic-windows'));
  assert.equal(
    rebuiltAssignment.body.assignment.assignment_version,
    republished.body.receipt.assignment_version,
    '控制节点重建后资源版本保持',
  );
  assert.ok(path.isAbsolute(databasePath));
  rebuiltStore.close();
});
