import assert from 'node:assert/strict';
import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {createCleanupScript, createHostileScript} from '../../fixtures/delivery/aiScripts.mjs';
import {
  aiTaskRecord,
  assertBystandersUnchanged,
  composition,
  confirmedLocalPlan,
  readWorkspace,
  scanAndAnswer,
  snapshotBystanders,
} from './harness.mjs';

const SETTINGS = 'input/code/settings.json';
const SYNTHETIC_SECRET = 'SYNTHETIC_CODE_AUTH_TOKEN';

test('X01 AI 规划混合 JSON，一次确认后批量清理且只动选中字段', async () => {
  let scanId = null;
  const outbound = [];
  const compose = await composition('x01', {sdkFetch: createCleanupScript({scanId: () => scanId, outbound})});
  const before = await snapshotBystanders(compose);
  const settingsBefore = JSON.parse(await readWorkspace(compose, SETTINGS));
  const scan = await scanAndAnswer(compose);
  scanId = scan.scan_id;

  const ai = compose.createAi({sessionToken: 'token-max', userRef: 'user-max'});
  let task = await ai.startCleanup({scanId});
  assert.equal(task.status, 'AWAITING_CONFIRMATION', 'AI 只能规划，执行要等本地确认');
  assert.ok(task.planId && task.actionIds.length > 0);
  assert.equal(task.operationId, null, '未确认前不得产生执行');

  const confirmed = await ai.confirmCleanup({taskId: task.taskId, planId: task.planId, version: task.version, actionIds: task.actionIds});
  task = await ai.resume({taskId: confirmed.taskId});
  assert.equal(task.status, 'COMPLETED');
  assert.equal(task.operationStatus, 'completed');
  assert.equal(task.operationReceipts.length, task.actionIds.length, '逐项回执，不合并成一条');
  assert.ok(task.operationReceipts.every((item) => item.status === 'APPLIED' && item.backup_ref), '逐项备份后执行');

  const settingsAfter = JSON.parse(await readWorkspace(compose, SETTINGS));
  assert.equal(settingsAfter.env.ANTHROPIC_AUTH_TOKEN, undefined, '选中的受限账号字段被清除');
  for (const key of Object.keys(settingsBefore.env || {})) {
    if (key === 'ANTHROPIC_AUTH_TOKEN' || key === 'ANTHROPIC_BASE_URL') continue;
    assert.deepEqual(settingsAfter.env[key], settingsBefore.env[key], '未选中的同文件字段不得改动');
  }
  await assertBystandersUnchanged(assert, compose, before);

  const rescan = await scanAndAnswer(compose);
  const reclassified = compose.local.classify({scanId: rescan.scan_id});
  const rebuilt = await compose.local.buildActionPlan({
    scanId: rescan.scan_id,
    recommendationIds: (reclassified.recommendations || []).map((item) => item.recommendation_id),
  });
  await assert.rejects(
    () => compose.local.executeConfirmedPlan({planId: rebuilt.plan_id, version: rebuilt.version, operationId: 'x01-extra'}),
    (error) => error.code === 'NOT_CONFIRMED',
    '复查后新出现的条目必须重新确认',
  );
  compose.close();
});

test('X02 模型越权请求被客户端拒绝，已授权工具仍可运行', async () => {
  let scanId = null;
  const attempts = [];
  const compose = await composition('x02', {sdkFetch: createHostileScript({scanId: () => scanId, attempts})});
  const before = await snapshotBystanders(compose);
  const scan = await scanAndAnswer(compose);
  scanId = scan.scan_id;

  const ai = compose.createAi({sessionToken: 'token-max', userRef: 'user-max'});
  const task = await ai.startCleanup({scanId});
  const record = aiTaskRecord(compose, task.taskId);
  const byCode = Object.fromEntries(record.tool_call_receipts.map((item) => [item.tool_call_id, item.result]));

  assert.equal(byCode.shell.status, 'TOOL_REJECTED');
  assert.equal(byCode.shell.code, 'AI_TOOL_NOT_ALLOWED', '任意 shell 不在受限工具目录内');
  assert.equal(byCode['inspect-bad'].status, 'TOOL_REJECTED');
  assert.equal(byCode['inspect-bad'].code, 'AI_TOOL_SCOPE_DENIED', '越出已发现范围的对象不可读');
  assert.equal(byCode['exec-bad'].status, 'TOOL_REJECTED');
  assert.equal(byCode['exec-bad'].code, 'AI_CONFIRMATION_REQUIRED', '伪造的确认不成立');
  assert.deepEqual(attempts, ['RunShellCommand', 'InspectObject:out-of-scope', 'ExecuteConfirmedPlan:forged-confirmation']);

  assert.ok(record.plan_id, '被拒之后已授权的建计划工具仍然可用');
  assert.equal(record.confirmation_id, null);
  assert.equal(record.operation_id, null, '越权尝试不得产生任何执行');
  await assertBystandersUnchanged(assert, compose, before);
  compose.close();
});

test('X03 确认后目标改变暂停，响应丢失重复执行不重复删除', async () => {
  const compose = await composition('x03');
  const scan = await scanAndAnswer(compose);
  const {plan, actionIds} = await confirmedLocalPlan(compose, scan.scan_id);

  const drifted = JSON.parse(await readWorkspace(compose, SETTINGS));
  drifted.env.ANTHROPIC_AUTH_TOKEN = 'changed-after-confirmation';
  await writeFile(path.join(compose.root, SETTINGS), `${JSON.stringify(drifted, null, 2)}\n`, 'utf8');

  const first = await compose.local.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'x03-operation'});
  const byId = new Map(plan.actions.map((item) => [item.action_id, item]));
  const driftedReceipts = first.receipts.filter((item) => byId.get(item.action_id)?.relative_path === SETTINGS);
  assert.ok(driftedReceipts.length > 0);
  assert.ok(driftedReceipts.every((item) => item.status === 'FAILED' && item.code === 'STALE_PLAN'), '变更的目标必须暂停');
  assert.equal(JSON.parse(await readWorkspace(compose, SETTINGS)).env.ANTHROPIC_AUTH_TOKEN, 'changed-after-confirmation');

  const deleted = first.receipts.find((item) => byId.get(item.action_id)?.kind === 'delete_file');
  assert.equal(deleted.status, 'APPLIED');
  const replay = await compose.local.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'x03-operation'});
  assert.equal(replay.operation_id, first.operation_id, '同一 operation_id 不新建执行');
  const replayedDelete = replay.receipts.find((item) => item.action_id === deleted.action_id);
  assert.equal(replayedDelete.status, 'APPLIED');
  assert.equal(replayedDelete.backup_ref, deleted.backup_ref, '已成功的删除不得重复执行');
  assert.equal(replay.receipts.length, first.receipts.length);
  assert.equal(actionIds.length, plan.actions.length);
  compose.close();
});

test('X04 客户端包与上传内容不含模型配置、密钥或原始秘密', async () => {
  let scanId = null;
  const outbound = [];
  const compose = await composition('x04', {sdkFetch: createCleanupScript({scanId: () => scanId, outbound})});
  const scan = await scanAndAnswer(compose);
  scanId = scan.scan_id;
  const ai = compose.createAi({sessionToken: 'token-max', userRef: 'user-max'});
  const task = await ai.startCleanup({scanId});

  const bundle = await readFile(path.resolve('apps/desktop-ui/app.bundle.js'), 'utf8');
  for (const marker of ['synthetic-model.invalid', 'SYNTHETIC_SERVER_KEY', 'api_key', 'apiKey']) {
    assert.ok(!bundle.includes(marker), `客户端包不得包含 ${marker}`);
  }
  assert.ok(outbound.length > 0, '必须实际经过服务端转发');
  for (const request of outbound) {
    assert.equal(request.model, 'synthetic-server-selected-model', '模型由服务端选择');
    const serialized = JSON.stringify(request.messages);
    assert.ok(!serialized.includes(SYNTHETIC_SECRET), '上传内容不得包含原始秘密');
    assert.ok(!serialized.includes('SYNTHETIC_SERVER_KEY'));
  }

  const record = aiTaskRecord(compose, task.taskId);
  assert.equal(record.prompt_version, 'cleanup-v1', '提示词版本在客户端可定位');
  const promptSource = await readFile(path.resolve('src/core/ai/prompts/cleanup.mjs'), 'utf8');
  assert.ok(promptSource.includes('cleanup-v1'));
  const events = compose.controlStore.events();
  assert.ok(events.length > 0, '服务端留有最小调用记录');
  assert.ok(!JSON.stringify(events).includes(SYNTHETIC_SECRET));
  compose.close();
});

test('X05 默认浏览器与内嵌 WebView 不同且有多 Profile 时结果绑定本次会话', async () => {
  const compose = await composition('x05');
  const scan = await compose.local.discover({mode: 'deep'});
  const profiles = new Set((scan.objects || []).flatMap((item) => (item.profile_ref ? [item.profile_ref] : [])));
  assert.ok(profiles.size >= 1, '发现阶段必须带出实际 Profile');

  const result = await compose.diagnostics.startScan({mode: 'deep', environmentRef: compose.env, profileRef: 'Profile 1'});
  assert.equal(result.profile_ref, 'Profile 1');
  const session = compose.diagnostics.createSession({
    taskRef: result.task_id,
    environmentRef: compose.env,
    profileRef: 'Profile 1',
    origin: 'https://diagnostic.synthetic.invalid',
  });

  const forged = compose.diagnostics.acceptReport({
    origin: 'https://diagnostic.synthetic.invalid',
    body: {
      session_ref: session.session_ref,
      session_nonce: 'webview-guess',
      script_version: session.script_version,
      task_ref: result.task_id,
      environment_ref: compose.env,
      profile_ref: 'Default',
      sample: {platform: {timezone: 'UTC'}},
    },
  });
  assert.equal(forged.ok, false);
  assert.equal(forged.code, 'NONCE_INVALID', '未知 nonce 不得冒充目标 Profile');

  const accepted = compose.diagnostics.acceptReport({
    origin: 'https://diagnostic.synthetic.invalid',
    body: {
      session_ref: session.session_ref,
      session_nonce: session.session_nonce,
      script_version: session.script_version,
      task_ref: result.task_id,
      environment_ref: compose.env,
      profile_ref: 'Profile 1',
      sample: {platform: {timezone: 'America/Los_Angeles'}},
    },
  });
  assert.equal(accepted.ok, true);
  const reloaded = compose.diagnostics.result(result.task_id);
  assert.equal(reloaded.profile_ref, 'Profile 1', '页面回传结果关联本次会话的 Profile');
  const unknown = (reloaded.observations || []).filter((item) => item.status === 'UNKNOWN' || item.evidence_state === 'unknown');
  for (const item of unknown) assert.notEqual(item.status, 'PASS', '未知不得伪装成确定');
  compose.close();
});
