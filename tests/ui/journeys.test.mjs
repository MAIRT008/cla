import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {createDesktopComposition} from '../../apps/desktop-ui/compose.mjs';
import {createDesktopSession} from '../../apps/desktop-ui/session.mjs';
import {createPageRuntime} from './page.mjs';

const NON_TARGET = 'input/audit/current.log';
const SETTINGS = 'input/code/settings.json';

async function waitFor(runtime, predicate, timeoutMs = 8000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate(runtime.snapshot())) return runtime.snapshot();
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('timed out waiting for page state');
}

async function waitForDom(page, predicate, timeoutMs = 8000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate(page.document)) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('timed out waiting for the page to re-render');
}

function readFixture(page, relative) {
  return readFile(path.join(page.compose.root, relative), 'utf8');
}

function writeFixture(page, relative, document) {
  return writeFile(path.join(page.compose.root, relative), `${JSON.stringify(document, null, 2)}\n`, 'utf8');
}

async function answerIdentities(page) {
  const scanned = await waitFor(page, (snap) => snap.local.identities.length >= 2);
  for (const identity of scanned.local.identities) {
    const value = identity.identity_ref === 'restricted-account' ? 'restricted' : 'normal';
    const input = page.document.querySelectorAll('input').find((item) => item.name === `account-${identity.identity_ref}` && item.value === value);
    assert.ok(input, `missing radio for ${identity.identity_ref}`);
    input.click();
  }
  await waitFor(page, (snap) => Object.keys(snap.local.answers).length >= scanned.local.identities.length);
}

async function confirmedPlan(page) {
  await page.click('scanDeep');
  await answerIdentities(page);
  await page.click('localClassify');
  await page.click('localBuildPlan');
  await waitFor(page, (snap) => Boolean(snap.local.plan_id));
  await page.click('localConfirm');
  await waitFor(page, (snap) => snap.local.plan_status === 'CONFIRMED');
  page.document.getElementById('confirmBox').checked = true;
}

const TERMINAL = new Set(['completed', 'partial', 'cancelled']);

function settled(snap) {
  return TERMINAL.has(snap.local.operation_status);
}

function actionsById(page) {
  const plan = page.compose.store.getRecord(page.snapshot().local.plan_id, 'plan');
  return new Map((plan?.actions || []).map((action) => [action.action_id, action]));
}

test('桥接契约：正式页面先装原生组合根，没有桥接时点名报未接入', async () => {
  const html = await readFile(path.resolve('apps/desktop-ui/index.html'), 'utf8');
  assert.match(html, /src="native-boot.mjs"/, '正式页面必须先装 WebView 组合根');
  assert.match(html, /src="bridge.js"/);
  assert.ok(html.indexOf('native-boot.mjs') < html.indexOf('bridge.js'), '组合根要排在桥接之前');

  const bridge = await readFile(path.resolve('apps/desktop-ui/bridge.js'), 'utf8');
  assert.match(bridge, /__STEWARD_BOOT__/, '桥接必须等待组合根装配完成');
  assert.match(bridge, /__STEWARD_HOST__/);
  assert.match(bridge, /UI_BACKEND_NOT_ATTACHED/);

  const boot = await readFile(path.resolve('apps/desktop-ui/native-boot.mjs'), 'utf8');
  assert.match(boot, /steward_request/, '原生调用统一走 steward_request');
  assert.ok(!boot.includes("'UiAction'"), '不得再有一揽子 UiAction');

  const commands = await readFile(path.resolve('apps/desktop-host/src-tauri/src/commands.rs'), 'utf8');
  assert.ok(!commands.includes('UiAction'), 'Rust 侧的一揽子分支必须撤掉');
  assert.match(commands, /NATIVE_OP_UNKNOWN/);
  const conf = await readFile(path.resolve('apps/desktop-host/src-tauri/tauri.conf.json'), 'utf8');
  assert.match(conf, /desktop-ui/);
});

test('旅程1 本地完整处理：分身份回答、问题保留、执行改目标而非目标不变', async () => {
  const page = await createPageRuntime('j1');
  const nonTargetBefore = await readFixture(page, NON_TARGET);
  await page.click('scanDeep');
  await answerIdentities(page);
  await page.click('localClassify');
  const classified = await waitFor(page, (snap) => snap.local.problems.length > 0);
  const problemCount = classified.local.problems.length;
  const scoreStatus = classified.local.score_status;
  const target = classified.local.problems[0].problem_id;
  await page.click(`problem-retain-${target}`);
  const retained = await waitFor(page, (snap) => snap.local.problems.find((item) => item.problem_id === target)?.retained === true);
  assert.equal(retained.local.problems.length, problemCount);
  assert.equal(retained.local.score_status, scoreStatus);

  await page.click('localBuildPlan');
  await waitFor(page, (snap) => Boolean(snap.local.plan_id));
  await page.click('localConfirm');
  await waitFor(page, (snap) => snap.local.plan_status === 'CONFIRMED');
  page.document.getElementById('confirmBox').checked = true;
  const before = await readFixture(page, SETTINGS);
  await page.click('localExecute');
  const executed = await waitFor(page, settled);
  assert.equal(executed.local.error, null);
  assert.equal(executed.local.operation_status, 'completed');
  assert.notEqual(await readFixture(page, SETTINGS), before);
  assert.equal(await readFixture(page, NON_TARGET), nonTargetBefore);
  await page.click('localRecheck');
  await page.click('localExport');
  await waitFor(page, (snap) => Boolean(snap.local.export));
  page.close();
});

test('旅程2a 确认后目标漂移被拒，非目标不变', async () => {
  const page = await createPageRuntime('j2a');
  await confirmedPlan(page);
  const nonTargetBefore = await readFixture(page, NON_TARGET);
  const drifted = JSON.parse(await readFixture(page, SETTINGS));
  drifted.env.ANTHROPIC_AUTH_TOKEN = 'drifted-after-confirmation';
  await writeFixture(page, SETTINGS, drifted);

  await page.click('localExecute');
  const executed = await waitFor(page, settled);
  const byId = actionsById(page);
  const driftedReceipts = executed.local.receipts.filter((item) => byId.get(item.action_id)?.relative_path === SETTINGS);
  assert.ok(driftedReceipts.length > 0);
  assert.ok(
    driftedReceipts.every((item) => item.status === 'FAILED' && item.code === 'STALE_PLAN'),
    JSON.stringify(driftedReceipts),
  );
  assert.equal(executed.local.operation_status, 'partial');
  const after = JSON.parse(await readFixture(page, SETTINGS));
  assert.equal(after.env.ANTHROPIC_AUTH_TOKEN, 'drifted-after-confirmation');
  assert.equal(await readFixture(page, NON_TARGET), nonTargetBefore);
  page.close();
});

test('旅程2b 执行中取消保留成功项，重开页面续接不重做', async () => {
  const page = await createPageRuntime('j2b', {executeStepDelayMs: 40});
  await confirmedPlan(page);
  await page.click('localExecute');
  await waitFor(page, (snap) => (snap.local.receipts || []).some((item) => item.status === 'APPLIED'));
  await page.click('scanCancel');
  const cancelled = await waitFor(page, (snap) => snap.local.operation_status === 'cancelled');
  const applied = cancelled.local.receipts.filter((item) => item.status === 'APPLIED');
  assert.ok(applied.length > 0, '取消必须保留已成功项');
  assert.ok(cancelled.local.receipts.some((item) => item.status === 'NOT_STARTED' && item.code === 'CANCELLED_AT_BOUNDARY'));
  const appliedBackups = new Map(applied.map((item) => [item.action_id, item.backup_ref]));

  const reopened = await createPageRuntime('j2b-reopen', {compose: page.compose});
  const restored = reopened.snapshot();
  assert.equal(restored.local.operation_id, cancelled.local.operation_id);
  assert.equal(restored.local.operation_status, 'cancelled');
  await reopened.click('localResume');
  const resumed = await waitFor(reopened, (snap) => snap.local.operation_status && snap.local.operation_status !== 'cancelled');
  assert.equal(resumed.local.error, null);
  for (const [actionId, backupRef] of appliedBackups) {
    const receipt = resumed.local.receipts.find((item) => item.action_id === actionId);
    assert.equal(receipt.status, 'APPLIED');
    assert.equal(receipt.backup_ref, backupRef, '续接不得重做已成功项');
  }
  assert.ok(!resumed.local.receipts.some((item) => item.status === 'NOT_STARTED'));
  reopened.close();
  page.close();
});

test('旅程2c 恢复预览：无关修改保留，目标被改则冲突可见', async () => {
  const page = await createPageRuntime('j2c');
  await confirmedPlan(page);
  await page.click('localExecute');
  await waitFor(page, settled);
  const byId = actionsById(page);
  const target = page.snapshot().local.restorables.find((item) => item.relative_path === SETTINGS && item.kind === 'json_remove');
  assert.ok(target, '需要 settings.json 的可恢复项');
  page.setValue('restoreTarget', target.backup_ref);

  const unrelated = JSON.parse(await readFixture(page, SETTINGS));
  unrelated.env.UNRELATED_USER_EDIT = 'keep-me';
  await writeFixture(page, SETTINGS, unrelated);
  await page.click('localPreviewRestore');
  const clean = await waitFor(page, (snap) => Boolean(snap.local.restore?.preview_id));
  assert.equal(clean.local.restore.recoverable, true);
  assert.deepEqual(clean.local.restore.conflicts, []);

  const fieldPath = byId.get(target.action_id).selector.field_path;
  const conflicted = JSON.parse(await readFixture(page, SETTINGS));
  conflicted.env[fieldPath.split('.').at(-1)] = 'someone-else-wrote-this';
  await writeFixture(page, SETTINGS, conflicted);
  await page.click('localPreviewRestore');
  const blocked = await waitFor(page, (snap) => snap.local.restore?.recoverable === false);
  assert.ok(blocked.local.restore.conflicts.length > 0);
  assert.equal(JSON.parse(await readFixture(page, SETTINGS)).env.UNRELATED_USER_EDIT, 'keep-me');
  page.close();
});

test('旅程3 诊断输入决定扫描对象，回传可计划，未知 nonce 不冒充目标 Profile', async () => {
  const page = await createPageRuntime('j3');
  await page.click('tabDiag');
  page.setValue('diagEnv', 'wsl-synthetic');
  page.setValue('diagProfile', 'Profile 1');
  await page.click('diagScan');
  const scanned = await waitFor(page, (snap) => Boolean(snap.diag.task_id));
  assert.equal(scanned.diag.env, 'wsl-synthetic');
  assert.equal(scanned.diag.profileRef, 'Profile 1');

  const session = page.compose.diagnostics.createSession({
    taskRef: scanned.diag.task_id,
    environmentRef: scanned.diag.env,
    profileRef: scanned.diag.profileRef,
    origin: 'https://diagnostic.synthetic.invalid',
  });
  const forged = page.compose.diagnostics.acceptReport({
    origin: 'https://diagnostic.synthetic.invalid',
    body: {
      session_ref: session.session_ref,
      session_nonce: 'unknown-nonce',
      script_version: session.script_version,
      task_ref: scanned.diag.task_id,
      environment_ref: scanned.diag.env,
      profile_ref: 'Default',
      sample: {platform: {timezone: 'UTC'}},
    },
  });
  assert.equal(forged.ok, false);
  assert.equal(forged.code, 'NONCE_INVALID');
  assert.equal(page.snapshot().diag.receipt, false);
  assert.equal(page.snapshot().diag.profileRef, 'Profile 1');

  await page.click('diagSample');
  const refused = await waitFor(page, (snap) => Boolean(snap.diag.error));
  assert.equal(refused.diag.error.code, 'BROWSER_DIAG_ENVIRONMENT_MISMATCH', '客体环境不能拿宿主默认浏览器的证据充数');
  assert.equal(refused.diag.receipt, false);

  page.setValue('diagEnv', 'synthetic-windows');
  await page.click('diagScan');
  await waitFor(page, (snap) => snap.diag.env === 'synthetic-windows' && snap.diag.task_id !== scanned.diag.task_id);
  await page.click('diagSample');
  await waitFor(page, (snap) => snap.diag.browser?.status === 'WAITING');
  await page.click('diagBrowserCheck');
  const received = await waitFor(page, (snap) => snap.diag.receipt === true);
  assert.equal(received.diag.browser.status, 'RECEIVED');
  assert.equal(page.compose.syntheticBrowser.opened.length, 1, '只在宿主环境打开过一次默认浏览器');
  await page.click('diagPlan');
  await page.click('diagConfirm');
  await page.click('diagExecute');
  await waitFor(page, (snap) => Boolean(snap.diag.executed));
  await page.click('diagRecheck');
  await waitFor(page, (snap) => Boolean(snap.diag.recheck));
  page.close();
});

test('旅程3b AI 模式走 T4 会话，应用前必须有本地确认', async () => {
  const page = await createPageRuntime('j3b');
  await page.click('tabDiag');
  await page.click('diagScan');
  await waitFor(page, (snap) => Boolean(snap.diag.task_id));
  await page.click('diagPlan');
  await waitFor(page, (snap) => Boolean(snap.diag.plan_id));

  await page.click('diagAiMode');
  const proposed = await waitFor(page, (snap) => Boolean(snap.diag.ai?.taskId));
  assert.equal(proposed.diag.ai.status, 'AWAITING_NETWORK_CONFIRMATION', 'AI 建议必须停在本地确认前');
  assert.equal(proposed.diag.ai.lastError, null);
  const record = page.compose.store.getRecord(proposed.diag.ai.taskId, 'ai_task_v1');
  assert.equal(record.network_plan.status, 'AWAITING_LOCAL_USER_CONFIRMATION');
  assert.equal(record.network_plan.applied, false, '未确认前不得应用');
  assert.equal(record.network_confirmation_id, null);
  assert.match(page.text('diagAiView'), /AWAITING_NETWORK_CONFIRMATION/);

  await page.click('diagAiConfirm');
  const done = await waitFor(page, (snap) => snap.diag.ai?.status === 'COMPLETED' || Boolean(snap.diag.error));
  assert.equal(page.snapshot().diag.error, null);
  assert.equal(done.diag.ai.status, 'COMPLETED');
  assert.ok(page.compose.store.getRecord(proposed.diag.ai.taskId, 'ai_task_v1').network_confirmation_id);
  assert.ok(page.compose.modelOutbound.length > 0, 'AI 模式必须真正走 T4 控制面转发');
  page.close();
});

test('旅程4 方案切换、专用模式停用日常白名单但保留、应急确认到期与结束', async () => {
  const page = await createPageRuntime('j4');
  await page.click('previewDaily');
  await page.click('applyDaily');
  const daily = await waitFor(page, (snap) => Boolean(snap.network.apply?.overall));
  assert.equal(daily.network.currentMode, 'daily_single_ip');
  await page.click('whitelistAdd');
  const added = await waitFor(page, (snap) => snap.network.whitelistRetained > 0);
  assert.equal(added.network.whitelistActive.length, 1);

  await page.click('applyClaude');
  const dedicated = await waitFor(page, (snap) => snap.network.currentMode === 'claude_single_ip');
  assert.equal(dedicated.network.whitelistActive.length, 0, '专用模式不得启用日常白名单');
  assert.equal(dedicated.network.whitelistRetained, 1, '专用模式必须保留日常白名单条目');
  assert.match(page.text('networkMode'), /专用模式停用但保留/);

  await page.click('networkProtect');
  const protectedSnap = await waitFor(page, (snap) => Boolean(snap.network.protection));
  assert.equal(protectedSnap.network.protection.protection.status, 'CONFIRMED');

  await page.click('emergencyOn');
  const denied = await waitFor(page, (snap) => Boolean(snap.network.error));
  assert.equal(denied.network.error.code, 'EMERGENCY_NOT_CONFIRMED', '未勾选本次确认不得开启应急');
  page.document.getElementById('emergencyConfirm').checked = true;
  page.setValue('emergencyMinutes', '45');
  await page.click('emergencyOn');
  const emergency = await waitFor(page, (snap) => Boolean(snap.network.emergency?.session_id));
  assert.equal(emergency.network.emergency.duration_minutes, 45);
  assert.equal(emergency.network.emergency.claude_protected, true);
  assert.ok(emergency.network.emergency.expires_at);
  assert.equal(emergency.network.emergency.targets.length, 1);
  assert.equal(emergency.network.emergency.targets[0].host, 'support.example');
  assert.equal(emergency.network.emergency.targets[0].match, 'subdomains');
  const openedSession = emergency.network.emergency;

  await page.click('emergencyOff');
  await waitFor(page, (snap) => snap.network.emergency !== openedSession);
  assert.equal(page.snapshot().network.error, null);
  assert.equal(page.snapshot().network.protection.protection.status, 'CONFIRMED', '结束应急不得解除原保护');

  await page.click('lifecycleClose');
  await waitFor(page, (snap) => Boolean(snap.network.lifecycle));
  assert.equal(page.snapshot().network.error, null);
  page.close();
});

test('旅程5 日报来自 T2 实际产物，AI 附注是独立产物且不改写标准事实', async () => {
  const page = await createPageRuntime('j5');
  await page.click('refreshTraffic');
  const snap = await waitFor(page, (item) => Boolean(item.traffic.daily?.reportId));
  assert.equal(snap.traffic.daily.routeResult, 'FAIL');
  assert.equal(snap.traffic.daily.coverageStatus, 'MONITORING_INCOMPLETE');
  assert.equal(snap.traffic.daily.applications, null, '日报未提供分应用数据时不得编造');
  assert.match(page.text('trafficRates'), /未知归属/);
  assert.match(page.text('trafficRates'), /UNKNOWN/);

  const artifactText = await page.compose.auditStore.readText(snap.traffic.dailyPath);
  const artifact = JSON.parse(artifactText);
  assert.equal(snap.traffic.daily.reportId, artifact.reportId, '页面日报必须来自已交付的 T2 产物');
  assert.deepEqual(snap.traffic.daily.routeCounts, artifact.routeCounts);
  assert.ok(snap.traffic.daily.archiveEntries.length > 0, '必须带出 T2 归档来源');
  assert.ok(snap.traffic.daily.archiveEntries.every((entry) => entry.sha256 && entry.archivePath));
  assert.ok(snap.traffic.history.length >= 2, '历史必须来自 T2 报告清单而不是诊断结果');
  assert.ok(snap.traffic.history.every((item) => item.path.endsWith('daily-audit.json')));
  assert.ok(snap.traffic.history.some((item) => item.reportDate === artifact.reportDate));

  assert.equal(snap.traffic.daily.late_ai_note, null, 'AI 尚未产出附注时不得预置');
  await page.click('aiDailyNote');
  const analysed = await waitFor(page, (item) => item.traffic.notes.length > 0 || Boolean(item.ai.error));
  assert.equal(analysed.ai.error, null, JSON.stringify(analysed.ai.task));
  const note = analysed.traffic.daily.late_ai_note;
  assert.equal(note.reportId, artifact.reportId);
  assert.equal(note.affectsStandardFacts, false);
  assert.ok(note.path.startsWith('reports/ai-notes/'), 'AI 附注必须是独立的 T2 产物');
  assert.equal(analysed.traffic.daily.routeResult, 'FAIL', '附注不得改写标准事实');
  assert.equal(await page.compose.auditStore.readText(snap.traffic.dailyPath), artifactText, '附注不得改写已交付产物');

  await page.click('exportDailyJson');
  const exportedJson = await waitFor(page, (item) => Boolean(item.traffic.export?.jsonPath));
  await page.click('exportDailyMd');
  const exported = await waitFor(page, (item) => item.traffic.export?.format === 'md');
  assert.equal(exported.traffic.export.reportId, artifact.reportId);
  assert.equal(exported.traffic.export.sourceJson, snap.traffic.dailyPath);

  const digest = (value) => createHash('sha256').update(value).digest('hex');
  const jsonText = await readFile(exportedJson.traffic.export.jsonPath, 'utf8');
  const mdText = await readFile(exported.traffic.export.mdPath, 'utf8');
  assert.equal(digest(jsonText), digest(artifactText), '导出的 JSON 必须与 T2 产物逐字节一致');
  assert.equal(digest(mdText), digest(await page.compose.auditStore.readText(exported.traffic.export.sourceMd)));
  page.close();
});

test('模型能力来自 T4 服务端能力接口，不由前端布尔值决定', async () => {
  const page = await createPageRuntime('j5-ai');
  await page.click('refreshCapabilities');
  const ready = await waitFor(page, (item) => Boolean(item.ai.capabilities));
  assert.equal(ready.ai.capabilities.user_ref, 'user-max');
  assert.equal(ready.ai.capabilities.tasks.daily_analysis.status, 'AVAILABLE');
  assert.match(page.text('capabilityDetail'), /daily_analysis/);

  const offline = await createPageRuntime('j5-ai-off', {aiAvailable: false, sessionToken: 'token-max'});
  await offline.click('refreshCapabilities');
  const down = await waitFor(offline, (item) => Boolean(item.ai.capabilities));
  assert.equal(down.ai.capabilities.tasks.daily_analysis.status, 'UNAVAILABLE');
  await offline.click('refreshTraffic');
  await waitFor(offline, (item) => Boolean(item.traffic.daily?.reportId));
  await offline.click('aiDailyNote');
  const denied = await waitFor(offline, (item) => Boolean(item.ai.error));
  assert.equal(denied.ai.error.code, 'AI_NOT_ATTACHED');
  assert.equal(denied.traffic.daily.routeResult, 'FAIL', 'AI 不可用时标准事实仍在');
  assert.ok(offline.snapshot().traffic.history.length >= 2, 'AI 不可用时历史仍可读');
  page.close();
  offline.close();
});

/**
 * Node 控制端基线没有应用用户管理路由（RC2 只在 Rust 控制端实现，页面按它的契约取用户列表）。
 * 旅程 6 与重启旅程继续跑在基线组合根上，所以在测试里补一个只读的用户目录路由：
 * 按基线自己的会话校验身份，非管理员 403，列出组合根里登记的合成用户。
 * 它只让管理页能按「先从服务端列表选用户」的正式交互操作基线的配额路由，不证明 Rust 用户管理已运行。
 */
const BASELINE_DIRECTORY = Object.freeze([
  {user_ref: 'user-max', username: 'user-max', role: 'user', status: 'ACTIVE', active_sessions: 1},
  {user_ref: 'user-pro', username: 'user-pro', role: 'user', status: 'ACTIVE', active_sessions: 1},
  {user_ref: 'user-free', username: 'user-free', role: 'user', status: 'ACTIVE', active_sessions: 1},
  {user_ref: 'admin', username: 'admin', role: 'admin', status: 'ACTIVE', active_sessions: 1},
]);

function withUserDirectory(compose) {
  const inner = compose.handler;
  compose.handler = {
    ...inner,
    async handle(request) {
      const url = new URL(request.url);
      if (request.method === 'GET' && url.pathname === '/api/admin/users') {
        let actor;
        try {
          actor = compose.controlAuth.authenticate(request);
        } catch {
          return Response.json({code: 'CONTROL_UNAUTHORIZED', reason: 'application session is invalid'}, {status: 401});
        }
        if (actor.role !== 'admin') return Response.json({code: 'CONTROL_FORBIDDEN', reason: 'administrator permission is required'}, {status: 403});
        return Response.json({users: BASELINE_DIRECTORY});
      }
      return inner.handle(request);
    },
  };
  return compose;
}

/** 点一个管理按钮，等这次动作完成（完成序号增加），返回完成后的快照。 */
async function adminStep(page, buttonId) {
  const before = page.snapshot().admin.completed?.seq ?? 0;
  await page.click(buttonId);
  return waitFor(page, (snap) => (snap.admin.completed?.seq ?? 0) > before);
}

async function selectAdminTarget(page, userRef) {
  await adminStep(page, 'adminRefresh');
  assert.ok(page.snapshot().admin.users.some((user) => user.user_ref === userRef), '目标来自服务端用户列表');
  page.setValue('adminUserSelect', userRef);
  const selected = await adminStep(page, 'adminSelectUser');
  assert.equal(selected.admin.selectedUserRef, userRef);
  return selected;
}

async function setQuotaForm(page, {value, unit = 'GB', expireAt = null}) {
  page.setValue('adminLimitValue', String(value));
  page.setValue('adminLimitUnit', unit);
  page.setValue('adminLimitPeriod', 'MONTH');
  if (expireAt) page.setValue('adminLimitExpire', expireAt);
}

test('旅程6 管理员调额只影响目标用户，攻击者被拒，重开不重置账目', async () => {
  const compose = withUserDirectory(await createDesktopComposition('j6-admin', {sessionToken: 'token-admin'}));
  const admin = await createPageRuntime('j6-admin', {compose, sessionToken: 'token-admin'});
  assert.equal(admin.snapshot().role, 'admin');
  assert.equal(admin.document.getElementById('adminCard').hidden, false);
  const proBefore = await createPageRuntime('j6-pro-before', {compose, sessionToken: 'token-pro'});
  await proBefore.click('refreshTraffic');
  const proLimitBefore = (await waitFor(proBefore, (snap) => Boolean(snap.traffic.quota))).traffic.quota.limit_bytes;

  const noTarget = await adminStep(admin, 'adminLimit');
  assert.equal(noTarget.admin.error.code, 'ADMIN_TARGET_REQUIRED', '没选用户时不向任何默认用户提交');

  await selectAdminTarget(admin, 'user-max');
  await setQuotaForm(admin, {value: 250, expireAt: '2030-01-01T00:00:00.000Z'});
  const allocated = await adminStep(admin, 'adminAllocate');
  assert.equal(allocated.admin.error, null, JSON.stringify(allocated.admin.error));
  await setQuotaForm(admin, {value: 80});
  const limited = await adminStep(admin, 'adminLimit');
  assert.equal(limited.admin.error, null, JSON.stringify(limited.admin.error));
  assert.equal(limited.admin.last.snapshot.limit_bytes, 80_000_000_000, '提交的是表单里填的额度');
  assert.equal(limited.admin.selectedUserRef, 'user-max');
  assert.equal(limited.userRef, 'admin', '切换管理对象不改变管理员自己的身份');
  const refreshed = await adminStep(admin, 'adminRefresh');
  assert.ok(refreshed.admin.resources.length > 0, '资源列表来自服务端');

  const max = await createPageRuntime('j6-max', {compose, sessionToken: 'token-max'});
  await max.click('refreshTraffic');
  const maxQuota = await waitFor(max, (snap) => Boolean(snap.traffic.quota));
  assert.equal(maxQuota.traffic.quota.limit_bytes, 80_000_000_000);
  assert.equal(max.document.getElementById('adminCard').hidden, true);
  assert.equal(max.snapshot().admin.users, null, '普通用户快照里没有管理数据');

  const pro = await createPageRuntime('j6-pro', {compose, sessionToken: 'token-pro'});
  await pro.click('refreshTraffic');
  const proQuota = await waitFor(pro, (snap) => Boolean(snap.traffic.quota));
  assert.equal(proQuota.traffic.quota.limit_bytes, proLimitBefore, '调额不得波及其他用户');

  const proRefresh = await adminStep(pro, 'adminRefresh');
  assert.equal(proRefresh.admin.error.code, 'CONTROL_FORBIDDEN', '普通用户读不到用户列表');
  assert.equal(proRefresh.admin.users, null);
  const forged = await compose.handler.handle(new Request('https://application.synthetic.invalid/api/admin/quota/limit', {
    method: 'POST',
    headers: {'content-type': 'application/json', authorization: 'Bearer token-pro'},
    body: JSON.stringify({userRef: 'user-max', operation_id: 'j6-forged', limit_value: 1, limit_unit: 'GB'}),
  }));
  assert.equal(forged.status, 403, '绕过页面直接调管理接口同样被控制端拒绝');

  const attacker = await createPageRuntime('j6-attacker', {compose, sessionToken: 'unregistered-attacker'});
  assert.notEqual(attacker.snapshot().role, 'admin');
  assert.equal(attacker.document.getElementById('becomeAdmin'), null);
  const attacked = await adminStep(attacker, 'adminRefresh');
  assert.ok(['CONTROL_UNAUTHORIZED', 'CONTROL_FORBIDDEN'].includes(attacked.admin.error.code));

  const reopened = await createPageRuntime('j6-reopen', {compose, sessionToken: 'token-max'});
  await reopened.click('refreshTraffic');
  const reopenedQuota = await waitFor(reopened, (snap) => Boolean(snap.traffic.quota));
  assert.equal(reopenedQuota.traffic.quota.limit_bytes, 80_000_000_000, '重开不得重置账目');

  for (const runtime of [proBefore, max, pro, attacker, reopened]) runtime.close();
  admin.close();
  compose.close();
});

test('旅程7 无服务降级：明确未接入，历史与恢复入口仍可操作', async () => {
  const page = await createPageRuntime('j7', {disconnected: true, aiAvailable: false, nativeBridge: false, sessionToken: 'token-max'});
  assert.match(page.text('sidebarStatus'), /原生桥接未接入/);
  assert.match(page.text('capabilityView'), /未接入/);
  await page.click('scanDeep');
  const snap = await waitFor(page, (item) => Boolean(item.local.error));
  assert.equal(snap.disconnected, true);
  assert.equal(snap.local.error.code, 'SERVICE_UNAVAILABLE');
  assert.ok(!/completed/.test(page.text('localResult')));

  await page.click('refreshTraffic');
  const traffic = await waitFor(page, (item) => Boolean(item.traffic.daily?.reportId));
  assert.equal(traffic.traffic.daily.routeResult, 'FAIL');
  await page.click('localPreviewRestore');
  const restore = await waitFor(page, (item) => Boolean(item.local.restore));
  assert.equal(restore.local.restore.status, 'NO_BACKUP');
  page.close();
});

test('合成宿主关闭重启后从既有存储挂载，任务与账目都不重置', async () => {
  const compose = withUserDirectory(await createDesktopComposition('j8', {sessionToken: 'token-admin'}));
  const page = await createPageRuntime('j8', {compose, sessionToken: 'token-admin'});
  const root = page.compose.root;
  await page.click('scanDeep');
  const scanned = await waitFor(page, (snap) => Boolean(snap.local.scan_id));
  const scanId = scanned.local.scan_id;
  await selectAdminTarget(page, 'user-max');
  await setQuotaForm(page, {value: 250, expireAt: '2030-01-01T00:00:00.000Z'});
  assert.equal((await adminStep(page, 'adminAllocate')).admin.error, null);
  await setQuotaForm(page, {value: 80});
  const limited = await adminStep(page, 'adminLimit');
  assert.equal(limited.admin.error, null, JSON.stringify(limited.admin.error));
  page.compose.close();

  const restarted = withUserDirectory(await createDesktopComposition('j8-restart', {
    root,
    mountExistingRoot: true,
    authority: page.compose.authority,
    sessionToken: 'token-admin',
  }));
  const reopened = await createPageRuntime('j8-reopen', {compose: restarted, sessionToken: 'token-admin'});
  assert.equal(reopened.snapshot().local.scan_id, scanId, '重启宿主后必须找回原任务');
  assert.notEqual(reopened.snapshot().local.status, 'IDLE');
  const maxPage = await createPageRuntime('j8-max', {compose: restarted, sessionToken: 'token-max'});
  await maxPage.click('refreshTraffic');
  const quota = await waitFor(maxPage, (snap) => Boolean(snap.traffic.quota));
  assert.equal(quota.traffic.quota.limit_bytes, 80_000_000_000, '重启宿主不得重置账目');
  assert.equal(quota.traffic.quota.stale, false, '重启后必须读到权威当前值而不是陈旧快照');
  assert.equal(quota.traffic.quota.authority_status, 'AVAILABLE');
  assert.ok(quota.traffic.daily?.reportId, '重启宿主后仍读到既有 T2 产物');

  await selectAdminTarget(reopened, 'user-max');
  const suspended = await adminStep(reopened, 'adminSuspend');
  assert.equal(suspended.admin.error, null, '重启后新的停用操作必须仍能落到权威');
  assert.equal(suspended.admin.last.ok, true);
  assert.equal(suspended.admin.last.snapshot.status, 'DISABLED');
  maxPage.close();
  reopened.close();
  restarted.close();
});

test('会话恢复按认证身份隔离，不串其他用户的任务与白名单', async () => {
  const max = await createPageRuntime('j8b-max', {sessionToken: 'token-max'});
  await max.click('scanDeep');
  const scanned = await waitFor(max, (snap) => Boolean(snap.local.scan_id));
  await max.click('whitelistAdd');
  await waitFor(max, (snap) => snap.network.whitelistRetained > 0);

  const pro = await createPageRuntime('j8b-pro', {compose: max.compose, sessionToken: 'token-pro'});
  assert.equal(pro.snapshot().userRef, 'user-pro');
  assert.equal(pro.snapshot().local.scan_id, null, '不得装入其他用户的扫描');
  assert.equal(pro.snapshot().local.status, 'IDLE');
  assert.equal(pro.snapshot().network.whitelistRetained, 0, '不得看到其他用户的白名单');

  const anonymous = await createPageRuntime('j8b-anon', {compose: max.compose, sessionToken: 'unregistered-attacker'});
  assert.equal(anonymous.snapshot().userRef, null);
  assert.equal(anonymous.snapshot().local.scan_id, null);
  assert.equal(anonymous.snapshot().network.whitelist, null, '匿名身份不得回退到某个真实用户');
  assert.equal(anonymous.snapshot().network.whitelistRetained, 0);

  const again = await createPageRuntime('j8b-max2', {compose: max.compose, sessionToken: 'token-max'});
  assert.equal(again.snapshot().local.scan_id, scanned.local.scan_id, '本人重开仍找回自己的任务');
  for (const runtime of [pro, anonymous, again]) runtime.close();
  max.close();
});

test('任务切换后旧诊断响应不得覆盖新任务', async () => {
  const page = await createPageRuntime('j8c');
  const started = [];
  const realStart = page.compose.diagnostics.startScan.bind(page.compose.diagnostics);
  let calls = 0;
  page.compose.diagnostics.startScan = async (input) => {
    const delayMs = (calls += 1) === 1 ? 250 : 0;
    const result = await realStart(input);
    started.push({environmentRef: input.environmentRef, profileRef: input.profileRef, task_id: result.task_id});
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return result;
  };

  await page.click('tabDiag');
  page.setValue('diagEnv', 'synthetic-windows');
  page.setValue('diagProfile', 'Default');
  await page.click('diagScan');
  page.setValue('diagEnv', 'wsl-synthetic');
  page.setValue('diagProfile', 'Profile 1');
  await page.click('diagScan');
  await waitFor(page, () => started.length === 2);
  await new Promise((resolve) => setTimeout(resolve, 400));

  const snap = page.snapshot();
  assert.equal(snap.diag.env, 'wsl-synthetic');
  assert.equal(snap.diag.profileRef, 'Profile 1');
  assert.equal(snap.diag.task_id, started[1].task_id, '页面必须留在新任务上');
  assert.notEqual(snap.diag.task_id, started[0].task_id);
  const record = page.compose.store.getRecord(snap.diag.task_id, 'diagnostic_result');
  assert.equal(record.environment_ref, 'wsl-synthetic', '展示的任务与其环境必须一致');
  page.close();
});

test('AI 调用归属发起会话的身份，不记到其他用户名下', async () => {
  const max = await createPageRuntime('j9-max', {sessionToken: 'token-max'});
  const pro = await createPageRuntime('j9-pro', {compose: max.compose, sessionToken: 'token-pro'});
  assert.equal(pro.snapshot().userRef, 'user-pro');

  await pro.click('tabDiag');
  await pro.click('diagScan');
  await waitFor(pro, (snap) => Boolean(snap.diag.task_id));
  await pro.click('diagPlan');
  await waitFor(pro, (snap) => Boolean(snap.diag.plan_id));
  await pro.click('diagAiMode');
  const proposed = await waitFor(pro, (snap) => Boolean(snap.diag.ai?.taskId) || Boolean(snap.diag.error));
  assert.equal(pro.snapshot().diag.error, null);
  const networkTask = pro.compose.controlStore.getTask(proposed.diag.ai.taskId);
  assert.equal(networkTask.user_ref, 'user-pro', 'T4 网络诊断任务必须记在发起者名下');

  await pro.click('refreshTraffic');
  await waitFor(pro, (snap) => Boolean(snap.traffic.daily?.reportId));
  await pro.click('aiDailyNote');
  const analysed = await waitFor(pro, (snap) => Boolean(snap.ai.task) || Boolean(snap.ai.error));
  assert.equal(analysed.ai.error, null, JSON.stringify(analysed.ai.task));
  assert.equal(pro.compose.controlStore.getTask(analysed.ai.task.taskId).user_ref, 'user-pro', 'T4 日报分析任务必须记在发起者名下');

  await max.click('refreshTraffic');
  await waitFor(max, (snap) => Boolean(snap.traffic.daily?.reportId));
  await max.click('aiDailyNote');
  const mine = await waitFor(max, (snap) => Boolean(snap.ai.task) || Boolean(snap.ai.error));
  assert.equal(max.compose.controlStore.getTask(mine.ai.task.taskId).user_ref, 'user-max');
  assert.notEqual(mine.ai.task.taskId, analysed.ai.task.taskId);

  const anonymous = await createPageRuntime('j9-anon', {compose: max.compose, sessionToken: 'unregistered-attacker'});
  await anonymous.click('refreshTraffic');
  await waitFor(anonymous, (snap) => Boolean(snap.traffic.daily?.reportId) || Boolean(snap.traffic.error));
  await anonymous.click('aiDailyNote');
  const denied = await waitFor(anonymous, (snap) => Boolean(snap.ai.error));
  assert.equal(denied.ai.error.code, 'AI_NOT_ATTACHED', '无身份不得拿到任何用户的 AI 会话');
  assert.equal(anonymous.snapshot().ai.available, false);

  for (const runtime of [pro, anonymous]) runtime.close();
  max.close();
});

test('替代扫描期间页面保持运行中，旧扫描不得把状态改回空闲', async () => {
  const page = await createPageRuntime('j9b', {scanDelayMs: 220});
  await page.click('scanDeep');
  await waitFor(page, (snap) => snap.local.status === 'RUNNING');
  await page.click('scanQuick');
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.equal(page.snapshot().local.status, 'RUNNING', '被取消的旧扫描不得把页面改成空闲');
  assert.equal(page.snapshot().local.scan_id, null);

  const scanned = await waitFor(page, (snap) => Boolean(snap.local.scan_id));
  assert.equal(scanned.local.error, null);
  assert.ok(scanned.local.identities.length >= 2, '替代扫描必须真正提交结果');
  assert.notEqual(scanned.local.status, 'RUNNING');
  page.close();
});

test('扫描进行中点击依赖动作被拒，替代扫描结果仍能提交', async () => {
  const page = await createPageRuntime('j9c', {scanDelayMs: 220});
  await page.click('scanDeep');
  await waitFor(page, (snap) => snap.local.status === 'RUNNING');
  await page.click('scanQuick');
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.equal(page.snapshot().local.status, 'RUNNING');
  assert.equal(page.document.getElementById('localClassify').disabled, true, '扫描中依赖动作必须不可触发');

  await page.click('localClassify');
  const blocked = page.snapshot();
  assert.equal(blocked.local.error.code, 'SCAN_IN_PROGRESS', '页面事件仍到达服务时必须被拒');
  assert.equal(blocked.local.status, 'RUNNING', '被拒的动作不得取消当前扫描');
  assert.equal(blocked.local.classification_id ?? null, null);

  await page.click('localBuildPlan');
  assert.equal(page.snapshot().local.error.code, 'SCAN_IN_PROGRESS');
  await page.click('localExport');
  assert.equal(page.snapshot().local.error.code, 'SCAN_IN_PROGRESS');

  const scanned = await waitFor(page, (snap) => Boolean(snap.local.scan_id));
  assert.ok(scanned.local.identities.length >= 2, '替代扫描结果不得被这些点击丢弃');
  await waitForDom(page, (doc) => doc.getElementById('localClassify').disabled === false);

  await page.click('localClassify');
  const classified = await waitFor(page, (snap) => snap.local.problems.length > 0);
  assert.equal(classified.local.error, null);
  page.close();
});

test('批量处理进行中不得被新扫描或导出打断', async () => {
  const page = await createPageRuntime('j9d', {executeStepDelayMs: 40});
  await confirmedPlan(page);
  await page.click('localExecute');
  await waitFor(page, (snap) => (snap.local.receipts || []).some((item) => item.status === 'APPLIED'));
  assert.equal(page.document.getElementById('scanDeep').disabled, true);

  await page.click('scanDeep');
  assert.equal(page.snapshot().local.error.code, 'OPERATION_IN_PROGRESS');
  await page.click('localExport');
  assert.equal(page.snapshot().local.error.code, 'OPERATION_IN_PROGRESS');

  const settled = await waitFor(page, settled_ => settled_.local.operation_status === 'completed' || settled_.local.operation_status === 'partial');
  assert.equal(settled.local.operation_status, 'completed', '执行结果不得被这些点击丢弃');
  await waitForDom(page, (doc) => doc.getElementById('scanDeep').disabled === false);
  page.close();
});

test('重开 session 从 store 恢复任务而不是 IDLE', async () => {
  const compose = await createDesktopComposition('reopen', {sessionToken: 'token-max'});
  const first = createDesktopSession(compose, {sessionToken: 'token-max'});
  await first.localScan('deep');
  assert.ok(first.snapshot().local.scan_id);
  const second = createDesktopSession(compose, {sessionToken: 'token-max'});
  assert.notEqual(second.snapshot().local.status, 'IDLE');
  assert.equal(second.snapshot().local.scan_id, first.snapshot().local.scan_id);
  compose.close();
});

test('RC6 旅程：窗口隐藏时危急事件经宿主发系统通知，提示列表写明结果；通知失败时危急横幅保留并写明失败', async (t) => {
  const {composition} = await import('../delivery/harness.mjs');
  const {createNativeHostDouble} = await import('../delivery/nativeHostDouble.mjs');
  const {PERSISTED_MAX_SESSION, createHostFetch, readyControl, withIdentityRoutes} = await import('../delivery/productHost.mjs');
  const {transientRun} = await import('../../fixtures/transientRoot.mjs');
  const {mkdir} = await import('node:fs/promises');
  const prepared = await composition('rc6-page');
  const base = transientRun('ui', 'rc6-page-logs');
  const logDirs = {host: path.join(base, 'host'), control: path.join(base, 'control'), service: path.join(base, 'service')};
  await mkdir(logDirs.service, {recursive: true});
  const kernel = {connections: []};
  const wrong = (id, host) => ({id, metadata: {process: 'claude.exe', host}, chains: ['DIRECT'], upload: 2, download: 2});
  const double = createNativeHostDouble({
    workspaceRoot: prepared.root,
    clock: () => new Date().toISOString(),
    logDirs,
    notices: {hidden: true, fail: 'NOTIFICATION_UNAVAILABLE'},
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
      protect: async () => ({protection: {requested: true, new_connections_restricted: true}, close_existing: {status: 'CLOSED'}}),
    },
  });
  const page = await createPageRuntime('rc6-page-ui', {
    hostPrimitives: {
      __TAURI__: {core: {invoke: (command, args) => (command === 'steward_user_confirm' ? double.confirm(args.request) : double.invoke(args.op, args.payload, args.authorizationRef))}},
      fetch: createHostFetch({controlBaseUrl: 'https://control.synthetic.invalid', controlHandler: withIdentityRoutes(prepared), core: prepared.core}),
      navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true, hardwareConcurrency: 8, cookieEnabled: true},
      RTCPeerConnection: null,
    },
  });
  const current = await page.window.__STEWARD_BOOT__;
  const runtime = current.compose.auditRuntime;
  t.after(async () => {
    await current.compose.dispose();
    page.close();
    prepared.close();
  });
  await page.click('monitorEnable');
  await waitForDom(page, () => /已启用/.test(page.text('monitorScope')));

  kernel.connections = [wrong('rc6-a', 'api.anthropic.com')];
  await runtime.tick();
  await runtime.idle();
  await page.click('monitorRefresh');
  await waitForDom(page, (document) => document.getElementById('criticalBanner').hidden === false && /系统通知/.test(page.text('monitorAlerts')));
  assert.match(page.text('monitorAlerts'), /系统通知失败（NOTIFICATION_UNAVAILABLE）/);
  assert.equal(double.notices.requests.length, 1);
  assert.deepEqual(Object.keys(double.notices.requests[0]).sort(), ['event', 'ref']);

  double.notices.fail = null;
  kernel.connections = [wrong('rc6-b', 'claude.ai')];
  await runtime.tick();
  await runtime.idle();
  await page.click('monitorRefresh');
  await waitForDom(page, () => /系统通知已弹出/.test(page.text('monitorAlerts')));
  assert.equal(double.notices.shown.length, 1);
});
