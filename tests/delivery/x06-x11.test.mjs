import assert from 'node:assert/strict';
import test from 'node:test';
import {adminRequest, createQuotaHarness, GB_250, handleJson, threeUserResources} from '../../fixtures/control/harness.mjs';
import {RECORD} from '../../src/core/network/constants.mjs';
import {composition} from './harness.mjs';

const USER = 'user-max';

async function provisionThreeUsers(handler, limits = {}) {
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
    assert.equal(allocated.status, 200, JSON.stringify(allocated.body));
    ids[user.userRef] = allocated.body.binding.provider_user_id;
  }
  return ids;
}

test('X06 三模式依次切换：Claude 固定 A，双模式其他走 B，专用模式停用日常白名单', async () => {
  const compose = await composition('x06');
  const applied = await compose.network.confirmAndApply({
    operation_id: 'x06-daily',
    userRef: USER,
    environmentRef: compose.env,
    mode: 'daily_single_ip',
    authorization: compose.auth(USER),
  });
  assert.ok(['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED'].includes(applied.overall));

  const added = await compose.network.updateWhitelist({
    userRef: USER,
    action: 'add',
    payload: {input: 'direct.example', match: 'exact'},
    mode: 'daily_single_ip',
    authorization: compose.auth(USER),
    environmentRef: compose.env,
    operation_id: 'x06-wl',
  });
  assert.equal(added.ok, true);

  const matrices = {};
  for (const mode of ['daily_single_ip', 'claude_single_ip', 'claude_dual_ip']) {
    const preview = await compose.network.previewModeChange({userRef: USER, environmentRef: compose.env, mode});
    matrices[mode] = preview.plan.matrix;
  }
  for (const [mode, matrix] of Object.entries(matrices)) {
    assert.equal(matrix.claude.exit, 'A', `${mode} 的 Claude 最终出口必须固定为 A`);
    assert.equal(matrix.claude.rotate, false, 'Claude 不在两个出口之间轮换');
  }
  assert.equal(matrices.daily_single_ip.whitelist.enabled, true);
  assert.equal(matrices.claude_single_ip.whitelist.enabled, false, '专用模式停用日常白名单');
  assert.equal(matrices.claude_dual_ip.whitelist.enabled, false);
  assert.equal(matrices.claude_dual_ip.other.exit, 'B', '双 IP 模式其他流量走 B');
  assert.equal(matrices.claude_single_ip.other.exit, 'A', '单 IP 模式其他流量与 Claude 同走 A');
  assert.equal(matrices.daily_single_ip.tun_required, false, '日常模式不接管全局');
  for (const mode of ['claude_single_ip', 'claude_dual_ip']) {
    assert.equal(matrices[mode].whitelist_retained, true, '切回后不要求用户重新录入');
    assert.equal(matrices[mode].tun_required, true, '专用模式由 TUN 接管，范围可见');
  }
  const retained = compose.network.getWhitelist(USER);
  assert.equal(retained.entries.length, 1);
  compose.close();
});

test('X07 固定出口故障后终止内核、停 TUN、关闭界面各自留痕且不放出未知出口', async () => {
  const compose = await composition('x07');
  await compose.network.confirmAndApply({
    operation_id: 'x07-apply',
    userRef: USER,
    environmentRef: compose.env,
    mode: 'claude_single_ip',
    authorization: compose.auth(USER),
  });

  const protectedResult = await compose.network.handleProtection(
    {user_ref: USER, environment_ref: compose.env},
    {classification: 'WRONG_ROUTE', live: true},
  );
  assert.equal(protectedResult.protection.requested, true, '阻断指令发出单独记录');
  assert.equal(protectedResult.protection.status, 'CONFIRMED', '生效结果单独记录');
  assert.equal(protectedResult.protection.new_connections_restricted, true);
  assert.equal(protectedResult.protection.existing_closed, true);
  assert.equal(protectedResult.protection.reconnect_allowed, false, '断开后不得再次错误连接');
  assert.ok(protectedResult.observed_at, '动作时间可读');

  const crashed = await compose.network.executeLifecycle({user_ref: USER, environment_ref: compose.env}, {type: 'core_crash'});
  assert.equal(crashed.effects.direct_released, false, '内核崩溃不得降级直连');
  assert.ok(crashed.executed.some((item) => item.action === 'keep_os_protection' && item.status === 'CONFIRMED'));

  const closed = await compose.network.executeLifecycle({user_ref: USER, environment_ref: compose.env}, {type: 'close_window'});
  assert.equal(closed.effects.core_stopped, false, '关闭界面不等于停内核');
  assert.equal(closed.effects.protection_retained, true);

  const stopped = await compose.network.executeLifecycle({user_ref: USER, environment_ref: compose.env}, {type: 'stop_management'});
  assert.equal(stopped.effects.management_stopped, true);
  assert.equal(stopped.effects.requires_explicit_confirm, true, '解除保护必须单独明确确认');
  assert.equal(stopped.effects.claude_unprotected, true, '解除后的失去保护状态必须写明，不得静默');
  compose.close();
});

test('X08 手动应急走可区分的第二浏览器，Claude 仍受保护，结束与到期都关闭', async () => {
  const compose = await composition('x08');
  await compose.network.confirmAndApply({
    operation_id: 'x08-apply',
    userRef: USER,
    environmentRef: compose.env,
    mode: 'claude_single_ip',
    authorization: compose.auth(USER),
  });

  await assert.rejects(
    () => compose.network.requestEmergency({
      user_ref: USER,
      environment_ref: compose.env,
      mode: 'claude_single_ip',
      targets: [{host: 'support.example', match: 'subdomains'}],
    }),
    (error) => error.code === 'EMERGENCY_NOT_CONFIRMED',
    '应急必须本次确认',
  );

  const session = await compose.network.requestEmergency({
    user_ref: USER,
    environment_ref: compose.env,
    mode: 'claude_single_ip',
    purpose: 'temporary_web_access',
    duration_minutes: 30,
    targets: [{host: 'support.example', match: 'subdomains'}],
    confirmation: {confirmed: true, confirmation_id: 'x08-confirm'},
  });
  assert.equal(session.host_opened, true);
  assert.equal(session.process, 'firefox.exe', '优先可区分的已安装第二浏览器');
  assert.equal(session.claude_protected, true, 'Claude 仍保持 A 或阻断');
  assert.equal(session.general_emergency, 'OPEN', '普通应急上网真实可用');
  assert.ok(session.expires_at);
  assert.equal(session.confirmation.original_protection_impact.includes('Claude'), true);

  const ended = await compose.network.endEmergency({
    session_id: session.session_id,
    user_ref: USER,
    environment_ref: compose.env,
  });
  assert.notEqual(ended.status, 'OPEN');
  assert.equal(ended.ended_reason, 'USER_ENDED', '手动结束要与到期区分');
  assert.equal(ended.open, false);
  const hostState = compose.emergencyHost.snapshot(session.session_id);
  assert.equal(hostState.open, false, '结束后第二浏览器会话必须关闭');

  const second = await compose.network.requestEmergency({
    user_ref: USER,
    environment_ref: compose.env,
    mode: 'claude_single_ip',
    purpose: 'temporary_web_access',
    duration_minutes: 15,
    targets: [{host: 'support.example', match: 'subdomains'}],
    confirmation: {confirmed: true, confirmation_id: 'x08-confirm-2'},
  });
  assert.equal(second.host_opened, true);
  compose.clock.set('2026-09-13T17:20:00.000Z');
  assert.equal(compose.emergencyHost.snapshot(second.session_id).open, true, '到期前会话仍开着');
  await compose.network.readState({userRef: USER, environmentRef: compose.env});
  const expired = compose.store.getRecord(second.session_id, RECORD.EMERGENCY);
  assert.equal(expired.ended_reason, 'EXPIRED', '到期由常规路径驱动关闭，不靠用户再点一次结束');
  assert.equal(expired.ended_at, '2026-09-13T17:20:00.000Z');
  assert.equal(expired.open, false);
  assert.equal(compose.emergencyHost.snapshot(second.session_id).open, false);
  assert.equal(expired.claude_protected, true, '到期关闭后 Claude 仍受保护');
  assert.equal(expired.mainline_restored_claim, false, '不得声称主线已恢复');
  compose.close();
});

test('X09 共享池内甲额度耗尽：甲 A/B 与在途受限，乙丙不受影响', async () => {
  const {handler, authority, store} = await createQuotaHarness('x09');
  const ids = await provisionThreeUsers(handler, {'user-jia': 1000});

  const openedBefore = authority.openConnection({connectionId: 'jia-before', userId: ids['user-jia'], role: 'A'});
  assert.equal(openedBefore.allowed, true);

  authority.ingestByteEvent({eventId: 'jia-burst', userId: ids['user-jia'], bytes: 2000, hop: 'metering'});
  const jia = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(jia.body.snapshot.status, 'LIMITED', '甲被服务端硬限额停用');

  for (const role of ['A', 'B']) {
    const opened = authority.openConnection({connectionId: `jia-new-${role}`, userId: ids['user-jia'], role});
    assert.equal(opened.allowed, false, `甲的新 ${role} 连接必须被拒`);
    assert.equal(opened.reason, 'USER_LIMITED');
  }
  assert.equal(authority.user(ids['user-jia']).remove !== null, true, '不能只撤销订阅下载，必须有节点侧处置');

  for (const other of ['user-yi', 'user-bing']) {
    const view = await handleJson(handler, adminRequest(`/api/admin/quota/usage?user_ref=${other}`));
    assert.notEqual(view.body.snapshot.status, 'LIMITED', `${other} 不受甲的耗尽影响`);
    const opened = authority.openConnection({connectionId: `${other}-new`, userId: ids[other], role: 'A'});
    assert.equal(opened.allowed, true);
  }
  store.close();
});

test('X10 重装、改本机时间、恢复旧配置、换模式都不重置服务端账目', async () => {
  const {handler, authority, store, clock} = await createQuotaHarness('x10');
  const ids = await provisionThreeUsers(handler, {'user-jia': 1000});
  authority.ingestByteEvent({eventId: 'jia-usage', userId: ids['user-jia'], bytes: 900, hop: 'metering'});
  const before = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(before.body.snapshot.used_bytes, 900);

  clock.set('2026-10-01T00:00:00.000Z');
  const afterClock = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(afterClock.body.snapshot.used_bytes, 900, '改本机时间不产生新周期');

  const reallocated = await handleJson(handler, adminRequest('/api/admin/quota/allocate', {method: 'POST', body: {
    userRef: 'user-jia',
    operation_id: 'alloc-user-jia',
    limitBytes: 1000,
    period: 'MONTH',
    expireAt: '2027-01-01T00:00:00.000Z',
  }}));
  assert.equal(reallocated.status, 200, JSON.stringify(reallocated.body));
  const afterReinstall = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(afterReinstall.body.snapshot.used_bytes, 900, '重装重跑同一 operation 不清账');

  await handleJson(handler, adminRequest('/api/admin/quota/suspend', {method: 'POST', body: {userRef: 'user-jia', operation_id: 'x10-suspend'}}));
  const suspended = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(suspended.body.snapshot.status, 'DISABLED');
  clock.set('2026-11-01T00:00:00.000Z');
  const stillSuspended = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(stillSuspended.body.snapshot.status, 'DISABLED', '暂停不因换周期或换模式自动解除');
  store.close();

  const compose = await composition('x10-network');
  const allocated = await handleJson(compose.handler, adminRequest('/api/admin/quota/allocate', {method: 'POST', body: {
    userRef: USER,
    operation_id: 'x10-alloc',
    limitBytes: 250_000_000_000,
    period: 'MONTH',
    expireAt: '2030-01-01T00:00:00.000Z',
  }}));
  assert.equal(allocated.status, 200, JSON.stringify(allocated.body));
  const limitSet = await handleJson(compose.handler, adminRequest('/api/admin/quota/limit', {method: 'POST', body: {userRef: USER, operation_id: 'x10-limit', limitBytes: 80_000_000_000}}));
  assert.equal(limitSet.status, 200, JSON.stringify(limitSet.body));
  const readQuota = async () => {
    const response = await compose.handler.handle(new Request('https://application.synthetic.invalid/api/network/quota', {headers: {authorization: 'Bearer token-max'}}));
    return (await response.json()).quota;
  };
  const baseline = await readQuota();
  assert.equal(baseline.limit_bytes, 80_000_000_000);

  const applied = await compose.network.confirmAndApply({
    operation_id: 'x10-apply-daily',
    userRef: USER,
    environmentRef: compose.env,
    mode: 'daily_single_ip',
    authorization: compose.auth(USER),
  });
  const restoreRef = applied.stages?.restore_saved?.restore_ref || applied.restore_ref;
  await compose.network.confirmAndApply({
    operation_id: 'x10-apply-claude',
    userRef: USER,
    environmentRef: compose.env,
    mode: 'claude_single_ip',
    authorization: compose.auth(USER),
  });
  const restored = await compose.network.restore({
    operation_id: 'x10-restore',
    userRef: USER,
    environmentRef: compose.env,
    restore_ref: restoreRef,
    authorization: compose.auth(USER),
  });
  assert.ok(restored.overall, '恢复旧配置必须给出结果');

  compose.clock.set('2026-10-05T00:00:00.000Z');
  const afterAll = await readQuota();
  assert.equal(afterAll.limit_bytes, baseline.limit_bytes, '换模式与恢复旧配置不得改服务端限额');
  assert.equal(afterAll.used_bytes, baseline.used_bytes, '换模式与恢复旧配置不得清用量');
  assert.equal(afterAll.status, baseline.status);
  compose.close();
});

test('X11 上游池耗尽、用户超额与后台失联三种情况分别呈现', async () => {
  const {handler, authority, store, quotaAdapter} = await createQuotaHarness('x11');
  const ids = await provisionThreeUsers(handler, {'user-jia': GB_250});

  authority.setPoolExhausted(true);
  const pool = await handleJson(handler, adminRequest('/api/admin/quota/pool'));
  assert.equal(pool.body.snapshot.exhausted, true, '上游池耗尽单独呈现');
  assert.equal(pool.body.snapshot.user_quota_sum_is_not_pool, true, '用户额度之和不等于池容量');
  const personal = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.notEqual(personal.body.snapshot.status, 'LIMITED', '池耗尽不等于用户超额');

  authority.ingestByteEvent({eventId: 'jia-over', userId: ids['user-jia'], bytes: GB_250 + 1, hop: 'metering'});
  const over = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(over.body.snapshot.status, 'LIMITED', '用户超额单独呈现');

  const original = quotaAdapter.request.bind(quotaAdapter);
  quotaAdapter.request = async () => { throw Object.assign(new Error('offline'), {code: 'AUTHORITY_UNAVAILABLE', retryable: true}); };
  const offline = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(offline.body.snapshot.stale, true, '后台失联单独呈现为陈旧快照');
  assert.notEqual(offline.body.snapshot.status, 'UNLIMITED', '失联不得被读成不限量');
  quotaAdapter.request = original;

  const opened = authority.openConnection({connectionId: 'jia-after-offline', userId: ids['user-jia'], role: 'A'});
  assert.equal(opened.allowed, false, '服务节点执行不因后台失联被绕过');
  store.close();
});
