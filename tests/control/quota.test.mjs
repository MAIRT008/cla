import assert from 'node:assert/strict';
import test from 'node:test';
import {adminRequest, createQuotaHarness, GB_250, handleJson, threeUserResources} from '../../fixtures/control/harness.mjs';
import {openControlStore} from '../../services/control/index.mjs';
import {applyQuotaOperation, readQuotaView} from '../../src/core/network/quota.mjs';
import {auth} from '../../fixtures/network/harness.mjs';

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
    assert.equal(allocated.status, 200, JSON.stringify(allocated.body));
    ids[user.userRef] = allocated.body.binding.provider_user_id;
  }
  return ids;
}

test('FD-03/A14-A21 单点计量、硬限额替身与超额暂停', async () => {
  const {handler, authority, controller, store} = await createQuotaHarness('hard-limit');
  const ids = await provision(handler, {'user-jia': 1000});
  const jia = ids['user-jia'];
  const yi = ids['user-yi'];

  const first = authority.ingestByteEvent({eventId: 'flow-1', userId: jia, bytes: 400, hop: 'admission'});
  const front = authority.ingestByteEvent({eventId: 'flow-1-front', userId: jia, bytes: 400, hop: 'front'});
  const dup = authority.ingestByteEvent({eventId: 'flow-1', userId: jia, bytes: 400, hop: 'admission'});
  const direct = authority.ingestByteEvent({eventId: 'lan-1', userId: jia, bytes: 9000, hop: 'admission', isDirect: true});
  assert.equal(first.counted, true);
  assert.equal(front.counted, false);
  assert.equal(dup.counted, false);
  assert.equal(direct.counted, false);

  authority.ingestByteEvent({eventId: 'flow-2', userId: jia, bytes: 600, hop: 'admission', role: 'A'});
  assert.equal(authority.user(jia).status, 'LIMITED');
  const denied = authority.openConnection({connectionId: 'c-new', userId: jia, role: 'A'});
  assert.equal(denied.allowed, false);
  const other = authority.openConnection({connectionId: 'c-yi', userId: yi, role: 'A'});
  assert.equal(other.allowed, true);

  const usage = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(usage.body.snapshot.status, 'LIMITED');
  assert.equal(usage.body.snapshot.used_bytes, 1000);
  assert.equal(usage.body.snapshot.upload_bytes.status, 'UNKNOWN');
  assert.equal(usage.body.snapshot.measured_at, null);

  const applied = await controller.confirmAndApply({
    operation_id: 'jia-limited',
    userRef: 'user-jia',
    environmentRef: 'synthetic-windows',
    mode: 'daily_single_ip',
    authorization: auth('user-jia'),
  });
  assert.equal(applied.public_plan.quota.proxy_paused, true);
  assert.match(applied.expected.yaml, /MATCH,REJECT/);
  assert.equal(applyQuotaOperation(usage.body.snapshot).no_borrow, true);

  const yiUsage = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-yi'));
  assert.equal(yiUsage.body.snapshot.status, 'ACTIVE');
  store.close();
});

test('FD-03/A18 A23 A29 客户端重建、改时钟和应用库重开不清权威账', async () => {
  const harness = await createQuotaHarness('continuity');
  const ids = await provision(harness.handler, {'user-jia': 5000});
  harness.authority.ingestByteEvent({eventId: 'keep-1', userId: ids['user-jia'], bytes: 2000, hop: 'admission'});
  await handleJson(harness.handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  const before = harness.authority.user(ids['user-jia']).usedTrafficBytes;
  harness.clock.set('1999-01-01T00:00:00.000Z');
  const path = harness.store.databasePath;
  harness.store.close();
  const reopened = openControlStore({databasePath: path, users: [{user_ref: 'user-jia', status: 'ACTIVE'}], sessions: []});
  assert.equal(reopened.getQuotaSnapshot('user-jia').used_bytes, 2000);
  assert.equal(harness.authority.user(ids['user-jia']).usedTrafficBytes, before);
  assert.notEqual(reopened.getQuotaSnapshot('user-jia').status, 'UNKNOWN');
  reopened.close();
});

test('FD-03/A22-A24 池耗尽、调额恢复原 A/B、查询失败保留快照', async () => {
  const {handler, authority, store, quotaAdapter} = await createQuotaHarness('recovery');
  const ids = await provision(handler);
  authority.setPoolExhausted(true);
  const pool = await handleJson(handler, adminRequest('/api/admin/quota/pool'));
  assert.equal(pool.body.snapshot.exhausted, true);
  assert.equal(pool.body.snapshot.shared_subscription_balance.status, 'UNKNOWN');
  assert.equal(pool.body.snapshot.user_quota_sum_is_not_pool, true);
  const jia = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.notEqual(jia.body.snapshot.status, 'LIMITED');

  authority.ingestByteEvent({eventId: 'jia-cap', userId: ids['user-jia'], bytes: GB_250, hop: 'admission'});
  await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  const raised = await handleJson(handler, adminRequest('/api/admin/quota/limit', {method: 'POST', body: {userRef: 'user-jia', operation_id: 'raise-jia', limitBytes: GB_250 * 2}}));
  assert.equal(raised.body.effective, true);
  const resumed = await handleJson(handler, adminRequest('/api/admin/quota/resume', {method: 'POST', body: {userRef: 'user-jia', operation_id: 'resume-jia'}}));
  assert.equal(resumed.status, 200, JSON.stringify(resumed.body));
  assert.equal(resumed.body.restored_roles.A, 'res-a-jia');

  const originalFetch = quotaAdapter.request.bind(quotaAdapter);
  quotaAdapter.request = async () => {
    throw Object.assign(new Error('timeout'), {code: 'AUTHORITY_UNAVAILABLE', retryable: true});
  };
  const stale = await handleJson(handler, adminRequest('/api/admin/quota/usage?user_ref=user-jia'));
  assert.equal(stale.body.snapshot.stale, true);
  assert.notEqual(stale.body.snapshot.used_bytes, 0);
  assert.notEqual(stale.body.snapshot.status, 'UNLIMITED');
  quotaAdapter.request = originalFetch;
  store.close();
});

test('FD-03/A32 同一 operation 重试不多建用户，产品拒绝无限额', async () => {
  const {handler, authority, store} = await createQuotaHarness('idempotent');
  const catalog = threeUserResources();
  await handleJson(handler, adminRequest('/api/admin/resources', {method: 'PUT', body: catalog.resources[1]}));
  const first = await handleJson(handler, adminRequest('/api/admin/quota/allocate', {method: 'POST', body: {
    userRef: 'user-jia', operation_id: 'same-op', limitBytes: 1000, period: 'MONTH', expireAt: '2027-01-01T00:00:00.000Z',
  }}));
  const second = await handleJson(handler, adminRequest('/api/admin/quota/allocate', {method: 'POST', body: {
    userRef: 'user-jia', operation_id: 'same-op', limitBytes: 1000, period: 'MONTH', expireAt: '2027-01-01T00:00:00.000Z',
  }}));
  assert.equal(second.body.replayed, true);
  assert.equal(first.body.binding.provider_user_id, second.body.binding.provider_user_id);
  assert.equal(authority.state.users.size, 1);
  const unlimited = await handleJson(handler, adminRequest('/api/admin/quota/allocate', {method: 'POST', body: {
    userRef: 'user-yi', operation_id: 'zero', limitBytes: 0, period: 'MONTH', expireAt: '2027-01-01T00:00:00.000Z',
  }}));
  assert.equal(unlimited.status, 400);
  assert.equal(unlimited.body.code, 'LIMIT_REQUIRED');
  const view = readQuotaView(first.body.snapshot);
  assert.equal(view.unlimited, false);
  store.close();
});
