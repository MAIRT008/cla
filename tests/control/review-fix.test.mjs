import assert from 'node:assert/strict';
import test from 'node:test';
import {adminRequest, createQuotaHarness, handleJson, threeUserResources} from '../../fixtures/control/harness.mjs';
import {createHttpControlPort} from '../../src/adapters/network/controlClient.mjs';
import {providerUsername} from '../../services/control/remnawave/routes.mjs';
import {createRemnawaveQuotaAdapter} from '../../services/control/remnawave/adapter.mjs';
import {createRemnawaveFakeTransport, wrapTransportErrors} from '../../fixtures/control/remnawaveTransport.mjs';

const YAML = 'proxies:\n  - {name: a, type: socks5, server: a.example.invalid, port: 1080}\n';

async function seedUser(handler, userRef, {limitBytes = 1000, validUntil = '2027-01-01T00:00:00.000Z'} = {}) {
  const catalog = threeUserResources();
  const resources = catalog.resources.filter((item) => item.role === 'front' || item.resource_id === 'res-a-jia');
  for (const item of catalog.resources) await handleJson(handler, adminRequest('/api/admin/resources', {method: 'PUT', body: item}));
  await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {template_id: 'managed', published: true, template: catalog.template}}));
  await handleJson(handler, adminRequest('/api/admin/assignments', {method: 'POST', body: {
    userRef,
    environmentRef: 'synthetic-windows',
    accountClass: 'free',
    allowedModes: ['daily_single_ip'],
    resources,
    roles: {A: 'res-a-jia'},
    validUntil,
    templateId: 'managed',
  }}));
  await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef, environmentRef: 'synthetic-windows'}}));
  const allocated = await handleJson(handler, adminRequest('/api/admin/quota/allocate', {method: 'POST', body: {
    userRef,
    operation_id: `alloc-${userRef}`,
    limitBytes,
    period: 'MONTH',
    expireAt: '2027-01-01T00:00:00.000Z',
  }}));
  assert.equal(allocated.status, 200, JSON.stringify(allocated.body));
  return allocated.body;
}

test('BLOCK 不同应用用户不能落到同一 provider 身份', async () => {
  assert.notEqual(providerUsername('tenant.a'), providerUsername('tenant/a'));
  const {handler, authority, store} = await createQuotaHarness('identity', {
    users: [
      {user_ref: 'tenant.a', status: 'ACTIVE'},
      {user_ref: 'tenant/a', status: 'ACTIVE'},
      {user_ref: 'user-admin', status: 'ACTIVE', role: 'admin'},
    ],
    sessions: [
      {session_ref: 's-a', user_ref: 'tenant.a', token: 'token-a', expires_at: '2030-01-01T00:00:00.000Z'},
      {session_ref: 's-b', user_ref: 'tenant/a', token: 'token-b', expires_at: '2030-01-01T00:00:00.000Z'},
      {session_ref: 's-admin', user_ref: 'user-admin', token: 'token-admin', expires_at: '2030-01-01T00:00:00.000Z'},
    ],
  });
  const first = await seedUser(handler, 'tenant.a');
  const second = await seedUser(handler, 'tenant/a');
  assert.notEqual(first.binding.provider_user_id, second.binding.provider_user_id);
  assert.equal(authority.state.users.size, 2);
  assert.throws(
    () => store.saveProviderBinding({user_ref: 'other', provider_user_id: first.binding.provider_user_id, username: 'x'}),
    {code: 'PROVIDER_IDENTITY_CONFLICT'},
  );
  store.close();
});

test('MAJOR 权威未配置时保留最后快照并标 STALE/OFFLINE', async () => {
  const {handler, quotaAdapter, store} = await createQuotaHarness('stale-authority');
  await seedUser(handler, 'user-jia');
  const live = await handleJson(handler, adminRequest('/api/network/quota', {token: 'token-jia'}));
  assert.equal(live.body.quota.status, 'ACTIVE');
  assert.equal(live.body.quota.authority_status, 'AVAILABLE');
  assert.equal(live.body.quota.stale, false);
  quotaAdapter.token = null;
  const stale = await handleJson(handler, adminRequest('/api/network/quota', {token: 'token-jia'}));
  assert.equal(stale.body.quota.status, 'ACTIVE');
  assert.equal(stale.body.quota.authority_status, 'OFFLINE');
  assert.equal(stale.body.quota.stale, true);
  assert.equal(stale.body.quota.node_new_limit_judgment, 'UNAVAILABLE');
  assert.equal(stale.body.code, 'AUTHORITY_UNCONFIGURED');
  store.close();
});

test('MAJOR HTTP client 离线保留刚读到的 Assignment 和 Quota', async () => {
  const {handler, store} = await createQuotaHarness('http-cache');
  await seedUser(handler, 'user-jia');
  const port = createHttpControlPort({handler, sessionToken: 'token-jia'});
  const online = await port.getAssignment('user-jia');
  const quota = await port.getQuotaSnapshot('user-jia');
  assert.equal(online.assignment.user_ref, 'user-jia');
  assert.equal(quota.snapshot.status, 'ACTIVE');
  port.setOffline(true);
  const cachedAssignment = await port.getAssignment('user-jia');
  const cachedQuota = await port.getQuotaSnapshot('user-jia');
  assert.equal(cachedAssignment.code, 'CONTROL_OFFLINE');
  assert.equal(cachedAssignment.used_cached, true);
  assert.equal(cachedAssignment.assignment.user_ref, 'user-jia');
  assert.equal(cachedQuota.used_cached, true);
  assert.equal(cachedQuota.snapshot.status, 'ACTIVE');
  assert.equal(cachedQuota.snapshot.control_status, 'OFFLINE');
  assert.equal(cachedQuota.snapshot.stale, true);
  store.close();
});

test('MAJOR 停用效果不可由调用者伪造，过期 Assignment 不能恢复', async () => {
  const {handler, store} = await createQuotaHarness('suspend-resume');
  await seedUser(handler, 'user-jia');
  const suspended = await handleJson(handler, adminRequest('/api/admin/quota/suspend', {method: 'POST', body: {
    userRef: 'user-jia',
    operation_id: 'suspend-jia',
    nodeEffect: {accepted: true, verified_disconnect: 'VERIFIED', in_flight: 'CLOSED'},
  }}));
  assert.equal(suspended.status, 200, JSON.stringify(suspended.body));
  assert.equal(suspended.body.node_effect.accepted, false);
  assert.equal(suspended.body.node_effect.verified_disconnect, 'UNKNOWN');
  assert.equal(store.getQuotaSnapshot('user-jia').node_remove.verified_disconnect, 'UNKNOWN');

  const assignment = store.getAssignment('user-jia');
  store.saveAssignment({...assignment, valid_until: '2026-09-12T00:00:00.000Z'});
  const resumed = await handleJson(handler, adminRequest('/api/admin/quota/resume', {method: 'POST', body: {userRef: 'user-jia', operation_id: 'resume-expired'}}));
  assert.notEqual(resumed.status, 200);
  assert.equal(resumed.body.code, 'ASSIGNMENT_EXPIRED');
  store.close();
});

test('MAJOR 丢失 disable 响应后同 operation 不二次执行', async () => {
  const {handler, quotaAdapter, store} = await createQuotaHarness('disable-replay');
  await seedUser(handler, 'user-jia');
  const inner = quotaAdapter.fetchImpl.bind(quotaAdapter);
  let disableCalls = 0;
  quotaAdapter.fetchImpl = async (url, init) => {
    if (String(url).includes('/actions/disable')) {
      disableCalls += 1;
      await inner(url, init);
      throw new Error('lost response');
    }
    return inner(url, init);
  };
  const first = await handleJson(handler, adminRequest('/api/admin/quota/suspend', {method: 'POST', body: {userRef: 'user-jia', operation_id: 'suspend-lost'}}));
  assert.equal(first.status, 503);
  quotaAdapter.fetchImpl = async (url, init) => {
    if (String(url).includes('/actions/disable')) {
      disableCalls += 1;
      return inner(url, init);
    }
    return inner(url, init);
  };
  const retry = await handleJson(handler, adminRequest('/api/admin/quota/suspend', {method: 'POST', body: {userRef: 'user-jia', operation_id: 'suspend-lost'}}));
  assert.equal(retry.status, 200, JSON.stringify(retry.body));
  assert.equal(retry.body.replayed, true);
  assert.equal(retry.body.snapshot.status, 'DISABLED');
  assert.equal(disableCalls, 1);
  store.close();
});

test('MAJOR 订阅来源可创建，HTTP 失败不能标 ACTIVE', async () => {
  const yamlBody = YAML;
  const {handler, store} = await createQuotaHarness('subscription-http', {
    subscriptionFetch: async () => ({
      status: 503,
      text: async () => yamlBody,
      headers: {get: () => 'application/x-yaml'},
    }),
  });
  const created = await handleJson(handler, adminRequest('/api/admin/subscriptions', {method: 'PUT', body: {
    source_id: 'src-up',
    format: 'clash-yaml',
    url_ref: 'https://subscription.synthetic.invalid/clash.yaml',
  }}));
  assert.equal(created.status, 200, JSON.stringify(created.body));
  assert.equal(created.body.source.source_id, 'src-up');
  const listed = await handleJson(handler, adminRequest('/api/admin/subscriptions'));
  assert.equal(listed.body.sources.some((item) => item.source_id === 'src-up'), true);
  const refresh = await handleJson(handler, adminRequest('/api/admin/subscriptions/refresh', {method: 'POST', body: {source_id: 'src-up'}}));
  assert.equal(refresh.body.ok, false);
  assert.equal(refresh.body.code, 'SOURCE_FETCH_FAILED');
  assert.equal(refresh.body.http_status, 503);
  assert.equal(refresh.body.source.status, 'FAILED');
  store.close();
});

test('MAJOR deadline 覆盖 response.text，调用者取消不是可重试超时', async () => {
  const hanging = createRemnawaveQuotaAdapter({
    baseUrl: 'https://remnawave.synthetic.invalid',
    token: 'synthetic-provider-token',
    timeoutMs: 30,
    fetchImpl: async () => ({status: 200, text: () => new Promise(() => {})}),
  });
  let hangingState = 'STILL_PENDING';
  const pending = hanging.getUser(101).then(
    () => { hangingState = 'RESOLVED'; },
    (error) => { hangingState = error.code; },
  );
  await new Promise((resolve) => setTimeout(resolve, 120));
  assert.notEqual(hangingState, 'STILL_PENDING');
  assert.equal(hangingState, 'AUTHORITY_TIMEOUT');
  await pending;

  const cancelled = new AbortController();
  cancelled.abort();
  const cancelAdapter = createRemnawaveQuotaAdapter({
    baseUrl: 'https://remnawave.synthetic.invalid',
    token: 'synthetic-provider-token',
    timeoutMs: 1000,
    fetchImpl: async () => ({status: 200, text: async () => '{"response":{}}'}),
  });
  await assert.rejects(
    () => cancelAdapter.request(
      {method: 'GET', path: '/api/users/101', success: 200},
      {path: '/api/users/101', signal: cancelled.signal},
    ),
    (error) => error.code === 'AUTHORITY_CANCELLED' && error.retryable === false,
  );
});
