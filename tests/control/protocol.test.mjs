import assert from 'node:assert/strict';
import test from 'node:test';
import {createQuotaHarness} from '../../fixtures/control/harness.mjs';
import {createRemnawaveFakeTransport, wrapTransportErrors} from '../../fixtures/control/remnawaveTransport.mjs';
import {createRemnawaveQuotaAdapter} from '../../services/control/remnawave/adapter.mjs';
import {REMNAWAVE_ROUTES} from '../../services/control/remnawave/routes.mjs';
import {loadAbProfile, renderAbTopology} from '../../services/control/topology.mjs';

test('FD-03/A27 A34 固定方法/路径/字段与错误响应', async () => {
  const calls = [];
  const harness = await createQuotaHarness('protocol');
  const inner = createRemnawaveFakeTransport(harness.authority);
  harness.quotaAdapter.fetchImpl = async (url, init) => {
    calls.push({url: String(url), method: init.method, body: init.body ? JSON.parse(init.body) : null, headers: init.headers});
    return inner(url, init);
  };

  const created = await harness.quotaAdapter.createUser({
    username: 'user_jia',
    expireAt: '2027-01-01T00:00:00.000Z',
    trafficLimitBytes: 1000,
    trafficLimitStrategy: 'MONTH',
    activeInternalSquads: ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
  });
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].url, 'https://remnawave.synthetic.invalid/api/users');
  assert.equal(calls[0].headers.Authorization, 'Bearer synthetic-provider-token');
  assert.equal(calls[0].body.username, 'user_jia');
  assert.equal(calls[0].body.trafficLimitBytes, 1000);
  assert.equal(calls[0].body.operation_id, undefined);
  assert.equal(created.http_status, 201);
  assert.equal(Number.isInteger(created.projected.id), true);
  assert.equal(created.projected.vlessUuid, undefined);

  await harness.quotaAdapter.getUser(created.projected.id);
  assert.equal(calls.at(-1).url, `https://remnawave.synthetic.invalid/api/users/${created.projected.id}`);
  await harness.quotaAdapter.updateUser({id: created.projected.id, trafficLimitBytes: 2000});
  assert.equal(calls.at(-1).method, 'PATCH');
  assert.equal(calls.at(-1).url, `https://remnawave.synthetic.invalid${REMNAWAVE_ROUTES.USERS_UPDATE.path}`);
  assert.equal(calls.at(-1).body.id, created.projected.id);
  await harness.quotaAdapter.disableUser(created.projected.id);
  assert.match(calls.at(-1).url, /\/actions\/disable$/);
  await harness.quotaAdapter.enableUser(created.projected.id);
  assert.match(calls.at(-1).url, /\/actions\/enable$/);

  const broken = wrapTransportErrors(inner, {failPath: '/api/users/999', status: 200, body: {response: {id: 999, status: 'ACTIVE'}}});
  const brokenAdapter = (await import('../../services/control/remnawave/adapter.mjs')).createRemnawaveQuotaAdapter({
    baseUrl: 'https://remnawave.synthetic.invalid',
    token: harness.authority.token,
    fetchImpl: broken,
  });
  await assert.rejects(() => brokenAdapter.getUser(999), {code: 'INVALID_RESPONSE'});

  const unauthorized = (await import('../../services/control/remnawave/adapter.mjs')).createRemnawaveQuotaAdapter({
    baseUrl: 'https://remnawave.synthetic.invalid',
    token: 'wrong',
    fetchImpl: inner,
  });
  await assert.rejects(() => unauthorized.getUser(created.projected.id), {code: 'AUTHORITY_UNAUTHORIZED'});

  const missing = wrapTransportErrors(inner, {failPath: '/api/users/404', status: 404, body: {message: 'User not found', errorCode: 'A025'}});
  const missingAdapter = (await import('../../services/control/remnawave/adapter.mjs')).createRemnawaveQuotaAdapter({
    baseUrl: 'https://remnawave.synthetic.invalid',
    token: harness.authority.token,
    fetchImpl: missing,
  });
  await assert.rejects(() => missingAdapter.getUser(404), {code: 'AUTHORITY_NOT_FOUND'});

  for (const [status, code, path] of [
    [403, 'AUTHORITY_FORBIDDEN', '/api/users/403'],
    [409, 'AUTHORITY_CONFLICT', '/api/users/409'],
    [429, 'AUTHORITY_RATE_LIMITED', '/api/users/429'],
    [503, 'AUTHORITY_UNAVAILABLE', '/api/users/503'],
  ]) {
    const failing = wrapTransportErrors(inner, {failPath: path, status, body: {message: 'mapped', errorCode: `E${status}`}});
    const mapped = (await import('../../services/control/remnawave/adapter.mjs')).createRemnawaveQuotaAdapter({
      baseUrl: 'https://remnawave.synthetic.invalid',
      token: harness.authority.token,
      fetchImpl: failing,
    });
    await assert.rejects(() => mapped.getUser(Number(path.split('/').at(-1))), {code});
  }

  await assert.rejects(() => harness.quotaAdapter.createUser({
    username: 'user_jia',
    expireAt: '2027-01-01T00:00:00.000Z',
    trafficLimitBytes: 1000,
    trafficLimitStrategy: 'MONTH',
  }), {code: 'AUTHORITY_CONFLICT'});

  const timed = createRemnawaveQuotaAdapter({
    baseUrl: 'https://remnawave.synthetic.invalid',
    token: harness.authority.token,
    timeoutMs: 40,
    fetchImpl: () => new Promise(() => {}),
  });
  await assert.rejects(() => timed.getUser(created.projected.id), {code: 'AUTHORITY_TIMEOUT'});

  const cancelled = new AbortController();
  cancelled.abort();
  const cancelAdapter = createRemnawaveQuotaAdapter({
    baseUrl: 'https://remnawave.synthetic.invalid',
    token: harness.authority.token,
    timeoutMs: 1000,
    fetchImpl: inner,
  });
  await assert.rejects(
    () => cancelAdapter.request(
      {method: 'GET', path: `/api/users/${created.projected.id}`, success: 200},
      {path: `/api/users/${created.projected.id}`, signal: cancelled.signal},
    ),
    (error) => error.code === 'AUTHORITY_CANCELLED' && error.retryable === false,
  );

  const hangingBody = createRemnawaveQuotaAdapter({
    baseUrl: 'https://remnawave.synthetic.invalid',
    token: harness.authority.token,
    timeoutMs: 30,
    fetchImpl: async () => ({status: 200, text: () => new Promise(() => {})}),
  });
  let hangingState = 'STILL_PENDING';
  const hanging = hangingBody.getUser(created.projected.id).then(
    () => { hangingState = 'RESOLVED'; },
    (error) => { hangingState = error.code; },
  );
  await new Promise((resolve) => setTimeout(resolve, 120));
  assert.notEqual(hangingState, 'STILL_PENDING');
  assert.equal(hangingState, 'AUTHORITY_TIMEOUT');
  await hanging;

  const profile = loadAbProfile();
  const topology = renderAbTopology({profile, providerUserId: created.projected.id, vlessUuid: created.user.vlessUuid});
  assert.equal(topology.ok, true);
  assert.equal(topology.same_authority_identity, true);
  assert.equal(topology.metering_point.includes('UserTraffic'), true);
  assert.equal(topology.rendered_inbounds[0].clients[0].email, String(created.projected.id));
  assert.equal(topology.udp, 'BLOCK');
  harness.store.close();
});
