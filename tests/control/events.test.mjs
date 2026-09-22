import assert from 'node:assert/strict';
import test from 'node:test';
import {adminRequest, createQuotaHarness, handleJson} from '../../fixtures/control/harness.mjs';

test('FD-03/A32-A33 FD-04/A20 最小事件隔离、幂等与秘密拒绝', async () => {
  const {handler, store} = await createQuotaHarness('events');
  const first = await handleJson(handler, adminRequest('/api/network/events', {
    token: 'token-jia',
    method: 'POST',
    body: {event_ref: 'evt-1', kind: 'WRONG_ROUTE', classification: 'WRONG_ROUTE', count: 1, first_at: '2026-09-13T17:00:00.000Z', last_at: '2026-09-13T17:00:00.000Z', protection_status: 'ACCEPTED'},
  }));
  assert.equal(first.status, 200);
  const dup = await handleJson(handler, adminRequest('/api/network/events', {
    token: 'token-jia',
    method: 'POST',
    body: {event_ref: 'evt-1', kind: 'WRONG_ROUTE', count: 3, last_at: '2026-09-13T18:00:00.000Z', protection_status: 'CONFIRMED'},
  }));
  assert.equal(dup.body.duplicate, true);
  const listed = await handleJson(handler, adminRequest('/api/network/events', {token: 'token-jia'}));
  assert.equal(listed.body.events.length, 1);
  assert.equal(listed.body.events[0].count, 3);
  assert.equal(listed.body.events[0].first_at, '2026-09-13T17:00:00.000Z');
  assert.equal(listed.body.events[0].protection_status, 'CONFIRMED');

  const other = await handleJson(handler, adminRequest('/api/network/events', {token: 'token-yi'}));
  assert.equal(other.body.events.length, 0);
  const steal = await handleJson(handler, adminRequest('/api/network/events', {
    token: 'token-yi',
    method: 'POST',
    body: {event_ref: 'evt-1', user_ref: 'user-jia', kind: 'WRONG_ROUTE'},
  }));
  assert.equal(steal.status, 403);

  const secret = await handleJson(handler, adminRequest('/api/network/events', {
    token: 'token-jia',
    method: 'POST',
    body: {event_ref: 'evt-secret', vlessUuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'},
  }));
  assert.equal(secret.status, 400);
  assert.equal(secret.body.code, 'EVENT_SECRET_REJECTED');

  const lateReceipt = store.getEventReceipt('evt-1');
  assert.equal(lateReceipt.status, 'ACCEPTED');
  store.saveEventReceipt({event_ref: 'evt-1', user_ref: 'user-jia', status: 'PENDING', accepted: false, received_at: '2026-09-13T16:00:00.000Z'});
  await handleJson(handler, adminRequest('/api/network/events', {
    token: 'token-jia',
    method: 'POST',
    body: {event_ref: 'evt-1', count: 4, last_at: '2026-09-13T19:00:00.000Z', protection_status: 'ACCEPTED'},
  }));
  assert.equal(store.getNetworkEvent('evt-1').protection_status, 'CONFIRMED');
  assert.equal(store.getEventReceipt('evt-1').status, 'ACCEPTED');
  store.close();
});

test('FD-03/A08 A25 模板更新不覆盖分配，敏感 A 变更需确认', async () => {
  const {handler, store} = await createQuotaHarness('publish');
  const resource = {resource_id: 'res-a', role: 'A', host: 'a.example.invalid', port: 1080, sharing: 'shared', status: 'ACTIVE'};
  const resourceB = {resource_id: 'res-b', role: 'B', host: 'b.example.invalid', port: 1080, sharing: 'shared', status: 'ACTIVE'};
  await handleJson(handler, adminRequest('/api/admin/resources', {method: 'PUT', body: resource}));
  await handleJson(handler, adminRequest('/api/admin/resources', {method: 'PUT', body: resourceB}));
  await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {
    template_id: 'managed',
    published: true,
    template: {version: 'template-v1', claude_domains: ['claude.ai'], claude_processes: ['claude.exe'], managed_browser_processes: [], protected_process_paths: ['C:\\Claude\\claude.exe'], lan_cidrs: [], control_plane: {}, udp_policy: 'REJECT', ipv6_policy: 'FOLLOW', dns: {nameserver: ['https://dns.steward.test/dns-query']}},
  }}));
  await handleJson(handler, adminRequest('/api/admin/assignments', {method: 'POST', body: {
    userRef: 'user-jia',
    environmentRef: 'synthetic-windows',
    accountClass: 'free',
    allowedModes: ['daily_single_ip'],
    resources: [resource],
    roles: {A: 'res-a'},
    validUntil: '2027-01-01T00:00:00.000Z',
    templateId: 'managed',
  }}));
  const first = await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: 'user-jia'}}));
  assert.equal(first.body.ok, true);
  await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {
    template_id: 'managed',
    published: true,
    template: {version: 'template-v2', claude_domains: ['claude.ai'], claude_processes: ['claude.exe'], managed_browser_processes: [], protected_process_paths: ['C:\\Claude\\claude.exe'], lan_cidrs: [], control_plane: {}, udp_policy: 'REJECT', ipv6_policy: 'FOLLOW', dns: {nameserver: ['https://dns.steward.test/dns-query']}},
  }}));
  assert.equal(store.getAssignment('user-jia').template.version, 'template-v1');

  await handleJson(handler, adminRequest('/api/admin/assignments', {method: 'POST', body: {
    userRef: 'user-jia',
    environmentRef: 'synthetic-windows',
    accountClass: 'free',
    allowedModes: ['daily_single_ip'],
    resources: [{...resource, host: 'a-new.example.invalid'}],
    roles: {A: 'res-a'},
    validUntil: '2027-01-01T00:00:00.000Z',
    templateId: 'managed',
  }}));
  const sensitive = await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: 'user-jia'}}));
  assert.equal(sensitive.body.code, 'SENSITIVE_CHANGE_CONFIRMATION_REQUIRED');
  const confirmed = await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: 'user-jia', confirmation: {confirmed: true}}}));
  assert.equal(confirmed.body.ok, true);
  store.close();
});

test('订阅刷新解析 Clash YAML，未知格式不冒充完成', async () => {
  const {handler, store} = await createQuotaHarness('subscription');
  store.saveSubscriptionSource({source_id: 'src-1', format: 'clash-yaml', status: 'PENDING'});
  const refresh = await handleJson(handler, adminRequest('/api/admin/subscriptions/refresh', {
    method: 'POST',
    body: {source_id: 'src-1', body: 'proxies:\n  - {name: a, type: socks5, server: a.example.invalid, port: 1080}\n'},
  }));
  assert.equal(refresh.body.ok, true, JSON.stringify(refresh.body));
  assert.equal(refresh.body.source.proxy_count, 1);
  store.saveSubscriptionSource({source_id: 'src-2', format: 'unknown-binary', status: 'PENDING'});
  const unsupported = await handleJson(handler, adminRequest('/api/admin/subscriptions/refresh', {
    method: 'POST',
    body: {source_id: 'src-2', body: 'not-yaml'},
  }));
  assert.equal(unsupported.body.code, 'UNSUPPORTED');
  store.close();
});
