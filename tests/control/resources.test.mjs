import assert from 'node:assert/strict';
import test from 'node:test';
import {adminRequest, createQuotaHarness, handleJson, threeUserResources} from '../../fixtures/control/harness.mjs';
import {validateAssignment} from '../../src/core/network/assignment.mjs';

test('FD-03/A01-A03 A33 三用户资源隔离、未分配与无 B 不能发布双 IP', async () => {
  const {handler, store} = await createQuotaHarness('resources');
  const catalog = threeUserResources();
  for (const item of catalog.resources) {
    const saved = await handleJson(handler, adminRequest('/api/admin/resources', {method: 'PUT', body: item}));
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
  }
  const template = await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {template_id: 'managed', published: true, template: catalog.template}}));
  assert.equal(template.status, 200);

  for (const user of catalog.users) {
    const allocated = await handleJson(handler, adminRequest('/api/admin/assignments', {method: 'POST', body: {
      userRef: user.userRef,
      environmentRef: 'synthetic-windows',
      accountClass: user.accountClass,
      allowedModes: user.allowedModes,
      resources: user.resources,
      roles: user.roles,
      validUntil: '2027-01-01T00:00:00.000Z',
      templateId: 'managed',
    }}));
    assert.equal(allocated.status, 200, JSON.stringify(allocated.body));
    const published = await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: user.userRef, environmentRef: 'synthetic-windows'}}));
    if (user.userRef === 'user-yi') {
      assert.equal(published.body.ok, false);
      assert.equal(published.body.ready, false);
      assert.equal(published.body.validation.issues.includes('DUAL_IP_REQUIRES_B'), true);
    } else {
      assert.equal(published.body.ok, true, JSON.stringify(published.body));
    }
  }

  const yiSeesJia = await handleJson(handler, adminRequest('/api/network/assignment', {token: 'token-jia'}));
  assert.equal(yiSeesJia.body.assignment.user_ref, 'user-jia');
  const other = await handleJson(handler, adminRequest('/api/admin/resources', {token: 'token-jia'}));
  assert.equal(other.status, 403);
  const forged = await handleJson(handler, adminRequest('/api/admin/quota/limit', {token: 'token-yi', method: 'POST', body: {userRef: 'user-jia', operation_id: 'steal', limitBytes: 1}}));
  assert.equal(forged.status, 403);

  const missing = validateAssignment(null, {environment_ref: 'synthetic-windows'}, '2026-09-13T17:00:00.000Z');
  assert.equal(missing.ok, false);
  store.close();
});
