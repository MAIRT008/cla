import assert from 'node:assert/strict';
import test from 'node:test';
import {auth, createHarness, ENV} from '../../fixtures/network/harness.mjs';

test('FD-03/A18-A24 A28-A29 超额消费与权威故障', async () => {
  const {controller, controlStore, control} = await createHarness('quota');
  controlStore.saveQuotaSnapshot({user_ref: 'user-free', status: 'LIMITED', used_bytes: 250000000000, limit_bytes: 250000000000, authority_status: 'AVAILABLE', control_status: 'AVAILABLE', node_new_limit_judgment: 'AVAILABLE', observed_at: '2026-09-13T17:00:00.000Z', proof_scope: 'simulation'});
  const daily = await controller.confirmAndApply({
    operation_id: 'quota-daily',
    userRef: 'user-free',
    environmentRef: ENV,
    mode: 'daily_single_ip',
    authorization: auth('user-free'),
  });
  await controller.updateWhitelist({userRef: 'user-free', action: 'add', payload: {input: 'keep-direct.example', match: 'exact'}});
  const dailyAgain = await controller.confirmAndApply({
    operation_id: 'quota-daily-wl',
    userRef: 'user-free',
    environmentRef: ENV,
    mode: 'daily_single_ip',
    authorization: auth('user-free'),
  });
  assert.match(dailyAgain.expected.yaml, /DOMAIN,keep-direct.example,DIRECT/);
  assert.match(dailyAgain.expected.yaml, /MATCH,REJECT/);
  assert.doesNotMatch(dailyAgain.expected.yaml, /DOMAIN-SUFFIX,claude.ai,DIRECT/);

  controlStore.saveQuotaSnapshot({user_ref: 'user-max', status: 'LIMITED', used_bytes: 1, limit_bytes: 1, authority_status: 'AVAILABLE', control_status: 'AVAILABLE', node_new_limit_judgment: 'AVAILABLE', observed_at: '2026-09-13T17:00:00.000Z', proof_scope: 'simulation'});
  const dual = await controller.confirmAndApply({
    operation_id: 'quota-dual',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  assert.doesNotMatch(dual.expected.yaml, /keep-direct\.example/);
  assert.match(dual.expected.yaml, /MATCH,REJECT/);
  assert.equal(dual.public_plan.quota.proxy_paused, true);

  control.setOffline(true);
  const offline = await controller.confirmAndApply({
    operation_id: 'quota-offline',
    userRef: 'user-pro',
    environmentRef: ENV,
    mode: 'claude_single_ip',
    authorization: auth('user-pro'),
  });
  assert.equal(['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED'].includes(offline.overall), true);
  control.setOffline(false);

  controlStore.saveQuotaSnapshot({user_ref: 'user-pro', status: 'ACTIVE', used_bytes: 1, limit_bytes: 10, authority_status: 'OFFLINE', control_status: 'AVAILABLE', node_new_limit_judgment: 'AVAILABLE', observed_at: '2026-09-13T16:00:00.000Z', proof_scope: 'simulation'});
  const stale = await controller.previewModeChange({userRef: 'user-pro', environmentRef: ENV, mode: 'claude_single_ip'});
  assert.equal(stale.plan.quota.authority_status, 'OFFLINE');
  assert.equal(stale.plan.quota.node_new_limit_judgment, 'UNAVAILABLE');
  assert.notEqual(stale.plan.quota.status, 'UNLIMITED');
  controlStore.close();
});
