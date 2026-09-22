import assert from 'node:assert/strict';
import test from 'node:test';
import {auth, createHarness, ENV} from '../../fixtures/network/harness.mjs';

test('FD-04/F22 RUNTIME §2 手动应急', async () => {
  const {controller, controlStore, emergencyHost} = await createHarness('emergency');
  const assignment = (await controller.getAssignment('user-max', ENV)).assignment;
  await assert.rejects(() => controller.requestEmergency({
    user_ref: 'user-max',
    environment_ref: ENV,
    assignment,
    mode: 'claude_dual_ip',
    confirmation: {confirmed: false},
  }), {code: 'EMERGENCY_NOT_CONFIRMED'});

  await assert.rejects(() => controller.requestEmergency({
    user_ref: 'user-max',
    environment_ref: ENV,
    assignment,
    mode: 'claude_dual_ip',
    confirmation: {confirmed: true, confirmation_id: 'em-1'},
    candidates: [{id: 'webview-shared', kind: 'shared_webview', distinguishable: false, process: 'msedgewebview2.exe', approved: true}],
    allow_shared_webview: true,
  }), {code: 'EMERGENCY_WEBVIEW_DENIED'});

  const opened = await controller.requestEmergency({
    user_ref: 'user-max',
    environment_ref: ENV,
    assignment,
    mode: 'claude_dual_ip',
    confirmation: {confirmed: true, confirmation_id: 'em-2'},
    purpose: 'temporary_web_access',
    targets: [{host: 'news.example'}, {host: 'api.anthropic.com'}],
    duration_minutes: 15,
    operation_id: 'em-open',
  });
  assert.equal(opened.process, 'firefox.exe');
  assert.equal(opened.claude_protected, true);
  assert.equal(opened.duration_is_release_value, false);
  assert.equal(opened.mainline_rechecked, false);
  const yaml = (await controller.readState({userRef: 'user-max', environmentRef: ENV})).expected;
  const apply = await controller.readState({userRef: 'user-max', environmentRef: ENV});
  assert.ok(apply.expected.yaml === undefined);
  const last = controlStore.getApplyReceipt('em-open') || opened;
  const sessionApply = opened.apply_overall;
  assert.ok(['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED', 'FAILED'].includes(sessionApply));

  controlStore.saveQuotaSnapshot({user_ref: 'user-max', status: 'LIMITED', used_bytes: 9, limit_bytes: 9, authority_status: 'AVAILABLE', control_status: 'AVAILABLE', observed_at: '2026-09-13T17:00:00.000Z', proof_scope: 'simulation'});
  const supportOnly = await controller.requestEmergency({
    user_ref: 'user-max',
    environment_ref: ENV,
    assignment,
    mode: 'claude_dual_ip',
    confirmation: {confirmed: true, confirmation_id: 'em-3'},
    targets: [{host: 'news.example'}],
    template: assignment.template,
    quotaSnapshot: controlStore.getQuotaSnapshot('user-max'),
    operation_id: 'em-limited',
  });
  assert.equal(supportOnly.general_emergency, 'INCOMPLETE');
  assert.equal(supportOnly.quota_limited, true);
  assert.ok(supportOnly.targets.every((item) => item.host === 'support.steward.test'));

  emergencyHost.inject({closeFail: true});
  const closeFail = await controller.endEmergency({
    session_id: opened.session_id,
    assignment,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  assert.equal(closeFail.visible_error, 'EMERGENCY_CLOSE_FAILED');
  assert.equal(closeFail.mainline_rechecked, false);

  emergencyHost.inject({closeFail: false});
  const ended = await controller.endEmergency({
    session_id: opened.session_id,
    assignment,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
    operation_id: 'em-end',
  });
  assert.equal(ended.mainline_restored_claim, false);
  controlStore.close();
});
