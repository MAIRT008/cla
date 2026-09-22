import assert from 'node:assert/strict';
import test from 'node:test';
import {auth, createHarness, ENV} from '../../fixtures/network/harness.mjs';

test('FD-03/A12-A13 A25-A29 A31 应用、回读、恢复与重试', async () => {
  const harness = await createHarness('apply');
  const {controller, core, controlStore} = harness;
  const first = await controller.confirmAndApply({
    operation_id: 'op-apply-1',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  assert.equal(first.stages.loaded.status, 'HTTP_ACCEPTED');
  assert.equal(first.applied.http_status, 204);
  assert.equal(first.loaded.loaded_version, null);
  assert.equal(first.overall, 'APPLIED_VERIFIED');
  const replay = await controller.confirmAndApply({
    operation_id: 'op-apply-1',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  assert.equal(replay.expected.mode, 'claude_dual_ip');
  assert.equal(core.loadedPayload().includes('PROXY-B'), true);

  core.inject({loadFail: true});
  const failedLoad = await controller.confirmAndApply({
    operation_id: 'op-load-fail',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_single_ip',
    authorization: auth('user-max'),
  });
  assert.equal(failedLoad.overall, 'FAILED');
  assert.equal(failedLoad.code, 'LOAD_FAILED');
  assert.equal(failedLoad.restore.status, 'RESTORED');
  core.inject({loadFail: false});

  core.inject({oldRulesYaml: 'mode: rule\nrules:\n  - MATCH,DIRECT\n'});
  const oldRules = await controller.confirmAndApply({
    operation_id: 'op-old-rules',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'daily_single_ip',
    authorization: auth('user-max'),
  });
  assert.equal(oldRules.code, 'READBACK_MISMATCH');
  assert.ok(oldRules.loaded.inconsistencies.includes('RULES_MISMATCH'));
  core.inject({oldRulesYaml: null});

  harness.verify.inject({failAll: true});
  const badPath = await controller.confirmAndApply({
    operation_id: 'op-path-fail',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'daily_single_ip',
    authorization: auth('user-max'),
  });
  assert.equal(badPath.code, 'VERIFY_FAILED');
  harness.verify.inject({failAll: false});

  const expired = await controller.confirmAndApply({
    operation_id: 'op-auth-expired',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'daily_single_ip',
    authorization: auth('user-max', {expires_at: '2026-09-01T00:00:00.000Z'}),
  });
  assert.equal(expired.code, 'AUTHORIZATION_EXPIRED');

  const assignment = structuredClone((await controller.getAssignment('user-max', ENV)).assignment);
  assignment.status = 'REVOKED';
  assignment.revoked = true;
  controlStore.saveAssignment(assignment);
  const revoked = await controller.restore({
    operation_id: 'op-revoked-restore',
    userRef: 'user-max',
    environmentRef: ENV,
    restore_ref: failedLoad.stages.restore_saved.restore_ref,
    authorization: auth('user-max'),
  });
  assert.equal(revoked.code, 'ASSIGNMENT_REVOKED');
  assignment.status = 'ACTIVE';
  assignment.revoked = false;
  controlStore.saveAssignment(assignment);

  const external = await controller.restore({
    operation_id: 'op-external',
    userRef: 'user-max',
    environmentRef: ENV,
    restore_ref: failedLoad.stages.restore_saved.restore_ref,
    authorization: auth('user-max'),
    detect_external: true,
    external_modified: true,
  });
  assert.equal(external.code, 'EXTERNAL_MODIFICATION');
  controlStore.close();
});
