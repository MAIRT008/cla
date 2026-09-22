import assert from 'node:assert/strict';
import test from 'node:test';
import {createDiagnosticHarness} from '../../fixtures/diagnostics/harness.mjs';

test('FD-02/A19-A26 确认、漂移暂停、应用成功仍异常、恢复冲突', async () => {
  const harness = await createDiagnosticHarness('plan', {world: {echoIp: '198.51.100.8', expectedA: '203.0.113.10'}});
  const scan = await harness.controller.startScan({mode: 'deep', expected: {A: '203.0.113.10'}});
  const plan = harness.controller.buildPlan(scan.task_id, [
    {
      issue_kind: 'PROTECTED_BYPASS_A',
      kind: 'apply_network',
      target: 'mode',
      before: 'daily_single_ip',
      after: 'claude_single_ip',
      impact: 'brief-interrupt',
      backup: true,
      payload: {
        userRef: 'user-jia',
        environmentRef: 'synthetic-windows',
        mode: 'claude_single_ip',
        operation_id: 'diag-fix-bypass',
        authorization: {kind: 'ONCE_CONFIRMED', user_ref: 'user-jia', environment_ref: 'synthetic-windows', authorization_ref: 'auth-jia'},
      },
      restore_payload: {
        userRef: 'user-jia',
        environmentRef: 'synthetic-windows',
        mode: 'daily_single_ip',
        operation_id: 'diag-restore-bypass',
        restore_ref: 'diag-backup',
        authorization: {kind: 'ONCE_CONFIRMED', user_ref: 'user-jia', environment_ref: 'synthetic-windows', authorization_ref: 'auth-jia'},
      },
    },
  ]);
  assert.equal(Boolean(plan.actions[0].payload?.userRef), true);
  assert.equal(plan.actions[0].suggestion, 'DIRECT_FIX');
  const confirmed = harness.controller.confirm(plan.plan_id, plan.actions.map((item) => item.action_id), 'confirm-1');
  const drifted = await harness.controller.execute(confirmed.plan_id, {drift: new Set([plan.actions[0].action_id])});
  assert.equal(drifted.receipts[0].status, 'PAUSED');

  const executed = await harness.controller.execute(confirmed.plan_id, {
    network: {
      async confirmAndApply(payload) {
        if (!payload?.userRef || !payload?.mode) throw new Error('empty payload');
        return {overall: 'APPLIED_VERIFIED', loaded: {loaded_version: 'v1'}};
      },
      async restore(payload) {
        if (!payload?.userRef) return {ok: false};
        return {ok: true, overall: 'APPLIED_VERIFIED'};
      },
    },
  });
  const unverified = await harness.controller.recheck(plan.plan_id, plan.actions[0].action_id);
  assert.equal(unverified.status, 'UNVERIFIED');
  const stillScan = await harness.controller.startScan({mode: 'deep', expected: {A: '203.0.113.10'}});
  const still = await harness.controller.recheck(plan.plan_id, plan.actions[0].action_id, stillScan);
  assert.equal(still.status, 'STILL_ABNORMAL');
  harness.world.state.echoIp = '203.0.113.10';
  const fixedScan = await harness.controller.startScan({mode: 'deep', expected: {A: '203.0.113.10'}});
  const verified = await harness.controller.recheck(plan.plan_id, plan.actions[0].action_id, fixedScan);
  assert.equal(verified.status, 'VERIFIED');
  assert.equal(executed.receipts[0].status === 'APPLIED' || executed.receipts[0].status === 'PAUSED', true);

  const preview = harness.controller.previewRestore(plan.plan_id);
  const conflict = await harness.controller.restore(plan.plan_id, true, [{reason: 'user-later-edit'}]);
  assert.equal(conflict.status, 'CONFLICT');
  assert.ok(preview.items);
});

test('FD-02/A22-A24 无批准候选拒绝，普通扫描不演练', async () => {
  const harness = await createDiagnosticHarness('drill');
  const scan = await harness.controller.startScan({mode: 'quick'});
  const plan = harness.controller.buildPlan(scan.task_id, []);
  assert.equal(plan.actions.every((item) => item.kind === 'unsupported' || !item.supported), true);
  assert.equal(scan.requests.some((item) => String(item.url).includes('firewall')), false);
});
