import assert from 'node:assert/strict';
import test from 'node:test';
import {collectBrowserSample, SCRIPT_VERSION} from '../../apps/diagnostic-page/sample.mjs';
import {createDiagnosticHarness} from '../../fixtures/diagnostics/harness.mjs';

test('FD-02/A11-A12 nonce/过期/不同Profile 拒绝，UA 不能覆盖 Profile', async () => {
  const harness = await createDiagnosticHarness('session');
  const scan = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  const session = harness.controller.createSession({
    taskRef: scan.task_id,
    environmentRef: 'synthetic-windows',
    profileRef: 'Default',
    origin: 'https://diagnostic.synthetic.invalid',
  });
  const sample = await collectBrowserSample({
    navigator: harness.ports.navigator,
    fingerprint: harness.ports.fingerprint,
    clock: harness.clock,
  });
  const ok = harness.controller.acceptReport({
    origin: 'https://diagnostic.synthetic.invalid',
    body: {
      session_ref: session.session_ref,
      session_nonce: session.session_nonce,
      script_version: SCRIPT_VERSION,
      task_ref: scan.task_id,
      environment_ref: 'synthetic-windows',
      profile_ref: 'Default',
      sample: {platform: sample.platform, fingerprint: {token: 'SECRET-TOKEN', hash: 'abc'}},
    },
  });
  assert.equal(ok.ok, true, JSON.stringify(ok));
  assert.equal(ok.task_ref, scan.task_id);
  const receipt = harness.store.getRecord(ok.receipt_ref, 'browser_receipt');
  assert.equal(receipt.sample.fingerprint.token, undefined);
  const missing = harness.controller.acceptReport({
    origin: 'https://diagnostic.synthetic.invalid',
    body: {session_ref: session.session_ref, session_nonce: session.session_nonce},
  });
  assert.equal(missing.ok, false);
  const otherTask = harness.controller.acceptReport({
    origin: 'https://diagnostic.synthetic.invalid',
    body: {
      session_ref: session.session_ref,
      session_nonce: session.session_nonce,
      script_version: SCRIPT_VERSION,
      task_ref: 'other-task',
      environment_ref: 'synthetic-windows',
      profile_ref: 'Default',
      sample: {token: 'NESTED', platform: sample.platform},
    },
  });
  assert.equal(otherTask.code, 'TASK_MISMATCH');
});
