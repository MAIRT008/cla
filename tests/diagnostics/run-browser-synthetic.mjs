import assert from 'node:assert/strict';
import {collectBrowserSample, SCRIPT_VERSION} from '../../apps/diagnostic-page/sample.mjs';
import {createDiagnosticHarness} from '../../fixtures/diagnostics/harness.mjs';

const harness = await createDiagnosticHarness('browser-page');
const scanned = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
const session = harness.controller.createSession({
  taskRef: scanned.task_id,
  environmentRef: 'synthetic-windows',
  profileRef: 'Default',
  origin: 'https://diagnostic.synthetic.invalid',
});
const sample = await collectBrowserSample({
  navigator: harness.ports.navigator,
  fingerprint: harness.ports.fingerprint,
  clock: harness.clock,
  peerConnection: harness.ports.peerConnection,
});
const accepted = harness.controller.acceptReport({
  origin: 'https://diagnostic.synthetic.invalid',
  body: {
    session_ref: session.session_ref,
    session_nonce: session.session_nonce,
    script_version: SCRIPT_VERSION,
    task_ref: scanned.task_id,
    environment_ref: 'synthetic-windows',
    profile_ref: 'Default',
    sample,
  },
});
assert.equal(accepted.ok, true);
assert.equal(accepted.task_ref, scanned.task_id);
assert.equal(sample.cookie_values_read, false);
assert.equal(sample.audio_played, false);
process.stdout.write(`${JSON.stringify({ok: true, receipt_ref: accepted.receipt_ref, script_version: SCRIPT_VERSION}, null, 2)}\n`);
