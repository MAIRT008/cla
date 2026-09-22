import assert from 'node:assert/strict';
import test from 'node:test';
import {createDiagnosticHarness} from '../../fixtures/diagnostics/harness.mjs';

test('FD-02/N04-N06 深/快/专项请求集合不同，取消保留已完成项', async () => {
  const deepH = await createDiagnosticHarness('deep');
  const deep = await deepH.controller.startScan({mode: 'deep'});
  const quickH = await createDiagnosticHarness('quick');
  const quick = await quickH.controller.startScan({mode: 'quick'});
  const specialH = await createDiagnosticHarness('special');
  const special = await specialH.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  assert.equal(deep.categories_completed.length, 6);
  assert.ok(quick.categories_completed.length < deep.categories_completed.length);
  assert.deepEqual(special.categories_requested, ['exit_ip']);
  assert.ok(deep.requests.length > special.requests.length);
  assert.equal(special.scoring.score, null);
  assert.equal(special.status, 'SCOPED');

  const ac = new AbortController();
  ac.abort();
  const cancelled = await deepH.controller.startScan({mode: 'deep', signal: ac.signal});
  assert.equal(cancelled.cancelled, true);
});

test('FD-02/A07-A10 情报缺失、DNS未捕获、无公网STUN、IPv6无结果分开', async () => {
  const harness = await createDiagnosticHarness('gaps', {
    world: {intelMissing: true, dnsCaptured: false, ipv6: {status: 'NO_RESULT'}},
  });
  const result = await harness.controller.startScan({mode: 'deep'});
  const intel = result.observations.find((item) => item.check_id === 'exit.intel');
  const dns = result.observations.find((item) => item.check_id === 'dns.probe');
  const ice = result.observations.find((item) => item.check_id === 'webrtc.ice');
  const ipv6 = result.observations.find((item) => item.check_id === 'ipv6.path');
  assert.equal(intel.status, 'NO_DATA');
  assert.equal(dns.status, 'NOT_CAPTURED');
  assert.equal(ice.limitation, 'NO_PUBLIC_STUN_CANDIDATE');
  assert.equal(ipv6.status, 'NO_RESULT');
  assert.equal(result.issues.some((item) => item.kind === 'PROTECTED_BYPASS_A'), false);
});
