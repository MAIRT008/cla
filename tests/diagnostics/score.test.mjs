import assert from 'node:assert/strict';
import test from 'node:test';
import {scoreNetwork, mergeRootCauses} from '../../src/core/diagnostics/index.mjs';
import {createDiagnosticHarness} from '../../fixtures/diagnostics/harness.mjs';

test('FD-02/A15-A18 危急封顶、同根因只扣一次、信誉不默认扣分、字体不扣分', async () => {
  const merged = mergeRootCauses([
    {issue_id: 'a', root_cause_id: 'bypass-approved-a', severity: 'critical', evidence_refs: ['e1']},
    {issue_id: 'b', root_cause_id: 'bypass-approved-a', severity: 'important', evidence_refs: ['e2']},
  ]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].severity, 'critical');
  const scored = scoreNetwork(merged, {keyChecks: [{check_id: 'k', required: true, status: 'PRESENT'}]});
  assert.equal(scored.score, 39);
  const intel = scoreNetwork([{issue_id: 'i', root_cause_id: 'intel-only', severity: null}], {keyChecks: [{check_id: 'k', required: true, status: 'PRESENT'}]});
  assert.equal(intel.score, 100);
  const missing = scoreNetwork([], {keyChecks: [{check_id: 'expected-ab', required: true, status: 'MISSING'}]});
  assert.equal(missing.score, null);
  assert.equal(missing.status, 'INCOMPLETE');
});

test('FD-02/A05 绕行批准 A 记危急，首次回显不是基准', async () => {
  const harness = await createDiagnosticHarness('bypass', {world: {echoIp: '198.51.100.8', expectedA: '203.0.113.10'}});
  const result = await harness.controller.startScan({mode: 'deep', expected: {A: '203.0.113.10', timezone: 'America/Los_Angeles'}});
  assert.equal(result.issues.some((item) => item.kind === 'PROTECTED_BYPASS_A' && item.severity === 'critical'), true);
  assert.notEqual(result.observations.find((item) => item.check_id === 'exit.echo').actual, 'first-echo-baseline');
});

test('BLOCK 结论只来自观测：无 bypass 开关仍记问题，匹配出口不因开关记问题', async () => {
  const mismatch = await createDiagnosticHarness('evidence-mismatch', {world: {echoIp: '198.51.100.8', bypass: false, expectedA: '203.0.113.10'}});
  const bad = await mismatch.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}, expected: {A: '203.0.113.10'}});
  assert.equal(bad.observations.find((item) => item.check_id === 'exit.echo').actual, '198.51.100.8');
  assert.equal(bad.issues.some((item) => item.kind === 'PROTECTED_BYPASS_A'), true);

  const match = await createDiagnosticHarness('evidence-match', {world: {echoIp: '203.0.113.10', bypass: true, expectedA: '203.0.113.10'}});
  const ok = await match.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}, expected: {A: '203.0.113.10'}});
  assert.equal(ok.observations.find((item) => item.check_id === 'exit.echo').actual, '203.0.113.10');
  assert.equal(ok.issues.some((item) => item.kind === 'PROTECTED_BYPASS_A'), false);
});

test('BLOCK DNS/保护结论来自观测，不读 dnsViolation/forbiddenOpen', async () => {
  const dohDest = await createDiagnosticHarness('dns-doh-dest', {world: {echoIp: '203.0.113.10', expectedA: '203.0.113.10', dohIp: '198.51.100.9'}});
  const dohScan = await dohDest.controller.startScan({mode: 'special', scope: {categories: ['multipath']}, expected: {A: '203.0.113.10'}});
  assert.equal(dohScan.observations.find((item) => item.check_id === 'dns.doh').actual.ips[0], '198.51.100.9');
  assert.equal(dohScan.issues.some((item) => item.kind === 'DNS_PATH_VIOLATION'), false);

  const dns = await createDiagnosticHarness('dns-obs', {
    world: {echoIp: '203.0.113.10', expectedA: '203.0.113.10', dnsCaptured: true, dnsResolver: '198.51.100.9', expectedDnsResolvers: ['192.0.2.53']},
  });
  const dnsScan = await dns.controller.startScan({mode: 'special', scope: {categories: ['multipath']}, expected: {A: '203.0.113.10'}});
  assert.equal(dnsScan.observations.find((item) => item.check_id === 'dns.probe').actual.resolver_ip, '198.51.100.9');
  assert.equal(dnsScan.issues.some((item) => item.kind === 'DNS_PATH_VIOLATION'), true);

  const okDns = await createDiagnosticHarness('dns-ok', {world: {echoIp: '203.0.113.10', expectedA: '203.0.113.10', dohIp: '198.51.100.9', dnsViolation: true}});
  const okScan = await okDns.controller.startScan({mode: 'special', scope: {categories: ['multipath']}, expected: {A: '203.0.113.10'}});
  assert.equal(okScan.issues.some((item) => item.kind === 'DNS_PATH_VIOLATION'), false);

  const protect = await createDiagnosticHarness('protect-obs', {
    world: {echoIp: '203.0.113.10', expectedA: '203.0.113.10', forbiddenOpen: false},
    ports: {networkState: {status: 'AVAILABLE', core: 'RUNNING', protection: {status: 'FAILED', new_connections_restricted: false}}},
  });
  const protectScan = await protect.controller.startScan({mode: 'special', scope: {categories: ['kernel']}, expected: {A: '203.0.113.10'}});
  assert.equal(protectScan.issues.some((item) => item.kind === 'PROTECTION_FAILED_NEW_CONNECTION'), true);

  const flagOnly = await createDiagnosticHarness('protect-flag', {
    world: {echoIp: '203.0.113.10', expectedA: '203.0.113.10', forbiddenOpen: true},
  });
  const flagScan = await flagOnly.controller.startScan({mode: 'special', scope: {categories: ['kernel']}, expected: {A: '203.0.113.10'}});
  assert.equal(flagScan.issues.some((item) => item.kind === 'PROTECTION_FAILED_NEW_CONNECTION'), false);
});
