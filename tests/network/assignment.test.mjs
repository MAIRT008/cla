import assert from 'node:assert/strict';
import test from 'node:test';
import {compileNetworkPlan, expectedRouteMatrix, validateAssignment} from '../../src/core/network/index.mjs';
import {auth, createHarness, ENV} from '../../fixtures/network/harness.mjs';

test('FD-03/A01-A04 A09-A11 三用户分配与路由矩阵', async () => {
  const {controller, controlStore} = await createHarness('assign');
  const free = await controller.getAssignment('user-free', ENV);
  const pro = await controller.getAssignment('user-pro', ENV);
  const max = await controller.getAssignment('user-max', ENV);
  assert.equal(free.validation.ok, true);
  assert.equal(free.validation.dual_ip_ready, false);
  assert.deepEqual(free.validation.allowed_modes, ['daily_single_ip']);
  assert.equal(pro.recommendation?.recommended_mode || (await controller.previewModeChange({userRef: 'user-pro', environmentRef: ENV, mode: 'claude_single_ip'})).recommendation.recommended_mode, 'claude_single_ip');
  const rec = await controller.previewModeChange({userRef: 'user-free', environmentRef: ENV, mode: 'daily_single_ip'});
  assert.equal(rec.recommendation.recommended_mode, 'daily_single_ip');
  assert.equal(rec.recommendation.official_risk_claim, false);
  await assert.rejects(() => controller.previewModeChange({userRef: 'user-free', environmentRef: ENV, mode: 'claude_dual_ip'}), {code: 'MODE_NOT_ALLOWED'});
  await assert.rejects(() => controller.previewModeChange({userRef: 'user-pro', environmentRef: ENV, mode: 'claude_dual_ip'}), {code: 'DUAL_IP_REQUIRES_B'});

  const daily = rec.plan;
  assert.equal(daily.matrix.claude.exit, 'A');
  assert.equal(daily.matrix.other.exit, 'A');
  assert.equal(daily.matrix.whitelist.enabled, false);
  assert.match(daily.yaml, /exit-a-free\.example\.invalid/);
  assert.doesNotMatch(daily.yaml, /url-test|fallback|load-balance/);

  const dedicated = (await controller.previewModeChange({userRef: 'user-pro', environmentRef: ENV, mode: 'claude_single_ip'})).plan;
  assert.equal(dedicated.matrix.tun_required, true);
  assert.equal(dedicated.matrix.whitelist.enabled, false);
  assert.match(dedicated.yaml, /tun:\n {2}enable: true/);
  assert.match(dedicated.yaml, /exit-a-pro\.example\.invalid/);
  assert.doesNotMatch(dedicated.yaml, /exit-a-free\.example\.invalid/);

  const dual = (await controller.previewModeChange({userRef: 'user-max', environmentRef: ENV, mode: 'claude_dual_ip'})).plan;
  assert.equal(dual.matrix.claude.exit, 'A');
  assert.equal(dual.matrix.other.exit, 'B');
  assert.equal(dual.matrix.claude.rotate, false);
  assert.match(dual.yaml, /exit-a-max\.example\.invalid/);
  assert.match(dual.yaml, /exit-b-max\.example\.invalid/);
  assert.match(dual.yaml, /name: CLAUDE-FIXED[\s\S]*PROXY-A/);
  assert.match(dual.yaml, /name: GENERAL-EGRESS[\s\S]*PROXY-B/);

  const expired = structuredClone(max.assignment);
  expired.valid_until = '2020-01-01T00:00:00.000Z';
  assert.equal(validateAssignment(expired, {environment_ref: ENV}, '2026-09-13T17:00:00.000Z').code, 'ASSIGNMENT_EXPIRED');

  const matrix = expectedRouteMatrix('daily_single_ip', {whitelistActive: true});
  assert.equal(matrix.whitelist.enabled, true);
  assert.equal(matrix.other.exit, 'A');

  const compiled = compileNetworkPlan({assignment: free.assignment, mode: 'daily_single_ip', whitelist: {entries: [{host: 'news.example', match: 'exact', enabled: true}]}, environmentScope: {environment_ref: ENV}});
  assert.match(compiled.yaml, /DOMAIN,news.example,DIRECT/);
  assert.ok(compiled.yaml.indexOf('DOMAIN-SUFFIX,claude.ai,CLAUDE-FIXED') < compiled.yaml.indexOf('DOMAIN,news.example,DIRECT'));

  controlStore.close();
});
