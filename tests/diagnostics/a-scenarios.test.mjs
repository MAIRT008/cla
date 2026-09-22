import assert from 'node:assert/strict';
import test from 'node:test';
import {redactDiagnostic} from '../../src/core/diagnostics/index.mjs';
import {createDiagnosticHarness} from '../../fixtures/diagnostics/harness.mjs';

test('FD-02/A01-A04 A13-A14 标准扫描、HTTP 状态不判账号、JA3 缺测', async () => {
  const harness = await createDiagnosticHarness('std', {world: {httpStatus: 403, ja3: null}});
  const result = await harness.controller.startScan({mode: 'deep'});
  const http = result.observations.find((item) => item.check_id === 'claude.http-status');
  assert.equal(http.actual.account, 'NOT_INFERRED');
  const tls = result.observations.find((item) => item.check_id === 'claude.tls');
  assert.equal(tls.actual.tls?.ja3 || tls.limitation, tls.limitation || 'UNAVAILABLE' || tls.actual.tls?.ja3);
  assert.ok(tls.actual.tls?.ja3 === null || tls.actual.tls?.ja3 === 'UNAVAILABLE' || tls.limitation);
  const view = harness.controller.view(result.task_id);
  assert.equal(view.task_id, result.task_id);
  const report = harness.controller.report(result.task_id);
  assert.match(report.markdown, /诊断报告/);
  assert.equal(report.audit_summary.does_not_override_daily_fail, true);
});

test('FD-02/A27 导出脱敏且不含 cookie 值', async () => {
  const harness = await createDiagnosticHarness('redact');
  const result = await harness.controller.startScan({mode: 'special', scope: {categories: ['browser']}});
  result.observations[0].actual.cookie = 'SECRETCOOKIE';
  result.observations[0].actual.nested = {token: 'NESTED-TOKEN'};
  const redacted = redactDiagnostic(result);
  assert.equal(redacted.observations[0].actual.cookie, undefined);
  assert.equal(redacted.observations[0].actual.nested.token, undefined);
  const report = harness.controller.report(result.task_id);
  assert.equal(harness.store.getRecord(`diag-report-${result.task_id}`, 'diagnostic_report').task_id, result.task_id);
  assert.ok(report.markdown);
});

test('未配置 echo 时零请求并记录 SERVICE_NOT_CONFIGURED', async () => {
  const harness = await createDiagnosticHarness('noconfig');
  harness.ports.echo = {};
  const result = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  assert.equal(result.observations[0].status, 'SERVICE_NOT_CONFIGURED');
  assert.equal(result.requests.length, 0);
});
