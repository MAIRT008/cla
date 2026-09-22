import assert from 'node:assert/strict';
import test from 'node:test';
import {createEchoAdapter} from '../../src/adapters/diagnostics/echo.mjs';
import {createProbeAdapter} from '../../src/adapters/diagnostics/probe.mjs';
import {createAiClient} from '../../src/core/ai/index.mjs';
import {executeClientTool} from '../../src/core/ai/tools.mjs';
import {redactDiagnostic, SCRIPT_VERSION} from '../../src/core/diagnostics/index.mjs';
import {createDiagnosticHarness} from '../../fixtures/diagnostics/harness.mjs';

test('BLOCK 调用者 expected 不能覆盖 Assignment，出口不匹配必出问题', async () => {
  const harness = await createDiagnosticHarness('expected-override', {world: {echoIp: '198.51.100.8', expectedA: '203.0.113.10'}});
  const result = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}, expected: {A: '198.51.100.8'}});
  assert.equal(result.expected_source, 'assignment');
  assert.equal(result.observations.find((item) => item.check_id === 'exit.echo').actual, '198.51.100.8');
  assert.equal(result.issues.some((item) => item.kind === 'PROTECTED_BYPASS_A'), true);
  assert.notEqual(result.scoring.scoped_score, 100);
});

test('BLOCK 空 payload 不能假 EXECUTED；恢复走 T5 restore；演练不声明已恢复', async () => {
  const harness = await createDiagnosticHarness('fake-fix', {world: {echoIp: '198.51.100.8', expectedA: '203.0.113.10'}});
  const scan = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  const empty = harness.controller.buildPlan(scan.task_id, [{issue_kind: 'PROTECTED_BYPASS_A', kind: 'apply_network'}]);
  harness.controller.confirm(empty.plan_id, empty.actions.map((item) => item.action_id), 'c1');
  const executed = await harness.controller.execute(empty.plan_id, {
    network: {async confirmAndApply(payload) { return {overall: Object.keys(payload || {}).length ? 'APPLIED_VERIFIED' : 'APPLIED_VERIFIED'}; }},
  });
  assert.equal(executed.receipts[0].status, 'FAILED');
  assert.equal(executed.status, 'PARTIAL');
  const drill = await harness.controller.drill({authorization: {confirmed: true}});
  assert.equal(drill.restored_claim, false);
});

test('MAJOR 取消中止 I/O 且最终保持 CANCELLED', async () => {
  const echo = createEchoAdapter({
    url: 'https://echo.synthetic.invalid/ip',
    timeoutMs: 2000,
    fetchImpl: (_url, init) => new Promise((_, reject) => {
      init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {name: 'AbortError', code: 'CANCELLED'})));
    }),
  });
  const harness = await createDiagnosticHarness('cancel', {ports: {echo}});
  const pending = harness.controller.startScan({mode: 'deep'});
  let running = null;
  for (let i = 0; i < 25 && !running; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
    running = harness.store.listRecords('diagnostic_task').find((item) => item.status === 'RUNNING')
      || harness.store.listRecords('diagnostic_task').at(-1);
    if (running && !running.task_id) running = null;
  }
  assert.ok(running?.task_id, 'running diagnostic task was not recorded');
  await harness.controller.cancel(running.task_id);
  const result = await pending;
  assert.equal(result.status, 'CANCELLED');
  assert.ok(result.categories_completed.length < 6);
  const stored = harness.store.getRecord(result.task_id, 'diagnostic_result') || harness.store.getRecord(result.task_id, 'diagnostic_task');
  assert.equal(stored?.status, 'CANCELLED');
});

test('MAJOR 快扫保留未关闭问题，专项不给全环境分', async () => {
  const harness = await createDiagnosticHarness('scope-score', {world: {echoIp: '203.0.113.10', expectedA: '203.0.113.10'}});
  const previous = {
    issues: [{issue_id: 'old-tz', kind: 'TIMEZONE_MISMATCH', root_cause_id: 'locale-mismatch', severity: 'mild', evidence_refs: ['old:browser:platform']}],
    observations: [{check_id: 'browser.platform', evidence_ref: 'old:browser:platform', actual: {timezone: 'America/Los_Angeles'}}],
  };
  const quick = await harness.controller.startScan({mode: 'quick', previous});
  assert.equal(quick.issues.some((item) => item.kind === 'TIMEZONE_MISMATCH' && item.retained), true);
  assert.ok(quick.scoring.score === null || quick.scoring.score < 100);
  const special = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  assert.equal(special.scoring.score, null);
  assert.equal(special.status, 'SCOPED');
});

test('MAJOR echo 503 不能当 OBSERVED；T4 读取 T7 诊断结果', async () => {
  const echo = createEchoAdapter({
    url: 'https://echo.synthetic.invalid/ip',
    fetchImpl: async () => ({status: 503, text: async () => '{"ip":"203.0.113.10"}'}),
  });
  const harness = await createDiagnosticHarness('echo-503', {ports: {echo}, world: {echoIp: '203.0.113.10', expectedA: '203.0.113.10'}});
  const failed = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  assert.equal(failed.observations.find((item) => item.check_id === 'exit.echo').status, 'REQUEST_FAILED');
  assert.equal(failed.issues.some((item) => item.kind === 'PROTECTED_BYPASS_A'), false);

  const ok = await createDiagnosticHarness('t4-consume', {world: {echoIp: '198.51.100.8', expectedA: '203.0.113.10'}});
  const scanned = await ok.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  const inspected = await executeClientTool({
    task: {task_type: 'network_diagnosis', network_facts: {diagnostic_task_id: scanned.task_id, environment: {}, profile: {}, configuration: {}, history: [], dns: [], exit: []}},
    call: {id: '1', function: {name: 'InspectNetworkEvidence', arguments: JSON.stringify({port: 'exit'})}},
    localService: {},
    localStore: ok.store,
    auditStore: {},
    diagnostics: ok.controller,
  });
  assert.equal(inspected.diagnostic_task_id, scanned.task_id);
  assert.equal(inspected.evidence[0].actual, '198.51.100.8');
});

test('BLOCK 调用者 Assignment 不能覆盖控制器持有的权威，合法 B 不是绕行', async () => {
  const harness = await createDiagnosticHarness('forged-assignment', {world: {echoIp: '198.51.100.8', expectedA: '203.0.113.10', expectedB: '203.0.113.20'}});
  const forged = {
    ...harness.assignment,
    expected_exits: {A: '198.51.100.8', B: '198.51.100.8'},
    resources: {
      'res-a': {public_ip: '198.51.100.8', role: 'A'},
      'res-b': {public_ip: '198.51.100.8', role: 'B'},
    },
  };
  const result = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}, assignment: forged});
  assert.deepEqual(result.expected_exits, {A: '203.0.113.10', B: '203.0.113.20'});
  assert.equal(result.issues.some((item) => item.kind === 'PROTECTED_BYPASS_A'), true);
  assert.equal(result.scoring.has_critical, true);
  assert.notEqual(result.scoring.scoped_score, 100);

  const legalB = await createDiagnosticHarness('legal-b', {world: {echoIp: '203.0.113.20', expectedA: '203.0.113.10', expectedB: '203.0.113.20'}});
  const bScan = await legalB.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  assert.equal(bScan.observations.find((item) => item.check_id === 'exit.echo').actual, '203.0.113.20');
  assert.deepEqual(bScan.observations.find((item) => item.check_id === 'exit.echo').expected, {A: '203.0.113.10', B: '203.0.113.20'});
  assert.equal(bScan.issues.some((item) => item.kind === 'PROTECTED_BYPASS_A'), false);
});

test('BLOCK 扫描结束后回传写入 DiagnosticResult 和报告', async () => {
  const harness = await createDiagnosticHarness('post-scan-receipt');
  const scan = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  const session = harness.controller.createSession({
    taskRef: scan.task_id,
    environmentRef: 'synthetic-windows',
    origin: 'https://diagnostic.synthetic.invalid',
  });
  const accepted = harness.controller.acceptReport({
    origin: 'https://diagnostic.synthetic.invalid',
    body: {
      session_ref: session.session_ref,
      session_nonce: session.session_nonce,
      script_version: SCRIPT_VERSION,
      task_ref: scan.task_id,
      environment_ref: 'synthetic-windows',
      sample: {platform: {timezone: 'America/Los_Angeles'}},
    },
  });
  assert.equal(accepted.ok, true);
  const result = harness.controller.result(scan.task_id);
  assert.equal(result.observations.some((item) => item.check_id === 'browser.session-sample' && item.actual?.platform), true);
  const report = harness.store.getRecord(`diag-report-${scan.task_id}`, 'diagnostic_report');
  assert.equal(Boolean(report?.json?.observations?.some((item) => item.check_id === 'browser.session-sample')), true);
});

test('BLOCK 恢复引用用 T5 apply 回执，演练未验证不声明已恢复', async () => {
  const restoreCalls = [];
  const harness = await createDiagnosticHarness('restore-ref', {
    world: {echoIp: '198.51.100.8', expectedA: '203.0.113.10'},
    network: {
      async handleProtection() { return {status: 'PROTECTED'}; },
      async confirmAndApply() {
        return {overall: 'APPLIED_VERIFIED', stages: {restore_saved: {restore_ref: 'REAL-RESTORE-REF'}}};
      },
      async restore(payload) {
        restoreCalls.push(payload.restore_ref);
        return {overall: payload.restore_ref === 'REAL-RESTORE-REF' ? 'APPLIED_VERIFIED' : 'PARTIAL'};
      },
    },
  });
  const scan = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  const plan = harness.controller.buildPlan(scan.task_id, [{
    issue_kind: 'PROTECTED_BYPASS_A',
    kind: 'apply_network',
    payload: {userRef: 'user-jia', mode: 'claude_single_ip', operation_id: 'diag-fix', authorization: {kind: 'ONCE_CONFIRMED'}},
    restore_payload: {userRef: 'user-jia', mode: 'daily_single_ip', operation_id: 'diag-restore', restore_ref: 'PREFILLED', authorization: {kind: 'ONCE_CONFIRMED'}},
  }]);
  harness.controller.confirm(plan.plan_id, plan.actions.map((item) => item.action_id), 'c-restore');
  const executed = await harness.controller.execute(plan.plan_id);
  assert.equal(executed.receipts[0].backup_ref, 'REAL-RESTORE-REF');
  const restored = await harness.controller.restore(plan.plan_id, true);
  assert.deepEqual(restoreCalls, ['REAL-RESTORE-REF']);
  assert.equal(restored.status, 'RESTORED');

  const unverified = await createDiagnosticHarness('drill-unverified', {
    network: {
      async handleProtection() { return {status: 'PROTECTED'}; },
      async restore() { return {overall: 'APPLIED_UNVERIFIED'}; },
    },
  });
  const unverifiedDrill = await unverified.controller.drill({
    authorization: {confirmed: true},
    restore: true,
    restore_request: {restore_ref: 'ANY'},
  });
  assert.equal(unverifiedDrill.restored_claim, false);
});

test('MAJOR T4 本地确认会确认诊断计划后再执行', async () => {
  const harness = await createDiagnosticHarness('t4-confirm', {
    world: {echoIp: '198.51.100.8', expectedA: '203.0.113.10'},
    network: {
      async confirmAndApply() {
        return {overall: 'APPLIED_VERIFIED', stages: {restore_saved: {restore_ref: 'REAL-RESTORE-REF'}}};
      },
    },
  });
  const scan = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  const plan = harness.controller.buildPlan(scan.task_id, [{
    issue_kind: 'PROTECTED_BYPASS_A',
    kind: 'apply_network',
    payload: {userRef: 'user-jia', mode: 'claude_single_ip', operation_id: 'diag-fix', authorization: {kind: 'ONCE_CONFIRMED'}},
  }]);
  const taskId = harness.store.newId('ai-task');
  harness.store.saveRecord('ai_task_v1', taskId, {
    task_id: taskId,
    task_type: 'network_diagnosis',
    status: 'AWAITING_NETWORK_CONFIRMATION',
    messages: [],
    network_facts: {
      diagnostic_plan_id: plan.plan_id,
      diagnostic_task_id: scan.task_id,
      supported_actions: [{action_id: plan.actions[0].action_id, environment_ref: 'synthetic-windows', profile_ref: 'Default', status: 'SUPPORTED'}],
    },
    network_plan: {
      plan_id: 'network-plan-1',
      version: 1,
      action_id: plan.actions[0].action_id,
      environment_ref: 'synthetic-windows',
      profile_ref: 'Default',
      reason: 'fix bypass',
      status: 'AWAITING_LOCAL_USER_CONFIRMATION',
    },
    network_confirmation_id: null,
    network_confirmation: null,
  });
  const client = createAiClient({
    localService: {confirmActionPlan: async () => ({confirmation_id: 'x'}), getTask: () => null},
    localStore: harness.store,
    auditStore: {async exists() { return false; }, async writeText() {}, async readText() { return ''; }, async listFiles() { return []; }},
    controlTransport: {async turn() { return {assistant: {content: '', tool_calls: []}}; }},
    diagnostics: harness.controller,
  });
  client.confirmNetwork({taskId, planId: 'network-plan-1'});
  assert.equal(harness.controller.plan(plan.plan_id).status, 'CONFIRMED');
  const applied = await executeClientTool({
    task: harness.store.getRecord(taskId, 'ai_task_v1'),
    call: {id: '1', function: {name: 'ApplyNetworkPlan', arguments: JSON.stringify({plan_id: 'network-plan-1'})}},
    localService: {},
    localStore: harness.store,
    auditStore: {},
    diagnostics: harness.controller,
  });
  assert.notEqual(applied.code, 'CONFIRMATION_REQUIRED');
  assert.equal(applied.status === 'EXECUTED' || applied.receipts?.[0]?.status === 'APPLIED', true);
});

test('BLOCK T4 确认只覆盖用户选定的一个动作', async () => {
  const ops = [];
  const harness = await createDiagnosticHarness('t4-scope', {
    world: {echoIp: '198.51.100.8', expectedA: '203.0.113.10'},
    ports: {networkState: {status: 'AVAILABLE', core: 'RUNNING', protection: {status: 'FAILED', new_connections_restricted: false}}},
    network: {
      async confirmAndApply(payload) {
        ops.push(payload.operation_id);
        return {overall: 'APPLIED_VERIFIED', stages: {restore_saved: {restore_ref: 'R1'}}};
      },
    },
  });
  const scan = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip', 'kernel']}});
  const plan = harness.controller.buildPlan(scan.task_id, [
    {issue_kind: 'PROTECTED_BYPASS_A', kind: 'apply_network', payload: {userRef: 'user-jia', mode: 'claude_single_ip', operation_id: 'op-bypass', authorization: {kind: 'ONCE_CONFIRMED'}}},
    {issue_kind: 'PROTECTION_FAILED_NEW_CONNECTION', kind: 'apply_network', payload: {userRef: 'user-jia', mode: 'claude_single_ip', operation_id: 'op-protect', authorization: {kind: 'ONCE_CONFIRMED'}}},
  ]);
  const supported = plan.actions.filter((item) => item.supported);
  assert.equal(supported.length, 2);
  const selected = supported[0].action_id;
  const taskId = harness.store.newId('ai-task');
  harness.store.saveRecord('ai_task_v1', taskId, {
    task_id: taskId,
    task_type: 'network_diagnosis',
    status: 'AWAITING_NETWORK_CONFIRMATION',
    messages: [],
    network_facts: {
      diagnostic_plan_id: plan.plan_id,
      diagnostic_task_id: scan.task_id,
      supported_actions: supported.map((item) => ({action_id: item.action_id, environment_ref: 'synthetic-windows', profile_ref: 'Default', status: 'SUPPORTED'})),
    },
    network_plan: {
      plan_id: 'network-plan-scope',
      version: 1,
      action_id: selected,
      environment_ref: 'synthetic-windows',
      profile_ref: 'Default',
      reason: 'fix one',
      status: 'AWAITING_LOCAL_USER_CONFIRMATION',
    },
    network_confirmation_id: null,
    network_confirmation: null,
  });
  const client = createAiClient({
    localService: {confirmActionPlan: async () => ({confirmation_id: 'x'}), getTask: () => null},
    localStore: harness.store,
    auditStore: {async exists() { return false; }, async writeText() {}, async readText() { return ''; }, async listFiles() { return []; }},
    controlTransport: {async turn() { return {assistant: {content: '', tool_calls: []}}; }},
    diagnostics: harness.controller,
  });
  client.confirmNetwork({taskId, planId: 'network-plan-scope'});
  const confirmed = harness.controller.plan(plan.plan_id);
  assert.equal(confirmed.confirmed_action_ids.length, 1);
  assert.equal(confirmed.confirmed_action_ids[0], selected);
  const applied = await executeClientTool({
    task: harness.store.getRecord(taskId, 'ai_task_v1'),
    call: {id: '1', function: {name: 'ApplyNetworkPlan', arguments: JSON.stringify({plan_id: 'network-plan-scope'})}},
    localService: {},
    localStore: harness.store,
    auditStore: {},
    diagnostics: harness.controller,
  });
  assert.equal(applied.receipts.length, 1);
  assert.deepEqual(ops, [supported[0].payload.operation_id]);
});

test('MAJOR DoH/Intel 取消、503 与抛错收敛到 DiagnosticResult', async () => {
  let dohSignal = false;
  const hangingDoh = {
    url: 'https://dns.synthetic.invalid/dns-query',
    fetch: (_url, init) => new Promise((_, reject) => {
      dohSignal = Boolean(init?.signal);
      init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {name: 'AbortError', code: 'CANCELLED'})));
    }),
  };
  const cancelH = await createDiagnosticHarness('doh-cancel', {ports: {doh: hangingDoh}});
  const pending = cancelH.controller.startScan({mode: 'special', scope: {categories: ['multipath']}});
  let running = null;
  for (let i = 0; i < 25 && !running; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
    running = cancelH.store.listRecords('diagnostic_task').find((item) => item.status === 'RUNNING');
  }
  assert.ok(running?.task_id);
  const started = Date.now();
  await cancelH.controller.cancel(running.task_id);
  const cancelled = await pending;
  assert.ok(Date.now() - started < 100);
  assert.equal(dohSignal, true);
  assert.equal(cancelled.status, 'CANCELLED');

  const doh503 = await createDiagnosticHarness('doh-503', {
    ports: {doh: {url: 'https://dns.synthetic.invalid/dns-query', fetch: async () => ({status: 503, text: async () => '{"Status":0}'})}},
  });
  const failed = await doh503.controller.startScan({mode: 'special', scope: {categories: ['multipath']}});
  assert.equal(failed.observations.find((item) => item.check_id === 'dns.doh').status, 'REQUEST_FAILED');

  const intelThrow = await createDiagnosticHarness('intel-throw', {
    world: {echoIp: '203.0.113.10', expectedA: '203.0.113.10'},
    ports: {intel: {url: 'https://intel.synthetic.invalid/lookup', fetch: async () => { throw new Error('intel down'); }}},
  });
  const intelResult = await intelThrow.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  assert.equal(intelResult.status === 'RUNNING', false);
  assert.ok(intelThrow.controller.result(intelResult.task_id));
  assert.equal(intelResult.observations.find((item) => item.check_id === 'exit.intel').status, 'REQUEST_FAILED');
});

test('MAJOR Probe 取消后扫描在 150ms 内结束', async () => {
  let probeSignal = false;
  let markStarted;
  const probeStarted = new Promise((resolve) => { markStarted = resolve; });
  const hangingProbe = createProbeAdapter({
    state: {},
    baseUrl: 'https://probe.synthetic.invalid',
    timeoutMs: 5000,
    fetchImpl: (_url, init) => new Promise(() => {
      probeSignal = Boolean(init?.signal);
      markStarted();
    }),
  });
  const harness = await createDiagnosticHarness('probe-cancel', {ports: {probe: hangingProbe}});
  const pending = harness.controller.startScan({mode: 'special', scope: {categories: ['multipath']}});
  await probeStarted;
  const running = harness.store.listRecords('diagnostic_task').find((item) => item.status === 'RUNNING');
  assert.ok(running?.task_id);
  const started = Date.now();
  await harness.controller.cancel(running.task_id);
  const cancelled = await pending;
  assert.ok(Date.now() - started < 150);
  assert.equal(probeSignal, true);
  assert.equal(cancelled.status, 'CANCELLED');
});

test('MAJOR 深层 token 与 errors[].token 不能泄漏到回执、结果或报告', async () => {
  let nested = {token: 'DEEP-TOKEN-LEAK'};
  for (let i = 0; i < 12; i += 1) nested = {wrap: nested};
  const redacted = redactDiagnostic({task_id: 'depth', observations: [{actual: nested}]});
  assert.equal(JSON.stringify(redacted).includes('DEEP-TOKEN-LEAK'), false);
  assert.equal(JSON.stringify(redacted).includes('"token"'), false);

  const harness = await createDiagnosticHarness('session-token-leak');
  const scan = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}});
  const session = harness.controller.createSession({
    taskRef: scan.task_id,
    environmentRef: 'synthetic-windows',
    origin: 'https://diagnostic.synthetic.invalid',
  });
  const accepted = harness.controller.acceptReport({
    origin: 'https://diagnostic.synthetic.invalid',
    body: {
      session_ref: session.session_ref,
      session_nonce: session.session_nonce,
      script_version: SCRIPT_VERSION,
      task_ref: scan.task_id,
      environment_ref: 'synthetic-windows',
      sample: {
        platform: {timezone: 'America/Los_Angeles'},
        fingerprint: nested,
        errors: [{token: 'SAMPLE-ERROR-TOKEN-LEAK', message: 'nested'}],
      },
      errors: [{token: 'ERROR-TOKEN-LEAK', message: 'ice failed'}],
    },
  });
  assert.equal(accepted.ok, true);
  const receipt = harness.store.getRecord(accepted.receipt_ref, 'browser_receipt');
  const storedSession = harness.store.getRecord(session.session_ref, 'browser_session');
  const result = harness.controller.result(scan.task_id);
  const report = harness.store.getRecord(`diag-report-${scan.task_id}`, 'diagnostic_report');
  const dumped = [receipt, storedSession, result, report].map((item) => JSON.stringify(item)).join('\n');
  assert.equal(dumped.includes('DEEP-TOKEN-LEAK'), false);
  assert.equal(dumped.includes('ERROR-TOKEN-LEAK'), false);
  assert.equal(dumped.includes('SAMPLE-ERROR-TOKEN-LEAK'), false);
  assert.equal(receipt.errors[0].token, undefined);
  assert.equal(receipt.errors[0].message, 'ice failed');
  assert.equal(receipt.sample.errors[0].token, undefined);
});
