import assert from 'node:assert/strict';
import test from 'node:test';
import {createProtectionFixture, createNativeNetworkHost, createProductHostState, dispatchHostState, createWindowsProtectionAdapter} from '../../src/adapters/network/index.mjs';
import {YAML_LIBRARY} from '../../src/core/network/index.mjs';
import {auth, createHarness, ENV} from '../../fixtures/network/harness.mjs';

test('BLOCK2 不能应用他人 Assignment，operation_id 按用户隔离', async () => {
  const {controller, controlStore} = await createHarness('sec-tenant');
  const max = (await controller.getAssignment('user-max', ENV)).assignment;
  const stolen = await controller.confirmAndApply({
    operation_id: 'op-stolen',
    userRef: 'user-free',
    environmentRef: ENV,
    mode: 'daily_single_ip',
    assignment: max,
    authorization: auth('user-free'),
  }).catch((error) => error);
  assert.equal(stolen.code, 'ASSIGNMENT_USER_MISMATCH');

  const first = await controller.confirmAndApply({
    operation_id: 'shared-op',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  assert.equal(first.overall, 'APPLIED_VERIFIED');
  const other = await controller.confirmAndApply({
    operation_id: 'shared-op',
    userRef: 'user-pro',
    environmentRef: ENV,
    mode: 'claude_single_ip',
    authorization: auth('user-pro'),
  });
  assert.notEqual(other.expected?.mode, 'claude_dual_ip');
  assert.equal(other.user_ref, 'user-pro');
  controlStore.close();
});

test('BLOCK3 恢复要授权并保持限额，保护失败不得加载配置', async () => {
  const {controller, controlStore, core} = await createHarness('sec-restore');
  await controller.confirmAndApply({
    operation_id: 'op-before-restore',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  const applied = await controller.confirmAndApply({
    operation_id: 'op-before-restore-2',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_single_ip',
    authorization: auth('user-max'),
  });
  const noAuth = await controller.restore({
    operation_id: 'op-no-auth',
    userRef: 'user-max',
    environmentRef: ENV,
    restore_ref: applied.stages.restore_saved.restore_ref,
  });
  assert.equal(noAuth.code, 'AUTHORIZATION_REQUIRED');

  controlStore.saveQuotaSnapshot({user_ref: 'user-max', status: 'LIMITED', used_bytes: 9, limit_bytes: 9, authority_status: 'AVAILABLE', control_status: 'AVAILABLE', observed_at: '2026-09-13T17:00:00.000Z', proof_scope: 'simulation'});
  const limited = await controller.restore({
    operation_id: 'op-limited-restore',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    restore_ref: applied.stages.restore_saved.restore_ref,
    authorization: auth('user-max'),
  });
  assert.equal(limited.overall, 'RESTORED');
  assert.match(core.loadedPayload(), /MATCH,REJECT/);
  controlStore.close();
});

test('BLOCK3 保护 UNCONFIRMED 且未限制新连接时不得加载配置', async () => {
  const protection = createProtectionFixture({inject: {reconnectAllowed: true, commandOnly: true}});
  const {controller, controlStore, core} = await createHarness('sec-protect-unconfirmed', {protection});
  const result = await controller.confirmAndApply({
    operation_id: 'op-protect-unconfirmed',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  assert.equal(result.code, 'PROTECTION_NOT_READY');
  assert.equal(result.overall, 'FAILED');
  assert.equal(result.stages.protection_ready.status, 'FAILED');
  assert.equal(result.stages.protection_ready.protection, 'UNCONFIRMED');
  assert.equal(core.loadedPayload(), null);
  controlStore.close();
});

test('BLOCK3 保护 REJECTED 后不得 APPLIED_VERIFIED', async () => {
  const protection = createProtectionFixture({inject: {refuse: true}});
  const {controller, controlStore, core} = await createHarness('sec-protect', {protection});
  const result = await controller.confirmAndApply({
    operation_id: 'op-protect-reject',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  assert.equal(result.code, 'PROTECTION_NOT_READY');
  assert.equal(result.overall, 'FAILED');
  assert.equal(core.loadedPayload(), null);
  controlStore.close();
});

test('BLOCK4 应急绑定进程、非递归组，限额结束仍 REJECT', async () => {
  const {controller, controlStore, core} = await createHarness('sec-em');
  const opened = await controller.requestEmergency({
    user_ref: 'user-max',
    environment_ref: ENV,
    mode: 'claude_dual_ip',
    confirmation: {confirmed: true, confirmation_id: 'em-sec'},
    targets: [{host: 'news.example', match: 'exact'}],
    duration_minutes: 15,
    operation_id: 'em-sec-open',
  });
  assert.equal(opened.process, 'firefox.exe');
  const yaml = core.loadedPayload();
  assert.match(yaml, /PROCESS-NAME,firefox.exe/);
  assert.match(yaml, /DOMAIN,news.example/);
  assert.doesNotMatch(yaml, /name: EMERGENCY-EGRESS\n    type: select\n    proxies:\n      - EMERGENCY-EGRESS/);
  assert.doesNotMatch(yaml, /DOMAIN-SUFFIX,news.example,EMERGENCY-EGRESS\n/);

  controlStore.saveQuotaSnapshot({user_ref: 'user-max', status: 'LIMITED', used_bytes: 9, limit_bytes: 9, authority_status: 'AVAILABLE', control_status: 'AVAILABLE', observed_at: '2026-09-13T17:00:00.000Z', proof_scope: 'simulation'});
  await controller.endEmergency({
    session_id: opened.session_id,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
    operation_id: 'em-sec-end',
  });
  assert.match(core.loadedPayload(), /MATCH,REJECT/);
  controlStore.close();
});

test('BLOCK5 当前连接经 T2 分类后立即保护', async () => {
  const {controller, controlStore, core} = await createHarness('sec-live');
  await controller.confirmAndApply({
    operation_id: 'op-live',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  core.setConnections([{id: 'c-live', metadata: {process: 'claude.exe', host: 'api.anthropic.com'}, chains: ['DIRECT'], upload: 3, download: 4, outcome: 'connected'}]);
  core.setTraffic({upTotal: 3, downTotal: 4});
  const live = await controller.observeLive({user_ref: 'user-max', expected: {plan_version: 'x', assignment_version: 1, classification_version: 'product-v1', matrix: {claude: {exit: 'A'}}}, environment_ref: ENV});
  assert.equal(live.events[0].classification, 'WRONG_ROUTE');
  assert.equal(live.protections[0].protection.requested, true);
  controlStore.close();
});

test('控制器把批准的完整进程路径传到 Windows 保护适配器', async () => {
  const encodedCalls = [];
  const protection = createWindowsProtectionAdapter({
    invoke: async ({encoded}) => {
      encodedCalls.push(encoded);
      return {accepted: true, effective: true, new_connections_restricted: true, readback: 'APPLIED', api: 'FwpmFilterAdd0'};
    },
  });
  const {controller, controlStore} = await createHarness('e2e-scope', {protection});
  const {assignment} = await controller.getAssignment('user-max', ENV);
  const templatePaths = [...assignment.template.protected_process_paths];
  const applied = await controller.confirmAndApply({
    operation_id: 'op-scope',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  assert.equal(applied.overall, 'APPLIED_VERIFIED');
  assert.deepEqual(encodedCalls[0].processes, templatePaths);
  const live = await controller.handleProtection({user_ref: 'user-max', environment_ref: ENV}, {
    live: true,
    source: 'live',
    classification: 'WRONG_ROUTE',
    process: 'claude.exe',
    destination: 'api.anthropic.com',
    environment_ref: ENV,
    user_ref: 'user-max',
  });
  assert.equal(live.protection.requested, true);
  assert.deepEqual(encodedCalls[1].processes, templatePaths);
  const denied = await createProtectionFixture().requestProtection({action: 'ensure_ready', environment_ref: ENV});
  assert.equal(denied.reason, 'EMPTY_PROCESS_SCOPE');
  const life = await controller.executeLifecycle({user_ref: 'user-max', environment_ref: ENV, network_enabled: true}, {type: 'core_crash'});
  assert.deepEqual(encodedCalls[2].processes, templatePaths);
  assert.equal(life.executed.some((item) => item.action === 'keep_os_protection' || item.action === 'limited_restart'), true);
  controlStore.close();
});

test('未批准 state 不能覆盖当前 Assignment 的批准范围', async () => {
  const encodedCalls = [];
  const protection = createWindowsProtectionAdapter({
    invoke: async ({encoded}) => {
      encodedCalls.push(encoded);
      return {accepted: true, effective: true, new_connections_restricted: true, readback: 'APPLIED', api: 'FwpmFilterAdd0'};
    },
  });
  const {controller, controlStore} = await createHarness('e2e-assignment-wins', {protection});
  const {assignment} = await controller.getAssignment('user-max', ENV);
  const templatePaths = [...assignment.template.protected_process_paths];
  const live = await controller.handleProtection({
    user_ref: 'user-max',
    environment_ref: ENV,
    protected_process_paths: ['C:\\Unapproved\\other.exe'],
  }, {
    live: true,
    source: 'live',
    classification: 'WRONG_ROUTE',
    process: 'claude.exe',
    destination: 'api.anthropic.com',
    environment_ref: ENV,
    user_ref: 'user-max',
  });
  assert.equal(live.protection.requested, true);
  assert.deepEqual(encodedCalls.at(-1).processes, templatePaths);
  assert.equal(encodedCalls.at(-1).processes.includes('C:\\Unapproved\\other.exe'), false);
  const life = await controller.executeLifecycle({
    user_ref: 'user-max',
    environment_ref: ENV,
    network_enabled: true,
    protected_process_paths: ['C:\\Unapproved\\other.exe'],
  }, {type: 'core_crash'});
  assert.deepEqual(encodedCalls.at(-1).processes, templatePaths);
  assert.equal(life.executed.some((item) => item.action === 'keep_os_protection' || item.action === 'limited_restart'), true);
  controlStore.close();
});

test('原生宿主实际发送 Mihomo 请求并注入保护 invoke', async () => {
  const {core} = await createHarness('sec-native');
  let invokeCalls = 0;
  const host = createNativeNetworkHost({
    windowsUser: 'synthetic-user',
    transport: core,
    invoke: async () => {
      invokeCalls += 1;
      return {accepted: true, effective: true, new_connections_restricted: true, readback: 'APPLIED', api: 'FwpmFilterAdd0'};
    },
  });
  const applied = await host.dispatch('ApplyNetworkPlan', {yaml: 'mode: rule\nrules:\n  - MATCH,REJECT\n'}, 'auth-native');
  assert.equal(applied.accepted, true);
  assert.equal(applied.loaded_version, null);
  assert.equal(applied.http_status, 204);
  assert.ok(applied.encoded.url.includes('/configs'));
  const emptyProtect = await host.dispatch('ProtectEnvironment', {environment_ref: ENV}, 'auth-native');
  assert.equal(emptyProtect.reason, 'EMPTY_PROCESS_SCOPE');
  assert.equal(emptyProtect.new_connections_restricted, false);
  assert.equal(invokeCalls, 0);
  const protectedResult = await host.dispatch('ProtectEnvironment', {
    environment_ref: ENV,
    processes: ['C:\\Program Files\\Claude\\claude.exe', 'C:\\Program Files\\Claude\\claude-browser.exe'],
  }, 'auth-native');
  assert.equal(protectedResult.new_connections_restricted, true);
  assert.equal(invokeCalls, 1);
  assert.equal(YAML_LIBRARY.name, 'js-yaml');
  assert.equal(YAML_LIBRARY.version, '4.3.0');
});

test('产品 HostState 工厂与 run() 同一装配，Apply/Protect 都到达适配器', async () => {
  const httpCalls = [];
  const wfpCalls = [];
  const state = createProductHostState({
    windowsUser: 'synthetic-user',
    send: async (request) => {
      httpCalls.push(request);
      if (request.method === 'PUT') return {status: 204, body: null};
      return {status: 200, body: {mode: 'rule', tun: {enable: true}, rules: []}};
    },
    wfpInvoke: async (encoded) => {
      wfpCalls.push(encoded);
      return {accepted: true, effective: true, new_connections_restricted: true, readback: 'APPLIED', api: 'FwpmFilterAdd0'};
    },
  });
  assert.equal(state.factory, 'product');
  assert.equal(state.transport.kind, 'http-mihomo');
  assert.equal(state.protection.kind, 'windows-wfp');
  const applied = await dispatchHostState(state, 'ApplyNetworkPlan', {yaml: 'mode: rule\n'}, 'auth-product');
  const emptyProtect = await dispatchHostState(state, 'ProtectEnvironment', {environment_ref: ENV, processes: []}, 'auth-product');
  assert.equal(emptyProtect.reason, 'EMPTY_PROCESS_SCOPE');
  assert.equal(emptyProtect.new_connections_restricted, false);
  const protectedResult = await dispatchHostState(state, 'ProtectEnvironment', {environment_ref: ENV, processes: ['C:\\Program Files\\Claude\\claude.exe']}, 'auth-product');
  assert.equal(applied.factory, 'product');
  assert.equal(applied.accepted, true);
  assert.equal(applied.http_status, 204);
  assert.equal(httpCalls.some((item) => item.method === 'PUT' && item.url.includes('/configs')), true);
  assert.equal(wfpCalls.length, 1);
  assert.equal(wfpCalls[0].apis.includes('FwpmFilterAdd0'), true);
  assert.deepEqual(wfpCalls[0].processes, ['C:\\Program Files\\Claude\\claude.exe']);
  assert.equal(protectedResult.encoded.processes.length, 1);
  assert.equal(protectedResult.factory, 'product');
  assert.equal(protectedResult.new_connections_restricted, true);
  assert.notEqual(protectedResult.reason, 'NATIVE_INVOKE_NOT_CONFIGURED');
});
