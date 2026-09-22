import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readdir, readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {AUTHORIZATION_SCOPES, OPS, PRODUCT_CONFIG_FIELDS, assertPayload, checkIssuedAuthorization} from '../../apps/desktop-host/bridge-contract.mjs';
import {createCoreFixture, createVerifyFixture} from '../../src/adapters/network/index.mjs';
import {RECORD} from '../../src/core/network/constants.mjs';
import {
  createNativeCorePort,
  createNativeEmergencyHost,
  createNativeProtectionPort,
  summarizeRuntime,
} from '../../src/adapters/network/nativePorts.mjs';
import {auth, createHarness, ENV} from '../../fixtures/network/harness.mjs';
import {createServiceBridgeDouble} from './serviceBridgeDouble.mjs';

/**
 * RC3：产品网络服务拥有 Mihomo、受管配置与 WFP，页面只经业务操作消费服务回执。
 * 前两组是源码与契约的静态核对；其余用例经 serviceBridgeDouble 验证页面端口与业务核心的消费，
 * 服务侧判定由用例设定。它们都不证明 Rust 已编译或运行。
 */

const SERVICE_ROOT = 'apps/desktop-host/vendor/service-ipc';
const HOST_SRC = 'apps/desktop-host/src-tauri/src';
const UPSTREAM_ROOT = 'experiments/p0-desktop/service-ipc-b964ed2992599fadefd589425c1acdabcb875623';
const SERVICE_COMMANDS = [
  'Handshake', 'ObserveRuntime', 'ValidateConfig', 'ApplyConfig', 'EnsureProtection', 'ReadProtection',
  'CloseManagedConnections', 'StartCore', 'StopCoreForMaintenance', 'RestoreLastValid', 'OpenEmergencyRoute', 'CloseEmergencyRoute',
];
const FORBIDDEN = ['clash-verge', 'clash_verge', 'verge-mihomo', '127.0.0.1:9090', 'localhost:9090'];
const CLOCK = () => '2026-09-13T17:00:00.000Z';

async function walk(directory, filter) {
  const found = [];
  for (const entry of await readdir(directory, {withFileTypes: true})) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) found.push(...(await walk(full, filter)));
    else if (filter(entry.name)) found.push(full);
  }
  return found;
}

/** 来源说明写在注释里是允许的；核对的是实际代码与清单条目。 */
function codeOnly(text, marker) {
  return text.split('\n').filter((line) => !line.trim().startsWith(marker)).join('\n');
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function nativeHarness(label) {
  const core = createCoreFixture();
  const bridge = createServiceBridgeDouble({environmentRef: ENV, core, clock: CLOCK});
  const ports = {invoke: bridge.invoke, confirm: bridge.confirm, environmentRef: ENV, clock: CLOCK};
  const harness = await createHarness(label, {
    core: createNativeCorePort(ports),
    protection: createNativeProtectionPort(ports),
    emergencyHost: createNativeEmergencyHost(ports),
    verify: createVerifyFixture(),
  });
  await harness.emergencyHost.refresh();
  return {...harness, kernel: core, bridge};
}

function apply(controller, operationId, mode, extra = {}) {
  return controller.confirmAndApply({
    operation_id: operationId,
    userRef: 'user-max',
    environmentRef: ENV,
    mode,
    authorization: auth('user-max', extra),
  });
}

test('RC3 Task1 产品命名空间：服务、程序、pipe、状态目录与测试身份都不沿用上游，固定来源未被改动', async () => {
  const paths = await readFile(`${SERVICE_ROOT}/src/core/paths.rs`, 'utf8');
  const constants = [...paths.matchAll(/pub const ([A-Z_]+): &str = r?"([^"]*)";/g)].map((match) => [match[1], match[2]]);
  const names = constants.map(([name]) => name);
  for (const required of ['PRODUCT_APP_ID', 'SERVICE_NAME', 'SERVICE_EXE', 'SERVICE_PIPE', 'CORE_PIPE', 'TEST_SERVICE_PIPE', 'STATE_DIR_NAME', 'PROTOCOL']) {
    assert.ok(names.includes(required), `缺少产品常量 ${required}`);
  }
  for (const [name, value] of constants) {
    assert.equal(FORBIDDEN.some((marker) => value.toLowerCase().includes(marker)), false, `${name} = ${value}`);
    assert.equal(value.includes('9090'), false, `${name} 指向默认控制器端口`);
  }
  const value = (name) => constants.find(([key]) => key === name)[1];
  assert.equal(value('PRODUCT_APP_ID'), 'local.ai-environmental-steward.desktop');
  assert.equal(value('SERVICE_NAME'), 'ai_environmental_steward_service');
  assert.equal(value('SERVICE_EXE'), 'ai-environmental-steward-service.exe');
  assert.equal(value('SERVICE_PIPE'), String.raw`\\.\pipe\ai-environmental-steward-service`);
  assert.equal(value('CORE_PIPE'), String.raw`\\.\pipe\ai-environmental-steward-mihomo`);
  assert.notEqual(value('TEST_SERVICE_PIPE'), value('SERVICE_PIPE'));

  for (const manifest of [`${SERVICE_ROOT}/Cargo.toml`, 'apps/desktop-host/src-tauri/Cargo.toml']) {
    const text = codeOnly(await readFile(manifest, 'utf8'), '#');
    assert.equal(/\bgit\s*=/.test(text), false, `${manifest} 不得保留漂移的 Git 依赖`);
    assert.equal(FORBIDDEN.some((marker) => text.toLowerCase().includes(marker)), false, `${manifest} 带上游身份`);
  }
  const hostManifest = await readFile('apps/desktop-host/src-tauri/Cargo.toml', 'utf8');
  assert.match(hostManifest, /steward-service-ipc = \{ path = "\.\.\/vendor\/service-ipc", features = \["client"\] \}/);
  const productSources = [
    ...(await walk(`${SERVICE_ROOT}/src`, (name) => name.endsWith('.rs'))),
    ...(await walk(HOST_SRC, (name) => name.endsWith('.rs'))),
  ].filter((file) => !file.endsWith(`core${path.sep}paths.rs`));
  for (const file of productSources) {
    const text = codeOnly(await readFile(file, 'utf8'), '//');
    assert.equal(FORBIDDEN.some((marker) => text.toLowerCase().includes(marker)), false, `${file} 出现上游身份或默认控制器地址`);
  }

  const source = JSON.parse(await readFile(`${UPSTREAM_ROOT}/SOURCE.json`, 'utf8'));
  const vendoredLicense = await readFile(`${SERVICE_ROOT}/LICENSE`);
  assert.equal(sha256(vendoredLicense), source.license.sha256.toLowerCase(), 'GPL LICENSE 逐字节保留');
  const upstream = await readFile(`${SERVICE_ROOT}/UPSTREAM.md`, 'utf8');
  assert.ok(upstream.includes(source.commit) && upstream.includes(source.declared_version), 'UPSTREAM.md 记录版本与提交');
  for (const file of source.files) {
    const bytes = await readFile(path.join(UPSTREAM_ROOT, source.source_root, file.path));
    assert.equal(sha256(bytes), file.sha256.toLowerCase(), `固定来源 ${file.path} 被改动`);
  }
});

test('RC3 Task2-4 所有权：GUI 进程不直连 Mihomo、不调 WFP，服务 pipe 不再世界可写，页面看不到服务命令', async () => {
  const hostFiles = await walk(HOST_SRC, (name) => name.endsWith('.rs'));
  for (const file of hostFiles) {
    const text = await readFile(file, 'utf8');
    assert.equal(text.includes('fwpuclnt'), false, `${file} 仍在 GUI 进程里调用 WFP`);
    assert.equal(/STEWARD_MIHOMO_BASE|STEWARD_NATIVE_WFP|STEWARD_CORE_CONTROLLER_URL/.test(text), false, `${file} 仍由环境变量决定连接或执行`);
    assert.equal(text.includes('/configs'), false, `${file} 仍自己拼 Mihomo 控制接口`);
  }
  for (const removed of ['http_transport.rs', 'mihomo.rs', 'protection.rs', 'wfp.rs']) {
    assert.equal(hostFiles.some((file) => file.endsWith(removed)), false, `${removed} 应已移出宿主`);
  }
  const commands = await readFile(`${HOST_SRC}/commands.rs`, 'utf8');
  assert.ok(commands.includes('"ProtectEnvironment" => crate::network_runtime::protect_environment'));
  assert.ok(commands.includes('"NetworkLifecycle" => crate::network_runtime::network_lifecycle'));
  const runtime = await readFile(`${HOST_SRC}/network_runtime.rs`, 'utf8');
  assert.ok(runtime.includes('"ok": effective'), 'ProtectEnvironment 外层 ok 必须反映真实保护结果');

  const wfp = await readFile(`${SERVICE_ROOT}/src/core/wfp.rs`, 'utf8');
  assert.ok(wfp.includes('FwpmFilterGetByKey0'), '服务按过滤器回读判定生效');
  const server = codeOnly(await readFile(`${SERVICE_ROOT}/src/core/server.rs`, 'utf8'), '//');
  assert.equal(server.includes('D:(A;;GA;;;WD)'), false, '服务 pipe 不能沿用 Everyone 全权 ACL');
  assert.ok(server.includes('service_pipe_sddl('));
  const manager = await readFile(`${SERVICE_ROOT}/src/core/manager.rs`, 'utf8');
  assert.ok(manager.includes('CORE_BINARY_MISSING') && manager.includes('LISTEN_NAMEDPIPE_SDDL') && manager.includes('CLASH_OVERRIDE_SECRET'));
  assert.equal(/\.arg\("-secret"\)/.test(manager), false, 'secret 不进命令行');
  const command = await readFile(`${SERVICE_ROOT}/src/core/command.rs`, 'utf8');
  for (const name of SERVICE_COMMANDS) assert.ok(command.includes(`ServiceCommand::${name} => "${name}"`), `服务命令表缺少 ${name}`);

  for (const name of SERVICE_COMMANDS) assert.equal(Object.hasOwn(OPS, name), false, `页面契约不得暴露服务命令 ${name}`);
  assert.ok(PRODUCT_CONFIG_FIELDS.includes('network_service'));
  assert.equal(PRODUCT_CONFIG_FIELDS.includes('core_controller_url'), false, '页面不再拿内核地址');
  const pageFiles = [
    ...(await walk('apps/desktop-ui', (name) => /\.(mjs|js)$/.test(name) && name !== 'app.bundle.js')),
    ...(await walk('src', (name) => name.endsWith('.mjs'))),
  ];
  const pattern = new RegExp(`\\b(${SERVICE_COMMANDS.filter((name) => name !== 'Handshake').join('|')})\\b`);
  for (const file of pageFiles) {
    const text = await readFile(file, 'utf8');
    assert.equal(pattern.test(text), false, `${file} 引用了服务命令`);
  }
  const productRuntime = await readFile('apps/desktop-ui/product-runtime.mjs', 'utf8');
  assert.equal(/core_controller_(url|secret)|controllerUrl/.test(productRuntime), false, '正式装配不再建内核直连');
});

test('RC3 Task5 契约拒绝旧形态载荷、任意路径与错环境，停止管理只能用单独确认', () => {
  assert.throws(() => assertPayload('ApplyNetworkPlan', {yaml: 'mode: rule\n'}), {code: 'NATIVE_PAYLOAD_INVALID'}, '只传 yaml 的旧形态必须被拒');
  assert.equal(OPS.ApplyNetworkPlan.payload.some((field) => /path|file/.test(field)), false, '页面不能把文件路径交给服务');
  assert.deepEqual(OPS.ProtectEnvironment.payload, ['operation_id', 'environment_ref', 'action', 'processes', 'loopback_policy', 'reason_code']);
  const protection = {authorization_ref: 'nat-p', scope: 'preauthorized_protection', environment_ref: ENV, confirmed: true, expires_at: '2026-09-14T00:00:00.000Z'};
  const wrongEnvironment = checkIssuedAuthorization('ApplyNetworkPlan', {environment_ref: 'wsl-guest'}, protection, CLOCK(), 'nat-p');
  assert.equal(wrongEnvironment.code, 'NATIVE_AUTHORIZATION_TARGET_MISMATCH');
  const missingEnvironment = checkIssuedAuthorization('ProtectEnvironment', {}, protection, CLOCK(), 'nat-p');
  assert.equal(missingEnvironment.code, 'NATIVE_AUTHORIZATION_TARGET_MISMATCH');
  const stopWithPreauthorization = checkIssuedAuthorization('NetworkLifecycle', {environment_ref: ENV, event: 'stop_management'}, protection, CLOCK(), 'nat-p');
  assert.equal(stopWithPreauthorization.code, 'NATIVE_AUTHORIZATION_SCOPE_INVALID');
  assert.equal(checkIssuedAuthorization('NetworkLifecycle', {environment_ref: ENV, event: 'restore_last_valid'}, protection, CLOCK(), 'nat-p'), null);
  assert.equal(AUTHORIZATION_SCOPES.stop_management.single_use, true);
  assert.deepEqual(AUTHORIZATION_SCOPES.stop_management.ops, ['NetworkLifecycle']);
});

test('RC3 Task3/5 配置阶段逐项呈现：服务回读不通过就 FAILED 并恢复 last-valid，不把 204 当生效', async () => {
  const {controller, kernel, bridge, controlStore} = await nativeHarness('rc3-stages');
  const first = await apply(controller, 'rc3-apply-1', 'claude_dual_ip');
  assert.equal(first.overall, 'APPLIED_VERIFIED', JSON.stringify(first));
  assert.equal(first.stages.downloaded.status, 'OK');
  assert.equal(first.stages.validated.status, 'OK');
  assert.equal(first.stages.loaded.status, 'HTTP_ACCEPTED');
  assert.equal(first.stages.service_verified.status, 'OK');
  const ops = bridge.calls.map((item) => item.op);
  assert.ok(ops.indexOf('ProtectEnvironment') < ops.indexOf('ApplyNetworkPlan'), '保护先于配置加载');
  const sent = bridge.calls.find((item) => item.op === 'ApplyNetworkPlan').payload;
  assert.equal(sent.expected_config_sha256, sha256(sent.yaml));
  assert.ok(sent.plan_version.startsWith(`plan:${sent.assignment_version}:`));
  assert.equal(typeof sent.assignment_version, 'string');
  const verifiedPayload = kernel.loadedPayload();

  bridge.verdicts.readback = 'VERIFY_FAILED';
  const failed = await apply(controller, 'rc3-apply-2', 'claude_single_ip');
  assert.equal(failed.overall, 'FAILED');
  assert.equal(failed.code, 'VERIFY_FAILED');
  assert.equal(failed.stages.loaded.status, 'HTTP_ACCEPTED', '内核已接受 204');
  assert.equal(failed.stages.service_verified.status, 'FAILED', '204 之后回读不通过就不是生效');
  assert.equal(failed.restore.status, 'RESTORED');
  const restore = bridge.calls.find((item) => item.op === 'NetworkLifecycle' && item.payload.event === 'restore_last_valid');
  assert.ok(restore, '失败后由服务重新加载它回读确认过的 last-valid');
  assert.equal(kernel.loadedPayload(), verifiedPayload);
  assert.equal(controlStore.getApplyReceipt('rc3-apply-2')?.expected?.yaml, undefined, '回执不带完整配置');
  controlStore.close();
});

test('RC3 Task4/5 保护未确认不放行、不显示已生效；关闭既有连接只在新连接阻断确认后单独执行', async () => {
  const {controller, kernel, bridge, controlStore} = await nativeHarness('rc3-protect');
  kernel.setConnections([{id: 'c1', metadata: {host: 'claude.ai', process: 'claude.exe'}, chains: ['DIRECT']}]);
  bridge.verdicts.protectionEffective = false;
  const blocked = await apply(controller, 'rc3-protect-apply', 'claude_single_ip');
  assert.equal(blocked.overall, 'FAILED');
  assert.equal(blocked.code, 'PROTECTION_NOT_READY');
  assert.equal(kernel.loadedPayload(), null, '保护未确认时不加载配置');
  assert.equal(bridge.calls.some((item) => item.op === 'ApplyNetworkPlan'), false);

  const state = {user_ref: 'user-max', environment_ref: ENV};
  const weak = await controller.handleProtection(state, {classification: 'WRONG_ROUTE', live: true, environment_ref: ENV});
  assert.notEqual(weak.protection.status, 'CONFIRMED');
  assert.equal(weak.protection.new_connections_restricted, false);
  assert.equal(kernel.state.connections.length, 1, '阻断没确认就不关连接冒充保护');

  bridge.verdicts.protectionEffective = true;
  const strong = await controller.handleProtection(state, {classification: 'WRONG_ROUTE', live: true, environment_ref: ENV, event_ref: 'incident-2'});
  assert.equal(strong.protection.status, 'CONFIRMED');
  assert.equal(strong.protection.existing_closed, true);
  assert.equal(strong.protection.waited_for_ai, false);
  assert.equal(kernel.state.connections.length, 0);
  const protect = bridge.calls.filter((item) => item.op === 'ProtectEnvironment').at(-1).payload;
  assert.equal(protect.action, 'block_new');
  assert.equal(protect.reason_code, 'WRONG_ROUTE');
  assert.ok(protect.processes.every((item) => /^[A-Z]:\\/.test(item)), '保护范围是绝对程序路径');
  controlStore.close();
});

test('RC3 Task5 服务不可达时六类状态都是未知、不直连；控制端离线继续用仍有效的分配，过期就停', async () => {
  const {controller, kernel, bridge, control, controlStore, clock} = await nativeHarness('rc3-offline');
  bridge.verdicts.reachable = false;
  const unknown = await controller.readState({userRef: 'user-max', environmentRef: ENV});
  assert.equal(unknown.runtime.service.status, 'UNREACHABLE');
  assert.equal(unknown.runtime.service.code, 'SERVICE_UNREACHABLE');
  for (const category of ['core', 'config', 'readback', 'protection', 'emergency']) {
    assert.equal(unknown.runtime[category].status, 'UNKNOWN', `${category} 不能拿缓存补`);
  }
  const refused = await apply(controller, 'rc3-offline-apply', 'daily_single_ip');
  assert.equal(refused.overall, 'FAILED');
  assert.equal(kernel.loadedPayload(), null);

  bridge.verdicts.reachable = true;
  control.setOffline(true);
  const cached = await apply(controller, 'rc3-cached', 'claude_single_ip', {expires_at: '2032-01-01T00:00:00.000Z'});
  assert.equal(cached.overall, 'APPLIED_VERIFIED', '控制端离线时同一用户仍有效的分配可以继续');
  const continued = kernel.loadedPayload();
  clock.set('2027-02-01T00:00:00.000Z');
  const expired = await apply(controller, 'rc3-expired', 'claude_dual_ip', {expires_at: '2032-01-01T00:00:00.000Z'});
  assert.equal(expired.overall, 'FAILED');
  assert.equal(expired.code, 'ASSIGNMENT_EXPIRED');
  assert.equal(kernel.loadedPayload(), continued, '过期分配不下发新配置');
  controlStore.close();
});

test('RC3 Task5 手动应急：路径未就绪不启动浏览器；就绪后回执带 Claude 约束与关闭读回', async () => {
  const {controller, bridge, controlStore} = await nativeHarness('rc3-emergency');
  const assignment = (await controller.getAssignment('user-max', ENV)).assignment;
  const request = (id) => ({
    user_ref: 'user-max',
    environment_ref: ENV,
    assignment,
    mode: 'claude_dual_ip',
    confirmation: {confirmed: true, confirmation_id: `em-${id}`},
    targets: [{host: 'news.example'}],
    duration_minutes: 15,
    operation_id: `rc3-em-${id}`,
    session_id: `rc3-session-${id}`,
  });
  bridge.verdicts.routeReady = false;
  await assert.rejects(() => controller.requestEmergency(request('a')), {code: 'EMERGENCY_ROUTE_ABSENT'});
  assert.equal(bridge.calls.filter((item) => item.op === 'EmergencyOpen').length, 1);

  bridge.verdicts.routeReady = true;
  const opened = await controller.requestEmergency(request('b'));
  assert.equal(opened.host_opened, true);
  assert.equal(opened.host_status, 'ACTIVE');
  assert.equal(opened.route_ready, true);
  assert.equal(opened.claude_protected, true);
  const openCall = bridge.calls.filter((item) => item.op === 'EmergencyOpen').at(-1);
  assert.equal(openCall.payload.environment_ref, ENV);
  const openIndex = bridge.calls.indexOf(openCall);
  const applyIndex = bridge.calls.map((item) => item.op).lastIndexOf('ApplyNetworkPlan', openIndex);
  assert.ok(applyIndex >= 0 && applyIndex < openIndex, '应急配置先下发并回读，再启动浏览器');

  assert.equal(bridge.service.lastValid.sha !== bridge.service.emergencySha, true, '应急临时配置不进 last-valid');

  const closed = await controller.endEmergency({session_id: 'rc3-session-b'});
  assert.equal(closed.host_close.ok, true);
  assert.equal(closed.host_close.readback, 'CLOSED', '服务结束浏览器并换回基线，规则不再存在');
  assert.equal(closed.host_close.route.closed_safely, true);
  assert.equal(closed.mainline_restored_claim, false);
  controlStore.close();
});

test('RC3-R5 应急关闭没确认时会话不算结束，到期清扫再试；关闭确认后才写结束', async () => {
  const {controller, bridge, controlStore, clock, adapter} = await nativeHarness('rc3-fix-emergency-close');
  const assignment = (await controller.getAssignment('user-max', ENV)).assignment;
  const opened = await controller.requestEmergency({
    user_ref: 'user-max',
    environment_ref: ENV,
    assignment,
    mode: 'claude_dual_ip',
    confirmation: {confirmed: true, confirmation_id: 'em-fix'},
    targets: [{host: 'news.example'}],
    duration_minutes: 15,
    operation_id: 'rc3-fix-em',
    session_id: 'rc3-fix-session',
  });
  assert.equal(opened.host_opened, true);

  bridge.verdicts.emergencyCloseConfirmed = false;
  const failed = await controller.endEmergency({session_id: 'rc3-fix-session'});
  assert.equal(failed.visible_error, 'PROCESS_TERMINATE_FAILED_5');
  assert.equal(failed.ended_at, undefined, '浏览器没结束就不写结束时间');
  assert.notEqual(failed.open, false);

  bridge.verdicts.emergencyCloseConfirmed = true;
  clock.set('2026-09-13T17:20:00.000Z');
  await controller.readState({userRef: 'user-max', environmentRef: ENV});
  const swept = adapter.getRecord('rc3-fix-session', RECORD.EMERGENCY);
  assert.equal(swept.ended_reason, 'EXPIRED', '到期清扫重新关闭');
  assert.equal(swept.open, false);
  assert.equal(swept.host_close.route.closed_safely, true);
  controlStore.close();
});

test('RC3-R2 保护未确认时维护不停内核：客户端不发命令；绕过客户端直接调服务同样拒绝', async () => {
  const {controller, kernel, bridge, controlStore} = await nativeHarness('rc3-fix-maintenance');
  assert.equal((await apply(controller, 'rc3-fix-maint-apply', 'claude_single_ip')).overall, 'APPLIED_VERIFIED');
  const base = {user_ref: 'user-max', environment_ref: ENV, network_enabled: true};

  bridge.verdicts.protectionEffective = false;
  const before = bridge.calls.filter((item) => item.op === 'NetworkLifecycle').length;
  const refused = await controller.executeLifecycle(base, {type: 'maintenance_start'});
  assert.equal(bridge.calls.filter((item) => item.op === 'NetworkLifecycle').length, before, '客户端层：保护失败后不发 StopCoreForMaintenance');
  const step = refused.executed.find((item) => item.action === 'stop_core_for_maintenance');
  assert.equal(step.code, 'PROTECTION_NOT_CONFIRMED');
  assert.equal(step.core_stopped, false);
  assert.equal(step.protection_retained, false);
  assert.equal(refused.effects.core_stopped, false);
  assert.equal(kernel.state.alive, true);

  const reference = (await bridge.confirm({scope: 'preauthorized_protection', environment_ref: ENV, reuse: true})).authorization_ref;
  const direct = await bridge.invoke('NetworkLifecycle', {operation_id: 'rc3-fix-bypass', environment_ref: ENV, event: 'maintenance_start'}, reference);
  assert.equal(direct.ok, false, '服务层（契约替身，按 Rust 服务的门槛回话）：绕过客户端也不停');
  assert.equal(direct.code, 'PROTECTION_NOT_EFFECTIVE');
  assert.equal(direct.receipt.core_stopped, false);
  assert.equal(kernel.state.alive, true);

  bridge.verdicts.protectionEffective = true;
  const stopped = await controller.executeLifecycle(base, {type: 'maintenance_start'});
  const done = stopped.executed.find((item) => item.action === 'stop_core_for_maintenance');
  assert.equal(done.core_stopped, true);
  assert.equal(done.protection_retained, true, '回执区分内核已停与保护保持');
  controlStore.close();
});

test('RC3-R5 重启后分配已过期就不恢复 last-valid；未过期的正常恢复不回归', async () => {
  const {controller, bridge, controlStore, clock} = await nativeHarness('rc3-fix-restart');
  assert.equal((await apply(controller, 'rc3-fix-restart-apply', 'claude_single_ip', {expires_at: '2032-01-01T00:00:00.000Z'})).overall, 'APPLIED_VERIFIED');
  const base = {user_ref: 'user-max', environment_ref: ENV, network_enabled: true};
  const restores = () => bridge.calls.filter((item) => item.op === 'NetworkLifecycle' && item.payload.event === 'restore_last_valid').length;

  const normal = await controller.executeLifecycle(base, {type: 'restart', authorization: auth('user-max', {expires_at: '2032-01-01T00:00:00.000Z'})});
  assert.equal(normal.executed.find((item) => item.action === 'load_last_valid_unrevoked').overall, 'RESTORED');
  assert.equal(restores(), 1);

  clock.set('2027-02-01T00:00:00.000Z');
  const expired = await controller.executeLifecycle(base, {type: 'restart', authorization: auth('user-max', {expires_at: '2032-01-01T00:00:00.000Z'})});
  const step = expired.executed.find((item) => item.action === 'load_last_valid_unrevoked');
  assert.equal(step.overall, 'FAILED');
  assert.equal(step.code, 'ASSIGNMENT_EXPIRED');
  assert.equal(restores(), 1, '过期分配不让服务重新加载 last-valid');
  controlStore.close();
});

test('RC3 Task4 生命周期：关窗不碰服务；唤醒先读回再保护；维护与停止管理走独立动作', async () => {
  const {controller, bridge, controlStore} = await nativeHarness('rc3-lifecycle');
  const base = {user_ref: 'user-max', environment_ref: ENV, network_enabled: true};
  const before = bridge.calls.length;
  const closed = controller.advanceLifecycle(base, {type: 'close_window'});
  assert.equal(closed.effects.core_stopped, false);
  assert.equal(closed.effects.protection.service_unaffected, true);
  assert.equal(bridge.calls.length, before, '窗口关闭不调用任何网络操作');

  const woke = await controller.executeLifecycle(base, {type: 'wake', authorization: auth('user-max')});
  assert.deepEqual(woke.executed.slice(0, 2).map((item) => item.action), ['read_back', 'protection_first']);

  const maintenance = await controller.executeLifecycle(base, {type: 'maintenance_start'});
  assert.deepEqual(maintenance.executed.map((item) => item.action), ['keep_os_protection', 'stop_core_for_maintenance']);
  assert.equal(bridge.calls.filter((item) => item.op === 'NetworkLifecycle').at(-1).payload.event, 'maintenance_start');

  bridge.verdicts.businessRunning = true;
  const busy = await controller.executeLifecycle(base, {type: 'stop_management'});
  assert.equal(busy.effects.protection_released, false);
  const stopConfirmation = bridge.confirmations.filter((item) => item.scope === 'stop_management').at(-1);
  assert.equal(stopConfirmation.native_op, 'NetworkLifecycle', '停止管理每次单独确认');
  bridge.verdicts.businessRunning = false;
  const stopped = await controller.executeLifecycle(base, {type: 'stop_management'});
  assert.equal(stopped.effects.protection_released, true);
  assert.equal(bridge.confirmations.filter((item) => item.scope === 'stop_management').length, 2);
  controlStore.close();
});

test('RC3 Task5 实时连接与日志经服务读取；六类状态带稳定错误码，不含配置正文或 secret', async () => {
  const {controller, kernel, bridge, controlStore} = await nativeHarness('rc3-live');
  assert.equal((await apply(controller, 'rc3-live-apply', 'claude_single_ip')).overall, 'APPLIED_VERIFIED');
  kernel.setConnections([{id: 'c9', metadata: {host: 'claude.ai', process: 'claude.exe'}, chains: ['EXIT-A', 'PROXY-A', 'CLAUDE-FIXED'], upload: 5, download: 9}]);
  const live = await controller.observeLive({user_ref: 'user-max', environment_ref: ENV});
  assert.ok(live.events.length >= 1);
  const reads = bridge.calls.filter((item) => item.op === 'ReadNetworkState').map((item) => item.payload.include);
  assert.ok(reads.some((include) => include.includes('connections')), '连接快照经服务读取');

  const state = await controller.readState({userRef: 'user-max', environmentRef: ENV});
  assert.deepEqual(Object.keys(state.runtime).sort(), ['config', 'core', 'emergency', 'missing', 'protection', 'readback', 'service'].sort());
  assert.equal(state.runtime.readback.status, 'VERIFIED');
  assert.equal(state.runtime.protection.status, 'EFFECTIVE');
  const text = JSON.stringify(state.runtime);
  for (const secret of ['synth-pass', 'password', 'sha256', 'proxies:', 'secret']) assert.equal(text.includes(secret), false, `状态摘要不能带 ${secret}`);

  bridge.verdicts.readback = 'VERIFY_FAILED';
  await apply(controller, 'rc3-live-fail', 'claude_dual_ip');
  bridge.service.lastVerdict = 'VERIFY_FAILED';
  const failed = summarizeRuntime((await bridge.invoke('ReadNetworkState', {environment_ref: ENV, include: []})).runtime);
  assert.equal(failed.readback.code, 'VERIFY_FAILED');
  assert.deepEqual(failed.readback.failed_checks, ['rules']);
  assert.equal(summarizeRuntime({service: {status: 'RUNNING'}, core: {running: false, binary_present: false}}).core.code, 'CORE_BINARY_MISSING');
  controlStore.close();
});
