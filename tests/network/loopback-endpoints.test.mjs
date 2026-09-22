import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {OPS, assertPayload} from '../../apps/desktop-host/bridge-contract.mjs';
import {adminRequest, createQuotaHarness, handleJson} from '../../fixtures/control/harness.mjs';
import {auth, createHarness, ENV, threeUsers} from '../../fixtures/network/harness.mjs';
import {createCoreFixture, createVerifyFixture} from '../../src/adapters/network/index.mjs';
import {createNativeCorePort, createNativeEmergencyHost, createNativeProtectionPort} from '../../src/adapters/network/nativePorts.mjs';
import {compileNetworkPlan, loopbackEndpointRules} from '../../src/core/network/compile.mjs';
import {approvedProtectionScope, validateLoopbackEndpoints} from '../../src/core/network/protectedProcesses.mjs';
import {parseMihomoConfig} from '../../src/core/network/yaml.mjs';
import {defaultTemplate, publicTemplate} from '../../services/control/index.mjs';
import {createServiceBridgeDouble} from './serviceBridgeDouble.mjs';

/**
 * RC3 Round 4 裁决：回环按模板 `loopback_endpoints` 精确放行，缺失或空清单全拦。
 * 这里验证 Node 侧的模板校验、编译器、保护范围与原生载荷；WFP 过滤器与服务状态的用例在 Rust 里（本机未编译、未运行）。
 */

const CLAUDE = 'C:\\Program Files\\Claude\\claude.exe';
const BROWSER = 'C:\\Program Files\\Claude\\claude-browser.exe';
const CLOCK = () => '2026-09-13T17:00:00.000Z';
const OAUTH = Object.freeze({source_process_path: CLAUDE, transport: 'tcp', address: '127.0.0.1', port: 43123, purpose: 'oauth_callback'});

function templateWith(endpoints, extra = {}) {
  return {...defaultTemplate(), version: 'template-v2', loopback_endpoints: endpoints, ...extra};
}

function loopbackRulesOf(yaml) {
  return parseMihomoConfig(yaml).rules.filter((rule) => rule.startsWith('AND,((PROCESS-PATH,') || /127\.0\.0\.|::1/.test(rule));
}

async function nativeHarness(label, template) {
  const core = createCoreFixture();
  const bridge = createServiceBridgeDouble({environmentRef: ENV, core, clock: CLOCK});
  const ports = {invoke: bridge.invoke, confirm: bridge.confirm, environmentRef: ENV, clock: CLOCK};
  const records = threeUsers();
  for (const assignment of records.assignments) {
    assignment.template = structuredClone(template);
    assignment.template_version = template.version;
  }
  const harness = await createHarness(label, {
    records,
    core: createNativeCorePort(ports),
    protection: createNativeProtectionPort(ports),
    emergencyHost: createNativeEmergencyHost(ports),
    verify: createVerifyFixture(),
  });
  await harness.emergencyHost.refresh();
  return {...harness, bridge};
}

test('RC3-R4 模板回环端点：缺失或空清单合法且表示全拦，只收批准程序的单个精确端点', () => {
  assert.deepEqual(validateLoopbackEndpoints(undefined, [CLAUDE]), {ok: true, endpoints: []});
  assert.deepEqual(validateLoopbackEndpoints([], [CLAUDE]), {ok: true, endpoints: []});
  const accepted = validateLoopbackEndpoints([OAUTH, {...OAUTH, transport: 'udp', address: '::1', port: 5353, purpose: 'discovery'}], [CLAUDE.toUpperCase()]);
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  assert.equal(accepted.endpoints.length, 2);

  const broader = [
    ['address', '127.0.0.0/8'],
    ['address', '*'],
    ['address', 'localhost'],
    ['address', '127.000.000.001'],
    ['address', '0.0.0.0'],
    ['address', '::ffff:127.0.0.1'],
    ['address', '10.0.0.1'],
    ['port', '43000-43200'],
    ['port', '*'],
    ['port', 0],
    ['port', 65536],
    ['port', 43123.5],
    ['transport', 'any'],
    ['purpose', 'OAuth Callback'],
    ['purpose', ''],
    ['source_process_path', 'claude.exe'],
    ['source_process_path', 'C:\\Tools\\curl.exe'],
    ['source_process_path', 'C:\\Program Files\\Claude\\..\\curl.exe'],
    ['source_process_path', 'C:\\Apps\\a,b\\tool.exe'],
    ['source_process_path', 'C:\\Apps\\odd)(\\tool.exe'],
  ];
  for (const [field, value] of broader) {
    const result = validateLoopbackEndpoints([{...OAUTH, [field]: value}], [CLAUDE]);
    assert.equal(result.ok, false, `${field}=${value}`);
    assert.equal(result.code, 'LOOPBACK_ENDPOINTS_INVALID');
    assert.equal(result.path, `loopback_endpoints[0].${field}`, `${field}=${value}`);
    assert.deepEqual(result.endpoints, [], '不挑出看起来还行的项');
  }
  for (const path of ['C:\\Apps\\a,b\\tool.exe', 'C:\\Apps\\odd)(\\tool.exe']) {
    const approvedButUnexpressible = validateLoopbackEndpoints([{...OAUTH, source_process_path: path}], [path]);
    assert.equal(approvedButUnexpressible.ok, false, path);
    assert.match(approvedButUnexpressible.reason, /逗号或括号不配对/, '即使是批准程序，受管配置表达不了的路径也拒绝');
  }
  assert.equal(validateLoopbackEndpoints([{...OAUTH, source_process_path: 'C:\\Program Files (x86)\\App\\app.exe'}], ['C:\\Program Files (x86)\\App\\app.exe']).ok, true, '配对的括号可以');
  assert.equal(validateLoopbackEndpoints([{...OAUTH, port_range: '43000-43200'}], [CLAUDE]).path, 'loopback_endpoints[0].port_range');
  assert.equal(validateLoopbackEndpoints([OAUTH, {...OAUTH, purpose: 'again'}], [CLAUDE]).path, 'loopback_endpoints[1]', '同一端点不能重复');
  assert.equal(validateLoopbackEndpoints({address: '127.0.0.1'}, [CLAUDE]).ok, false);
});

test('RC3-R4 编译器：不再无条件写 127.0.0.0/8 DIRECT；精确端点生成精确规则，表达不了的端点在模板校验时拒绝', () => {
  const assignment = structuredClone(threeUsers().assignments[1]);
  const compile = () => compileNetworkPlan({assignment, mode: 'claude_single_ip', environmentScope: {environment_ref: ENV}, now: CLOCK()});

  const plain = compile();
  assert.deepEqual(loopbackRulesOf(plain.yaml), [], '默认模板空清单：不生成任何回环直连规则');

  assignment.template = templateWith([OAUTH, {source_process_path: BROWSER, transport: 'udp', address: '::1', port: 5353, purpose: 'discovery'}]);
  const exact = compile();
  const rules = parseMihomoConfig(exact.yaml).rules;
  assert.deepEqual(loopbackRulesOf(exact.yaml), [
    'AND,((PROCESS-PATH,C:\\Program Files\\Claude\\claude.exe),(IP-CIDR,127.0.0.1/32,no-resolve),(DST-PORT,43123),(NETWORK,tcp)),DIRECT',
    'AND,((PROCESS-PATH,C:\\Program Files\\Claude\\claude-browser.exe),(IP-CIDR6,::1/128,no-resolve),(DST-PORT,5353),(NETWORK,udp)),DIRECT',
  ], '程序、地址、端口、协议四项同时绑定；YAML 往返后路径原样');
  const firstLoopback = rules.findIndex((rule) => rule.startsWith('AND,((PROCESS-PATH,'));
  assert.ok(firstLoopback < rules.findIndex((rule) => rule.startsWith('PROCESS-NAME,claude.exe,')), '精确回环规则排在 Claude 进程规则之前');
  assert.ok(firstLoopback < rules.indexOf('NETWORK,udp,REJECT'), '模板点名的 UDP 回环端点排在 UDP 拒绝之前');

  const x86 = 'C:\\Program Files (x86)\\Claude\\claude.exe';
  const expressible = templateWith(
    [x86, 'C:/Program Files/Claude/claude.exe'].map((path, index) => ({...OAUTH, source_process_path: path, port: 43200 + index})),
    {protected_process_paths: [x86, 'C:/Program Files/Claude/claude.exe']},
  );
  assert.deepEqual(loopbackEndpointRules(expressible), [
    'AND,((PROCESS-PATH,C:\\Program Files (x86)\\Claude\\claude.exe),(IP-CIDR,127.0.0.1/32,no-resolve),(DST-PORT,43200),(NETWORK,tcp)),DIRECT',
    'AND,((PROCESS-PATH,C:\\Program Files\\Claude\\claude.exe),(IP-CIDR,127.0.0.1/32,no-resolve),(DST-PORT,43201),(NETWORK,tcp)),DIRECT',
  ], '配对的括号能表达；正斜杠按 Windows 进程路径写成反斜杠');
  for (const path of ['C:\\Apps\\a,b\\tool.exe', 'C:\\Apps\\odd)(\\tool.exe']) {
    const unexpressible = templateWith([{...OAUTH, source_process_path: path}], {protected_process_paths: [path]});
    assert.throws(() => loopbackEndpointRules(unexpressible), {code: 'TEMPLATE_INVALID'}, `${path}：已接受的端点不会被静默丢弃`);
  }

  assert.throws(() => loopbackEndpointRules(templateWith([{...OAUTH, address: '127.0.0.0/8'}])), {code: 'TEMPLATE_INVALID'});
  assignment.template = templateWith([{...OAUTH, port: '1-65535'}]);
  assert.throws(compile, {code: 'TEMPLATE_INVALID'}, '模板端点不合法时不编译出配置');
});

test('RC3-R4 保护范围：批准程序与回环端点取自同一份模板，端点不合法时按空清单下发', () => {
  const scope = approvedProtectionScope({template_version: 'template-v2', template: templateWith([OAUTH])});
  assert.deepEqual(scope.processes, defaultTemplate().protected_process_paths);
  assert.deepEqual(scope.loopback_policy, {template_version: 'template-v2', endpoints: [OAUTH]});

  const invalid = approvedProtectionScope({template_version: 'template-v2', template: templateWith([{...OAUTH, port: '1-65535'}])});
  assert.deepEqual(invalid.loopback_policy.endpoints, [], 'fail-closed：回环全拦');
  assert.equal(invalid.processes.length, 2, '阻断范围不受影响');

  const mixed = approvedProtectionScope({template_version: 'template-v2', template: templateWith([])}, {protected_process_paths: [CLAUDE], loopback_policy: {template_version: 'template-v1', endpoints: [OAUTH]}});
  assert.deepEqual(mixed.loopback_policy, {template_version: 'template-v2', endpoints: []}, '不跨来源拼接端点');

  const stored = approvedProtectionScope(null, {protected_process_paths: [CLAUDE], loopback_policy: {template_version: 'template-v1', endpoints: [OAUTH]}});
  assert.deepEqual(stored.loopback_policy, {template_version: 'template-v1', endpoints: [OAUTH]}, '控制端不可达时沿用状态里同一来源的策略');
  const orphan = approvedProtectionScope({protected_process_paths: [CLAUDE], loopback_policy: {endpoints: [{...OAUTH, source_process_path: BROWSER}]}});
  assert.deepEqual(orphan.loopback_policy.endpoints, [], '端点的程序不在同一来源的批准程序里');
});

test('RC3-R4 原生载荷：应用前保护与 WRONG_ROUTE 保护都把模板回环策略交给宿主，契约要求显式携带', async () => {
  const empty = await nativeHarness('loopback-empty', defaultTemplate());
  const plain = await empty.controller.confirmAndApply({operation_id: 'loopback-empty-apply', userRef: 'user-max', environmentRef: ENV, mode: 'claude_single_ip', authorization: auth('user-max')});
  assert.equal(plain.overall, 'APPLIED_VERIFIED', JSON.stringify(plain));
  const plainProtect = empty.bridge.calls.find((item) => item.op === 'ProtectEnvironment').payload;
  assert.deepEqual(plainProtect.loopback_policy, {template_version: 'template-v1', endpoints: []}, '默认模板显式下发空清单');
  assert.deepEqual(loopbackRulesOf(empty.bridge.calls.find((item) => item.op === 'ApplyNetworkPlan').payload.yaml), []);
  empty.controlStore.close();

  const {controller, bridge, controlStore} = await nativeHarness('loopback-exact', templateWith([OAUTH]));
  const applied = await controller.confirmAndApply({operation_id: 'loopback-apply', userRef: 'user-max', environmentRef: ENV, mode: 'claude_single_ip', authorization: auth('user-max')});
  assert.equal(applied.overall, 'APPLIED_VERIFIED', JSON.stringify(applied));
  const ready = bridge.calls.find((item) => item.op === 'ProtectEnvironment').payload;
  assert.deepEqual(ready.loopback_policy, {template_version: 'template-v2', endpoints: [OAUTH]});
  assert.deepEqual(ready.processes, defaultTemplate().protected_process_paths);
  assert.equal(loopbackRulesOf(bridge.calls.find((item) => item.op === 'ApplyNetworkPlan').payload.yaml).length, 1);

  const incident = await controller.handleProtection({user_ref: 'user-max', environment_ref: ENV}, {classification: 'WRONG_ROUTE', live: true, environment_ref: ENV, event_ref: 'loopback-incident'});
  assert.equal(incident.protection.status, 'CONFIRMED');
  const wrongRoute = bridge.calls.filter((item) => item.op === 'ProtectEnvironment').at(-1).payload;
  assert.equal(wrongRoute.reason_code, 'WRONG_ROUTE');
  assert.deepEqual(wrongRoute.loopback_policy, {template_version: 'template-v2', endpoints: [OAUTH]});

  assert.ok(OPS.ProtectEnvironment.payload.includes('loopback_policy'));
  const {loopback_policy: omitted, ...withoutPolicy} = wrongRoute;
  assert.ok(omitted);
  assert.throws(() => assertPayload('ProtectEnvironment', withoutPolicy), {code: 'NATIVE_PAYLOAD_INVALID'});
  const runtime = await readFile('apps/desktop-host/src-tauri/src/network_runtime.rs', 'utf8');
  assert.match(runtime, /"loopback_policy": payload\.get\("loopback_policy"\)\.cloned\(\)\.unwrap_or\(Value::Null\)/, '宿主把策略原样交给服务，缺失时服务按空清单处理');
  controlStore.close();
});

test('RC3-R4 Node 控制端：模板拒绝宽泛回环端点，公开视图带端点，端点变化按敏感变更确认', async () => {
  assert.deepEqual(defaultTemplate().loopback_endpoints, []);
  assert.deepEqual(publicTemplate(templateWith([OAUTH])).loopback_endpoints, [OAUTH]);

  const {handler, store} = await createQuotaHarness('loopback-template');
  const base = {version: 'template-v1', claude_domains: ['claude.ai'], claude_processes: ['claude.exe'], managed_browser_processes: [], protected_process_paths: [CLAUDE], lan_cidrs: [], control_plane: {}, udp_policy: 'REJECT', ipv6_policy: 'FOLLOW', dns: {nameserver: ['https://dns.steward.test/dns-query']}};
  const broad = await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {template_id: 'managed', published: true, template: {...base, loopback_endpoints: [{...OAUTH, address: '127.0.0.0/8'}]}}}));
  assert.equal(broad.body.code, 'TEMPLATE_INVALID', JSON.stringify(broad.body));
  const orphan = await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {template_id: 'managed', published: true, template: {...base, loopback_endpoints: [{...OAUTH, source_process_path: BROWSER}]}}}));
  assert.equal(orphan.body.code, 'TEMPLATE_INVALID', '端点的程序必须属于批准程序');

  const resource = {resource_id: 'res-a', role: 'A', host: 'a.example.invalid', port: 1080, sharing: 'shared', status: 'ACTIVE'};
  await handleJson(handler, adminRequest('/api/admin/resources', {method: 'PUT', body: resource}));
  const allocate = () => handleJson(handler, adminRequest('/api/admin/assignments', {method: 'POST', body: {
    userRef: 'user-jia',
    environmentRef: 'synthetic-windows',
    accountClass: 'free',
    allowedModes: ['daily_single_ip'],
    resources: [resource],
    roles: {A: 'res-a'},
    validUntil: '2027-01-01T00:00:00.000Z',
    templateId: 'managed',
  }}));
  await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {template_id: 'managed', published: true, template: base}}));
  await allocate();
  assert.equal((await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: 'user-jia'}}))).body.ok, true);

  const saved = await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {template_id: 'managed', published: true, template: {...base, version: 'template-v2', loopback_endpoints: [OAUTH]}}}));
  assert.deepEqual(saved.body.template.template.loopback_endpoints, [OAUTH]);
  await allocate();
  const sensitive = await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: 'user-jia'}}));
  assert.equal(sensitive.body.code, 'SENSITIVE_CHANGE_CONFIRMATION_REQUIRED', '新增回环放行与改批准程序同级，需要确认');
  const confirmed = await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: 'user-jia', confirmation: {confirmed: true}}}));
  assert.equal(confirmed.body.ok, true);
  const seen = await handleJson(handler, adminRequest('/api/network/assignment', {token: 'token-jia'}));
  assert.deepEqual(seen.body.assignment.template.loopback_endpoints, [OAUTH], '用户拿到的分配带端点清单');
  store.close();
});

test('RC3-R5 模板版本只认分配记录：正文版本滞后或缺失时，编译计划、保护载荷与控制端视图都用同一个版本', async () => {
  const assignment = structuredClone(threeUsers().assignments[1]);
  assignment.template_version = 'row-v9';
  for (const body of [templateWith([OAUTH], {version: 'body-v1'}), (({version, ...rest}) => rest)(templateWith([OAUTH]))]) {
    assignment.template = body;
    const plan = compileNetworkPlan({assignment, mode: 'claude_single_ip', environmentScope: {environment_ref: ENV}, now: CLOCK()});
    assert.equal(plan.template_version, 'row-v9', `正文版本 ${body.version ?? '缺失'}：编译计划用分配版本`);
    assert.equal(approvedProtectionScope(assignment).loopback_policy.template_version, 'row-v9', `正文版本 ${body.version ?? '缺失'}：保护策略用分配版本`);
    assert.equal(approvedProtectionScope({assignment}).loopback_policy.template_version, 'row-v9');
  }

  const stale = templateWith([OAUTH], {version: 'body-v1'});
  const {controller, bridge, controlStore} = await nativeHarness('loopback-version', stale);
  const record = controlStore.getAssignment('user-max');
  controlStore.saveAssignment({...record, template_version: 'row-v9'});
  const applied = await controller.confirmAndApply({operation_id: 'loopback-version-apply', userRef: 'user-max', environmentRef: ENV, mode: 'claude_single_ip', authorization: auth('user-max')});
  assert.equal(applied.overall, 'APPLIED_VERIFIED', JSON.stringify(applied));
  assert.equal(bridge.calls.find((item) => item.op === 'ProtectEnvironment').payload.loopback_policy.template_version, 'row-v9', '宿主收到的策略版本是分配版本');
  controlStore.close();

  const {handler, store} = await createQuotaHarness('loopback-version-control');
  const base = {claude_domains: ['claude.ai'], claude_processes: ['claude.exe'], managed_browser_processes: [], protected_process_paths: [CLAUDE], lan_cidrs: [], loopback_endpoints: [OAUTH], control_plane: {}, udp_policy: 'REJECT', ipv6_policy: 'FOLLOW', dns: {nameserver: ['https://dns.steward.test/dns-query']}};
  const lagging = await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {template_id: 'managed', published: true, version: 'row-v9', template: {...base, version: 'body-v1'}}}));
  assert.equal(lagging.body.template.version, 'row-v9');
  assert.equal(lagging.body.template.template.version, 'row-v9', '正文滞后的版本被记录版本覆盖');
  const missing = await handleJson(handler, adminRequest('/api/admin/templates', {method: 'PUT', body: {template_id: 'managed', published: true, template: base}}));
  assert.equal(missing.body.template.template.version, missing.body.template.version, '正文缺版本时补上记录版本');
  const legacy = store.getTemplate('managed');
  store.saveTemplate({...legacy, template: {...legacy.template, version: 'body-v0'}});
  const listed = await handleJson(handler, adminRequest('/api/admin/templates'));
  assert.equal(listed.body.templates[0].template.version, legacy.version, '规则生效前保存的滞后正文，读出时同样按记录版本');

  const resource = {resource_id: 'res-a', role: 'A', host: 'a.example.invalid', port: 1080, sharing: 'shared', status: 'ACTIVE'};
  await handleJson(handler, adminRequest('/api/admin/resources', {method: 'PUT', body: resource}));
  await handleJson(handler, adminRequest('/api/admin/assignments', {method: 'POST', body: {userRef: 'user-jia', environmentRef: 'synthetic-windows', accountClass: 'free', allowedModes: ['daily_single_ip'], resources: [resource], roles: {A: 'res-a'}, validUntil: '2027-01-01T00:00:00.000Z', templateId: 'managed'}}));
  await handleJson(handler, adminRequest('/api/admin/assignments/publish', {method: 'POST', body: {userRef: 'user-jia'}}));
  const seen = await handleJson(handler, adminRequest('/api/network/assignment', {token: 'token-jia'}));
  assert.equal(seen.body.assignment.template_version, legacy.version, '分配版本取记录版本');
  assert.equal(seen.body.assignment.template.version, seen.body.assignment.template_version, '分配冻结的正文版本与分配版本一致');
  store.close();
});
