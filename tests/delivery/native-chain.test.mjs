import assert from 'node:assert/strict';
import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {OPS, PRODUCT_CONFIG_FIELDS, opNames, opsForGroup} from '../../apps/desktop-host/bridge-contract.mjs';
import {createProductRuntimeOptions} from '../../apps/desktop-ui/product-runtime.mjs';
import {installNativeSteward} from '../../apps/desktop-ui/native.mjs';
import {SYNTHETIC_ENVIRONMENT} from '../local/demo.mjs';
import {createPageRuntime} from '../ui/page.mjs';
import {composition} from './harness.mjs';
import {createNativeHostDouble} from './nativeHostDouble.mjs';
import {PERSISTED_MAX_SESSION, createHostFetch, readyControl, withIdentityRoutes} from './productHost.mjs';
import {createBridgeWorkspaceAdapter} from '../../src/adapters/local/bridgeWorkspace.mjs';

const CONTROL_BASE_URL = 'https://control.synthetic.invalid';
const CORE_CONTROLLER_URL = 'http://127.0.0.1:9797';
const PROBE_SERVICES = {
  'synthetic-windows': {
    echo_url: `${CONTROL_BASE_URL}/probe/host/ip`,
    doh_url: `${CONTROL_BASE_URL}/probe/host/dns-query`,
    probe_base_url: `${CONTROL_BASE_URL}/probe/host`,
    client_kind: 'webview',
  },
  'wsl-synthetic': {
    echo_url: `${CONTROL_BASE_URL}/probe/wsl/ip`,
    doh_url: `${CONTROL_BASE_URL}/probe/wsl/dns-query`,
    probe_base_url: `${CONTROL_BASE_URL}/probe/wsl`,
    client_kind: 'wsl-cli',
    webrtc: false,
  },
};
const PROBE_PROFILES = {
  host: {ip: '198.51.100.8', resolver: '192.0.2.53', asn: 'AS64500', org: 'SYNTHETIC-HOST'},
  wsl: {ip: '198.51.100.24', resolver: '192.0.2.61', asn: 'AS64501', org: 'SYNTHETIC-GUEST'},
};
const EMERGENCY_HOSTS = [
  {id: 'browser-firefox', kind: 'second_browser', process: 'firefox.exe', installed: true, distinguishable: true, approved: true},
  {id: 'webview-shared', kind: 'shared_webview', process: 'msedgewebview2.exe', installed: true, distinguishable: false, approved: false},
];

const SETTINGS = 'input/code/settings.json';

async function waitFor(page, predicate, timeoutMs = 8000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const snap = await page.window.__STEWARD__.snapshot();
    if (!snap?.__unavailable__ && predicate(snap)) return snap;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('timed out waiting for the formal page state');
}

/**
 * 正式页面按产品路径启动：测试只摆宿主边界——受限原生桥、WebView 的 fetch 与 localStorage。
 * 控制端地址、受管内核地址、声明环境与身份全部由产品代码自己从 DescribeCapabilities 取。
 */
async function formalPage(label) {
  const prepared = await composition(label);
  const root = prepared.root;
  const double = createNativeHostDouble({
    workspaceRoot: root,
    clock: prepared.clock,
    emergencyHosts: EMERGENCY_HOSTS,
    product: {
      control_base_url: CONTROL_BASE_URL,
      core_controller_url: CORE_CONTROLLER_URL,
      windows_user: 'synthetic-user',
      environment_ref: prepared.env,
      environments: prepared.environments,
      environment: SYNTHETIC_ENVIRONMENT,
      control: readyControl(CONTROL_BASE_URL),
    },
    session: PERSISTED_MAX_SESSION,
    network: {
      readState: async () => ({general: {mode: 'rule'}, loaded_version: null}),
      apply: async () => ({accepted: true}),
      protect: async () => ({status: 'CONFIRMED', new_connections_restricted: true}),
    },
  });
  const hostFetch = createHostFetch({
    controlBaseUrl: CONTROL_BASE_URL,
    controlHandler: withIdentityRoutes(prepared, {probeServices: PROBE_SERVICES}),
    coreControllerUrl: CORE_CONTROLLER_URL,
    core: prepared.core,
    probes: PROBE_PROFILES,
  });

  const page = await createPageRuntime(`${label}-page`, {
    hostPrimitives: {
      __TAURI__: {core: {invoke: (command, args) => {
        if (command === 'steward_user_confirm') return double.confirm(args.request);
        assert.equal(command, 'steward_request', '写命令只经 steward_request，授权只经 steward_user_confirm');
        return double.invoke(args.op, args.payload, args.authorizationRef);
      }}},
      fetch: hostFetch,
      navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true, hardwareConcurrency: 8, cookieEnabled: true},
      RTCPeerConnection: null,
    },
  });
  return {prepared, double, page, root, hostFetch};
}

test('契约：commands.rs 与 registered_ops 同契约一致，没有一揽子未接入分支', async () => {
  const source = await readFile(path.resolve('apps/desktop-host/src-tauri/src/commands.rs'), 'utf8');
  const lib = await readFile(path.resolve('apps/desktop-host/src-tauri/src/lib.rs'), 'utf8');

  const fnStart = lib.indexOf('pub fn registered_ops');
  const body = lib.slice(fnStart, lib.indexOf('\n}', fnStart));
  const declared = [...body.matchAll(/"([A-Za-z]+)"/g)].map((item) => item[1]);
  assert.deepEqual(declared.slice().sort(), opNames().sort(), 'registered_ops 必须与契约完全一致，不多不少');

  for (const op of opNames()) {
    assert.ok(source.includes(`"${op}" =>`), `commands.rs 必须处理 ${op}`);
  }
  assert.ok(!source.includes('UiAction'), '旧的一揽子 UiAction 必须撤掉');
  assert.ok(!lib.includes('UiAction'));
  assert.ok(source.includes('NATIVE_OP_UNKNOWN'), '未知操作必须有明确错误码');
  assert.ok(source.includes('NATIVE_AUTHORIZATION_REQUIRED'), '写入类操作必须要求授权引用');

  const confirmSource = await readFile(path.resolve('apps/desktop-host/src-tauri/src/confirm.rs'), 'utf8');
  const cargoSource = await readFile(path.resolve('apps/desktop-host/src-tauri/Cargo.toml'), 'utf8');
  const libSource = lib;
  const workspaceSource = await readFile(path.resolve('apps/desktop-host/src-tauri/src/workspace.rs'), 'utf8');
  assert.ok(lib.includes('steward_user_confirm'), 'lib.rs 必须注册本地确认命令');
  assert.ok(source.includes('pub fn user_confirm'), 'commands.rs 必须实现 steward_user_confirm');
  assert.ok(source.includes('workspace::authorization_load'), '写命令必须按引用读宿主自己签发的记录');
  assert.ok(source.includes('authorization_ref: Option<&str>'), '写命令只收引用字符串');
  assert.equal(source.includes('authorization: Option<&Value>'), false, '写命令不得再接收授权内容');
  assert.ok(source.includes('NATIVE_AUTHORIZATION_UNKNOWN'), '未签发的引用必须有明确错误码');
  assert.ok(confirmSource.includes('ConfirmationPrompt'), '确认必须绑定本地用户交互');
  assert.ok(confirmSource.includes('NATIVE_CONFIRMATION_UI_UNAVAILABLE'), '没有窗口时不得退化成自动同意');
  assert.ok(confirmSource.includes('tauri_plugin_dialog'), 'Tauri v2 的对话框在独立插件里');
  assert.ok(confirmSource.includes('DialogExt'), 'v2 经 DialogExt 取得对话框');
  assert.equal(confirmSource.includes('tauri::api::dialog'), false, 'v1 的 tauri::api::dialog 路径在 v2 不存在');
  assert.ok(confirmSource.includes('the host did not compose a prompt body'), '宿主没拼好正文时必须报错，不得退回调用方说明');
  assert.ok(cargoSource.includes('tauri-plugin-dialog'), 'Cargo.toml 必须声明对话框插件');
  assert.ok(libSource.includes('tauri_plugin_dialog::init()'), '插件必须在 Builder 上初始化');
  assert.ok(source.includes('&state.vault_root'), '授权记录必须读写保险库，不是工作区');
  assert.equal(source.includes('authorization_load(&state.workspace_root'), false, '授权库不得落在受限桥可写的工作区里');
  assert.ok(source.includes('.vault_lock'), '校验与消费必须在同一把锁内');
  assert.ok(source.includes('authorization_consume'), '一次性授权必须原子消费');
  assert.ok(source.includes('NATIVE_AUTHORIZATION_OP_MISMATCH'), '授权必须绑定精确原生操作');
  assert.ok(workspaceSource.includes('pub fn hmac_sha256'), '授权记录需要宿主侧完整性标签');
  assert.ok(workspaceSource.includes('NATIVE_AUTHORIZATION_STORE_TAMPERED'), '签名对不上必须整本作废');
  assert.equal(workspaceSource.includes('resolve(root, \"state/native-authorizations.json\")'), false, '保险库不经工作区路径解析');
  assert.equal(source.includes('probe_services'), false, '探测服务地址由控制端下发，宿主不再回报');
  assert.equal(PRODUCT_CONFIG_FIELDS.includes('probe_services'), false, '探测服务不是宿主的产品配置');
  assert.ok(/"unimplemented": unimplemented_capabilities\(state[,)]/.test(source), '未接入能力必须如实回报，不得写死空数组');

  const cargo = await readFile(path.resolve('apps/desktop-host/src-tauri/Cargo.toml'), 'utf8');
  assert.ok(cargo.includes('rusqlite'), '数据库能力组需要的依赖必须写进 Cargo.toml');
  assert.ok(opsForGroup('databases').length >= 5);
  for (const [name, spec] of Object.entries(OPS)) {
    assert.ok(typeof spec.group === 'string' && Array.isArray(spec.payload), `${name} 契约定义不完整`);
  }
});

test('正式页面经 bridge.js 与受限原生桥可取得快照并跑完本地处理', async () => {
  const {prepared, double, page, root} = await formalPage('native-local');
  assert.ok(typeof page.window.__STEWARD__ === 'object', '正式页面必须拿到 __STEWARD__');

  const initial = await page.window.__STEWARD__.snapshot();
  assert.ok(!initial.__unavailable__, JSON.stringify(initial));
  assert.equal(initial.userRef, 'user-max', '身份来自服务端会话');
  assert.equal(initial.nativeBridge, true);

  await page.click('scanDeep');
  const scanned = await waitFor(page, (snap) => snap.local.identities.length >= 2);
  assert.ok(scanned.local.scan_id);
  assert.ok(double.calls.some((item) => item.op === 'FileWalk'), '扫描必须经受限原生桥读文件');
  assert.ok(double.calls.some((item) => item.op === 'RecordSave'), '记录必须落到原生记录库');

  for (const identity of scanned.local.identities) {
    const value = identity.identity_ref === 'restricted-account' ? 'restricted' : 'normal';
    const input = page.document.querySelectorAll('input').find((item) => item.name === `account-${identity.identity_ref}` && item.value === value);
    input.click();
  }
  await waitFor(page, (snap) => Object.keys(snap.local.answers).length >= scanned.local.identities.length);
  await page.click('localClassify');
  await waitFor(page, (snap) => snap.local.problems.length > 0);
  await page.click('localBuildPlan');
  await waitFor(page, (snap) => Boolean(snap.local.plan_id));
  await page.click('localConfirm');
  await waitFor(page, (snap) => snap.local.plan_status === 'CONFIRMED');
  page.document.getElementById('confirmBox').checked = true;

  const before = await readFile(path.join(root, SETTINGS), 'utf8');
  await page.click('localExecute');
  const executed = await waitFor(page, (snap) => ['completed', 'partial'].includes(snap.local.operation_status));
  assert.equal(executed.local.error, null);
  assert.equal(executed.local.operation_status, 'completed');
  assert.notEqual(await readFile(path.join(root, SETTINGS), 'utf8'), before, '正式链路必须真的改到目标文件');
  assert.ok(double.calls.some((item) => item.op === 'DbMutate'), 'Cookie/CC Switch 改写必须经数据库能力组');
  assert.ok(double.calls.some((item) => item.op === 'FileWrite' && item.authorizationRef), '写入必须带授权引用');
  page.close();
  prepared.close();
});

test('正式页面经原生桥读回 T2 产物并导出，四模块入口都可操作', async () => {
  const {prepared, double, page} = await formalPage('native-modules');

  await page.click('refreshTraffic');
  const traffic = await waitFor(page, (snap) => Boolean(snap.traffic.daily?.reportId));
  assert.equal(traffic.traffic.daily.routeResult, 'FAIL');
  assert.ok(traffic.traffic.history.length >= 2, '历史来自原生桥读回的 T2 报告清单');
  assert.ok(double.calls.some((item) => item.op === 'FileWalk'));

  await page.click('exportDailyJson');
  const exported = await waitFor(page, (snap) => Boolean(snap.traffic.export?.jsonPath));
  assert.ok(exported.traffic.export.jsonPath.startsWith('exports/'), '导出经原生桥写到工作区内');
  const exportedBytes = await double.adapter.readBytes(exported.traffic.export.jsonPath);
  assert.equal(new TextDecoder().decode(exportedBytes), await prepared.auditStore.readText(exported.traffic.export.sourceJson));

  await page.click('tabDiag');
  await page.click('diagScan');
  const diag = await waitFor(page, (snap) => Boolean(snap.diag.task_id) || Boolean(snap.diag.error));
  assert.equal(page.window.__STEWARD_SESSION__ === undefined, true);
  assert.ok(diag.diag.task_id || diag.diag.error, '诊断入口有确定结果');

  await page.click('applyDaily');
  const network = await waitFor(page, (snap) => Boolean(snap.network.apply) || Boolean(snap.network.error));
  assert.ok(network.network.apply || network.network.error, '网络方案入口有确定结果');
  page.close();
  prepared.close();
});

test('正式启动路径只吃宿主原语：没有预置配置，也没有一揽子旧通道', async () => {
  const boot = await readFile(path.resolve('apps/desktop-ui/native-boot.mjs'), 'utf8');
  const bridge = await readFile(path.resolve('apps/desktop-ui/bridge.js'), 'utf8');
  assert.equal(boot.includes('__STEWARD_CONFIG__'), false, '启动脚本不得依赖仓库里不存在的预置配置');
  assert.ok(boot.includes('bootNativeSteward'), '启动脚本必须走产品装配入口');
  assert.equal(bridge.includes('UiAction'), false, 'bridge.js 不得退回已从 Rust 删掉的一揽子操作');
  assert.ok(bridge.includes('UI_BACKEND_BOOT_INCOMPLETE'), '桥在位但未装配时要点名，不得静默');

  const {prepared, page, hostFetch, double} = await formalPage('native-boot');
  const report = page.window.__STEWARD_HOST_REPORT__;
  assert.ok(report, '产品装配必须留下宿主回报');
  assert.equal(report.contract, 'steward-bridge-1');
  assert.equal(report.windows_user, 'synthetic-user', '安装信息只能来自宿主');
  assert.equal(report.emergency_candidates, EMERGENCY_HOSTS.length, '应急候选来自宿主枚举');
  assert.equal(EMERGENCY_HOSTS.filter((item) => item.approved).length, 1, '只有可区分的第二浏览器可被批准');
  assert.ok(double.calls.some((item) => item.op === 'DescribeCapabilities'), '运行配置必须经契约取得');
  assert.ok(
    hostFetch.calls.some((item) => item.path === '/api/auth/me'),
    '身份必须向控制端的 /api/auth/me 取，不在本地假设',
  );
  assert.equal(hostFetch.calls.some((item) => item.path === '/api/admin/resources'), false, '角色不再靠探测管理接口推断');
  assert.equal(page.window.localStorage.getItem('steward-session'), null, '会话材料不进 localStorage');
  assert.equal(report.account_phase, 'authenticated');
  const snapshot = await page.window.__STEWARD__.snapshot();
  assert.equal(snapshot.__unavailable__, undefined, JSON.stringify(snapshot));
  assert.equal(snapshot.env, prepared.env, '声明环境来自宿主，不是页面自选');
  page.close();
  prepared.close();
});

test('没有受限原生桥时正式页面点名未接入，不返回未知操作', async () => {
  const page = await createPageRuntime('native-detached', {hostPrimitives: {fetch: async () => { throw new Error('no network'); }}});
  const snapshot = await page.window.__STEWARD__?.snapshot?.();
  if (snapshot) {
    assert.equal(snapshot.__unavailable__?.code, 'UI_BACKEND_NOT_ATTACHED');
    assert.notEqual(snapshot.__unavailable__?.code, 'NATIVE_OP_UNKNOWN');
  } else {
    assert.equal(page.window.__STEWARD__, null, '没有桥就不装配客户端');
  }
  page.close();
});

/** 跑完一次完整的本地处理，返回执行后的页面与宿主替身。 */
async function runLocalCleanup(label) {
  const context = await formalPage(label);
  const {page} = context;
  await page.click('scanDeep');
  const scanned = await waitFor(page, (snap) => snap.local.identities.length >= 2);
  for (const identity of scanned.local.identities) {
    const value = identity.identity_ref === 'restricted-account' ? 'restricted' : 'normal';
    page.document.querySelectorAll('input').find((item) => item.name === `account-${identity.identity_ref}` && item.value === value).click();
  }
  await waitFor(page, (snap) => Object.keys(snap.local.answers).length >= scanned.local.identities.length);
  await page.click('localClassify');
  await waitFor(page, (snap) => snap.local.problems.length > 0);
  await page.click('localBuildPlan');
  await waitFor(page, (snap) => Boolean(snap.local.plan_id));
  await page.click('localConfirm');
  await waitFor(page, (snap) => snap.local.plan_status === 'CONFIRMED');
  page.document.getElementById('confirmBox').checked = true;
  await page.click('localExecute');
  const executed = await waitFor(page, (snap) => ['completed', 'partial'].includes(snap.local.operation_status));
  return {...context, executed};
}

test('授权只能由原生签发：写入带的是宿主签发的引用，记录留在原生侧', async () => {
  const {prepared, double, page} = await runLocalCleanup('native-authorization');

  const objectWrites = double.calls.filter((item) => item.op === 'FileWrite' && item.scope === 'single_confirmation');
  assert.ok(objectWrites.length > 0, '改用户对象必须走单次确认授权');
  for (const write of objectWrites) {
    assert.ok(typeof write.authorizationRef === 'string', '发给原生的只是一个引用字符串');
    const record = double.issuedAuthorizations.get(write.authorizationRef);
    assert.ok(record, `${write.authorizationRef} 必须在宿主的签发表里`);
    assert.equal(record.confirmed, true, '记录必须带本地确认');
    assert.ok(record.plan_ref && record.plan_version !== undefined, '授权必须绑定计划与版本');
    assert.ok(record.action_id && record.action, '授权必须绑定具体动作');
    assert.ok(record.target?.path, '授权必须绑定目标对象');
    assert.ok('expected_sha256' in record, '指纹由宿主自己测量后写进记录');
    assert.ok(Date.parse(record.expires_at) > Date.parse(record.issued_at), '授权必须有期限');
  }
  assert.ok(
    double.confirmations.some((item) => item.scope === 'single_confirmation'),
    '每次改用户对象前都真的走过一次本地确认',
  );
  assert.ok(
    double.calls.filter((item) => item.op === 'RecordSave').every((item) => item.scope === 'workspace_owned'),
    '应用自有记录走首次范围授权，不冒用单次确认',
  );
  page.close();
  prepared.close();
});

/** 为对抗用例签发一条全新的单次确认，避免复用已被消费的引用。 */
async function issueFor(double, target, nativeOp, extra = {}) {
  return double.confirm({
    scope: 'single_confirmation',
    plan_ref: 'plan-adversarial',
    plan_version: 1,
    action_id: `action-${nativeOp}`,
    action: 'json_set',
    native_op: nativeOp,
    target: {path: target, kind: 'json_set'},
    ...extra,
  });
}

test('结构完整但未经原生签发的授权，在写入之前就被拒', async () => {
  const {prepared, double, page, root} = await runLocalCleanup('native-forged-authorization');
  const objectWrites = double.calls.filter((item) => item.op === 'FileWrite' && item.scope === 'single_confirmation');
  const good = double.issuedAuthorizations.get(objectWrites.at(-1).authorizationRef);
  const target = good.target.path;
  const bytes = 'eyJvayI6dHJ1ZX0=';
  const before = await readFile(path.join(root, target), 'utf8');

  // 复核给出的反向对照：完全不做用户确认，自填一份结构完整的授权直接写。
  const confirmationsBefore = double.confirmations.length;
  const inline = await double.invoke('FileWrite', {path: target, bytes}, {
    authorization_ref: 'ui-session',
    scope: 'single_confirmation',
    confirmed: true,
    plan_ref: good.plan_ref,
    plan_version: good.plan_version,
    action_id: good.action_id,
    action: good.action,
    native_op: 'FileWrite',
    target: good.target,
    expected_sha256: await double.adapter.fingerprint(target),
    issued_at: prepared.clock(),
    expires_at: '2099-01-01T00:00:00.000Z',
  });
  assert.equal(inline.code, 'NATIVE_AUTHORIZATION_REQUIRED', '写命令根本不收授权内容，只收引用');
  assert.equal(double.confirmations.length, confirmationsBefore, '这条路径上没有发生任何用户确认');

  const guessed = await double.invoke('FileWrite', {path: target, bytes}, `nat-${'f'.repeat(32)}`);
  assert.equal(guessed.code, 'NATIVE_AUTHORIZATION_UNKNOWN', '猜一个引用也命中不了保险库');

  const bare = await double.invoke('FileWrite', {path: target, bytes}, null);
  assert.equal(bare.code, 'NATIVE_AUTHORIZATION_REQUIRED', '没有引用必须被拒');

  const ownedRef = double.calls.find((item) => item.scope === 'workspace_owned')?.authorizationRef;
  assert.ok(ownedRef, '会话范围引用也是宿主签发的');
  const crossScope = await double.invoke('FileWrite', {path: target, bytes}, ownedRef);
  assert.equal(crossScope.code, 'NATIVE_AUTHORIZATION_TARGET_MISMATCH', '会话范围不得用来改用户对象');

  const forOther = await issueFor(double, target, 'FileWrite');
  const otherObject = await double.invoke('FileWrite', {path: 'input/code/user-settings.json', bytes}, forOther.authorization_ref);
  assert.equal(otherObject.code, 'NATIVE_AUTHORIZATION_TARGET_MISMATCH', '一次确认不得改到别的对象');

  assert.equal(await readFile(path.join(root, target), 'utf8'), before, '以上全部被拒，目标文件始终未变');
  page.close();
  prepared.close();
});

test('一次确认绑定一个精确原生操作：拿它调别的操作不成立', async () => {
  const {prepared, double, page, root} = await runLocalCleanup('native-op-binding');
  const objectWrites = double.calls.filter((item) => item.op === 'FileWrite' && item.scope === 'single_confirmation');
  const target = double.issuedAuthorizations.get(objectWrites.at(-1).authorizationRef).target.path;
  const before = await readFile(path.join(root, target), 'utf8');

  // 复核演示的那一条：对 json_set 的确认引用调用 FileRemove。
  const issued = await issueFor(double, target, 'FileWrite');
  const removed = await double.invoke('FileRemove', {path: target}, issued.authorization_ref);
  assert.equal(removed.code, 'NATIVE_AUTHORIZATION_OP_MISMATCH', 'FileWrite 的确认不得用来删文件');
  assert.equal(await readFile(path.join(root, target), 'utf8'), before, '目标文件必须还在');

  const copied = await double.invoke('FileCopy', {from: target, to: 'backups/stolen.json'}, issued.authorization_ref);
  assert.equal(copied.code, 'NATIVE_AUTHORIZATION_OP_MISMATCH', '也不得用来复制');

  // 确认请求本身也要点名一个属于该范围的原生操作。
  const bogus = await issueFor(double, target, 'RecordsLoad');
  assert.equal(bogus.code, 'NATIVE_AUTHORIZATION_SCOPE_INVALID', '单次确认不得点名范围外的操作');
  page.close();
  prepared.close();
});

test('一次确认只用一次：同一引用第二次调用被拒，内容相同也不例外', async () => {
  const {prepared, double, page, root} = await runLocalCleanup('native-replay');
  const objectWrites = double.calls.filter((item) => item.op === 'FileWrite' && item.scope === 'single_confirmation');
  const target = double.issuedAuthorizations.get(objectWrites.at(-1).authorizationRef).target.path;

  const issued = await issueFor(double, target, 'FileWrite');
  const current = await readFile(path.join(root, target), 'utf8');
  const unchanged = Buffer.from(current, 'utf8').toString('base64');

  const first = await double.invoke('FileWrite', {path: target, bytes: unchanged}, issued.authorization_ref);
  assert.equal(first.ok, true, '第一次写入按授权放行');
  // 复核演示的那一条：内容没变，同一引用再写一次。
  const second = await double.invoke('FileWrite', {path: target, bytes: unchanged}, issued.authorization_ref);
  assert.equal(second.code, 'NATIVE_AUTHORIZATION_CONSUMED', '同一引用不得重放，哪怕写的内容一样');

  const consumed = double.issuedAuthorizations.get(issued.authorization_ref);
  assert.ok(consumed.consumed_at, '消费状态必须落进记录');
  assert.equal(consumed.consumed_by_op, 'FileWrite', '记录要留下它被哪个操作用掉');

  // 执行链路上每条单次授权都恰好被用掉一次。
  const singleUse = double.issuedAuthorizations.list().filter((row) => row.scope === 'single_confirmation' && row.consumed_at);
  assert.ok(singleUse.length > 0);
  assert.equal(new Set(singleUse.map((row) => row.authorization_ref)).size, singleUse.length, '引用不重复');
  page.close();
  prepared.close();
});

test('授权保险库在受限桥之外，且被篡改后整本作废', async () => {
  const {prepared, double, page, root} = await runLocalCleanup('native-vault');
  const objectWrites = double.calls.filter((item) => item.op === 'FileWrite' && item.scope === 'single_confirmation');
  const target = double.issuedAuthorizations.get(objectWrites.at(-1).authorizationRef).target.path;

  // 保险库不在受限工作区内：桥的路径解析根本到不了。
  assert.ok(!path.resolve(double.vaultFile).startsWith(path.resolve(root) + path.sep), '授权库不得落在桥可写的工作区内');
  // 即使拿到最宽的那条会话范围授权，也越不出工作区。
  const ownedRef = double.calls.find((item) => item.scope === 'workspace_owned')?.authorizationRef;
  const escapeByScope = await double.invoke('FileWrite', {path: '../vault/authorizations.json', bytes: 'e30='}, ownedRef);
  assert.equal(escapeByScope.code, 'NATIVE_AUTHORIZATION_TARGET_MISMATCH', '会话范围只覆盖应用自有目录');
  const escapeGrant = await issueFor(double, '../vault/authorizations.json', 'FileWrite');
  const escapeByGrant = await double.invoke('FileWrite', {path: '../vault/authorizations.json', bytes: 'e30='}, escapeGrant.authorization_ref);
  assert.equal(escapeByGrant.code, 'NATIVE_PATH_OUT_OF_SCOPE', '专门为保险库签的授权也越不出工作区');

  // 写 state/ 下的同名文件改不到真正的授权库。
  const decoy = await double.invoke('FileWrite', {path: 'state/native-authorizations.json', bytes: 'eyJhdXRob3JpemF0aW9ucyI6W119'}, ownedRef);
  assert.equal(decoy.ok, true, '工作区内的同名文件只是一个普通文件');
  const stillGood = await issueFor(double, target, 'FileWrite');
  const afterDecoy = await double.invoke('FileWrite', {path: target, bytes: 'eyJvayI6dHJ1ZX0='}, stillGood.authorization_ref);
  assert.equal(afterDecoy.ok, true, '写工作区里的同名文件影响不了真正的授权库');

  // 直接篡改保险库：宿主签名对不上，整本作废。
  const fresh = await issueFor(double, target, 'FileWrite');
  const vault = JSON.parse(await readFile(double.vaultFile, 'utf8'));
  const index = vault.authorizations.findIndex((row) => row.authorization_ref === fresh.authorization_ref);
  vault.authorizations[index] = {...vault.authorizations[index], target: {path: 'input/code/user-settings.json', kind: 'json_set'}};
  await writeFile(double.vaultFile, JSON.stringify(vault, null, 2), 'utf8');
  const tampered = await double.invoke('FileWrite', {path: 'input/code/user-settings.json', bytes: 'eyJvayI6dHJ1ZX0='}, fresh.authorization_ref);
  assert.equal(tampered.code, 'NATIVE_AUTHORIZATION_STORE_TAMPERED', '改过的记录不得被接受');

  // 插入一条自造的 confirmed 记录同样不成立。
  const forged = JSON.parse(await readFile(double.vaultFile, 'utf8'));
  forged.authorizations.push({
    authorization_ref: 'nat-forged-0000000000000000000000000000',
    scope: 'single_confirmation',
    confirmed: true,
    consumed_at: null,
    plan_ref: 'plan-forged',
    plan_version: 1,
    action_id: 'action-forged',
    action: 'json_set',
    native_op: 'FileWrite',
    target: {path: target, kind: 'json_set'},
    expected_sha256: await double.adapter.fingerprint(target),
    issued_at: prepared.clock(),
    expires_at: '2099-01-01T00:00:00.000Z',
    mac: 'f'.repeat(64),
  });
  await writeFile(double.vaultFile, JSON.stringify(forged, null, 2), 'utf8');
  const inserted = await double.invoke('FileWrite', {path: target, bytes: 'eyJvayI6dHJ1ZX0='}, 'nat-forged-0000000000000000000000000000');
  assert.equal(inserted.code, 'NATIVE_AUTHORIZATION_STORE_TAMPERED', '插入的记录过不了账本签名');
  page.close();
  prepared.close();
});

test('确认窗口展示的是宿主测得的事实，调用方说明只是单独一行', async () => {
  const {prepared, double, page} = await runLocalCleanup('native-prompt');
  const prompt = double.confirmations.find((item) => item.scope === 'single_confirmation');
  assert.ok(prompt, '改用户对象前必须弹过确认');
  assert.ok(prompt.body, '正文必须由宿主拼好');
  assert.ok(prompt.body.includes(prompt.target.path), '正文必须点名宿主测得的目标');
  assert.ok(prompt.body.includes(prompt.native_op), '正文必须点名将要执行的原生操作');
  assert.ok(prompt.body.includes(prompt.observed_sha256), '正文必须给出宿主自己测得的指纹');
  assert.ok(prompt.body.includes(prompt.expires_at), '正文必须给出有效期');
  assert.ok(prompt.body.includes('未经本机核实'), '调用方说明必须标明未经核实');
  assert.ok(prompt.body.indexOf('未经本机核实') > prompt.body.indexOf(prompt.target.path), '调用方说明排在宿主事实之后');

  // 调用方的 summary 换成误导文案，宿主展示的事实不受影响。
  const misleading = await double.confirm({
    scope: 'single_confirmation',
    plan_ref: 'plan-misleading',
    plan_version: 1,
    action_id: 'action-misleading',
    action: 'json_set',
    native_op: 'FileWrite',
    target: {path: prompt.target.path, kind: 'json_set'},
    summary: '这只是一次无害的只读检查',
  });
  assert.ok(misleading.authorization_ref);
  const shown = double.confirmations.at(-1);
  assert.ok(shown.body.includes('原生操作：FileWrite'), '误导性说明改变不了宿主展示的原生操作');
  assert.ok(shown.body.includes(prompt.target.path), '误导性说明改变不了宿主展示的目标');
  page.close();
  prepared.close();
});

test('记录真的落盘之后才发布完成状态：写入未完成或失败都不报 completed', async () => {
  const prepared = await composition('native-persist');
  let released = null;
  const gate = new Promise((resolve) => { released = resolve; });
  let held = false;
  const double = createNativeHostDouble({
    workspaceRoot: prepared.root,
    clock: prepared.clock,
    emergencyHosts: EMERGENCY_HOSTS,
    product: {
      control_base_url: CONTROL_BASE_URL,
      core_controller_url: CORE_CONTROLLER_URL,
      windows_user: 'synthetic-user',
      environment_ref: prepared.env,
      environments: prepared.environments,
      environment: SYNTHETIC_ENVIRONMENT,
      control: readyControl(CONTROL_BASE_URL),
    },
    network: {
      readState: async () => ({general: {mode: 'rule'}, loaded_version: null}),
      apply: async () => ({accepted: true}),
      protect: async () => ({status: 'CONFIRMED', new_connections_restricted: true}),
    },
    hooks: {
      RecordSave: async () => {
        if (held) return null;
        held = true;
        await gate;
        return {ok: false, code: 'NATIVE_IO_FAILED', reason: 'synthetic disk failure on the first record write'};
      },
    },
  });

  const store = await createBridgeWorkspaceAdapter({invoke: double.invoke, confirm: double.confirm, clock: prepared.clock});
  const saved = store.saveRecord('operation', 'op-1', {status: 'completed'});
  assert.equal(saved.id, 'op-1', 'saveRecord 仍是同步接口，不改已验收的 T3 契约');
  assert.equal(store.pendingWrites(), 1, '异步写入必须被记在未完成集合里');

  let flushed = null;
  const flushing = store.flush().then(() => { flushed = true; }, (error) => { flushed = error.code; });
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(flushed, null, 'flush 必须等未完成的原生写入，不得立刻返回');

  released();
  await flushing;
  assert.equal(flushed, 'NATIVE_IO_FAILED', '原生写入失败必须在 flush 时暴露');
  assert.equal(store.pendingWrites(), 0);
  assert.throws(() => store.saveRecord('operation', 'op-2', {}), (error) => error.code === 'NATIVE_IO_FAILED');
  prepared.close();
});

test('执行完成的操作带着落盘确认返回，重开后读回的记录就带 records_persisted', async () => {
  const {prepared, double, page, root, executed} = await runLocalCleanup('native-persist-ok');
  assert.equal(executed.local.operation_status, 'completed');

  const persisted = JSON.parse(await readFile(path.join(root, 'state', 'native-records.json'), 'utf8'));
  const operations = persisted.records.filter((row) => row.type === 'operation');
  assert.ok(operations.length > 0, '完成状态发布时，操作记录必须已经在原生记录库里');
  const completed = operations.filter((row) => row.payload.status === 'completed');
  assert.ok(completed.length > 0, '落盘的记录必须与页面报告的完成状态一致');
  assert.ok(
    completed.every((row) => row.payload.records_persisted === true),
    '落盘确认本身也要写进记录，重开后能严格读到 true',
  );

  const reopened = await createBridgeWorkspaceAdapter({invoke: double.invoke, confirm: double.confirm, clock: prepared.clock});
  const reopenedOperations = reopened.listRecords('operation').filter((row) => row.status === 'completed');
  assert.ok(reopenedOperations.length > 0, '重开后能读回已完成的操作');
  assert.ok(reopenedOperations.every((row) => row.records_persisted === true), '重开后 records_persisted 严格为 true');
  assert.ok(reopened.listRecords('plan').length > 0, '重开后计划仍在');
  page.close();
  prepared.close();
});

test('正式组合根按环境换探测端口：主机与客体证据不同，没有端口的环境被拒', async () => {
  const prepared = await composition('native-environments');
  const double = createNativeHostDouble({
    workspaceRoot: prepared.root,
    clock: prepared.clock,
    emergencyHosts: EMERGENCY_HOSTS,
    product: {
      control_base_url: CONTROL_BASE_URL,
      core_controller_url: CORE_CONTROLLER_URL,
      windows_user: 'synthetic-user',
      environment_ref: prepared.env,
      environments: prepared.environments,
      environment: SYNTHETIC_ENVIRONMENT,
      control: readyControl(CONTROL_BASE_URL),
    },
    session: PERSISTED_MAX_SESSION,
    network: {
      readState: async () => ({general: {mode: 'rule'}, loaded_version: null}),
      apply: async () => ({accepted: true}),
      protect: async () => ({status: 'CONFIRMED', new_connections_restricted: true}),
    },
  });
  const options = await createProductRuntimeOptions({
    invoke: double.invoke,
    confirm: double.confirm,
    fetchImpl: createHostFetch({
      controlBaseUrl: CONTROL_BASE_URL,
      controlHandler: withIdentityRoutes(prepared, {probeServices: PROBE_SERVICES}),
      coreControllerUrl: CORE_CONTROLLER_URL,
      core: prepared.core,
      probes: PROBE_PROFILES,
    }),
    navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true},
    clock: prepared.clock,
  });
  assert.equal(typeof options.environmentPorts, 'function', '正式组合根必须拿到分环境端口');
  assert.deepEqual(options.hostReport.probe_environments.sort(), ['synthetic-windows', 'wsl-synthetic']);
  assert.equal(options.hostReport.probe_source, 'control', '探测服务地址来自控制端');

  const {compose} = await installNativeSteward({}, options);
  const host = await compose.diagnostics.startScan({mode: 'deep', environmentRef: 'synthetic-windows', profileRef: 'Default'});
  const guest = await compose.diagnostics.startScan({mode: 'deep', environmentRef: 'wsl-synthetic', profileRef: 'Default'});

  const bare = (result) => result.observations
    .filter((item) => !item.stale)
    .map(({task_id, environment_ref, evidence_ref, observed_at, ...rest}) => JSON.stringify(rest))
    .sort();
  assert.notDeepEqual(bare(guest), bare(host), '正式组合根上，两个环境的观测证据本身必须不同');

  const hostCoverage = Object.fromEntries(host.environment_coverage.map((item) => [item.environment_ref, item]));
  const guestCoverage = Object.fromEntries(guest.environment_coverage.map((item) => [item.environment_ref, item]));
  assert.equal(hostCoverage['synthetic-windows'].status, 'MEASURED');
  assert.equal(hostCoverage['wsl-synthetic'].status, 'NOT_MEASURED');
  assert.equal(guestCoverage['wsl-synthetic'].status, 'MEASURED');
  assert.equal(guestCoverage['synthetic-windows'].status, 'NOT_MEASURED');
  assert.ok(guestCoverage['wsl-synthetic'].evidence_count > 0);

  await assert.rejects(
    () => compose.diagnostics.startScan({mode: 'deep', environmentRef: 'undeclared-environment'}),
    (error) => error.code === 'ENVIRONMENT_PROBE_UNAVAILABLE',
    '宿主没给探测端口的环境不得用主机证据冒充',
  );
  prepared.close();
});

test('控制端没有配置探测服务时，诊断按未接入点名，不拿主机端口凑数', async () => {
  const prepared = await composition('native-no-probes');
  const double = createNativeHostDouble({
    workspaceRoot: prepared.root,
    clock: prepared.clock,
    emergencyHosts: EMERGENCY_HOSTS,
    product: {
      control_base_url: CONTROL_BASE_URL,
      core_controller_url: CORE_CONTROLLER_URL,
      windows_user: 'synthetic-user',
      environment_ref: prepared.env,
      environments: prepared.environments,
      environment: SYNTHETIC_ENVIRONMENT,
      control: readyControl(CONTROL_BASE_URL),
    },
    session: PERSISTED_MAX_SESSION,
    network: {readState: async () => ({}), apply: async () => ({}), protect: async () => ({})},
  });
  const options = await createProductRuntimeOptions({
    invoke: double.invoke,
    confirm: double.confirm,
    fetchImpl: createHostFetch({controlBaseUrl: CONTROL_BASE_URL, controlHandler: withIdentityRoutes(prepared), coreControllerUrl: CORE_CONTROLLER_URL, core: prepared.core}),
    navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true},
    clock: prepared.clock,
  });
  assert.equal(options.diagnosticPorts, null, '没有探测服务就没有诊断端口');
  assert.equal(options.environmentPorts, null);
  assert.equal(options.hostReport.diagnostics_attached, false);
  assert.ok(
    options.hostReport.unimplemented.some((item) => item.startsWith('diagnostics.probe_services')),
    '能力报告必须如实说明诊断未完整接入',
  );
  const {compose} = await installNativeSteward({}, options);
  assert.equal(compose.diagnostics, null, '没有端口就不给诊断控制器，不退回主机端口');
  const {createDesktopSession} = await import('../../apps/desktop-ui/session.mjs');
  const session = createDesktopSession(compose, {sessionToken: options.sessionToken});
  const attempted = await session.diagScan('deep');
  assert.equal(attempted.diag.error?.code, 'DIAGNOSTICS_NOT_ATTACHED', '诊断入口必须点名未接入，不崩成内部错误');
  prepared.close();
});

test('正式页面的浏览器证据来自默认浏览器里的诊断页，WebView 不再自己拼样本', async () => {
  const {prepared, double, page} = await formalPage('native-default-browser');
  const steward = page.window.__STEWARD__;
  const scanned = await steward.diagScan('special', {environmentRef: prepared.env});
  assert.ok(scanned.diag.task_id, JSON.stringify(scanned.diag.error));
  const opened = await steward.diagOpenBrowser();
  assert.equal(opened.diag.browser?.status, 'WAITING', JSON.stringify(opened.diag.error));
  assert.deepEqual(double.calls.filter((call) => call.op.startsWith('BrowserDiag')).map((call) => call.op), ['BrowserDiagListen', 'BrowserDiagLaunch']);
  assert.equal(double.browserHost.opened.length, 1, '宿主只打开本监听的诊断页');

  const checked = await steward.diagCheckBrowser();
  assert.equal(checked.diag.browser.status, 'RECEIVED', JSON.stringify(checked.diag));
  assert.equal(checked.diag.receipt, true);
  assert.ok(double.calls.some((call) => call.op === 'BrowserDiagClose'), '收到回传后关闭监听');
  const source = await readFile(path.resolve('apps/desktop-ui/session.mjs'), 'utf8');
  assert.ok(!source.includes('diagnostic.synthetic.invalid'), '正式会话里不再有拼样本的来源');
  page.close();
  prepared.close();
});

test('MAJOR 只给客体配了探测服务时诊断照样挂上：客体按自己的端口诊断，宿主本机如实缺测', async () => {
  const prepared = await composition('native-guest-only-probes');
  const double = createNativeHostDouble({
    workspaceRoot: prepared.root,
    clock: prepared.clock,
    emergencyHosts: EMERGENCY_HOSTS,
    product: {
      control_base_url: CONTROL_BASE_URL,
      core_controller_url: CORE_CONTROLLER_URL,
      windows_user: 'synthetic-user',
      environment_ref: prepared.env,
      environments: prepared.environments,
      environment: SYNTHETIC_ENVIRONMENT,
      control: readyControl(CONTROL_BASE_URL),
    },
    session: PERSISTED_MAX_SESSION,
    network: {readState: async () => ({}), apply: async () => ({}), protect: async () => ({})},
  });
  const options = await createProductRuntimeOptions({
    invoke: double.invoke,
    confirm: double.confirm,
    fetchImpl: createHostFetch({
      controlBaseUrl: CONTROL_BASE_URL,
      controlHandler: withIdentityRoutes(prepared, {probeServices: {'wsl-synthetic': PROBE_SERVICES['wsl-synthetic']}}),
      coreControllerUrl: CORE_CONTROLLER_URL,
      core: prepared.core,
      probes: PROBE_PROFILES,
    }),
    navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true},
    clock: prepared.clock,
  });
  assert.equal(options.diagnosticPorts, null, '宿主本机没有探测端口');
  assert.equal(options.hostReport.diagnostics_attached, true, '有环境配了端口就算接上');
  assert.ok(options.hostReport.unimplemented.includes(`diagnostics.probe_services:${prepared.env}`), '宿主本机如实列为缺测');

  const {compose} = await installNativeSteward({}, options);
  assert.ok(compose.diagnostics, '只配了客体也有诊断控制器');
  const {createDesktopSession} = await import('../../apps/desktop-ui/session.mjs');
  const session = createDesktopSession(compose, {sessionToken: options.sessionToken});
  const guest = await session.diagScan('deep', {environmentRef: 'wsl-synthetic'});
  assert.equal(guest.diag.error, null, JSON.stringify(guest.diag.error));
  const result = compose.diagnostics.result(guest.diag.task_id);
  const coverage = Object.fromEntries(result.environment_coverage.map((item) => [item.environment_ref, item.status]));
  assert.equal(coverage['wsl-synthetic'], 'MEASURED');
  const host = await session.diagScan('deep', {environmentRef: prepared.env});
  assert.equal(host.diag.error?.code, 'ENVIRONMENT_PROBE_UNAVAILABLE', '宿主本机按缺测报，不是整体未接入');
  prepared.close();
});
