import './offline-guard.mjs';
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {composition} from '../delivery/harness.mjs';
import {createNativeHostDouble} from '../delivery/nativeHostDouble.mjs';
import {createHostFetch, readyControl} from '../delivery/productHost.mjs';
import {SYNTHETIC_ENVIRONMENT} from '../local/demo.mjs';
import {createPageRuntime} from '../ui/page.mjs';
import {createAuthControlDouble} from './authControlDouble.mjs';

/**
 * 正式页面的首启、登录、注销与故障展示。
 *
 * 页面经 native-boot.mjs → bridge.js → app.bundle.js 真实执行；宿主是 nativeHostDouble（契约替身），
 * 控制端是 authControlDouble（Rust 认证接口的替身）。这里证明的是「页面提交 → 传输适配 → 响应消费」，
 * 不证明 Rust 控制端或 Rust 宿主已经运行。
 */

const CONTROL_BASE_URL = 'http://127.0.0.1:50123';
const CORE_CONTROLLER_URL = 'http://127.0.0.1:9797';
const ADMIN_PASSWORD = 'synthetic-Admin-Passw0rd';
const MEMBER_PASSWORD = 'synthetic-Member-Passw0rd';

async function prepare(label) {
  return composition(label, {root: transientRun('control-runtime', label)});
}

function hostDouble(prepared, {control, auth, session = null}) {
  return createNativeHostDouble({
    workspaceRoot: prepared.root,
    clock: prepared.clock,
    product: {
      control_base_url: CONTROL_BASE_URL,
      core_controller_url: CORE_CONTROLLER_URL,
      windows_user: 'synthetic-user',
      environment_ref: prepared.env,
      environments: prepared.environments,
      environment: SYNTHETIC_ENVIRONMENT,
    },
    control,
    controlSetup: auth ? (payload) => auth.setupFromHost(payload) : null,
    session,
    network: {
      readState: async () => ({general: {mode: 'rule'}, loaded_version: null}),
      apply: async () => ({accepted: true}),
      protect: async () => ({status: 'CONFIRMED', new_connections_restricted: true}),
    },
  });
}

async function openPage(label, {prepared, double, auth, controlHandler = null}) {
  const hostFetch = createHostFetch({
    controlBaseUrl: CONTROL_BASE_URL,
    controlHandler: controlHandler || auth || {handle: () => { throw new Error('控制端未就绪时页面不应向它发请求'); }},
    coreControllerUrl: CORE_CONTROLLER_URL,
    core: prepared.core,
  });
  const page = await createPageRuntime(`${label}-page`, {
    hostPrimitives: {
      __TAURI__: {core: {invoke: (command, args) => (command === 'steward_user_confirm'
        ? double.confirm(args.request)
        : double.invoke(args.op, args.payload, args.authorizationRef))}},
      fetch: hostFetch,
      navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true},
      RTCPeerConnection: null,
    },
  });
  return {page, hostFetch};
}

async function waitFor(page, predicate, timeoutMs = 8000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const snap = await page.window.__STEWARD__.snapshot();
    if (!snap?.__unavailable__ && predicate(snap)) return snap;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  const last = await page.window.__STEWARD__?.snapshot?.();
  throw new Error(`timed out waiting for page state; last account=${JSON.stringify(last?.account)}`);
}

function visibleText(page) {
  return page.document.all.map((node) => `${node.textContent}\n${node.value}`).join('\n');
}

async function setupAndLogin(page, username = 'admin.ops', password = ADMIN_PASSWORD) {
  await waitFor(page, (snap) => snap.account?.phase === 'setup_required');
  page.setValue('setupUsername', username);
  page.setValue('setupPassword', password);
  page.setValue('setupPasswordConfirm', password);
  await page.click('setupSubmit');
  await waitFor(page, (snap) => snap.account?.phase === 'login_required');
  return login(page, username, password);
}

async function login(page, username, password) {
  page.setValue('loginUsername', username);
  page.setValue('loginPassword', password);
  await page.click('loginSubmit');
  return waitFor(page, (snap) => snap.account?.phase === 'authenticated' || Boolean(snap.account?.notice));
}

test('首启：空控制端显示管理员设置页，提交后转登录；角色取自服务端；注销只撤销会话并回到登录页', async () => {
  const prepared = await prepare('rc1-first-run');
  const auth = createAuthControlDouble({clock: prepared.clock});
  const double = hostDouble(prepared, {control: readyControl(CONTROL_BASE_URL), auth});
  const {page, hostFetch} = await openPage('rc1-first-run', {prepared, double, auth});

  let snap = await waitFor(page, (item) => item.account?.phase === 'setup_required');
  assert.equal(page.document.getElementById('accountPanel').hidden, false);
  assert.equal(page.document.getElementById('setupForm').hidden, false, '空控制端显示管理员设置页');
  assert.equal(page.document.getElementById('loginForm').hidden, true);
  assert.equal(snap.userRef, null, '首启前没有任何合成身份');

  page.setValue('setupUsername', ' Admin.Ops ');
  page.setValue('setupPassword', ADMIN_PASSWORD);
  page.setValue('setupPasswordConfirm', ADMIN_PASSWORD);
  await page.click('setupSubmit');
  snap = await waitFor(page, (item) => item.account?.phase === 'login_required');
  assert.equal(snap.account.notice.code, 'SETUP_COMPLETED');
  assert.equal(page.document.getElementById('setupPassword').value, '', '密码框提交后清空');
  assert.equal(page.document.getElementById('loginForm').hidden, false);

  const setupCall = auth.requests.find((item) => item.path === '/api/setup/admin');
  assert.deepEqual(setupCall.body_keys, ['password', 'username'], '首启请求只带账号与密码，不带角色');
  assert.equal(setupCall.setup_token_header, true, '一次性首启凭据由宿主附加');
  assert.equal(hostFetch.calls.some((item) => item.path === '/api/setup/admin'), false, '页面不直接调首启接口，凭据不经过页面');
  assert.ok(double.calls.some((item) => item.op === 'ControlSetupAdmin'), '首启经受限宿主能力提交');
  assert.deepEqual(auth.users().map((user) => [user.username, user.role]), [['admin.ops', 'admin']]);

  snap = await login(page, 'admin.ops', ADMIN_PASSWORD);
  assert.equal(snap.account.phase, 'authenticated', JSON.stringify(snap.account));
  assert.equal(snap.role, 'admin', '角色来自 /api/auth/me');
  assert.equal(snap.username, 'admin.ops');
  assert.equal(snap.userRef, auth.users()[0].user_ref);
  assert.equal(page.document.getElementById('loginPassword').value, '');
  assert.equal(page.document.getElementById('adminCard').hidden, false);
  assert.match(page.text('sidebarStatus'), /admin\.ops/);
  assert.deepEqual(auth.requests.find((item) => item.path === '/api/auth/login').body_keys, ['password', 'username']);
  assert.ok(hostFetch.calls.some((item) => item.path === '/api/auth/me'));
  assert.equal(hostFetch.calls.some((item) => item.path === '/api/admin/resources'), false, '不靠管理接口成败推断角色');

  const stored = JSON.parse(readFileSync(double.sessionFile, 'utf8'));
  assert.equal(stored.user_ref, snap.userRef, '会话材料由宿主保管');
  assert.ok(!path.resolve(double.sessionFile).startsWith(`${path.resolve(prepared.root)}${path.sep}`), '会话文件不在受限桥可达的工作区');
  assert.equal(page.window.localStorage.getItem('steward-session'), null, '会话不进 localStorage');
  const token = stored.access_token;
  const exposed = [JSON.stringify(snap), JSON.stringify(page.window.__STEWARD_HOST_REPORT__), visibleText(page)].join('\n');
  assert.equal(exposed.includes(token), false, '快照、宿主回报与页面文字都不带会话令牌');
  assert.equal(exposed.includes(ADMIN_PASSWORD), false, '页面状态里没有密码');

  assert.equal(snap.ai.available, false, '服务端还没有模型配置，不能显示可用');
  assert.match(page.text('capabilityView'), /AI_UNAVAILABLE/);
  assert.match(page.text('assignmentStatus'), /网络资源：未分配/, '管理员还没有分配资源');
  assert.equal(page.text('capabilityView').includes('CONTROL_CAPABILITY_NOT_MIGRATED'), false, 'RC2 不再有未迁移的 501');

  await page.click('logoutButton');
  snap = await waitFor(page, (item) => item.account?.phase === 'login_required');
  assert.equal(snap.account.notice.code, 'LOGGED_OUT');
  assert.equal(auth.sessionState(token), 'REVOKED', '服务端撤销了这条会话');
  assert.equal(existsSync(double.sessionFile), false, '本机会话材料已清除');
  assert.equal(auth.users().length, 1, '注销不删用户');
  assert.equal(snap.userRef, null);
  assert.equal(page.document.getElementById('adminCard').hidden, true, '旧身份不留在页面上');
  page.close();
  prepared.close();
});

test('错误密码回统一 401，页面留在登录页、不保存会话', async () => {
  const prepared = await prepare('rc1-wrong-password');
  const auth = createAuthControlDouble({clock: prepared.clock});
  const double = hostDouble(prepared, {control: readyControl(CONTROL_BASE_URL), auth});
  const {page} = await openPage('rc1-wrong-password', {prepared, double, auth});
  await setupAndLogin(page);
  await page.click('logoutButton');
  await waitFor(page, (item) => item.account?.notice?.code === 'LOGGED_OUT');

  const snap = await login(page, 'admin.ops', 'synthetic-Wrong-Passw0rd');
  assert.equal(snap.account.phase, 'login_required');
  assert.equal(snap.account.notice.code, 'AUTH_LOGIN_REJECTED');
  assert.ok(snap.account.notice.request_ref, '错误带请求引用，可与控制端日志对应');
  assert.match(page.text('accountNotice'), /AUTH_LOGIN_REJECTED/);
  assert.equal(existsSync(double.sessionFile), false);
  assert.equal(snap.userRef, null);
  page.close();
  prepared.close();
});

test('会话过期：启动时读到过期或被撤销的会话走登录；使用中被判失效也退回登录并清掉本机会话', async () => {
  const prepared = await prepare('rc1-expiry');
  const auth = createAuthControlDouble({clock: prepared.clock});
  const double = hostDouble(prepared, {control: readyControl(CONTROL_BASE_URL), auth});
  const first = await openPage('rc1-expiry-a', {prepared, double, auth});
  await setupAndLogin(first.page);
  const token = JSON.parse(readFileSync(double.sessionFile, 'utf8')).access_token;

  auth.expireAllSessions();
  await first.page.click('refreshTraffic');
  const expired = await waitFor(first.page, (item) => item.account?.notice?.code === 'SESSION_EXPIRED');
  assert.equal(expired.account.phase, 'login_required');
  assert.equal(expired.userRef, null);
  assert.equal(existsSync(double.sessionFile), false, '被服务端判失效的会话从宿主清除');
  first.page.close();

  const revokedDouble = hostDouble(prepared, {
    control: readyControl(CONTROL_BASE_URL),
    auth,
    session: {access_token: token, expires_at: '2030-01-01T00:00:00.000Z', user_ref: expired.account.identity?.user_ref || 'usr-any'},
  });
  const second = await openPage('rc1-expiry-b', {prepared, double: revokedDouble, auth});
  const rejected = await waitFor(second.page, (item) => item.account?.phase === 'login_required');
  assert.equal(rejected.account.notice.code, 'AUTH_SESSION_INVALID', '宿主记录未过期但服务端不认，照样回登录');
  assert.equal(existsSync(revokedDouble.sessionFile), false);
  second.page.close();

  const staleDouble = hostDouble(prepared, {
    control: readyControl(CONTROL_BASE_URL),
    auth,
    session: {access_token: token, expires_at: '2026-01-01T00:00:00.000Z', user_ref: 'usr-any'},
  });
  const third = await openPage('rc1-expiry-c', {prepared, double: staleDouble, auth});
  const stale = await waitFor(third.page, (item) => item.account?.phase === 'login_required');
  assert.equal(stale.account.notice.code, 'SESSION_EXPIRED');
  third.page.close();
  prepared.close();
});

test('未分配资源与无模型配置：照常登录，页面分别显示未分配与 AI 不可用', async () => {
  const prepared = await prepare('rc1-unassigned');
  const auth = createAuthControlDouble({
    clock: prepared.clock,
    business: {
      '/api/ai/capabilities': ({user, json}) => json(200, {user_ref: user.user_ref, tasks: {cleanup: {status: 'UNAVAILABLE', reason: 'MODEL_POLICY_MISSING'}}}),
      '/api/network/assignment': ({user, json}) => json(200, {user_ref: user.user_ref, assignment: null, quota: null}),
    },
  });
  const double = hostDouble(prepared, {control: readyControl(CONTROL_BASE_URL), auth});
  const {page} = await openPage('rc1-unassigned', {prepared, double, auth});
  const snap = await setupAndLogin(page);
  assert.equal(snap.account.phase, 'authenticated');
  assert.equal(snap.account.assignment.status, 'UNASSIGNED');
  assert.match(page.text('assignmentStatus'), /网络资源：未分配/);
  assert.equal(snap.account.ai.code, 'AI_UNAVAILABLE');
  assert.match(page.text('capabilityView'), /AI_UNAVAILABLE/);
  assert.equal(snap.ai.available, false);
  page.close();
  prepared.close();
});

test('控制端启动失败：显示具体错误与日志位置，登录入口不出现，本地检查照常可用，不退回合成控制端', async () => {
  const prepared = await prepare('rc1-control-failed');
  let status = {
    status: 'failed',
    mode: 'managed',
    log_file: 'C:\\synthetic\\ai.steward.desktop\\control\\logs\\control-20260913T170000000Z-ctl-x.log',
    host_log: 'C:\\synthetic\\ai.steward.desktop\\logs\\host-control-20260913T170000000Z-4242.log',
    error: {code: 'CONTROL_STORE_CORRUPT', reason: '控制端数据库已损坏或不是 SQLite 文件'},
    failure: {exit_code: 3},
  };
  const auth = createAuthControlDouble({clock: prepared.clock});
  const double = hostDouble(prepared, {control: () => status, auth});
  const {page, hostFetch} = await openPage('rc1-control-failed', {prepared, double, auth});

  let snap = await waitFor(page, (item) => item.account?.phase === 'control_unavailable');
  assert.match(page.text('controlStatus'), /CONTROL_STORE_CORRUPT/);
  assert.match(page.text('controlStatus'), /control-20260913T170000000Z-ctl-x\.log/, '点名控制端日志位置');
  assert.match(page.text('controlStatus'), /host-control-20260913T170000000Z-4242\.log/, '点名宿主日志位置');
  assert.equal(page.document.getElementById('loginForm').hidden, true);
  assert.equal(page.document.getElementById('setupForm').hidden, true);
  assert.equal(page.document.getElementById('accountRetry').hidden, false);
  assert.equal(snap.userRef, null, '没有自动兜底出一个身份');

  await page.click('refreshTraffic');
  snap = await waitFor(page, (item) => Boolean(item.traffic.quota));
  assert.equal(snap.traffic.quota.code, 'CONTROL_STORE_CORRUPT', '依赖控制端的操作回具体故障，不给假数据');

  await page.click('scanDeep');
  snap = await waitFor(page, (item) => item.local.identities.length >= 2);
  assert.ok(snap.local.scan_id, '本地标准检查不依赖控制端');
  assert.equal(hostFetch.calls.filter((item) => item.host === new URL(CONTROL_BASE_URL).host).length, 0, '没有向不可用的控制端发请求');

  status = readyControl(CONTROL_BASE_URL);
  await page.click('accountRetry');
  snap = await waitFor(page, (item) => item.account?.phase === 'setup_required');
  assert.equal(page.document.getElementById('setupForm').hidden, false, '控制端恢复后重新检测即可进入首启');
  assert.equal(snap.account.control.status, 'ready');
  page.close();
  prepared.close();
});

test('控制端还在启动：页面等握手完成再进入首启，不先报未接入', async () => {
  const prepared = await prepare('rc1-starting');
  const auth = createAuthControlDouble({clock: prepared.clock});
  let polls = 0;
  const double = hostDouble(prepared, {
    control: () => {
      polls += 1;
      return polls < 3 ? {status: 'starting', mode: 'managed', log_dir: 'C:\\synthetic\\control\\logs'} : readyControl(CONTROL_BASE_URL);
    },
    auth,
  });
  const {page} = await openPage('rc1-starting', {prepared, double, auth});
  const snap = await waitFor(page, (item) => item.account?.phase === 'setup_required');
  assert.ok(double.calls.filter((item) => item.op === 'ControlStatus').length >= 1, '启动期间轮询宿主的控制端状态');
  assert.equal(snap.account.control.status, 'ready');
  page.close();
  prepared.close();
});

test('换用户登录：身份、角色、令牌与受权消费者整套换掉，不带上一位用户的东西', async () => {
  const prepared = await prepare('rc1-switch-user');
  const auth = createAuthControlDouble({clock: prepared.clock});
  const double = hostDouble(prepared, {control: readyControl(CONTROL_BASE_URL), auth});
  const {page} = await openPage('rc1-switch-user', {prepared, double, auth});
  const admin = await setupAndLogin(page);
  const adminToken = JSON.parse(readFileSync(double.sessionFile, 'utf8')).access_token;
  await page.click('logoutButton');
  await waitFor(page, (item) => item.account?.notice?.code === 'LOGGED_OUT');

  const member = auth.addUser('member', MEMBER_PASSWORD, 'user');
  const switchedAt = auth.requests.length;
  const snap = await login(page, 'member', MEMBER_PASSWORD);
  assert.equal(snap.account.phase, 'authenticated');
  assert.equal(snap.userRef, member.user_ref);
  assert.notEqual(snap.userRef, admin.userRef);
  assert.equal(snap.role, 'user');
  assert.equal(page.document.getElementById('adminCard').hidden, true, '普通用户看不到管理入口');

  await page.click('refreshTraffic');
  await waitFor(page, (item) => Boolean(item.traffic.quota));
  const memberToken = JSON.parse(readFileSync(double.sessionFile, 'utf8')).access_token;
  const used = auth.requests.slice(switchedAt).map((item) => item.bearer).filter(Boolean);
  assert.ok(used.length > 0);
  assert.ok(used.every((bearer) => bearer === memberToken), '换人之后所有带会话的请求只用新令牌');
  assert.equal(auth.sessionState(adminToken), 'REVOKED');
  page.close();
  prepared.close();
});

test('重开应用：宿主保管的有效会话直接读回，不再要求登录', async () => {
  const prepared = await prepare('rc1-reopen');
  const auth = createAuthControlDouble({clock: prepared.clock});
  const double = hostDouble(prepared, {control: readyControl(CONTROL_BASE_URL), auth});
  const first = await openPage('rc1-reopen-a', {prepared, double, auth});
  const before = await setupAndLogin(first.page);
  first.page.close();

  const logins = auth.requests.filter((item) => item.path === '/api/auth/login').length;
  const second = await openPage('rc1-reopen-b', {prepared, double, auth});
  const after = await waitFor(second.page, (item) => item.account?.phase === 'authenticated');
  assert.equal(after.userRef, before.userRef);
  assert.equal(after.role, 'admin');
  assert.equal(auth.requests.filter((item) => item.path === '/api/auth/login').length, logins, '没有重新登录');
  assert.equal(second.page.window.localStorage.getItem('steward-session'), null);
  second.page.close();
  prepared.close();
});

test('首启表单：两次密码不一致不提交；两个窗口抢首启，后提交的看到冲突而不是覆盖', async () => {
  const prepared = await prepare('rc1-setup-guards');
  const auth = createAuthControlDouble({clock: prepared.clock});
  const double = hostDouble(prepared, {control: readyControl(CONTROL_BASE_URL), auth});
  const first = await openPage('rc1-setup-guards-a', {prepared, double, auth});
  const second = await openPage('rc1-setup-guards-b', {prepared, double, auth});
  await waitFor(first.page, (item) => item.account?.phase === 'setup_required');
  await waitFor(second.page, (item) => item.account?.phase === 'setup_required');

  first.page.setValue('setupUsername', 'admin');
  first.page.setValue('setupPassword', ADMIN_PASSWORD);
  first.page.setValue('setupPasswordConfirm', `${ADMIN_PASSWORD}-typo`);
  await first.page.click('setupSubmit');
  assert.match(first.page.text('accountNotice'), /PASSWORD_CONFIRMATION_MISMATCH/);
  assert.equal(double.calls.some((item) => item.op === 'ControlSetupAdmin'), false, '不一致时根本不提交');

  first.page.setValue('setupPassword', ADMIN_PASSWORD);
  first.page.setValue('setupPasswordConfirm', ADMIN_PASSWORD);
  await first.page.click('setupSubmit');
  await waitFor(first.page, (item) => item.account?.phase === 'login_required');

  second.page.setValue('setupUsername', 'intruder');
  second.page.setValue('setupPassword', MEMBER_PASSWORD);
  second.page.setValue('setupPasswordConfirm', MEMBER_PASSWORD);
  await second.page.click('setupSubmit');
  const conflict = await waitFor(second.page, (item) => Boolean(item.account?.notice));
  assert.equal(conflict.account.notice.code, 'CONTROL_SETUP_CONFLICT');
  assert.deepEqual(auth.users().map((user) => user.username), ['admin'], '已建管理员没有被覆盖');
  first.page.close();
  second.page.close();
  prepared.close();
});

/**
 * RC1 复核 R1/R2/R3 的正式用例。
 * 等待条件：控制端状态切换发生在触发它的那个页面动作的 promise 链里（向宿主查一次 ControlStatus，没有定时器），
 * 所以用 waitFor 等明确的快照条件，时限沿用本文件的 8 秒上限。
 */

/** 可以随时「断开」的控制端替身：断开后每个请求都像连接被拒一样抛错。 */
function switchableControl(auth) {
  const state = {reachable: true};
  return {
    state,
    handler: {
      async handle(request) {
        if (!state.reachable) throw new TypeError('synthetic connection refused');
        return auth.handle(request);
      },
    },
  };
}

const EXITED = {
  status: 'failed',
  mode: 'managed',
  log_file: 'C:\\synthetic\\ai.steward.desktop\\control\\logs\\control-20260913T170000000Z-ctl-exit.log',
  host_log: 'C:\\synthetic\\ai.steward.desktop\\logs\\host-control-20260913T170000000Z-4242.log',
  host_log_status: 'ok',
  error: {code: 'CONTROL_EXITED', reason: '控制端进程意外退出，详见控制端日志'},
  failure: {exit_code: 101},
};

function controlHostCalls(hostFetch) {
  return hostFetch.calls.filter((item) => item.host === new URL(CONTROL_BASE_URL).host).length;
}

test('R1 运行中控制端退出：下一次依赖操作后显示原因与日志、出现重检入口，会话保留，后续请求不再连失效地址，恢复后重检回到原会话', async () => {
  const prepared = await prepare('rc1-fix-exit-after-login');
  const auth = createAuthControlDouble({clock: prepared.clock});
  const link = switchableControl(auth);
  let status = readyControl(CONTROL_BASE_URL);
  const double = hostDouble(prepared, {control: () => status, auth});
  const {page, hostFetch} = await openPage('rc1-fix-exit-after-login', {prepared, double, auth, controlHandler: link.handler});
  const before = await setupAndLogin(page);
  assert.equal(before.account.phase, 'authenticated');
  assert.equal(page.document.getElementById('accountRetry').hidden, true, '控制端就绪时不显示重检');
  const loginsBefore = auth.requests.filter((item) => item.path === '/api/auth/login').length;

  status = EXITED;
  link.state.reachable = false;
  const statusPollsBefore = double.calls.filter((item) => item.op === 'ControlStatus').length;
  await page.click('refreshTraffic');
  let snap = await waitFor(page, (item) => item.account?.control?.status === 'failed');
  assert.ok(double.calls.filter((item) => item.op === 'ControlStatus').length > statusPollsBefore, '请求失败后向宿主核对了控制端状态');
  assert.match(page.text('controlStatus'), /CONTROL_EXITED/);
  assert.match(page.text('controlStatus'), /control-20260913T170000000Z-ctl-exit.log/, '点名控制端日志');
  assert.match(page.text('controlStatus'), /host-control-20260913T170000000Z-4242.log/, '点名宿主日志');
  assert.doesNotMatch(page.text('controlStatus'), /已就绪/, '不再显示启动时的就绪状态');
  assert.equal(page.document.getElementById('accountRetry').hidden, false, '出现可见的重检入口');
  assert.equal(snap.account.phase, 'authenticated', '控制端故障不等于会话被撤销');
  assert.match(page.text('accountStatus'), /控制端当前不可用/);
  assert.ok(existsSync(double.sessionFile), '宿主会话记录没有被删除');
  assert.equal(snap.userRef, before.userRef);

  const callsAfterFailure = controlHostCalls(hostFetch);
  await page.click('refreshTraffic');
  snap = await waitFor(page, (item) => item.traffic.quota?.code === 'CONTROL_EXITED');
  assert.equal(controlHostCalls(hostFetch), callsAfterFailure, '确认失败后依赖操作不再连失效地址，直接回具体故障');
  assert.equal(snap.account.control.status, 'failed');

  await page.click('scanDeep');
  snap = await waitFor(page, (item) => item.local.identities.length >= 2);
  assert.ok(snap.local.scan_id, '本地标准检查照常可用');

  status = readyControl(CONTROL_BASE_URL);
  link.state.reachable = true;
  await page.click('accountRetry');
  snap = await waitFor(page, (item) => item.account?.control?.status === 'ready' && item.account?.phase === 'authenticated');
  assert.equal(snap.userRef, before.userRef, '恢复后回到原来的有效会话');
  assert.equal(auth.requests.filter((item) => item.path === '/api/auth/login').length, loginsBefore, '恢复不需要重新登录');
  assert.equal(page.document.getElementById('accountRetry').hidden, true);
  assert.match(page.text('controlStatus'), /已就绪/);

  await page.click('logoutButton');
  snap = await waitFor(page, (item) => item.account?.notice?.code === 'LOGGED_OUT');
  assert.equal(snap.account.phase, 'login_required', '注销回归');
  page.close();
  prepared.close();
});

test('R1 未登录时控制端退出：点登录后显示宿主回报的失败与重检入口，而不只是「连不上」', async () => {
  const prepared = await prepare('rc1-fix-exit-before-login');
  const auth = createAuthControlDouble({clock: prepared.clock});
  const link = switchableControl(auth);
  let status = readyControl(CONTROL_BASE_URL);
  const double = hostDouble(prepared, {control: () => status, auth});
  const {page} = await openPage('rc1-fix-exit-before-login', {prepared, double, auth, controlHandler: link.handler});
  await setupAndLogin(page);
  await page.click('logoutButton');
  await waitFor(page, (item) => item.account?.notice?.code === 'LOGGED_OUT');

  status = EXITED;
  link.state.reachable = false;
  const snap = await login(page, 'admin.ops', ADMIN_PASSWORD);
  const failed = snap.account.control.status === 'failed' ? snap : await waitFor(page, (item) => item.account?.control?.status === 'failed');
  assert.equal(failed.account.notice.code, 'CONTROL_UNREACHABLE');
  assert.match(page.text('controlStatus'), /CONTROL_EXITED/);
  assert.equal(page.document.getElementById('accountRetry').hidden, false);
  assert.equal(existsSync(double.sessionFile), false);
  page.close();
  prepared.close();
});

test('R2 日志未成功保存：控制端日志、宿主日志、两者都失败各自点名；服务就绪照常可用，服务失败时两类信息都在', async () => {
  const cases = [
    {label: 'control-log', patch: {log_status: 'failed', log_file: 'C:\\synthetic\\control\\logs\\unwritable-control.log', host_log_status: 'ok', host_log: 'C:\\synthetic\\logs\\host-ok.log'}, expect: ['控制端日志（C:\\synthetic\\control\\logs\\unwritable-control.log）'], absent: ['宿主日志（']},
    {label: 'host-log', patch: {log_status: 'ok', log_file: 'C:\\synthetic\\control\\logs\\control-ok.log', host_log_status: 'failed', host_log: 'C:\\synthetic\\logs\\unwritable-host.log'}, expect: ['宿主日志（C:\\synthetic\\logs\\unwritable-host.log）'], absent: ['控制端日志（']},
    {label: 'both-logs', patch: {log_status: 'failed', log_file: 'C:\\synthetic\\control\\logs\\unwritable-control.log', host_log_status: 'failed', host_log: 'C:\\synthetic\\logs\\unwritable-host.log'}, expect: ['控制端日志（', '宿主日志（'], absent: []},
  ];
  for (const item of cases) {
    const prepared = await prepare(`rc1-fix-${item.label}`);
    const auth = createAuthControlDouble({clock: prepared.clock});
    const double = hostDouble(prepared, {control: {...readyControl(CONTROL_BASE_URL), ...item.patch}, auth});
    const {page} = await openPage(`rc1-fix-${item.label}`, {prepared, double, auth});
    const snap = await waitFor(page, (value) => value.account?.phase === 'setup_required');
    const shown = page.text('controlStatus');
    assert.match(shown, /控制端：已就绪/, `${item.label}：服务状态照实显示为就绪`);
    assert.match(shown, /日志未成功保存/, `${item.label}：必须明示日志未成功保存`);
    for (const text of item.expect) assert.ok(shown.includes(text), `${item.label}：应点名 ${text}`);
    for (const text of item.absent) assert.equal(shown.includes(text), false, `${item.label}：不应误报 ${text}`);
    assert.equal(page.document.getElementById('setupForm').hidden, false, `${item.label}：日志警告不把可用服务当成不可用`);
    assert.equal(snap.account.notice, null);
    page.close();
    prepared.close();
  }

  const prepared = await prepare('rc1-fix-failed-and-logs');
  const double = hostDouble(prepared, {control: {...EXITED, log_status: 'failed', host_log_status: 'failed'}, auth: null});
  const {page} = await openPage('rc1-fix-failed-and-logs', {prepared, double, auth: null});
  await waitFor(page, (value) => value.account?.phase === 'control_unavailable');
  const shown = page.text('controlStatus');
  assert.match(shown, /CONTROL_EXITED/, '服务错误不被日志警告遮住');
  assert.match(shown, /日志未成功保存：控制端日志（.*）；宿主日志（.*）/);
  page.close();
  prepared.close();
});

test('R3 装配期间会话被判失效：清宿主会话、进入登录页、只重装一次；上游模型 401 不当成会话失效', async () => {
  const prepared = await prepare('rc1-fix-rejected-during-boot');
  const auth = createAuthControlDouble({clock: prepared.clock});
  let armed = false;
  const handler = {
    async handle(request) {
      const response = await auth.handle(request);
      if (armed && new URL(request.url).pathname === '/api/auth/me' && response.status === 200) {
        armed = false;
        auth.expireAllSessions();
      }
      return response;
    },
  };
  const double = hostDouble(prepared, {control: readyControl(CONTROL_BASE_URL), auth});
  const {page} = await openPage('rc1-fix-rejected-during-boot', {prepared, double, auth, controlHandler: handler});
  await waitFor(page, (item) => item.account?.phase === 'setup_required');
  page.setValue('setupUsername', 'admin.ops');
  page.setValue('setupPassword', ADMIN_PASSWORD);
  page.setValue('setupPasswordConfirm', ADMIN_PASSWORD);
  await page.click('setupSubmit');
  await waitFor(page, (item) => item.account?.phase === 'login_required');

  armed = true;
  const meBefore = auth.requests.filter((item) => item.path === '/api/auth/me').length;
  page.setValue('loginUsername', 'admin.ops');
  page.setValue('loginPassword', ADMIN_PASSWORD);
  await page.click('loginSubmit');
  const snap = await waitFor(page, (item) => item.account?.notice?.code === 'SESSION_EXPIRED');
  assert.equal(snap.account.phase, 'login_required');
  assert.equal(snap.userRef, null, '不留下失效身份');
  assert.equal(snap.role, 'anonymous');
  assert.equal(existsSync(double.sessionFile), false, '宿主会话已清除');
  assert.equal(auth.requests.filter((item) => item.path === '/api/auth/me').length - meBefore, 1, '清会话后按未登录装配，不拿失效令牌反复重试');
  page.close();
  prepared.close();

  const upstream = await prepare('rc1-fix-upstream-401');
  const upstreamAuth = createAuthControlDouble({
    clock: upstream.clock,
    business: {
      '/api/ai/capabilities': ({json}) => json(401, {code: 'MODEL_PROVIDER_UNAUTHORIZED', reason: '模型服务拒绝了服务端配置的密钥'}),
    },
  });
  const upstreamDouble = hostDouble(upstream, {control: readyControl(CONTROL_BASE_URL), auth: upstreamAuth});
  const opened = await openPage('rc1-fix-upstream-401', {prepared: upstream, double: upstreamDouble, auth: upstreamAuth});
  const signedIn = await setupAndLogin(opened.page);
  assert.equal(signedIn.account.phase, 'authenticated', '上游模型的 401 不是本应用会话失效');
  assert.equal(signedIn.account.ai.code, 'MODEL_PROVIDER_UNAUTHORIZED');
  assert.ok(existsSync(upstreamDouble.sessionFile));
  opened.page.close();
  upstream.close();
});

test('离线守卫在位：本套用例里起进程、监听端口与外发 fetch 都会被拦下', async () => {
  const {default: net} = await import('node:net');
  const {spawnSync} = await import('node:child_process');
  assert.throws(() => net.createServer().listen(0), (error) => error.code === 'OFFLINE_GUARD');
  assert.throws(() => spawnSync('cargo', ['--version']), (error) => error.code === 'OFFLINE_GUARD');
  assert.throws(() => globalThis.fetch('https://example.com'), (error) => error.code === 'OFFLINE_GUARD');
});
