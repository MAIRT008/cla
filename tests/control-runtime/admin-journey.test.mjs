import './offline-guard.mjs';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {composition} from '../delivery/harness.mjs';
import {createNativeHostDouble} from '../delivery/nativeHostDouble.mjs';
import {createHostFetch, readyControl} from '../delivery/productHost.mjs';
import {SYNTHETIC_ENVIRONMENT} from '../local/demo.mjs';
import {createPageRuntime} from '../ui/page.mjs';
import {createProductRuntimeOptions} from '../../apps/desktop-ui/product-runtime.mjs';
import {createAuthControlDouble} from './authControlDouble.mjs';

/**
 * RC2 管理后台的正式页面旅程。
 *
 * 页面经 native-boot.mjs → bridge.js → app.bundle.js 真实执行，所有动作走
 * 页面输入与按钮 → session.mjs → product-runtime 的远端控制传输 → 控制端替身。
 * 控制端替身按 Rust 控制端 RC2 契约写（见 authControlDouble.mjs），配额与事件复用 Node 基线服务。
 * 这里证明的是页面提交、传输与响应消费，不证明 Rust 控制端已经编译或运行。
 */

const CONTROL_BASE_URL = 'http://127.0.0.1:50123';
const CORE_CONTROLLER_URL = 'http://127.0.0.1:9797';
const ADMIN_PASSWORD = 'synthetic-Admin-Passw0rd';
const MEMBER_PASSWORD = 'synthetic-Member-Passw0rd';
const RESET_PASSWORD = 'synthetic-Reset-Passw0rd-2';
const MODEL_KEY = 'sk-synthetic-admin-entered-key-4242';
const PROXY_PASSWORD = 'synthetic-member-proxy-pass-777';
const GB_80 = 80_000_000_000;

async function prepare(label) {
  return composition(label, {root: transientRun('control-runtime', label)});
}

function hostDouble(prepared, control) {
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
    control: () => control.status,
    controlSetup: (payload) => control.double.setupFromHost(payload),
    network: {
      readState: async () => ({general: {mode: 'rule'}, loaded_version: null}),
      apply: async () => ({accepted: true}),
      protect: async () => ({status: 'CONFIRMED', new_connections_restricted: true}),
    },
  });
}

/** 可断开的控制端：断开后每个请求像连接被拒一样抛错，宿主同时回报控制端已退出。 */
function controlEndpoint(prepared) {
  const double = createAuthControlDouble({clock: prepared.clock});
  const endpoint = {
    double,
    status: readyControl(CONTROL_BASE_URL),
    reachable: true,
    handler: {
      async handle(request) {
        if (!endpoint.reachable) throw new TypeError('synthetic connection refused');
        return double.handle(request);
      },
    },
    disconnect() {
      endpoint.reachable = false;
      endpoint.status = {status: 'failed', mode: 'managed', log_file: 'C:\\synthetic\\control\\logs\\control-exit.log', host_log_status: 'ok', error: {code: 'CONTROL_EXITED', reason: '控制端进程意外退出'}};
    },
  };
  return endpoint;
}

/** 同一台机器重开应用时传入原来的宿主替身：保险库密钥与账本随宿主，不能换一个新宿主去读。 */
async function openPage(label, prepared, endpoint, host = hostDouble(prepared, endpoint)) {
  const hostFetch = createHostFetch({controlBaseUrl: CONTROL_BASE_URL, controlHandler: endpoint.handler, coreControllerUrl: CORE_CONTROLLER_URL, core: prepared.core});
  const page = await createPageRuntime(`${label}-page`, {
    hostPrimitives: {
      __TAURI__: {core: {invoke: (command, args) => (command === 'steward_user_confirm' ? host.confirm(args.request) : host.invoke(args.op, args.payload, args.authorizationRef))}},
      fetch: hostFetch,
      navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true},
      RTCPeerConnection: null,
    },
  });
  return {page, host, hostFetch};
}

async function waitFor(page, predicate, timeoutMs = 8000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const snap = await page.window.__STEWARD__.snapshot();
    if (!snap?.__unavailable__ && predicate(snap)) return snap;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  const last = await page.window.__STEWARD__?.snapshot?.();
  throw new Error(`timed out waiting for page state; account=${JSON.stringify(last?.account)} admin.error=${JSON.stringify(last?.admin?.error)}`);
}

/** 点一个管理按钮并等这次动作完成（完成序号增加）。 */
async function adminStep(page, buttonId) {
  const before = (await page.window.__STEWARD__.snapshot()).admin.completed.seq;
  await page.click(buttonId);
  return waitFor(page, (snap) => snap.admin.completed.seq > before);
}

async function setupAndLogin(page) {
  await waitFor(page, (snap) => snap.account?.phase === 'setup_required');
  page.setValue('setupUsername', 'admin.ops');
  page.setValue('setupPassword', ADMIN_PASSWORD);
  page.setValue('setupPasswordConfirm', ADMIN_PASSWORD);
  await page.click('setupSubmit');
  await waitFor(page, (snap) => snap.account?.phase === 'login_required');
  return login(page, 'admin.ops', ADMIN_PASSWORD);
}

async function login(page, username, password) {
  page.setValue('loginUsername', username);
  page.setValue('loginPassword', password);
  await page.click('loginSubmit');
  return waitFor(page, (snap) => snap.account?.phase === 'authenticated' || Boolean(snap.account?.notice && snap.account.notice.level !== 'info'));
}

async function logout(page) {
  await page.click('logoutButton');
  return waitFor(page, (snap) => snap.account?.notice?.code === 'LOGGED_OUT');
}

function exposed(page) {
  const texts = page.document.all.map((node) => `${node.textContent}\n${node.value}`).join('\n');
  const storage = JSON.stringify([...page.window.localStorage.map.entries()]);
  return [texts, storage, JSON.stringify(page.window.__STEWARD_HOST_REPORT__)].join('\n');
}

async function snapshotText(page) {
  return JSON.stringify(await page.window.__STEWARD__.snapshot());
}

async function createMember(page, username, password = MEMBER_PASSWORD) {
  page.setValue('adminNewUsername', username);
  page.setValue('adminNewPassword', password);
  const snap = await adminStep(page, 'adminCreateUser');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.equal(page.document.getElementById('adminNewPassword').value, '', '初始密码读出后立即清空');
  return snap.admin.users.find((user) => user.username === username).user_ref;
}

async function selectUser(page, userRef) {
  page.setValue('adminUserSelect', userRef);
  const snap = await adminStep(page, 'adminSelectUser');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.equal(snap.admin.selectedUserRef, userRef);
  return snap;
}

async function saveResource(page, {id, role, host, sharing}) {
  page.setValue('adminResourceId', id);
  page.setValue('adminResourceRole', role);
  page.setValue('adminResourceHost', host);
  page.setValue('adminResourcePort', '1080');
  page.setValue('adminResourceSharing', sharing);
  page.setValue('adminResourceStatus', 'ACTIVE');
  const snap = await adminStep(page, 'adminResourceSave');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
}

async function saveTemplate(page) {
  page.setValue('adminTemplateId', 'managed');
  page.setValue('adminTemplateJson', JSON.stringify({
    version: 'template-v1',
    claude_domains: ['claude.ai', 'anthropic.com'],
    claude_processes: ['claude.exe'],
    managed_browser_processes: [],
    protected_process_paths: ['C:/Program Files/Claude/claude.exe'],
    lan_cidrs: ['192.168.0.0/16'],
    control_plane: {login: [{host: 'login.synthetic.invalid', outbound: 'DIRECT'}]},
    udp_policy: 'REJECT',
    ipv6_policy: 'FOLLOW',
    dns: {enable: true, nameserver: ['https://dns.synthetic.invalid/dns-query']},
  }));
  page.document.getElementById('adminTemplatePublished').checked = true;
  const snap = await adminStep(page, 'adminTemplateSave');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
}

async function saveCredential(page, credentialRef, username, password) {
  page.setValue('adminCredentialRef', credentialRef);
  page.setValue('adminCredentialUsername', username);
  page.setValue('adminCredentialPassword', password);
  const snap = await adminStep(page, 'adminCredentialSave');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.equal(page.document.getElementById('adminCredentialPassword').value, '', '接入密码读出后立即清空');
}

async function assignAndPublish(page, aResource) {
  page.setValue('adminAssignFront', 'res-front');
  page.setValue('adminAssignA', aResource);
  page.setValue('adminAssignB', '');
  page.setValue('adminAssignTemplate', 'managed');
  page.setValue('adminAssignValidUntil', '2027-01-01T00:00:00.000Z');
  let snap = await adminStep(page, 'adminAssignSave');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.equal(snap.admin.assignment.candidate.status, 'DRAFT');
  assert.equal(snap.admin.assignment.published, null, '保存只是候选，还没有发布');
  snap = await adminStep(page, 'adminPublish');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.equal(snap.admin.assignment.published.status, 'ACTIVE');
  return snap;
}

test('RC2 完整管理旅程：建用户 → 选用户 → 配资源、模板、凭据、分配 → 发布 → 额度操作 → 普通用户登录读到自己的分配与额度', async () => {
  const prepared = await prepare('rc2-admin-journey');
  const endpoint = controlEndpoint(prepared);
  const {page, host} = await openPage('rc2-admin-journey', prepared, endpoint);
  await setupAndLogin(page);

  let snap = await adminStep(page, 'adminRefresh');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.deepEqual(snap.admin.users.map((user) => user.username), ['admin.ops']);
  const noTarget = await adminStep(page, 'adminSuspend');
  assert.equal(noTarget.admin.error.code, 'ADMIN_TARGET_REQUIRED', '没选用户时不向任何默认用户提交');

  const memberRef = await createMember(page, 'member.one');
  await selectUser(page, memberRef);
  assert.match(page.text('adminTargetLine'), /member\.one/);

  page.setValue('adminQuotaUrl', endpoint.double.remnawave.url);
  page.setValue('adminQuotaToken', endpoint.double.remnawave.token);
  page.setValue('adminQuotaTimeout', '5000');
  snap = await adminStep(page, 'adminQuotaSave');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.equal(snap.admin.quotaAdapter.configured, true);
  assert.equal(snap.admin.quotaAdapter.verification, 'NOT_TESTED', '保存配置不等于验证过');
  assert.equal(page.document.getElementById('adminQuotaToken').value, '', '管理令牌读出后立即清空');
  assert.equal(page.document.getElementById('adminQuotaUrl').value, '');

  await saveResource(page, {id: 'res-front', role: 'front', host: 'front.synthetic.invalid', sharing: 'shared'});
  await saveResource(page, {id: 'res-a-member', role: 'A', host: 'exit-a.synthetic.invalid', sharing: 'dedicated'});
  await saveTemplate(page);
  snap = await page.window.__STEWARD__.snapshot();
  assert.deepEqual(snap.admin.resources.map((item) => item.resource_id).sort(), ['res-a-member', 'res-front']);
  assert.ok(page.document.getElementById('adminAssignA').children.some((option) => option.value === 'res-a-member'), '出口 A 下拉框来自服务端资源');

  await saveCredential(page, 'cred-res-front', 'member-front', PROXY_PASSWORD);
  await saveCredential(page, 'cred-res-a-member', 'member-exit', PROXY_PASSWORD);
  snap = await assignAndPublish(page, 'res-a-member');
  assert.equal(snap.admin.assignment.published.resources['res-a-member'].host, 'exit-a.synthetic.invalid');

  page.setValue('adminLimitValue', '250');
  page.setValue('adminLimitUnit', 'GB');
  page.setValue('adminLimitPeriod', 'MONTH');
  page.setValue('adminLimitExpire', '2027-01-01T00:00:00.000Z');
  snap = await adminStep(page, 'adminAllocate');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.ok(snap.admin.last.binding.provider_user_id > 0);
  page.setValue('adminLimitValue', '80');
  snap = await adminStep(page, 'adminLimit');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.equal(snap.admin.last.snapshot.limit_bytes, GB_80, '提交的是表单里填的额度');
  assert.equal(snap.admin.last.effective, true);
  snap = await adminStep(page, 'adminSuspend');
  assert.equal(snap.admin.last.snapshot.status, 'DISABLED');
  snap = await adminStep(page, 'adminResume');
  assert.equal(snap.admin.last.snapshot.status, 'ACTIVE');
  assert.equal(snap.admin.last.restored_roles.A, 'res-a-member');
  assert.notEqual(snap.userRef, memberRef, '管理对象切换不改变管理员自己的身份');

  const adminExposure = `${exposed(page)}\n${await snapshotText(page)}`;
  for (const secret of [MEMBER_PASSWORD, PROXY_PASSWORD, endpoint.double.remnawave.token, ADMIN_PASSWORD]) {
    assert.equal(adminExposure.includes(secret), false, `页面状态里出现了秘密 ${secret.slice(0, 12)}…`);
  }
  assert.equal(page.document.getElementById('adminCard').hidden, false);

  await logout(page);
  snap = await login(page, 'member.one', MEMBER_PASSWORD);
  assert.equal(snap.account.phase, 'authenticated', JSON.stringify(snap.account));
  assert.equal(snap.userRef, memberRef);
  assert.equal(snap.role, 'user');
  assert.equal(snap.account.assignment.status, 'ASSIGNED');
  assert.equal(page.document.getElementById('adminCard').hidden, true, '普通用户看不到管理区');
  assert.equal(snap.admin.users, null, '普通用户快照里没有管理数据');
  assert.equal(page.window.__STEWARD_HOST_REPORT__.credentials, 'AVAILABLE', '个人凭据按已发布分配换取到了');
  const memberToken = JSON.parse(readFileSync(host.sessionFile, 'utf8')).access_token;
  const credentialCalls = endpoint.double.requests.filter((item) => item.path === '/api/network/credentials' && item.bearer === memberToken);
  assert.ok(credentialCalls.length >= 1, '凭据请求带的是普通用户自己的会话');

  await page.click('refreshTraffic');
  snap = await waitFor(page, (item) => Boolean(item.traffic.quota?.limit_bytes));
  assert.equal(snap.traffic.quota.limit_bytes, GB_80, '普通用户读到管理员调整后的权威额度');
  assert.equal(snap.traffic.quota.status, 'ACTIVE');
  const memberExposure = `${exposed(page)}\n${await snapshotText(page)}`;
  assert.equal(memberExposure.includes(PROXY_PASSWORD), false, '个人凭据只在内存里交给受管配置，不进页面状态');

  const reopened = await openPage('rc2-admin-journey-reopen', prepared, endpoint, host);
  const again = await waitFor(reopened.page, (item) => item.account?.phase === 'authenticated');
  assert.equal(again.userRef, memberRef, '重开应用读回同一会话');
  assert.equal(again.account.assignment.status, 'ASSIGNED', '重开后分配仍在');
  reopened.page.close();
  page.close();
  endpoint.double.close();
  prepared.close();
});

test('RC2 模型配置：Key 只写不回显，保存不等于验证；普通用户只看到能力，看不到端点、模型与配置入口', async () => {
  const prepared = await prepare('rc2-model-config');
  const endpoint = controlEndpoint(prepared);
  const {page} = await openPage('rc2-model-config', prepared, endpoint);
  await setupAndLogin(page);
  await adminStep(page, 'adminRefresh');
  const memberRef = await createMember(page, 'member.model');

  page.setValue('adminModelTask', 'cleanup');
  page.document.getElementById('adminModelEnabled').checked = true;
  page.setValue('adminModelBaseUrl', 'https://model.synthetic.invalid/v1');
  page.setValue('adminModelName', 'synthetic-server-model');
  page.setValue('adminModelPolicy', 'policy-cleanup-v1');
  page.setValue('adminModelKey', MODEL_KEY);
  let snap = await adminStep(page, 'adminModelSave');
  assert.equal(snap.admin.error, null, JSON.stringify(snap.admin.error));
  assert.equal(page.document.getElementById('adminModelKey').value, '', 'Key 读出后立即清空');
  const cleanup = snap.admin.modelConfig.tasks.cleanup;
  assert.equal(cleanup.secret_present, true);
  assert.equal(cleanup.status, 'AVAILABLE');
  assert.equal(cleanup.verification, 'NOT_TESTED', '保存只代表已配置');
  assert.match(page.text('adminNotice'), /NOT_TESTED/);
  assert.equal(endpoint.double.storedModelKey('cleanup'), MODEL_KEY, 'Key 确实交给了控制端');
  assert.equal(`${exposed(page)}\n${await snapshotText(page)}`.includes(MODEL_KEY), false, 'Key 不在页面文字、快照、宿主回报或 localStorage 里');

  const invalid = await (async () => {
    page.setValue('adminModelTask', 'daily_analysis');
    page.setValue('adminModelBaseUrl', 'http://model.synthetic.invalid');
    page.setValue('adminModelPolicy', 'policy-daily-v1');
    return adminStep(page, 'adminModelSave');
  })();
  assert.equal(invalid.admin.error.code, 'CONTROL_REQUEST_INVALID', '服务端校验失败时显示错误，不显示已保存');
  assert.ok(invalid.admin.error.request_ref, '错误带请求引用');
  assert.equal(invalid.admin.modelConfig.tasks.daily_analysis.configured, false);

  await logout(page);
  snap = await login(page, 'member.model', MEMBER_PASSWORD);
  assert.equal(snap.userRef, memberRef);
  assert.equal(snap.ai.available, true, '服务端已配置模型，普通用户能力可用');
  assert.match(page.text('capabilityView'), /服务端已配置/);
  await page.click('refreshCapabilities');
  snap = await waitFor(page, (item) => Boolean(item.ai.capabilities));
  assert.equal(snap.ai.capabilities.tasks.cleanup.status, 'AVAILABLE');
  const memberView = `${exposed(page)}\n${await snapshotText(page)}`;
  for (const hidden of ['model.synthetic.invalid', 'synthetic-server-model', MODEL_KEY]) {
    assert.equal(memberView.includes(hidden), false, `普通用户页面出现了 ${hidden}`);
  }
  assert.equal(page.document.getElementById('adminCard').hidden, true, '普通用户没有模型配置入口');
  page.close();
  endpoint.double.close();
  prepared.close();
});

test('RC2 越权与停用：普通用户调不了管理动作；停用后旧会话在下一次操作时失效，重置密码后旧密码失效', async () => {
  const adminPrepared = await prepare('rc2-disable-admin');
  const endpoint = controlEndpoint(adminPrepared);
  const adminPage = (await openPage('rc2-disable-admin', adminPrepared, endpoint)).page;
  await setupAndLogin(adminPage);
  await adminStep(adminPage, 'adminRefresh');
  const memberRef = await createMember(adminPage, 'member.two');

  const memberPrepared = await prepare('rc2-disable-member');
  const memberPage = (await openPage('rc2-disable-member', memberPrepared, endpoint)).page;
  await waitFor(memberPage, (snap) => snap.account?.phase === 'login_required');
  let member = await login(memberPage, 'member.two', MEMBER_PASSWORD);
  assert.equal(member.role, 'user');

  const usersBefore = endpoint.double.users().length;
  member = await memberPage.window.__STEWARD__.adminRefresh();
  assert.equal(member.admin.error.code, 'CONTROL_FORBIDDEN', '绕过隐藏的管理区直接调用也被控制端拒绝');
  member = await memberPage.window.__STEWARD__.adminCreateUser('intruder.x', 'synthetic-Intruder-Passw0rd');
  assert.equal(member.admin.error.code, 'CONTROL_FORBIDDEN');
  assert.equal(endpoint.double.users().length, usersBefore, '没有建出用户');
  member = await memberPage.window.__STEWARD__.adminSelectUser(memberRef);
  assert.ok(['CONTROL_FORBIDDEN', 'ADMIN_TARGET_UNKNOWN'].includes(member.admin.error.code));
  assert.equal(member.admin.selectedUserRef, null);

  await selectUser(adminPage, memberRef);
  let admin = await adminStep(adminPage, 'adminDisableUser');
  assert.equal(admin.admin.error, null, JSON.stringify(admin.admin.error));
  assert.match(adminPage.text('adminNotice'), /撤销会话 1 条/);

  await memberPage.click('refreshTraffic');
  member = await waitFor(memberPage, (snap) => snap.account?.notice?.code === 'SESSION_EXPIRED');
  assert.equal(member.account.phase, 'login_required', '停用后旧会话失效，页面退回登录');
  member = await login(memberPage, 'member.two', MEMBER_PASSWORD);
  assert.equal(member.account.notice.code, 'AUTH_LOGIN_REJECTED', '停用账号不能再登录');

  admin = await adminStep(adminPage, 'adminEnableUser');
  assert.equal(admin.admin.error, null);
  adminPage.setValue('adminResetPasswordInput', RESET_PASSWORD);
  admin = await adminStep(adminPage, 'adminResetPassword');
  assert.equal(admin.admin.error, null, JSON.stringify(admin.admin.error));
  assert.equal(adminPage.document.getElementById('adminResetPasswordInput').value, '', '新密码读出后立即清空');
  assert.equal(`${exposed(adminPage)}\n${await snapshotText(adminPage)}`.includes(RESET_PASSWORD), false);
  member = await login(memberPage, 'member.two', MEMBER_PASSWORD);
  assert.equal(member.account.notice.code, 'AUTH_LOGIN_REJECTED', '旧密码失效');
  member = await login(memberPage, 'member.two', RESET_PASSWORD);
  assert.equal(member.account.phase, 'authenticated');
  admin = await adminStep(adminPage, 'adminRevokeSessions');
  assert.match(adminPage.text('adminNotice'), /撤销会话 1 条/);
  await memberPage.click('refreshTraffic');
  member = await waitFor(memberPage, (snap) => snap.account?.notice?.code === 'SESSION_EXPIRED');
  assert.equal(member.userRef, null);
  adminPage.close();
  memberPage.close();
  endpoint.double.close();
  adminPrepared.close();
  memberPrepared.close();
});

test('RC2 凭据隔离：用户只换到自己的个人凭据；未分配或分配撤销后换不到', async () => {
  const adminPrepared = await prepare('rc2-credentials-admin');
  const endpoint = controlEndpoint(adminPrepared);
  const adminPage = (await openPage('rc2-credentials-admin', adminPrepared, endpoint)).page;
  await setupAndLogin(adminPage);
  await adminStep(adminPage, 'adminRefresh');
  const aliceRef = await createMember(adminPage, 'alice');
  const bobRef = await createMember(adminPage, 'bob');
  await createMember(adminPage, 'carol');
  await saveResource(adminPage, {id: 'res-front', role: 'front', host: 'front.synthetic.invalid', sharing: 'shared'});
  await saveResource(adminPage, {id: 'res-a-shared', role: 'A', host: 'exit-a.synthetic.invalid', sharing: 'shared'});
  await saveTemplate(adminPage);
  for (const [userRef, name] of [[aliceRef, 'alice'], [bobRef, 'bob']]) {
    await selectUser(adminPage, userRef);
    await saveCredential(adminPage, 'cred-res-front', `${name}-front`, `synthetic-${name}-front-pass`);
    await saveCredential(adminPage, 'cred-res-a-shared', `${name}-exit`, `synthetic-${name}-exit-pass`);
    await assignAndPublish(adminPage, 'res-a-shared');
  }

  const alicePrepared = await prepare('rc2-credentials-alice');
  const alicePage = (await openPage('rc2-credentials-alice', alicePrepared, endpoint)).page;
  await waitFor(alicePage, (snap) => snap.account?.phase === 'login_required');
  const alice = await login(alicePage, 'alice', MEMBER_PASSWORD);
  assert.equal(alice.userRef, aliceRef);
  assert.equal(alicePage.window.__STEWARD_HOST_REPORT__.credentials, 'AVAILABLE');
  const aliceToken = endpoint.double.requests.filter((item) => item.path === '/api/network/credentials').at(-1).bearer;
  const aliceMaterial = endpoint.double.credentialsFor(aliceToken);
  assert.equal(aliceMaterial.credentials['cred-res-a-shared'].username, 'alice-exit');
  assert.equal(JSON.stringify(aliceMaterial).includes('bob'), false, '同一 credential_ref 下拿不到别人的材料');
  assert.equal(`${exposed(alicePage)}\n${await snapshotText(alicePage)}`.includes('synthetic-alice'), false, '自己的凭据也不进页面状态');

  const carolPrepared = await prepare('rc2-credentials-carol');
  const carolPage = (await openPage('rc2-credentials-carol', carolPrepared, endpoint)).page;
  await waitFor(carolPage, (snap) => snap.account?.phase === 'login_required');
  const carol = await login(carolPage, 'carol', MEMBER_PASSWORD);
  assert.equal(carol.account.assignment.status, 'UNASSIGNED');
  assert.equal(carolPage.window.__STEWARD_HOST_REPORT__.credentials, 'NOT_ATTACHED', '未分配换不到凭据');

  await selectUser(adminPage, aliceRef);
  const revoked = await adminStep(adminPage, 'adminRevoke');
  assert.equal(revoked.admin.assignment.published.status, 'REVOKED');
  await alicePage.click('accountRetry');
  const refreshed = await waitFor(alicePage, (snap) => snap.account?.assignment?.status === 'REVOKED');
  assert.match(alicePage.text('assignmentStatus'), /已撤销/);
  assert.equal(alicePage.window.__STEWARD_HOST_REPORT__.credentials, 'NOT_ATTACHED', '撤销后重新装配换不到凭据');
  assert.equal(refreshed.userRef, aliceRef);
  for (const runtime of [adminPage, alicePage, carolPage]) runtime.close();
  endpoint.double.close();
  for (const item of [adminPrepared, alicePrepared, carolPrepared]) item.close();
});

test('RC2 未配置与离线不伪造成功：权威未配置时额度操作报错、普通用户看到陈旧未知额度；控制端断开时管理动作显示故障', async () => {
  const prepared = await prepare('rc2-unconfigured');
  const endpoint = controlEndpoint(prepared);
  const {page} = await openPage('rc2-unconfigured', prepared, endpoint);
  await setupAndLogin(page);
  await adminStep(page, 'adminRefresh');
  const memberRef = await createMember(page, 'member.three');
  await selectUser(page, memberRef);
  page.setValue('adminLimitValue', '250');
  page.setValue('adminLimitUnit', 'GB');
  page.setValue('adminLimitExpire', '2027-01-01T00:00:00.000Z');
  let snap = await adminStep(page, 'adminAllocate');
  assert.equal(snap.admin.error.code, 'AUTHORITY_UNCONFIGURED');
  assert.match(page.text('adminError'), /配额适配未配置/);
  assert.equal(snap.admin.usage, null, '没有伪造额度结果');
  snap = await adminStep(page, 'adminPool');
  assert.equal(snap.admin.error.code, 'AUTHORITY_UNCONFIGURED');
  assert.equal(snap.admin.modelConfig.tasks.cleanup.status, 'UNAVAILABLE');

  await logout(page);
  snap = await login(page, 'member.three', MEMBER_PASSWORD);
  assert.equal(snap.ai.available, false);
  await page.click('refreshTraffic');
  snap = await waitFor(page, (item) => Boolean(item.traffic.quota));
  assert.equal(snap.traffic.quota.status, 'UNKNOWN', '权威未配置时额度是未知，不是零也不是无限');
  assert.equal(snap.traffic.quota.stale, true);
  assert.equal(snap.traffic.quota.unlimited, false);
  await logout(page);
  await login(page, 'admin.ops', ADMIN_PASSWORD);
  snap = await adminStep(page, 'adminRefresh');
  const usersBefore = snap.admin.users.length;

  endpoint.disconnect();
  page.setValue('adminNewUsername', 'member.offline');
  page.setValue('adminNewPassword', MEMBER_PASSWORD);
  snap = await adminStep(page, 'adminCreateUser');
  assert.equal(snap.admin.error.code, 'CONTROL_UNREACHABLE', '连不上控制端时不显示已创建');
  snap = await waitFor(page, (item) => item.account?.control?.status === 'failed');
  assert.match(page.text('controlStatus'), /CONTROL_EXITED/);
  assert.equal(snap.admin.users.length, usersBefore, '页面没有在本地添加用户');
  snap = await adminStep(page, 'adminRefresh');
  assert.equal(snap.admin.error.code, 'CONTROL_EXITED', '确认失败后管理动作直接回具体故障');
  page.close();
  endpoint.double.close();
  prepared.close();
});

test('RC4 管理员按环境配置探测服务，客户端登录后只为配置了的环境建探测端口', async () => {
  const prepared = await prepare('rc4-probe-services');
  const endpoint = controlEndpoint(prepared);
  assert.equal((await endpoint.double.setupFromHost({username: 'admin', password: ADMIN_PASSWORD})).ok, true);
  const call = async (method, pathname, token, body) => {
    const headers = {};
    if (token) headers.authorization = `Bearer ${token}`;
    if (body) headers['content-type'] = 'application/json';
    const response = await endpoint.double.handle(new Request(`${CONTROL_BASE_URL}${pathname}`, {method, headers, body: body ? JSON.stringify(body) : undefined}));
    return {status: response.status, body: await response.json().catch(() => null)};
  };
  const login = await call('POST', '/api/auth/login', null, {username: 'admin', password: ADMIN_PASSWORD});
  const token = login.body.access_token;
  const host = {
    environment_ref: prepared.env,
    echo_url: `${CONTROL_BASE_URL}/probe/host/ip`,
    doh_url: `${CONTROL_BASE_URL}/probe/host/dns-query`,
    probe_base_url: `${CONTROL_BASE_URL}/probe/host`,
    stun_urls: ['stun:stun.synthetic.invalid:3478'],
    client_kind: 'webview',
  };
  const saved = await call('PUT', '/api/admin/probe-services', token, host);
  assert.equal(saved.status, 200, JSON.stringify(saved.body));
  assert.equal(saved.body.probe_services.version, 1);
  assert.equal((await call('PUT', '/api/admin/probe-services', token, {...host, echo_url: 'http://echo.synthetic.invalid/ip'})).status, 400, '非回环的 http 地址不收');
  assert.equal((await call('PUT', '/api/admin/probe-services', token, {...host, stun_urls: ['turn:relay.synthetic.invalid']})).status, 400, 'STUN 不收 TURN');
  assert.equal((await call('PUT', '/api/admin/probe-services', token, {...host, expected_version: 0})).status, 409, '按版本防覆盖');

  const double = createNativeHostDouble({
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
    control: () => endpoint.status,
    session: {access_token: token, expires_at: login.body.expires_at, user_ref: login.body.user.user_ref},
    network: {readState: async () => ({}), apply: async () => ({}), protect: async () => ({})},
  });
  const options = await createProductRuntimeOptions({
    invoke: double.invoke,
    confirm: double.confirm,
    fetchImpl: createHostFetch({controlBaseUrl: CONTROL_BASE_URL, controlHandler: endpoint.handler, coreControllerUrl: CORE_CONTROLLER_URL, core: prepared.core}),
    navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true},
    clock: prepared.clock,
  });
  assert.equal(options.hostReport.probe_source, 'control');
  assert.deepEqual(options.hostReport.probe_environments, [prepared.env], '只为配置了的环境建端口');
  assert.deepEqual(options.diagnosticPorts.iceServers, [{urls: ['stun:stun.synthetic.invalid:3478']}], 'STUN 地址交给 WebRTC 与默认浏览器诊断页');
  const uncovered = prepared.environments.map((item) => item.environment_ref).filter((ref) => ref !== prepared.env);
  assert.ok(options.hostReport.unimplemented.includes(`diagnostics.probe_services:${uncovered.join(',')}`), '没配置的环境如实缺测');
  endpoint.double.close();
  prepared.close();
});

test('RC4 管理页的探测服务表单：保存经控制端校验，列表回显，删除后不再下发', async () => {
  const prepared = await prepare('rc4-probe-page');
  const endpoint = controlEndpoint(prepared);
  const {page} = await openPage('rc4-probe-page', prepared, endpoint);
  await setupAndLogin(page);
  await adminStep(page, 'adminRefresh');

  page.setValue('adminProbeEnv', 'windows-host');
  page.setValue('adminProbeEcho', 'http://echo.synthetic.invalid/ip');
  const refused = await adminStep(page, 'adminProbeSave');
  assert.equal(refused.admin.error?.code, 'CONTROL_REQUEST_INVALID', '非回环 http 被控制端拒绝');

  page.setValue('adminProbeEcho', 'https://echo.synthetic.invalid/ip');
  page.setValue('adminProbeStun', 'stun:stun.synthetic.invalid:3478, stun:stun2.synthetic.invalid');
  const saved = await adminStep(page, 'adminProbeSave');
  assert.equal(saved.admin.error, null, JSON.stringify(saved.admin.error));
  assert.equal(saved.admin.probeServices.length, 1);
  assert.deepEqual(saved.admin.probeServices[0].config.stun_urls, ['stun:stun.synthetic.invalid:3478', 'stun:stun2.synthetic.invalid']);
  assert.match(page.text('adminProbeView'), /echo\.synthetic\.invalid/);

  const removed = await adminStep(page, 'adminProbeRemove');
  assert.equal(removed.admin.error, null);
  assert.deepEqual(removed.admin.probeServices, []);
  page.close();
  endpoint.double.close();
  prepared.close();
});

test('MINOR 管理页保存探测服务带上看到的版本：别人先改过就回 409 并刷新，不静默覆盖', async () => {
  const prepared = await prepare('rc4-probe-version');
  const endpoint = controlEndpoint(prepared);
  const {page} = await openPage('rc4-probe-version', prepared, endpoint);
  await setupAndLogin(page);
  const request = async (method, pathname, token, body) => {
    const response = await endpoint.double.handle(new Request(`${CONTROL_BASE_URL}${pathname}`, {
      method,
      headers: {...(token ? {authorization: `Bearer ${token}`} : {}), ...(body ? {'content-type': 'application/json'} : {})},
      body: body ? JSON.stringify(body) : undefined,
    }));
    return {status: response.status, body: await response.json().catch(() => null)};
  };

  page.setValue('adminProbeEnv', 'windows-host');
  page.setValue('adminProbeEcho', 'https://echo-a.synthetic.invalid/ip');
  const first = await adminStep(page, 'adminProbeSave');
  assert.equal(first.admin.error, null, JSON.stringify(first.admin.error));
  assert.equal(first.admin.probeServices[0].version, 1);

  const other = (await request('POST', '/api/auth/login', null, {username: 'admin.ops', password: ADMIN_PASSWORD})).body.access_token;
  const concurrent = await request('PUT', '/api/admin/probe-services', other, {environment_ref: 'windows-host', echo_url: 'https://echo-b.synthetic.invalid/ip', expected_version: 1});
  assert.equal(concurrent.status, 200, '另一位管理员基于版本 1 改成功');

  page.setValue('adminProbeEcho', 'https://echo-c.synthetic.invalid/ip');
  const conflicted = await adminStep(page, 'adminProbeSave');
  assert.equal(conflicted.admin.error?.code, 'PROBE_SERVICES_CONFLICT', '页面看到的是版本 1，不能覆盖版本 2');
  assert.equal(conflicted.admin.probeServices[0].version, 2, '冲突后列表刷新到最新版本');
  assert.equal(conflicted.admin.probeServices[0].config.echo_url, 'https://echo-b.synthetic.invalid/ip', '别人的修改保留着');

  const retried = await adminStep(page, 'adminProbeSave');
  assert.equal(retried.admin.error, null, JSON.stringify(retried.admin.error));
  assert.equal(retried.admin.probeServices[0].version, 3);
  assert.equal(retried.admin.probeServices[0].config.echo_url, 'https://echo-c.synthetic.invalid/ip');
  page.close();
  endpoint.double.close();
  prepared.close();
});
