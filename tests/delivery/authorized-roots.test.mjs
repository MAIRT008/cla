import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {mkdir, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {DatabaseSync} from 'node:sqlite';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {createPageRuntime} from '../ui/page.mjs';
import {createCcSwitchDatabase, createCookieDatabase} from '../local/demo.mjs';
import {composition} from './harness.mjs';
import {createNativeHostDouble} from './nativeHostDouble.mjs';
import {PERSISTED_MAX_SESSION, createHostFetch, readyControl, withIdentityRoutes} from './productHost.mjs';

const CONTROL_BASE_URL = 'https://control.synthetic.invalid';
const CORE_CONTROLLER_URL = 'http://127.0.0.1:9797';
const LEGACY = 'third-party/pure-legacy.json';

/**
 * 合成「用户目录」：落在工作区之外的另一棵临时树里，模拟宿主在真实 Windows 用户下发现的位置。
 * 工作区里的 input/ 合成夹具保持不动，用来确认测试工作区与真实根分开。
 */
async function createSyntheticProfile(profile) {
  const write = async (relative, value) => {
    const target = path.join(profile, ...relative.split('/'));
    await mkdir(path.dirname(target), {recursive: true});
    await writeFile(target, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  };
  await write(`.claude/${LEGACY}`, {legacyProvider: {identity_ref: 'restricted-account', credential: 'SYNTHETIC_REAL_ROOT_SECRET'}});
  await write('.claude/settings.json', {env: {ANTHROPIC_MODEL: 'synthetic-model'}, permissions: {allow: []}});
  await write('.claude/projects/keep/notes.jsonl', '{"project":"keep-me"}\n');
  await mkdir(path.join(profile, '.cc-switch'), {recursive: true});
  createCcSwitchDatabase(path.join(profile, '.cc-switch', 'cc-switch.db'));
  await mkdir(path.join(profile, 'Chrome', 'Default', 'Network'), {recursive: true});
  createCookieDatabase(path.join(profile, 'Chrome', 'Default', 'Network', 'Cookies'));
}

/** 与 discovery.rs 的候选项同形：路径是宿主测得的绝对路径，页面只拿 root_ref 指代它们。 */
function discoveryFor(profile) {
  const base = {environment_ref: 'windows-host', status: 'found', authorizable: true, scan_prefixes: [], object_kinds: [], json_shapes: [], profile: null};
  return {
    candidates: [
      {...base, root_ref: 'claude-code-home', kind: 'directory', client_ref: 'claude-code', category: 'claude_code', label: 'Claude Code 配置目录', path: path.join(profile, '.claude'), json_shapes: [{path: 'settings.json', role: 'claude_code_settings'}]},
      {...base, root_ref: 'cc-switch', kind: 'directory', client_ref: 'cc-switch', category: 'third_party', label: 'CC Switch 配置', path: path.join(profile, '.cc-switch'), object_kinds: [{path: 'cc-switch.db', kind: 'cc_switch_sqlite'}]},
      {
        ...base,
        root_ref: 'chrome-default',
        kind: 'directory',
        client_ref: 'browser-chrome',
        category: 'browser_profile',
        label: 'Google Chrome · 用户 1',
        path: path.join(profile, 'Chrome', 'Default'),
        scan_prefixes: ['Network/Cookies'],
        object_kinds: [{path: 'Network/Cookies', kind: 'cookie_sqlite'}, {path: 'Cookies', kind: 'cookie_sqlite'}],
        profile: {browser: 'chrome', profile_dir: 'Default', profile_name: '用户 1', last_used: true},
      },
      {...base, root_ref: 'firefox-synthetic', kind: 'directory', client_ref: 'browser-firefox', category: 'browser_profile', label: 'Firefox · synthetic', path: path.join(profile, 'Firefox'), authorizable: false, reason: 'FIREFOX_FORMAT_UNSUPPORTED'},
      {...base, root_ref: 'claude-3p-local', kind: 'directory', client_ref: 'claude-3p', category: 'third_party', label: 'Claude-3p（本地）', path: path.join(profile, 'Claude-3p'), status: 'not_found', authorizable: false},
    ],
    default_browser: {status: 'DETECTED', prog_id: 'ChromeHTML', browser: 'chrome', client_ref: 'browser-chrome', profile_ref: null},
    environments: [
      {environment_ref: 'windows-host', kind: 'windows', status: 'DETECTED'},
      {environment_ref: 'wsl-ubuntu', kind: 'wsl', distribution: 'Ubuntu', status: 'NOT_SCANNED', reason: 'WSL_NOT_SCANNED'},
    ],
  };
}

async function rootsPage(label, {confirmDecision, hooks = {}} = {}) {
  const prepared = await composition(label);
  const realBase = transientRun('delivery', `${label}-real`);
  const profile = path.join(realBase, 'Users', 'synthetic');
  await createSyntheticProfile(profile);
  const discovery = discoveryFor(profile);
  const double = createNativeHostDouble({
    workspaceRoot: prepared.root,
    realBase,
    clock: prepared.clock,
    confirmDecision,
    hooks,
    discovery,
    product: {
      control_base_url: CONTROL_BASE_URL,
      core_controller_url: CORE_CONTROLLER_URL,
      windows_user: 'synthetic-user',
      environment_ref: 'windows-host',
      control: readyControl(CONTROL_BASE_URL),
    },
    session: PERSISTED_MAX_SESSION,
    network: {readState: async () => ({general: {mode: 'rule'}, loaded_version: null})},
  });
  const page = await createPageRuntime(`${label}-page`, {
    hostPrimitives: {
      __TAURI__: {core: {invoke: (command, args) => {
        if (command === 'steward_user_confirm') return double.confirm(args.request);
        assert.equal(command, 'steward_request');
        return double.invoke(args.op, args.payload, args.authorizationRef);
      }}},
      fetch: createHostFetch({controlBaseUrl: CONTROL_BASE_URL, controlHandler: withIdentityRoutes(prepared), coreControllerUrl: CORE_CONTROLLER_URL, core: prepared.core}),
      navigator: {language: 'en-US', languages: ['en-US'], userAgent: 'synthetic-webview', onLine: true, hardwareConcurrency: 8, cookieEnabled: true},
      RTCPeerConnection: null,
    },
  });
  const steward = page.window.__STEWARD__;
  const close = async () => {
    page.close();
    prepared.close();
    await rm(realBase, {recursive: true, force: true});
  };
  return {prepared, double, page, steward, realBase, profile, discovery, close};
}

function providerIds(file) {
  const db = new DatabaseSync(file, {readOnly: true});
  try {
    return db.prepare('SELECT id FROM providers ORDER BY id').all().map((row) => row.id);
  } finally { db.close(); }
}

async function listFiles(root) {
  const out = [];
  async function visit(current) {
    for (const item of await readdir(current, {withFileTypes: true})) {
      const full = path.join(current, item.name);
      if (item.isDirectory()) await visit(full);
      else out.push(path.relative(root, full).split(path.sep).join('/'));
    }
  }
  await visit(root);
  return out.sort();
}

async function scanAndPlan(steward) {
  const scanned = await steward.localScan('deep');
  assert.equal(scanned.local.error, null, JSON.stringify(scanned.local.error));
  for (const identity of scanned.local.identities) {
    await steward.localAnswer(identity.identity_ref, identity.identity_ref === 'restricted-account' ? 'restricted' : 'normal');
  }
  await steward.localClassify();
  const planned = await steward.localBuildPlan();
  assert.ok(planned.local.plan_id, JSON.stringify(planned.local.error));
  const confirmed = await steward.localConfirm();
  assert.equal(confirmed.local.plan_status, 'CONFIRMED', JSON.stringify(confirmed.local.error));
  return scanned;
}

test('未授权时发现只列位置、不给扫描范围；扫描被拒并点名要先授权', async () => {
  const {steward, double, close} = await rootsPage('roots-unauthorized');
  const discovered = await steward.discoverEnvironment();
  assert.equal(discovered.discovery.error, null);
  assert.equal(discovered.discovery.status, 'NOT_AUTHORIZED');
  assert.deepEqual(discovered.discovery.scopes, []);
  assert.equal(discovered.discovery.candidates.length, 5);
  const gapCodes = discovered.discovery.gaps.map((item) => item.code);
  assert.ok(gapCodes.includes('FIREFOX_FORMAT_UNSUPPORTED'), 'Firefox 登记但标不支持');
  assert.ok(gapCodes.includes('WSL_NOT_SCANNED'), 'WSL 只登记不扫描');
  assert.equal(discovered.discovery.default_browser.browser, 'chrome');

  const callsBefore = double.calls.length;
  const scanned = await steward.localScan('deep');
  assert.equal(scanned.local.error?.code, 'SCOPE_NOT_AUTHORIZED');
  assert.ok(!double.calls.slice(callsBefore).some((item) => item.op === 'FileWalk'), '没有授权范围就不遍历任何位置');

  const direct = await double.invoke('FileRead', {path: 'roots/claude-code-home/settings.json'});
  assert.equal(direct.code, 'NATIVE_PATH_OUT_OF_SCOPE', '未登记的根一个字节都读不到');
  await close();
});

test('授权窗口显示宿主测得的路径；不支持或不存在的位置授权不了', async () => {
  const {steward, double, profile, close} = await rootsPage('roots-authorize');
  const authorized = await steward.authorizeRoots(['claude-code-home', 'cc-switch']);
  assert.equal(authorized.discovery.error, null, JSON.stringify(authorized.discovery.error));
  assert.equal(authorized.discovery.status, 'DETECTED');
  assert.deepEqual(authorized.discovery.scopes.slice().sort(), ['roots/cc-switch', 'roots/claude-code-home']);
  assert.deepEqual(authorized.discovery.authorized_roots.map((item) => item.root_ref), ['cc-switch', 'claude-code-home']);

  const prompt = double.confirmations.at(-1);
  assert.equal(prompt.title, '授权扫描范围');
  assert.ok(prompt.body.includes(path.join(profile, '.claude')), '确认框列出宿主自己测得的路径');
  assert.ok(prompt.body.includes(path.join(profile, '.cc-switch')));

  for (const refused of ['firefox-synthetic', 'claude-3p-local', 'not-discovered']) {
    const result = await steward.authorizeRoots([refused]);
    assert.equal(result.discovery.error?.code, 'NATIVE_ROOT_UNAVAILABLE', refused);
  }
  assert.equal((await steward.authorizeRoots(['../escape'])).discovery.error?.code, 'NATIVE_PAYLOAD_INVALID');
  assert.deepEqual(double.authorizedRoots().map((item) => item.root_ref), ['cc-switch', 'claude-code-home'], '失败的授权不改登记');
  await close();
});

test('用户拒绝授权时登记不变，扫描范围仍为空', async () => {
  const {steward, double, close} = await rootsPage('roots-declined', {confirmDecision: (prompt) => prompt.scope !== 'authorized_roots'});
  const result = await steward.authorizeRoots(['claude-code-home']);
  assert.equal(result.discovery.error?.code, 'NATIVE_CONFIRMATION_DECLINED');
  assert.deepEqual(double.authorizedRoots(), []);
  assert.equal((await steward.discoverEnvironment()).discovery.status, 'NOT_AUTHORIZED');
  await close();
});

test('已授权的真实根走完扫描、计划、确认、执行与恢复；测试工作区 input/ 不被扫描', async () => {
  const {steward, double, profile, prepared, close} = await rootsPage('roots-chain');
  await steward.authorizeRoots(['claude-code-home', 'cc-switch']);
  const legacyFile = path.join(profile, '.claude', ...LEGACY.split('/'));
  const legacyBefore = await readFile(legacyFile, 'utf8');
  const ccSwitch = path.join(profile, '.cc-switch', 'cc-switch.db');
  assert.deepEqual(providerIds(ccSwitch), ['normal-provider', 'restricted-provider']);
  const workspaceInputBefore = await listFiles(path.join(prepared.root, 'input'));

  const scanned = await scanAndPlan(steward);
  const snapshot = await steward.snapshot();
  const objects = snapshot.local.object_count;
  assert.ok(objects >= 4, `应扫到真实根里的对象，实际 ${objects}`);
  const walked = double.calls.filter((item) => item.op === 'FileWalk');
  assert.ok(walked.length > 0);
  assert.ok(scanned.local.identities.some((item) => item.identity_ref === 'restricted-account'));

  const executed = await steward.localExecute();
  assert.equal(executed.local.error, null, JSON.stringify(executed.local.error));
  assert.equal(executed.local.operation_status, 'completed', JSON.stringify(executed.local.receipts));

  assert.equal(existsSync(legacyFile), false, '真实根里的旧第三方文件被删除');
  assert.deepEqual(providerIds(ccSwitch), ['normal-provider'], 'CC Switch 库按发现声明的类型识别并删掉受限 Provider');
  const removed = double.calls.find((item) => item.op === 'FileRemove');
  assert.equal(removed.authorization.target.path, `roots/claude-code-home/${LEGACY}`, '单次确认绑定真实根里的精确目标');
  assert.equal(removed.scope, 'single_confirmation');
  const mutated = double.calls.find((item) => item.op === 'DbMutate');
  assert.equal(mutated.authorization.target.path, 'roots/cc-switch/cc-switch.db');
  for (const call of double.calls.filter((item) => item.scope === 'workspace_owned')) {
    assert.ok(!JSON.stringify(call.authorization).includes('roots/'), '工作区自有授权不碰真实根');
  }

  const backups = await listFiles(path.join(prepared.root, 'backups'));
  assert.ok(backups.length >= 2, '备份落在产品工作区');
  assert.ok(!(await listFiles(profile)).some((item) => item.startsWith('backups/')), '备份不落进用户目录');
  assert.deepEqual(await listFiles(path.join(prepared.root, 'input')), workspaceInputBefore, '测试工作区 input/ 原样');

  const deleteReceipt = executed.local.restorables.find((item) => item.kind === 'delete_file');
  const previewed = await steward.localPreviewRestore(deleteReceipt.backup_ref);
  assert.equal(previewed.local.restore?.recoverable, true, JSON.stringify(previewed.local.restore));
  const restored = await steward.localRestore();
  assert.equal(restored.local.error, null, JSON.stringify(restored.local.error));
  assert.equal(await readFile(legacyFile, 'utf8'), legacyBefore, '恢复把真实文件原样写回');
  await close();
});

test('撤销授权后，已确认未执行的真实根动作被拒，文件保持原样', async () => {
  const {steward, double, profile, close} = await rootsPage('roots-revoke');
  await steward.authorizeRoots(['claude-code-home']);
  await scanAndPlan(steward);
  const legacyFile = path.join(profile, '.claude', ...LEGACY.split('/'));
  const before = await readFile(legacyFile, 'utf8');

  const revoked = await steward.revokeRoots(['claude-code-home']);
  assert.equal(revoked.discovery.error, null);
  assert.equal(revoked.discovery.status, 'NOT_AUTHORIZED');
  assert.deepEqual(double.authorizedRoots(), []);

  const executed = await steward.localExecute();
  assert.notEqual(executed.local.operation_status, 'completed');
  assert.equal(await readFile(legacyFile, 'utf8'), before, '撤销后真实文件不被改动');
  assert.ok(!double.calls.some((item) => item.op === 'FileRemove'), '撤销后不发出任何真实写入');
  await close();
});

test('真实根只能作单次确认绑定的那一个目标：工作区自有授权、复制去向、越界路径都被拒', async () => {
  const {steward, double, close} = await rootsPage('roots-boundaries');
  await steward.authorizeRoots(['claude-code-home']);
  const bytes = Buffer.from('{}\n').toString('base64');

  const owned = await double.confirm({scope: 'workspace_owned', environment_ref: 'windows-host', summary: 'synthetic'});
  assert.equal(owned.ok, true);
  const ownedWrite = await double.invoke('FileWrite', {path: 'roots/claude-code-home/settings.json', bytes}, owned.authorization_ref);
  assert.equal(ownedWrite.code, 'NATIVE_AUTHORIZATION_TARGET_MISMATCH', '工作区自有授权写不进真实根');

  const copy = await double.confirm({scope: 'single_confirmation', plan_ref: 'plan-synthetic', plan_version: 1, action_id: 'action-synthetic', native_op: 'FileCopy', action: 'copy', target: {path: 'input/code/settings.json', kind: 'file'}});
  assert.equal(copy.ok, true, JSON.stringify(copy));
  const copied = await double.invoke('FileCopy', {from: 'input/code/settings.json', to: 'roots/claude-code-home/settings.json'}, copy.authorization_ref);
  assert.equal(copied.code, 'NATIVE_AUTHORIZATION_TARGET_MISMATCH', '复制去向不能是真实根');

  const escape = await double.invoke('FileRead', {path: 'roots/claude-code-home/../../../outside.txt'});
  assert.equal(escape.code, 'NATIVE_PATH_OUT_OF_SCOPE', '越出已授权根的路径被拒');
  const other = await double.invoke('FileRead', {path: 'roots/cc-switch/cc-switch.db'});
  assert.equal(other.code, 'NATIVE_PATH_OUT_OF_SCOPE', '只登记了一个根时，别的根仍读不到');
  await close();
});

async function until(steward, predicate, timeoutMs = 5000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const snap = await steward.snapshot();
    if (!snap?.__unavailable__ && predicate(snap)) return snap;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('timed out waiting for the formal page state');
}

test('页面入口：发现、勾选、授权都走按钮；格式不支持的位置不能勾选', async () => {
  const {page, steward, close} = await rootsPage('roots-page-entry');
  await page.click('discoverEnvironment');
  await until(steward, (snap) => snap.discovery.status === 'NOT_AUTHORIZED');
  const boxes = () => page.document.querySelectorAll('input').filter((item) => item.dataset?.root);
  assert.equal(boxes().find((item) => item.dataset.root === 'firefox-synthetic').disabled, true, 'Firefox 只登记，不能授权');
  assert.equal(boxes().find((item) => item.dataset.root === 'claude-3p-local').disabled, true, '不存在的位置不能授权');
  boxes().find((item) => item.dataset.root === 'claude-code-home').click();
  await page.click('authorizeRoots');
  const done = await until(steward, (snap) => snap.discovery.status === 'DETECTED');
  assert.deepEqual(done.discovery.scopes, ['roots/claude-code-home']);
  assert.match(page.text('discoveryView'), /roots\/claude-code-home/);
  await close();
});

/** CC Switch 切到 WAL、关掉自动检查点；原有 Provider 清掉后，受限 Provider 只提交在 WAL 里，写连接一直开着。 */
function walOnlyProvider(file) {
  const writer = new DatabaseSync(file);
  writer.exec('PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; PRAGMA foreign_keys = ON; DELETE FROM providers;');
  writer.exec('PRAGMA wal_checkpoint(TRUNCATE);');
  writer.prepare('INSERT INTO providers (id, app_type, name, settings_config, is_current) VALUES (?, ?, ?, ?, ?)')
    .run('wal-provider', 'claude', 'WAL-only provider', JSON.stringify({identity_ref: 'restricted-account'}), 0);
  return writer;
}

test('BLOCK 正式链路：CC Switch 记录只在 WAL 里时，经原生桥按一致快照备份、执行与恢复', async () => {
  const fileReads = [];
  const {steward, double, profile, close} = await rootsPage('roots-wal', {hooks: {FileRead: async ({payload}) => { fileReads.push(payload.path); return null; }}});
  const ccSwitch = path.join(profile, '.cc-switch', 'cc-switch.db');
  const writer = walOnlyProvider(ccSwitch);
  try {
    await steward.authorizeRoots(['cc-switch']);
    await scanAndPlan(steward);
    const executed = await steward.localExecute();
    assert.equal(executed.local.operation_status, 'completed', JSON.stringify(executed.local.receipts));
    assert.deepEqual(providerIds(ccSwitch), [], '受限 Provider 被删除');
    const ops = double.calls.map((item) => item.op);
    assert.ok(ops.includes('DbSnapshot') && ops.includes('DbFingerprint'), '备份与复核走数据库一致快照和逻辑指纹');
    assert.ok(fileReads.length > 0, '钩子确实记到了文件读取');
    assert.ok(!fileReads.includes('roots/cc-switch/cc-switch.db'), '不再按主文件字节读库');

    const receipt = executed.local.restorables.find((item) => item.kind === 'cc_provider_delete');
    const previewed = await steward.localPreviewRestore(receipt.backup_ref);
    assert.equal(previewed.local.restore?.recoverable, true, JSON.stringify(previewed.local.restore));
    const restored = await steward.localRestore();
    assert.equal(restored.local.error, null, JSON.stringify(restored.local.error));
    assert.deepEqual(providerIds(ccSwitch), ['wal-provider'], '恢复写回只在 WAL 里的那条记录');
  } finally {
    writer.close();
    await close();
  }
});

test('BLOCK 正式链路：宿主取不到一致快照时不发出任何改写', async () => {
  const unavailable = async () => ({ok: false, code: 'DB_SNAPSHOT_UNAVAILABLE', reason: 'synthetic: database is locked by another process'});
  const {steward, double, profile, close} = await rootsPage('roots-wal-locked', {hooks: {DbSnapshot: unavailable}});
  const ccSwitch = path.join(profile, '.cc-switch', 'cc-switch.db');
  const writer = walOnlyProvider(ccSwitch);
  try {
    await steward.authorizeRoots(['cc-switch']);
    await scanAndPlan(steward);
    const executed = await steward.localExecute();
    assert.notEqual(executed.local.operation_status, 'completed');
    assert.equal(executed.local.receipts[0]?.code, 'DB_SNAPSHOT_UNAVAILABLE', JSON.stringify(executed.local.receipts));
    assert.ok(!double.calls.some((item) => item.op === 'DbMutate'), '没有快照就没有改写');
    assert.deepEqual(providerIds(ccSwitch), ['wal-provider']);
  } finally {
    writer.close();
    await close();
  }
});

test('MAJOR 已授权位置变了（如 CLAUDE_CONFIG_DIR 改指）就标授权过期、收回扫描范围；重新授权后按新位置', async () => {
  const {steward, double, profile, discovery, close} = await rootsPage('roots-stale');
  const first = await steward.authorizeRoots(['claude-code-home']);
  assert.deepEqual(first.discovery.scopes, ['roots/claude-code-home']);

  const moved = path.join(profile, 'custom-claude-config');
  await mkdir(moved, {recursive: true});
  await writeFile(path.join(moved, 'settings.json'), '{}\n', 'utf8');
  discovery.candidates.find((item) => item.root_ref === 'claude-code-home').path = moved;

  const stale = await steward.discoverEnvironment();
  assert.equal(stale.discovery.status, 'NOT_AUTHORIZED', '不再宣称已授权、已覆盖');
  assert.deepEqual(stale.discovery.scopes, []);
  assert.deepEqual(stale.discovery.stale_roots, ['claude-code-home']);
  assert.ok(stale.discovery.gaps.some((gap) => gap.code === 'AUTHORIZED_ROOT_STALE'));
  assert.equal((await steward.localScan('deep')).local.error?.code, 'SCOPE_NOT_AUTHORIZED', '过期的授权不能拿来扫描');

  const again = await steward.authorizeRoots(['claude-code-home']);
  assert.equal(again.discovery.status, 'DETECTED');
  assert.deepEqual(again.discovery.stale_roots, []);
  assert.equal(double.authorizedRoots().find((item) => item.root_ref === 'claude-code-home').path, moved, '登记换成新位置');
  assert.ok(double.confirmations.at(-1).body.includes(moved), '重新确认时显示新位置');
  await close();
});
