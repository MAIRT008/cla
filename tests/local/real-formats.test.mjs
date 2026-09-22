import assert from 'node:assert/strict';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {DatabaseSync} from 'node:sqlite';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {createSyntheticLocalService} from '../../src/adapters/local/index.mjs';
import {claudeAccountIdentity, endpointHost, isClaudeSiteHost, maskEmail} from '../../src/core/local/realFormats.mjs';
import {createCcSwitchDatabase, createCookieDatabase} from './demo.mjs';

const EMAIL = 'synthetic.owner@example.invalid';
const ACCOUNT = '00000000-0000-4000-8000-00000000a001';
const ORGANIZATION = '00000000-0000-4000-8000-00000000b002';
const OAUTH_TOKEN = 'SYNTHETIC_OAUTH_ACCESS_TOKEN';
const RELAY_TOKEN = 'SYNTHETIC_RELAY_TOKEN';
const SITE_HOSTS = ['claude.ai', 'claude.com', 'anthropic.com'];

/**
 * 按真实客户端的文件格式摆一套合成数据，路径按宿主解析后的 `roots/<root_ref>/…` 放在工作区里；
 * 环境声明与宿主 discovery.rs 为这些已授权根生成的同形。内容全部是合成值。
 */
async function realFormatWorkspace(label) {
  const root = transientRun('local', label);
  const write = async (relative, value) => {
    const target = path.join(root, ...relative.split('/'));
    await mkdir(path.dirname(target), {recursive: true});
    await writeFile(target, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  };
  await write('roots/claude-code-state', {
    userID: 'synthetic-anonymous-id',
    oauthAccount: {accountUuid: ACCOUNT, emailAddress: EMAIL, organizationUuid: ORGANIZATION, organizationName: 'Synthetic Org', displayName: 'Synthetic'},
    projects: {'D:/work/keep-me': {allowedTools: [], history: [{display: 'keep this project history'}]}},
    mcpServers: {keep: {command: 'synthetic-mcp'}},
  });
  await write('roots/claude-code-home/.credentials.json', {claudeAiOauth: {accessToken: OAUTH_TOKEN, refreshToken: 'SYNTHETIC_REFRESH', expiresAt: 1, scopes: ['user:inference']}});
  await write('roots/claude-code-home/settings.json', {env: {ANTHROPIC_BASE_URL: 'https://relay.synthetic.invalid/api', ANTHROPIC_AUTH_TOKEN: RELAY_TOKEN}, permissions: {allow: []}});
  await write('roots/claude-code-home/projects/keep-me/session.jsonl', '{"project":"keep-me"}\n');
  await write('roots/claude-desktop-roaming/config.json', {locale: 'zh-CN', 'oauth:tokenCache': 'SYNTHETIC_DESKTOP_TOKEN_CACHE'});
  await write('roots/claude-desktop-roaming/claude_desktop_config.json', {mcpServers: {keep: {command: 'synthetic-mcp'}}});
  await write('roots/claude-desktop-roaming/Cache/Cache_Data/data_0', 'binary-cache-block');
  await write('roots/claude-desktop-roaming/Cache/Cache_Data/f_000001', 'binary-cache-block');
  await write('roots/claude-3p-local/providers.json', {endpoint: 'https://third.synthetic.invalid'});

  await mkdir(path.join(root, 'roots/claude-desktop-roaming/Network'), {recursive: true});
  claudeCookies(path.join(root, 'roots/claude-desktop-roaming/Network/Cookies'));
  await mkdir(path.join(root, 'roots/chrome-default/Network'), {recursive: true});
  claudeCookies(path.join(root, 'roots/chrome-default/Network/Cookies'));
  await mkdir(path.join(root, 'roots/cc-switch'), {recursive: true});
  realCcSwitch(path.join(root, 'roots/cc-switch/cc-switch.db'));
  return root;
}

/** 在合成 Chromium v24 库里加上 Claude 站点的记录；原有的 .claude.example 记录充当「其他站点」。 */
function claudeCookies(file) {
  createCookieDatabase(file);
  const db = new DatabaseSync(file);
  try {
    const insert = db.prepare('INSERT INTO cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    for (const [host, name] of [['.claude.ai', 'sessionKey'], ['claude.ai', 'lastActiveOrg'], ['.anthropic.com', 'ajs_user_id']]) {
      insert.run(13438656000000001n, host, '', name, '', Buffer.from([9]), '/', 0, 1, 1, 13438656000000002n, 0, 0, 1, 0, 2, 443, 13438656000000003n, 0, 0);
    }
  } finally { db.close(); }
}

/** CC Switch v18 的真实 Provider 形状：凭据与端点在 settings_config.env 里，is_current 标出当前使用的那个。 */
function realCcSwitch(file) {
  createCcSwitchDatabase(file);
  const db = new DatabaseSync(file);
  try {
    db.exec('PRAGMA foreign_keys = ON; DELETE FROM providers;');
    const insert = db.prepare('INSERT INTO providers (id, app_type, name, settings_config, is_current) VALUES (?, ?, ?, ?, ?)');
    insert.run('relay-current', 'claude', 'Synthetic relay', JSON.stringify({env: {ANTHROPIC_BASE_URL: 'https://relay.synthetic.invalid', ANTHROPIC_AUTH_TOKEN: RELAY_TOKEN}}), 1);
    insert.run('relay-old', 'claude', 'Synthetic old relay', JSON.stringify({env: {ANTHROPIC_BASE_URL: 'https://old.synthetic.invalid'}}), 0);
  } finally { db.close(); }
}

function hostDeclaration({withState = true} = {}) {
  const client = (rootRef, clientRef, category, label, profileRef = null) => ({
    client_ref: clientRef, environment_ref: 'windows-host', installed: true, authorized: true, path_prefix: `roots/${rootRef}`, profile_ref: profileRef, category, label,
  });
  const clients = [
    client('claude-code-home', 'claude-code', 'claude_code', 'Claude Code 配置目录'),
    client('claude-desktop-roaming', 'claude-desktop', 'claude_desktop', 'Claude Desktop 用户数据'),
    client('claude-3p-local', 'claude-3p', 'third_party', 'Claude-3p（本地）'),
    client('cc-switch', 'cc-switch', 'third_party', 'CC Switch 配置'),
    client('chrome-default', 'browser-chrome', 'browser_profile', 'Google Chrome · 用户 1', 'Default'),
  ];
  const scopes = ['roots/claude-code-home', 'roots/claude-desktop-roaming', 'roots/claude-3p-local', 'roots/cc-switch', 'roots/chrome-default/Network/Cookies'];
  const jsonShapes = [
    {relative_path: 'roots/claude-code-home/settings.json', role: 'claude_code_settings'},
    {relative_path: 'roots/claude-code-home/.credentials.json', role: 'claude_code_credentials'},
    {relative_path: 'roots/claude-desktop-roaming/config.json', role: 'claude_desktop_config'},
  ];
  if (withState) {
    clients.push(client('claude-code-state', 'claude-code', 'claude_code', 'Claude Code 账号与项目状态'));
    scopes.push('roots/claude-code-state');
    jsonShapes.push({relative_path: 'roots/claude-code-state', role: 'claude_code_state'});
  }
  return {
    status: 'DETECTED',
    environment_ref: 'windows-host',
    source_ref: 'host-discovery-v1',
    source_version: 'host-discovery-v1',
    scopes,
    clients,
    default_browser: {status: 'DETECTED', browser: 'chrome', client_ref: 'browser-chrome', profile_ref: null},
    json_shapes: jsonShapes,
    object_kinds: [
      {relative_path: 'roots/claude-desktop-roaming/Network/Cookies', kind: 'cookie_sqlite'},
      {relative_path: 'roots/chrome-default/Network/Cookies', kind: 'cookie_sqlite'},
      {relative_path: 'roots/cc-switch/cc-switch.db', kind: 'cc_switch_sqlite'},
    ],
    site_hosts: SITE_HOSTS,
    gaps: [],
  };
}

async function scanned(label, options = {}) {
  const root = await realFormatWorkspace(label);
  const service = createSyntheticLocalService({workspaceRoot: root, environment: hostDeclaration(options)});
  const scan = await service.discover({mode: 'deep', profileRefs: ['Default']});
  return {root, service, scan};
}

function answer(service, scan, statusFor) {
  for (const identity of scan.identities) {
    service.recordAccountAnswer({scanId: scan.scan_id, identityRef: identity.identity_ref, identityFingerprint: identity.identity_fingerprint, status: statusFor(identity)});
  }
}

test('真实格式辅助函数：身份脱敏且稳定，站点与端点只取主机', () => {
  const first = claudeAccountIdentity({accountUuid: ACCOUNT, emailAddress: EMAIL, organizationUuid: ORGANIZATION});
  const again = claudeAccountIdentity({accountUuid: ACCOUNT, emailAddress: 'changed@example.invalid', organizationUuid: ORGANIZATION});
  assert.equal(first.identity_ref, again.identity_ref, '同一账号与组织得到同一引用');
  assert.ok(!first.identity_ref.includes(ACCOUNT));
  assert.equal(maskEmail(EMAIL), 's***@example.invalid');
  assert.ok(first.label.includes('s***@example.invalid') && first.label.includes('…b002'));
  assert.equal(claudeAccountIdentity({}), null);
  assert.ok(isClaudeSiteHost('.claude.ai', SITE_HOSTS) && isClaudeSiteHost('console.anthropic.com', SITE_HOSTS));
  assert.ok(!isClaudeSiteHost('.claude.example', SITE_HOSTS) && !isClaudeSiteHost('notclaude.ai', SITE_HOSTS));
  assert.equal(endpointHost('https://Relay.Synthetic.invalid:8443/v1?x=1'), 'relay.synthetic.invalid');
  assert.equal(endpointHost('not a url'), null);
});

test('F09/F15：从真实格式认出账号与网站登录，不记邮箱原文、凭据与其他站点的 Cookie', async () => {
  const {scan} = await scanned('real-identify');
  const kinds = Object.fromEntries(scan.identities.map((identity) => [identity.identity_ref, identity.kind]));
  const account = scan.identities.find((identity) => identity.kind === 'claude_account');
  assert.ok(account, JSON.stringify(scan.identities));
  assert.ok(account.label.includes('s***@example.invalid'));
  assert.equal(kinds['site-login-chrome-default'], 'site_login');
  assert.equal(kinds['site-login-claude-desktop-roaming'], 'site_login');

  const state = scan.objects.find((object) => object.relative_path === 'roots/claude-code-state');
  assert.equal(state.kind, 'json', '声明了角色的文件根按 JSON 读');
  assert.ok(state.protected_paths.includes('projects') && state.protected_paths.includes('mcpServers'), '项目与 MCP 配置受保护');
  const credentials = scan.objects.find((object) => object.relative_path.endsWith('.credentials.json'));
  assert.deepEqual(credentials.identities, [account.identity_ref], '凭据按同一客户端归属到唯一的账号');
  assert.equal(credentials.removable_items.find((item) => item.field_path === 'claudeAiOauth').evidence, 'same_client');

  const chromeCookies = scan.objects.find((object) => object.relative_path === 'roots/chrome-default/Network/Cookies');
  assert.equal(chromeCookies.kind, 'cookie_sqlite', 'Cookie 库按发现声明的类型识别');
  assert.deepEqual(chromeCookies.cookies.map((cookie) => cookie.host_key).sort(), ['.anthropic.com', '.claude.ai', 'claude.ai']);
  assert.equal(chromeCookies.profile_ref, 'Default');

  const recorded = JSON.stringify(scan);
  for (const secret of [EMAIL, ACCOUNT, OAUTH_TOKEN, RELAY_TOKEN, 'SYNTHETIC_DESKTOP_TOKEN_CACHE', 'restricted-session', '.claude.example']) {
    assert.ok(!recorded.includes(secret), `扫描记录不应包含 ${secret}`);
  }

  const cache = scan.objects.filter((object) => object.relative_path.includes('/Cache/'));
  assert.equal(cache.length, 2);
  assert.ok(cache.every((object) => object.status === 'unsupported' && object.read === false && !object.sha256), '不支持的缓存块不读、不取指纹');
  const unsupported = scan.coverage.gaps.filter((gap) => gap.code === 'UNSUPPORTED_FORMAT');
  assert.equal(unsupported.length, 1, '同一目录的不支持文件合并成一条缺口');
  assert.ok(unsupported[0].message.includes('2 file(s)'));
});

test('F10—F12/F14：受限账号的登录资料进推荐，正常登录与第三方来源只报告', async () => {
  const {root, service, scan} = await scanned('real-restricted');
  answer(service, scan, (identity) => (identity.kind === 'claude_account' ? 'restricted' : 'normal'));
  const classification = service.classify({scanId: scan.scan_id});
  const targets = classification.recommendations.map((item) => `${item.kind}:${item.relative_path}:${item.selector?.field_path || ''}`).sort();
  assert.deepEqual(targets, [
    'json_remove:roots/claude-code-home/.credentials.json:claudeAiOauth',
    'json_remove:roots/claude-code-state:oauthAccount',
  ]);
  assert.ok(!classification.recommendations.some((item) => item.kind === 'cookie_delete'), '正常使用的网站登录不进推荐');
  const loginProblems = classification.problems.filter((problem) => problem.root_cause_ref.startsWith('login-material:'));
  assert.equal(loginProblems.length, 1, '同一受限账号的登录资料是一个根因');

  const sources = classification.third_party_sources;
  const settings = sources.find((item) => item.source === 'claude_code_settings');
  assert.equal(settings.endpoint_host, 'relay.synthetic.invalid');
  assert.equal(settings.active, true);
  assert.deepEqual(settings.matching_cc_switch_providers, ['relay-current'], '生效配置与 CC Switch 当前 Provider 对得上');
  assert.deepEqual(sources.filter((item) => item.source === 'cc_switch').map((item) => [item.provider_id, item.active]).sort(), [['relay-current', true], ['relay-old', false]]);
  assert.ok(!classification.problems.some((problem) => /third|provider/i.test(problem.root_cause_ref)), '第三方来源本身不扣分');
  const thirdParty = classification.result_groups.find((group) => group.category === 'third_party_configuration');
  const thirdPartyPaths = scan.objects.filter((object) => thirdParty.object_refs.includes(object.object_ref)).map((object) => object.relative_path);
  assert.ok(thirdPartyPaths.includes('roots/claude-3p-local/providers.json'), '按客户端类别归入第三方');

  const plan = await service.buildActionPlan({scanId: scan.scan_id, recommendationIds: classification.recommendations.map((item) => item.recommendation_id)});
  await service.confirmActionPlan({planId: plan.plan_id, version: plan.version, actionIds: plan.actions.map((item) => item.action_id), source: 'local-user'});
  const operation = await service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'real-restricted-op'});
  assert.equal(operation.status, 'completed', JSON.stringify(operation.receipts));

  const state = JSON.parse(await readFile(path.join(root, 'roots/claude-code-state'), 'utf8'));
  assert.equal(state.oauthAccount, undefined, '受限账号的登录记录被移除');
  assert.deepEqual(Object.keys(state.projects), ['D:/work/keep-me'], '项目历史原样保留');
  assert.deepEqual(state.mcpServers, {keep: {command: 'synthetic-mcp'}});
  const credentials = JSON.parse(await readFile(path.join(root, 'roots/claude-code-home/.credentials.json'), 'utf8'));
  assert.equal(credentials.claudeAiOauth, undefined);
  const settingsAfter = JSON.parse(await readFile(path.join(root, 'roots/claude-code-home/settings.json'), 'utf8'));
  assert.equal(settingsAfter.env.ANTHROPIC_AUTH_TOKEN, RELAY_TOKEN, '第三方配置不因存在就被清');

  const backup = operation.receipts.find((receipt) => receipt.backup_ref && receipt.action_id === plan.actions.find((item) => item.relative_path === 'roots/claude-code-state').action_id);
  const preview = await service.previewRestore({backupRef: backup.backup_ref});
  assert.equal(preview.recoverable, true, JSON.stringify(preview));
  service.confirmRestore({previewId: preview.preview_id, source: 'local-user'});
  await service.restoreChange({previewId: preview.preview_id});
  const restored = JSON.parse(await readFile(path.join(root, 'roots/claude-code-state'), 'utf8'));
  assert.equal(restored.oauthAccount.accountUuid, ACCOUNT, '恢复写回登录记录');
});

test('F15：受限的网站登录只删 Claude 站点的 Cookie，Desktop 令牌缓存随同一登录处理', async () => {
  const {root, service, scan} = await scanned('real-site-login');
  answer(service, scan, (identity) => (identity.identity_ref === 'site-login-claude-desktop-roaming' ? 'restricted' : 'normal'));
  const classification = service.classify({scanId: scan.scan_id});
  const cookieActions = classification.recommendations.filter((item) => item.kind === 'cookie_delete');
  assert.equal(cookieActions.length, 3);
  assert.ok(cookieActions.every((item) => item.relative_path === 'roots/claude-desktop-roaming/Network/Cookies'), '只动受限那个登录所在的库');
  assert.ok(classification.recommendations.some((item) => item.kind === 'json_remove' && item.selector.field_path === 'oauth:tokenCache'));

  const plan = await service.buildActionPlan({scanId: scan.scan_id, recommendationIds: classification.recommendations.map((item) => item.recommendation_id)});
  await service.confirmActionPlan({planId: plan.plan_id, version: plan.version, actionIds: plan.actions.map((item) => item.action_id), source: 'local-user'});
  const operation = await service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'real-site-login-op'});
  assert.equal(operation.status, 'completed', JSON.stringify(operation.receipts));

  const read = (file) => {
    const db = new DatabaseSync(file, {readOnly: true});
    try { return db.prepare('SELECT host_key FROM cookies ORDER BY host_key').all().map((row) => row.host_key); } finally { db.close(); }
  };
  assert.deepEqual(read(path.join(root, 'roots/claude-desktop-roaming/Network/Cookies')), ['.claude.example', '.claude.example', '.claude.example'], '其他站点的 Cookie 原样');
  assert.equal(read(path.join(root, 'roots/chrome-default/Network/Cookies')).length, 6, '正常使用的浏览器登录不动');
  const config = JSON.parse(await readFile(path.join(root, 'roots/claude-desktop-roaming/config.json'), 'utf8'));
  assert.equal(config['oauth:tokenCache'], undefined);
  assert.equal(config.locale, 'zh-CN');
});

test('F09：凭据找不到唯一归属时记缺口，不进推荐', async () => {
  const {service, scan} = await scanned('real-owner-unknown', {withState: false});
  assert.ok(!scan.identities.some((identity) => identity.kind === 'claude_account'));
  assert.ok(scan.coverage.gaps.some((gap) => gap.code === 'CREDENTIAL_OWNER_UNKNOWN' && gap.message.includes('claudeAiOauth')));
  answer(service, scan, () => 'restricted');
  const classification = service.classify({scanId: scan.scan_id});
  assert.ok(!classification.recommendations.some((item) => item.selector?.field_path === 'claudeAiOauth'), '归属不明的凭据不推荐清理');
  assert.equal(classification.score.status, 'unknown', '有缺口就不给最终分');
});
