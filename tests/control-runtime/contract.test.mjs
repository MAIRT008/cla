import './offline-guard.mjs';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {CONTROL_PROTOCOL as CONTRACT_PROTOCOL, OPS, PRODUCT_CONFIG_FIELDS} from '../../apps/desktop-host/bridge-contract.mjs';
import {CONTROL_PROTOCOL as PAGE_PROTOCOL} from '../../apps/desktop-ui/auth-client.mjs';
import {catalogFor} from '../../src/core/ai/tools.mjs';
import {expectedProtocol} from '../../services/control/modelPolicy.mjs';
import {checkRustSources} from '../../tools/check-rust-sources.mjs';
import {createAuthControlDouble} from './authControlDouble.mjs';

/**
 * 页面、桥接契约、Rust 宿主与 Rust 控制端之间的名字一致性。
 * 这些是源码文本核对：确认同一个接口、字段、协议版本在各侧没有被改名，
 * 以及几条边界在源码里确实成立。它们不是编译或运行证明——Rust 两个 crate 都未编译、未运行。
 */

const read = (relative) => readFile(path.resolve(relative), 'utf8');

test('控制端协议版本在页面、契约、宿主与控制端四处一致', async () => {
  const controlLib = await read('services/control-rs/src/lib.rs');
  const supervisor = await read('apps/desktop-host/src-tauri/src/control_process.rs');
  assert.equal(PAGE_PROTOCOL, 'steward-control-1');
  assert.equal(CONTRACT_PROTOCOL, PAGE_PROTOCOL);
  assert.ok(controlLib.includes(`pub const PROTOCOL_VERSION: &str = "${PAGE_PROTOCOL}";`));
  assert.ok(supervisor.includes(`pub const CONTROL_PROTOCOL: &str = "${PAGE_PROTOCOL}";`));
  assert.ok(controlLib.includes('pub const SERVICE_NAME: &str = "ai-steward-control";'));
  assert.ok(supervisor.includes('pub const CONTROL_SERVICE: &str = "ai-steward-control";'));
});

test('页面调用的每个控制端路径，Rust 路由都有同方法的分支', async () => {
  const router = await read('services/control-rs/src/router.rs');
  const client = await read('apps/desktop-ui/auth-client.mjs');
  const expected = [
    ['GET', '/api/setup/status'],
    ['POST', '/api/auth/login'],
    ['GET', '/api/auth/me'],
    ['POST', '/api/auth/logout'],
  ];
  for (const [method, route] of expected) {
    assert.ok(client.includes(`request('${method}', '${route}'`), `页面应以 ${method} 调 ${route}`);
    assert.ok(router.includes(`("${method}", "${route}") =>`), `router.rs 缺少 ${method} ${route}`);
  }
  assert.ok(router.includes('("POST", "/api/setup/admin") =>'));
  assert.ok(router.includes('("GET", "/health") =>'));
  const supervisor = await read('apps/desktop-host/src-tauri/src/control_process.rs');
  assert.ok(supervisor.includes('"POST",\n            "/api/setup/admin"'), '首启由宿主转交到同一路径');
  assert.ok(supervisor.includes('"GET", "/health"'), '宿主握手读同一个健康检查');
});

test('响应字段两侧同名：登录、身份、首启、错误与退避', async () => {
  const router = await read('services/control-rs/src/router.rs');
  const client = await read('apps/desktop-ui/auth-client.mjs');
  const native = await read('apps/desktop-ui/native.mjs');
  for (const field of ['access_token', 'expires_at', 'user_ref', 'username', 'role', 'status', 'initialized', 'request_ref', 'retry_after_ms', 'code', 'reason']) {
    assert.ok(router.includes(`"${field}"`), `router.rs 没有字段 ${field}`);
    assert.ok(client.includes(field) || native.includes(field), `页面侧没有消费字段 ${field}`);
  }
  for (const code of ['AUTH_SESSION_INVALID', 'AUTH_LOGIN_REJECTED', 'CONTROL_SETUP_CONFLICT', 'CONTROL_SETUP_TOKEN_INVALID', 'CONTROL_FORBIDDEN', 'CONTROL_NOT_FOUND', 'AUTH_THROTTLED', 'CONTROL_STORE_READ_FAILED']) {
    assert.ok(router.includes(code), `router.rs 没有错误码 ${code}`);
  }
  assert.ok(client.includes("'AUTH_SESSION_INVALID'"), '页面按 Rust 的会话失效码退回登录');
});

test('首启凭据头在控制端与宿主两侧同名，页面源码里不出现', async () => {
  const router = await read('services/control-rs/src/router.rs');
  const supervisor = await read('apps/desktop-host/src-tauri/src/control_process.rs');
  assert.ok(router.includes('pub const SETUP_TOKEN_HEADER: &str = "x-steward-setup-token";'));
  assert.ok(supervisor.toLowerCase().includes('"x-steward-setup-token"'));
  for (const file of ['auth-client.mjs', 'native.mjs', 'product-runtime.mjs', 'app.js', 'bridge.js', 'native-boot.mjs', 'index.html']) {
    const source = await read(`apps/desktop-ui/${file}`);
    assert.equal(source.toLowerCase().includes('x-steward-setup-token'), false, `${file} 不应接触首启凭据`);
    assert.equal(source.includes('setup_token'), false, `${file} 不应接触首启凭据`);
  }
});

test('新增桥接能力只有控制端状态、首启提交与会话保管，两侧登记一致', async () => {
  const lib = await read('apps/desktop-host/src-tauri/src/lib.rs');
  const commands = await read('apps/desktop-host/src-tauri/src/commands.rs');
  const added = ['ControlStatus', 'ControlSetupAdmin', 'SessionLoad', 'SessionSave', 'SessionClear'];
  for (const op of added) {
    assert.ok(OPS[op], `契约缺少 ${op}`);
    assert.equal(OPS[op].authorization, false);
    assert.ok(lib.includes(`"${op}",`), `registered_ops 缺少 ${op}`);
    assert.ok(commands.includes(`"${op}" =>`), `commands.rs 缺少 ${op}`);
  }
  assert.deepEqual(OPS.ControlSetupAdmin.payload, ['username', 'password']);
  assert.ok(PRODUCT_CONFIG_FIELDS.includes('control'));
  const groups = Object.entries(OPS).filter(([, spec]) => ['control', 'session'].includes(spec.group)).map(([name]) => name).sort();
  assert.deepEqual(groups, added.slice().sort(), '没有夹带启动任意进程或读秘密的操作');
});

test('宿主只结束自己启动的控制端，不按名字杀进程，不搜 PATH，失败时不回报占位地址', async () => {
  const supervisor = await read('apps/desktop-host/src-tauri/src/control_process.rs');
  const host = await read('apps/desktop-host/src-tauri/src/host.rs');
  const lib = await read('apps/desktop-host/src-tauri/src/lib.rs');
  assert.equal(supervisor.includes('taskkill'), false);
  assert.equal(/Command::new\("/.test(supervisor), false, '控制端程序路径不是写死的程序名');
  assert.ok(supervisor.includes('Command::new(executable)'));
  assert.ok(supervisor.includes('process.child.kill()'), '只 kill 自己持有的子进程句柄');
  assert.ok(host.includes('resources.join("control").join(control_executable_name())'), '程序来自产品资源目录');
  assert.equal(host.includes('control.ai-steward.invalid'), false, '不再回报 .invalid 默认地址');
  assert.ok(lib.includes('tauri::RunEvent::Exit'), '只在应用真正退出时停止控制端');
  assert.ok(lib.includes('control.start()'));
});

test('控制端密码存储用 Argon2 与系统随机盐，会话令牌来自系统随机源且库里只存摘要', async () => {
  const auth = await read('services/control-rs/src/auth.rs');
  const store = await read('services/control-rs/src/store.rs');
  const router = await read('services/control-rs/src/router.rs');
  assert.ok(auth.includes('Argon2::default()') && auth.includes('hash_password_with_salt'));
  assert.ok(auth.includes('getrandom::fill(&mut salt)'));
  assert.equal(/sha256_hex\(\s*password/.test(auth + router), false, '不得用普通 SHA-256 代替密码哈希');
  assert.ok(router.includes('create_session(&token_digest(&token)'), '入库的是令牌摘要');
  assert.ok(store.includes('token_sha256 TEXT PRIMARY KEY'));
  assert.ok(store.includes('TransactionBehavior::Immediate'), '首启在 IMMEDIATE 事务里完成');
  assert.ok(store.includes('CONTROL_STORE_UNRECOGNIZED'), '已存在但不认识的库拒绝接管');
});

test('Rust 源码的本机静态检查：没有非法转义与悬空模块；唯一报出的是本 crate 自身导入', async () => {
  const control = await checkRustSources('services/control-rs/src', 'services/control-rs/Cargo.toml');
  const unexpected = control.problems.filter((item) => !(item.reason === 'crate is not declared in Cargo.toml' && item.escape === 'use ai_steward_control::'));
  assert.deepEqual(unexpected, [], JSON.stringify(unexpected, null, 2));
  assert.ok(control.files >= 7);
  const tests = await checkRustSources('services/control-rs/tests', 'services/control-rs/Cargo.toml');
  assert.deepEqual(tests.problems.filter((item) => item.escape !== 'use ai_steward_control::'), []);
  const host = await checkRustSources();
  assert.deepEqual(host.problems, [], JSON.stringify(host.problems, null, 2));
});

/** router.rs 里登记的业务路由表（ROUTES 常量）。 */
function rustRoutes(router) {
  const block = /pub const ROUTES: &\[\(&str, &str\)\] = &\[([\s\S]*?)\];/.exec(router);
  assert.ok(block, 'router.rs 应有 ROUTES 路由表');
  return [...block[1].matchAll(/\("(GET|POST|PUT)", "([^"]+)"\)/g)].map((match) => `${match[1]} ${match[2]}`);
}

/** 页面与适配器实际发出的控制端请求：方法 + 不含查询串的路径。 */
async function pageCalls() {
  const calls = new Set();
  const session = await read('apps/desktop-ui/session.mjs');
  for (const match of session.matchAll(/(?:adminRequest|control)\('(GET|POST|PUT)',\s*[`']([^`'?$]+)/g)) calls.add(`${match[1]} ${match[2]}`);
  for (const match of session.matchAll(/load\((?:'\w+', )?[`'](\/api\/[^`'?$]+)/g)) calls.add(`GET ${match[1]}`);
  for (const match of session.matchAll(/\? `(\/api\/[^`?$]+)\?\$\{[^}]+\}` : '(\/api\/[^']+)'/g)) {
    calls.add(`GET ${match[1]}`);
    calls.add(`GET ${match[2]}`);
  }
  const authClient = await read('apps/desktop-ui/auth-client.mjs');
  for (const match of authClient.matchAll(/request\('(GET|POST|PUT)', '(\/api\/[^']+)'/g)) calls.add(`${match[1]} ${match[2]}`);
  for (const match of authClient.matchAll(/authClient\.get\('(\/api\/[^']+)'/g)) calls.add(`GET ${match[1]}`);
  const controlClient = await read('src/adapters/network/controlClient.mjs');
  for (const match of controlClient.matchAll(/send\('(GET|POST|PUT)', '(\/api\/[^']+)'/g)) calls.add(`${match[1]} ${match[2]}`);
  const nativePorts = await read('src/adapters/network/nativePorts.mjs');
  for (const match of nativePorts.matchAll(/new Request\('https:\/\/application\.invalid(\/api\/[^']+)'/g)) calls.add(`GET ${match[1]}`);
  const transport = await read('src/core/ai/controlTransport.mjs');
  for (const match of transport.matchAll(/application\.synthetic\.invalid(\/api\/[^']+)'/g)) calls.add(`POST ${match[1]}`);
  return [...calls].filter((call) => !/^(GET|POST) \/api\/(setup|auth)\//.test(call)).sort();
}

test('RC2 每条页面与适配器调用的业务路由，Rust 路由表与分发都有同方法分支，不再落入 501', async () => {
  const router = await read('services/control-rs/src/router.rs');
  const routes = rustRoutes(router);
  const calls = await pageCalls();
  assert.ok(calls.length >= 35, `页面调用清单异常偏少：${calls.length} ${JSON.stringify(calls)}`);
  for (const call of calls) {
    const [method, route] = call.split(' ');
    assert.ok(routes.includes(call), `ROUTES 缺少 ${call}`);
    assert.ok(router.includes(`("${method}", "${route}") =>`), `dispatch 缺少 ${call} 的分支`);
  }
  for (const route of routes) {
    const [method, pathname] = route.split(' ');
    assert.ok(router.includes(`("${method}", "${pathname}") =>`), `ROUTES 登记了 ${route} 却没有分发分支`);
  }
  for (const expected of ['GET /api/admin/users', 'POST /api/admin/users', 'POST /api/admin/users/status', 'POST /api/admin/users/password-reset', 'GET /api/admin/sessions', 'POST /api/admin/sessions/revoke', 'GET /api/admin/model-config', 'PUT /api/admin/model-config', 'GET /api/admin/quota-adapter', 'PUT /api/admin/quota-adapter', 'GET /api/network/credentials']) {
    assert.ok(calls.includes(expected), `页面没有调用 ${expected}`);
  }
  assert.equal(router.includes('CONTROL_CAPABILITY_NOT_MIGRATED'), false, 'Rust 路由不再回未迁移');
  assert.equal(/ApiResponse::(json|error)\(\s*501/.test(router), false, 'Rust 路由不再回 501');
  for (const name of ['admin_users', 'ai', 'assignments', 'events', 'quota', 'resources']) {
    assert.equal(/\b501\b/.test(await read(`services/control-rs/src/${name}.rs`)), false, `${name}.rs 不应出现 501`);
  }
});

test('RC2 控制端替身覆盖 Rust 路由表的每一条：管理员会话下没有 404、405 或 501', async () => {
  const router = await read('services/control-rs/src/router.rs');
  const double = createAuthControlDouble({clock: () => '2026-09-16T00:00:00.000Z'});
  await double.setupFromHost({username: 'admin', password: 'synthetic-Admin-Passw0rd'});
  const login = await double.handle(new Request('http://127.0.0.1/api/auth/login', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({username: 'admin', password: 'synthetic-Admin-Passw0rd'})}));
  const token = (await login.json()).access_token;
  for (const route of rustRoutes(router)) {
    const [method, pathname] = route.split(' ');
    const init = {method, headers: {authorization: `Bearer ${token}`, 'content-type': 'application/json'}};
    if (method !== 'GET') init.body = '{}';
    const response = await double.handle(new Request(`http://127.0.0.1${pathname}`, init));
    const code = response.status >= 400 ? (await response.json()).code : null;
    assert.ok(response.status !== 501 && !['CONTROL_NOT_FOUND', 'CONTROL_METHOD_NOT_ALLOWED', 'CONTROL_CAPABILITY_NOT_MIGRATED'].includes(code), `替身对 ${route} 回 ${response.status} ${code}`);
  }
  double.close();
});

test('RC2 Rust 内置 AI 协议表与客户端工具目录、提示词版本逐项一致', async () => {
  const table = JSON.parse(await read('services/control-rs/protocol/ai-protocol.json'));
  assert.deepEqual(Object.keys(table).sort(), ['cleanup', 'daily_analysis', 'network_diagnosis']);
  for (const task of Object.keys(table)) {
    const catalog = catalogFor(task);
    assert.equal(table[task].prompt_version, expectedProtocol(task).prompt);
    assert.equal(table[task].tool_catalog_version, catalog.version);
    assert.deepEqual(table[task].tools, JSON.parse(JSON.stringify(catalog.definitions)), `${task} 的工具定义与客户端不一致`);
  }
  const ai = await read('services/control-rs/src/ai.rs');
  assert.ok(ai.includes('include_str!("../protocol/ai-protocol.json")'), 'Rust 从同一份协议表读取');
});

test('RC2 管理页不再写死样例目标：没有 user-max、固定 250 GB 字节数或 2030 到期日被暗中提交', async () => {
  for (const file of ['apps/desktop-ui/app.js', 'apps/desktop-ui/session.mjs', 'apps/desktop-ui/index.html']) {
    const source = await read(file);
    assert.equal(source.includes('user-max'), false, `${file} 仍写死 user-max`);
    assert.equal(/250_?000_?000_?000/.test(source), false, `${file} 仍写死 250 GB 字节数`);
    assert.equal(source.includes('2030-01-01'), false, `${file} 仍写死 2030 到期日`);
  }
  const html = await read('apps/desktop-ui/index.html');
  assert.ok(html.includes('id="adminLimitValue" value="250"'), '250 只作为可编辑的表单默认建议');
  const app = await read('apps/desktop-ui/app.js');
  for (const secretInput of ['adminNewPassword', 'adminResetPasswordInput', 'adminModelKey', 'adminQuotaToken', 'adminQuotaUrl', 'adminSourceUrl', 'adminCredentialPassword']) {
    assert.ok(app.includes(`takeSecret('${secretInput}')`), `${secretInput} 读出后必须清空`);
  }
});

test('RC2 秘密保护与日志边界在 Rust 源码里成立：DPAPI 当前用户、库里只存密文、不跟随重定向', async () => {
  const secrets = await read('services/control-rs/src/secrets.rs');
  assert.ok(secrets.includes('CryptProtectData') && secrets.includes('CryptUnprotectData'));
  assert.ok(secrets.includes('CRYPTPROTECT_UI_FORBIDDEN'));
  assert.equal(secrets.includes('CRYPTPROTECT_LOCAL_MACHINE,'), false, '不用机器范围保护');
  assert.equal(/base64/i.test(secrets), false, '不用 Base64 冒充保护');
  const store = await read('services/control-rs/src/store.rs');
  assert.ok(store.includes('ciphertext BLOB NOT NULL'));
  for (const column of ['api_key TEXT', 'token TEXT', 'password TEXT', ' url TEXT']) {
    assert.equal(store.includes(column), false, `库结构里不应有明文秘密列 ${column}`);
  }
  const router = await read('services/control-rs/src/router.rs');
  assert.ok(router.includes('"request.completed"'));
  const cargo = await read('services/control-rs/Cargo.toml');
  assert.ok(cargo.includes('windows-sys = { version = "=0.61.2"'));
  assert.ok(cargo.includes('ureq = "=3.4.2"'));
  const http = await read('services/control-rs/src/http.rs');
  assert.ok(http.includes('.max_redirects(0)'), '不跟随重定向，鉴权头不外带');
});

test('探测服务：页面读取的路径与管理接口在 Rust 路由里都有同方法分支，宿主不再回报', async () => {
  const router = await read('services/control-rs/src/router.rs');
  const runtime = await read('apps/desktop-ui/product-runtime.mjs');
  const store = await read('services/control-rs/src/store.rs');
  assert.ok(runtime.includes("authClient.get('/api/network/probe-services'"), '页面从控制端取探测服务地址');
  for (const [method, route] of [
    ['GET', '/api/network/probe-services'],
    ['GET', '/api/admin/probe-services'],
    ['PUT', '/api/admin/probe-services'],
    ['POST', '/api/admin/probe-services/remove'],
  ]) {
    assert.ok(router.includes(`("${method}", "${route}") =>`), `router.rs 缺少 ${method} ${route}`);
    assert.ok(router.includes(`("${method}", "${route}"),`), `ROUTES 缺少 ${method} ${route}`);
  }
  assert.ok(store.includes('pub const SCHEMA_VERSION: i64 = 3;') && store.includes('CREATE TABLE control_probe_services'), '探测服务配置有自己的表，库升到 v3');
  assert.equal(PRODUCT_CONFIG_FIELDS.includes('probe_services'), false, '探测服务不是宿主的产品配置');
});
