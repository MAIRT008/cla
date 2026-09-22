import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync, readFileSync, readdirSync, statSync} from 'node:fs';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {OPS} from '../../apps/desktop-host/bridge-contract.mjs';
import {redactSecrets} from '../../src/core/audit/redact.mjs';

/**
 * RC6 发布候选：显式装配清单、页面闭包、桌面生命周期接线、安装器钩子、统一日志收集与交付材料。
 * 装配与收集器在合成目录上真实运行；Rust 与 NSIS 只做源码静态核对，不证明能编译或能执行。
 */
const ROOT = process.cwd();
const release = () => import('../../tools/release/assemble.mjs');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const read = (file) => readFileSync(path.join(ROOT, file), 'utf8');
const EXCLUDED = ['services/control/', 'fixtures/', 'experiments/', 'dist/', 'tests/', 'evidence/', 'node_modules/'];

function listFiles(dir, base = dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, {withFileTypes: true}).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? listFiles(full, base) : [path.relative(base, full).split(path.sep).join('/')];
  });
}

/** 合成仓库：两份「构建产物」、一份许可、一个页面入口与跨目录模块、一份锁文件与一份异机材料。字节都是合成的。 */
async function syntheticRepo(label) {
  const root = transientRun('delivery', `rc6-${label}`);
  const files = {
    'build/out/control.exe': 'synthetic control program bytes',
    'build/out/service.exe': 'synthetic service program bytes',
    'licenses/GPL.txt': 'synthetic license text',
    'Cargo.lock': '# synthetic lock\n',
    'docs/field-guide.md': '# synthetic field guide\n',
    'page/index.html': '<link rel="stylesheet" href="app.css" />\n<script type="module" src="boot.mjs"></script>\n<script src="classic.js"></script>\n',
    'page/app.css': 'body{}\n',
    'page/boot.mjs': "import {x} from '../lib/x.mjs';\nexport const y = x;\n",
    'page/classic.js': 'window.z = 1;\n',
    'lib/x.mjs': "export {w as x} from './w.mjs';\n",
    'lib/w.mjs': 'export const w = 2;\n',
  };
  for (const [relative, text] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, relative)), {recursive: true});
    await writeFile(path.join(root, relative), text);
  }
  const inputs = {
    schema: 'steward-release-inputs-1',
    product: {name: 'Synthetic', identifier: 'local.synthetic.desktop', version: '0.0.1'},
    frontend: {entry: 'page/index.html', forbidden: ['node:', 'services/control/', 'fixtures/', 'tests/']},
    excluded: EXCLUDED,
    items: [
      {id: 'control', class: 'runtime', source: 'build/out/control.exe', target: 'control/control.exe', built: true, sha256: null, license: 'gpl', required: true},
      {id: 'service', class: 'runtime', source: 'build/out/service.exe', target: 'service/service.exe', built: true, sha256: null, license: 'gpl', required: true},
      {id: 'gpl', class: 'source_license', source: 'licenses/GPL.txt', target: 'licenses/GPL.txt', sha256: sha('synthetic license text'), required: true},
      {id: 'lock', class: 'build_input', source: 'Cargo.lock', target: null, built: true, sha256: null, required: true},
      {id: 'guide', class: 'test_material', source: 'docs/field-guide.md', target: null, sha256: null, required: true},
    ],
  };
  return {root, inputs, out: path.join(root, 'staging')};
}

test('RC6 R01 发布检查在本机缺件时安全输出结构化 NOT_READY，逐项写原因；命令行退出码 2', async () => {
  const {checkRelease, loadReleaseInputs, RELEASE_CLASSES} = await release();
  const inputs = await loadReleaseInputs(ROOT);
  assert.deepEqual([...new Set(inputs.items.map((item) => item.class))].filter((kind) => !RELEASE_CLASSES.includes(kind)), [], '只用约定的类别');
  const report = await checkRelease({root: ROOT, inputs, probeTool: async () => ({found: false})});
  assert.equal(report.status, 'NOT_READY');
  const byId = new Map(report.items.map((item) => [item.id, item]));
  for (const id of ['control', 'service', 'service-install', 'service-uninstall', 'lock-host', 'lock-control', 'lock-service', 'rust-third-party']) {
    assert.deepEqual(byId.get(id)?.reasons, ['MISSING'], `${id}: ${JSON.stringify(byId.get(id))}`);
  }
  assert.deepEqual(byId.get('mihomo').reasons, ['MISSING', 'PIN_REQUIRED'], 'Mihomo 二进制没有、哈希也没固定');
  for (const id of ['license-gpl', 'license-service-ipc', 'notice', 'collect-logs', 'collect-logs-cmd']) assert.equal(byId.get(id)?.status, 'PRESENT', id);
  assert.ok(report.tools.length >= 4 && report.tools.every((tool) => tool.status === 'TOOL_MISSING' || tool.status === 'UNCHECKED'), JSON.stringify(report.tools));
  assert.equal(report.frontend.status, 'OK', JSON.stringify(report.frontend.problems));

  const cli = spawnSync(process.execPath, ['tools/release/release.mjs', 'check'], {encoding: 'utf8'});
  assert.equal(cli.status, 2, cli.stderr);
  const printed = JSON.parse(cli.stdout);
  assert.equal(printed.status, 'NOT_READY');
  assert.ok(printed.items.find((item) => item.id === 'control').reasons.includes('MISSING'));
});

test('RC6 R02 装配只按显式清单复制，复制后逐个复核哈希，manifest 最后写；锁文件只记哈希不入包，异机材料不入包', async () => {
  const {assembleRelease} = await release();
  const {root, inputs, out} = await syntheticRepo('assemble-ok');
  const seen = [];
  const result = await assembleRelease({root, inputs, out, onCopied: ({partial, target}) => seen.push({target, manifestYet: existsSync(path.join(partial, 'release-manifest.json'))})});
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.ok(seen.length >= 7 && seen.every((item) => item.manifestYet === false), '复制过程中还没有 manifest');
  assert.deepEqual(listFiles(out).sort(), [
    'frontend/lib/w.mjs', 'frontend/lib/x.mjs', 'frontend/page/app.css', 'frontend/page/boot.mjs', 'frontend/page/classic.js', 'frontend/page/index.html',
    'install/control/control.exe', 'install/licenses/GPL.txt', 'install/service/service.exe', 'release-manifest.json',
  ]);
  const manifest = JSON.parse(await readFile(path.join(out, 'release-manifest.json'), 'utf8'));
  assert.equal(manifest.items.find((item) => item.id === 'control').sha256, sha('synthetic control program bytes'));
  assert.equal(manifest.build_inputs.find((item) => item.id === 'lock').sha256, sha('# synthetic lock\n'));
  assert.equal(manifest.items.some((item) => item.id === 'guide'), false, '异机测试材料不入包');
  assert.equal(JSON.stringify(manifest).includes(root.replaceAll('\\', '/')) || JSON.stringify(manifest).includes(root.replaceAll('\\', '\\\\')), false, 'manifest 不含本机绝对路径');
  assert.equal(listFiles(root).some((file) => file.startsWith('staging.partial')), false, '临时目录已改名');
});

test('RC6 R03 装配遇缺件、哈希不符、固定哈希未给、目标重名、越界、许可不全、半途中断、复制后被改、目标已存在都非零退出且不留正式目录', async () => {
  const {assembleRelease} = await release();
  const cases = [
    ['ITEM_MISSING', (inputs) => { inputs.items[0].source = 'build/out/absent.exe'; }],
    ['HASH_MISMATCH', (inputs) => { inputs.items[2].sha256 = sha('something else'); }],
    ['PIN_REQUIRED', (inputs) => { inputs.items[1].built = false; inputs.items[1].pin = 'PIN_REQUIRED'; }],
    ['TARGET_DUPLICATE', (inputs) => { inputs.items[1].target = 'control/control.exe'; }],
    ['TARGET_OUT_OF_BOUNDS', (inputs) => { inputs.items[1].target = '../escape.exe'; }],
    ['TARGET_OUT_OF_BOUNDS', (inputs) => { inputs.items[1].target = 'C:/Windows/escape.exe'; }],
    ['SOURCE_OUT_OF_BOUNDS', (inputs) => { inputs.items[0].source = '../../outside.exe'; }],
    ['LICENSE_INCOMPLETE', (inputs) => { inputs.items[0].license = 'unknown-license'; }],
    ['LICENSE_INCOMPLETE', (inputs) => { inputs.items[2].source = 'licenses/absent.txt'; }],
  ];
  let index = 0;
  for (const [code, mutate] of cases) {
    const {root, inputs, out} = await syntheticRepo(`assemble-fail-${index += 1}`);
    mutate(inputs);
    const result = await assembleRelease({root, inputs, out});
    assert.equal(result.ok, false, code);
    assert.equal(result.code, code, JSON.stringify(result));
    assert.equal(existsSync(out), false, `${code}: 失败不留正式目录`);
  }

  const interrupted = await syntheticRepo('assemble-interrupt');
  let copies = 0;
  const stopped = await assembleRelease({...interrupted, onCopied: () => { copies += 1; if (copies === 2) throw new Error('synthetic interruption'); }});
  assert.equal(stopped.code, 'ASSEMBLY_INTERRUPTED');
  assert.equal(existsSync(interrupted.out), false);
  assert.equal(listFiles(interrupted.root).some((file) => file.startsWith('staging.partial')), false, '半成品已清掉，没有像完整包的 manifest');

  const tampered = await syntheticRepo('assemble-tamper');
  const altered = await assembleRelease({...tampered, onBeforeCopy: async ({item}) => {
    if (item.id === 'service') await writeFile(path.join(tampered.root, item.source), 'swapped after the check');
  }});
  assert.equal(altered.code, 'COPY_VERIFY_FAILED', JSON.stringify(altered));
  assert.equal(existsSync(tampered.out), false);

  const occupied = await syntheticRepo('assemble-exists');
  await mkdir(occupied.out, {recursive: true});
  assert.equal((await assembleRelease(occupied)).code, 'ASSEMBLY_TARGET_EXISTS');

  const cliCase = await syntheticRepo('assemble-cli');
  cliCase.inputs.items[0].source = 'build/out/absent.exe';
  await writeFile(path.join(cliCase.root, 'inputs.json'), JSON.stringify(cliCase.inputs));
  const cli = spawnSync(process.execPath, ['tools/release/release.mjs', 'assemble', '--root', cliCase.root, '--inputs', 'inputs.json', '--out', cliCase.out], {encoding: 'utf8'});
  assert.equal(cli.status, 1, cli.stdout + cli.stderr);
  assert.match(cli.stdout + cli.stderr, /ITEM_MISSING/);
});

test('RC6 R04 发布清单分类完整：普通用户运行文件不来自 Node 控制端、夹具、实验树、历史导出或测试；不需要 Rust/Node/Python 运行时', async () => {
  const {loadReleaseInputs} = await release();
  const inputs = await loadReleaseInputs(ROOT);
  const runtime = inputs.items.filter((item) => item.class === 'runtime');
  for (const item of inputs.items.filter((entry) => entry.target)) {
    assert.equal(EXCLUDED.some((prefix) => item.source.startsWith(prefix)), false, `${item.id} 来源 ${item.source} 在不入包目录里`);
    assert.doesNotMatch(item.target, /\.(zip|mjs|js|py|ts)$/i, `${item.id}：脚本或源码 ZIP 不作运行文件`);
  }
  assert.deepEqual(runtime.map((item) => item.target).sort(), [
    'control/ai-steward-control.exe',
    'service/ai-environmental-steward-service-install.exe',
    'service/ai-environmental-steward-service-uninstall.exe',
    'service/ai-environmental-steward-service.exe',
    'service/core/mihomo-windows-amd64-v1.19.30.exe',
    'support/collect-logs.cmd',
    'support/collect-logs.ps1',
  ]);
  for (const item of runtime) assert.ok(inputs.items.some((entry) => entry.id === item.license && entry.class === 'source_license'), `${item.id} 有许可`);
  assert.ok(inputs.items.some((item) => item.class === 'build_tool' && item.id === 'node'), 'Node 只作构建机工具');
  assert.equal(inputs.items.some((item) => /openai|tauri-plugin-mihomo|services\/control\//i.test(JSON.stringify(item))), false, '未采用组件不进清单');
  assert.ok(inputs.not_adopted.some((entry) => entry.id === 'tauri-plugin-mihomo'), '未采用组件单列排除');
  const licenseText = readFileSync(path.join(ROOT, inputs.items.find((item) => item.id === 'license-gpl').source));
  assert.equal(sha(licenseText), sha(readFileSync(path.join(ROOT, 'experiments/p0-network/mihomo-v1.19.30/src/LICENSE'))), 'GPL 文本与固定上游逐字节一致');
});

test('RC6 R05 页面闭包：正式入口引用的每个模块都能在装配目录内解析，不含 Node 专用、控制端、夹具或测试模块，也没有本机路径或秘密', async () => {
  const {assembleRelease, frontendClosure, loadReleaseInputs} = await release();
  const inputs = await loadReleaseInputs(ROOT);
  const closure = await frontendClosure(ROOT, inputs.frontend);
  assert.deepEqual(closure.problems, []);
  for (const file of ['apps/desktop-ui/index.html', 'apps/desktop-ui/native-boot.mjs', 'apps/desktop-ui/native.mjs', 'src/adapters/audit/runtime.mjs', 'src/core/audit/redact.mjs', 'apps/desktop-ui/bridge.js', 'apps/desktop-ui/app.bundle.js']) {
    assert.ok(closure.files.includes(file), `${file} 在闭包里`);
  }
  for (const file of closure.files) {
    assert.equal(EXCLUDED.some((prefix) => file.startsWith(prefix)), false, file);
    assert.notEqual(file, 'apps/desktop-ui/compose.mjs', '合成组合根不入包');
  }
  for (const file of closure.files) {
    const text = read(file);
    assert.equal(text.includes(ROOT) || text.includes(ROOT.replaceAll('\\', '/')), false, `${file} 含本机路径`);
    assert.doesNotMatch(text, /from\s+['"]node:/, `${file} 引用了 Node 内置模块`);
    assert.equal(/\bsk-[A-Za-z0-9_-]{8,}/.test(text), false, `${file} 像是带了密钥`);
  }

  const out = transientRun('delivery', 'rc6-frontend-closure');
  const assembled = await assembleRelease({root: ROOT, inputs: {...inputs, items: []}, out, frontendOnly: true});
  assert.equal(assembled.ok, true, JSON.stringify(assembled));
  const again = await frontendClosure(path.join(out, 'frontend'), {...inputs.frontend});
  assert.deepEqual(again.problems, [], '装配后的页面目录自足');
  assert.deepEqual(again.files.sort(), closure.files.slice().sort());
});

test('RC6 R06 桌面生命周期接线（源码静态核对）：单实例最先注册；关窗拦截并隐藏；托盘固定三项；退出只停托管控制端，不发服务命令', () => {
  const lib = read('apps/desktop-host/src-tauri/src/lib.rs');
  const life = read('apps/desktop-host/src-tauri/src/lifecycle.rs');
  const cargo = read('apps/desktop-host/src-tauri/Cargo.toml');
  const run = lib.slice(lib.indexOf('#[cfg(feature = "tauri")]\npub fn run()'), lib.indexOf('#[cfg(not(feature = "tauri"))]\npub fn run()'));
  assert.ok(run.length > 0, '找到 tauri 装配');
  const plugins = [...run.matchAll(/\.plugin\(([a-z_]+)::/g)].map((match) => match[1]);
  assert.deepEqual(plugins, ['tauri_plugin_single_instance', 'tauri_plugin_dialog', 'tauri_plugin_notification'], '单实例必须第一个注册');
  assert.match(run, /CloseRequested \{ api, \.\. \}[\s\S]*?api\.prevent_close\(\);[\s\S]*?\.hide\(\)/);
  assert.match(run, /RunEvent::ExitRequested \{ api, code, \.\. \} if code\.is_none\(\) => api\.prevent_exit\(\)/, '关最后一个窗口不退出');
  const exitArm = run.slice(run.indexOf('tauri::RunEvent::Exit =>'), run.indexOf('}', run.indexOf('tauri::RunEvent::Exit =>')) + 1);
  assert.match(exitArm, /control\.stop\(\)/);
  assert.equal(/ServiceCommand|network\./.test(run) || /ServiceCommand|StopCoreForMaintenance|release_owned/.test(life), false, '生命周期不碰产品网络服务');
  const menu = [...life.matchAll(/\("([a-z_]+)", "([^"]+)"\)/g)].map((match) => [match[1], match[2]]);
  assert.deepEqual(menu.map(([id]) => id), ['show', 'open_logs', 'quit_ui']);
  for (const [, label] of menu) assert.doesNotMatch(label, /代理|模式|导入|解除|停止管理|订阅/);
  assert.match(life, /TrayAction::QuitInterface => app\.exit\(0\)/);
  assert.match(cargo, /tauri = \{ version = "2\.11\.5", optional = true, features = \["tray-icon"\] \}/);
  assert.match(cargo, /tauri-plugin-single-instance = \{ version = "=2\.4\.5", optional = true \}/);
  assert.match(cargo, /tauri-plugin-notification = \{ version = "=2\.3\.3", optional = true \}/);
  assert.match(cargo, /\[build-dependencies\]\ntauri-build = \{ version = "=2\.6\.3", optional = true \}/);
  assert.match(read('apps/desktop-host/src-tauri/build.rs'), /#\[cfg\(feature = "tauri"\)\]\s*tauri_build::build\(\)/);
});

test('RC6 R07 危急系统通知只收固定事件与提示编号：契约、宿主注册与固定文案一致，文案不带任何可变内容', () => {
  assert.deepEqual(OPS.NotifyCritical, {group: 'notify', payload: ['event', 'ref'], authorization: false});
  const lib = read('apps/desktop-host/src-tauri/src/lib.rs');
  const registered = [...lib.slice(lib.indexOf('pub fn registered_ops'), lib.indexOf('\n}', lib.indexOf('pub fn registered_ops'))).matchAll(/"([A-Za-z]+)"/g)].map((match) => match[1]);
  assert.deepEqual(registered.slice().sort(), Object.keys(OPS).sort());
  const commands = read('apps/desktop-host/src-tauri/src/commands.rs');
  assert.match(commands, /"NotifyCritical" => crate::lifecycle::notify_critical\(state\.notices\.as_ref\(\), payload\)/);
  const life = read('apps/desktop-host/src-tauri/src/lifecycle.rs');
  const texts = [...life.matchAll(/=> \("([^"]*)", "([^"]*)"\)/g)].flatMap((match) => [match[1], match[2]]);
  assert.equal(texts.length, 8, '四类通知各有固定标题与正文');
  for (const text of texts) assert.doesNotMatch(text, /\{|\}|http|\\|\/|token|secret/i, text);
  for (const event of ['WRONG_ROUTE', 'PROTECTION_NOT_CONFIRMED', 'PROTECTION_FAILED']) assert.ok(life.includes(`"${event}"`), event);
  assert.match(life, /NOTIFY_FIELD_FORBIDDEN/);
});

test('RC6 R08 发布构建输入（配置静态核对）：产品标识、NSIS perMachine、产品自有图标、资源映射与清单一致、钩子只动产品命名空间、无远程更新', () => {
  const conf = JSON.parse(read('apps/desktop-host/src-tauri/tauri.conf.json'));
  const productId = /PRODUCT_APP_ID: &str = "([^"]+)"/.exec(read('apps/desktop-host/vendor/service-ipc/src/core/paths.rs'))[1];
  assert.equal(conf.identifier, productId, 'Tauri 标识与产品命名空间一致');
  assert.equal(conf.bundle.active, true);
  assert.deepEqual(conf.bundle.targets, ['nsis']);
  assert.equal(conf.bundle.createUpdaterArtifacts, false);
  assert.equal(JSON.stringify(conf).includes('nsv'), false);
  assert.equal(JSON.stringify(conf.plugins || {}).includes('updater'), false, '不注册远程更新');
  assert.equal(conf.bundle.windows.nsis.installMode, 'perMachine');
  assert.equal(conf.build.frontendDist, '../../../build/release-staging/frontend');
  assert.equal(conf.app.windows[0].url, 'apps/desktop-ui/index.html');
  const hooksPath = path.join('apps/desktop-host/src-tauri', conf.bundle.windows.nsis.installerHooks);
  assert.equal(path.normalize(hooksPath), path.normalize('apps/desktop-host/vendor/service-ipc/resources/installer.nsi'));
  for (const icon of conf.bundle.icon) {
    const bytes = readFileSync(path.join(ROOT, 'apps/desktop-host/src-tauri', icon));
    if (icon.endsWith('.ico')) assert.deepEqual([...bytes.subarray(0, 4)], [0, 0, 1, 0], icon);
    else assert.deepEqual([...bytes.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], icon);
  }
  const regenerated = transientRun('delivery', 'rc6-icons');
  const made = spawnSync(process.execPath, ['tools/release/make-icons.mjs', '--out', regenerated], {encoding: 'utf8'});
  assert.equal(made.status, 0, made.stderr);
  for (const icon of conf.bundle.icon) {
    assert.equal(sha(readFileSync(path.join(regenerated, path.basename(icon)))), sha(readFileSync(path.join(ROOT, 'apps/desktop-host/src-tauri', icon))), `${icon} 可由产品脚本逐字节重现`);
  }
  const inputs = JSON.parse(read('tools/release/release-inputs.json'));
  const resources = {...conf.bundle.resources};
  assert.equal(resources['../../../build/release-staging/release-manifest.json'], 'release-manifest.json', '装配清单随包安装，作本地版本清单');
  delete resources['../../../build/release-staging/release-manifest.json'];
  const bundled = Object.entries(resources).map(([from, to]) => [from.replace('../../../build/release-staging/install/', ''), to]);
  assert.ok(Object.keys(resources).every((from) => from.startsWith('../../../build/release-staging/install/')), '资源只来自装配目录');
  assert.deepEqual(bundled.map(([from, to]) => { assert.equal(from, to); return to; }).sort(), inputs.items.filter((item) => item.target).map((item) => item.target).sort());

  const hooks = read('apps/desktop-host/vendor/service-ipc/resources/installer.nsi');
  for (const macro of ['NSIS_HOOK_PREINSTALL', 'NSIS_HOOK_POSTINSTALL', 'NSIS_HOOK_PREUNINSTALL', 'NSIS_HOOK_POSTUNINSTALL']) assert.match(hooks, new RegExp(`!macro ${macro}\\b`), macro);
  assert.doesNotMatch(hooks, /PLACEHOLDER/, '没有模板占位');
  assert.doesNotMatch(hooks, /clash|verge|taskkill|netsh|sc\.exe delete/i, '不碰上游服务、不批量结束进程、不改网络');
  for (const [call] of hooks.matchAll(/nsis_tauri_utils::\w+ [^\n]*/g)) assert.match(call, /^nsis_tauri_utils::(Find|Kill)Process(CurrentUser)? "\$\{MAINBINARYNAME\}\.exe"$/, `只查找、结束本产品自己的桌面程序：${call}`);
  const executed = [...hooks.matchAll(/(?:ExecWait|nsExec::ExecToStack|nsExec::Exec)\s+'"([^"]+)"/g)].map((match) => match[1]);
  assert.ok(executed.length >= 5, executed.join('\n'));
  for (const program of executed) assert.match(program, /^\$INSTDIR\\service\\ai-environmental-steward-service-(install|uninstall)\.exe$/, program);
  for (const action of ['install', 'repair', 'prepare-upgrade', 'complete-upgrade', 'rollback-upgrade']) assert.ok(hooks.includes(`--action ${action}`), action);
  const preUninstall = hooks.slice(hooks.indexOf('!macro NSIS_HOOK_PREUNINSTALL'), hooks.indexOf('!macroend', hooks.indexOf('!macro NSIS_HOOK_PREUNINSTALL')));
  assert.match(preUninstall, /停止管理并恢复原网络/);
  assert.match(preUninstall, /--release-protection/);
  assert.ok(preUninstall.indexOf('MessageBox') < preUninstall.indexOf('--release-protection'), '先明确选择再撤保护');
  const postUninstall = hooks.slice(hooks.indexOf('!macro NSIS_HOOK_POSTUNINSTALL'), hooks.indexOf('!macroend', hooks.indexOf('!macro NSIS_HOOK_POSTUNINSTALL')));
  assert.match(postUninstall, /\$DeleteAppDataCheckboxState/, '只有勾选删除应用数据才删服务状态');
  assert.match(hooks, /installer-/, '安装器写自己的日志');

  const installer = read('apps/desktop-host/vendor/service-ipc/src/bin/install_service.rs');
  assert.match(installer, /"install" \| "repair" \| "prepare-upgrade" \| "complete-upgrade" \| "rollback-upgrade"/);
  assert.match(read('apps/desktop-host/vendor/service-ipc/src/bin/uninstall_service.rs'), /--delete-state/);
});

function powershell() {
  if (process.platform !== 'win32') return null;
  const probe = spawnSync('powershell.exe', ['-NoProfile', '-Command', '$PSVersionTable.PSVersion.Major'], {encoding: 'utf8'});
  return probe.status === 0 ? 'powershell.exe' : null;
}

async function syntheticLogs(label) {
  const root = transientRun('delivery', `rc6-collect-${label}`);
  const dataRoot = path.join(root, 'data');
  const serviceRoot = path.join(root, 'service');
  const files = {
    [path.join(dataRoot, 'logs', 'app-20260921T010000000Z-11.log')]: '{"event":"ui.action_failed","fields":{"code":"X","authorization":"Bearer abc123secret"}}\n'
      + '中token=cjk1；令牌Bearer 值xyz；https://用户:密码@例子.test/?sig=zz&k=1\n-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n',
    [path.join(dataRoot, 'logs', 'host-control-20260921T010000000Z-11.log')]: '{"event":"control.stderr","fields":{"line":"GET https://user:hunter2@example.test/?token=abc&x=1"}}\n',
    [path.join(dataRoot, 'control', 'logs', 'control-20260921T010000000Z-12.log')]: '{"event":"control.ready","fields":{"cookie":"sid=abcdef","key":"sk-ABCDEFGH12345678"}}\n',
    [path.join(serviceRoot, 'logs', 'service.log')]: '{"event":"ipc.command","fields":{"command":"ObserveRuntime"}}\n',
    [path.join(serviceRoot, 'logs', 'core.log')]: 'time="t" level=info msg="[TCP] 127.0.0.1:1(claude.exe) --> api.anthropic.com:443 using CLAUDE-FIXED[EXIT-A]"\n',
    [path.join(serviceRoot, 'logs', 'install-20260921T010000000Z-13.log')]: 'install.begin action=install password=hunter2\n',
    [path.join(serviceRoot, 'logs', 'installer-20260921T010000000Z-14.log')]: 'maintenance.begin\n',
    [path.join(dataRoot, 'vault', 'authorizations.json')]: 'SECRET-VAULT-CONTENT',
    [path.join(serviceRoot, 'link', 'host-link.key')]: 'SECRET-LINK-KEY',
    [path.join(serviceRoot, 'core', 'configs', 'active.yaml')]: 'SECRET-CONFIG-BODY',
  };
  for (const [file, text] of Object.entries(files)) {
    await mkdir(path.dirname(file), {recursive: true});
    await writeFile(file, text);
  }
  return {root, dataRoot, serviceRoot, files, out: path.join(root, 'bundles')};
}

function collect(shell, world, extra) {
  const run = spawnSync(shell, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'tools/release/collect-logs.ps1',
    '-DataRoot', world.dataRoot, '-ServiceRoot', world.serviceRoot, '-BuildLogRoot', path.join(world.root, 'no-build-logs'), ...extra], {encoding: 'utf8'});
  return run;
}

test('RC6 R09 统一日志收集（Windows PowerShell 实跑）：先预览、逐文件按共享规则脱敏、manifest 最后写、缺口写明、不读保险库/密钥/配置、每次新目录不覆盖', async (t) => {
  const shell = powershell();
  if (!shell) return t.skip('Windows PowerShell 5.1 不可用');
  const script = readFileSync(path.join(ROOT, 'tools/release/collect-logs.ps1'));
  assert.deepEqual([...script.subarray(0, 3)], [0xef, 0xbb, 0xbf], 'Windows PowerShell 5.1 按 BOM 识别 UTF-8');
  const world = await syntheticLogs('ok');

  const preview = collect(shell, world, ['-Preview']);
  assert.equal(preview.status, 0, preview.stdout + preview.stderr);
  const listed = JSON.parse(preview.stdout);
  const refs = listed.sources.map((item) => item.source_ref).sort();
  assert.deepEqual(refs, ['control/control-20260921T010000000Z-12.log', 'host/app-20260921T010000000Z-11.log', 'host/host-control-20260921T010000000Z-11.log',
    'installer/install-20260921T010000000Z-13.log', 'installer/installer-20260921T010000000Z-14.log', 'network_core/core.log', 'network_service/service.log']);
  assert.equal(listed.sources.find((item) => item.source_ref === 'network_core/core.log').selected, false, '访问明细默认不选');
  assert.deepEqual(listed.gaps.map((gap) => gap.category), ['build'], '没有构建日志就记缺口');
  assert.equal(JSON.stringify(listed).includes('SECRET-'), false);

  const first = collect(shell, world, ['-Export', '-CaseId', 'E57', '-Out', world.out]);
  assert.equal(first.status, 0, first.stdout + first.stderr);
  const firstBundle = JSON.parse(first.stdout).bundle;
  const bundleDir = path.join(world.out, firstBundle);
  const manifestPath = path.join(bundleDir, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.case_id, 'E57');
  assert.equal(manifest.uploaded, false);
  assert.ok(manifest.excluded.some((item) => item.source_ref === 'network_core/core.log'));
  const newest = Math.max(...manifest.files.map((item) => statSync(path.join(bundleDir, item.name)).mtimeMs));
  assert.ok(statSync(manifestPath).mtimeMs >= newest, 'manifest 最后写');
  for (const item of manifest.files) {
    const original = readFileSync(Object.keys(world.files).find((file) => file.endsWith(item.source_ref.split('/')[1])), 'utf8');
    const exported = readFileSync(path.join(bundleDir, item.name), 'utf8');
    assert.equal(exported, redactSecrets(original).text, `${item.source_ref} 与共享脱敏规则结果一致`);
    assert.equal(item.sha256, sha(Buffer.from(exported)));
  }
  const everything = listFiles(bundleDir).map((file) => readFileSync(path.join(bundleDir, file), 'utf8')).join('\n');
  for (const secret of ['abc123secret', 'hunter2', 'sid=abcdef', 'sk-ABCDEFGH12345678', 'token=abc', 'SECRET-']) assert.equal(everything.includes(secret), false, secret);

  const second = collect(shell, world, ['-Export', '-CaseId', 'E57', '-Out', world.out]);
  assert.equal(second.status, 0, second.stderr);
  assert.notEqual(JSON.parse(second.stdout).bundle, firstBundle, '复测另起目录');
  assert.ok(existsSync(manifestPath), '上一份仍在');
});

test('RC6 R10 统一日志收集写失败时明说「日志包未生成」、不留 manifest；构建脚本在工具缺失时失败且日志可找到', async (t) => {
  const shell = powershell();
  if (!shell) return t.skip('Windows PowerShell 5.1 不可用');
  const world = await syntheticLogs('fail');
  const failed = collect(shell, world, ['-Export', '-CaseId', 'E57', '-Out', world.out, '-FailAfterFiles', '2']);
  assert.notEqual(failed.status, 0);
  assert.match(failed.stdout + failed.stderr, /日志包未生成/);
  assert.equal(listFiles(world.out).some((file) => file.endsWith('manifest.json')), false, '失败不留 manifest');

  const logRoot = transientRun('delivery', 'rc6-build-plan');
  const planned = spawnSync(shell, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'tools/release/build-release.ps1', '-PlanOnly', '-LogRoot', logRoot], {encoding: 'utf8'});
  assert.equal(planned.status, 2, planned.stdout + planned.stderr);
  const runs = readdirSync(logRoot);
  assert.equal(runs.length, 1);
  const log = readFileSync(path.join(logRoot, runs[0], 'build.log'), 'utf8');
  assert.match(log, /cargo/);
  assert.match(log, /NOT_READY/);
});

test('E54 返工 B1 构建脚本在 Windows PowerShell 5.1 下按退出码判定每一步：stderr 加退出 0 继续、stderr 加非零失败、命令起不来不沿用上一步的 0、步骤日志写不进去就终止', async (t) => {
  const shell = powershell();
  if (!shell) return t.skip('Windows PowerShell 5.1 不可用');
  // 假工具只放在临时目录里，排在 PATH 最前；cargo 的进度照真 cargo 的习惯写 stderr。
  const rustc = '@echo rustc 1.95.0 (synthetic)\r\n';
  const cargo = (code) => `@echo    Compiling synthetic v0.0.0 1>&2\r\n@echo synthetic stdout\r\n@exit /b ${code}\r\n`;
  const build = async (label, tools) => {
    const root = transientRun('delivery', `e54-build-${label}`);
    const bin = path.join(root, 'bin');
    const logRoot = path.join(root, 'logs');
    await mkdir(bin, {recursive: true});
    for (const [name, body] of Object.entries(tools)) await writeFile(path.join(bin, name), body);
    // 自建最小环境（验收运行器只传 SystemRoot/WINDIR/TEMP/TMP）：假工具在前，其后是真 node 与系统目录；不带外面的 PSModulePath。
    const system = process.env.SystemRoot || 'C:\\Windows';
    const env = Object.fromEntries(Object.entries({
      SystemRoot: system,
      WINDIR: process.env.WINDIR || system,
      TEMP: process.env.TEMP,
      TMP: process.env.TMP,
      ComSpec: path.join(system, 'System32', 'cmd.exe'),
      PATHEXT: '.COM;.EXE;.BAT;.CMD',
      PATH: [bin, path.dirname(process.execPath), path.join(system, 'System32'), path.join(system, 'System32', 'WindowsPowerShell', 'v1.0')].join(';'),
      SYNTHETIC_LOG_ROOT: logRoot,
    }).filter(([, value]) => value));
    const result = spawnSync(shell, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'tools/release/build-release.ps1', '-LogRoot', logRoot], {encoding: 'utf8', env});
    const runs = existsSync(logRoot) ? readdirSync(logRoot) : [];
    const dir = runs.length === 1 ? path.join(logRoot, runs[0]) : null;
    const log = dir && existsSync(path.join(dir, 'build.log')) ? readFileSync(path.join(dir, 'build.log'), 'utf8') : '';
    return {status: result.status, dir, log, output: `${result.stdout}${result.stderr}\n${log}`};
  };

  const noisy = await build('stderr-zero', {'cargo.cmd': cargo(0), 'rustc.cmd': rustc});
  assert.match(noisy.log, /step\.end cargo-control exit=0 /, noisy.output);
  assert.match(noisy.log, /step\.end cargo-service exit=0 /, noisy.output);
  assert.match(readFileSync(path.join(noisy.dir, 'cargo-control.log'), 'utf8'), /Compiling synthetic/, 'stderr 照样进步骤日志');
  assert.match(noisy.log, /build\.stop NOT_READY/, '本机没有真实产物，停在发布检查');
  assert.equal(noisy.status, 2, noisy.output);

  const failing = await build('stderr-nonzero', {'cargo.cmd': cargo(3), 'rustc.cmd': rustc});
  assert.match(failing.log, /step\.end cargo-control exit=3 /, failing.output);
  assert.match(failing.log, /build\.failed cargo-control/, failing.output);
  assert.doesNotMatch(failing.log, /cargo-service/, '第一步失败就停');
  assert.equal(failing.status, 1, failing.output);

  // 前两步成功后 node 起不来（同名的非程序文件排在 PATH 最前）：不能沿用 cargo-service 留下的 0。
  const unstartable = await build('start-failure', {'cargo.cmd': cargo(0), 'rustc.cmd': rustc, 'node.exe': 'not a program'});
  assert.match(unstartable.log, /step\.end cargo-service exit=0 /, unstartable.output);
  assert.match(unstartable.log, /step\.end release-check exit=-1 /, unstartable.output);
  assert.doesNotMatch(unstartable.log, /release\.check READY|step\.begin assemble|build\.done/, unstartable.output);
  assert.notEqual(unstartable.status, 0, unstartable.output);

  // cargo 先在步骤日志的位置建一个同名目录，再输出：日志写不进去，构建终止，不记这一步结束、不进下一步。
  const blocked = await build('log-unwritable', {'cargo.cmd': `@for /d %%d in ("%SYNTHETIC_LOG_ROOT%\\*") do @mkdir "%%d\\cargo-control.log"\r\n${cargo(0)}`, 'rustc.cmd': rustc});
  assert.match(blocked.log, /step\.begin cargo-control/, blocked.output);
  assert.doesNotMatch(blocked.log, /step\.end cargo-control|cargo-service|build\.done/, blocked.output);
  assert.notEqual(blocked.status, 0, blocked.output);
});

test('RC6 R11 机器可读就绪清单与人工调用链：桥操作与控制端路由按代码实算，五段调用链的调用者、证据与异机编号都存在', () => {
  const readiness = JSON.parse(read('evidence/delivery/release-readiness.json'));
  assert.deepEqual(readiness.bridge_ops.ops.slice().sort(), Object.keys(OPS).sort());
  assert.equal(readiness.bridge_ops.count, Object.keys(OPS).length);
  const router = read('services/control-rs/src/router.rs');
  const routeTable = router.match(/pub const ROUTES:[\s\S]*?= &\[([\s\S]*?)\n\];/)?.[1] || '';
  const routes = [...routeTable.matchAll(/\("(GET|POST|PUT)",\s*"([^"\n]+)"\)/g)].map((match) => `${match[1]} ${match[2]}`);
  assert.deepEqual(readiness.control_routes.routes, routes);
  assert.equal(readiness.control_routes.count, 44);
  assert.equal(readiness.check.status, 'NOT_READY', '本机生成的清单如实写未就绪');
  assert.equal(readiness.segments.length, 5);
  const experiments = read('evidence/delivery/t10-real-experiments.md');
  for (const segment of readiness.segments) {
    for (const hop of segment.hops) {
      assert.ok(read(hop.caller.file).includes(hop.caller.symbol), `${segment.id}：${hop.caller.file} 里有 ${hop.caller.symbol}`);
      assert.ok(read(hop.callee.file).includes(hop.callee.symbol), `${segment.id}：${hop.callee.file} 里有 ${hop.callee.symbol}`);
      assert.ok(['WIRED_OFFLINE_VERIFIED', 'WIRED_UNCOMPILED'].includes(hop.status), hop.status);
    }
    for (const [file, name] of segment.offline_evidence) assert.ok(read(file).includes(name), `${file} 里有 ${name}`);
    for (const id of segment.experiments) assert.ok(experiments.includes(`| ${id} |`), id);
  }
  const chain = read('evidence/delivery/release-call-chain.md');
  for (const heading of ['页面 → Tauri bridge → 宿主受限操作', '宿主 → Rust 控制端', '页面网络端口 → 宿主签名 IPC → 产品网络服务', '日志/计数 → RC5 审计运行时', '安装器 → 服务/控制端/资源落点']) assert.ok(chain.includes(heading), heading);
  assert.ok(chain.includes(`${Object.keys(OPS).length} 个`) && chain.includes('44 条'));
});

test('RC6 R12 交付文档纠正旧口径；E01—E52 原行逐字节不变；E53—E58 六列完整且未执行', () => {
  const docs = ['evidence/delivery/build-packaging.md', 'evidence/delivery/portable-data.md', 'evidence/delivery/t10-real-experiments.md'].map((file) => [file, read(file)]);
  // E01—E52 原行按要求逐字不改，旧口径在第 7d 节更正表里说明；这里只查冻结行以外的文字。
  const current = (text) => text.split('\n').filter((line) => !/^\| E\d{2} \|/.test(line)).join('\n');
  for (const [file, whole] of docs) {
    const text = current(whole);
    for (const stale of ['21 个受限操作', '固定 21 个', '24 个操作', '从 21 改到 24', '运行时只依赖 Node', '`state/local.sqlite`', '`state/control.sqlite`']) {
      assert.equal(text.includes(stale), false, `${file} 还写着 ${stale}`);
    }
    for (const line of text.split('\n').filter((row) => /tauri-plugin-mihomo|state\/environment\.json|state\/probe-services\.json/.test(row))) {
      assert.match(line, /不采用|未采用|不再|不是|已不|历史/, `${file}：${line}`);
    }
  }
  const t10 = docs[2][1];
  const rows = (text) => text.split('\n').filter((line) => /^\| E\d{2} \|/.test(line));
  const before = read('evidence/development/rc6/t10-e01-e52-before.txt').split('\n').filter(Boolean);
  assert.equal(before.length, 52);
  assert.deepEqual(rows(t10).filter((line) => Number(line.slice(3, 5)) <= 52), before, 'E01—E52 原行不改');
  const added = rows(t10).filter((line) => Number(line.slice(3, 5)) >= 53);
  assert.deepEqual(added.map((line) => line.slice(2, 5)), ['E53', 'E54', 'E55', 'E56', 'E57', 'E58']);
  for (const line of added) {
    const cells = line.split('|').slice(1, -1).map((cell) => cell.trim());
    assert.equal(cells.length, 6, line);
    assert.ok(cells.every(Boolean), line);
    assert.doesNotMatch(line, /\bPASS\b|已执行|已验证/);
  }
  const portable = docs[1][1];
  for (const fact of ['native-records.json', 'control.sqlite3', 'vault', 'ai-environmental-steward-service', 'ai_environmental_steward_service']) assert.ok(portable.includes(fact), fact);
  const packaging = docs[0][1];
  assert.ok(packaging.includes(`${Object.keys(OPS).length} 个`), '桥操作数按代码实算');
  assert.ok(packaging.includes('release.mjs check') && packaging.includes('release.mjs assemble'));
});

test('RC6 R13 publicQuota 迁到核心模块后输出与迁移前逐项一致；Node 控制端改为再导出同一函数；正式页面闭包不含 services/control/**', async () => {
  const {frontendClosure, loadReleaseInputs} = await release();
  const inputs = await loadReleaseInputs(ROOT);
  const closure = await frontendClosure(ROOT, inputs.frontend);
  const leaked = [...closure.files, ...closure.problems.map((item) => item.file)].filter((file) => file.startsWith('services/control/'));
  assert.deepEqual(leaked, [], '正式页面闭包不含 Node 控制端目录');
  const core = await import('../../src/core/network/quota.mjs');
  const node = await import('../../services/control/network.mjs');
  assert.equal(typeof core.publicQuota, 'function', '核心模块导出 publicQuota');
  assert.equal(node.publicQuota, core.publicQuota, '服务端沿用同一个函数，没有两份实现');
  const before = JSON.parse(read('evidence/development/rc6/public-quota-before.json'));
  assert.equal(before.cases.length, 17);
  for (const {input, output} of before.cases) {
    const given = input && input.undefined === true ? undefined : input;
    assert.deepEqual(JSON.parse(JSON.stringify(core.publicQuota(given) ?? null)), output, JSON.stringify(input));
  }
  const client = read('src/adapters/network/controlClient.mjs');
  assert.match(client, /from '\.\.\/\.\.\/core\/network\/quota\.mjs'/);
  assert.doesNotMatch(client, /services\/control/);
});

test('RC6 R14 正式页面按浏览器方式加载（没有 process、不能加载 Node 内置模块）时，入口先装上固定版 js-yaml，受管配置能编译', async () => {
  const vm = await import('node:vm');
  const {fileURLToPath, pathToFileURL} = await import('node:url');
  const context = vm.createContext({console, URL, TextEncoder, TextDecoder, setTimeout, clearTimeout, Date, Intl});
  const modules = new Map();
  const load = (file) => {
    if (!modules.has(file)) modules.set(file, new vm.SourceTextModule(readFileSync(file, 'utf8'), {context, identifier: pathToFileURL(file).href}));
    return modules.get(file);
  };
  const entry = load(path.join(ROOT, 'apps/desktop-ui/native-boot.mjs'));
  await entry.link(async (specifier, referencing) => {
    if (!specifier.startsWith('.')) throw new Error(`a browser cannot load ${specifier}`);
    return load(path.resolve(path.dirname(fileURLToPath(referencing.identifier)), specifier));
  });
  await entry.evaluate();
  const yaml = modules.get(path.join(ROOT, 'src/core/network/yaml.mjs'));
  assert.ok(yaml, 'yaml.mjs 在正式页面的模块图里');
  assert.equal(yaml.namespace.dumpYaml({mode: 'rule'}), 'mode: rule', '受管配置编译用的 YAML 库已装上');
  assert.ok(modules.has(path.join(ROOT, 'vendor/deps/js-yaml-4.3.0/dist/js-yaml.mjs')), '装的是固定的 js-yaml 4.3.0 构建');
});

const HOOKS = 'apps/desktop-host/vendor/service-ipc/resources/installer.nsi';
const INSTALLER = 'apps/desktop-host/vendor/service-ipc/src/bin/install_service.rs';
const UNINSTALLER = 'apps/desktop-host/vendor/service-ipc/src/bin/uninstall_service.rs';
const macroBody = (text, name) => {
  const start = text.indexOf(`!macro ${name}`);
  return start < 0 ? '' : text.slice(start, text.indexOf('!macroend', start));
};

test('RC6 Round 2 F1 修复与升级失败回到完整旧版本（源码静态核对）：先备份整个安装目录与安装记录再停服务，失败时整目录恢复、版本号与安装记录复原后再启动旧服务', () => {
  const hooks = read(HOOKS);
  const begin = macroBody(hooks, 'STEWARD_MAINTENANCE_BEGIN');
  assert.ok(begin, '维护准备写成一个宏');
  assert.match(begin, /CopyFiles \/SILENT "\$INSTDIR\\\*\.\*" "\$StewardBackup"/, '整个安装目录（桌面程序、页面、控制端、服务、内核、许可、卸载程序）进回滚副本');
  assert.match(begin, /WriteINIStr "\$StewardMarker"/, '副本旁边的标记记下旧版本号（Round 4 起标记不在副本里）');
  assert.ok(begin.indexOf('CopyFiles') < begin.indexOf('--action prepare-upgrade'), '备份成功之后才确认保护并停服务');
  assert.match(hooks, /StrCpy \$StewardBackup "\$INSTDIR\.rollback"/, '回滚副本放在安装目录旁边，不会被新文件覆盖');
  const preinstall = macroBody(hooks, 'NSIS_HOOK_PREINSTALL');
  assert.match(preinstall, /\$\{FileExists\} "\$StewardMarker"/, '上次维护没有提交时先回滚');
  assert.match(preinstall, /!insertmacro STEWARD_MAINTENANCE_BEGIN/);
  const rollback = functionBody(hooks, 'StewardRollback');
  assert.ok(rollback, '失败回滚写成一个函数，后安装钩子与 .onInstFailed 共用');
  const order = ['SetOutPath', 'Rename "$INSTDIR" "$StewardFailed"', 'Rename "$StewardBackup" "$INSTDIR"', 'WriteRegStr SHCTX "$StewardUninstKey" "DisplayVersion" "$StewardInstalled"', '--action rollback-upgrade'];
  const positions = order.map((needle) => rollback.indexOf(needle));
  assert.ok(positions.every((at) => at >= 0), JSON.stringify(order.filter((_, index) => positions[index] < 0)));
  assert.deepEqual(positions.slice().sort((a, b) => a - b), positions, '先离开安装目录、把新文件整目录挪开、换回旧版，复原版本号，最后用旧助手复原安装记录并启动旧服务');
  const postinstall = macroBody(hooks, 'NSIS_HOOK_POSTINSTALL');
  assert.match(postinstall, /Call StewardRollback/);
  assert.match(postinstall, /RMDir \/r "\$StewardBackup"/, '成功后删掉回滚副本');
  assert.equal(hooks.includes('service.rollback'), false, '不再只回滚服务目录');

  const installer = read(INSTALLER);
  assert.match(installer, /fn state_rollback_dir/);
  for (const file of ['install.json', 'runtime-state.json']) assert.ok(installer.includes(`"${file}"`), `${file} 进回滚副本`);
  assert.equal(installer.includes('PRODUCT_FILES'), false, '不再由助手逐个复制服务文件');
  const complete = installer.slice(installer.indexOf('fn complete_upgrade'), installer.indexOf('\n}\n', installer.indexOf('fn complete_upgrade')));
  assert.equal(complete.includes('rollback_upgrade('), false, '完成升级失败时不自己半截回滚，交给安装器整目录恢复');
});

test('RC6 Round 2 F2 批准用户取安装器所在会话的桌面用户，不取提权令牌的用户（源码静态核对）', () => {
  const hooks = read(HOOKS);
  assert.equal(/whoami|--user-sid|--network-root/.test(hooks), false, '钩子不再用提权进程的令牌推断用户');
  const calls = [...hooks.matchAll(/--action (install|repair|complete-upgrade) ([^\n']*)/g)];
  assert.equal(calls.length, 3);
  for (const [, action, rest] of calls) assert.match(rest, /--user-from-session/, action);
  const installer = read(INSTALLER);
  for (const symbol of ['ProcessIdToSessionId', 'WTSQuerySessionInformationW', 'WTSUserName', 'WTSDomainName', 'LookupAccountNameW', 'ConvertSidToStringSidW', 'ProfileImagePath', 'fn resolve_user', 'fn network_root_for_profile']) {
    assert.ok(installer.includes(symbol), symbol);
  }
  const cargo = read('apps/desktop-host/vendor/service-ipc/Cargo.toml');
  for (const feature of ['Win32_Security', 'Win32_Security_Authorization', 'Win32_System_RemoteDesktop', 'Win32_System_Registry']) assert.ok(cargo.includes(`"${feature}"`), feature);
});

test('RC6 Round 2 F3 卸载先证明服务已停、再撤保护并复核撤净，才删服务；任何一步没证明就中止（源码静态核对；Round 3 起撤净证明改为枚举本产品子层，见 G3）', () => {
  const uninstaller = read(UNINSTALLER);
  const body = uninstaller.slice(uninstaller.indexOf('fn uninstall()'));
  const stopped = body.indexOf('did not stop');
  const sweep = body.indexOf('product_sublayer_sweep(');
  const remove = body.indexOf('service.delete()');
  assert.ok(stopped > 0 && sweep > stopped, '服务没停下来就不撤保护');
  assert.ok(remove > sweep, '复核撤净之后才删服务');
  assert.match(body, /restart\("service_did_not_stop"\)/, '停不下来就重启服务并中止');
});

test('RC6 Round 2 F4 发布检查：必需工具必须实际探测到才算 READY，未探测或探测不到都是 NOT_READY', async () => {
  const {checkRelease, loadReleaseInputs} = await release();
  const {root, inputs} = await syntheticRepo('tools-required');
  const found = async () => ({found: true, version: 'synthetic'});
  const tools = (nsis) => [
    {id: 'cargo', class: 'build_tool', probe: ['cargo', '--version']},
    {id: 'nsis', class: 'build_tool', probe: nsis},
  ];
  const unchecked = await checkRelease({root, inputs: {...inputs, items: [...inputs.items, ...tools(null)]}, probeTool: found});
  assert.equal(unchecked.status, 'NOT_READY', '必需工具没有探测方式就不能 READY');
  assert.equal(unchecked.tools.find((tool) => tool.id === 'nsis').status, 'TOOL_UNCHECKED');
  const probed = await checkRelease({root, inputs: {...inputs, items: [...inputs.items, ...tools({file: '%LOCALAPPDATA%/tauri/NSIS/makensis.exe'})]}, probeTool: found});
  assert.equal(probed.status, 'READY', JSON.stringify(probed.tools));
  const missing = await checkRelease({root, inputs: {...inputs, items: [...inputs.items, ...tools({file: 'nowhere/makensis.exe'})]}, probeTool: async (probe) => ({found: Array.isArray(probe)})});
  assert.equal(missing.status, 'NOT_READY');
  assert.equal(missing.tools.find((tool) => tool.id === 'nsis').status, 'TOOL_MISSING');

  const real = await loadReleaseInputs(ROOT);
  for (const tool of real.items.filter((item) => item.class === 'build_tool')) {
    assert.ok(tool.probe, `${tool.id} 有探测方式`);
    assert.notEqual(tool.required, false, `${tool.id} 是必需工具`);
  }
  assert.deepEqual(real.items.find((item) => item.id === 'nsis').probe, {file: '%LOCALAPPDATA%/tauri/NSIS/makensis.exe'}, 'tauri-cli 在 Windows 上只用自己缓存的 NSIS');
});

test('RC6 Round 2 F5 项目入口文档写明 RC6 已施工、Round 1 复核 FAIL 与 Round 2 状态', () => {
  for (const file of ['AGENTS.md', 'README.md', 'evidence/development/product-completion-plan.md', 'evidence/development/implementation-plan.md']) {
    const text = read(file);
    assert.equal(text.includes('RC6 尚未开工'), false, `${file} 还写着尚未开工`);
    assert.match(text, /RC6[^\n]*Round 1[^\n]*FAIL/, `${file} 写明 Round 1 结论`);
  }
});

const UPSTREAM_TEMPLATE = 'evidence/development/rc6-round3/upstream-tauri-2.11.5/installer.nsi';
const WFP = 'apps/desktop-host/vendor/service-ipc/src/core/wfp.rs';
const functionBody = (text, name) => {
  const start = text.indexOf(`\nFunction ${name}\n`);
  return start < 0 ? '' : text.slice(start, text.indexOf('\nFunctionEnd', start));
};
const rustFn = (text, signature) => {
  const start = text.indexOf(signature);
  return start < 0 ? '' : text.slice(start, text.indexOf('\n}\n', start));
};
const inOrder = (text, needles) => {
  const missing = [];
  let from = 0;
  for (const needle of needles) {
    const at = text.indexOf(needle, from);
    if (at < 0) missing.push(needle);
    else from = at + needle.length;
  }
  return {missing, ordered: missing.length === 0};
};

test('RC6 Round 3 G1 会话用户的配置文件目录：REG_SZ 与 REG_EXPAND_SZ 都接受并展开环境变量（源码静态核对）', () => {
  const installer = read(INSTALLER);
  const session = rustFn(installer, 'fn session_user()');
  assert.ok(session, 'session_user 还在');
  assert.doesNotMatch(session, /RRF_RT_REG_SZ,/, '只允许 REG_SZ 会让标准配置文件（REG_EXPAND_SZ）读取失败');
  assert.match(session, /RRF_RT_REG_SZ \| RRF_RT_REG_EXPAND_SZ \| RRF_NOEXPAND/, '两种字符串类型都接受，先取原文与类型');
  const calls = [...session.matchAll(/RegGetValueW\(/g)];
  assert.equal(calls.length, 2, '先取长度再取内容');
  assert.match(session, /ExpandEnvironmentStringsW/, 'REG_EXPAND_SZ 由助手自己展开');
  assert.match(session, /profile_directory\(/, '类型判定与展开走一个可单测的纯函数');
  const decode = rustFn(installer, 'fn profile_directory(');
  assert.match(decode, /REG_EXPAND_SZ/);
  assert.match(decode, /REG_SZ/);
  assert.ok(read('apps/desktop-host/vendor/service-ipc/Cargo.toml').includes('"Win32_System_Environment"'), '展开函数所在的 windows-sys 特性');
});

test('RC6 Round 3 G2 停服务之后的每个失败出口都回到旧版本：先关应用再停服务，安装失败走 .onInstFailed，中断后下次运行先回滚（源码静态核对，对照 Tauri 2.11.5 模板）', () => {
  const template = read(UPSTREAM_TEMPLATE);
  const include = template.indexOf('!include "{{installer_hooks}}"');
  assert.ok(include > 0 && include < template.indexOf('!define UNINSTKEY') && include < template.indexOf('!define MAINBINARYNAME'), '模板在定义常量之前 include 钩子文件');
  assert.equal(/Function \.onInstFailed|AllowSkipFiles/.test(template), false, '模板没有占用 .onInstFailed，也没设 AllowSkipFiles');
  assert.ok(template.indexOf('!addplugindir "${ADDITIONALPLUGINSPATH}"') > include, '插件目录在 include 钩子文件之后才加入');
  const section = template.slice(template.indexOf('Section Install'));
  assert.ok(inOrder(section, ['NSIS_HOOK_PREINSTALL', 'CheckIfAppIsRunning', 'File "${MAINBINARYSRCPATH}"', 'NSIS_HOOK_POSTINSTALL']).ordered, '预钩子在应用检查与文件复制之前');
  const unsection = template.slice(template.indexOf('Section Uninstall'));
  assert.ok(inOrder(unsection, ['NSIS_HOOK_PREUNINSTALL', 'CheckIfAppIsRunning']).ordered, '卸载预钩子也在应用检查之前');
  assert.match(template, /\$\{If\} \$UpdateMode = 1\s+Goto reinst_done/, '新安装器从不带 /UPDATE 调旧卸载器：带 /UPDATE 时直接跳过卸载');

  const hooks = read(HOOKS);
  for (const [, name, body] of hooks.matchAll(/\nFunction (\S+)\n([\s\S]*?)\nFunctionEnd/g)) {
    assert.doesNotMatch(body, /\$\{(UNINSTKEY|MAINBINARYNAME|VERSION|PRODUCTNAME|INSTALLMODE|MANUPRODUCTKEY)\}|\$\(/, `${name} 在模板常量与语言串定义之前编译，只能用变量`);
    assert.doesNotMatch(body, /::/, `${name} 编译时插件目录还没加入，不能调插件`);
  }
  assert.match(hooks, /^AllowSkipFiles off$/m, '文件写不进时只能重试或取消，不能跳过留下新旧混装');
  const failed = functionBody(hooks, '.onInstFailed');
  assert.match(failed, /\$StewardMaintenance == "1"[\s\S]*Call StewardRollback/, '安装在维护阶段失败或中止时回滚');
  const rollback = functionBody(hooks, 'StewardRollback');
  const steps = inOrder(rollback, ['StrCpy $StewardMaintenance "0"', '--action stop-for-rollback', 'SetOutPath', 'Rename "$INSTDIR" "$StewardFailed"', '${If} ${Errors}', 'Return', 'Rename "$StewardBackup" "$INSTDIR"', 'RMDir /r "$StewardFailed"', 'WriteRegStr SHCTX "$StewardUninstKey" "DisplayVersion" "$StewardInstalled"', '--action rollback-upgrade']);
  assert.deepEqual(steps.missing, []);
  assert.ok(steps.ordered, '只回滚一次；先停服务，把当前目录整个改名挪开（有文件被占用就整步不动、留给下次运行），再换回副本、复原版本号，最后由旧助手复原状态并启动旧服务');
  assert.equal(rollback.includes('RMDir /r "$INSTDIR"'), false, '不先删安装目录：删到一半遇到被占用的文件会留下残缺目录');

  const preinstall = macroBody(hooks, 'NSIS_HOOK_PREINSTALL');
  const recovery = inOrder(preinstall, ['StrCpy $StewardUninstKey "${UNINSTKEY}"', '!insertmacro STEWARD_CLOSE_RUNNING_APP', '${FileExists} "$StewardMarker"', 'Call StewardRollback', '!insertmacro STEWARD_MAINTENANCE_BEGIN']);
  assert.deepEqual(recovery.missing, []);
  assert.ok(recovery.ordered, '先征得同意关掉应用；上次维护没有提交就先回滚；然后才备份并停服务');
  assert.ok(inOrder(preinstall, ['!insertmacro STEWARD_MAINTENANCE_BEGIN', 'SetOutPath "$INSTDIR"']).ordered, '回滚把输出目录切到了 $TEMP，模板随后的 File 要解压回安装目录');
  const close = macroBody(hooks, 'STEWARD_CLOSE_RUNNING_APP');
  assert.ok(inOrder(close, ['nsis_tauri_utils::FindProcess', 'Abort', 'nsis_tauri_utils::KillProcess']).ordered, '用户不关应用就在停服务之前退出');
  const begin = macroBody(hooks, 'STEWARD_MAINTENANCE_BEGIN');
  assert.ok(inOrder(begin, ['--action prepare-upgrade', 'StrCpy $StewardMaintenance "1"']).ordered, '服务停下之后才进入需要回滚的阶段');
  const postinstall = macroBody(hooks, 'NSIS_HOOK_POSTINSTALL');
  assert.ok(inOrder(postinstall, ['Delete "$StewardMarker"', 'RMDir /r "$StewardBackup"']).ordered, '先删标记算提交，再删副本');
  assert.match(postinstall, /Call StewardRollback\s+Abort/, '修复或升级失败时回滚并以失败结束');
  const preuninstall = macroBody(hooks, 'NSIS_HOOK_PREUNINSTALL');
  assert.equal(/STEWARD_MAINTENANCE_BEGIN|\$UpdateMode/.test(preuninstall), false, '卸载器不做维护准备：新安装器从不带 /UPDATE 调它');
  assert.ok(inOrder(preuninstall, ['MessageBox', '!insertmacro STEWARD_CLOSE_RUNNING_APP', 'ai-environmental-steward-service-uninstall.exe']).ordered, '确认之后先关应用，再撤保护、删服务');

  const installer = read(INSTALLER);
  assert.match(installer, /"stop-for-rollback"/);
  assert.match(installer, /fn stop_for_rollback\(/);
  assert.match(rustFn(installer, 'fn prepare_upgrade('), /service\.start\(/, '停不下来时把服务重新启动，不留停着的服务');
});

test('RC6 Round 3 G3 卸载按本产品子层独立枚举证明撤净：不依赖运行状态，枚举或单键读取出错就中止（源码静态核对）', () => {
  const wfp = read(WFP);
  assert.match(wfp, /pub struct ProductSweep/);
  assert.match(wfp, /pub fn product_sublayer_sweep\(release: bool\) -> ProductSweep/);
  const sweep = rustFn(wfp, 'pub fn sweep_product_sublayer(&self, release: bool) -> ProductSweep');
  assert.ok(sweep, 'WfpProtection 上的子层清扫');
  assert.ok(inOrder(sweep, ['product_filters(engine)', 'delete_keys', 'product_filters(engine)', 'delete_keys', 'product_filters(engine)']).ordered, '枚举 → 删 permit → 再枚举确认只剩阻断 → 删阻断 → 再枚举（Round 4 H3 细化）');
  const enumerate = rustFn(wfp, 'unsafe fn product_filters(');
  assert.match(enumerate, /ptr::null\(\)/, '不带模板枚举全部层');
  assert.match(enumerate, /sub_layer_key == PRODUCT_SUBLAYER/);
  assert.match(rustFn(wfp, 'unsafe fn read_filter('), /FWP_E_FILTER_NOT_FOUND => return Ok\(None\)/, '只有「不存在」才算不在');
  assert.match(wfp, /"NATIVE_FILTER_READ_FAILED"/, '其他读取错误写错误码');
  for (const name of ['the_sweep_removes_every_product_filter_whatever_the_records_say', 'an_enumeration_or_delete_failure_is_never_a_clean_sweep', 'a_read_error_is_not_absence']) assert.match(wfp, new RegExp(`fn ${name}\\(`), name);

  const uninstaller = read(UNINSTALLER);
  const body = rustFn(uninstaller, 'fn uninstall()');
  assert.equal(/RuntimeState|runtime_state\(\)|unwrap_or_default/.test(body), false, '撤净证明不依赖运行状态文件');
  assert.ok(inOrder(body, ['did not stop', 'product_sublayer_sweep(release_protection)', '.clean()', 'service.delete()']).ordered, '服务停下 → 子层清扫与复核 → 清干净才删服务');
  assert.match(body, /restart\("protection_not_released"\)/, '没清干净就重启服务并中止');
});

const NETWORK = 'apps/desktop-host/vendor/service-ipc/src/core/network/mod.rs';
const NETWORK_TESTS = 'apps/desktop-host/vendor/service-ipc/src/core/network/tests.rs';

test('RC6 Round 4 H1 回滚标记放在目录交换之外，旧助手复原状态并启动旧服务成功后才删；目录已换回、服务还没恢复时下次运行接着恢复（源码静态核对）', () => {
  const hooks = read(HOOKS);
  assert.match(hooks, /StrCpy \$StewardMarker "\$INSTDIR\.rollback\.ini"/, '标记是安装目录旁边的独立文件，不随目录交换');
  assert.equal(/\$StewardBackup\\steward-rollback\.ini|\$INSTDIR\\steward-rollback\.ini/.test(hooks), false, '标记不放在会被交换的目录里');
  const begin = macroBody(hooks, 'STEWARD_MAINTENANCE_BEGIN');
  assert.ok(inOrder(begin, ['CopyFiles', 'WriteINIStr "$StewardMarker"', '--action prepare-upgrade']).ordered, '副本完整之后、停服务之前写标记');
  assert.match(begin.slice(begin.indexOf('--action prepare-upgrade')), /Delete "\$StewardMarker"/, '没停服务就退出时删标记');
  const rollback = functionBody(hooks, 'StewardRollback');
  const helper = rollback.indexOf('--action rollback-upgrade');
  assert.ok(helper > 0);
  assert.match(rollback, /\$\{If\} \$\{FileExists\} "\$StewardBackup\\\*\.\*"/, '副本还在才做目录交换；已经换回就直接复原状态与服务');
  assert.equal(rollback.slice(0, helper).includes('Delete "$StewardMarker"'), false, '旧助手成功之前不删标记');
  assert.equal(rollback.slice(0, helper).includes('StrCpy $StewardRestored "1"'), false, '旧助手成功之前不算恢复');
  assert.match(rollback.slice(helper), /\$\{If\} \$StewardExit == "0"\s+Delete "\$StewardMarker"\s+StrCpy \$StewardRestored "1"/, '只有旧助手退出码为 0 才删标记、算恢复');
  const preinstall = macroBody(hooks, 'NSIS_HOOK_PREINSTALL');
  assert.ok(inOrder(preinstall, ['${If} ${FileExists} "$StewardMarker"', 'Call StewardRollback', '${If} $StewardRestored != "1"', 'Abort', '!insertmacro STEWARD_MAINTENANCE_BEGIN']).ordered, '有未完成的维护或回滚就先恢复，恢复不成就中止，不开新维护、不覆盖原状态备份');
  assert.equal(/Delete "[^"]*rollback\.ini"/.test(preinstall), false, '预安装不删标记');
  const postinstall = macroBody(hooks, 'NSIS_HOOK_POSTINSTALL');
  assert.ok(inOrder(postinstall, ['Delete "$StewardMarker"', 'RMDir /r "$StewardBackup"']).ordered, '提交时先删标记再删副本');
});

test('RC6 Round 4 H2 卸载选择停止管理时，保留数据也把保护请求持久化为已撤销；重装后启动不会自动装回保护（源码静态核对）', () => {
  const network = read(NETWORK);
  const revoke = rustFn(network, 'pub fn revoke_protection_for_uninstall(');
  assert.ok(revoke, 'core/network 提供作废保护请求的函数');
  assert.ok(inOrder(revoke, ['reconcile_pending(state', 'record.requested = false', 'record.effective = false', '"UNINSTALL_REVOKED"']).ordered, '先把没落盘的保护意图对账进待定历史，再把全部保护请求作废');
  const saved = rustFn(network, 'pub fn revoke_saved_protection(');
  assert.ok(inOrder(saved, ['store.load()', 'revoke_protection_for_uninstall(', 'store.save(']).ordered, '读出已保存的状态、作废、写回');
  assert.match(read(NETWORK_TESTS), /fn uninstall_revocation_keeps_reports_but_restart_does_not_reapply_protection\(/);
  const uninstaller = read(UNINSTALLER);
  const body = rustFn(uninstaller, 'fn uninstall()');
  assert.ok(inOrder(body, ['.clean()', 'revoke_saved_protection(', 'service.delete()', 'if delete_state']).ordered, '子层清干净之后、删服务之前作废保护请求；删状态目录在最后');
  assert.match(body, /restart\("protection_request_not_revoked"\)/, '作废写不进就重启服务并中止，服务按原请求补回阻断');
});

test('RC6 Round 4 H3 子层清扫：放行没删净（删除报错或重新枚举还有放行）就不删任何阻断（源码静态核对）', () => {
  const wfp = read(WFP);
  const sweep = rustFn(wfp, 'pub fn sweep_product_sublayer(&self, release: bool) -> ProductSweep');
  assert.ok(inOrder(sweep, ['delete_keys(engine, &permits', 'deleted.code.is_none()', 'self.product_filters(engine)', '== FWP_ACTION_BLOCK', 'delete_keys(engine, &blocks', 'self.product_filters(engine)']).ordered, '先删放行；没有报错且重新枚举只剩阻断，才删阻断；最后再枚举复核');
  assert.match(sweep, /"PERMIT_NOT_RELEASED"/, '重新枚举还有放行时如实报错');
  assert.match(wfp, /fn a_permit_that_cannot_be_deleted_keeps_every_block\(/, '单个放行删除失败的回归用例');
  assert.match(wfp, /fail_delete_key/, '替身能让单个键删除失败');
});
