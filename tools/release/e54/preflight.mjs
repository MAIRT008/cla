import {existsSync, readdirSync, readFileSync, statSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {checkRelease, loadReleaseInputs} from '../assemble.mjs';

/**
 * E54 源镜像完整性预检（只读、不联网）：白名单漏带了正式编译或装配要读的源文件，就在下载依赖前失败。
 *   node tools/release/e54/preflight.mjs     全部齐全退出 0，缺任何一项退出 1；结果 JSON 打到标准输出。
 *
 * - 发布输入：除构建机生成的（built: true 或位于 build/ 下）以外，每一项都必须 PRESENT；固定哈希的许可文件哈希必须一致。
 * - 页面：从正式入口走模块图，闭包里每个 import 都要解析到镜像内的文件。
 * - 三个 crate 与 NSIS 预热工程：Cargo.toml 里的 path、include_str!/include_bytes! 目标、tauri.conf.json 引用的图标与安装钩子都要存在。
 */
const root = path.resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const problems = [];
const checked = {};

const inputs = await loadReleaseInputs(root);
const release = await checkRelease({root, inputs, probeTool: null});
const byId = new Map(inputs.items.map((item) => [item.id, item]));
const generated = (item) => item.built === true || item.source.startsWith('build/');
for (const entry of release.items) {
  if (entry.status === 'PRESENT') continue;
  const item = byId.get(entry.id);
  const tolerated = new Set(generated(item) ? ['MISSING'] : []);
  if (item.pin === 'PIN_REQUIRED') tolerated.add('PIN_REQUIRED');
  const unexpected = entry.reasons.filter((reason) => !tolerated.has(reason));
  if (unexpected.length) problems.push({code: 'RELEASE_INPUT', id: entry.id, source: entry.source, reasons: unexpected});
}
checked.release_items = release.items.length;
if (release.frontend.status !== 'OK') problems.push({code: 'FRONTEND_CLOSURE', problems: release.frontend.problems});
checked.frontend_files = release.frontend.files.length;

const crates = [
  'services/control-rs',
  'apps/desktop-host/vendor/service-ipc',
  'apps/desktop-host/src-tauri',
  'tools/release/nsis-warmup',
];

function rustFiles(directory) {
  const found = [];
  for (const entry of readdirSync(directory, {withFileTypes: true})) {
    if (entry.name === 'target') continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) found.push(...rustFiles(absolute));
    else if (entry.name.endsWith('.rs')) found.push(absolute);
  }
  return found;
}

const relative = (absolute) => path.relative(root, absolute).split(path.sep).join('/');
let references = 0;
for (const crate of crates) {
  const directory = path.join(root, ...crate.split('/'));
  const manifest = path.join(directory, 'Cargo.toml');
  if (!existsSync(manifest)) {
    problems.push({code: 'CARGO_MANIFEST_MISSING', crate});
    continue;
  }
  for (const [, target] of readFileSync(manifest, 'utf8').matchAll(/\bpath\s*=\s*"([^"]+)"/g)) {
    references += 1;
    const resolved = path.resolve(directory, target);
    const ok = existsSync(resolved) && (!statSync(resolved).isDirectory() || existsSync(path.join(resolved, 'Cargo.toml')));
    if (!ok) problems.push({code: 'CARGO_PATH_MISSING', crate, path: target});
  }
  for (const file of rustFiles(directory)) {
    for (const [, target] of readFileSync(file, 'utf8').matchAll(/\binclude_(?:str|bytes)!\(\s*"([^"]+)"\s*\)/g)) {
      references += 1;
      if (!existsSync(path.resolve(path.dirname(file), target))) problems.push({code: 'INCLUDE_MISSING', file: relative(file), path: target});
    }
  }
  const config = path.join(directory, 'tauri.conf.json');
  if (!existsSync(config)) continue;
  const tauri = JSON.parse(readFileSync(config, 'utf8'));
  const referenced = [...(tauri.bundle?.icon || [])];
  const hooks = tauri.bundle?.windows?.nsis?.installerHooks;
  if (hooks) referenced.push(hooks);
  const frontend = tauri.build?.frontendDist;
  if (frontend && !path.resolve(directory, frontend).startsWith(path.join(root, 'build'))) referenced.push(path.join(frontend, 'index.html'));
  for (const target of referenced) {
    references += 1;
    if (!existsSync(path.resolve(directory, target))) problems.push({code: 'TAURI_REFERENCE_MISSING', crate, path: target});
  }
}
checked.crates = crates.length;
checked.crate_references = references;

const status = problems.length ? 'FAIL' : 'PASS';
process.stdout.write(`${JSON.stringify({schema: 'steward-e54-preflight-1', status, checked, problems}, null, 1)}\n`);
process.exit(problems.length ? 1 : 0);
