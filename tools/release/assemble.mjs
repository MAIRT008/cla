import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync} from 'node:fs';
import {copyFile, lstat, mkdir, readFile, rename, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';

/**
 * 发布输入的检查与装配（只在构建机上跑；普通用户机器不需要 Node）。
 *
 * - 清单 `release-inputs.json` 是显式 allowlist：没列的文件不会进发布目录，列了的必须真实存在。
 * - 检查只读：缺二进制、锁文件、许可或构建工具时回结构化 NOT_READY 与逐项原因，不生成任何占位文件。
 * - 装配先检查，再复制到临时目录并逐个复核哈希；manifest 最后写，全部成功才改名成正式目录。
 *   任何一步失败都删掉临时目录、非零退出，不留貌似完整的发布目录。
 * - 页面资源按正式入口 `index.html` 走模块图取闭包，任何一个 import 解析不到、或落进 Node 专用 / 控制端 / 夹具 / 测试目录就失败。
 */
export const RELEASE_CLASSES = Object.freeze(['runtime', 'build_input', 'build_tool', 'test_material', 'source_license']);

const FAILURE_ORDER = Object.freeze(['SOURCE_OUT_OF_BOUNDS', 'TARGET_OUT_OF_BOUNDS', 'TARGET_DUPLICATE', 'MISSING', 'HASH_MISMATCH', 'PIN_REQUIRED', 'LICENSE_UNRESOLVED']);

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export async function loadReleaseInputs(root, file = 'tools/release/release-inputs.json') {
  return JSON.parse(await readFile(path.resolve(root, file), 'utf8'));
}

/** 清单里的路径只接受正斜杠相对形式：没有盘符、绝对路径、反斜杠、空段或 `.`/`..` 段。 */
function plainRelative(relative) {
  return typeof relative === 'string'
    && relative.length > 0
    && !relative.includes('\\')
    && !path.isAbsolute(relative)
    && !/^[A-Za-z]:/.test(relative)
    && !relative.split('/').some((part) => part === '' || part === '.' || part === '..');
}

function relativeInside(root, relative) {
  if (!plainRelative(relative)) return null;
  const resolved = path.resolve(root, relative);
  const back = path.relative(root, resolved);
  return !back || back.startsWith('..') || path.isAbsolute(back) ? null : resolved;
}

function htmlReferences(text) {
  return [...text.matchAll(/<(?:script|link)\b[^>]*?\b(?:src|href)="([^"]+)"/gi)].map((match) => match[1]);
}

function moduleReferences(text) {
  return [
    ...[...text.matchAll(/\b(?:import|export)\s+(?:[^'"`;]*?\s+from\s+)?['"]([^'"\n]+)['"]/g)].map((match) => ({specifier: match[1], dynamic: false})),
    ...[...text.matchAll(/\bimport\(\s*['"]([^'"\n]+)['"]\s*\)/g)].map((match) => ({specifier: match[1], dynamic: true})),
  ];
}

/** 页面闭包：从入口出发的全部静态引用，路径相对仓库根。 */
export async function frontendClosure(root, frontend) {
  const forbidden = frontend.forbidden || [];
  const files = new Set();
  const problems = [];
  const guarded = [];
  const queue = [frontend.entry];
  while (queue.length) {
    const file = queue.shift();
    if (files.has(file)) continue;
    if (forbidden.some((prefix) => file.startsWith(prefix))) {
      problems.push({code: 'MODULE_FORBIDDEN', file});
      continue;
    }
    const absolute = relativeInside(root, file);
    if (!absolute || !existsSync(absolute)) {
      problems.push({code: 'MODULE_UNRESOLVED', file});
      continue;
    }
    files.add(file);
    const text = await readFile(absolute, 'utf8');
    const html = file.endsWith('.html');
    const references = html ? htmlReferences(text).map((specifier) => ({specifier, dynamic: false})) : /\.m?js$/.test(file) ? moduleReferences(text) : [];
    for (const {specifier, dynamic} of references) {
      if (specifier.startsWith('node:') && dynamic) {
        // 动态 import 只在执行到时才加载：这些都在「是 Node 才走」的分支或 try/catch 里，页面不会触发。静态的一律拒绝。
        guarded.push({file, specifier});
      } else if (specifier.startsWith('node:')) {
        problems.push({code: 'MODULE_FORBIDDEN', file, specifier});
      } else if (/^[a-z][a-z0-9+.-]*:|^\/\//i.test(specifier)) {
        problems.push({code: 'REFERENCE_EXTERNAL', file, specifier});
      } else if (!html && !specifier.startsWith('.') && !specifier.startsWith('/')) {
        // HTML 里的 `app.css` 是相对地址；模块里的裸名要靠打包器或 import map，本产品两者都没有。
        problems.push({code: 'MODULE_BARE', file, specifier});
      } else {
        const joined = specifier.startsWith('/') ? specifier.slice(1) : path.posix.join(path.posix.dirname(file), specifier);
        const normalized = path.posix.normalize(joined);
        if (normalized.startsWith('..')) problems.push({code: 'MODULE_OUT_OF_ROOT', file, specifier});
        else queue.push(normalized);
      }
    }
  }
  return {files: [...files].sort(), problems, guarded_node_imports: guarded};
}

/** 探测方式二选一：命令数组（退出码 0 算有），或 `{file}`（按环境变量展开 `%NAME%` 后文件存在算有）。 */
function defaultProbe(probe) {
  if (!Array.isArray(probe)) {
    const file = String(probe.file).replace(/%([A-Za-z0-9_]+)%/g, (whole, name) => process.env[name] ?? whole);
    return {found: !/%[A-Za-z0-9_]+%/.test(file) && existsSync(file), version: null};
  }
  const command = probe;
  const run = spawnSync(command[0], command.slice(1), {encoding: 'utf8', timeout: 20_000, windowsHide: true});
  return {found: run.status === 0, version: run.status === 0 ? String(run.stdout || '').trim().split('\n')[0] : null};
}

/** 只读检查。probeTool 为 null 时不查构建工具（装配本身不需要它们）；查的时候必需工具（默认都是）必须探测到才 READY。 */
export async function checkRelease({root, inputs, probeTool = defaultProbe}) {
  const items = [];
  const targets = new Map();
  const licenses = new Set(inputs.items.filter((item) => item.class === 'source_license').map((item) => item.id));
  for (const item of inputs.items.filter((entry) => entry.class !== 'build_tool')) {
    const reasons = [];
    let digest = null;
    if (item.target !== null && item.target !== undefined) {
      if (!plainRelative(item.target)) reasons.push('TARGET_OUT_OF_BOUNDS');
      else targets.set(item.target, [...(targets.get(item.target) || []), item.id]);
    }
    const source = relativeInside(root, item.source);
    if (!source) reasons.push('SOURCE_OUT_OF_BOUNDS');
    else if (!existsSync(source)) reasons.push('MISSING');
    else if ((await lstat(source)).isSymbolicLink()) reasons.push('SOURCE_OUT_OF_BOUNDS');
    else {
      digest = sha256(await readFile(source));
      if (item.sha256 && item.sha256 !== digest) reasons.push('HASH_MISMATCH');
    }
    if (item.pin === 'PIN_REQUIRED' && !item.sha256) reasons.push('PIN_REQUIRED');
    if (item.class === 'runtime' && !licenses.has(item.license)) reasons.push('LICENSE_UNRESOLVED');
    items.push({id: item.id, class: item.class, status: reasons[0] || 'PRESENT', reasons, sha256: digest, source: item.source, target: item.target ?? null});
  }
  for (const [, ids] of targets) {
    if (ids.length < 2) continue;
    for (const entry of items.filter((item) => ids.includes(item.id))) {
      entry.reasons.unshift('TARGET_DUPLICATE');
      entry.status = entry.reasons[0];
    }
  }
  const tools = [];
  for (const tool of inputs.items.filter((entry) => entry.class === 'build_tool')) {
    if (!probeTool) continue;
    const required = tool.required !== false;
    if (!tool.probe) {
      tools.push({id: tool.id, required, status: required ? 'TOOL_UNCHECKED' : 'UNCHECKED', note: tool.note || null});
      continue;
    }
    const probed = await probeTool(tool.probe);
    tools.push({id: tool.id, required, status: probed.found ? 'PRESENT' : 'TOOL_MISSING', version: probed.version || null});
  }
  const closure = inputs.frontend ? await frontendClosure(root, inputs.frontend) : {files: [], problems: []};
  const frontend = {status: closure.problems.length ? 'PROBLEMS' : 'OK', files: closure.files, problems: closure.problems};
  const ready = items.every((item) => item.status === 'PRESENT') && tools.every((tool) => !tool.required || tool.status === 'PRESENT') && frontend.status === 'OK';
  return {status: ready ? 'READY' : 'NOT_READY', items, tools, frontend};
}

function failureCode(item) {
  const reason = FAILURE_ORDER.find((code) => item.reasons.includes(code));
  if (reason === 'MISSING') return item.class === 'source_license' ? 'LICENSE_INCOMPLETE' : 'ITEM_MISSING';
  if (reason === 'LICENSE_UNRESOLVED') return 'LICENSE_INCOMPLETE';
  return reason;
}

async function copyVerified(from, to, expected) {
  await mkdir(path.dirname(to), {recursive: true});
  await copyFile(from, to);
  const actual = sha256(await readFile(to));
  if (actual !== expected) throw Object.assign(new Error(`copied bytes of ${path.basename(to)} differ from the checked source`), {code: 'COPY_VERIFY_FAILED'});
  return actual;
}

/**
 * 装配：out 不能已存在。成功时 out 下是 `install/`（按清单目标路径，供 Tauri resources 映射）、
 * `frontend/`（页面闭包，保持仓库相对路径）与最后写入的 `release-manifest.json`。
 */
export async function assembleRelease({root, inputs, out, onBeforeCopy = null, onCopied = null, frontendOnly = false}) {
  if (existsSync(out)) return {ok: false, code: 'ASSEMBLY_TARGET_EXISTS', detail: 'the output directory already exists; assembly never overwrites'};
  const report = await checkRelease({root, inputs, probeTool: null});
  const broken = report.items.find((item) => item.status !== 'PRESENT');
  if (broken) return {ok: false, code: failureCode(broken), item: broken.id, reasons: broken.reasons};
  if (report.frontend.status !== 'OK') return {ok: false, code: 'FRONTEND_UNRESOLVED', problems: report.frontend.problems};

  const partial = `${out}.partial-${process.pid}-${Date.now()}`;
  const byId = new Map(inputs.items.map((item) => [item.id, item]));
  try {
    await mkdir(partial, {recursive: true});
    const packaged = [];
    for (const checked of frontendOnly ? [] : report.items.filter((item) => item.target)) {
      const item = byId.get(checked.id);
      await onBeforeCopy?.({item});
      const target = `install/${item.target}`;
      await copyVerified(relativeInside(root, item.source), path.join(partial, ...target.split('/')), checked.sha256);
      packaged.push({id: item.id, class: item.class, target: item.target, sha256: checked.sha256, source: item.source, origin: item.origin || null, license: item.license || null});
      await onCopied?.({partial, target});
    }
    const pages = [];
    for (const file of report.frontend.files) {
      const digest = sha256(await readFile(relativeInside(root, file)));
      await copyVerified(relativeInside(root, file), path.join(partial, 'frontend', ...file.split('/')), digest);
      pages.push({path: file, sha256: digest});
      await onCopied?.({partial, target: `frontend/${file}`});
    }
    const manifest = {
      schema: 'steward-release-manifest-1',
      product: inputs.product,
      assembled_at: new Date().toISOString(),
      items: packaged,
      build_inputs: frontendOnly ? [] : report.items.filter((item) => item.class === 'build_input').map((item) => ({id: item.id, source: item.source, sha256: item.sha256})),
      frontend: {entry: inputs.frontend?.entry || null, files: pages},
      not_included: {
        test_material: report.items.filter((item) => item.class === 'test_material').map((item) => item.id),
        build_tools: inputs.items.filter((item) => item.class === 'build_tool').map((item) => item.id),
      },
    };
    await writeFile(path.join(partial, 'release-manifest.json'), `${JSON.stringify(manifest, null, 1)}\n`);
    await rename(partial, out);
    return {ok: true, out, manifest};
  } catch (error) {
    await rm(partial, {recursive: true, force: true});
    return {ok: false, code: error.code === 'COPY_VERIFY_FAILED' ? 'COPY_VERIFY_FAILED' : 'ASSEMBLY_INTERRUPTED', detail: String(error.message || error)};
  }
}
