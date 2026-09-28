import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync, writeSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import zlib from 'node:zlib';
import {WARMUP_LOCK} from './locks.mjs';

/**
 * E54 构建提交的 GPL 对应源码归档（2026-09-28 裁决第 2 步）。
 *   node tools/release/e54/corresponding-source.mjs build  [--repo <仓库>] --commit <提交> --out <目录> --cache <目录> [--offline]
 *   node tools/release/e54/corresponding-source.mjs verify <e54-corresponding-source.zip> [--repo <仓库> [--commit <提交>]]
 *
 * - 首方源码取构建提交里的全部已跟踪文件（读 git blob，不读工作区），含构建与安装脚本、四份 Cargo.lock 与改造后的 service-ipc。
 * - 第三方源码：Mihomo 固定提交的官方源码 ZIP（按已记录的 SHA-256 核对）；三份产品锁里全部 crates.io 包的原始 .crate（按锁里的 checksum 核对）；
 *   Mihomo go.sum 列出的 Go 模块 zip 与 go.mod（按 go.sum 的 h1 核对），按 GOPROXY 目录布局存放。
 * - 缓存里没有才下载（HTTPS GET，固定 UA，不带身份）；每个文件先核对再原子写入缓存。--offline 或 E54_SOURCE_OFFLINE=1 时缺文件就失败。
 * - 归档用 store 方式、条目按字节序排序、时间固定，同样的输入得到同样的字节；SOURCE-MANIFEST.json 逐项写来源与哈希，不含时间戳。
 * - verify 只靠归档自身逐项复核来源与哈希，给了 --repo 时再对照构建提交核对首方文件齐全；缺失、多出、来源不明或哈希不符都失败。
 */
export const MIHOMO = Object.freeze({
  repository: 'MetaCubeX/mihomo',
  tag: 'v1.19.30',
  commit: 'ac017cdd246ce8bd547653d927e7bf77d7ee73d5',
  url: 'https://codeload.github.com/MetaCubeX/mihomo/zip/ac017cdd246ce8bd547653d927e7bf77d7ee73d5',
  bytes: 1761718,
  sha256: 'd26880078fae7755c7ee9ce718ef6de5806d76c8d289237ec926b6a2f35d69be',
});
export const ARCHIVE_NAME = 'e54-corresponding-source.zip';
export const RECORD_NAME = 'e54-corresponding-source.json';
const ROOT = 'e54-corresponding-source';
const PRODUCT_LOCKS = ['services/control-rs/Cargo.lock', 'apps/desktop-host/vendor/service-ipc/Cargo.lock', 'apps/desktop-host/src-tauri/Cargo.lock'];
const CRATES_IO = 'registry+https://github.com/rust-lang/crates.io-index';
const USER_AGENT = 'e54-source-archive';
const MIHOMO_ENTRY = `third-party/mihomo/source-${MIHOMO.commit}.zip`;
export const NOT_INCLUDED = Object.freeze([
  {item: 'NSIS 安装器运行时与插件（安装包里的 uninstall.exe、$PLUGINSDIR 下的 System.dll、nsDialogs.dll、StartMenu.dll、modern-wizard.bmp）', reason: '由 tauri-cli 2.10.1 取得的 NSIS 打包进安装器，zlib/libpng 许可，不属于 GPL 作品；未随附源码'},
  {item: 'nsis_tauri_utils.dll（安装包 $PLUGINSDIR）', reason: 'tauri-cli 2.10.1 固定下载的 tauri-apps/nsis-tauri-utils 插件，MIT/Apache-2.0，不属于 GPL 作品；未随附源码'},
  {item: 'MicrosoftEdgeWebview2Setup.exe（安装包 $TEMP）', reason: 'Microsoft 的 WebView2 引导程序，按再分发条款随附，不是本作品的一部分；没有源码'},
  {item: 'WebView2LoaderStatic.lib（crate webview2-com-sys 0.38.2 自带，msvc 目标下以 kind = "static" 链接进桌面宿主）', reason: 'Microsoft WebView2 SDK 的预编译静态库，没有源码；归档里只有 crate 自带的预编译原件'},
  {item: 'wintun.dll（Go 模块 github.com/metacubex/sing-tun v0.4.22 自带，经 go:embed 嵌进 Mihomo 的 Windows 程序）', reason: 'WireGuard LLC 发布的预编译 Wintun 库；归档里只有模块包自带的预编译原件，Wintun 本身的源码未随附'},
  {item: '构建 Mihomo 官方程序所用的 Go 工具链与发布流程', reason: '随附的是官方发布程序，其构建流程在 Mihomo 源码的 .github 与 Makefile 里；本项目没有自行编译 Mihomo，也未验证可逐字节重现'},
  {item: 'Rust 工具链、tauri-cli、cargo-about、Node、Windows PowerShell', reason: '通用、未修改的构建工具与系统库；版本写在 BUILD.md'},
  {item: 'NSIS 预热工程 tools/release/nsis-warmup 的依赖 crate', reason: '预热只用于让 tauri-cli 取得 NSIS，不进安装包；它的锁在首方源码里，依赖源码未随附'},
  {item: 'Go 模块代理的 .info 文件', reason: 'go.sum 不覆盖 .info，无法核对来源；按固定版本离线构建一般不需要'},
]);

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const byBytes = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const gitBlobId = (bytes) => createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');

function git(repo, args, binary = false) {
  const run = spawnSync('git', ['-C', repo, ...args], {maxBuffer: 1 << 30, encoding: binary ? 'buffer' : 'utf8'});
  if (run.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${run.stderr}`);
  return run.stdout;
}

export function commitFiles(repo, rev) {
  const commit = git(repo, ['rev-parse', '--verify', `${rev}^{commit}`]).trim();
  const files = git(repo, ['ls-tree', '-r', '-z', '--full-tree', commit]).split('\0').filter(Boolean).map((line) => {
    const tab = line.indexOf('\t');
    const [mode, type, blob] = line.slice(0, tab).split(' ');
    return {mode, type, blob, path: line.slice(tab + 1)};
  });
  const odd = files.filter((file) => file.type !== 'blob' || !['100644', '100755'].includes(file.mode));
  if (odd.length) throw new Error(`commit ${commit} has non-regular entries: ${odd.map((file) => `${file.mode} ${file.path}`).join(', ')}`);
  for (const file of files) {
    file.bytes = git(repo, ['cat-file', 'blob', file.blob], true);
    if (gitBlobId(file.bytes) !== file.blob) throw new Error(`${file.path}: blob content does not match ${file.blob}`);
  }
  return {commit, files: files.sort((a, b) => byBytes(a.path, b.path))};
}

export function lockPackages(text) {
  return text.replace(/\r\n/g, '\n').split(/\n\[\[package\]\]\n/).slice(1).map((block) => {
    const field = (name) => block.match(new RegExp(`^${name} = "([^"]*)"$`, 'm'))?.[1] ?? null;
    return {name: field('name'), version: field('version'), source: field('source'), checksum: field('checksum')};
  });
}

export function rustCrates(locks) {
  const found = new Map();
  for (const [lock, text] of locks) {
    for (const pkg of lockPackages(text)) {
      if (!pkg.source) continue;
      if (pkg.source !== CRATES_IO) throw new Error(`${lock}: ${pkg.name} ${pkg.version} comes from an unsupported source ${pkg.source}`);
      if (!/^[0-9a-f]{64}$/.test(pkg.checksum || '')) throw new Error(`${lock}: ${pkg.name} ${pkg.version} has no checksum`);
      const key = `${pkg.name}-${pkg.version}`;
      const previous = found.get(key);
      if (previous && previous.checksum !== pkg.checksum) throw new Error(`${key}: checksum differs between ${previous.locks.join(', ')} and ${lock}`);
      found.set(key, {name: pkg.name, version: pkg.version, checksum: pkg.checksum, locks: [...(previous?.locks || []), lock]});
    }
  }
  return [...found.values()].sort((a, b) => byBytes(`${a.name}-${a.version}`, `${b.name}-${b.version}`));
}

export function goSum(text) {
  const zips = [];
  const mods = [];
  for (const line of text.replace(/\r\n/g, '\n').split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length !== 3) continue;
    const [module, version, hash] = parts;
    if (!hash.startsWith('h1:')) throw new Error(`go.sum: ${module} ${version} is not an h1 hash`);
    if (version.endsWith('/go.mod')) mods.push({module, version: version.slice(0, -'/go.mod'.length), hash});
    else zips.push({module, version, hash});
  }
  const order = (a, b) => byBytes(`${a.module}@${a.version}`, `${b.module}@${b.version}`);
  return {zips: zips.sort(order), mods: mods.sort(order)};
}

const escapeGo = (value) => value.replace(/[A-Z]/g, (letter) => `!${letter.toLowerCase()}`);
const goEntry = (module, version, ext) => `third-party/go/${escapeGo(module)}/@v/${escapeGo(version)}.${ext}`;
const crateEntry = (crate) => `third-party/rust/crates/${crate.name}-${crate.version}.crate`;

export function hash1(files) {
  const lines = files.map(({name, bytes}) => {
    if (name.includes('\n')) throw new Error(`dirhash: file name with newline: ${JSON.stringify(name)}`);
    return {name, line: `${sha256(bytes)}  ${name}\n`};
  }).sort((a, b) => byBytes(a.name, b.name)).map((entry) => entry.line).join('');
  return `h1:${createHash('sha256').update(lines).digest('base64')}`;
}

export function readZip(bytes) {
  let end = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i -= 1) {
    if (bytes.readUInt32LE(i) === 0x06054b50) { end = i; break; }
  }
  if (end < 0) throw new Error('not a zip file');
  const count = bytes.readUInt16LE(end + 10);
  let offset = bytes.readUInt32LE(end + 16);
  if (count === 0xffff || offset === 0xffffffff) throw new Error('zip64 archives are not supported');
  const entries = [];
  for (let n = 0; n < count; n += 1) {
    if (bytes.readUInt32LE(offset) !== 0x02014b50) throw new Error('corrupt zip central directory');
    const nameLength = bytes.readUInt16LE(offset + 28);
    entries.push({
      name: bytes.toString('utf8', offset + 46, offset + 46 + nameLength),
      method: bytes.readUInt16LE(offset + 10),
      crc: bytes.readUInt32LE(offset + 16),
      compressed: bytes.readUInt32LE(offset + 20),
      size: bytes.readUInt32LE(offset + 24),
      local: bytes.readUInt32LE(offset + 42),
    });
    offset += 46 + nameLength + bytes.readUInt16LE(offset + 30) + bytes.readUInt16LE(offset + 32);
  }
  const data = (entry) => {
    if (bytes.readUInt32LE(entry.local) !== 0x04034b50) throw new Error(`${entry.name}: corrupt local header`);
    const start = entry.local + 30 + bytes.readUInt16LE(entry.local + 26) + bytes.readUInt16LE(entry.local + 28);
    const raw = bytes.subarray(start, start + entry.compressed);
    let out;
    if (entry.method === 0) out = raw;
    else if (entry.method === 8) out = zlib.inflateRawSync(raw);
    else throw new Error(`${entry.name}: unsupported compression method ${entry.method}`);
    if (out.length !== entry.size || (zlib.crc32(out) >>> 0) !== entry.crc) throw new Error(`${entry.name}: size or CRC mismatch`);
    return out;
  };
  return {entries, data};
}

const zipFiles = (bytes) => {
  const zip = readZip(bytes);
  return zip.entries.map((entry) => ({name: entry.name, bytes: zip.data(entry)}));
};

function writeZip(target, entries) {
  if (entries.length >= 0xffff) throw new Error('too many entries for a plain zip');
  const fd = openSync(target, 'w');
  const central = [];
  let offset = 0;
  const put = (buffer) => { writeSync(fd, buffer); offset += buffer.length; };
  try {
    for (const entry of entries) {
      const bytes = entry.read();
      const name = Buffer.from(entry.name, 'utf8');
      const crc = zlib.crc32(bytes) >>> 0;
      if (bytes.length >= 0xffffffff || offset >= 0xffffffff) throw new Error('archive too large for a plain zip');
      const local = Buffer.alloc(30);
      local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x0800, 6); local.writeUInt16LE(0, 8);
      local.writeUInt16LE(0, 10); local.writeUInt16LE(0x0021, 12); local.writeUInt32LE(crc, 14); local.writeUInt32LE(bytes.length, 18);
      local.writeUInt32LE(bytes.length, 22); local.writeUInt16LE(name.length, 26); local.writeUInt16LE(0, 28);
      central.push({name, crc, size: bytes.length, offset});
      put(local); put(name); put(bytes);
    }
    const start = offset;
    for (const item of central) {
      const header = Buffer.alloc(46);
      header.writeUInt32LE(0x02014b50, 0); header.writeUInt16LE(20, 4); header.writeUInt16LE(20, 6); header.writeUInt16LE(0x0800, 8);
      header.writeUInt16LE(0, 10); header.writeUInt16LE(0, 12); header.writeUInt16LE(0x0021, 14); header.writeUInt32LE(item.crc, 16);
      header.writeUInt32LE(item.size, 20); header.writeUInt32LE(item.size, 24); header.writeUInt16LE(item.name.length, 28);
      header.writeUInt32LE(item.offset, 42);
      put(header); put(item.name);
    }
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(central.length, 8); eocd.writeUInt16LE(central.length, 10);
    eocd.writeUInt32LE(offset - start, 12); eocd.writeUInt32LE(start, 16);
    put(eocd);
  } finally {
    closeSync(fd);
  }
}

const verifyCrate = (crate) => (bytes) => sha256(bytes) === crate.checksum ? null : `sha256 ${sha256(bytes)} is not the Cargo.lock checksum ${crate.checksum}`;
const verifyGoZip = (item) => (bytes) => { const actual = hash1(zipFiles(bytes)); return actual === item.hash ? null : `${actual} is not the go.sum hash ${item.hash}`; };
const verifyGoMod = (item) => (bytes) => { const actual = hash1([{name: 'go.mod', bytes}]); return actual === item.hash ? null : `${actual} is not the go.sum hash ${item.hash}`; };
const verifyMihomo = (bytes) => bytes.length === MIHOMO.bytes && sha256(bytes) === MIHOMO.sha256 ? null : `bytes=${bytes.length} sha256=${sha256(bytes)} is not the recorded Mihomo source archive`;

async function fetchVerified({url, cacheFile, check, offline}) {
  if (existsSync(cacheFile)) {
    const bytes = readFileSync(cacheFile);
    const problem = check(bytes);
    if (problem) throw new Error(`${cacheFile}: cached file fails verification: ${problem}`);
    return bytes;
  }
  if (offline) throw new Error(`offline and not cached: ${url}`);
  let last = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const response = await fetch(url, {headers: {'User-Agent': USER_AGENT}});
      if (response.status === 404 || response.status === 410) throw Object.assign(new Error(`${url}: HTTP ${response.status}`), {final: true});
      if (response.status !== 200) throw new Error(`${url}: HTTP ${response.status}`);
      const bytes = Buffer.from(await response.arrayBuffer());
      const problem = check(bytes);
      if (problem) throw Object.assign(new Error(`${url}: downloaded file fails verification: ${problem}`), {final: true});
      mkdirSync(path.dirname(cacheFile), {recursive: true});
      writeFileSync(`${cacheFile}.partial-${process.pid}`, bytes);
      renameSync(`${cacheFile}.partial-${process.pid}`, cacheFile);
      return bytes;
    } catch (error) {
      last = error;
      if (error.final) break;
      await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
    }
  }
  throw last;
}

async function pool(items, limit, work) {
  const results = new Array(items.length);
  let next = 0;
  const problems = [];
  await Promise.all(Array.from({length: Math.min(limit, items.length)}, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      try { results[index] = await work(items[index]); } catch (error) { problems.push(error.message); }
    }
  }));
  if (problems.length) throw new Error(`${problems.length} third-party file(s) failed:\n${problems.sort().join('\n')}`);
  return results;
}

function workflowToolchain(files) {
  const workflow = files.find((file) => file.path === '.github/workflows/e54-windows-release.yml');
  const text = workflow ? workflow.bytes.toString('utf8') : '';
  const value = (name) => text.match(new RegExp(`^\\s*${name}:\\s*(\\S+)\\s*$`, 'm'))?.[1] ?? null;
  return {rust: value('E54_RUST_TOOLCHAIN'), tauri_cli: value('E54_TAURI_CLI_VERSION'), cargo_about: value('E54_CARGO_ABOUT_VERSION'), node: '22.x', powershell: 'Windows PowerShell 5.1', runner: value('runs-on')};
}

function lockRecords(files, releaseInputs) {
  const records = [];
  for (const lock of [...PRODUCT_LOCKS, WARMUP_LOCK.source]) {
    const file = files.find((item) => item.path === lock);
    if (!file) throw new Error(`${lock} is not in the commit`);
    const expected = lock === WARMUP_LOCK.source ? WARMUP_LOCK.sha256 : releaseInputs.items.find((item) => item.source === lock)?.sha256;
    const actual = sha256(file.bytes);
    if (actual !== expected) throw new Error(`${lock}: sha256 ${actual} is not the approved baseline ${expected}`);
    records.push({path: lock, bytes: file.bytes.length, sha256: actual});
  }
  return records;
}

export function buildMarkdown(manifest) {
  const locks = manifest.locks.map((lock) => `- \`${lock.path}\`：${lock.bytes} 字节，SHA-256 \`${lock.sha256}\``).join('\n');
  const tool = manifest.toolchain;
  return `# E54 对应源码

本归档对应 AI Environmental Steward 镜像仓库提交 \`${manifest.mirror_commit}\` 的构建，按 GPLv3 第 1、6 节提供对应源码。每个文件的来源与 SHA-256 写在同目录的 \`SOURCE-MANIFEST.json\`。

## 内容

- \`first-party/\`：该提交的全部已跟踪文件（${manifest.counts.first_party} 个），逐字节取自 git blob。包括桌面宿主、页面、Rust 控制端、改造后的 service-ipc（\`apps/desktop-host/vendor/service-ipc\`）、发布与安装脚本（\`tools/release\`、NSIS 钩子）、GitHub Actions 工作流与四份 \`Cargo.lock\`。
- \`${MIHOMO_ENTRY}\`：${manifest.mihomo.repository} 标签 ${manifest.mihomo.tag}、提交 \`${manifest.mihomo.commit}\` 的官方源码 ZIP（${manifest.mihomo.bytes} 字节，SHA-256 \`${manifest.mihomo.sha256}\`，取自 ${manifest.mihomo.url}）。
- \`third-party/rust/crates/\`：三份产品 \`Cargo.lock\` 里全部 crates.io 包的原始 \`.crate\`（${manifest.counts.crates} 个），SHA-256 等于锁里的 \`checksum\`。
- \`third-party/go/\`：Mihomo \`go.sum\` 列出的模块 zip（${manifest.counts.go_zips} 个）与 \`go.mod\`（${manifest.counts.go_mods} 个），按 GOPROXY 目录布局存放，哈希等于 \`go.sum\` 的 \`h1\`。

四份锁：

${locks}

## 构建本项目程序

构建机器是 GitHub Actions \`${tool.runner}\`，工具版本为 Rust \`${tool.rust}\`、tauri-cli \`${tool.tauri_cli}\`、cargo-about \`${tool.cargo_about}\`、Node ${tool.node}、${tool.powershell}。完整流程见 \`first-party/.github/workflows/e54-windows-release.yml\` 的 build 模式与 \`first-party/tools/release/build-release.ps1\`：

1. 取得 \`first-party/\` 的内容作为仓库根目录。
2. 所有 cargo 命令都带 \`--locked\`，按入库锁构建：\`powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\\release\\build-release.ps1\`。它依次编译控制端与网络服务、检查发布输入、装配，再运行 \`cargo tauri build --features tauri -- --locked\`。
3. 联网构建时，cargo 下载到的 crate 与 \`third-party/rust/crates/\` 里的文件逐字节相同（校验和在 \`Cargo.lock\`）。离线构建时，把这些 \`.crate\` 解包成 cargo 的 directory source 或 local registry 使用；这条离线路径没有在本项目验证过。

## Mihomo

安装包里的 \`service/core/mihomo-windows-amd64-v1.19.30.exe\` 是官方发布程序，SHA-256 \`${manifest.mihomo_binary.sha256}\`。对应源码是上面的官方源码 ZIP；上游的构建方法在它的 \`Makefile\` 与 \`.github/workflows\` 里。Go 依赖可以离线使用，例如 \`GOPROXY=file:///<解压目录>/third-party/go GOSUMDB=off GOFLAGS=-mod=mod go build\`。这条离线路径也没有在本项目验证过。

## 复核

\`node first-party/tools/release/e54/corresponding-source.mjs verify <本 ZIP>\` 会逐项核对来源与哈希：首方文件对 git blob 编号，crate 对锁的 checksum，Go 文件对 go.sum，Mihomo 对已记录的 SHA-256。如果还有该提交的仓库，再加 \`--repo <仓库>\`，就会同时核对首方文件是否齐全。

## 未随附

${manifest.not_included.map((entry) => `- ${entry.item}：${entry.reason}`).join('\n')}
`;
}

export async function build({repo, rev, out, cache, offline}) {
  const {commit, files} = commitFiles(repo, rev);
  const releaseInputs = JSON.parse(files.find((file) => file.path === 'tools/release/release-inputs.json').bytes.toString('utf8'));
  const locks = lockRecords(files, releaseInputs);
  const crates = rustCrates(PRODUCT_LOCKS.map((lock) => [lock, files.find((file) => file.path === lock).bytes.toString('utf8')]));
  const mihomoZip = await fetchVerified({url: MIHOMO.url, cacheFile: path.join(cache, 'mihomo', `source-${MIHOMO.commit}.zip`), check: verifyMihomo, offline});
  const mihomoFiles = zipFiles(mihomoZip);
  const goSumFile = mihomoFiles.find((file) => /^[^/]+\/go\.sum$/.test(file.name));
  if (!goSumFile) throw new Error('the Mihomo source archive has no top-level go.sum');
  const sums = goSum(goSumFile.bytes.toString('utf8'));
  const third = [];
  third.push(...await pool(crates, 6, async (crate) => {
    const bytes = await fetchVerified({url: `https://static.crates.io/crates/${crate.name}/${crate.name}-${crate.version}.crate`, cacheFile: path.join(cache, ...crateEntry(crate).split('/').slice(1)), check: verifyCrate(crate), offline});
    return {path: crateEntry(crate), bytes: bytes.length, sha256: sha256(bytes), file: path.join(cache, ...crateEntry(crate).split('/').slice(1)), origin: {kind: 'crates.io', crate: crate.name, version: crate.version, lock_checksum: crate.checksum, locks: crate.locks}};
  }));
  const goItems = [...sums.zips.map((item) => ({...item, ext: 'zip'})), ...sums.mods.map((item) => ({...item, ext: 'mod'}))];
  third.push(...await pool(goItems, 6, async (item) => {
    const entry = goEntry(item.module, item.version, item.ext);
    const cacheFile = path.join(cache, ...entry.split('/').slice(1));
    const bytes = await fetchVerified({url: `https://proxy.golang.org/${escapeGo(item.module)}/@v/${escapeGo(item.version)}.${item.ext}`, cacheFile, check: item.ext === 'zip' ? verifyGoZip(item) : verifyGoMod(item), offline});
    return {path: entry, bytes: bytes.length, sha256: sha256(bytes), file: cacheFile, origin: {kind: item.ext === 'zip' ? 'go-module-zip' : 'go-mod', module: item.module, version: item.version, go_sum: item.hash}};
  }));
  const mihomoItem = releaseInputs.items.find((item) => item.id === 'mihomo');
  const entries = [
    ...files.map((file) => ({path: `first-party/${file.path}`, bytes: file.bytes.length, sha256: sha256(file.bytes), data: file.bytes, origin: {kind: 'git-blob', blob: file.blob}})),
    {path: MIHOMO_ENTRY, bytes: mihomoZip.length, sha256: sha256(mihomoZip), data: mihomoZip, origin: {kind: 'mihomo-source', url: MIHOMO.url, commit: MIHOMO.commit}},
    ...third,
  ].sort((a, b) => byBytes(a.path, b.path));
  const manifest = {
    schema: 'steward-e54-corresponding-source-1',
    mirror_commit: commit,
    mihomo: {...MIHOMO},
    mihomo_binary: {target: mihomoItem.target, sha256: mihomoItem.sha256},
    locks,
    toolchain: workflowToolchain(files),
    counts: {first_party: files.length, crates: crates.length, go_zips: sums.zips.length, go_mods: sums.mods.length},
    not_included: NOT_INCLUDED,
    entries: null,
  };
  const markdown = Buffer.from(buildMarkdown(manifest), 'utf8');
  entries.push({path: 'BUILD.md', bytes: markdown.length, sha256: sha256(markdown), data: markdown, origin: {kind: 'generated', from: 'SOURCE-MANIFEST.json'}});
  entries.sort((a, b) => byBytes(a.path, b.path));
  manifest.entries = entries.map(({path: entryPath, bytes, sha256: digest, origin}) => ({path: entryPath, bytes, sha256: digest, origin}));
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 1)}\n`, 'utf8');
  mkdirSync(out, {recursive: true});
  const target = path.join(out, ARCHIVE_NAME);
  const partial = `${target}.partial-${process.pid}`;
  rmSync(partial, {force: true});
  try {
    writeZip(partial, [
      ...entries.map((entry) => ({name: `${ROOT}/${entry.path}`, read: () => entry.data || readFileSync(entry.file)})),
      {name: `${ROOT}/SOURCE-MANIFEST.json`, read: () => manifestBytes},
    ].sort((a, b) => byBytes(a.name, b.name)));
    renameSync(partial, target);
  } finally {
    rmSync(partial, {force: true});
  }
  const archive = readFileSync(target);
  const record = {
    schema: 'steward-e54-corresponding-source-record-1',
    archive: {name: ARCHIVE_NAME, bytes: archive.length, sha256: sha256(archive)},
    manifest_sha256: sha256(manifestBytes),
    mirror_commit: commit,
    mihomo_commit: MIHOMO.commit,
    locks,
    counts: {...manifest.counts, entries: entries.length + 1},
    not_included: NOT_INCLUDED,
    generated_utc: new Date().toISOString(),
  };
  writeFileSync(path.join(out, RECORD_NAME), `${JSON.stringify(record, null, 1)}\n`);
  return record;
}

export function verify({zipPath, repo = null, rev = null}) {
  const problems = [];
  const problem = (code, detail) => problems.push(`${code} ${detail}`);
  const zip = readZip(readFileSync(zipPath));
  const byName = new Map();
  for (const entry of zip.entries) {
    if (!entry.name.startsWith(`${ROOT}/`) || entry.name.endsWith('/')) problem('UNEXPECTED_ENTRY', entry.name);
    if (byName.has(entry.name)) problem('DUPLICATE_ENTRY', entry.name);
    byName.set(entry.name, entry);
  }
  const manifestEntry = byName.get(`${ROOT}/SOURCE-MANIFEST.json`);
  if (!manifestEntry) return {ok: false, problems: ['MISSING_MANIFEST SOURCE-MANIFEST.json']};
  const manifest = JSON.parse(zip.data(manifestEntry).toString('utf8'));
  const content = new Map();
  const listed = new Map(manifest.entries.map((entry) => [entry.path, entry]));
  for (const entry of manifest.entries) {
    const zipped = byName.get(`${ROOT}/${entry.path}`);
    if (!zipped) { problem('MISSING', entry.path); continue; }
    const bytes = zip.data(zipped);
    content.set(entry.path, bytes);
    if (bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) problem('HASH_MISMATCH', entry.path);
  }
  for (const name of byName.keys()) {
    const relative = name.slice(ROOT.length + 1);
    if (relative !== 'SOURCE-MANIFEST.json' && !listed.has(relative)) problem('UNLISTED', relative);
  }
  const firstParty = manifest.entries.filter((entry) => entry.path.startsWith('first-party/'));
  for (const entry of firstParty) {
    const bytes = content.get(entry.path);
    if (entry.origin?.kind !== 'git-blob') problem('UNKNOWN_ORIGIN', entry.path);
    else if (bytes && gitBlobId(bytes) !== entry.origin.blob) problem('BLOB_MISMATCH', entry.path);
  }
  const firstPartyFile = (relative) => content.get(`first-party/${relative}`);
  for (const lock of manifest.locks) {
    const bytes = firstPartyFile(lock.path);
    if (!bytes || sha256(bytes) !== lock.sha256 || bytes.length !== lock.bytes) problem('LOCK_RECORD', lock.path);
  }
  const inputsBytes = firstPartyFile('tools/release/release-inputs.json');
  if (!inputsBytes) problem('MISSING', 'first-party/tools/release/release-inputs.json');
  else {
    const releaseInputs = JSON.parse(inputsBytes.toString('utf8'));
    for (const lock of PRODUCT_LOCKS) {
      const expected = releaseInputs.items.find((item) => item.source === lock)?.sha256;
      if (manifest.locks.find((entry) => entry.path === lock)?.sha256 !== expected) problem('LOCK_BASELINE', lock);
    }
    if (manifest.mihomo_binary?.sha256 !== releaseInputs.items.find((item) => item.id === 'mihomo')?.sha256) problem('MIHOMO_BINARY', 'release-inputs.json');
  }
  if (manifest.locks.find((entry) => entry.path === WARMUP_LOCK.source)?.sha256 !== WARMUP_LOCK.sha256) problem('LOCK_BASELINE', WARMUP_LOCK.source);
  if (manifest.locks.length !== 4) problem('LOCK_COUNT', String(manifest.locks.length));
  const locksText = PRODUCT_LOCKS.map((lock) => [lock, (firstPartyFile(lock) || Buffer.alloc(0)).toString('utf8')]);
  let crates = [];
  try { crates = rustCrates(locksText); } catch (error) { problem('LOCK_PARSE', error.message); }
  const expectedThird = new Map();
  for (const crate of crates) expectedThird.set(crateEntry(crate), {check: verifyCrate(crate), kind: 'crates.io'});
  if (JSON.stringify(manifest.mihomo) !== JSON.stringify({...MIHOMO})) problem('MIHOMO_RECORD', 'manifest.mihomo');
  const mihomoZip = content.get(MIHOMO_ENTRY);
  if (!mihomoZip) problem('MISSING', MIHOMO_ENTRY);
  else if (verifyMihomo(mihomoZip)) problem('MIHOMO_SOURCE', verifyMihomo(mihomoZip));
  else {
    const goSumFile = zipFiles(mihomoZip).find((file) => /^[^/]+\/go\.sum$/.test(file.name));
    const sums = goSum(goSumFile.bytes.toString('utf8'));
    for (const item of sums.zips) expectedThird.set(goEntry(item.module, item.version, 'zip'), {check: verifyGoZip(item), kind: 'go-module-zip'});
    for (const item of sums.mods) expectedThird.set(goEntry(item.module, item.version, 'mod'), {check: verifyGoMod(item), kind: 'go-mod'});
    if (manifest.counts.go_zips !== sums.zips.length || manifest.counts.go_mods !== sums.mods.length) problem('COUNTS', 'go');
  }
  if (manifest.counts.crates !== crates.length || manifest.counts.first_party !== firstParty.length) problem('COUNTS', 'crates/first-party');
  for (const entry of manifest.entries.filter((item) => item.path.startsWith('third-party/') && item.path !== MIHOMO_ENTRY)) {
    const expected = expectedThird.get(entry.path);
    if (!expected) { problem('UNKNOWN_ORIGIN', entry.path); continue; }
    if (entry.origin?.kind !== expected.kind) problem('ORIGIN_KIND', entry.path);
    const bytes = content.get(entry.path);
    if (bytes) {
      let failure = null;
      try { failure = expected.check(bytes); } catch (error) { failure = error.message; }
      if (failure) problem('SOURCE_MISMATCH', `${entry.path}: ${failure}`);
    }
    expectedThird.delete(entry.path);
  }
  for (const missing of expectedThird.keys()) problem('MISSING', missing);
  for (const entry of manifest.entries.filter((item) => !item.path.startsWith('first-party/') && !item.path.startsWith('third-party/') && item.path !== 'BUILD.md')) problem('UNKNOWN_ORIGIN', entry.path);
  const markdown = content.get('BUILD.md');
  if (!markdown || markdown.toString('utf8') !== buildMarkdown(manifest)) problem('BUILD_MD', 'BUILD.md does not match the manifest');
  if (repo) {
    const {commit, files} = commitFiles(repo, rev || manifest.mirror_commit);
    if (commit !== manifest.mirror_commit) problem('COMMIT', `${commit} is not ${manifest.mirror_commit}`);
    const archived = new Set(firstParty.map((entry) => entry.path.slice('first-party/'.length)));
    for (const file of files) {
      const bytes = firstPartyFile(file.path);
      if (!bytes) problem('MISSING', `first-party/${file.path}`);
      else if (Buffer.compare(bytes, file.bytes) !== 0) problem('COMMIT_MISMATCH', `first-party/${file.path}`);
      archived.delete(file.path);
    }
    for (const extra of archived) problem('NOT_IN_COMMIT', `first-party/${extra}`);
  }
  return {ok: problems.length === 0, problems, mirror_commit: manifest.mirror_commit, entries: zip.entries.length};
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [command, ...rest] = process.argv.slice(2);
  const option = (name) => { const index = rest.indexOf(`--${name}`); return index >= 0 ? rest[index + 1] : null; };
  const defaultRepo = path.resolve(fileURLToPath(new URL('../../..', import.meta.url)));
  try {
    if (command === 'build') {
      const record = await build({repo: path.resolve(option('repo') || defaultRepo), rev: option('commit') || 'HEAD', out: path.resolve(option('out') || 'build/source'), cache: path.resolve(option('cache') || 'build/source-cache'), offline: rest.includes('--offline') || process.env.E54_SOURCE_OFFLINE === '1'});
      console.log(`source.build PASS ${record.archive.name} bytes=${record.archive.bytes} sha256=${record.archive.sha256} commit=${record.mirror_commit} entries=${record.counts.entries}`);
    } else if (command === 'verify' && rest[0] && !rest[0].startsWith('--')) {
      const result = verify({zipPath: path.resolve(rest[0]), repo: option('repo') ? path.resolve(option('repo')) : null, rev: option('commit')});
      for (const line of result.problems) console.log(`source.verify ${line}`);
      console.log(`source.verify ${result.ok ? 'PASS' : 'FAIL'} entries=${result.entries} commit=${result.mirror_commit} problems=${result.problems.length}`);
      process.exit(result.ok ? 0 : 1);
    } else {
      console.error('usage: corresponding-source.mjs build --commit <rev> --out <dir> --cache <dir> [--repo <dir>] [--offline] | verify <zip> [--repo <dir> [--commit <rev>]]');
      process.exit(64);
    }
  } catch (error) {
    console.log(`source.build FAIL ${error.message}`);
    process.exit(1);
  }
}
