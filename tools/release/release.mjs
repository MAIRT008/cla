import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {assembleRelease, checkRelease, loadReleaseInputs} from './assemble.mjs';

/**
 * 发布工具入口（构建机）：
 *   node tools/release/release.mjs check     [--root <仓库根>] [--inputs <清单>]            READY 退出 0，NOT_READY 退出 2
 *   node tools/release/release.mjs assemble  [--root <仓库根>] [--inputs <清单>] [--out <目录>]  成功退出 0，失败退出 1
 *   node tools/release/release.mjs readiness [--write <文件>]    生成机器可读发布就绪清单
 * 所有输出是 JSON，打印到标准输出。
 */
const [command, ...rest] = process.argv.slice(2);
const option = (name, fallback) => {
  const index = rest.indexOf(`--${name}`);
  return index >= 0 ? rest[index + 1] : fallback;
};
const root = path.resolve(option('root', process.cwd()));
const inputs = await loadReleaseInputs(root, option('inputs', 'tools/release/release-inputs.json'));
const print = (value) => process.stdout.write(`${JSON.stringify(value, null, 1)}\n`);

function controlRoutes() {
  const router = readFileSync(path.join(root, 'services/control-rs/src/router.rs'), 'utf8');
  const table = router.match(/pub const ROUTES:[\s\S]*?= &\[([\s\S]*?)\n\];/)?.[1] || '';
  return [...table.matchAll(/\("(GET|POST|PUT)",\s*"([^"\n]+)"\)/g)].map((match) => `${match[1]} ${match[2]}`);
}

async function readiness() {
  const {OPS} = await import(pathToFileURL(path.join(root, 'apps/desktop-host/bridge-contract.mjs')).href);
  const chain = JSON.parse(readFileSync(path.join(root, 'tools/release/call-chain.json'), 'utf8'));
  const problems = [];
  const has = (file, text) => existsSync(path.join(root, file)) && readFileSync(path.join(root, file), 'utf8').includes(text);
  for (const segment of chain.segments) {
    for (const hop of segment.hops) {
      for (const end of [hop.caller, hop.callee]) if (!has(end.file, end.symbol)) problems.push(`${segment.id}: ${end.file} has no ${end.symbol}`);
    }
    for (const [file, name] of segment.offline_evidence) if (!has(file, name)) problems.push(`${segment.id}: ${file} has no test ${name}`);
  }
  if (problems.length) throw new Error(`call chain references are stale:\n${problems.join('\n')}`);
  const routes = controlRoutes();
  const check = await checkRelease({root, inputs});
  return {
    schema: 'steward-release-readiness-1',
    generated_on: 'offline development machine: no Rust toolchain, no built binaries, nothing installed or executed',
    check: {status: check.status, items: check.items.map(({id, class: kind, status, reasons}) => ({id, class: kind, status, reasons})), tools: check.tools, frontend: {status: check.frontend.status, modules: check.frontend.files.length}},
    bridge_ops: {count: Object.keys(OPS).length, ops: Object.keys(OPS)},
    control_routes: {count: routes.length, routes},
    segments: chain.segments,
  };
}

if (command === 'check') {
  const report = await checkRelease({root, inputs});
  print(report);
  process.exit(report.status === 'READY' ? 0 : 2);
} else if (command === 'assemble') {
  const out = path.resolve(root, option('out', inputs.staging_root || 'build/release-staging'));
  const result = await assembleRelease({root, inputs, out});
  print(result.ok ? {ok: true, out: path.relative(root, out).split(path.sep).join('/'), items: result.manifest.items.length, frontend: result.manifest.frontend.files.length} : result);
  process.exit(result.ok ? 0 : 1);
} else if (command === 'readiness') {
  const report = await readiness();
  const target = option('write', null);
  if (target) writeFileSync(path.resolve(root, target), `${JSON.stringify(report, null, 1)}\n`);
  else print(report);
} else {
  process.stderr.write('usage: node tools/release/release.mjs check|assemble|readiness [options]\n');
  process.exit(64);
}
