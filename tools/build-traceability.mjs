import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import path from 'node:path';
import {FD01} from './traceability/fd01.mjs';
import {FD02} from './traceability/fd02.mjs';
import {FD03} from './traceability/fd03.mjs';
import {FD04} from './traceability/fd04.mjs';

const STATUSES = new Set(['SIM_PASS', 'PARTIAL', 'IMPLEMENTED_UNTESTED', 'DEFERRED_T10', 'NOT_IMPLEMENTED']);
const MODULES = [['FD-01', FD01], ['FD-02', FD02], ['FD-03', FD03], ['FD-04', FD04]];
const OUT_DIR = 'evidence/delivery';

const fileCache = new Map();
async function textOf(file) {
  if (!fileCache.has(file)) fileCache.set(file, await readFile(path.resolve(file), 'utf8'));
  return fileCache.get(file);
}

async function checkImpl(reference, problems, key) {
  const [file, symbol] = reference.split('#');
  if (!existsSync(path.resolve(file))) {
    problems.push(`${key}: 实现文件不存在 ${file}`);
    return;
  }
  if (symbol && !(await textOf(file)).includes(symbol)) {
    problems.push(`${key}: ${file} 中找不到符号 ${symbol}`);
  }
}

async function checkEvidence(entry, problems, key) {
  const [file, testName] = entry;
  if (!existsSync(path.resolve(file))) {
    problems.push(`${key}: 证据文件不存在 ${file}`);
    return;
  }
  if (!(await textOf(file)).includes(testName)) {
    problems.push(`${key}: ${file} 中找不到用例 “${testName}”`);
  }
}

async function main() {
  const spec = JSON.parse(await readFile(path.resolve('DOCS/index/spec-index.json'), 'utf8'));
  const specByKey = new Map(spec.entries.map((item) => [item.key, item]));
  const problems = [];
  const records = [];
  const seen = new Set();

  for (const [module, rows] of MODULES) {
    for (const row of rows) {
      if (!STATUSES.has(row.status)) problems.push(`${module}: 未知状态 ${row.status}`);
      for (const id of row.ids) {
        const key = `${module}/${id}`;
        const entry = specByKey.get(key);
        if (!entry) {
          problems.push(`${key}: 原文索引里没有这个编号`);
          continue;
        }
        if (seen.has(key)) problems.push(`${key}: 重复登记`);
        seen.add(key);
        for (const reference of row.impl) await checkImpl(reference, problems, key);
        for (const item of row.evidence) await checkEvidence(item, problems, key);
        if (row.status === 'SIM_PASS' && row.evidence.length === 0) {
          problems.push(`${key}: 标为 SIM_PASS 但没有给出任何用例`);
        }
        records.push({
          key,
          module,
          id,
          kind: entry.kind,
          title: entry.title,
          spec: {path: entry.path, line: entry.line},
          implementation: row.impl,
          evidence: row.evidence.map(([file, test]) => ({file, test})),
          status: row.status,
          note: row.note || null,
        });
      }
    }
  }

  for (const entry of spec.entries) {
    if (!seen.has(entry.key)) problems.push(`${entry.key}: 没有实现映射`);
  }

  const byStatus = {};
  for (const record of records) byStatus[record.status] = (byStatus[record.status] || 0) + 1;
  const byModule = {};
  for (const record of records) {
    byModule[record.module] = byModule[record.module] || {};
    byModule[record.module][record.status] = (byModule[record.module][record.status] || 0) + 1;
  }

  if (problems.length) {
    process.stderr.write(`${problems.join('\n')}\n`);
    process.stderr.write(`映射校验失败：${problems.length} 项\n`);
    process.exit(1);
  }

  await mkdir(OUT_DIR, {recursive: true});
  const json = {
    version: spec.version,
    generated_from: 'DOCS/index/spec-index.json',
    generator: 'tools/build-traceability.mjs',
    totals: {entries: records.length, by_status: byStatus, by_module: byModule},
    records,
  };
  await writeFile(path.join(OUT_DIR, 'traceability.json'), `${JSON.stringify(json, null, 2)}\n`, 'utf8');
  await writeFile(path.join(OUT_DIR, 'traceability.md'), renderMarkdown(json), 'utf8');
  process.stdout.write(`${records.length} 条映射已生成：${JSON.stringify(byStatus)}\n`);
}

function renderMarkdown(json) {
  const lines = [];
  lines.push('# FD-01—FD-04 实现映射');
  lines.push('');
  lines.push('> 由 `node tools/build-traceability.mjs` 生成，不要手改。编号与标题来自 `DOCS/index/spec-index.json`；');
  lines.push('> 生成器会校验每条实现路径/符号与每条用例名真实存在，缺一条就构建失败。');
  lines.push('');
  lines.push('## 状态口径');
  lines.push('');
  lines.push('| 状态 | 含义 |');
  lines.push('|---|---|');
  lines.push('| `SIM_PASS` | 已实现，且有实际跑过的项目内模拟用例 |');
  lines.push('| `PARTIAL` | 已实现主要部分，注记里写明缺什么或哪部分留到 T10 |');
  lines.push('| `IMPLEMENTED_UNTESTED` | 代码在，没有对应的自动化用例 |');
  lines.push('| `DEFERRED_T10` | 需要真实环境，按 T10 清单执行 |');
  lines.push('| `NOT_IMPLEMENTED` | 本版没有实现 |');
  lines.push('');
  lines.push('生成器校验的是「引用存在」：实现路径与符号在源码里、用例名在测试文件里。它不判断该用例是否足以覆盖该条要求，');
  lines.push('所以这张表是可追溯的证据指针，不是覆盖率证明。模拟通过也不等于真实通过——真实 Profile、网络、模型、sidecar、');
  lines.push('Rust 编译与安装包实机仍为 `UNVERIFIED`。');
  lines.push('');
  lines.push('## 总计');
  lines.push('');
  lines.push(`共 ${json.totals.entries} 条：${Object.entries(json.totals.by_status).map(([key, value]) => `${key} ${value}`).join('，')}。`);
  lines.push('');
  lines.push('| 模块 | ' + Object.keys(json.totals.by_status).join(' | ') + ' |');
  lines.push('|---|' + Object.keys(json.totals.by_status).map(() => '---:').join('|') + '|');
  for (const [module, counts] of Object.entries(json.totals.by_module)) {
    lines.push(`| ${module} | ` + Object.keys(json.totals.by_status).map((status) => counts[status] || 0).join(' | ') + ' |');
  }

  for (const [module] of MODULES) {
    const rows = json.records.filter((item) => item.module === module);
    lines.push('');
    lines.push(`## ${module}`);
    for (const kind of ['rule', 'function', 'acceptance']) {
      const group = rows.filter((item) => item.kind === kind);
      if (!group.length) continue;
      lines.push('');
      lines.push(`### ${kind === 'rule' ? '规则' : kind === 'function' ? '功能' : '原验收场景'}（${group.length}）`);
      lines.push('');
      lines.push('| 编号 | 标题 | 实现 | 模拟证据 | 状态 | 说明 |');
      lines.push('|---|---|---|---|---|---|');
      for (const item of group) {
        const impl = item.implementation.map((value) => `\`${value}\``).join('<br>');
        const evidence = item.evidence.map((value) => `${value.file}<br>「${value.test}」`).join('<br>') || '—';
        lines.push(`| ${item.id} | ${item.title.replaceAll('|', '\\|')} | ${impl} | ${evidence} | ${item.status} | ${(item.note || '').replaceAll('|', '\\|')} |`);
      }
    }
  }
  lines.push('');
  return lines.join('\n');
}

await main();
