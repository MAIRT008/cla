import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import {readdir, readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {
  HISTORICAL_EVIDENCE_SUITES,
  TRANSIENT_ROOT,
  assertTransient,
  transientRun,
  transientSuiteRoot,
} from '../../fixtures/transientRoot.mjs';

/**
 * Owner 裁决：`fixtures/{ai,local,diagnostics,network}/runs/` 保留为只读历史证据
 * （evidence/ 下 21 份交接共 76 处路径引用指向它们），一次性产物一律改道 `fixtures/_transient/`。
 * 这组用例守住这条约束，防止新写的测试又把产物落回历史目录。
 */

const CODE_ROOTS = ['apps', 'examples', 'fixtures', 'services', 'src', 'tests', 'tools', 'evidence'];

async function collectScripts(directory, found = []) {
  let entries;
  try {
    entries = await readdir(directory, {withFileTypes: true});
  } catch {
    return found;
  }
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'runs' || entry.name === '_transient' || entry.name === 'target') continue;
      await collectScripts(full, found);
    } else if (entry.name.endsWith('.mjs') || entry.name.endsWith('.js')) {
      found.push(full);
    }
  }
  return found;
}

test('没有任何脚本再往历史证据目录写产物', async () => {
  const offenders = [];
  const pattern = new RegExp(`fixtures/(${HISTORICAL_EVIDENCE_SUITES.join('|')}|ui|control|delivery)/runs`);
  for (const root of CODE_ROOTS) {
    for (const file of await collectScripts(path.resolve(root))) {
      if (path.basename(file) === 'transientRoot.mjs') continue;
      const source = await readFile(file, 'utf8');
      for (const [index, lineText] of source.split('\n').entries()) {
        if (pattern.test(lineText) && !lineText.includes('_transient')) {
          offenders.push(`${path.relative(process.cwd(), file)}:${index + 1}  ${lineText.trim()}`);
        }
      }
    }
  }
  assert.deepEqual(offenders, [], `这些行仍指向历史证据目录：\n${offenders.join('\n')}`);
});

test('一次性产物路径落在临时根之内，套件之间分开', () => {
  const run = transientRun('ui', 'demo');
  assert.ok(run.startsWith(`${TRANSIENT_ROOT}${path.sep}`), run);
  assert.ok(run.startsWith(`${transientSuiteRoot('ui')}${path.sep}`), run);
  assert.notEqual(transientRun('ui', 'demo'), transientRun('ui', 'demo'), '每次都要是新目录');
  assert.notEqual(transientSuiteRoot('ui'), transientSuiteRoot('local'), '套件之间不共用目录');
});

test('守卫挡住写回历史证据目录，也挡住写到临时根之外', () => {
  for (const suite of HISTORICAL_EVIDENCE_SUITES) {
    assert.throws(
      () => assertTransient(path.resolve('fixtures', suite, 'runs', 'whatever'), {suite}),
      (error) => error.code === 'HISTORICAL_EVIDENCE_READONLY',
      `${suite} 的历史目录必须被挡下`,
    );
  }
  assert.throws(
    () => assertTransient(path.resolve('fixtures', 'ai', 'runs'), {suite: 'ai'}),
    (error) => error.code === 'HISTORICAL_EVIDENCE_READONLY',
    '历史目录本身也算',
  );
  assert.throws(
    () => assertTransient(path.resolve('src'), {suite: 'ai'}),
    (error) => error.code === 'TRANSIENT_ROOT_REQUIRED',
    '临时根之外一律拒绝',
  );
  assert.throws(
    () => assertTransient(transientSuiteRoot('local'), {suite: 'ai'}),
    (error) => error.code === 'TRANSIENT_ROOT_REQUIRED',
    '不得跨套件写',
  );

  const allowed = transientRun('ai', 'demo');
  assert.equal(assertTransient(allowed, {suite: 'ai'}), path.resolve(allowed), '本套件内的新目录放行');
});

test('忽略规则覆盖临时根，且没有顺手忽略历史证据', async () => {
  const ignore = await readFile(path.resolve('.gitignore'), 'utf8');
  assert.ok(ignore.includes('fixtures/_transient/'), '临时根必须进忽略规则');
  for (const suite of HISTORICAL_EVIDENCE_SUITES) {
    assert.ok(!ignore.includes(`fixtures/${suite}/runs`), `历史证据目录 ${suite} 不得被忽略`);
  }
});

/** 数一个目录下的文件，目录不存在算 0。 */
async function countFiles(directory, total = 0) {
  let entries;
  try {
    entries = await readdir(directory, {withFileTypes: true});
  } catch {
    return total;
  }
  let count = total;
  for (const entry of entries) {
    count = entry.isDirectory()
      ? await countFiles(path.join(directory, entry.name), count)
      : count + 1;
  }
  return count;
}

/**
 * 守卫必须长在 demo 自己身上。
 * 外层的 run-synthetic.mjs 挡得住经它转发的调用，挡不住直接用 node 跑 demo.mjs。
 */
const DIRECT_DEMOS = [
  {suite: 'ai', script: 'tests/ai/demo.mjs'},
  {suite: 'local', script: 'tests/local/demo.mjs'},
];

for (const {suite, script} of DIRECT_DEMOS) {
  test(`直接执行 ${script} 传历史目录，写入前就退出`, async () => {
    const historical = path.resolve('fixtures', suite, 'runs');
    const target = path.join(historical, `guard-probe-${Date.now()}`);
    const before = await countFiles(historical);

    const run = spawnSync(process.execPath, [script, 'init', '--workspace', target], {
      cwd: process.cwd(),
      encoding: 'utf8',
      env: Object.fromEntries(
        ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'LOCALAPPDATA'].
          filter((key) => process.env[key]).map((key) => [key, process.env[key]]),
      ),
    });

    assert.notEqual(run.status, 0, `${script} 必须以非零退出`);
    const output = `${run.stdout || ''}${run.stderr || ''}`;
    assert.match(output, /HISTORICAL_EVIDENCE_READONLY/, output.slice(0, 400));
    assert.equal(existsSync(target), false, '被拒的工作区一个目录都不该创建');
    assert.equal(await countFiles(historical), before, '历史目录文件数必须不变');
  });

  test(`直接执行 ${script} 传临时根，正常放行`, async () => {
    const target = path.join(transientSuiteRoot(suite), `guard-allow-${Date.now()}`);
    const run = spawnSync(process.execPath, [script, 'init', '--workspace', target], {
      cwd: process.cwd(),
      encoding: 'utf8',
      env: Object.fromEntries(
        ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'LOCALAPPDATA'].
          filter((key) => process.env[key]).map((key) => [key, process.env[key]]),
      ),
    });
    assert.equal(run.status, 0, `${run.stdout || ''}${run.stderr || ''}`.slice(0, 400));
    assert.ok(existsSync(target), '放行的工作区应该被建出来');
  });
}

test('两个 demo 的守卫长在自己身上，不依赖外层运行器', async () => {
  for (const {suite, script} of DIRECT_DEMOS) {
    const source = await readFile(path.resolve(script), 'utf8');
    assert.match(source, /assertTransient\(/, `${script} 必须自己调 assertTransient`);
    assert.match(source, new RegExp(`suite: '${suite}'`), `${script} 必须点名自己的套件`);
    assert.match(source, /fixtures\/_transient\//, `${script} 的 usage 要给出正确路径`);
  }
});
