import {spawnSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import path from 'node:path';
import {assertTransient, transientSuiteRoot} from '../../fixtures/transientRoot.mjs';
import {fileURLToPath} from 'node:url';

const [command, ...rest] = process.argv.slice(2);
const allowed = new Set(['test', 'demo']);
if (!allowed.has(command)) throw new Error('usage: node tests/ai/run-synthetic.mjs test | demo <command> --workspace fixtures/_transient/ai/runs/<name>');
if (command === 'demo') {
  const index = rest.indexOf('--workspace');
  const workspace = index >= 0 ? rest[index + 1] : null;
  if (!workspace) throw new Error(`usage: node tests/ai/run-synthetic.mjs demo <action> --workspace ${transientSuiteRoot('ai')}/<name>`);
  assertTransient(workspace, {suite: 'ai'});
  if (rest[0] === 'init' && existsSync(workspace)) throw new Error('demo init 需要一个尚不存在的工作区目录');
}
const env = {};
for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key];
const node = process.execPath;
const target = command === 'test' ? ['--test', 'tests/ai/aiSynthetic.test.mjs', 'tests/ai/networkT5.test.mjs'] : ['tests/ai/demo.mjs', ...rest];
const result = spawnSync(node, target, {cwd: process.cwd(), env, stdio: 'inherit'});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
