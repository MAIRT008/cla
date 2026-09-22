import {spawnSync} from 'node:child_process';

const [command] = process.argv.slice(2);
if (command !== 'test') throw new Error('usage: node tests/control-runtime/run-synthetic.mjs test');
const env = {};
for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key];
const result = spawnSync(process.execPath, [
  '--experimental-vm-modules',
  '--test',
  'tests/control-runtime/login-flow.test.mjs',
  'tests/control-runtime/contract.test.mjs',
  'tests/control-runtime/admin-journey.test.mjs',
], {cwd: process.cwd(), env, stdio: 'inherit'});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
