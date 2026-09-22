import {spawnSync} from 'node:child_process';

const [command] = process.argv.slice(2);
if (command !== 'test') throw new Error('usage: node tests/control/run-synthetic.mjs test');
const env = {};
for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key];
const result = spawnSync(process.execPath, ['--test', 'tests/control/resources.test.mjs', 'tests/control/quota.test.mjs', 'tests/control/protocol.test.mjs', 'tests/control/events.test.mjs', 'tests/control/review-fix.test.mjs'], {cwd: process.cwd(), env, stdio: 'inherit'});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
