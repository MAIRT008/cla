import {spawnSync} from 'node:child_process';

const [command] = process.argv.slice(2);
if (command !== 'test') throw new Error('usage: node tests/network/run-synthetic.mjs test');
const env = {};
for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key];
const result = spawnSync(process.execPath, ['--test', 'tests/network/assignment.test.mjs', 'tests/network/whitelist.test.mjs', 'tests/network/apply.test.mjs', 'tests/network/lifecycle.test.mjs', 'tests/network/quota.test.mjs', 'tests/network/protection.test.mjs', 'tests/network/emergency.test.mjs', 'tests/network/protocol.test.mjs', 'tests/network/security.test.mjs', 'tests/network/control-api.test.mjs', 'tests/network/rc3-runtime.test.mjs', 'tests/network/loopback-endpoints.test.mjs'], {cwd: process.cwd(), env, stdio: 'inherit'});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
