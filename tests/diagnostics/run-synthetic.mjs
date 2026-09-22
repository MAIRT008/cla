import {spawnSync} from 'node:child_process';

const [command] = process.argv.slice(2);
if (command !== 'test') throw new Error('usage: node tests/diagnostics/run-synthetic.mjs test');
const env = {};
for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key];
const result = spawnSync(process.execPath, ['--test', 'tests/diagnostics/scan.test.mjs', 'tests/diagnostics/score.test.mjs', 'tests/diagnostics/session.test.mjs', 'tests/diagnostics/plan.test.mjs', 'tests/diagnostics/a-scenarios.test.mjs', 'tests/diagnostics/review-fix.test.mjs'], {cwd: process.cwd(), env, stdio: 'inherit'});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
