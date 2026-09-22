import {spawnSync} from 'node:child_process';

const [command] = process.argv.slice(2);
if (command !== 'test') throw new Error('usage: node tests/delivery/run-acceptance.mjs test');

const env = {};
for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key];

const result = spawnSync(process.execPath, [
  '--experimental-vm-modules',
  '--test',
  'tests/delivery/x01-x05.test.mjs',
  'tests/delivery/x06-x11.test.mjs',
  'tests/delivery/x12-x16.test.mjs',
  'tests/delivery/x17-x20.test.mjs',
  'tests/delivery/gaps.test.mjs',
  'tests/delivery/platform.test.mjs',
  'tests/delivery/native-chain.test.mjs',
  'tests/delivery/authorized-roots.test.mjs',
  'tests/delivery/audit-runtime.test.mjs',
  'tests/delivery/release-candidate.test.mjs',
  'tests/delivery/rust-sources.test.mjs',
  'tests/delivery/transient-root.test.mjs',
], {cwd: process.cwd(), env, stdio: 'inherit'});

if (result.error) throw result.error;
process.exit(result.status ?? 1);
