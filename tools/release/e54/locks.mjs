import {createHash} from 'node:crypto';
import {appendFileSync, existsSync, mkdirSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {loadReleaseInputs} from '../assemble.mjs';

/**
 * E54 四份入库 Cargo.lock 的基线核对（只读、不联网；从不生成、改写或恢复锁）。
 *   node tools/release/e54/locks.mjs <阶段>    四份都在且等于批准基线退出 0，否则退出 1；每次向 build/logs/e54-locks.jsonl 追加一条记录
 *
 * - 三份产品锁的基线就是 tools/release/release-inputs.json 里 build_input 锁项的 sha256，不另存一份。
 * - 预热锁只属于镜像的 NSIS 预热工程，基线只在这里固定（2026-09-27 第四次 pin 裁决，取第二、三次 pin 相同的预热锁）。
 * - 缺失或漂移只记实际字节数与哈希并失败；不把新值当基线，也不把文件改回去。
 */
export const WARMUP_LOCK = Object.freeze({id: 'lock-nsis-warmup', source: 'tools/release/nsis-warmup/Cargo.lock', sha256: 'd15333f23352e84eb8f303035e6f843e6e40f3733908dbf11d8d0629770382d5'});

export function lockBaseline(inputs) {
  const product = inputs.items.filter((item) => item.class === 'build_input' && item.source.endsWith('/Cargo.lock'));
  return [...product.map(({id, source, sha256}) => ({id, source, sha256: sha256 || null})), {...WARMUP_LOCK}];
}

export function checkLocks(root, baseline) {
  return baseline.map((lock) => {
    const file = path.join(root, ...lock.source.split('/'));
    if (!lock.sha256) return {...lock, status: 'LOCK_UNPINNED', bytes: null, actual: null};
    if (!existsSync(file)) return {...lock, status: 'LOCK_MISSING', bytes: null, actual: null};
    const bytes = readFileSync(file);
    const actual = createHash('sha256').update(bytes).digest('hex');
    return {...lock, status: actual === lock.sha256 ? 'OK' : 'LOCK_CHANGED', bytes: bytes.length, actual};
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const stage = process.argv[2];
  if (!stage) {
    process.stderr.write('usage: node tools/release/e54/locks.mjs <stage>\n');
    process.exit(64);
  }
  const root = path.resolve(fileURLToPath(new URL('../../..', import.meta.url)));
  const locks = checkLocks(root, lockBaseline(await loadReleaseInputs(root)));
  const status = locks.length === 4 && locks.every((lock) => lock.status === 'OK') ? 'PASS' : 'FAIL';
  for (const lock of locks) console.log(`locks.${stage} ${lock.status} ${lock.source} expected=${lock.sha256} actual=${lock.actual} bytes=${lock.bytes}`);
  console.log(`locks.${stage} result ${status} count=${locks.length}`);
  const logs = path.join(root, 'build', 'logs');
  mkdirSync(logs, {recursive: true});
  appendFileSync(path.join(logs, 'e54-locks.jsonl'), `${JSON.stringify({schema: 'steward-e54-locks-1', stage, utc: new Date().toISOString(), status, locks})}\n`);
  process.exit(status === 'PASS' ? 0 : 1);
}
