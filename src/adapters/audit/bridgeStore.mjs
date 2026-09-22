import {OPS} from '../../../apps/desktop-host/bridge-contract.mjs';
import {decodeBytes, encodeBytes} from '../local/bridgeWorkspace.mjs';
import {sha256Hex} from '../platform/index.mjs';

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function join(root, relativePath) {
  return `${root}/${String(relativePath).replaceAll('\\', '/').replace(/^\.\//, '')}`.replace(/\/+/g, '/');
}

/** 正式桌面上的审计产物存储：与 FixtureAuditStore 同接口，字节全部经受限原生桥。 */
export function createBridgeAuditStore({
  invoke,
  confirm,
  root = 'audit',
  clock = () => new Date().toISOString(),
  sessionValidityMs = 12 * 60 * 60 * 1000,
} = {}) {
  if (typeof invoke !== 'function') throw new Error('BRIDGE_REQUIRED: native bridge invoke is required');
  if (typeof confirm !== 'function') throw new Error('CONFIRMATION_REQUIRED: the native user-confirmation channel is required');

  let issued = null;

  /** 审计产物都在应用自有目录下，按首次范围授权走，不冒用单次确认。 */
  async function referenceFor(op) {
    if (!OPS[op]?.authorization) return null;
    if (issued && Date.parse(issued.expires_at) > Date.parse(clock())) return issued.authorization_ref;
    const result = await confirm({
      scope: 'workspace_owned',
      reuse: true,
      validity_ms: sessionValidityMs,
      summary: '允许本应用写入自己的审计归档与日报产物。',
    });
    if (!result?.authorization_ref) {
      throw Object.assign(new Error(result?.reason || 'the host did not issue an authorization'), {code: result?.code || 'NATIVE_CONFIRMATION_DECLINED'});
    }
    issued = result;
    return issued.authorization_ref;
  }

  async function call(op, payload) {
    const result = await invoke(op, payload, await referenceFor(op));
    if (result && result.ok === false) {
      throw Object.assign(new Error(result.reason || `native op ${op} failed`), {code: result.code});
    }
    return result;
  }

  return {
    root,
    async exists(relativePath) {
      return (await call('FileExists', {path: join(root, relativePath)})).exists === true;
    },
    async readBytes(relativePath) {
      return decodeBytes((await call('FileRead', {path: join(root, relativePath)})).bytes);
    },
    async readText(relativePath) {
      return decoder.decode(await this.readBytes(relativePath));
    },
    async writeBytes(relativePath, bytes, {overwrite = false} = {}) {
      const target = join(root, relativePath);
      if (!overwrite && (await call('FileExists', {path: target})).exists === true) {
        throw Object.assign(new Error('audit record exists'), {code: 'EEXIST'});
      }
      await call('FileWrite', {path: target, bytes: encodeBytes(bytes)});
    },
    async writeText(relativePath, text, options) {
      await this.writeBytes(relativePath, encoder.encode(String(text)), options);
    },
    /** 只经 FileWalk 列路径，不逐个 FileRead；归档索引与窗口回放按需再读。 */
    async listPaths(relativeRoot = '') {
      const walked = await call('FileWalk', {prefixes: [join(root, relativeRoot)]});
      return (walked.entries || [])
        .filter((item) => item.status === 'found')
        .sort((left, right) => left.relative_path.localeCompare(right.relative_path))
        .map((entry) => ({path: entry.relative_path.slice(root.length + 1), size: entry.size ?? null}));
    },
    async listFiles(relativeRoot = '') {
      const prefix = join(root, relativeRoot);
      const walked = await call('FileWalk', {prefixes: [prefix]});
      const files = (walked.entries || [])
        .filter((item) => item.status === 'found')
        .sort((left, right) => left.relative_path.localeCompare(right.relative_path));
      const found = [];
      for (const entry of files) {
        found.push({
          path: entry.relative_path.slice(root.length + 1),
          bytes: decodeBytes((await call('FileRead', {path: entry.relative_path})).bytes),
        });
      }
      return found;
    },
    async sha256(bytes) {
      return sha256Hex(bytes);
    },
  };
}
