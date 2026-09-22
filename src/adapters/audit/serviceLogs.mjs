import {decodeBytes} from '../local/bridgeWorkspace.mjs';

/** 归档来源：产品网络服务的内核日志。活动文件 core.log，轮转后的 core.1.log 可能还不存在。 */
export const SERVICE_LOG_ROOT = 'service-logs';
export const CORE_LOG_NAMES = Object.freeze(['core.log', 'core.1.log']);
export const CORE_LOG_REQUEST = Object.freeze({
  sourceRoot: SERVICE_LOG_ROOT,
  approvedSourceNames: [...CORE_LOG_NAMES],
  latestSourceNames: ['core.log'],
  optionalSourceNames: ['core.1.log'],
});

async function safeInvoke(invoke, op, payload) {
  try {
    const result = await invoke(op, payload, null);
    return result && typeof result === 'object' ? result : {ok: false, code: 'NATIVE_RESULT_INVALID'};
  } catch (error) {
    const text = String(error?.message ?? error);
    return {ok: false, code: error?.code || /^([A-Z][A-Z0-9_]+):/.exec(text)?.[1] || 'NATIVE_CALL_FAILED', reason: text};
  }
}

/**
 * 只读：经宿主的 LogSources / LogRead 取文件，页面给不了路径。
 * 目录读不到、文件读不到都如实回成 unreadable / not_found，由归档记缺口，不合成内容。
 */
export function createServiceLogSource({invoke}) {
  if (typeof invoke !== 'function') throw new Error('BRIDGE_REQUIRED: native bridge invoke is required');
  return {
    async listFiles() {
      const listed = await safeInvoke(invoke, 'LogSources', {});
      if (listed.ok !== true) {
        return CORE_LOG_NAMES.map((name) => ({path: `${SERVICE_LOG_ROOT}/${name}`, status: 'unreadable', reason: listed.code || 'LOG_SOURCES_UNAVAILABLE'}));
      }
      const directory = (listed.directories || []).find((item) => item.category === 'network_core');
      if (directory && directory.status !== 'found') {
        const status = directory.status === 'missing' ? 'not_found' : 'unreadable';
        return CORE_LOG_NAMES.map((name) => ({path: `${SERVICE_LOG_ROOT}/${name}`, status, reason: directory.reason || directory.status}));
      }
      const present = new Set((listed.sources || []).filter((item) => item.category === 'network_core').map((item) => item.name));
      const files = [];
      for (const name of CORE_LOG_NAMES) {
        const path = `${SERVICE_LOG_ROOT}/${name}`;
        if (!present.has(name)) {
          files.push({path, status: 'not_found'});
          continue;
        }
        const read = await safeInvoke(invoke, 'LogRead', {source_ref: `network_core/${name}`});
        if (read.ok === true) files.push({path, status: 'found', bytes: decodeBytes(read.bytes), modifiedAt: read.modified_at || null});
        else if (read.code === 'LOG_SOURCE_NOT_FOUND') files.push({path, status: 'not_found'});
        else files.push({path, status: 'unreadable', reason: read.code || 'LOG_SOURCE_UNREADABLE'});
      }
      return files;
    },
  };
}
