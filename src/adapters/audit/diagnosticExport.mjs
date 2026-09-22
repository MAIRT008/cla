import {redactSecrets} from '../../core/audit/redact.mjs';
import {decodeBytes, encodeBytes} from '../local/bridgeWorkspace.mjs';
import {randomHex, sha256Hex} from '../platform/index.mjs';

const decoder = new TextDecoder();
const encoder = new TextEncoder();

async function safeInvoke(invoke, op, payload) {
  try {
    const result = await invoke(op, payload, null);
    return result && typeof result === 'object' ? result : {ok: false, code: 'NATIVE_RESULT_INVALID'};
  } catch (error) {
    const text = String(error?.message ?? error);
    const match = /^([A-Z][A-Z0-9_]+):\s*([\s\S]*)$/.exec(text);
    return {ok: false, code: error?.code || match?.[1] || 'NATIVE_CALL_FAILED', reason: match?.[2] || text};
  }
}

function exportRefAt(iso) {
  const compact = new Date(iso).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, '');
  return `diag-${compact.slice(0, 8)}-${compact.slice(9, 15)}-${randomHex(4)}`;
}

/**
 * 诊断包：先预览，确认后导出；不自动上传。
 * - 来源只有宿主列出的本地日志（宿主、控制端、网络服务）与本应用生成的监测状态摘要；
 *   内核日志含访问明细，预览里标出、默认不选。
 * - 每个文件先按与归档同一份规则脱敏再写；清单记下来源哈希、导出件哈希与替换次数，脱敏件不冒称与原件一致。
 * - 清单最后写。任何一个文件写失败就回「诊断包未生成」，半截目录没有清单。
 */
export function createDiagnosticExport({invoke, clock = () => new Date().toISOString(), statusSummary = null}) {
  if (typeof invoke !== 'function') throw new Error('BRIDGE_REQUIRED: native bridge invoke is required');

  async function preview() {
    const listed = await safeInvoke(invoke, 'LogSources', {});
    if (listed.ok !== true) return {ok: false, code: listed.code || 'LOG_SOURCES_UNAVAILABLE', reason: listed.reason || null, items: [], directories: []};
    return {
      ok: true,
      items: (listed.sources || []).map((item) => ({
        source_ref: item.source_ref,
        category: item.category,
        name: item.name,
        size: item.size,
        modified_at: item.modified_at || null,
        contains_access_history: item.contains_access_history === true,
        selected: item.contains_access_history !== true,
      })),
      directories: listed.directories || [],
      generated: statusSummary ? ['audit-status.json'] : [],
      note: '导出前逐个文件脱敏；包留在本机日志目录下，由你决定是否转交，不会自动上传。',
    };
  }

  async function create({include = null, confirmed = false} = {}) {
    if (confirmed !== true) return {ok: false, code: 'EXPORT_NOT_CONFIRMED', message: '请先查看预览并确认导出范围'};
    const listing = await preview();
    if (!listing.ok) return {ok: false, code: listing.code, message: `诊断包未生成：读不到日志清单（${listing.code}）`};
    const chosen = listing.items.filter((item) => (Array.isArray(include) ? include.includes(item.source_ref) : item.selected));
    const exportRef = exportRefAt(clock());
    const files = [];
    const skipped = [];
    async function write(name, bytes) {
      const written = await safeInvoke(invoke, 'LogExportWrite', {export_ref: exportRef, name, bytes: encodeBytes(bytes)});
      if (written.ok !== true) {
        const code = written.code || 'LOG_EXPORT_WRITE_FAILED';
        throw Object.assign(new Error(code), {code, reason: written.reason || null, file: name});
      }
      return written;
    }
    try {
      for (const item of chosen) {
        const read = await safeInvoke(invoke, 'LogRead', {source_ref: item.source_ref});
        if (read.ok !== true) {
          skipped.push({source_ref: item.source_ref, code: read.code || 'LOG_SOURCE_UNREADABLE'});
          continue;
        }
        const original = decodeBytes(read.bytes);
        const redacted = redactSecrets(decoder.decode(original));
        const bytes = encoder.encode(redacted.text);
        const name = `${item.category}__${item.name}`;
        await write(name, bytes);
        files.push({
          name,
          source_ref: item.source_ref,
          contains_access_history: item.contains_access_history,
          source_sha256: sha256Hex(original),
          sha256: sha256Hex(bytes),
          redactions: redacted.count,
          redaction_rules: redacted.rules,
          derived: redacted.count > 0 ? 'REDACTED' : 'COPY',
        });
      }
      if (statusSummary) {
        const summary = redactSecrets(JSON.stringify(await statusSummary(), null, 2));
        const bytes = encoder.encode(summary.text);
        await write('audit-status.json', bytes);
        files.push({name: 'audit-status.json', source_ref: 'generated/audit-status', sha256: sha256Hex(bytes), redactions: summary.count, derived: 'GENERATED'});
      }
      const manifest = {
        schemaVersion: 1,
        export_ref: exportRef,
        created_at: clock(),
        uploaded: false,
        files,
        skipped,
        excluded: listing.items.filter((item) => !chosen.includes(item)).map((item) => ({source_ref: item.source_ref, contains_access_history: item.contains_access_history})),
        notes: [
          '每个日志文件导出前按与归档相同的秘密规则脱敏；derived 为 REDACTED 的文件与原件字节不同，sha256 是导出件自己的。',
          '本包只留在本机日志目录，由用户决定是否转交；应用不会自动上传。',
        ],
      };
      const written = await write('manifest.json', encoder.encode(JSON.stringify(manifest, null, 2)));
      return {ok: true, export_ref: exportRef, manifest_path: written.path || null, files, skipped, excluded: manifest.excluded};
    } catch (error) {
      return {
        ok: false,
        code: error.code || 'LOG_EXPORT_WRITE_FAILED',
        export_ref: exportRef,
        failed_file: error.file || null,
        reason: error.reason || null,
        files,
        message: `诊断包未生成：${error.file || '文件'} 没能写入（${error.code || 'LOG_EXPORT_WRITE_FAILED'}）`,
      };
    }
  }

  async function openFolder(target = 'logs', exportRef = null) {
    return safeInvoke(invoke, 'LogOpenFolder', exportRef ? {target, export_ref: exportRef} : {target});
  }

  return {preview, create, openFolder};
}
