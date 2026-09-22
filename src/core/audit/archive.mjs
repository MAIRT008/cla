import {classifyLogLine} from './routeClassifier.mjs';
import {inspectSecrets} from './redact.mjs';
import {localDateKey, localTimestampKey} from './time.mjs';

const DEFAULT_LATEST_NAMES = ['service_latest.log'];
const PREDECESSOR_CHECKS = 3;

function baseName(relativePath) {
  return relativePath.split('/').at(-1);
}

function extension(name) {
  const index = name.lastIndexOf('.');
  return index === -1 ? '' : name.slice(index);
}

function withoutExtension(name) {
  const index = name.lastIndexOf('.');
  return index === -1 ? name : name.slice(0, index);
}

function metadataPath(archivePath) {
  const marker = '/raw/';
  const index = archivePath.indexOf(marker);
  if (index === -1) throw new Error(`archive path lacks raw marker: ${archivePath}`);
  return `${archivePath.slice(0, index)}/entries/${archivePath.slice(index + marker.length)}.archive.json`;
}

function decode(bytes) {
  return new TextDecoder().decode(bytes);
}

function isBytePrefix(prefix, value) {
  if (prefix.byteLength > value.byteLength) return false;
  for (let index = 0; index < prefix.byteLength; index += 1) {
    if (prefix[index] !== value[index]) return false;
  }
  return true;
}

function cloneMapping(mapping) {
  return mapping ? JSON.parse(JSON.stringify(mapping)) : null;
}

function parseArchiveMetadata(file) {
  try {
    const metadata = JSON.parse(decode(file.bytes));
    return metadata?.archivePath && metadata?.sha256 ? metadata : null;
  } catch {
    return null;
  }
}

function newestFirst(left, right) {
  return String(right.archivedAt).localeCompare(String(left.archivedAt)) || String(right.archivePath).localeCompare(String(left.archivePath));
}

/** 同一日志的轮转成员属于一族：`core.1.log` 与 `core.log`。 */
export function rotationFamily(sourcePath) {
  return String(sourcePath).replace(/\.\d+(\.[^./]+)$/, '$1');
}

/** 只列路径，不把每个归档的字节都读回来；没有 listPaths 的存储退回 listFiles。 */
export async function listArchivePaths(store, root) {
  if (typeof store.listPaths === 'function') return store.listPaths(root);
  return (await store.listFiles(root)).map((file) => ({path: file.path}));
}

/** 归档索引只读元数据：哈希、来源、流标识与归档时刻都记在 `.archive.json` 里。 */
export async function readArchiveIndex(store, archiveRoot) {
  const metadataByArchivePath = new Map();
  const rawPaths = [];
  for (const entry of await listArchivePaths(store, archiveRoot)) {
    if (entry.path.endsWith('.archive.json')) {
      let metadata = null;
      try {
        metadata = parseArchiveMetadata({bytes: await store.readBytes(entry.path)});
      } catch {
        metadata = null;
      }
      if (metadata) metadataByArchivePath.set(metadata.archivePath, metadata);
    } else if (entry.path.includes('/raw/')) {
      rawPaths.push(entry.path);
    }
  }
  return {metadataByArchivePath, rawPaths};
}

function wrongRoutesIn(text, mapping) {
  if (!mapping) return 0;
  let count = 0;
  for (const line of text.split(/\r?\n/)) {
    if (classifyLogLine(line, mapping).classification === 'WRONG_ROUTE') count += 1;
  }
  return count;
}

export function planArchive(now, lastRunAt) {
  const nowMillis = new Date(now).getTime();
  if (Number.isNaN(nowMillis)) throw new Error(`invalid archive time: ${now}`);
  if (!lastRunAt) return {due: true, reason: 'NO_PRIOR_RUN'};
  const lastMillis = new Date(lastRunAt).getTime();
  if (Number.isNaN(lastMillis)) return {due: true, reason: 'INVALID_PRIOR_RUN'};
  return nowMillis - lastMillis >= 2 * 60 * 60 * 1000
    ? {due: true, reason: 'INTERVAL_ELAPSED'}
    : {due: false, reason: 'INTERVAL_NOT_ELAPSED'};
}

/**
 * 只读归档：来源默认与归档同一个存储；正式桌面上来源是产品网络服务的日志（`options.sources`），归档写进审计存储。
 * `latestSourceNames` 是会继续增长的活动日志，按当地时间戳快照命名；`optionalSourceNames` 缺席不算缺口（如尚未轮转的 `core.1.log`）。
 */
export async function archiveLogs(request, store, {sources = null} = {}) {
  const now = request.now;
  const date = localDateKey(now);
  const stamp = localTimestampKey(now);
  const sourceFiles = await (sources || store).listFiles(request.sourceRoot);
  const latestNames = new Set(request.latestSourceNames || DEFAULT_LATEST_NAMES);
  const optionalNames = new Set(request.optionalSourceNames || []);
  const explicitApprovedNames = request.approvedSourceNames || null;
  const approved = new Set(explicitApprovedNames || sourceFiles.map((entry) => baseName(entry.path)));
  const found = sourceFiles.filter((file) => approved.has(baseName(file.path)) && (!file.status || file.status === 'found'));
  const foundNames = new Set(found.map((file) => baseName(file.path)));
  const {metadataByArchivePath} = await readArchiveIndex(store, request.archiveRoot);
  const prior = [...metadataByArchivePath.values()];
  const hashIndex = new Map(prior.map((metadata) => [metadata.sha256, metadata.archivePath]));
  const bytesCache = new Map();
  async function archivedBytes(archivePath) {
    if (!bytesCache.has(archivePath)) bytesCache.set(archivePath, await store.readBytes(archivePath));
    return bytesCache.get(archivePath);
  }

  const result = {
    status: 'OK',
    archivedAt: new Date(now).toISOString(),
    date,
    newCount: 0,
    duplicateCount: 0,
    verifiedCount: 0,
    derivedCount: 0,
    entries: [],
    restrictedExceptions: [],
    issues: [],
    wrongRouteCount: 0,
    notification: 'DONT_NOTIFY',
    collection: {
      approvedSourceCount: [...approved].filter((name) => foundNames.has(name) || !optionalNames.has(name)).length,
      snapshotCount: 0,
      verifiedSnapshotCount: 0,
    },
  };
  if (explicitApprovedNames) {
    for (const name of explicitApprovedNames) {
      if (!foundNames.has(name) && !optionalNames.has(name)) result.issues.push({sourcePath: name, code: 'APPROVED_SOURCE_MISSING'});
    }
  }
  for (const file of sourceFiles) {
    if (!approved.has(baseName(file.path)) || !file.status || ['found', 'not_found', 'missing'].includes(file.status)) continue;
    result.issues.push({sourcePath: file.path, code: 'SOURCE_UNREADABLE', reason: file.reason || file.status});
  }

  /** 前一快照是本快照的字节前缀就沿用它的流标识：增长与轮转（core.log → core.1.log）都不重复计数。 */
  async function predecessor(sourcePath, bytes, derived) {
    const candidates = prior
      .filter((metadata) => metadata.sourceStreamId && Boolean(metadata.derived) === derived && rotationFamily(metadata.sourcePath) === rotationFamily(sourcePath))
      .sort(newestFirst)
      .slice(0, PREDECESSOR_CHECKS);
    for (const candidate of candidates) {
      try {
        const earlier = await archivedBytes(candidate.archivePath);
        if (isBytePrefix(earlier, bytes)) return {sourceStreamId: candidate.sourceStreamId, prefixLength: earlier.byteLength};
      } catch {
        result.issues.push({sourcePath: candidate.archivePath, code: 'PRIOR_ARCHIVE_UNREADABLE'});
      }
    }
    return null;
  }

  async function nameFor(sourceName, sha256, derived) {
    const base = derived ? `${withoutExtension(sourceName)}.redacted${extension(sourceName)}` : sourceName;
    let archiveName = latestNames.has(sourceName) ? `${withoutExtension(base)}.snapshot_${stamp}${extension(base)}` : base;
    let archivePath = `${request.archiveRoot}/${date}/raw/${archiveName}`;
    if (await store.exists(archivePath)) {
      archiveName = `${withoutExtension(archiveName)}.${sha256.slice(0, 12)}${extension(archiveName)}`;
      archivePath = `${request.archiveRoot}/${date}/raw/${archiveName}`;
    }
    return archivePath;
  }

  async function writeSnapshot(file, bytes, sha256, extra = {}) {
    const derived = Boolean(extra.derived);
    const archivePath = await nameFor(baseName(file.path), sha256, derived);
    await store.writeBytes(archivePath, bytes, {overwrite: false});
    const verified = (await store.sha256(await store.readBytes(archivePath))) === sha256;
    if (!verified) throw new Error('ARCHIVE_HASH_MISMATCH');
    const inherited = await predecessor(file.path, bytes, derived);
    const metadata = {
      schemaVersion: 1,
      archivePath,
      sourcePath: file.path,
      sourceStreamId: inherited?.sourceStreamId || `stream:${file.path}:${sha256}`,
      sha256,
      archivedAt: new Date(now).toISOString(),
      mapping: cloneMapping(request.mapping),
      ...extra,
    };
    const entryMetadataPath = metadataPath(archivePath);
    await store.writeText(entryMetadataPath, JSON.stringify(metadata, null, 2), {overwrite: false});
    hashIndex.set(sha256, archivePath);
    metadataByArchivePath.set(archivePath, metadata);
    result.wrongRouteCount += wrongRoutesIn(decode(bytes.subarray(inherited?.prefixLength || 0)), metadata.mapping);
    return {archivePath, metadataPath: entryMetadataPath, sourceStreamId: metadata.sourceStreamId};
  }

  for (const file of found) {
    const sha256 = await store.sha256(file.bytes);
    const secrets = inspectSecrets(decode(file.bytes));
    if (secrets.found) {
      const exception = {sourcePath: file.path, sha256, reason: 'SECRET_MATERIAL'};
      result.restrictedExceptions.push(exception);
      // 原件不进普通归档；能定位到秘密值时另存脱敏派生件，带自己的哈希，只声明来源哈希，不声称与原件一致。
      if (secrets.redacted) {
        const derivedBytes = new TextEncoder().encode(secrets.redacted.text);
        const derivedSha256 = await store.sha256(derivedBytes);
        exception.derivedSha256 = derivedSha256;
        exception.redactionCount = secrets.redacted.count;
        if (hashIndex.has(derivedSha256)) {
          exception.derivedArchivePath = hashIndex.get(derivedSha256);
          exception.derivedStatus = 'DUPLICATE';
          continue;
        }
        try {
          const written = await writeSnapshot(file, derivedBytes, derivedSha256, {
            derived: 'REDACTED',
            sourceSha256: sha256,
            redactionCount: secrets.redacted.count,
            redactionRules: secrets.redacted.rules,
          });
          exception.derivedArchivePath = written.archivePath;
          exception.derivedStatus = 'ARCHIVED_REDACTED';
          result.derivedCount += 1;
          result.entries.push({sourcePath: file.path, ...written, sha256: derivedSha256, sourceSha256: sha256, status: 'ARCHIVED_REDACTED', verified: true});
        } catch (error) {
          exception.derivedStatus = 'FAILED';
          result.issues.push({sourcePath: file.path, code: error.message});
        }
      }
      continue;
    }
    if (hashIndex.has(sha256)) {
      const archivePath = hashIndex.get(sha256);
      const metadata = metadataByArchivePath.get(archivePath);
      result.duplicateCount += 1;
      result.verifiedCount += 1;
      result.collection.snapshotCount += 1;
      if (metadata) result.collection.verifiedSnapshotCount += 1;
      result.entries.push({
        sourcePath: file.path,
        archivePath,
        metadataPath: metadata ? metadataPath(archivePath) : null,
        sourceStreamId: metadata?.sourceStreamId || null,
        sha256,
        status: 'DUPLICATE',
      });
      continue;
    }
    try {
      const written = await writeSnapshot(file, file.bytes, sha256);
      result.newCount += 1;
      result.verifiedCount += 1;
      result.collection.snapshotCount += 1;
      result.collection.verifiedSnapshotCount += 1;
      result.entries.push({sourcePath: file.path, ...written, sha256, status: 'ARCHIVED', verified: true});
    } catch (error) {
      result.issues.push({sourcePath: file.path, code: error.message});
    }
  }

  // 活动日志上一次的快照必须仍是某个当前来源的前缀；两次归档之间轮转两次或被截断，中间那段就丢了。
  for (const liveName of latestNames) {
    if (!approved.has(liveName)) continue;
    const head = prior.filter((metadata) => !metadata.derived && baseName(metadata.sourcePath) === liveName).sort(newestFirst)[0];
    if (!head) continue;
    let headBytes;
    try {
      headBytes = await archivedBytes(head.archivePath);
    } catch {
      result.issues.push({sourcePath: head.archivePath, code: 'PRIOR_ARCHIVE_UNREADABLE'});
      continue;
    }
    if (!found.some((file) => isBytePrefix(headBytes, file.bytes))) {
      result.issues.push({sourcePath: head.sourcePath, code: 'SOURCE_ROTATION_GAP', lastArchivePath: head.archivePath, lastArchivedAt: head.archivedAt});
    }
  }

  if (result.issues.length) result.status = 'PARTIAL';
  result.collection.status = result.collection.approvedSourceCount > 0
    && result.collection.snapshotCount === result.collection.approvedSourceCount
    && result.collection.verifiedSnapshotCount === result.collection.approvedSourceCount
    && !result.issues.length
    && !result.restrictedExceptions.length
    ? 'VERIFIED_SNAPSHOTS'
    : 'INCOMPLETE';
  if (result.wrongRouteCount || result.issues.length || result.restrictedExceptions.length) result.notification = 'ATTENTION';
  return result;
}
