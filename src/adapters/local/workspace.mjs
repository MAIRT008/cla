import {createHash, randomUUID} from 'node:crypto';
import {
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import {existsSync, lstatSync, mkdirSync} from 'node:fs';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function parsePayload(row) {
  return {...JSON.parse(row.payload), created_at: row.created_at, updated_at: row.updated_at};
}

const COOKIE_COLUMNS = [
  'creation_utc', 'host_key', 'top_frame_site_key', 'name', 'value', 'encrypted_value', 'path',
  'expires_utc', 'is_secure', 'is_httponly', 'last_access_utc', 'has_expires', 'is_persistent',
  'priority', 'samesite', 'source_scheme', 'source_port', 'last_update_utc', 'source_type',
  'has_cross_site_ancestor',
];
const COOKIE_KEY_COLUMNS = [
  'host_key', 'top_frame_site_key', 'has_cross_site_ancestor', 'name', 'path', 'source_scheme', 'source_port',
];

function openDatabase(absolutePath) {
  return new DatabaseSync(absolutePath);
}

function databaseTables(db) {
  return new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((row) => row.name));
}

function assertCcSwitchV18(db) {
  const tables = databaseTables(db);
  if (!tables.has('providers') || !tables.has('provider_endpoints')) {
    throw Object.assign(new Error('CC Switch Provider and endpoint tables are required'), {code: 'UNSUPPORTED_FORMAT'});
  }
  const version = db.prepare('PRAGMA user_version').get().user_version;
  if (version !== 18) throw Object.assign(new Error(`CC Switch schema version ${version} is not supported`), {code: 'UNSUPPORTED_FORMAT'});
  const columns = new Set(db.prepare("PRAGMA table_info('providers')").all().map((row) => row.name));
  for (const column of ['id', 'app_type', 'name', 'settings_config']) {
    if (!columns.has(column)) throw Object.assign(new Error(`providers.${column} is required`), {code: 'UNSUPPORTED_FORMAT'});
  }
}

function assertChromiumCookieV24(db) {
  const tables = databaseTables(db);
  if (!tables.has('meta') || !tables.has('cookies')) {
    throw Object.assign(new Error('Chromium meta and cookies tables are required'), {code: 'UNSUPPORTED_FORMAT'});
  }
  const versions = new Map(db.prepare("SELECT key, value FROM meta WHERE key IN ('version', 'last_compatible_version')").all().map((row) => [row.key, String(row.value)]));
  if (versions.get('version') !== '24' || versions.get('last_compatible_version') !== '24') {
    throw Object.assign(new Error('only Chromium Cookie schema v24 is supported'), {code: 'UNSUPPORTED_FORMAT'});
  }
  const columns = new Set(db.prepare("PRAGMA table_info('cookies')").all().map((row) => row.name));
  if (COOKIE_COLUMNS.some((column) => !columns.has(column))) {
    throw Object.assign(new Error('Chromium Cookie v24 columns are incomplete'), {code: 'UNSUPPORTED_FORMAT'});
  }
  const uniqueIndexes = db.prepare("PRAGMA index_list('cookies')").all().filter((row) => row.unique === 1);
  const hasExpectedIndex = uniqueIndexes.some((index) => {
    const columnsForIndex = db.prepare(`PRAGMA index_info('${index.name.replaceAll("'", "''")}')`).all().map((row) => row.name);
    return JSON.stringify(columnsForIndex) === JSON.stringify(COOKIE_KEY_COLUMNS);
  });
  if (!hasExpectedIndex) throw Object.assign(new Error('Chromium Cookie v24 seven-column unique index is required'), {code: 'UNSUPPORTED_FORMAT'});
}

function containsProtectedUsage(value) {
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, child]) => /(?:project|memory|skills?|hooks?|mcp|audit|daily.?report|active.?log)/i.test(key)
    || containsProtectedUsage(child));
}

function inspectCcSwitch(db) {
  assertCcSwitchV18(db);
  const providers = db.prepare('SELECT id, app_type, name, settings_config, is_current FROM providers').all().map((row) => {
    let configuration = {};
    try { configuration = JSON.parse(row.settings_config); } catch {}
    const env = configuration?.env && typeof configuration.env === 'object' ? configuration.env : {};
    let endpointHost = null;
    try { endpointHost = env.ANTHROPIC_BASE_URL ? new URL(String(env.ANTHROPIC_BASE_URL)).hostname.toLowerCase() : null; } catch {}
    return {
      provider_id: row.id,
      app_type: row.app_type,
      name: row.name,
      is_current: Number(row.is_current) === 1,
      endpoint_host: endpointHost,
      credential_present: ['ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY'].some((key) => typeof env[key] === 'string' && env[key].trim() !== ''),
      identity_ref: configuration.identity_ref || configuration.identityRef || null,
      protected_usage: containsProtectedUsage(configuration),
    };
  });
  return {schema_version: 18, providers, tables: [...databaseTables(db)].sort()};
}

function inspectCookies(db) {
  assertChromiumCookieV24(db);
  const selectors = db.prepare(`
    SELECT host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port
    FROM cookies
  `).all();
  return {schema_version: 24, cookies: selectors, tables: [...databaseTables(db)].sort()};
}

function deleteCcProvider(db, selector) {
  assertCcSwitchV18(db);
  db.exec('PRAGMA foreign_keys = ON; BEGIN IMMEDIATE;');
  try {
    const provider = db.prepare('SELECT id, app_type FROM providers WHERE id = ? AND app_type = ?').get(selector.provider_id, selector.app_type);
    if (!provider) {
      db.exec('COMMIT;');
      return {matched: 0, changed: 0, endpoints: 0};
    }
    const endpoints = db.prepare('SELECT COUNT(*) AS count FROM provider_endpoints WHERE provider_id = ? AND app_type = ?').get(selector.provider_id, selector.app_type).count;
    const changed = db.prepare('DELETE FROM providers WHERE id = ? AND app_type = ?').run(selector.provider_id, selector.app_type).changes;
    db.exec('COMMIT;');
    return {matched: 1, changed, endpoints};
  } catch (error) {
    try { db.exec('ROLLBACK;'); } catch {}
    throw error;
  }
}

function deleteChromiumCookie(db, selector) {
  assertChromiumCookieV24(db);
  db.exec('BEGIN IMMEDIATE;');
  try {
    const statement = db.prepare(`
      DELETE FROM cookies
      WHERE name = ? AND host_key = ? AND top_frame_site_key = ? AND path = ?
        AND source_scheme = ? AND source_port = ? AND has_cross_site_ancestor = ?
    `);
    const changed = statement.run(
      selector.name,
      selector.host_key,
      selector.top_frame_site_key,
      selector.path,
      selector.source_scheme,
      selector.source_port,
      selector.has_cross_site_ancestor,
    ).changes;
    db.exec('COMMIT;');
    return {matched: changed, changed};
  } catch (error) {
    try { db.exec('ROLLBACK;'); } catch {}
    throw error;
  }
}

function encodeCell(value) {
  if (value === null || value === undefined) return 'n';
  if (typeof value === 'bigint') return `i:${value}`;
  if (typeof value === 'number') return `r:${value}`;
  if (typeof value === 'string') return `t:${Buffer.from(value, 'utf8').toString('base64')}`;
  return `b:${Buffer.from(value).toString('base64')}`;
}

/**
 * 数据库的逻辑指纹：user_version、结构与每张表全部行（按全部列排序）取 SHA-256。
 * 经 SQLite 读取，WAL 里已提交的内容一并算在内；与主文件字节、页面布局和 rowid 无关。与 workspace.rs 的 logical_digest 同一规则。
 */
function logicalDigest(db) {
  const lines = [`user_version=${db.prepare('PRAGMA user_version').get().user_version}`];
  const entries = db.prepare("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").all();
  for (const entry of entries) lines.push(`${entry.type}\t${entry.name}\t${entry.sql ?? ''}`);
  for (const entry of entries.filter((item) => item.type === 'table')) {
    const quoted = quoteIdentifier(entry.name);
    const columns = db.prepare(`PRAGMA table_info(${quoted})`).all().length;
    const statement = db.prepare(`SELECT * FROM ${quoted} ORDER BY ${Array.from({length: columns}, (_, index) => index + 1).join(', ')}`);
    statement.setReadBigInts(true);
    lines.push(`rows\t${entry.name}`);
    for (const row of statement.all()) lines.push(Object.values(row).map(encodeCell).join('\t'));
  }
  return createHash('sha256').update(lines.join('\n')).digest('hex');
}

/** 一致快照：只读连接上 VACUUM INTO 一个新文件；取不到就报 DB_SNAPSHOT_UNAVAILABLE，不退回复制主文件。 */
function snapshotTo(sourceAbsolute, targetAbsolute) {
  let db;
  try {
    db = new DatabaseSync(sourceAbsolute, {readOnly: true});
    db.prepare('VACUUM INTO ?').run(targetAbsolute);
  } catch (error) {
    throw Object.assign(new Error(`DB_SNAPSHOT_UNAVAILABLE: ${error.message}`), {code: 'DB_SNAPSHOT_UNAVAILABLE'});
  } finally {
    db?.close();
  }
}

function digestFile(absolute) {
  const db = new DatabaseSync(absolute, {readOnly: true});
  try {
    return logicalDigest(db);
  } finally {
    db.close();
  }
}

function quoteIdentifier(value) {
  return `"${String(value).replaceAll('"', '""')}"`;
}

function copySelectedRow(sourceDb, targetDb, table, whereSql, parameters) {
  const sourceStatement = sourceDb.prepare(`SELECT * FROM ${quoteIdentifier(table)} WHERE ${whereSql}`);
  sourceStatement.setReadBigInts(true);
  const source = sourceStatement.get(...parameters);
  if (!source) return {source_found: false, restored: 0};
  if (targetDb.prepare(`SELECT 1 AS present FROM ${quoteIdentifier(table)} WHERE ${whereSql}`).get(...parameters)) {
    return {source_found: true, conflict: true, restored: 0};
  }
  const columns = Object.keys(source);
  targetDb.prepare(`INSERT INTO ${quoteIdentifier(table)} (${columns.map(quoteIdentifier).join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`)
    .run(...columns.map((column) => source[column]));
  return {source_found: true, restored: 1};
}

export function createWorkspaceAdapter({workspaceRoot, clock = () => new Date().toISOString()}) {
  const declaredRoot = path.resolve(workspaceRoot);
  if (!existsSync(declaredRoot)) throw new Error('WORKSPACE_NOT_FOUND: explicit synthetic workspace must exist');
  const root = path.resolve(declaredRoot);
  const stateDir = path.join(root, 'state');
  const backupDir = path.join(root, 'backups');

  function assertRelative(relativePath) {
    if (typeof relativePath !== 'string' || !relativePath || path.isAbsolute(relativePath)) {
      throw new Error('OUT_OF_SCOPE: path must be a non-empty relative path');
    }
    const absolute = path.resolve(root, relativePath);
    const relation = path.relative(root, absolute);
    if (relation === '' || relation.startsWith(`..${path.sep}`) || relation === '..' || path.isAbsolute(relation)) {
      throw new Error('OUT_OF_SCOPE: path escapes explicit workspace');
    }
    return {absolute, relative: relation.split(path.sep).join('/')};
  }

  function assertStatePath(relativePath) {
    const resolved = assertRelative(relativePath);
    if (lstatSync(root).isSymbolicLink()) throw new Error('OUT_OF_SCOPE: workspace root cannot be a link');
    let cursor = root;
    for (const part of resolved.relative.split('/')) {
      cursor = path.join(cursor, part);
      if (existsSync(cursor) && lstatSync(cursor).isSymbolicLink()) {
        throw new Error('OUT_OF_SCOPE: state and backup paths cannot traverse links');
      }
    }
    return resolved;
  }

  assertStatePath('state');
  assertStatePath('backups');
  mkdirSync(stateDir, {recursive: true});
  mkdirSync(backupDir, {recursive: true});
  assertStatePath('state/local.sqlite');
  const statePath = path.join(stateDir, 'local.sqlite');

  async function assertNoLinks(absolute, allowMissing = false) {
    const relation = path.relative(root, absolute);
    const parts = relation ? relation.split(path.sep) : [];
    let cursor = root;
    const rootStat = await lstat(root);
    if (rootStat.isSymbolicLink()) throw new Error('OUT_OF_SCOPE: workspace root cannot be a link');
    for (let index = 0; index < parts.length; index += 1) {
      cursor = path.join(cursor, parts[index]);
      try {
        const stat = await lstat(cursor);
        if (stat.isSymbolicLink()) throw new Error('OUT_OF_SCOPE: links are not supported');
      } catch (error) {
        if (error?.code === 'ENOENT' && allowMissing) return;
        throw error;
      }
    }
  }

  async function resolvePath(relativePath, options = {}) {
    const resolved = assertRelative(relativePath);
    await assertNoLinks(resolved.absolute, options.allowMissing === true);
    return resolved;
  }

  async function ensureParent(relativePath) {
    const {absolute} = assertRelative(relativePath);
    const parent = path.dirname(absolute);
    await assertNoLinks(parent, true);
    await mkdir(parent, {recursive: true});
    await assertNoLinks(parent, false);
  }

  function openState() {
    assertStatePath('state/local.sqlite');
    const db = new DatabaseSync(statePath);
    db.exec(`
      PRAGMA journal_mode = DELETE;
      CREATE TABLE IF NOT EXISTS records (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS records_type_updated ON records(type, updated_at);
      CREATE TABLE IF NOT EXISTS backups (
        backup_ref TEXT PRIMARY KEY,
        action_id TEXT NOT NULL,
        payload_path TEXT NOT NULL,
        metadata TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);
    return db;
  }

  function saveRecord(type, id, payload) {
    const db = openState();
    try {
      const now = clock();
      db.prepare(`
        INSERT INTO records (id, type, payload, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET type = excluded.type, payload = excluded.payload, updated_at = excluded.updated_at
      `).run(id, type, JSON.stringify(payload), now, now);
      return {...payload, created_at: now, updated_at: now};
    } finally {
      db.close();
    }
  }

  function getRecord(id, expectedType) {
    const db = openState();
    try {
      const row = expectedType
        ? db.prepare('SELECT * FROM records WHERE id = ? AND type = ?').get(id, expectedType)
        : db.prepare('SELECT * FROM records WHERE id = ?').get(id);
      return row ? parsePayload(row) : null;
    } finally {
      db.close();
    }
  }

  function listRecords(type) {
    const db = openState();
    try {
      const rows = type
        ? db.prepare('SELECT * FROM records WHERE type = ? ORDER BY updated_at, id').all(type)
        : db.prepare('SELECT * FROM records ORDER BY updated_at, id').all();
      return rows.map(parsePayload);
    } finally {
      db.close();
    }
  }

  async function writeBackup(actionId, bytes, metadata) {
    const backupRef = `backup-${randomUUID()}`;
    const relative = `backups/${backupRef}.bin`;
    await ensureParent(relative);
    const {absolute} = await resolvePath(relative, {allowMissing: true});
    await writeFile(absolute, bytes);
    const db = openState();
    try {
      db.prepare('INSERT INTO backups (backup_ref, action_id, payload_path, metadata, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(backupRef, actionId, relative, JSON.stringify(metadata), clock());
    } finally {
      db.close();
    }
    return {backup_ref: backupRef, payload_path: relative, metadata};
  }

  function getBackup(backupRef) {
    const db = openState();
    try {
      const row = db.prepare('SELECT * FROM backups WHERE backup_ref = ?').get(backupRef);
      return row ? {...row, metadata: JSON.parse(row.metadata)} : null;
    } finally {
      db.close();
    }
  }

  function getBackupByAction(actionId) {
    const db = openState();
    try {
      const row = db.prepare('SELECT * FROM backups WHERE action_id = ? ORDER BY created_at DESC, backup_ref DESC LIMIT 1').get(actionId);
      return row ? {...row, metadata: JSON.parse(row.metadata)} : null;
    } finally {
      db.close();
    }
  }

  async function materializeBackupDatabase(bytes) {
    const relative = `state/restore-source-${randomUUID()}.sqlite`;
    await ensureParent(relative);
    const target = await resolvePath(relative, {allowMissing: true});
    await writeFile(target.absolute, bytes);
    return {relative, absolute: target.absolute};
  }

  async function fingerprintDirectory(relativePath) {
    const location = await resolvePath(relativePath);
    const rootStat = await lstat(location.absolute);
    if (!rootStat.isDirectory()) throw Object.assign(new Error('directory action requires a directory target'), {code: 'UNSUPPORTED_FORMAT'});
    const entries = [];
    async function visit(absolute, relative) {
      const children = await readdir(absolute, {withFileTypes: true});
      for (const child of children.sort((left, right) => left.name.localeCompare(right.name))) {
        const childRelative = path.posix.join(relative, child.name);
        const childAbsolute = path.join(absolute, child.name);
        const stat = await lstat(childAbsolute);
        if (stat.isSymbolicLink()) throw Object.assign(new Error('directory action does not support links'), {code: 'OUT_OF_SCOPE'});
        if (stat.isDirectory()) await visit(childAbsolute, childRelative);
        else if (stat.isFile()) entries.push({path: childRelative, sha256: sha256(await readFile(childAbsolute))});
        else throw Object.assign(new Error('directory action supports files only'), {code: 'UNSUPPORTED_FORMAT'});
      }
    }
    await visit(location.absolute, '');
    return sha256(JSON.stringify(entries));
  }

  async function beginDirectoryIsolation(actionId, relativePath, metadata) {
    const backupRef = `backup-${randomUUID()}`;
    const isolationPath = `backups/isolation/${backupRef}`;
    const payloadPath = `backups/${backupRef}.directory.json`;
    const source = await resolvePath(relativePath);
    const sourceStat = await lstat(source.absolute);
    if (!sourceStat.isDirectory()) throw Object.assign(new Error('directory isolation target is not a directory'), {code: 'UNSUPPORTED_FORMAT'});
    const storedMetadata = {...metadata, isolation_path: isolationPath, original_relative_path: source.relative};
    await ensureParent(payloadPath);
    const payload = await resolvePath(payloadPath, {allowMissing: true});
    await writeFile(payload.absolute, `${JSON.stringify({backup_ref: backupRef, ...storedMetadata}, null, 2)}\n`, 'utf8');
    const db = openState();
    try {
      db.prepare('INSERT INTO backups (backup_ref, action_id, payload_path, metadata, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(backupRef, actionId, payloadPath, JSON.stringify(storedMetadata), clock());
    } finally {
      db.close();
    }
    return {backup_ref: backupRef, payload_path: payloadPath, metadata: storedMetadata};
  }

  async function isolateDirectory(relativePath, isolationPath) {
    const source = await resolvePath(relativePath);
    const target = await resolvePath(isolationPath, {allowMissing: true});
    if ((await lstat(source.absolute)).isDirectory() !== true) throw Object.assign(new Error('directory isolation target is not a directory'), {code: 'UNSUPPORTED_FORMAT'});
    try {
      await lstat(target.absolute);
      throw Object.assign(new Error('isolation target already exists'), {code: 'CONFLICT'});
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    await ensureParent(isolationPath);
    await rename(source.absolute, target.absolute);
  }

  async function previewDirectoryRestore(isolationPath, targetPath) {
    const pathExists = async (relativePath) => {
      try {
        const location = await resolvePath(relativePath, {allowMissing: true});
        await lstat(location.absolute);
        return true;
      } catch (error) {
        if (error?.code === 'ENOENT') return false;
        throw error;
      }
    };
    const isolated = await pathExists(isolationPath);
    const target = await pathExists(targetPath);
    return {
      recoverable: isolated && !target,
      conflicts: isolated && !target ? [] : [{code: 'RESTORE_CONFLICT', message: target ? 'directory path now exists' : 'isolated directory is missing'}],
    };
  }

  async function restoreDirectoryIsolation(isolationPath, targetPath) {
    const preview = await previewDirectoryRestore(isolationPath, targetPath);
    if (!preview.recoverable) throw Object.assign(new Error('directory restore cannot overwrite current target'), {code: 'RESTORE_CONFLICT'});
    const source = await resolvePath(isolationPath);
    const target = await resolvePath(targetPath, {allowMissing: true});
    await ensureParent(targetPath);
    await rename(source.absolute, target.absolute);
  }

  async function walk(relativeRoots) {
    const result = [];
    async function visit(relative) {
      const location = await resolvePath(relative, {allowMissing: true});
      // 前缀本身是一个文件（单文件授权根，或直指某个库文件的扫描前缀）：与原生宿主一样列出它自己。
      const itself = await lstat(location.absolute).catch(() => null);
      if (itself?.isFile()) {
        result.push({relative_path: location.relative, status: 'found', size: itself.size});
        return;
      }
      let entries;
      try {
        entries = await readdir(location.absolute, {withFileTypes: true});
      } catch (error) {
        if (error?.code === 'ENOENT') {
          result.push({relative_path: location.relative, status: 'missing'});
          return;
        }
        result.push({relative_path: location.relative, status: 'unreadable', error: error.code || 'READ_ERROR'});
        return;
      }
      for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
        const child = path.posix.join(location.relative, entry.name);
        if (entry.isSymbolicLink()) {
          result.push({relative_path: child, status: 'unsupported_link'});
        } else if (entry.isDirectory()) {
          await visit(child);
        } else if (entry.isFile()) {
          const file = await resolvePath(child);
          const stat = await lstat(file.absolute);
          result.push({relative_path: file.relative, status: 'found', size: stat.size});
        }
      }
    }
    for (const rootPath of relativeRoots) await visit(rootPath);
    return result;
  }

  return {
    root,
    state_path: statePath,
    clock,
    sha256,
    hashBytes: (value) => sha256(value),
    hashText: (value) => sha256(String(value)),
    newId: (prefix) => `${prefix}-${randomUUID()}`,
    resolvePath,
    async readBytes(relativePath) {
      const {absolute} = await resolvePath(relativePath);
      return readFile(absolute);
    },
    async writeBytes(relativePath, value) {
      await ensureParent(relativePath);
      const {absolute} = await resolvePath(relativePath, {allowMissing: true});
      await writeFile(absolute, value);
    },
    async remove(relativePath) {
      const {absolute} = await resolvePath(relativePath, {allowMissing: true});
      await rm(absolute, {force: true});
    },
    async copy(relativeSource, relativeTarget) {
      const source = await resolvePath(relativeSource);
      await ensureParent(relativeTarget);
      const target = await resolvePath(relativeTarget, {allowMissing: true});
      await copyFile(source.absolute, target.absolute);
    },
    async fingerprint(relativePath) {
      const bytes = await this.readBytes(relativePath);
      return sha256(bytes);
    },
    fingerprintDirectory,
    async exists(relativePath) {
      try {
        const {absolute} = await resolvePath(relativePath, {allowMissing: true});
        await lstat(absolute);
        return true;
      } catch (error) {
        if (error?.code === 'ENOENT') return false;
        throw error;
      }
    },
    walk,
    beginDirectoryIsolation,
    isolateDirectory,
    previewDirectoryRestore,
    restoreDirectoryIsolation,
    async inspectDatabase(relativePath, kind) {
      const {absolute} = await resolvePath(relativePath);
      const db = openDatabase(absolute);
      try {
        if (kind === 'cc_switch_sqlite') return inspectCcSwitch(db);
        if (kind === 'cookie_sqlite') return inspectCookies(db);
        throw Object.assign(new Error('database adapter is not declared for this format'), {code: 'UNSUPPORTED_FORMAT'});
      } finally {
        db.close();
      }
    },
    async mutateDatabase(relativePath, kind, selector) {
      const {absolute} = await resolvePath(relativePath);
      const db = openDatabase(absolute);
      try {
        if (kind === 'cc_provider_delete') return deleteCcProvider(db, selector);
        if (kind === 'cookie_delete') return deleteChromiumCookie(db, selector);
        throw Object.assign(new Error('database action is not declared'), {code: 'UNSUPPORTED_FORMAT'});
      } finally {
        db.close();
      }
    },
    async fingerprintDatabase(relativePath) {
      const {absolute} = await resolvePath(relativePath);
      return digestFile(absolute);
    },
    async snapshotDatabase(relativePath) {
      const source = await resolvePath(relativePath);
      const snapshot = `state/snapshot-${randomUUID()}.sqlite`;
      await ensureParent(snapshot);
      const target = await resolvePath(snapshot, {allowMissing: true});
      try {
        snapshotTo(source.absolute, target.absolute);
        return {bytes: new Uint8Array(await readFile(target.absolute)), sha256: digestFile(target.absolute)};
      } finally {
        await rm(target.absolute, {force: true});
      }
    },
    async simulateDatabaseMutation(relativePath, kind, selector, prior = []) {
      const simulation = `state/sim-${randomUUID()}.sqlite`;
      const source = await resolvePath(relativePath);
      await ensureParent(simulation);
      const target = await resolvePath(simulation, {allowMissing: true});
      try {
        snapshotTo(source.absolute, target.absolute);
        const db = openDatabase(target.absolute);
        try {
          for (const step of [...prior, {kind, selector}]) {
            if (step.kind === 'cc_provider_delete') deleteCcProvider(db, step.selector);
            else if (step.kind === 'cookie_delete') deleteChromiumCookie(db, step.selector);
            else throw Object.assign(new Error('database action is not declared'), {code: 'UNSUPPORTED_FORMAT'});
          }
        } finally {
          db.close();
        }
        return digestFile(target.absolute);
      } finally {
        await rm(target.absolute, {force: true});
      }
    },
    async previewDatabaseRestore(relativePath, kind, selector, backupBytes) {
      const source = await materializeBackupDatabase(backupBytes);
      const target = await resolvePath(relativePath);
      const sourceDb = openDatabase(source.absolute);
      const targetDb = openDatabase(target.absolute);
      try {
        if (kind === 'cc_provider_delete') {
          assertCcSwitchV18(sourceDb);
          assertCcSwitchV18(targetDb);
          const sourceRow = sourceDb.prepare('SELECT 1 AS present FROM providers WHERE id = ? AND app_type = ?').get(selector.provider_id, selector.app_type);
          const targetRow = targetDb.prepare('SELECT 1 AS present FROM providers WHERE id = ? AND app_type = ?').get(selector.provider_id, selector.app_type);
          return {recoverable: Boolean(sourceRow) && !targetRow, conflicts: sourceRow && targetRow ? [{code: 'RESTORE_CONFLICT', message: 'provider key now exists'}] : []};
        }
        if (kind === 'cookie_delete') {
          assertChromiumCookieV24(sourceDb);
          assertChromiumCookieV24(targetDb);
          const where = 'name = ? AND host_key = ? AND top_frame_site_key = ? AND path = ? AND source_scheme = ? AND source_port = ? AND has_cross_site_ancestor = ?';
          const parameters = [selector.name, selector.host_key, selector.top_frame_site_key, selector.path, selector.source_scheme, selector.source_port, selector.has_cross_site_ancestor];
          const sourceRow = sourceDb.prepare(`SELECT 1 AS present FROM cookies WHERE ${where}`).get(...parameters);
          const targetRow = targetDb.prepare(`SELECT 1 AS present FROM cookies WHERE ${where}`).get(...parameters);
          return {recoverable: Boolean(sourceRow) && !targetRow, conflicts: sourceRow && targetRow ? [{code: 'RESTORE_CONFLICT', message: 'cookie compound key now exists'}] : []};
        }
        throw Object.assign(new Error('database restore is not declared'), {code: 'UNSUPPORTED_FORMAT'});
      } finally {
        sourceDb.close();
        targetDb.close();
        await rm(source.absolute, {force: true});
      }
    },
    async restoreDatabaseMutation(relativePath, kind, selector, backupBytes) {
      const source = await materializeBackupDatabase(backupBytes);
      const target = await resolvePath(relativePath);
      const sourceDb = openDatabase(source.absolute);
      const targetDb = openDatabase(target.absolute);
      try {
        targetDb.exec('PRAGMA foreign_keys = ON; BEGIN IMMEDIATE;');
        let result;
        if (kind === 'cc_provider_delete') {
          assertCcSwitchV18(sourceDb);
          assertCcSwitchV18(targetDb);
          result = copySelectedRow(sourceDb, targetDb, 'providers', 'id = ? AND app_type = ?', [selector.provider_id, selector.app_type]);
          if (!result.source_found || result.conflict) throw Object.assign(new Error('provider record cannot be restored without overwrite'), {code: 'RESTORE_CONFLICT'});
          const endpointStatement = sourceDb.prepare('SELECT * FROM provider_endpoints WHERE provider_id = ? AND app_type = ?');
          endpointStatement.setReadBigInts(true);
          const endpoints = endpointStatement.all(selector.provider_id, selector.app_type);
          for (const endpoint of endpoints) {
            const columns = Object.keys(endpoint);
            targetDb.prepare(`INSERT INTO provider_endpoints (${columns.map(quoteIdentifier).join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`)
              .run(...columns.map((column) => endpoint[column]));
          }
          result.endpoints = endpoints.length;
        } else if (kind === 'cookie_delete') {
          assertChromiumCookieV24(sourceDb);
          assertChromiumCookieV24(targetDb);
          const where = 'name = ? AND host_key = ? AND top_frame_site_key = ? AND path = ? AND source_scheme = ? AND source_port = ? AND has_cross_site_ancestor = ?';
          const parameters = [selector.name, selector.host_key, selector.top_frame_site_key, selector.path, selector.source_scheme, selector.source_port, selector.has_cross_site_ancestor];
          result = copySelectedRow(sourceDb, targetDb, 'cookies', where, parameters);
          if (!result.source_found || result.conflict) throw Object.assign(new Error('cookie record cannot be restored without overwrite'), {code: 'RESTORE_CONFLICT'});
        } else {
          throw Object.assign(new Error('database restore is not declared'), {code: 'UNSUPPORTED_FORMAT'});
        }
        targetDb.exec('COMMIT;');
        return result;
      } catch (error) {
        try { targetDb.exec('ROLLBACK;'); } catch {}
        throw error;
      } finally {
        sourceDb.close();
        targetDb.close();
        await rm(source.absolute, {force: true});
      }
    },
    saveRecord,
    getRecord,
    listRecords,
    writeBackup,
    getBackup,
    getBackupByAction,
  };
}
