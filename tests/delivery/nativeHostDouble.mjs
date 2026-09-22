import {appendFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync} from 'node:fs';
import {cp, lstat, mkdir, readdir, rm} from 'node:fs/promises';
import path from 'node:path';
import {createHmac, randomBytes, randomUUID, timingSafeEqual} from 'node:crypto';
import {AUTHORIZATION_SCOPES, CAPABILITY_GROUPS, DATABASE_ACTION_KINDS, ERROR_CODES, OPS, assertPayload, checkIssuedAuthorization, isRealPath, targetPathFor} from '../../apps/desktop-host/bridge-contract.mjs';
import {createWorkspaceAdapter} from '../../src/adapters/local/workspace.mjs';
import {decodeBytes, encodeBytes} from '../../src/adapters/local/bridgeWorkspace.mjs';
import {createSyntheticBrowserHost} from '../diagnostics/browserHost.mjs';

const LOG_CATEGORIES = Object.freeze([
  ['host', 'host', (name) => safeLogName(name) && name.endsWith('.log') && (name.startsWith('host-control-') || name.startsWith('app-')), false],
  ['control', 'control', (name) => safeLogName(name) && name.endsWith('.log') && name.startsWith('control-'), false],
  ['network_service', 'service', (name) => name === 'service.log' || name === 'service.1.log', false],
  ['network_core', 'service', (name) => name === 'core.log' || name === 'core.1.log', true],
]);
const LOG_MAX_READ = 16 * 1024 * 1024;
const LOG_MAX_EXPORT = 32 * 1024 * 1024;

function safeLogName(name) {
  return Boolean(name) && name.length <= 160 && !name.startsWith('.') && !name.includes('..') && /^[A-Za-z0-9._-]+$/.test(name);
}

function logPayloadInvalid(reason) {
  return Object.assign(new Error(`${ERROR_CODES.PAYLOAD_INVALID}: ${reason}`), {code: ERROR_CODES.PAYLOAD_INVALID});
}

function validExportRef(value) {
  return /^diag-\d{8}-\d{6}-[0-9a-f]{6,16}$/.test(String(value || ''));
}

function byteOrder(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

/**
 * 站在 logs.rs 的位置：固定目录、白名单文件名、只读列举与读取；写只进本进程的应用日志与导出目录（新建不覆盖）。
 * 失败的原生操作按 dispatch_logged 记一行（操作名与错误码，不记载荷）。
 */
export function createLogDirsDouble(dirs, clock = () => new Date().toISOString()) {
  let appLogPath = null;
  const opened = [];

  function sources() {
    const listed = [];
    const directories = [];
    for (const [id, key, accepts, access] of LOG_CATEGORIES) {
      let names;
      try {
        names = readdirSync(dirs[key]);
      } catch (error) {
        directories.push(error.code === 'ENOENT' ? {category: id, status: 'missing'} : {category: id, status: 'unreadable', reason: error.code || String(error)});
        continue;
      }
      directories.push({category: id, status: 'found'});
      const found = [];
      for (const name of names) {
        if (!accepts(name)) continue;
        const info = lstatSync(path.join(dirs[key], name), {throwIfNoEntry: false});
        if (!info?.isFile()) continue;
        found.push({source_ref: `${id}/${name}`, category: id, name, size: info.size, modified_at: new Date(info.mtimeMs).toISOString(), contains_access_history: access});
      }
      listed.push(...found.sort((left, right) => byteOrder(left.name, right.name)));
    }
    return {ok: true, sources: listed, directories};
  }

  function read(sourceRef) {
    const text = String(sourceRef || '');
    const slash = text.indexOf('/');
    if (slash < 0) throw logPayloadInvalid('source_ref must be <category>/<file>');
    const category = LOG_CATEGORIES.find(([id]) => id === text.slice(0, slash));
    const name = text.slice(slash + 1);
    if (!category) throw logPayloadInvalid(`unknown log category ${text.slice(0, slash)}`);
    if (!category[2](name)) throw logPayloadInvalid(`${name} is not a ${category[0]} log`);
    const file = path.join(dirs[category[1]], name);
    const info = lstatSync(file, {throwIfNoEntry: false});
    if (!info) return {ok: false, code: 'LOG_SOURCE_NOT_FOUND', source_ref: text};
    if (!info.isFile()) return {ok: false, code: 'LOG_SOURCE_NOT_FILE', source_ref: text};
    if (info.size > LOG_MAX_READ) return {ok: false, code: 'LOG_SOURCE_TOO_LARGE', source_ref: text, size: info.size};
    try {
      const bytes = readFileSync(file);
      return {ok: true, source_ref: text, size: bytes.length, modified_at: new Date(info.mtimeMs).toISOString(), contains_access_history: category[3], bytes: encodeBytes(new Uint8Array(bytes))};
    } catch (error) {
      return {ok: false, code: 'LOG_SOURCE_UNREADABLE', source_ref: text, reason: error.code || String(error)};
    }
  }

  function append(level, event, fields) {
    if (!appLogPath) appLogPath = path.join(dirs.host, `app-${clock().replace(/[-:.]/g, '')}-${process.pid}.log`);
    mkdirSync(dirs.host, {recursive: true});
    appendFileSync(appLogPath, `${JSON.stringify({at: clock(), level, event, pid: process.pid, fields})}\n`);
    return appLogPath;
  }

  function appLogAppend(payload) {
    const event = payload.event;
    if (typeof event !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(event)) throw logPayloadInvalid('event must be a short lowercase name');
    const level = payload.level ?? 'info';
    if (!['info', 'warning', 'error'].includes(level)) throw logPayloadInvalid('level must be info, warning or error');
    const fields = {};
    if (payload.fields !== undefined) {
      if (!payload.fields || typeof payload.fields !== 'object' || Array.isArray(payload.fields)) throw logPayloadInvalid('fields must be an object');
      const entries = Object.entries(payload.fields);
      if (entries.length > 32) throw logPayloadInvalid('too many fields');
      for (const [key, value] of entries) {
        let cleaned;
        if (/token|password|cookie|secret|authorization|api_key|apikey|credential/i.test(key)) cleaned = '[redacted]';
        else if (typeof value === 'string') cleaned = [...value].slice(0, 512).join('');
        else if (value === null || typeof value === 'number' || typeof value === 'boolean') cleaned = value;
        else throw logPayloadInvalid(`field ${key} must be a string, number, boolean or null`);
        fields[[...key].slice(0, 64).join('')] = cleaned;
      }
    }
    if (JSON.stringify(fields).length > 8 * 1024) throw logPayloadInvalid('fields are too large');
    try {
      return {ok: true, path: append(level, event, fields)};
    } catch (error) {
      return {ok: false, code: 'APP_LOG_WRITE_FAILED', reason: error.code || String(error)};
    }
  }

  function recordOutcome(op, result) {
    if (op === 'AppLogAppend' || result?.ok !== false) return;
    const code = /^[A-Z0-9_]{1,64}$/.test(String(result.code || '')) ? result.code : 'NATIVE_ERROR';
    try { append('warning', 'native.op_failed', {op, code}); } catch { /* 与 Rust 一样，应用日志自己写不进时不再报错 */ }
  }

  function exportWrite(payload) {
    if (!validExportRef(payload.export_ref)) throw logPayloadInvalid('export_ref must look like diag-YYYYMMDD-HHMMSS-<hex>');
    if (!safeLogName(payload.name)) throw logPayloadInvalid('export file name is not allowed');
    const bytes = decodeBytes(payload.bytes || '');
    if (bytes.length > LOG_MAX_EXPORT) throw logPayloadInvalid('export file is too large');
    const dir = path.join(dirs.host, 'exports', payload.export_ref);
    const file = path.join(dir, payload.name);
    try {
      mkdirSync(dir, {recursive: true});
      writeFileSync(file, bytes, {flag: 'wx'});
    } catch (error) {
      if (error.code === 'EEXIST') return {ok: false, code: 'LOG_EXPORT_EXISTS', name: payload.name};
      rmSync(file, {force: true});
      return {ok: false, code: 'LOG_EXPORT_WRITE_FAILED', name: payload.name, reason: error.code || String(error)};
    }
    return {ok: true, path: file, size: bytes.length};
  }

  function openFolder(payload) {
    const target = payload.target ?? 'logs';
    let folder;
    if (target === 'logs') {
      mkdirSync(dirs.host, {recursive: true});
      folder = dirs.host;
    } else if (target === 'export') {
      if (!validExportRef(payload.export_ref)) throw logPayloadInvalid('export_ref must look like diag-YYYYMMDD-HHMMSS-<hex>');
      folder = path.join(dirs.host, 'exports', payload.export_ref);
      if (!existsSync(folder)) return {ok: false, code: 'LOG_EXPORT_NOT_FOUND'};
    } else {
      throw logPayloadInvalid('target must be logs or export');
    }
    opened.push(folder);
    return {ok: true, path: folder};
  }

  return {dirs, sources, read, appLogAppend, recordOutcome, exportWrite, openFolder, opened, appLogPath: () => appLogPath};
}

/**
 * 契约替身：按 apps/desktop-host/bridge-contract.mjs 实现同一组操作。
 * 它站在 Rust 宿主的位置，用 Node 原语提供同样的受限本地能力，
 * 从而让「页面 → bridge.js → 契约 → src/core」这条正式链路可以离线跑通。
 * 它不证明 Rust 侧实现的语义，只证明接线与契约。
 */
export function createNativeHostDouble({
  workspaceRoot,
  clock = () => new Date().toISOString(),
  network,
  product = null,
  emergencyHosts = [],
  hooks = {},
  confirmDecision = () => true,
  control = undefined,
  controlSetup = null,
  session = null,
  discovery = null,
  realBase = null,
  browserHost = null,
  logDirs = null,
  notices = {},
} = {}) {
  const adapter = createWorkspaceAdapter({workspaceRoot, clock});
  /**
   * 站在 lifecycle.rs 的位置：只收 event 与 ref，标题正文由宿主按事件取固定文案；
   * hidden 表示主窗口已隐藏或最小化，fail 让弹出失败并回这个错误码。requests 记下页面给的原始载荷。
   */
  const noticeState = {hidden: notices.hidden === true, fail: notices.fail || null, requests: [], shown: []};
  const NOTICE_TITLES = {WRONG_ROUTE: 'Claude 连接走了错误出口', PROTECTION_NOT_CONFIRMED: '阻断没有确认生效', PROTECTION_FAILED: '阻断失败'};
  function notifyCritical(payload) {
    noticeState.requests.push(structuredClone(payload));
    const refuse = (code, message) => Object.assign(new Error(message), {code});
    if (Object.keys(payload || {}).some((key) => key !== 'event' && key !== 'ref')) throw refuse('NOTIFY_FIELD_FORBIDDEN', 'only event and ref are accepted');
    const title = NOTICE_TITLES[payload.event];
    if (!title) throw refuse('NOTIFY_EVENT_UNKNOWN', 'event is not a critical notice');
    if (!/^[A-Za-z0-9._:-]{1,64}$/.test(String(payload.ref || ''))) throw refuse('NOTIFY_REF_INVALID', 'ref must be a short alert reference');
    if (!noticeState.hidden) return {ok: true, status: 'SKIPPED_WINDOW_VISIBLE', event: payload.event};
    if (noticeState.fail) return {ok: false, status: 'FAILED', code: noticeState.fail, event: payload.event};
    noticeState.shown.push({event: payload.event, title});
    return {ok: true, status: 'SHOWN', event: payload.event};
  }
  const logs = createLogDirsDouble(logDirs || {
    host: `${workspaceRoot}-logs/host`,
    control: `${workspaceRoot}-logs/control`,
    service: `${workspaceRoot}-logs/service`,
  }, clock);
  /** 站在 browser_diag.rs 的位置：不开真实端口、不打开真实浏览器，诊断页在合成浏览器里执行。 */
  const browser = browserHost || createSyntheticBrowserHost({hostEnvironment: product?.environment_ref || 'windows-host', clock});

  /**
   * 站在 Rust discovery.rs / roots.rs 的位置：发现结果由用例直接给出（替身不重写发现逻辑），
   * 授权登记在内存里，`roots/<ref>/…` 只解析到已授权的根。真实根挂在 realBase 下的合成目录里，
   * 适配器挂在 realBase 上，它自己的 state/ 与 backups/ 因此不会落进被扫描的根。
   */
  const realAdapter = realBase ? createWorkspaceAdapter({workspaceRoot: realBase, clock}) : null;
  let authorizedRoots = [];
  const outOfScope = (reason) => Object.assign(new Error(`OUT_OF_SCOPE: ${reason}`), {code: ERROR_CODES.OUT_OF_SCOPE});

  function route(relative) {
    if (!isRealPath(relative)) return {adapter, path: relative, real: false};
    const text = String(relative).replaceAll('\\', '/');
    const rest = text.slice('roots/'.length);
    const slash = rest.indexOf('/');
    const rootRef = slash < 0 ? rest : rest.slice(0, slash);
    const inner = slash < 0 ? '' : rest.slice(slash + 1).replace(/\/+$/, '');
    const root = authorizedRoots.find((item) => item.root_ref === rootRef);
    if (!root || !realAdapter) throw outOfScope(`${rootRef} is not an authorized root`);
    if (root.kind === 'file' && inner) throw outOfScope(`${rootRef} is a single-file root`);
    const absolute = inner ? path.join(root.path, ...inner.split('/')) : root.path;
    const withinRoot = path.relative(root.path, absolute);
    if (withinRoot.startsWith('..') || path.isAbsolute(withinRoot)) throw outOfScope('path escapes its authorized root');
    const mapped = path.relative(path.resolve(realBase), absolute).split(path.sep).join('/');
    if (!mapped || mapped.startsWith('..')) throw outOfScope('authorized root lies outside the synthetic real base');
    return {adapter: realAdapter, path: mapped, real: true, original: text.replace(/\/+$/, '')};
  }

  async function walkRouted(prefixes = []) {
    const entries = [];
    for (const prefix of prefixes) {
      const target = route(prefix);
      const walked = await target.adapter.walk([target.path]);
      for (const entry of walked) {
        entries.push(target.real ? {...entry, relative_path: `${target.original}${entry.relative_path.slice(target.path.length)}`} : entry);
      }
    }
    return entries;
  }

  /** 真实根的目录隔离按 Rust workspace.rs 的语义：整树复制进工作区后删除原目录；恢复把隔离树复制回去，重名文件算冲突。 */
  function absoluteOf(relative) {
    const target = route(relative);
    const base = path.resolve(target.real ? realBase : workspaceRoot);
    const absolute = path.resolve(base, ...target.path.split('/'));
    const relation = path.relative(base, absolute);
    if (!relation || relation.startsWith('..') || path.isAbsolute(relation)) throw outOfScope('path escapes its base');
    return absolute;
  }

  async function treeEntries(base) {
    const out = [];
    async function visit(current) {
      for (const item of await readdir(current, {withFileTypes: true})) {
        const full = path.join(current, item.name);
        if (item.isDirectory()) await visit(full);
        else out.push(path.relative(base, full).split(path.sep).join('/'));
      }
    }
    if ((await lstat(base).catch(() => null))?.isDirectory()) await visit(base);
    return out.sort();
  }

  async function isolateRealDirectory(from, to) {
    const source = absoluteOf(from);
    const target = absoluteOf(to);
    if (!(await lstat(source).catch(() => null))?.isDirectory()) throw Object.assign(new Error('directory isolation target is not a directory'), {code: 'UNSUPPORTED_FORMAT'});
    if (await lstat(target).catch(() => null)) throw Object.assign(new Error('isolation target already exists'), {code: 'CONFLICT'});
    await mkdir(path.dirname(target), {recursive: true});
    await cp(source, target, {recursive: true});
    await rm(source, {recursive: true, force: true});
  }

  async function previewRealRestore(isolationPath, targetPath) {
    const stored = await treeEntries(absoluteOf(isolationPath));
    const present = await treeEntries(absoluteOf(targetPath));
    const conflicts = present.filter((item) => stored.includes(item)).map((item) => ({code: 'RESTORE_CONFLICT', path: item}));
    return {recoverable: conflicts.length === 0, conflicts, entries: stored};
  }

  /** 与 discovery.rs 的 environment_declaration 同一规则：只有已授权且存在的根进扫描范围。 */
  function declareEnvironment() {
    const candidates = discovery?.candidates || [];
    const scopes = [];
    const clients = [];
    const jsonShapes = [];
    const objectKinds = [];
    const gaps = [];
    const scoped = (ref, inner) => (inner ? `roots/${ref}/${inner}` : `roots/${ref}`);
    const staleRoots = [];
    // 与 discovery.rs 的 authorization_matches 同一规则：规范化路径、根类型、客户端、类别与环境都一致才算同一个位置。
    const samePath = (left, right) => {
      const normal = (value) => {
        const resolved = path.resolve(String(value || ''));
        return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
      };
      return Boolean(right) && normal(left) === normal(right);
    };
    const matches = (stored, candidate) => samePath(stored.path, candidate.path)
      && stored.kind === candidate.kind
      && stored.client_ref === candidate.client_ref
      && stored.category === candidate.category
      && stored.environment_ref === (candidate.environment_ref || 'windows-host');
    for (const candidate of candidates) {
      const stored = authorizedRoots.find((item) => item.root_ref === candidate.root_ref);
      const registered = Boolean(stored);
      if (candidate.status !== 'found') {
        if (registered) gaps.push({code: 'AUTHORIZED_ROOT_MISSING', message: `${candidate.root_ref}: authorized earlier but now ${candidate.status}`});
        continue;
      }
      if (candidate.authorizable !== true) {
        gaps.push({code: candidate.reason || 'ROOT_NOT_SUPPORTED', message: `${candidate.root_ref}: discovered but its format is not supported`});
        continue;
      }
      clients.push({
        client_ref: candidate.client_ref,
        environment_ref: 'windows-host',
        installed: true,
        authorized: Boolean(stored && matches(stored, candidate)),
        path_prefix: scoped(candidate.root_ref, ''),
        profile_ref: candidate.profile?.profile_dir ?? null,
        category: candidate.category,
        label: candidate.label ?? null,
      });
      if (registered && !matches(stored, candidate)) {
        staleRoots.push(candidate.root_ref);
        gaps.push({code: 'AUTHORIZED_ROOT_STALE', message: `${candidate.root_ref}: the location authorized earlier is not the one discovered now; authorize it again`});
      }
      if (!stored || !matches(stored, candidate)) continue;
      const prefixes = candidate.scan_prefixes || [];
      if (prefixes.length) scopes.push(...prefixes.map((inner) => scoped(candidate.root_ref, inner)));
      else scopes.push(scoped(candidate.root_ref, ''));
      for (const item of candidate.object_kinds || []) objectKinds.push({relative_path: scoped(candidate.root_ref, item.path), kind: item.kind});
      for (const item of candidate.json_shapes || []) jsonShapes.push({relative_path: scoped(candidate.root_ref, item.path), role: item.role});
      if (candidate.category === 'browser_profile') {
        gaps.push({code: 'SITE_STORAGE_FORMAT_UNSUPPORTED', message: `${candidate.root_ref}: LevelDB site storage (Local Storage / IndexedDB) is not read in this version`});
      }
    }
    for (const item of discovery?.environments || []) {
      if (item.status === 'NOT_SCANNED') gaps.push({code: 'WSL_NOT_SCANNED', message: `${item.environment_ref}: WSL distribution is listed but not scanned`});
    }
    return {
      status: scopes.length ? 'DETECTED' : 'NOT_AUTHORIZED',
      environment_ref: 'windows-host',
      source_ref: 'host-discovery-v1',
      source_version: 'host-discovery-v1',
      scopes,
      clients,
      default_browser: discovery?.default_browser || null,
      json_shapes: jsonShapes,
      object_kinds: objectKinds,
      site_hosts: ['claude.ai', 'claude.com', 'anthropic.com'],
      stale_roots: staleRoots,
      gaps,
    };
  }

  function discoveryView() {
    return {
      ok: true,
      discovered: {source: 'host-discovery-v1', environment_ref: 'windows-host', candidates: discovery?.candidates || [], default_browser: discovery?.default_browser || null, environments: discovery?.environments || []},
      environment: declareEnvironment(),
      authorized_roots: authorizedRoots.map((item) => ({...item})),
    };
  }

  function requestedRoots(payload) {
    const refs = Array.isArray(payload.root_refs) ? payload.root_refs : [];
    if (!refs.length || refs.length > 64 || refs.some((item) => typeof item !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(item))) {
      throw Object.assign(new Error('root_refs must name 1 to 64 valid roots'), {code: ERROR_CODES.PAYLOAD_INVALID});
    }
    return [...new Set(refs)];
  }
  const statePath = path.join(path.resolve(workspaceRoot), 'state', 'native-records.json');
  mkdirSync(path.dirname(statePath), {recursive: true});

  function readStore() {
    if (!existsSync(statePath)) return {records: [], backups: []};
    try { return JSON.parse(readFileSync(statePath, 'utf8')); } catch { return {records: [], backups: []}; }
  }

  function writeStore(value) {
    writeFileSync(statePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  }

  const calls = [];
  const openedSessions = new Map();
  const confirmations = [];
  /**
   * 站在 Rust 宿主的位置实现授权保险库：
   * 它落在受限工作区**之外**（桥的 resolve 只放行工作区内路径，所以桥够不到），
   * 每条记录与整本账本都带宿主侧 HMAC，一次性授权用掉即作废。
   */
  const vaultRoot = path.join(path.dirname(path.resolve(workspaceRoot)), `vault-${path.basename(path.resolve(workspaceRoot))}`);
  const vaultFile = path.join(vaultRoot, 'authorizations.json');
  const vaultKey = randomBytes(32);

  /**
   * 控制端状态与会话保管，对应 Rust 的 control_process.rs：
   * 状态可以是固定对象，也可以是每次查询时求值的函数（模拟 starting → ready）；
   * 首启提交转给注入的 controlSetup（站在宿主附加一次性凭据的位置上）；
   * 会话材料落在工作区之外的保险库目录，校验规则与 Rust 的 session_save 一致。
   */
  const sessionFile = path.join(vaultRoot, 'control-session.json');
  const controlStatus = () => {
    const value = typeof control === 'function' ? control() : control === undefined ? product?.control : control;
    return value ? {...value} : null;
  };
  if (session) {
    mkdirSync(vaultRoot, {recursive: true});
    writeFileSync(sessionFile, JSON.stringify({...session, saved_at: clock()}), 'utf8');
  }

  function sessionLoad() {
    if (!existsSync(sessionFile)) return {ok: true, session: null};
    let stored = null;
    try { stored = JSON.parse(readFileSync(sessionFile, 'utf8')); } catch { stored = null; }
    if (!stored?.access_token || !stored?.expires_at || !stored?.user_ref) {
      rmSync(sessionFile, {force: true});
      return {ok: true, session: null, discarded: 'SESSION_FILE_INVALID'};
    }
    if (!(Date.parse(stored.expires_at) > Date.parse(clock()))) {
      rmSync(sessionFile, {force: true});
      return {ok: true, session: null, expired: true};
    }
    return {ok: true, session: {access_token: stored.access_token, expires_at: stored.expires_at, user_ref: stored.user_ref}};
  }

  function sessionSave(payload) {
    const token = String(payload.access_token || '');
    if (token.length < 16 || token.length > 512 || /\s/.test(token)) return {ok: false, code: ERROR_CODES.PAYLOAD_INVALID, reason: 'access_token is malformed'};
    if (!payload.user_ref || String(payload.user_ref).length > 128) return {ok: false, code: ERROR_CODES.PAYLOAD_INVALID, reason: 'user_ref is malformed'};
    if (!(Date.parse(payload.expires_at) > Date.parse(clock()))) return {ok: false, code: ERROR_CODES.PAYLOAD_INVALID, reason: 'expires_at must be a future instant'};
    mkdirSync(vaultRoot, {recursive: true});
    const staging = `${sessionFile}.tmp`;
    writeFileSync(staging, JSON.stringify({access_token: token, expires_at: payload.expires_at, user_ref: payload.user_ref, saved_at: clock()}), 'utf8');
    renameSync(staging, sessionFile);
    return {ok: true, expires_at: payload.expires_at, user_ref: payload.user_ref};
  }

  /** 规范化到与 Rust 侧 serde_json 的 BTreeMap 序列化一致：逐层按键排序，嵌套字段一并覆盖。 */
  function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
    }
    return value;
  }

  function recordMac(record) {
    const {mac: _ignored, ...rest} = record;
    return createHmac('sha256', vaultKey).update(JSON.stringify(canonical(rest))).digest('hex');
  }

  function ledgerMac(rows) {
    return createHmac('sha256', vaultKey).update(rows.map((row) => row.authorization_ref).join('\n')).digest('hex');
  }

  function macEquals(left, right) {
    const a = Buffer.from(String(left || ''), 'utf8');
    const b = Buffer.from(String(right || ''), 'utf8');
    return a.length === b.length && timingSafeEqual(a, b);
  }

  function readVault() {
    if (!existsSync(vaultFile)) return [];
    const parsed = JSON.parse(readFileSync(vaultFile, 'utf8'));
    const rows = parsed.authorizations || [];
    if (!macEquals(parsed.ledger_mac, ledgerMac(rows))) {
      throw Object.assign(new Error('the authorization ledger does not match its host signature'), {code: ERROR_CODES.AUTHORIZATION_STORE_TAMPERED});
    }
    return rows;
  }

  function writeVault(rows) {
    mkdirSync(vaultRoot, {recursive: true});
    writeFileSync(vaultFile, `${JSON.stringify({authorizations: rows, ledger_mac: ledgerMac(rows)}, null, 2)}\n`, 'utf8');
  }

  function loadAuthorization(reference) {
    const row = readVault().reverse().find((item) => item.authorization_ref === reference);
    if (!row) return null;
    if (!macEquals(row.mac, recordMac(row))) {
      throw Object.assign(new Error('this record does not match its host signature'), {code: ERROR_CODES.AUTHORIZATION_STORE_TAMPERED});
    }
    return row;
  }

  /** 读-改-写在同一次调用里完成：同一引用不会被第二次用掉。 */
  function consumeAuthorization(reference, op, now) {
    const rows = readVault();
    const index = rows.map((row) => row.authorization_ref).lastIndexOf(reference);
    if (index < 0) throw Object.assign(new Error(`${reference} was never issued`), {code: ERROR_CODES.AUTHORIZATION_UNKNOWN});
    const row = rows[index];
    if (!macEquals(row.mac, recordMac(row))) {
      throw Object.assign(new Error('this record does not match its host signature'), {code: ERROR_CODES.AUTHORIZATION_STORE_TAMPERED});
    }
    if (row.consumed_at) throw Object.assign(new Error(`${reference} was already used once`), {code: ERROR_CODES.AUTHORIZATION_CONSUMED});
    const updated = {...row, consumed_at: now, consumed_by_op: op};
    delete updated.mac;
    updated.mac = recordMac(updated);
    rows[index] = updated;
    writeVault(rows);
    return updated;
  }

  /** 与 commands.rs 的 target_fingerprint 同一规则：目录按树、记录级数据库改写按逻辑状态、其余按文件字节。 */
  async function fingerprintOf(target, kind) {
    try {
      const routed = route(target);
      if (kind === 'isolate_directory') return await routed.adapter.fingerprintDirectory(routed.path);
      if (!(await routed.adapter.exists(routed.path))) return null;
      if (DATABASE_ACTION_KINDS.includes(kind)) return await routed.adapter.fingerprintDatabase(routed.path);
      return await routed.adapter.fingerprint(routed.path);
    } catch {
      return null;
    }
  }

  async function userConfirm(request = {}) {
    const scope = AUTHORIZATION_SCOPES[request.scope];
    if (!scope) return {ok: false, code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: `unknown authorization scope ${request.scope}`};

    if (request.reuse === true && ['workspace_owned', 'preauthorized_protection'].includes(request.scope)) {
      const existing = readVault().reverse().find((row) => row.scope === request.scope
        && row.confirmed === true
        && Date.parse(row.expires_at) > Date.parse(clock())
        && (request.environment_ref === undefined || row.environment_ref === request.environment_ref));
      if (existing) {
        return {ok: true, authorization_ref: existing.authorization_ref, scope: existing.scope, expires_at: existing.expires_at, reused: true};
      }
    }

    if (scope.single_use && !scope.ops.includes(request.native_op)) {
      return {ok: false, code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: `scope ${request.scope} does not cover ${request.native_op}`};
    }

    const record = {scope: request.scope, consumed_at: null};
    for (const field of ['plan_ref', 'plan_version', 'action_id', 'action', 'native_op', 'environment_ref', 'session_ref']) {
      if (request[field] !== undefined) record[field] = request[field];
    }
    if (request.scope === 'single_confirmation') {
      const path = request.target?.path;
      if (!path) return {ok: false, code: ERROR_CODES.PAYLOAD_INVALID, reason: 'target.path is required'};
      const observed = await fingerprintOf(path, request.target?.kind);
      if (request.expected_sha256 !== undefined && request.expected_sha256 !== observed) {
        return {ok: false, code: ERROR_CODES.OBJECT_DRIFTED, reason: `${path} does not look the way this confirmation describes`};
      }
      record.target = {...request.target};
      record.expected_sha256 = observed;
    }

    const now = clock();
    const validity = Number.isFinite(request.validity_ms) ? request.validity_ms : 2 * 60 * 60 * 1000;
    const expiresAt = new Date(Date.parse(now) + validity).toISOString();
    // 窗口正文由宿主按已测得的事实拼出来；调用方说明单列一行并标明未经核实。
    const body = [
      `范围：${request.scope}`,
      `动作：${record.action ?? '（无）'}`,
      `原生操作：${record.native_op ?? '（无）'}`,
      `目标：${record.target?.path ?? '（本次不针对单个对象）'}`,
      `目标当前指纹：${record.expected_sha256 ?? '对象当前不存在'}`,
      `计划：${record.plan_ref ?? '（无）'} 版本 ${record.plan_version ?? '（无）'}`,
      `有效期至：${expiresAt}`,
      '',
      `调用方说明（未经本机核实）：${request.summary ?? '（调用方未提供说明）'}`,
    ].join('\n');
    const prompt = {
      title: '确认本次处理',
      body,
      scope: request.scope,
      native_op: record.native_op || null,
      target: record.target || null,
      observed_sha256: record.expected_sha256 ?? null,
      action: record.action || null,
      expires_at: expiresAt,
      caller_summary: request.summary || null,
    };
    confirmations.push(prompt);
    if (!(await confirmDecision(prompt))) {
      return {ok: false, code: ERROR_CODES.CONFIRMATION_DECLINED, reason: 'the local user did not confirm this operation'};
    }

    record.authorization_ref = `nat-${randomUUID().replaceAll('-', '')}`;
    record.confirmed = true;
    record.issued_at = now;
    record.expires_at = expiresAt;
    record.mac = recordMac(record);
    const rows = readVault();
    rows.push(record);
    writeVault(rows);
    return {ok: true, authorization_ref: record.authorization_ref, scope: record.scope, expires_at: record.expires_at, expected_sha256: record.expected_sha256 ?? null};
  }

  /** 站在原生侧复核目标指纹：确认之后对象漂移就拒绝写入。 */
  async function fingerprintProblem(target, grant) {
    if (!target) return null;
    const actual = await fingerprintOf(target, grant.target?.kind);
    if (grant.expected_sha256 === null) {
      return actual === null ? null : {ok: false, code: ERROR_CODES.OBJECT_DRIFTED, reason: `${target} is present but the authorization expects it absent`};
    }
    if (actual === null) return {ok: false, code: ERROR_CODES.OBJECT_DRIFTED, reason: `${target} is missing since the confirmation`};
    if (actual !== grant.expected_sha256) {
      return {ok: false, code: ERROR_CODES.OBJECT_DRIFTED, reason: `${target} changed after the confirmation`};
    }
    return null;
  }

  async function handle(op, payload, reference) {
    const spec = OPS[op];
    if (!spec) return {ok: false, code: ERROR_CODES.OP_UNKNOWN, reason: `unknown native op ${op}`};
    try {
      assertPayload(op, payload);
    } catch (error) {
      return {ok: false, code: error.code, reason: error.message};
    }
    // 只认保险库里带有效宿主签名的记录。
    let record = null;
    try {
      record = typeof reference === 'string' ? loadAuthorization(reference) : null;
    } catch (error) {
      return {ok: false, code: error.code, reason: error.message};
    }
    const problem = checkIssuedAuthorization(op, payload, record, clock(), typeof reference === 'string' ? reference : null);
    if (problem) return {ok: false, code: problem.code, reason: problem.reason};
    if (record && AUTHORIZATION_SCOPES[record.scope]?.fingerprint_must_match_object) {
      const drift = await fingerprintProblem(targetPathFor(op, payload), record);
      if (drift) return drift;
    }
    if (record && AUTHORIZATION_SCOPES[record.scope]?.single_use) {
      try {
        consumeAuthorization(reference, op, clock());
      } catch (error) {
        return {ok: false, code: error.code, reason: error.message};
      }
    }

    if (op === 'DescribeCapabilities') {
      return {
        ok: true,
        contract: 'steward-bridge-1',
        identity: {app_id: 'local.ai-environmental-steward.desktop'},
        groups: Object.keys(CAPABILITY_GROUPS),
        unimplemented: [],
        product: product && {
          ...product,
          ...(discovery ? {environments: discoveryView().discovered.environments, environment: declareEnvironment()} : {}),
          control: controlStatus(),
          control_base_url: controlStatus()?.status === 'ready' ? product.control_base_url : null,
          log_root: logs.dirs.host,
        },
      };
    }
    if (op === 'DiscoverEnvironment') return discoveryView();
    if (op === 'LogSources') return logs.sources();
    if (op === 'LogRead') return logs.read(payload.source_ref);
    if (op === 'AppLogAppend') return logs.appLogAppend(payload);
    if (op === 'LogExportWrite') return logs.exportWrite(payload);
    if (op === 'LogOpenFolder') return logs.openFolder(payload);
    if (op === 'NotifyCritical') return notifyCritical(payload);
    if (op.startsWith('BrowserDiag')) return browser.invoke(op, payload);
    if (op === 'AuthorizeRoots') {
      const refs = requestedRoots(payload);
      const chosen = [];
      for (const reference of refs) {
        const candidate = (discovery?.candidates || []).find((item) => item.root_ref === reference);
        if (!candidate) return {ok: false, code: 'NATIVE_ROOT_UNAVAILABLE', reason: `${reference} was not discovered on this machine`};
        if (candidate.authorizable !== true) return {ok: false, code: 'NATIVE_ROOT_UNAVAILABLE', reason: `${reference} cannot be authorized (${candidate.reason || candidate.status})`};
        chosen.push({root_ref: reference, path: candidate.path, kind: candidate.kind, client_ref: candidate.client_ref, category: candidate.category, environment_ref: 'windows-host', authorized_at: clock(), label: candidate.label});
      }
      const prompt = {
        title: '授权扫描范围',
        body: `允许本应用只读扫描下面这些位置：\n${chosen.map((item) => `• ${item.label}：${item.path}`).join('\n')}\n\n扫描只读取、不修改。清理或修改其中任何对象，仍会逐项请你确认。授权可以随时撤销。`,
        scope: 'authorized_roots',
        roots: refs,
      };
      confirmations.push(prompt);
      if (!(await confirmDecision(prompt))) return {ok: false, code: ERROR_CODES.CONFIRMATION_DECLINED, reason: 'the local user did not authorize these locations'};
      authorizedRoots = [...authorizedRoots.filter((item) => !refs.includes(item.root_ref)), ...chosen.map(({label: _label, ...rest}) => rest)]
        .sort((left, right) => left.root_ref.localeCompare(right.root_ref));
      return {ok: true, authorized_roots: authorizedRoots.map((item) => ({...item})), replaced_tampered_registry: false};
    }
    if (op === 'RevokeRoots') {
      const refs = requestedRoots(payload);
      authorizedRoots = authorizedRoots.filter((item) => !refs.includes(item.root_ref));
      return {ok: true, authorized_roots: authorizedRoots.map((item) => ({...item})), revoked: refs, replaced_tampered_registry: false};
    }
    if (op === 'ControlStatus') return {ok: true, control: controlStatus()};
    if (op === 'ControlSetupAdmin') {
      if (controlStatus()?.status !== 'ready') return {ok: false, code: 'CONTROL_NOT_READY', reason: '控制端尚未就绪，暂时不能完成首启'};
      if (!controlSetup) return {ok: false, code: 'CONTROL_SETUP_NOT_MANAGED', reason: '外部控制端的首次初始化须在控制端所在机器上完成'};
      return controlSetup({username: payload.username, password: payload.password});
    }
    if (op === 'SessionLoad') return sessionLoad();
    if (op === 'SessionSave') return sessionSave(payload);
    if (op === 'SessionClear') {
      const existed = existsSync(sessionFile);
      rmSync(sessionFile, {force: true});
      return {ok: true, cleared: existed};
    }
    if (op === 'EmergencyHosts') return {ok: true, hosts: emergencyHosts.map((item) => ({...item}))};
    if (op === 'EmergencyOpen') {
      const host = emergencyHosts.find((item) => item.id === payload.host_id);
      if (!host?.approved) return {ok: false, code: 'EMERGENCY_HOST_DENIED', reason: `${payload.host_id} is not an approved second browser`};
      const session = {session_id: payload.session_id, host_id: payload.host_id, pid: 4000 + openedSessions.size, expires_at: payload.expires_at, open: true};
      openedSessions.set(payload.session_id, session);
      return {ok: true, session};
    }
    if (op === 'EmergencyClose') {
      const opened = openedSessions.get(payload.session_id);
      if (!opened) return {ok: false, code: 'EMERGENCY_SESSION_UNKNOWN'};
      const closed = {...opened, open: false, process_stopped: true};
      openedSessions.set(payload.session_id, closed);
      return {ok: true, session: closed};
    }
    if (op === 'FileRead') {
      const target = route(payload.path);
      return {ok: true, bytes: encodeBytes(await target.adapter.readBytes(target.path))};
    }
    if (op === 'FileWrite') {
      const target = route(payload.path);
      await target.adapter.writeBytes(target.path, decodeBytes(payload.bytes));
      return {ok: true};
    }
    if (op === 'FileRemove') {
      const target = route(payload.path);
      await target.adapter.remove(target.path);
      return {ok: true};
    }
    if (op === 'FileCopy') {
      if (isRealPath(payload.from) || isRealPath(payload.to)) return {ok: false, code: ERROR_CODES.CAPABILITY_UNIMPLEMENTED, reason: 'this double copies only inside the workspace'};
      await adapter.copy(payload.from, payload.to);
      return {ok: true};
    }
    if (op === 'FileExists') {
      const target = route(payload.path);
      return {ok: true, exists: await target.adapter.exists(target.path)};
    }
    if (op === 'FileWalk') return {ok: true, entries: await walkRouted(payload.prefixes)};
    if (op === 'DirIsolate') {
      if (isRealPath(payload.from)) {
        await isolateRealDirectory(payload.from, payload.to);
        return {ok: true};
      }
      await adapter.isolateDirectory(payload.from, payload.to);
      return {ok: true};
    }
    if (op === 'DirPreviewRestore') {
      if (isRealPath(payload.target_path)) return {ok: true, ...(await previewRealRestore(payload.isolation_path, payload.target_path))};
      return {ok: true, ...(await adapter.previewDirectoryRestore(payload.isolation_path, payload.target_path))};
    }
    if (op === 'DirRestore') {
      if (isRealPath(payload.target_path)) {
        const preview = await previewRealRestore(payload.isolation_path, payload.target_path);
        if (!preview.recoverable) throw Object.assign(new Error('isolated directory cannot be restored without overwrite'), {code: 'RESTORE_CONFLICT'});
        await cp(absoluteOf(payload.isolation_path), absoluteOf(payload.target_path), {recursive: true});
        return {ok: true, restored: preview.entries};
      }
      return {ok: true, ...(await adapter.restoreDirectoryIsolation(payload.isolation_path, payload.target_path))};
    }

    if (op === 'RecordsLoad') {
      const store = readStore();
      return {ok: true, records: store.records, backups: store.backups};
    }
    if (op === 'RecordSave') {
      const store = readStore();
      const index = store.records.findIndex((row) => row.type === payload.type && row.id === payload.id);
      const created = index >= 0 ? store.records[index].created_at : payload.now;
      const row = {type: payload.type, id: payload.id, payload: payload.payload, created_at: created, updated_at: payload.now};
      if (index >= 0) store.records[index] = row;
      else store.records.push(row);
      writeStore(store);
      return {ok: true};
    }
    if (op === 'BackupSave') {
      const store = readStore();
      store.backups = store.backups.filter((row) => row.backup_ref !== payload.backup_ref);
      store.backups.push({
        backup_ref: payload.backup_ref,
        action_id: payload.action_id,
        payload_path: payload.payload_path,
        metadata: payload.metadata,
        created_at: payload.now,
      });
      writeStore(store);
      return {ok: true};
    }

    if (op === 'DbInspect') {
      const target = route(payload.path);
      return {ok: true, ...(await target.adapter.inspectDatabase(target.path, payload.kind))};
    }
    if (op === 'DbMutate') {
      const target = route(payload.path);
      return {ok: true, ...(await target.adapter.mutateDatabase(target.path, payload.kind, payload.selector))};
    }
    if (op === 'DbFingerprint') {
      const target = route(payload.path);
      return {ok: true, sha256: await target.adapter.fingerprintDatabase(target.path)};
    }
    if (op === 'DbSnapshot') {
      const target = route(payload.path);
      const snapshot = await target.adapter.snapshotDatabase(target.path);
      return {ok: true, bytes: encodeBytes(snapshot.bytes), sha256: snapshot.sha256};
    }
    if (op === 'DbSimulate') {
      const target = route(payload.path);
      return {ok: true, sha256: await target.adapter.simulateDatabaseMutation(target.path, payload.kind, payload.selector, payload.prior_mutations || [])};
    }
    if (op === 'DbPreviewRestore') {
      const target = route(payload.path);
      return {ok: true, ...(await target.adapter.previewDatabaseRestore(target.path, payload.kind, payload.selector, decodeBytes(payload.backup_bytes)))};
    }
    if (op === 'DbRestore') {
      const target = route(payload.path);
      return {ok: true, ...(await target.adapter.restoreDatabaseMutation(target.path, payload.kind, payload.selector, decodeBytes(payload.backup_bytes)))};
    }

    // 站在「宿主 + 产品网络服务」的位置：形状按 Rust network_runtime 的回执，结论取注入的 network 钩子，不自己判生效。
    if (op === 'ReadNetworkState') {
      if (!network?.readState) return {ok: false, code: 'SERVICE_UNREACHABLE', runtime: {service: {status: 'UNREACHABLE'}}};
      return {ok: true, service: {link: 'READY'}, runtime: await network.readState(payload)};
    }
    if (op === 'ApplyNetworkPlan') {
      const result = await network?.apply?.(payload, reference);
      return result ? {...result, ok: result.ok === true} : {ok: false, code: 'SERVICE_UNREACHABLE'};
    }
    if (op === 'ProtectEnvironment') {
      const result = await network?.protect?.(payload, reference);
      if (!result) return {ok: false, code: 'SERVICE_UNREACHABLE'};
      const protection = result.protection || result;
      return {
        ok: protection.new_connections_restricted === true,
        code: result.code || null,
        protection,
        close_existing: result.close_existing || {status: 'SKIPPED', reason: 'NOT_REQUESTED'},
      };
    }
    if (op === 'NetworkLifecycle') {
      const result = await network?.lifecycle?.(payload, reference);
      return result ? {...result, ok: result.ok === true} : {ok: false, code: 'SERVICE_UNREACHABLE'};
    }

    return {ok: false, code: ERROR_CODES.CAPABILITY_UNIMPLEMENTED, reason: `${op} is declared but not implemented by this host`};
  }

  return {
    adapter,
    realAdapter,
    logs,
    notices: noticeState,
    browserHost: browser,
    authorizedRoots: () => authorizedRoots.map((item) => ({...item})),
    calls,
    openedSessions,
    confirmations,
    vaultRoot,
    vaultFile,
    sessionFile,
    issuedAuthorizations: {
      get: (reference) => { try { return loadAuthorization(reference); } catch { return null; } },
      list: () => readVault(),
    },
    /** 对应真实宿主的 steward_user_confirm 命令。 */
    confirm: userConfirm,
    async invoke(op, payload = {}, reference = null) {
      let record = null;
      try { record = typeof reference === 'string' ? loadAuthorization(reference) : null; } catch { record = null; }
      calls.push({op, authorizationRef: typeof reference === 'string' ? reference : null, scope: record?.scope || null, authorization: record});
      const intercepted = await hooks[op]?.({op, payload, reference, record});
      if (intercepted) {
        logs.recordOutcome(op, intercepted);
        return intercepted;
      }
      let result;
      try {
        result = await handle(op, payload, reference);
      } catch (error) {
        // 桥接错误要回成明确状态，不能吞成 ok:true，也不能只丢一个未分类的异常。
        const code = error.code || (String(error.message || '').startsWith('OUT_OF_SCOPE') ? ERROR_CODES.OUT_OF_SCOPE : ERROR_CODES.IO_FAILED);
        result = {ok: false, code, reason: error.message};
        logs.recordOutcome(op, result);
        return result;
      }
      if (result?.ok === false && result.code === undefined) result.code = ERROR_CODES.IO_FAILED;
      logs.recordOutcome(op, result);
      return result;
    },
  };
}
