import {DATABASE_ACTION_KINDS, nativeOpForAction} from '../../../apps/desktop-host/bridge-contract.mjs';
import {applyCleanupToDocument, canonicalize, isProtectedUnchanged, parseFieldPath, removeByPath} from '../../../apps/desktop-ui/cleanupCore.shared.mjs';
import {LOCAL_RULESET_VERSION, makeMarkdownReport, redactForExport, scoreProblems} from './rules.mjs';
import {REAL_JSON_ROLES, ccSwitchSources, isClaudeSiteHost, readRealJson, siteLoginIdentity} from './realFormats.mjs';

const PROTECTED_NAMES = /(?:project|memory|skills?|hooks?|mcp|audit|daily.?report|active.?log)/i;
const REMOVABLE_JSON_KEYS = new Set(['legacyProvider', 'legacyCredential', 'legacyProxy', 'deprecatedProvider']);
const DATABASE_ACTIONS = new Set(DATABASE_ACTION_KINDS);
const DATABASE_OBJECT_KINDS = new Set(['cookie_sqlite', 'cc_switch_sqlite']);
const SECRET_KEYS = /(?:token|cookie|password|secret|private.?key|credential)/i;
const CODE_ENV_FIELDS = new Set([
  'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY', 'ANTHROPIC_MODEL',
  'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_OPUS_MODEL',
]);
const BUSINESS_CATEGORIES = new Set([
  'cache_and_logs', 'login_account_material', 'third_party_configuration', 'session_and_work_material', 'old_backup_and_isolation',
]);

function digest(value) {
  const text = String(value);
  let state = 2166136261;
  for (let index = 0; index < text.length; index += 1) state = Math.imul(state ^ text.charCodeAt(index), 16777619);
  return (state >>> 0).toString(16).padStart(8, '0').repeat(8);
}

function serviceError(code, message) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  return error;
}

function nowId(prefix) {
  const suffix = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${suffix}`;
}

const textDecoder = new TextDecoder();

function decodeBytes(value) {
  return textDecoder.decode(value);
}

function jsonText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function objectKind(relativePath) {
  const lower = relativePath.toLowerCase();
  if (lower.endsWith('.sqlite') && lower.includes('cc-switch')) return 'cc_switch_sqlite';
  if (lower.endsWith('.sqlite') && lower.includes('cookie')) return 'cookie_sqlite';
  if (lower.endsWith('.sqlite')) return 'unsupported_sqlite';
  if (lower.endsWith('.json')) return 'json';
  if (lower.endsWith('.jsonl')) return 'jsonl';
  if (/\.(?:log|txt|md)$/i.test(lower)) return 'text';
  return 'unsupported';
}

function categoriesForPath(relativePath, kind = objectKind(relativePath), clientCategory = null) {
  const categories = new Set();
  // 真实根按发现声明的客户端类别归类，目录名里没有 third-party 这类字样。
  if (clientCategory === 'third_party') categories.add('third_party_configuration');
  if (clientCategory === 'old_backup') categories.add('old_backup_and_isolation');
  if (clientCategory === 'browser_profile') categories.add('session_and_work_material');
  // 真实 Chromium Cookie 库与 CC Switch 库没有可辨认的扩展名，类别按发现声明的类型补上。
  if (kind === 'cookie_sqlite' || kind === 'cc_switch_sqlite') categories.add('login_account_material');
  if (kind === 'cc_switch_sqlite') categories.add('third_party_configuration');
  if (/(?:cache|\.log$)/i.test(relativePath)) categories.add('cache_and_logs');
  if (/(?:cookies\.sqlite|cc-switch\.sqlite|settings(?:-add)?\.json)/i.test(relativePath)) categories.add('login_account_material');
  if (/(?:third-party|cc-switch)/i.test(relativePath)) categories.add('third_party_configuration');
  if (/(?:browser|session|workspace|wsl)/i.test(relativePath) || kind === 'cookie_sqlite') categories.add('session_and_work_material');
  if (/(?:backup|isolation)/i.test(relativePath)) categories.add('old_backup_and_isolation');
  return categories;
}

function getNested(root, dottedPath) {
  return dottedPath.split('.').reduce((value, part) => (value && typeof value === 'object' ? value[part] : undefined), root);
}

function removeNested(root, dottedPath) {
  return removeByPath(root, parseFieldPath(dottedPath));
}

function setNested(root, dottedPath, value) {
  const parts = dottedPath.split('.');
  let cursor = root;
  for (let index = 0; index < parts.length - 1; index += 1) {
    const part = parts[index];
    if (!cursor[part] || typeof cursor[part] !== 'object' || Array.isArray(cursor[part])) cursor[part] = {};
    cursor = cursor[part];
  }
  if (Object.hasOwn(cursor, parts.at(-1))) return false;
  cursor[parts.at(-1)] = value;
  return true;
}

function upsertNested(root, dottedPath, value) {
  const parts = dottedPath.split('.');
  let cursor = root;
  for (let index = 0; index < parts.length - 1; index += 1) {
    if (!cursor || typeof cursor !== 'object' || Array.isArray(cursor) || !Object.hasOwn(cursor, parts[index])) return false;
    cursor = cursor[parts[index]];
  }
  if (!cursor || typeof cursor !== 'object' || Array.isArray(cursor)) return false;
  if (JSON.stringify(canonicalize(cursor[parts.at(-1)])) === JSON.stringify(canonicalize(value))) return false;
  cursor[parts.at(-1)] = structuredClone(value);
  return true;
}

function containsProtectedDescendant(value) {
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, child]) => PROTECTED_NAMES.test(key) || containsProtectedDescendant(child));
}

function collectJsonFacts(value, prefix = '', collected = {identities: new Set(), protected_paths: [], removable_paths: [], removable_items: [], repair_items: [], pointer_items: [], source_backed_fields: []}) {
  if (!value || typeof value !== 'object') return collected;
  for (const [key, child] of Object.entries(value)) {
    const childPath = prefix ? `${prefix}.${key}` : key;
    if (PROTECTED_NAMES.test(key)) collected.protected_paths.push(childPath);
    if (REMOVABLE_JSON_KEYS.has(key)) {
      collected.removable_paths.push(childPath);
      collected.removable_items.push({
        field_path: childPath,
        identity_ref: identityFromValue(child),
        contains_protected: containsProtectedDescendant(child),
        linked_provider_ids: collectProviderIds(child),
      });
    }
    if (key === 'providerMode' && child === 'legacy') {
      collected.repair_items.push({field_path: childPath, expected_value: 'legacy', value: 'managed'});
    }
    if (key === 'legacyProvider' && prefix === '' && !Object.hasOwn(value, 'providerMode')) {
      collected.repair_items.push({field_path: prefix ? `${prefix}.providerMode` : 'providerMode', expected_missing: true, value: 'managed'});
    }
    if ((key === 'providerRef' || key === 'provider_id') && typeof child === 'string') {
      collected.pointer_items.push({field_path: childPath, provider_id: child});
    }
    if ((key === 'identity_ref' || key === 'identityRef') && typeof child === 'string') collected.identities.add(child);
    if (prefix === 'env' && key === 'ANTHROPIC_AUTH_TOKEN' && typeof child === 'string' && child.trim()) {
      collected.source_backed_fields.push({field_path: childPath, source_kind: 'credential'});
    }
    collectJsonFacts(child, childPath, collected);
  }
  return collected;
}

function collectProviderIds(value, collected = new Set()) {
  if (!value || typeof value !== 'object') return [...collected];
  for (const [key, child] of Object.entries(value)) {
    if ((key === 'providerRef' || key === 'provider_id') && typeof child === 'string') collected.add(child);
    collectProviderIds(child, collected);
  }
  return [...collected].sort();
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function validateSourceBackedJsonShape(value, declaration) {
  if (!declaration || !isPlainObject(value)) return {valid: false, message: 'declared JSON source shape must be an object'};
  if (declaration.role === 'claude_code_settings') {
    // 真实 settings.json 可以没有 env；有 env 时必须是对象。
    if (Object.hasOwn(value, 'env') && !isPlainObject(value.env)) return {valid: false, message: 'Claude Code settings env must be an object'};
  } else if (declaration.role === 'desktop_profile') {
    if (typeof declaration.profile_id !== 'string' || !declaration.profile_id || !isPlainObject(value)) {
      return {valid: false, message: 'Desktop profile requires a declared profile id'};
    }
  } else if (declaration.role === 'desktop_meta') {
    if (!Array.isArray(value.entries) || typeof value.appliedId !== 'string') {
      return {valid: false, message: 'Desktop meta requires entries and appliedId'};
    }
    return {valid: true, applied_profile_id: value.appliedId};
  } else if (!Object.hasOwn(REAL_JSON_ROLES, declaration.role)) {
    return {valid: false, message: 'declared JSON role is not supported'};
  }
  return {valid: true};
}

function supportedJsonSelector(role, fieldPath) {
  if (Object.hasOwn(REAL_JSON_ROLES, role)) return REAL_JSON_ROLES[role].includes(fieldPath);
  const topLevel = fieldPath?.split('.')[0];
  const leaf = fieldPath?.split('.').at(-1);
  return role === 'claude_code_settings'
    ? topLevel === 'env' && CODE_ENV_FIELDS.has(leaf)
    : role === 'desktop_profile' && ['inferenceGatewayBaseUrl', 'inferenceGatewayApiKey'].includes(fieldPath);
}

function identityFromValue(value) {
  if (!value || typeof value !== 'object') return null;
  return value.identity_ref || value.identityRef || null;
}

function pathIsProtected(dottedPath, protectedPaths) {
  return protectedPaths.some((protectedPath) => dottedPath === protectedPath || dottedPath.startsWith(`${protectedPath}.`));
}

function sourceIdentityAssociation(environment, relativePath, fieldPath) {
  const associations = environment.identity_associations;
  if (!associations) return null;
  let association = null;
  if (Array.isArray(associations)) {
    association = associations.find((entry) => entry?.relative_path === relativePath && entry?.field_path === fieldPath) || null;
  } else {
    const byPath = associations[relativePath];
    association = Array.isArray(byPath)
      ? byPath.find((entry) => entry?.field_path === fieldPath) || null
      : byPath?.[fieldPath] || null;
  }
  if (!association || typeof association !== 'object') return null;
  const identityRef = association.identity_ref || association.identityRef || null;
  const providerId = association.provider_id || association.providerId || null;
  return identityRef && providerId ? {identity_ref: identityRef, provider_id: providerId} : null;
}

function legacyPathSegments(fieldPath) {
  return fieldPath.split('.').flatMap((part) => part.endsWith('[]') ? [part.slice(0, -2), '[]'] : [part]);
}

function sameCanonicalValue(left, right) {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
}

function legacyFieldIsAbsent(document, fieldPath) {
  const visit = (value, segments, index) => {
    if (segments[index] === '[]') return Array.isArray(value) && value.every((entry) => visit(entry, segments, index + 1));
    if (!value || typeof value !== 'object' || Array.isArray(value)) return true;
    const key = segments[index];
    if (index === segments.length - 1) return !Object.hasOwn(value, key);
    return !Object.hasOwn(value, key) || visit(value[key], segments, index + 1);
  };
  return visit(document, legacyPathSegments(fieldPath), 0);
}

function mergeLegacyField(before, current, fieldPath) {
  const conflicts = [];
  const segments = legacyPathSegments(fieldPath);
  const visit = (original, live, index, location) => {
    const segment = segments[index];
    if (segment === '[]') {
      if (!Array.isArray(original) || !Array.isArray(live) || original.length !== live.length) {
        conflicts.push({code: 'RESTORE_CONFLICT', field_path: fieldPath, message: `${location}: array structure changed`});
        return;
      }
      original.forEach((item, itemIndex) => visit(item, live[itemIndex], index + 1, `${location}[${itemIndex}]`));
      return;
    }
    if (!original || typeof original !== 'object' || Array.isArray(original) || !live || typeof live !== 'object' || Array.isArray(live)) {
      conflicts.push({code: 'RESTORE_CONFLICT', field_path: fieldPath, message: `${location}: parent structure changed`});
      return;
    }
    if (index === segments.length - 1) {
      if (!Object.hasOwn(original, segment)) {
        return;
      } else if (Object.hasOwn(live, segment) && !sameCanonicalValue(live[segment], original[segment])) {
        conflicts.push({code: 'RESTORE_CONFLICT', field_path: fieldPath, message: `${location}: target field now has a different value`});
      } else {
        live[segment] = structuredClone(original[segment]);
      }
      return;
    }
    if (!Object.hasOwn(original, segment) || !Object.hasOwn(live, segment)) {
      conflicts.push({code: 'RESTORE_CONFLICT', field_path: fieldPath, message: `${location}: parent field is absent`});
      return;
    }
    visit(original[segment], live[segment], index + 1, location ? `${location}.${segment}` : segment);
  };
  visit(before, current, 0, 'root');
  return conflicts;
}

function previewLegacyRestore(before, current, action) {
  const proposed = structuredClone(current);
  const conflicts = [];
  for (const fieldPath of action.selector.requested_removals || []) {
    conflicts.push(...mergeLegacyField(before, proposed, fieldPath));
  }
  return {recoverable: conflicts.length === 0, conflicts, proposed};
}

function legacyP0BridgeKey({file, approvedRemovals, requestedRemovals}) {
  return digest(JSON.stringify({
    file,
    approved_removals: [...approvedRemovals].sort(),
    requested_removals: [...requestedRemovals].sort(),
  }));
}

function sameCookieSelector(left, right) {
  return ['host_key', 'top_frame_site_key', 'has_cross_site_ancestor', 'name', 'path', 'source_scheme', 'source_port']
    .every((key) => left?.[key] === right?.[key]);
}

function matchesSiteEntry(entry, selector) {
  return entry.entry_id === selector.entry_id
    && entry.profile_ref === selector.profile_ref
    && entry.site === selector.site
    && entry.storage_type === selector.storage_type;
}

/** 路径是否落在一个扫描范围内：等于范围本身，或在它下面。 */
function withinScope(relativePath, scope) {
  const prefix = String(scope || '').replace(/\/+$/, '');
  return Boolean(prefix) && (relativePath === prefix || relativePath.startsWith(`${prefix}/`));
}

/**
 * 可改写的对象只有两类：测试工作区里的合成输入，和当前环境声明授权扫描的真实根（`roots/…`）。
 * 真实根的授权撤销后，已确认但未执行的动作在这里被拒。
 */
function assertActionTarget(action, environment) {
  const path = action.relative_path;
  const synthetic = path.startsWith('input/');
  const authorizedReal = path.startsWith('roots/')
    && (Array.isArray(environment?.scopes) ? environment.scopes : []).some((scope) => String(scope).startsWith('roots/') && withinScope(path, scope));
  if (!synthetic && !authorizedReal) throw serviceError('OUT_OF_SCOPE', 'only discovered objects inside an authorized scope can be changed');
  if (action.selector?.field_path && PROTECTED_NAMES.test(action.selector.field_path)) {
    throw serviceError('OUT_OF_SCOPE', 'project, memory, configuration, hook and audit fields are protected');
  }
}

function actionDigest(plan) {
  return digest(JSON.stringify(plan.actions.map((action) => ({
    action_id: action.action_id,
    kind: action.kind,
    relative_path: action.relative_path,
    before: action.expected_before_sha256,
    after: action.expected_after_sha256,
    selector: action.selector,
    account_answer_id: action.account_answer_id,
    account_answer_version: action.account_answer_version,
    dependencies: action.dependencies,
  }))));
}

function errorReceipt(action, error) {
  return {
    action_id: action.action_id,
    status: 'FAILED',
    code: error.code || 'EXECUTION_FAILED',
    message: error.message,
  };
}

/** 单次具体确认的有效期：过期后原生侧拒绝写入，需要重新确认。 */
const CONFIRMATION_VALIDITY_MS = 2 * 60 * 60 * 1000;

/** 超过这个大小的文本或 JSON 不读入内容、不取指纹，记成缺口；真实目录里的大文件不能拖垮一次扫描。 */
const MAX_CONTENT_BYTES = 4 * 1024 * 1024;
/** 发现声明了角色的 JSON（如 .claude.json）承载身份，项目历史多时会超过普通上限，单独放宽。 */
const MAX_DECLARED_JSON_BYTES = 32 * 1024 * 1024;

export function createLocalService({adapter, environment = {}, capabilities = {}}) {
  if (!adapter || typeof adapter.inspectDatabase !== 'function' || typeof adapter.mutateDatabase !== 'function' || typeof adapter.hashBytes !== 'function') {
    throw serviceError('ADAPTER_REQUIRED', 'createLocalService requires an explicit local adapter');
  }
  const blocked = new Set(capabilities.blocked_paths || []);
  const busy = new Set(capabilities.busy_paths || []);

  /** 数据库对象只认经 SQLite 读出的逻辑状态（含 WAL 里已提交的内容）；适配器给不了就不处理，不退回主文件字节。 */
  function databaseCapability(name) {
    if (typeof adapter[name] !== 'function') throw serviceError('ADAPTER_INCOMPLETE', `local adapter does not provide ${name} for SQLite objects`);
    return adapter[name].bind(adapter);
  }

  async function fingerprintObject(relativePath, kind) {
    return DATABASE_OBJECT_KINDS.has(kind) ? databaseCapability('fingerprintDatabase')(relativePath) : adapter.fingerprint(relativePath);
  }

  async function fingerprintAction(action) {
    if (action.kind === 'isolate_directory') return adapter.fingerprintDirectory(action.relative_path);
    if (DATABASE_ACTIONS.has(action.kind)) return databaseCapability('fingerprintDatabase')(action.relative_path);
    return adapter.fingerprint(action.relative_path);
  }

  async function discover(options = {}) {
    const mode = options.mode || 'deep';
    if (!['deep', 'quick', 'focused'].includes(mode)) throw serviceError('INVALID_SCAN_MODE', 'mode must be deep, quick or focused');
    const scopes = options.scopes || environment.scopes || ['input'];
    if (!Array.isArray(scopes) || !scopes.length) {
      throw serviceError('SCOPE_NOT_AUTHORIZED', 'no scan scope is authorized yet; authorize the discovered locations first');
    }
    const entries = await adapter.walk(scopes);
    const declaredClients = Array.isArray(environment.clients) ? environment.clients : [];
    const jsonShapeByPath = new Map((environment.json_shapes || []).map((entry) => [entry.relative_path, entry]));
    const declaredKinds = new Map((environment.object_kinds || []).map((entry) => [entry.relative_path, entry.kind]));
    const siteHosts = Array.isArray(environment.site_hosts) ? environment.site_hosts.map((host) => String(host).toLowerCase()) : null;
    const identityDetails = new Map();
    const pendingCredentials = [];
    const unsupportedByDirectory = new Map();
    const defaultProfileRef = environment.default_browser?.profile_ref || environment.default_profile_ref || null;
    const selectedProfileRefs = new Set(options.profileRefs || environment.selected_profile_refs || (defaultProfileRef ? [defaultProfileRef] : []));
    const relationByPath = environment.object_relations && typeof environment.object_relations === 'object' ? environment.object_relations : {};
    const priorScan = mode === 'quick' && options.priorScanId ? findScan(options.priorScanId) : null;
    const selectedKinds = options.kinds ? new Set(options.kinds) : null;
    if (selectedKinds && [...selectedKinds].some((kind) => !['json', 'jsonl', 'text', 'cc_switch_sqlite', 'cookie_sqlite'].includes(kind))) {
      throw serviceError('INVALID_FOCUSED_TYPE', 'focused scan requested an unsupported object kind');
    }
    const selectedCategories = options.categories ? new Set(options.categories) : null;
    if (selectedCategories && (!selectedCategories.size || [...selectedCategories].some((category) => !BUSINESS_CATEGORIES.has(category)))) {
      throw serviceError('INVALID_FOCUSED_CATEGORY', 'focused scan requested an unsupported business category');
    }
    const criticalPaths = new Set(options.criticalPaths || environment.critical_paths || []);
    const objects = [];
    const gaps = (Array.isArray(environment.gaps) ? environment.gaps : [])
      .filter((gap) => gap && typeof gap.code === 'string')
      .map((gap) => ({code: gap.code, message: String(gap.message || gap.code)}));
    const evidence = [];
    const environmentEvidence = declaredClients.map((client) => ({
      client_ref: client.client_ref || null,
      environment_ref: client.environment_ref || environment.environment_ref || 'windows-synthetic',
      installed: client.installed !== false,
      authorized: client.authorized !== false,
      profile_refs: client.profile_refs || [],
    }));
    for (const client of environmentEvidence) {
      if (!client.installed) gaps.push({code: 'CLIENT_NOT_INSTALLED', message: `${client.client_ref || 'client'} is declared not installed`});
      else if (!client.authorized) gaps.push({code: 'CLIENT_NOT_AUTHORIZED', message: `${client.client_ref || 'client'} is outside the selected synthetic authorization`});
    }
    let processed = 0;
    for (const entry of entries) {
      if (entry.status !== 'found') {
        gaps.push({code: entry.status.toUpperCase(), message: `${entry.relative_path}: ${entry.status}`});
        continue;
      }
      const kind = declaredKinds.get(entry.relative_path) || (jsonShapeByPath.has(entry.relative_path) ? 'json' : objectKind(entry.relative_path));
      if (mode === 'focused' && selectedKinds && !selectedKinds.has(kind)) continue;
      const pathClient = declaredClients.find((candidate) => candidate.path_prefix && withinScope(entry.relative_path, candidate.path_prefix));
      if (selectedCategories && ![...categoriesForPath(entry.relative_path, kind, pathClient?.category)].some((category) => selectedCategories.has(category))) continue;
      await Promise.resolve();
      if (options.signal?.aborted || (Number.isInteger(options.cancelAfter) && processed >= options.cancelAfter)) {
        gaps.push({code: 'SCAN_CANCELLED', message: `not read: ${entry.relative_path}`});
        continue;
      }
      const object = {
        object_ref: `obj-${digest(entry.relative_path).slice(0, 16)}`,
        relative_path: entry.relative_path,
        kind,
        source_ref: environment.source_ref || 'synthetic-local-fixture-v1',
        status: 'found',
        size: entry.size,
        environment_ref: entry.relative_path.includes('/wsl/') ? 'wsl-synthetic' : 'windows-synthetic',
        profile_ref: /browser\/([^/]+)/.exec(entry.relative_path)?.[1] || null,
        client_ref: null,
        client_category: null,
        identities: [],
        protected_paths: [],
        removable_paths: [],
        removable_items: [],
      };
      const client = declaredClients.find((candidate) => candidate.profile_refs?.includes(object.profile_ref)
        || (candidate.path_prefix && withinScope(entry.relative_path, candidate.path_prefix)));
      if (client) {
        object.client_ref = client.client_ref || null;
        object.environment_ref = client.environment_ref || object.environment_ref;
        if (!object.profile_ref && client.profile_ref) object.profile_ref = client.profile_ref;
        object.client_category = client.category || null;
      }
      if (client && (client.installed === false || client.authorized === false)) {
        object.status = client.installed === false ? 'not_installed' : 'not_authorized';
        object.read = false;
        gaps.push({
          code: client.installed === false ? 'CLIENT_NOT_INSTALLED' : 'CLIENT_NOT_AUTHORIZED',
          message: `${object.client_ref || entry.relative_path}: excluded before content and fingerprint reads`,
        });
        objects.push(object);
        evidence.push({relative_path: entry.relative_path, read: false, observed_at: null, client_ref: object.client_ref, authorized: false});
        processed += 1;
        continue;
      }
      if (object.profile_ref && selectedProfileRefs.size && !selectedProfileRefs.has(object.profile_ref)) {
        object.status = 'not_selected';
        object.read = false;
        gaps.push({code: 'PROFILE_NOT_SELECTED', message: `${object.profile_ref}: discovered but not selected for a deep scan`});
        objects.push(object);
        evidence.push({relative_path: entry.relative_path, read: false, observed_at: null, profile_ref: object.profile_ref, selected: false});
        processed += 1;
        continue;
      }
      // 没有解析器的格式（缓存块、LevelDB 等）只登记存在与大小，不读内容、不取指纹，缺口按目录合并。
      if (kind === 'unsupported' || kind === 'unsupported_sqlite') {
        object.status = 'unsupported';
        object.read = false;
        const directory = entry.relative_path.split('/').slice(0, -1).join('/') || entry.relative_path;
        unsupportedByDirectory.set(directory, (unsupportedByDirectory.get(directory) || 0) + 1);
        objects.push(object);
        evidence.push({relative_path: entry.relative_path, read: false, observed_at: null});
        processed += 1;
        continue;
      }
      const contentLimit = jsonShapeByPath.has(entry.relative_path) ? MAX_DECLARED_JSON_BYTES : MAX_CONTENT_BYTES;
      if (['json', 'jsonl', 'text'].includes(kind) && Number(entry.size) > contentLimit) {
        object.status = 'too_large';
        object.read = false;
        gaps.push({code: 'OBJECT_TOO_LARGE', message: `${entry.relative_path}: ${entry.size} bytes exceeds the content read limit`});
        objects.push(object);
        evidence.push({relative_path: entry.relative_path, read: false, observed_at: null});
        processed += 1;
        continue;
      }
      try {
        object.sha256 = await fingerprintObject(entry.relative_path, kind);
        const priorObject = priorScan?.objects.find((item) => item.relative_path === entry.relative_path);
        const criticalRechecked = criticalPaths.has(entry.relative_path);
        if (mode === 'quick' && priorObject?.sha256 === object.sha256 && !criticalRechecked) {
          const reused = structuredClone(priorObject);
          reused.read = false;
          reused.critical_rechecked = false;
          objects.push(reused);
          evidence.push({relative_path: entry.relative_path, read: false, observed_at: priorObject.observed_at, critical_rechecked: false});
          processed += 1;
          options.onProgress?.({completed: processed, total: entries.length, relative_path: entry.relative_path, read: false});
          continue;
        }
        object.read = true;
        object.critical_rechecked = criticalRechecked;
        object.observed_at = adapter.clock();
        if (kind === 'json') {
          const value = JSON.parse(decodeBytes(await adapter.readBytes(entry.relative_path)));
          const facts = collectJsonFacts(value);
          object.identities = [...facts.identities].sort();
          object.protected_paths = facts.protected_paths.sort();
          object.removable_paths = facts.removable_paths.sort();
          object.removable_items = facts.removable_items;
          object.repair_items = facts.repair_items;
          object.pointer_items = facts.pointer_items;
          object.source_backed_fields = facts.source_backed_fields;
          object.json_top_level_keys = value && typeof value === 'object' && !Array.isArray(value)
            ? Object.keys(value).sort() : [];
          object.site_storage_entries = Array.isArray(value?.entries)
            ? value.entries.map((entryValue) => ({
              entry_id: entryValue.entry_id,
              profile_ref: entryValue.profile_ref,
              site: entryValue.site,
              storage_type: entryValue.storage_type,
              identity_ref: entryValue.identity_ref,
            })) : [];
          object.cookie_database_ref = typeof value?.cookie_database_ref === 'string' ? value.cookie_database_ref : null;
          object.cookie_associations = Array.isArray(value?.cookie_associations)
            ? value.cookie_associations.map((association) => ({
              profile_ref: association.profile_ref,
              identity_ref: association.identity_ref,
              selector: association.selector,
            })) : [];
          if (Object.hasOwn(value || {}, 'schema_version') && value.schema_version !== 'synthetic-v1') {
            object.status = 'unsupported';
            gaps.push({code: 'UNSUPPORTED_FORMAT', message: `${entry.relative_path}: declared JSON schema is not supported`});
          }
          const declaration = jsonShapeByPath.get(entry.relative_path);
          if (declaration) {
            const shape = validateSourceBackedJsonShape(value, declaration);
            if (!shape.valid) {
              object.status = 'unsupported';
              gaps.push({code: 'UNSUPPORTED_FORMAT', message: `${entry.relative_path}: ${shape.message}`});
            } else {
              object.json_shape = declaration.role;
              object.desktop_profile_id = declaration.profile_id || null;
              object.desktop_meta_applied_id = shape.applied_profile_id || null;
              object.desktop_meta_path = declaration.meta_path || null;
              object.supported_json_selectors = declaration.role === 'claude_code_settings'
                ? [...CODE_ENV_FIELDS].map((field) => `env.${field}`)
                : REAL_JSON_ROLES[declaration.role]?.slice() || ['inferenceGatewayBaseUrl', 'inferenceGatewayApiKey'];
              const real = readRealJson(declaration.role, value);
              for (const identity of real.identities) identityDetails.set(identity.identity_ref, identity);
              object.identities = [...new Set([...object.identities, ...real.identities.map((identity) => identity.identity_ref)])].sort();
              object.removable_items.push(...real.direct_items.map((item) => ({
                field_path: item.field_path,
                identity_ref: item.identity_ref,
                contains_protected: false,
                linked_provider_ids: [],
                evidence: item.evidence,
              })));
              object.removable_paths = [...new Set([...object.removable_paths, ...real.direct_items.map((item) => item.field_path)])].sort();
              if (real.credential_items.length) pendingCredentials.push({object, items: real.credential_items});
              object.third_party_sources = real.third_party_sources;
            }
          }
        } else if (kind.endsWith('sqlite')) {
          Object.assign(object, await adapter.inspectDatabase(object.relative_path, object.kind));
          object.identities = kind === 'cc_switch_sqlite'
            ? object.providers.map((provider) => provider.identity_ref).filter(Boolean)
            : object.cookies.map((cookie) => cookie.identity_ref).filter(Boolean);
          if (kind === 'cc_switch_sqlite') object.third_party_sources = ccSwitchSources(object.providers);
          // 真实 Cookie 库只留 Claude 站点的记录；其余站点的 Cookie 不进扫描记录。
          if (kind === 'cookie_sqlite' && siteHosts) {
            object.cookies = object.cookies.filter((cookie) => isClaudeSiteHost(cookie.host_key, siteHosts));
            const login = client ? siteLoginIdentity(client) : null;
            if (login && object.cookies.length) {
              identityDetails.set(login.identity_ref, login);
              object.identities = [login.identity_ref];
              object.cookie_associations = object.cookies.map((cookie) => ({profile_ref: object.profile_ref, identity_ref: login.identity_ref, selector: {...cookie}}));
            }
          }
        } else if (kind === 'text' || kind === 'jsonl') {
          const content = decodeBytes(await adapter.readBytes(entry.relative_path));
          object.content_roles = ['project', 'memory', 'configuration', 'skill', 'hook', 'mcp', 'audit']
            .filter((role) => new RegExp(role, 'i').test(content));
          object.contains_identity_reference = /(?:org_id|[\w.+-]+@[\w.-]+)/i.test(content);
          if (object.content_roles.some((role) => ['project', 'memory', 'configuration', 'skill', 'hook', 'mcp', 'audit'].includes(role))) {
            object.protected_paths = object.content_roles.map((role) => `content:${role}`);
          }
        }
        const relation = relationByPath[entry.relative_path];
        if (relation && typeof relation === 'object') {
          object.usage = {
            purpose: relation.purpose || 'unknown',
            lifecycle: relation.lifecycle || 'unknown',
            references: Array.isArray(relation.references) ? relation.references.slice() : [],
          };
          if (['project', 'memory', 'configuration', 'audit', 'active_log'].includes(object.usage.purpose)
            || object.usage.lifecycle === 'active') object.protected_paths.push(`relation:${object.usage.purpose}`);
        }
      } catch (error) {
        object.status = error.code === 'UNSUPPORTED_FORMAT' ? 'unsupported' : 'unreadable';
        object.error_code = error.code || 'READ_ERROR';
        gaps.push({code: object.error_code, message: `${entry.relative_path}: ${error.message}`});
      }
      objects.push(object);
      evidence.push({relative_path: entry.relative_path, read: true, observed_at: object.observed_at, critical_rechecked: object.critical_rechecked});
      processed += 1;
      options.onProgress?.({completed: processed, total: entries.length, relative_path: entry.relative_path, read: true});
    }
    for (const [directory, count] of unsupportedByDirectory) {
      gaps.push({code: 'UNSUPPORTED_FORMAT', message: `${directory}: ${count} file(s) in formats this version does not parse were listed but not read`});
    }
    // 凭据文件里没有账号标识：同一客户端恰好认出一个身份才归属过去，否则记缺口，不进推荐。
    for (const {object, items} of pendingCredentials) {
      const owners = new Set(objects
        .filter((other) => other !== object && other.client_ref && other.client_ref === object.client_ref)
        .flatMap((other) => other.identities || [])
        .filter((identityRef) => identityDetails.has(identityRef)));
      if (owners.size !== 1) {
        gaps.push({
          code: 'CREDENTIAL_OWNER_UNKNOWN',
          message: `${object.relative_path}: ${items.map((item) => item.field_path).join(', ')} cannot be attributed to exactly one identity (${owners.size} found)`,
        });
        continue;
      }
      const [owner] = owners;
      object.identities = [...new Set([...object.identities, owner])].sort();
      object.removable_items.push(...items.map((item) => ({field_path: item.field_path, identity_ref: owner, contains_protected: false, linked_provider_ids: [], evidence: 'same_client'})));
      object.removable_paths = [...new Set([...object.removable_paths, ...items.map((item) => item.field_path)])].sort();
    }
    for (const associationDocument of objects.filter((object) => object.kind === 'json' && object.cookie_database_ref)) {
      const target = objects.find((object) => object.relative_path === associationDocument.cookie_database_ref && object.kind === 'cookie_sqlite');
      if (!target || target.status !== 'found') continue;
      target.cookie_associations = [
        ...(target.cookie_associations || []),
        ...associationDocument.cookie_associations.filter((association) => target.cookies.some((cookie) => sameCookieSelector(cookie, association.selector))),
      ];
    }
    for (const profile of objects.filter((object) => object.json_shape === 'desktop_profile' && object.desktop_meta_path)) {
      const meta = objects.find((object) => object.relative_path === profile.desktop_meta_path && object.json_shape === 'desktop_meta');
      profile.desktop_meta_ref = meta?.object_ref || null;
      profile.desktop_pointer_status = meta?.desktop_meta_applied_id === profile.desktop_profile_id ? 'applied' : 'not_applied_or_unknown';
      if (!meta) gaps.push({code: 'DESKTOP_META_MISSING', message: `${profile.relative_path}: declared Desktop meta was not discovered`});
    }
    for (const directoryPath of environment.cleanup_directories || []) {
      if (typeof directoryPath !== 'string' || !scopes.some((scope) => withinScope(directoryPath, scope))) {
        gaps.push({code: 'OUT_OF_SCOPE', message: 'declared cleanup directory must stay inside the scanned scope'});
        continue;
      }
      const childObjects = objects.filter((object) => object.relative_path.startsWith(`${directoryPath}/`));
      if (!childObjects.length) {
        gaps.push({code: 'DIRECTORY_MISSING', message: `${directoryPath}: no discovered child objects`});
        continue;
      }
      try {
        objects.push({
          object_ref: `obj-${digest(directoryPath).slice(0, 16)}`,
          relative_path: directoryPath,
          kind: 'directory',
          source_ref: environment.source_ref || 'synthetic-local-fixture-v1',
          status: 'found',
          sha256: await adapter.fingerprintDirectory(directoryPath),
          environment_ref: 'windows-synthetic',
          profile_ref: null,
          identities: [...new Set(childObjects.flatMap((object) => object.identities || []))].sort(),
          protected_paths: childObjects.flatMap((object) => (object.protected_paths || []).map((item) => `${object.relative_path}:${item}`)),
          directory_children: childObjects.map((object) => object.relative_path),
          isolation_eligible: childObjects.every((object) => object.status === 'found' && !(object.protected_paths || []).length),
        });
      } catch (error) {
        gaps.push({code: error.code || 'READ_ERROR', message: `${directoryPath}: ${error.message}`});
      }
    }
    const identitySources = new Map();
    for (const object of objects) {
      for (const identityRef of object.identities) {
        if (!identitySources.has(identityRef)) identitySources.set(identityRef, []);
        identitySources.get(identityRef).push(object.sha256 || object.relative_path);
      }
    }
    // 真实身份的指纹由账号标识派生，不随文件内容变化：同一账号换一次扫描不必重新回答。
    const identities = [...identitySources.entries()].map(([identity_ref, sources]) => {
      const detail = identityDetails.get(identity_ref);
      return {
        identity_ref,
        identity_fingerprint: detail ? digest(detail.stable_key) : digest(JSON.stringify(sources.sort())),
        ...(detail ? {kind: detail.kind, label: detail.label} : {}),
      };
    }).sort((left, right) => left.identity_ref.localeCompare(right.identity_ref));
    const scan = {
      scan_id: nowId('scan'),
      task_id: nowId('local-task'),
      mode,
      scopes,
      status: gaps.length ? (gaps.some((gap) => gap.code === 'SCAN_CANCELLED') ? 'cancelled' : 'partial') : 'completed',
      observed_at: adapter.clock(),
      source_version: environment.source_version || 'synthetic-adapter-v1',
      environment_ref: environment.environment_ref || 'windows-synthetic',
      environment_snapshot: {
        clients: environmentEvidence,
        default_browser: environment.default_browser || null,
        selected_profile_refs: [...selectedProfileRefs],
      },
      objects,
      identities,
      evidence,
      coverage: {
        complete: mode === 'deep' ? gaps.length === 0 : mode === 'quick' ? gaps.length === 0 && priorScan?.coverage?.complete === true : false,
        gaps: mode === 'focused' ? [...gaps, {code: 'FOCUSED_SCOPE_ONLY', message: 'score is limited to the selected scope'}] : gaps,
      },
    };
    adapter.saveRecord('scan', scan.scan_id, scan);
    return scan;
  }

  function findScan(scanId) {
    const scan = adapter.getRecord(scanId, 'scan');
    if (!scan) throw serviceError('SCAN_NOT_FOUND', 'scan_id is unknown');
    return scan;
  }

  async function inspectObject({scanId, objectRef, selector = {}, readBudget = 20}) {
    if (!Number.isInteger(readBudget) || readBudget < 1 || readBudget > 20) {
      throw serviceError('READ_BUDGET_EXCEEDED', 'read budget must be between 1 and 20');
    }
    const object = findScan(scanId).objects.find((item) => item.object_ref === objectRef);
    if (!object) throw serviceError('OBJECT_NOT_FOUND', 'object_ref is not part of this scan');
    const evidence = {
      object_ref: objectRef,
      relative_path: object.relative_path,
      kind: object.kind,
      sha256: await fingerprintObject(object.relative_path, object.kind),
      identities: object.identities,
      protected_paths: object.protected_paths,
      selector: redactForExport(selector),
    };
    if (object.kind === 'json') evidence.available_keys = object.json_top_level_keys.slice(0, readBudget);
    if (object.kind.endsWith('sqlite')) evidence.tables = object.tables;
    return evidence;
  }

  function recordAccountAnswer({scanId, identityRef, identityFingerprint, status}) {
    const identity = findScan(scanId).identities.find((entry) => entry.identity_ref === identityRef);
    if (!identity || identity.identity_fingerprint !== identityFingerprint) {
      throw serviceError('STALE_IDENTITY', 'identity changed or does not belong to this scan');
    }
    if (!['normal', 'restricted'].includes(status)) {
      throw serviceError('INVALID_ACCOUNT_ANSWER', 'status must be normal or restricted');
    }
    const answer = {
      answer_id: nowId('answer'),
      identity_ref: identityRef,
      identity_fingerprint: identityFingerprint,
      scan_id: scanId,
      status,
      recorded_at: adapter.clock(),
    };
    adapter.saveRecord('account_answer', `account:${identityRef}`, answer);
    return answer;
  }

  function currentAnswer(identityRef, scan) {
    const answer = adapter.getRecord(`account:${identityRef}`, 'account_answer');
    const identity = scan.identities.find((entry) => entry.identity_ref === identityRef);
    if (!answer || !identity || answer.identity_fingerprint !== identity.identity_fingerprint) return null;
    return answer;
  }

  function classify({scanId, retainedProblemIds = [], correctedProblemIds = []}) {
    const scan = findScan(scanId);
    const recommendations = [];
    const problems = [];
    const gaps = [...scan.coverage.gaps];
    const providerIdentityById = new Map();
    const providerById = new Map();
    const storedDecisions = adapter.listRecords('problem_decision').filter((entry) => entry.scan_id === scanId);
    const retained = new Set([...retainedProblemIds, ...storedDecisions.filter((entry) => entry.decision === 'retain').map((entry) => entry.problem_id)]);
    const corrected = new Set([...correctedProblemIds, ...storedDecisions.filter((entry) => entry.decision === 'correct').map((entry) => entry.problem_id)]);
    const identityKinds = new Map(scan.identities.map((identity) => [identity.identity_ref, identity.kind || null]));
    const isolatedDirectoryPrefixes = scan.objects.filter((entry) => entry.kind === 'directory' && entry.isolation_eligible)
      .map((entry) => `${entry.relative_path}/`);
    for (const object of scan.objects.filter((entry) => entry.kind === 'cc_switch_sqlite')) {
      for (const provider of object.providers || []) {
        providerIdentityById.set(provider.provider_id, provider.identity_ref);
        providerById.set(provider.provider_id, provider);
      }
    }
    let candidateIndex = 0;
    const addCandidate = ({object, kind, selector, identityRef, severity, summary, rootCause}) => {
      const answer = identityRef ? currentAnswer(identityRef, scan) : null;
      if (identityRef && !answer) {
        gaps.push({code: 'ACCOUNT_ANSWER_MISSING', message: `${identityRef}: user answer is required before a cleanup recommendation`});
        return;
      }
      if (answer?.status === 'normal') return;
      const candidate = {
        recommendation_id: `rec-${scanId}-${candidateIndex += 1}`,
        object_ref: object.object_ref,
        relative_path: object.relative_path,
        kind,
        selector,
        identity_ref: identityRef || null,
        account_answer_id: answer?.answer_id || null,
        account_answer_version: answer?.identity_fingerprint || null,
        severity,
        summary,
        root_cause_ref: rootCause,
        backup_method: 'restricted-local-backup',
        impact: kind === 'cookie_delete' ? 'the selected synthetic site login record will be removed' : 'the selected supported residue will be removed',
      };
      recommendations.push(candidate);
      const problemId = `problem-${rootCause}`;
      let problem = problems.find((item) => item.problem_id === problemId);
      if (!problem) {
        problem = {
          problem_id: problemId,
          root_cause_ref: rootCause,
          severity,
          summary,
          evidence_state: 'fact',
          object_refs: [],
          false_positive: corrected.has(problemId),
          retained: retained.has(problemId),
        };
        problems.push(problem);
      }
      problem.object_refs.push(object.object_ref);
    };

    for (const object of scan.objects) {
      if (object.status !== 'found') continue;
      if (object.kind !== 'directory' && isolatedDirectoryPrefixes.some((prefix) => object.relative_path.startsWith(prefix))) continue;
      if (object.kind === 'json') {
        const relationProtected = object.protected_paths.some((entry) => entry.startsWith('relation:'));
        if (!relationProtected && object.json_shape === 'claude_code_settings') {
          for (const field of object.source_backed_fields || []) {
            const association = sourceIdentityAssociation(environment, object.relative_path, field.field_path);
            const provider = association ? providerById.get(association.provider_id) : null;
            if (!provider || provider.protected_usage || provider.identity_ref !== association.identity_ref) continue;
            addCandidate({
              object,
              kind: 'json_remove',
              selector: {field_path: field.field_path, evidence_provider_id: association.provider_id},
              identityRef: association.identity_ref,
              severity: 'important',
              summary: 'Actual supported Code credential is attributed to the selected restricted Provider',
              rootCause: `code-env-provider:${association.provider_id}:${field.field_path}`,
            });
          }
        }
        const isolatedThirdPartyFile = object.relative_path.includes('/third-party/') && object.json_top_level_keys.length === 1 && !object.protected_paths.length;
        const protectedArchive = object.relative_path.includes('/backup/');
        for (const item of object.removable_items || []) {
          if (protectedArchive || relationProtected) continue;
          const fieldPath = item.field_path;
          if (item.contains_protected || pathIsProtected(fieldPath, object.protected_paths)) continue;
          const identityRef = item.identity_ref || null;
          addCandidate({
            object,
            kind: object.relative_path.includes('/third-party/') && fieldPath === 'legacyProvider' && object.json_top_level_keys.length === 1 && !object.protected_paths.length ? 'delete_file' : 'json_remove',
            selector: {field_path: fieldPath, linked_provider_ids: item.linked_provider_ids},
            identityRef,
            severity: 'important',
            summary: item.evidence ? 'Local login material of the identity the user marked restricted' : 'Explicitly identified legacy third-party configuration',
            rootCause: item.evidence ? `login-material:${identityRef}` : `legacy-config:${identityRef || object.object_ref}`,
          });
        }
        for (const repair of object.repair_items || []) {
          if (isolatedThirdPartyFile || protectedArchive || relationProtected) continue;
          addCandidate({
            object,
            kind: 'json_set',
            selector: {field_path: repair.field_path, value: repair.value, expected_value: repair.expected_value, expected_missing: repair.expected_missing === true},
            identityRef: object.identities.find((identity) => currentAnswer(identity, scan)?.status === 'restricted') || null,
            severity: 'important',
            summary: 'Supported legacy JSON provider mode is changed to the managed value',
            rootCause: `legacy-config:${object.object_ref}`,
          });
        }
        for (const pointer of object.pointer_items || []) {
          if (relationProtected) continue;
          const identityRef = providerIdentityById.get(pointer.provider_id);
          if (!identityRef) continue;
          addCandidate({
            object,
            kind: 'json_remove',
            selector: {field_path: pointer.field_path, linked_provider_ids: [pointer.provider_id]},
            identityRef,
            severity: 'important',
            summary: 'Supported JSON provider pointer explicitly targets the selected restricted provider',
            rootCause: `provider-pointer:${pointer.provider_id}`,
          });
        }
        for (const entry of object.site_storage_entries || []) {
          if (!entry.identity_ref || entry.identity_ref === 'shared') continue;
          addCandidate({
            object,
            kind: 'site_storage_remove',
            selector: {entry_id: entry.entry_id, profile_ref: entry.profile_ref, site: entry.site, storage_type: entry.storage_type},
            identityRef: entry.identity_ref,
            severity: 'important',
            summary: 'Supported site-storage record explicitly belongs to the selected identity',
            rootCause: `site-storage:${entry.identity_ref}`,
          });
        }
      }
      if (object.kind === 'cc_switch_sqlite') {
        for (const provider of object.providers || []) {
          // 没有身份归属的 Provider 是第三方来源，只报告；存在第三方不等于要清。
          if (provider.protected_usage || !provider.identity_ref) continue;
          addCandidate({
            object,
            kind: 'cc_provider_delete',
            selector: {provider_id: provider.provider_id, app_type: provider.app_type},
            identityRef: provider.identity_ref,
            severity: 'important',
            summary: 'Supported CC Switch Provider record explicitly belongs to the selected identity',
            rootCause: `provider:${provider.provider_id}:${provider.app_type}`,
          });
        }
      }
      if (object.kind === 'cookie_sqlite') {
        for (const cookie of object.cookie_associations || []) {
          if (!cookie.identity_ref || cookie.identity_ref === 'shared') continue;
          addCandidate({
            object,
            kind: 'cookie_delete',
            selector: {...cookie.selector, profile_ref: cookie.profile_ref},
            identityRef: cookie.identity_ref,
            severity: 'important',
            summary: 'Supported Cookie record explicitly belongs to the selected identity',
            rootCause: identityKinds.get(cookie.identity_ref) === 'site_login'
              ? `login-material:${cookie.identity_ref}`
              : `cookie:${cookie.profile_ref}:${cookie.selector.host_key}:${cookie.selector.name}:${cookie.identity_ref}`,
          });
        }
      }
      if (object.kind === 'directory' && object.isolation_eligible) {
        const identityRef = object.identities.find((identity) => currentAnswer(identity, scan)?.status === 'restricted') || null;
        addCandidate({
          object,
          kind: 'isolate_directory',
          selector: {directory_path: object.relative_path},
          identityRef,
          severity: 'important',
          summary: 'Explicit synthetic cleanup directory is isolated without deleting its contents',
          rootCause: `isolated-directory:${object.relative_path}`,
        });
      }
    }

    const score = scoreProblems(problems, {complete: scan.coverage.complete && gaps.length === 0, gaps});
    const categoryMatchers = {
      cache_and_logs: (object) => /(?:cache|\.log$)/i.test(object.relative_path),
      login_account_material: (object) => (object.identities || []).length > 0 || object.kind === 'cookie_sqlite',
      third_party_configuration: (object) => /(?:third-party|cc-switch)/i.test(object.relative_path) || object.client_category === 'third_party',
      session_and_work_material: (object) => /(?:browser|session|workspace|wsl)/i.test(object.relative_path) || object.client_category === 'browser_profile',
      old_backup_and_isolation: (object) => /(?:backup|isolation)/i.test(object.relative_path) || object.kind === 'directory' || object.client_category === 'old_backup',
    };
    const result_groups = Object.entries(categoryMatchers).map(([category, matcher]) => ({
      category,
      object_refs: scan.objects.filter(matcher).map((object) => object.object_ref),
      recommendation_ids: recommendations.filter((recommendation) => scan.objects.find((object) => object.object_ref === recommendation.object_ref && matcher(object)))
        .map((recommendation) => recommendation.recommendation_id),
    }));
    // 第三方来源只报告来源、是否生效和端点，不因存在就扣分或建议清理。
    const thirdPartySources = scan.objects.flatMap((object) => (object.third_party_sources || [])
      .map((source) => ({...source, object_ref: object.object_ref, relative_path: object.relative_path})));
    for (const source of thirdPartySources.filter((item) => item.source === 'claude_code_settings')) {
      source.matching_cc_switch_providers = thirdPartySources
        .filter((item) => item.source === 'cc_switch' && item.endpoint_host === source.endpoint_host)
        .map((item) => item.provider_id);
    }
    const classification = {
      classification_id: nowId('classification'),
      scan_id: scanId,
      mode: 'standard',
      ruleset_version: LOCAL_RULESET_VERSION,
      problems,
      recommendations,
      result_groups,
      third_party_sources: thirdPartySources,
      score,
      coverage: {status: score.status === 'final' ? 'complete' : 'incomplete', gaps},
    };
    for (const problem of problems) {
      if (retainedProblemIds.includes(problem.problem_id)) {
        adapter.saveRecord('problem_decision', `decision:${scanId}:${problem.problem_id}`, {
          scan_id: scanId, problem_id: problem.problem_id, decision: 'retain', reason: 'selected during classification', recorded_at: adapter.clock(),
        });
      }
      if (correctedProblemIds.includes(problem.problem_id)) {
        adapter.saveRecord('problem_decision', `decision:${scanId}:${problem.problem_id}`, {
          scan_id: scanId, problem_id: problem.problem_id, decision: 'correct', reason: 'selected during classification', recorded_at: adapter.clock(),
        });
      }
    }
    adapter.saveRecord('classification', classification.classification_id, classification);
    return classification;
  }

  function recordProblemDecision({scanId, problemId, decision, reason}) {
    const classification = findClassification(scanId);
    const problem = classification.problems.find((entry) => entry.problem_id === problemId);
    if (!problem) throw serviceError('PROBLEM_NOT_FOUND', 'decision target is not part of this classification');
    if (!['retain', 'correct'].includes(decision) || typeof reason !== 'string' || !reason.trim()) {
      throw serviceError('INVALID_DECISION', 'decision must be retain or correct with a non-empty reason');
    }
    const record = {scan_id: scanId, problem_id: problemId, decision, reason: reason.trim(), recorded_at: adapter.clock()};
    adapter.saveRecord('problem_decision', `decision:${scanId}:${problemId}`, record);
    problem.retained = decision === 'retain';
    problem.false_positive = decision === 'correct';
    problem.decision_reason = record.reason;
    adapter.saveRecord('classification', classification.classification_id, classification);
    return record;
  }

  function requestSiteCommand({scanId, profileRef, site, storageType, command = 'clear_supported_site_storage'}) {
    const scan = findScan(scanId);
    const declared = environment.site_command_capabilities || [];
    const capability = declared.find((entry) => entry.command === command && entry.profile_ref === profileRef
      && entry.site === site && entry.storage_type === storageType);
    if (!capability) throw serviceError('SITE_COMMAND_UNSUPPORTED', 'no declared synthetic command capability matches the selected site storage');
    const object = scan.objects.find((entry) => entry.site_storage_entries?.some((item) => item.profile_ref === profileRef && item.site === site && item.storage_type === storageType));
    if (!object) throw serviceError('OBJECT_NOT_FOUND', 'selected site storage does not belong to this scan');
    const request = {
      request_id: nowId('site-command'),
      scan_id: scanId,
      command,
      profile_ref: profileRef,
      site,
      storage_type: storageType,
      protocol_version: capability.protocol_version || 'synthetic-site-command-v1',
      object_ref: object.object_ref,
      requested_at: adapter.clock(),
    };
    adapter.saveRecord('site_command_request', request.request_id, request);
    return request;
  }

  function recordSiteCommandResponse({requestId, response}) {
    const request = adapter.getRecord(requestId, 'site_command_request');
    if (!request || !response || typeof response !== 'object') throw serviceError('SITE_COMMAND_RESPONSE_INVALID', 'a known request and structured response are required');
    for (const key of ['command', 'profile_ref', 'site', 'storage_type', 'protocol_version']) {
      if (response[key] !== request[key]) throw serviceError('SITE_COMMAND_RESPONSE_INVALID', `response ${key} does not match the fixed request`);
    }
    if (!['completed', 'unsupported', 'failed'].includes(response.status)) throw serviceError('SITE_COMMAND_RESPONSE_INVALID', 'response status is not supported');
    const result = {
      response_id: nowId('site-command-response'),
      request_id: requestId,
      status: response.status,
      changed_entries: Number.isInteger(response.changed_entries) && response.changed_entries >= 0 ? response.changed_entries : 0,
      capability_ref: response.capability_ref || null,
      received_at: adapter.clock(),
    };
    adapter.saveRecord('site_command_response', result.response_id, result);
    return result;
  }

  async function proposeJsonChange({scanId, objectRef, kind, fieldPath, value, expectedValue, identityRef, source, reason}) {
    if (!['local-user', 'validated-plan-proposal'].includes(source)) {
      throw serviceError('NOT_AUTHORIZED', 'JSON changes require an explicit local or validated plan proposal source');
    }
    if (!['json_remove', 'json_set'].includes(kind) || typeof reason !== 'string' || !reason.trim()) {
      throw serviceError('INVALID_PROPOSAL', 'proposal kind and a concrete reason are required');
    }
    const scan = findScan(scanId);
    const object = scan.objects.find((entry) => entry.object_ref === objectRef);
    if (!object || object.kind !== 'json' || object.status !== 'found' || !object.json_shape) {
      throw serviceError('UNSUPPORTED_FORMAT', 'proposal target is not a discovered supported JSON shape');
    }
    if (!supportedJsonSelector(object.json_shape, fieldPath) || object.protected_paths.some((entry) => entry.startsWith('relation:'))) {
      throw serviceError('OUT_OF_SCOPE', 'proposal selector is unsupported or the object is protected by a declared relation');
    }
    const association = (environment.identity_associations || []).find((entry) => entry.relative_path === object.relative_path
      && entry.field_path === fieldPath && entry.identity_ref === identityRef);
    const answer = currentAnswer(identityRef, scan);
    if (!association || !answer || answer.status !== 'restricted') {
      throw serviceError('IDENTITY_ASSOCIATION_REQUIRED', 'proposal needs a declared field-to-identity association and a restricted account answer');
    }
    const document = JSON.parse(decodeBytes(await adapter.readBytes(object.relative_path)));
    const current = getNested(document, fieldPath);
    if (kind === 'json_remove' && current === undefined) throw serviceError('STALE_PLAN', 'proposed JSON field is already absent');
    if (kind === 'json_set' && value === undefined) throw serviceError('INVALID_PROPOSAL', 'a JSON update requires an explicit new value');
    if (expectedValue !== undefined && JSON.stringify(canonicalize(current)) !== JSON.stringify(canonicalize(expectedValue))) {
      throw serviceError('STALE_PLAN', 'proposal expected value does not match the current declared field');
    }
    const proposal = {
      proposal_id: nowId('json-proposal'),
      recommendation_id: null,
      scan_id: scanId,
      object_ref: objectRef,
      relative_path: object.relative_path,
      kind,
      selector: {
        field_path: fieldPath,
        value,
        expected_value: current,
        expected_missing: current === undefined,
        linked_provider_ids: association.linked_provider_ids || [],
      },
      identity_ref: identityRef,
      account_answer_id: answer.answer_id,
      account_answer_version: answer.identity_fingerprint,
      summary: reason.trim(),
      impact: 'Explicit local JSON proposal changes only the selected supported leaf',
      backup_method: 'restricted-local-backup',
      source,
      created_at: adapter.clock(),
    };
    proposal.recommendation_id = proposal.proposal_id;
    adapter.saveRecord('json_change_proposal', proposal.proposal_id, proposal);
    return proposal;
  }

  function findClassification(scanId) {
    const candidates = adapter.listRecords('classification').filter((entry) => entry.scan_id === scanId);
    if (!candidates.length) throw serviceError('CLASSIFICATION_NOT_FOUND', 'classify must run before planning');
    return candidates.at(-1);
  }

  async function simulateSqlite(action, prior = []) {
    return adapter.simulateDatabaseMutation(action.relative_path, action.kind, action.selector, prior);
  }

  async function expectedAction(action, stagedObjects) {
    const staged = stagedObjects.get(action.relative_path);
    const before = staged?.sha256 || await fingerprintAction(action);
    if (action.kind === 'delete_file') return {before, after: null};
    if (action.kind === 'isolate_directory') return {before, after: null};
    if (action.kind === 'legacy_json_cleanup') {
      const source = staged?.document || JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      const cleanup = applyCleanupToDocument(source, action.selector.approved_removals, action.selector.requested_removals);
      if (!isProtectedUnchanged(cleanup.before, cleanup.after)) throw serviceError('OUT_OF_SCOPE', 'legacy cleanup would alter protected sections');
      const after = adapter.hashBytes(new TextEncoder().encode(jsonText(cleanup.after)));
      stagedObjects.set(action.relative_path, {document: cleanup.after, sha256: after});
      return {before, after};
    }
    if (action.kind === 'json_set') {
      const source = staged?.document || JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      const beforeDocument = structuredClone(source);
      const current = getNested(source, action.selector.field_path);
      if ((action.selector.expected_missing && current !== undefined) || (!action.selector.expected_missing && JSON.stringify(canonicalize(current)) !== JSON.stringify(canonicalize(action.selector.expected_value)))) {
        throw serviceError('STALE_PLAN', 'planned JSON value is no longer the frozen supported value');
      }
      if (!upsertNested(source, action.selector.field_path, action.selector.value)) throw serviceError('STALE_PLAN', 'planned JSON value cannot be set');
      if (!isProtectedUnchanged(beforeDocument, source)) throw serviceError('OUT_OF_SCOPE', 'planned JSON change would alter protected sections');
      const after = adapter.hashBytes(new TextEncoder().encode(jsonText(source)));
      stagedObjects.set(action.relative_path, {document: source, sha256: after});
      return {before, after};
    }
    if (action.kind === 'json_remove') {
      const source = staged?.document || JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      const beforeDocument = structuredClone(source);
      if (!removeNested(source, action.selector.field_path)) throw serviceError('STALE_PLAN', 'planned JSON field is missing');
      if (!isProtectedUnchanged(beforeDocument, source)) throw serviceError('OUT_OF_SCOPE', 'planned JSON change would alter protected sections');
      const after = adapter.hashBytes(new TextEncoder().encode(jsonText(source)));
      stagedObjects.set(action.relative_path, {document: source, sha256: after});
      return {before, after};
    }
    if (action.kind === 'site_storage_remove') {
      const source = staged?.document || JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      const beforeCount = Array.isArray(source.entries) ? source.entries.length : -1;
      source.entries = source.entries.filter((entry) => !matchesSiteEntry(entry, action.selector));
      if (source.entries.length === beforeCount) throw serviceError('STALE_PLAN', 'planned site-storage record is missing');
      const after = adapter.hashBytes(new TextEncoder().encode(jsonText(source)));
      stagedObjects.set(action.relative_path, {document: source, sha256: after});
      return {before, after};
    }
    // 同一个库上的多条记录级改写按计划顺序在同一份副本上累积模拟：后一条的改前就是前一条的改后。
    const prior = staged?.mutations || [];
    const after = await simulateSqlite(action, prior);
    stagedObjects.set(action.relative_path, {sha256: after, mutations: [...prior, {kind: action.kind, selector: action.selector}]});
    return {before, after};
  }

  async function buildActionPlan({scanId, recommendationIds, retainedRecommendationIds = [], proposalIds = []}) {
    const scan = findScan(scanId);
    const classification = findClassification(scanId);
    const proposals = proposalIds.map((proposalId) => {
      const proposal = adapter.getRecord(proposalId, 'json_change_proposal');
      if (!proposal || proposal.scan_id !== scanId) throw serviceError('OUT_OF_SCOPE', 'proposal does not belong to this scan');
      return proposal;
    });
    const requested = [...(recommendationIds || classification.recommendations.map((entry) => entry.recommendation_id)), ...proposals.map((proposal) => proposal.recommendation_id)];
    const allowed = new Map([
      ...classification.recommendations.map((entry) => [entry.recommendation_id, entry]),
      ...proposals.map((proposal) => [proposal.recommendation_id, proposal]),
    ]);
    const actions = [];
    const stagedObjects = new Map();
    for (const recommendationId of requested) {
      if (retainedRecommendationIds.includes(recommendationId)) continue;
      const recommendation = allowed.get(recommendationId);
      if (!recommendation) throw serviceError('OUT_OF_SCOPE', 'recommendation does not belong to current classification');
      const object = scan.objects.find((entry) => entry.object_ref === recommendation.object_ref);
      if (!object) throw serviceError('OBJECT_NOT_FOUND', 'recommendation source object is missing');
      const action = {
        action_id: nowId('action'),
        recommendation_id: recommendation.recommendation_id,
        scan_id: scanId,
        object_ref: object.object_ref,
        relative_path: recommendation.relative_path,
        environment_ref: object.environment_ref,
        profile_ref: object.profile_ref,
        kind: recommendation.kind,
        selector: recommendation.selector,
        identity_ref: recommendation.identity_ref,
        account_answer_id: recommendation.account_answer_id,
        account_answer_version: recommendation.account_answer_version,
        changes: recommendation.summary,
        impact: recommendation.impact,
          backup_method: recommendation.backup_method,
          dependencies: [],
          source_before_sha256: object.sha256,
        };
      assertActionTarget(action, environment);
      if ((await fingerprintAction(action)) !== object.sha256) {
        throw serviceError('STALE_PLAN', 'object changed after scan and before planning');
      }
      const expected = await expectedAction(action, stagedObjects);
      actions.push({...action, expected_before_sha256: expected.before, expected_after_sha256: expected.after});
    }
    const providerActions = new Map(actions.filter((action) => action.kind === 'cc_provider_delete').map((action) => [action.selector.provider_id, action.action_id]));
    for (const action of actions) {
      const linkedProviderIds = action.selector?.linked_provider_ids || (action.selector?.linked_provider_id ? [action.selector.linked_provider_id] : []);
      action.dependencies = [...new Set([...action.dependencies, ...linkedProviderIds.map((providerId) => providerActions.get(providerId)).filter(Boolean)])];
    }
    const plan = {
      plan_id: nowId('plan'),
      version: 1,
      scan_id: scanId,
      status: 'draft',
      created_at: adapter.clock(),
      retained_recommendation_ids: retainedRecommendationIds,
      proposal_ids: proposalIds,
      actions,
    };
    adapter.saveRecord('plan', plan.plan_id, plan);
    return plan;
  }

  async function buildLegacyP0Plan({targets}) {
    if (!Array.isArray(targets) || !targets.length) throw serviceError('INVALID_PLAN', 'legacy P0 conversion requires at least one target');
    const actions = [];
    const stagedObjects = new Map();
    for (const [index, target] of targets.entries()) {
      if (!target || typeof target.file !== 'string') throw serviceError('INVALID_PLAN', 'legacy P0 target file is required');
      const action = {
        action_id: nowId('action'),
        recommendation_id: `legacy-p0-${index}`,
        scan_id: null,
        object_ref: `legacy-p0-object-${index}`,
        relative_path: target.file,
        environment_ref: 'legacy-p0-synthetic',
        profile_ref: null,
        kind: 'legacy_json_cleanup',
        selector: {
          approved_removals: target.approvedRemovals,
          requested_removals: target.requestedRemovals,
          target_index: index,
          legacy_expected_before_sha256: target.legacyExpectedBeforeSha256 || null,
          legacy_expected_after_sha256: target.legacyExpectedAfterSha256 || null,
        },
        identity_ref: null,
        account_answer_id: null,
        account_answer_version: null,
        changes: 'Legacy P0 approved JSON fields are removed through the local service',
        impact: 'Only requested and allowed P0 fields are removed',
        backup_method: 'restricted-local-backup',
        dependencies: [],
        source_before_sha256: await adapter.fingerprint(target.file),
      };
      assertActionTarget(action, environment);
      const expected = await expectedAction(action, stagedObjects);
      actions.push({...action, expected_before_sha256: expected.before, expected_after_sha256: expected.after});
    }
    const plan = {
      plan_id: nowId('legacy-p0-plan'),
      version: 1,
      scan_id: null,
      status: 'draft',
      legacy_p0: true,
      created_at: adapter.clock(),
      retained_recommendation_ids: [],
      actions,
    };
    adapter.saveRecord('plan', plan.plan_id, plan);
    return plan;
  }

  function recordLegacyP0Bridge({planId, operationId}) {
    const plan = adapter.getRecord(planId, 'plan');
    const operation = adapter.getRecord(operationId, 'operation');
    if (!plan?.legacy_p0 || !operation || operation.plan_id !== planId) {
      throw serviceError('REPLAY_MISMATCH', 'legacy bridge must bind the completed local plan and operation');
    }
    return plan.actions.map((action) => {
      const targetKey = legacyP0BridgeKey({
        file: action.relative_path,
        approvedRemovals: action.selector.approved_removals,
        requestedRemovals: action.selector.requested_removals,
      });
      const receipt = operation.receipts.find((entry) => entry.action_id === action.action_id) || null;
      const bridge = {
        bridge_id: `legacy-p0:${targetKey}`,
        target_key: targetKey,
        relative_path: action.relative_path,
        approved_removals: action.selector.approved_removals,
        requested_removals: action.selector.requested_removals,
        legacy_expected_before_sha256: action.selector.legacy_expected_before_sha256,
        legacy_expected_after_sha256: action.selector.legacy_expected_after_sha256,
        plan_id: planId,
        operation_id: operationId,
        action_id: action.action_id,
        receipt_status: receipt?.status || 'NOT_STARTED',
        backup_ref: receipt?.backup_ref || null,
        recorded_at: adapter.clock(),
      };
      adapter.saveRecord('legacy_p0_bridge', bridge.bridge_id, bridge);
      return bridge;
    });
  }

  function getLegacyP0Bridge({file, approvedRemovals, requestedRemovals}) {
    const targetKey = legacyP0BridgeKey({file, approvedRemovals, requestedRemovals});
    const bridge = adapter.getRecord(`legacy-p0:${targetKey}`, 'legacy_p0_bridge');
    if (!bridge) return null;
    const plan = adapter.getRecord(bridge.plan_id, 'plan');
    const operation = adapter.getRecord(bridge.operation_id, 'operation');
    const action = plan?.actions?.find((entry) => entry.action_id === bridge.action_id);
    const receipt = operation?.receipts?.find((entry) => entry.action_id === bridge.action_id);
    if (!plan?.legacy_p0 || !operation || !action || !receipt) {
      throw serviceError('REPLAY_MISMATCH', 'legacy bridge does not resolve to a complete local record chain');
    }
    return {
      ...bridge,
      operation_status: operation.status,
      receipt: {status: receipt.status, code: receipt.code || null, backup_ref: receipt.backup_ref || bridge.backup_ref},
    };
  }

  async function confirmActionPlan({planId, version, actionIds, source}) {
    const plan = adapter.getRecord(planId, 'plan');
    if (!plan || plan.version !== version) throw serviceError('STALE_PLAN', 'plan id or version is not current');
    if (source !== 'local-user') throw serviceError('NOT_CONFIRMED', 'only the local user confirmation adapter can confirm a plan');
    const selected = new Set(actionIds || []);
    if (!selected.size || [...selected].some((id) => !plan.actions.some((action) => action.action_id === id))) {
      throw serviceError('NOT_CONFIRMED', 'confirmation must select only current plan actions');
    }
    const stagedObjects = new Map();
    const lastActionByPath = new Map();
    const actions = [];
    for (const action of plan.actions.filter((entry) => selected.has(entry.action_id))) {
      if (!stagedObjects.has(action.relative_path)) {
        const actual = await fingerprintAction(action);
        if (actual !== action.source_before_sha256) throw serviceError('STALE_PLAN', 'selected object changed before confirmation');
      }
      const priorAction = lastActionByPath.get(action.relative_path);
      const derived = {...action, dependencies: [...new Set([...action.dependencies, ...(priorAction ? [priorAction] : [])]) ]};
      const expected = await expectedAction(derived, stagedObjects);
      actions.push({...derived, expected_before_sha256: expected.before, expected_after_sha256: expected.after});
      lastActionByPath.set(action.relative_path, action.action_id);
    }
    const confirmation = {
      confirmation_id: nowId('confirmation'),
      plan_id: planId,
      version,
      action_ids: [...selected],
      actions,
      action_digest: actionDigest({actions}),
      source,
      confirmed_at: adapter.clock(),
    };
    adapter.saveRecord('confirmation', `confirmation:${planId}`, confirmation);
    return confirmation;
  }

  /**
    * 一次具体确认的请求：交给原生签发，不是自造的凭证。
    * 目标指纹带的是计划冻结时的期望值，原生会拿它跟磁盘现状比对，对不上就当场拒绝签发。
    */
  function confirmationRequest(action, confirmation) {
    if (!confirmation) return null;
    return {
      scope: 'single_confirmation',
      plan_ref: confirmation.plan_id,
      plan_version: confirmation.version,
      action_id: action.action_id,
      action: action.kind,
      native_op: nativeOpForAction(action.kind),
      target: {path: action.relative_path, kind: action.kind},
      expected_sha256: action.expected_before_sha256,
      validity_ms: CONFIRMATION_VALIDITY_MS,
      summary: `${action.kind} 将改动 ${action.relative_path}`,
    };
  }

  async function executeAction(action, {onBackup, confirmation} = {}) {
    const scope = (await adapter.authorize?.(confirmationRequest(action, confirmation))) || null;
    try {
      return await runAction(action, {onBackup});
    } finally {
      scope?.release?.();
    }
  }

  async function runAction(action, {onBackup} = {}) {
    assertActionTarget(action, environment);
    if (blocked.has(action.relative_path)) throw serviceError('ACCESS_DENIED', 'injected synthetic permission denial');
    if (busy.has(action.relative_path)) throw serviceError('OBJECT_BUSY', 'injected synthetic object busy state');
    if (action.identity_ref) {
      const scan = findScan(action.scan_id);
      const answer = currentAnswer(action.identity_ref, scan);
      if (!answer || answer.answer_id !== action.account_answer_id || answer.identity_fingerprint !== action.account_answer_version || answer.status !== 'restricted') {
        throw serviceError('STALE_PLAN', 'account answer changed after planning');
      }
    }
    const exists = await adapter.exists(action.relative_path);
    if (!exists) {
      if (action.kind === 'delete_file') return {status: 'ALREADY_ABSENT', actual_changes: 0, backup_ref: null};
      throw serviceError('STALE_PLAN', 'planned object no longer exists');
    }
    const before = await fingerprintAction(action);
    if (before !== action.expected_before_sha256) throw serviceError('STALE_PLAN', 'object changed after confirmation');
    const backupMetadata = {
      action,
      before_sha256: before,
      expected_after_sha256: action.expected_after_sha256,
    };
    let backup;
    if (action.kind === 'isolate_directory') {
      backup = await adapter.beginDirectoryIsolation(action.action_id, action.relative_path, backupMetadata);
    } else if (DATABASE_ACTIONS.has(action.kind)) {
      // 记录级改写的备份是 SQLite 一致快照（含 WAL 里已提交的内容）；快照必须正是确认时的改前状态，取不到就不改。
      const snapshot = await databaseCapability('snapshotDatabase')(action.relative_path);
      if (snapshot.sha256 !== action.expected_before_sha256) throw serviceError('STALE_PLAN', 'database changed before its backup snapshot');
      backup = await adapter.writeBackup(action.action_id, snapshot.bytes, backupMetadata);
    } else {
      backup = await adapter.writeBackup(action.action_id, await adapter.readBytes(action.relative_path), backupMetadata);
    }
    await onBackup?.(backup);
    let result;
    if (action.kind === 'isolate_directory') {
      await adapter.isolateDirectory(action.relative_path, backup.metadata.isolation_path);
      result = {actual_changes: 1, isolated: true};
    } else if (action.kind === 'legacy_json_cleanup') {
      const document = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      const cleanup = applyCleanupToDocument(document, action.selector.approved_removals, action.selector.requested_removals);
      if (!isProtectedUnchanged(cleanup.before, cleanup.after)) throw serviceError('OUT_OF_SCOPE', 'legacy cleanup would alter protected sections');
      await adapter.writeBytes(action.relative_path, jsonText(cleanup.after));
      result = {actual_changes: cleanup.removed.length, removed: cleanup.removed};
    } else if (action.kind === 'legacy_json_cleanup') {
      const document = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      const cleanup = applyCleanupToDocument(document, action.selector.approved_removals, action.selector.requested_removals);
      if (!isProtectedUnchanged(cleanup.before, cleanup.after)) throw serviceError('OUT_OF_SCOPE', 'legacy cleanup would alter protected sections');
      await adapter.writeBytes(action.relative_path, jsonText(cleanup.after));
      result = {actual_changes: cleanup.removed.length, removed: cleanup.removed};
    } else if (action.kind === 'json_set') {
      const document = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      const beforeDocument = structuredClone(document);
      const current = getNested(document, action.selector.field_path);
      if ((action.selector.expected_missing && current !== undefined) || (!action.selector.expected_missing && JSON.stringify(canonicalize(current)) !== JSON.stringify(canonicalize(action.selector.expected_value)))) {
        throw serviceError('STALE_PLAN', 'planned JSON value changed after confirmation');
      }
      if (!upsertNested(document, action.selector.field_path, action.selector.value)) throw serviceError('STALE_PLAN', 'planned JSON value cannot be set');
      if (!isProtectedUnchanged(beforeDocument, document)) throw serviceError('OUT_OF_SCOPE', 'JSON change would alter protected sections');
      await adapter.writeBytes(action.relative_path, jsonText(document));
      result = {actual_changes: 1};
    } else if (action.kind === 'json_remove') {
      const document = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      const beforeDocument = structuredClone(document);
      if (!removeNested(document, action.selector.field_path)) throw serviceError('STALE_PLAN', 'planned JSON field is missing');
      if (!isProtectedUnchanged(beforeDocument, document)) throw serviceError('OUT_OF_SCOPE', 'JSON change would alter protected sections');
      await adapter.writeBytes(action.relative_path, jsonText(document));
      result = {actual_changes: 1};
    } else if (action.kind === 'site_storage_remove') {
      const document = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      const originalLength = Array.isArray(document.entries) ? document.entries.length : -1;
      document.entries = document.entries.filter((entry) => !matchesSiteEntry(entry, action.selector));
      if (document.entries.length === originalLength) throw serviceError('STALE_PLAN', 'planned site-storage record is missing');
      await adapter.writeBytes(action.relative_path, jsonText(document));
      result = {actual_changes: originalLength - document.entries.length};
    } else if (action.kind === 'delete_file') {
      await adapter.remove(action.relative_path);
      result = {actual_changes: 1};
    } else {
      result = await adapter.mutateDatabase(action.relative_path, action.kind, action.selector);
      if (!result.changed) return {status: 'NOT_FOUND', actual_changes: 0, backup_ref: backup.backup_ref};
      result.actual_changes = result.changed;
    }
    const actualAfter = action.kind === 'delete_file' || action.kind === 'isolate_directory' ? null : await fingerprintAction(action);
    if (actualAfter !== action.expected_after_sha256) throw serviceError('READBACK_FAILED', 'actual object does not match frozen expected result');
    return {status: 'APPLIED', actual_changes: result.actual_changes, backup_ref: backup.backup_ref, after_sha256: actualAfter, endpoints: result.endpoints || 0};
  }

  async function executeConfirmedPlan({planId, version, operationId = nowId('operation'), cancelAfter = null, signal = null}) {
    const plan = adapter.getRecord(planId, 'plan');
    const confirmation = adapter.getRecord(`confirmation:${planId}`, 'confirmation');
    if (!plan || plan.version !== version || !confirmation || confirmation.version !== version || confirmation.source !== 'local-user') {
      throw serviceError('NOT_CONFIRMED', 'a matching local confirmation is required');
    }
    const confirmedActions = confirmation.actions || plan.actions.filter((entry) => confirmation.action_ids.includes(entry.action_id));
    const confirmedDigest = actionDigest({actions: confirmedActions});
    if (!confirmation.action_digest || confirmation.action_digest !== confirmedDigest) {
      throw serviceError('REPLAY_MISMATCH', 'confirmation snapshot content no longer matches its frozen digest');
    }
    const planHash = confirmedDigest;
    let operation = adapter.getRecord(operationId, 'operation');
    if (operation && (operation.plan_id !== planId || operation.plan_hash !== planHash)) {
      throw serviceError('REPLAY_MISMATCH', 'operation id cannot be reused for a different frozen plan');
    }
    if (!operation) {
      operation = {operation_id: operationId, plan_id: planId, plan_hash: planHash, status: 'running', receipts: [], started_at: adapter.clock()};
      adapter.saveRecord('operation', operationId, operation);
    } else if (operation.status === 'cancelled') {
      operation.status = 'running';
      delete operation.finished_at;
      adapter.saveRecord('operation', operationId, operation);
    }
    let appliedThisCall = 0;
    for (const action of confirmedActions) {
      if (operation.receipts.some((receipt) => receipt.action_id === action.action_id && ['APPLIED', 'RECOVERED_APPLIED', 'ALREADY_ABSENT'].includes(receipt.status))) continue;
      if (signal?.aborted || (Number.isInteger(cancelAfter) && appliedThisCall >= cancelAfter)) {
        operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
        operation.receipts.push({action_id: action.action_id, status: 'NOT_STARTED', code: 'CANCELLED_AT_BOUNDARY'});
        operation.status = 'cancelled';
        adapter.saveRecord('operation', operationId, operation);
        continue;
      }
      if (action.dependencies.some((dependencyId) => !operation.receipts.some((receipt) => receipt.action_id === dependencyId && ['APPLIED', 'RECOVERED_APPLIED', 'ALREADY_ABSENT'].includes(receipt.status)))) {
        operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
        operation.receipts.push({action_id: action.action_id, status: 'DEPENDENCY_BLOCKED', code: 'DEPENDENCY_NOT_APPLIED'});
        adapter.saveRecord('operation', operationId, operation);
        continue;
      }
      let receipt;
      try {
        operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
        operation.receipts.push({action_id: action.action_id, status: 'STARTED', started_at: adapter.clock()});
        adapter.saveRecord('operation', operationId, operation);
        receipt = {action_id: action.action_id, ...(await executeAction(action, {confirmation, onBackup: async (backup) => {
          operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
          operation.receipts.push({action_id: action.action_id, status: 'BACKUP_SAVED', backup_ref: backup.backup_ref, started_at: adapter.clock()});
          adapter.saveRecord('operation', operationId, operation);
        }}))};
        if (receipt.status === 'APPLIED') appliedThisCall += 1;
      } catch (error) {
        receipt = errorReceipt(action, error);
      }
      operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
      operation.receipts.push(receipt);
      adapter.saveRecord('operation', operationId, operation);
    }
    operation.status = operation.receipts.some((receipt) => receipt.status === 'NOT_STARTED')
      ? 'cancelled'
      : operation.receipts.some((receipt) => ['FAILED', 'DEPENDENCY_BLOCKED', 'EXTERNALLY_CHANGED'].includes(receipt.status)) ? 'partial' : 'completed';
    operation.finished_at = adapter.clock();
    adapter.saveRecord('operation', operationId, operation);
    return settleOperation(operationId, operation);
  }

  /** 完成状态只在记录真的落盘之后发布：未完成或失败的持久写入不得报告 completed。 */
  async function settleOperation(operationId, operation) {
    if (typeof adapter.flush !== 'function') {
      operation.records_persisted = true;
      return operation;
    }
    try {
      await adapter.flush();
      operation.records_persisted = true;
      adapter.saveRecord('operation', operationId, operation);
      await adapter.flush();
    } catch (error) {
      operation.records_persisted = false;
      operation.persist_error = error.code || 'RECORD_PERSIST_FAILED';
      operation.status = 'partial';
    }
    return operation;
  }

  async function resumeOperation({operationId}) {
    const operation = adapter.getRecord(operationId, 'operation');
    if (!operation) throw serviceError('OPERATION_NOT_FOUND', 'operation id is unknown');
    const plan = adapter.getRecord(operation.plan_id, 'plan');
    if (!plan) throw serviceError('REPLAY_MISMATCH', 'stored plan changed');
    const confirmation = adapter.getRecord(`confirmation:${plan.plan_id}`, 'confirmation');
    if (!confirmation || confirmation.version !== plan.version || confirmation.source !== 'local-user') {
      throw serviceError('NOT_CONFIRMED', 'a matching local confirmation is required to resume');
    }
    const confirmedActions = confirmation.actions || plan.actions.filter((entry) => confirmation.action_ids.includes(entry.action_id));
    const confirmationHash = actionDigest({actions: confirmedActions});
    if (!confirmation.action_digest || confirmation.action_digest !== confirmationHash) {
      throw serviceError('REPLAY_MISMATCH', 'confirmation snapshot content no longer matches its frozen digest');
    }
    if (confirmationHash !== operation.plan_hash) throw serviceError('REPLAY_MISMATCH', 'operation confirmation changed');
    for (const action of confirmedActions) {
      const prior = operation.receipts.find((receipt) => receipt.action_id === action.action_id);
      if (prior && ['APPLIED', 'RECOVERED_APPLIED', 'ALREADY_ABSENT'].includes(prior.status)) continue;
      const actual = await adapter.exists(action.relative_path)
        ? await fingerprintAction(action)
        : null;
      if (actual === action.expected_after_sha256 || (action.kind === 'delete_file' && actual === null)) {
        operation.receipts = operation.receipts.filter((receipt) => receipt.action_id !== action.action_id);
        const backupRef = prior?.backup_ref || adapter.getBackupByAction?.(action.action_id)?.backup_ref || null;
        if (prior?.status === 'BACKUP_SAVED' && backupRef) {
          operation.receipts.push({action_id: action.action_id, status: 'RECOVERED_APPLIED', after_sha256: actual, backup_ref: backupRef});
        } else {
          operation.receipts.push({action_id: action.action_id, status: 'EXTERNALLY_CHANGED', code: 'EXTERNAL_AFTER_STATE', message: 'target changed while this action had no persisted backup'});
        }
        continue;
      }
      if (actual !== action.expected_before_sha256) {
        operation.receipts = operation.receipts.filter((receipt) => receipt.action_id !== action.action_id);
        operation.receipts.push({action_id: action.action_id, status: 'CONFLICT', code: 'STALE_PLAN', message: 'object is neither frozen before nor frozen after state'});
        continue;
      }
      if (action.dependencies.some((dependencyId) => !operation.receipts.some((receipt) => receipt.action_id === dependencyId && ['APPLIED', 'RECOVERED_APPLIED', 'ALREADY_ABSENT'].includes(receipt.status)))) {
        operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
        operation.receipts.push({action_id: action.action_id, status: 'DEPENDENCY_BLOCKED', code: 'DEPENDENCY_NOT_APPLIED'});
        continue;
      }
      try {
        operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
        operation.receipts.push({action_id: action.action_id, status: 'STARTED', started_at: adapter.clock()});
        adapter.saveRecord('operation', operationId, operation);
        const receipt = {action_id: action.action_id, ...(await executeAction(action, {confirmation, onBackup: async (backup) => {
          operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
          operation.receipts.push({action_id: action.action_id, status: 'BACKUP_SAVED', backup_ref: backup.backup_ref, started_at: adapter.clock()});
          adapter.saveRecord('operation', operationId, operation);
        }}))};
        operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
        operation.receipts.push(receipt);
      } catch (error) {
        operation.receipts = operation.receipts.filter((entry) => entry.action_id !== action.action_id);
        operation.receipts.push(errorReceipt(action, error));
      }
      adapter.saveRecord('operation', operationId, operation);
    }
    operation.status = operation.receipts.some((receipt) => ['FAILED', 'CONFLICT', 'DEPENDENCY_BLOCKED', 'EXTERNALLY_CHANGED'].includes(receipt.status)) ? 'partial' : 'completed';
    operation.resumed_at = adapter.clock();
    adapter.saveRecord('operation', operationId, operation);
    return settleOperation(operationId, operation);
  }

  function listTasks() {
    return adapter.listRecords('operation').map((operation) => ({
      operation_id: operation.operation_id,
      plan_id: operation.plan_id,
      status: operation.status,
      receipts: operation.receipts.length,
    }));
  }

  function getTask(operationId) {
    const task = adapter.getRecord(operationId, 'operation');
    if (!task) throw serviceError('OPERATION_NOT_FOUND', 'operation id is unknown');
    return task;
  }

  async function verifyActionTarget(action) {
    const exists = await adapter.exists(action.relative_path);
    if (action.kind === 'delete_file' || action.kind === 'isolate_directory') return {verified: !exists, actual: null};
    if (!exists) return {verified: false, actual: null};
    const bytes = DATABASE_ACTIONS.has(action.kind) ? null : await adapter.readBytes(action.relative_path);
    const actual = await fingerprintAction(action);
    if (action.kind === 'json_remove') {
      const current = JSON.parse(decodeBytes(bytes));
      const backup = adapter.getBackupByAction?.(action.action_id);
      const before = backup ? JSON.parse(decodeBytes(await adapter.readBytes(backup.payload_path))) : null;
      return {verified: getNested(current, action.selector.field_path) === undefined && (!before || isProtectedUnchanged(before, current)), actual};
    }
    if (action.kind === 'json_set') {
      const current = JSON.parse(decodeBytes(bytes));
      const backup = adapter.getBackupByAction?.(action.action_id);
      const before = backup ? JSON.parse(decodeBytes(await adapter.readBytes(backup.payload_path))) : null;
      return {
        verified: JSON.stringify(canonicalize(getNested(current, action.selector.field_path))) === JSON.stringify(canonicalize(action.selector.value))
          && (!before || isProtectedUnchanged(before, current)),
        actual,
      };
    }
    if (action.kind === 'legacy_json_cleanup') {
      const current = JSON.parse(decodeBytes(bytes));
      const backup = adapter.getBackupByAction?.(action.action_id);
      const before = backup ? JSON.parse(decodeBytes(await adapter.readBytes(backup.payload_path))) : null;
      return {
        verified: (action.selector.requested_removals || []).every((fieldPath) => legacyFieldIsAbsent(current, fieldPath))
          && (!before || isProtectedUnchanged(before, current)),
        actual,
      };
    }
    if (action.kind === 'site_storage_remove') {
      const current = JSON.parse(decodeBytes(bytes));
      return {verified: Array.isArray(current.entries) && !current.entries.some((entry) => matchesSiteEntry(entry, action.selector)), actual};
    }
    if (action.kind === 'cc_provider_delete' || action.kind === 'cookie_delete') {
      const database = await adapter.inspectDatabase(action.relative_path, action.kind === 'cc_provider_delete' ? 'cc_switch_sqlite' : 'cookie_sqlite');
      const present = action.kind === 'cc_provider_delete'
        ? database.providers.some((provider) => provider.provider_id === action.selector.provider_id && provider.app_type === action.selector.app_type)
        : database.cookies.some((cookie) => sameCookieSelector(cookie, action.selector));
      return {verified: !present, actual};
    }
    return {verified: actual === action.expected_after_sha256, actual};
  }

  async function recheckAction({planId, actionId}) {
    const plan = adapter.getRecord(planId, 'plan');
    const confirmation = adapter.getRecord(`confirmation:${planId}`, 'confirmation');
    const action = confirmation?.actions?.find((entry) => entry.action_id === actionId) || plan?.actions.find((entry) => entry.action_id === actionId);
    if (!action) throw serviceError('ACTION_NOT_FOUND', 'action is not part of plan');
    const target = await verifyActionTarget(action);
    const recheck = {
      recheck_id: nowId('recheck'),
      plan_id: planId,
      action_id: actionId,
      expected_after_sha256: action.expected_after_sha256,
      actual_after_sha256: target.actual,
      status: target.verified ? 'verified' : 'remaining_or_changed',
      checked_at: adapter.clock(),
    };
    adapter.saveRecord('recheck', recheck.recheck_id, recheck);
    return recheck;
  }

  async function previewRestore({backupRef}) {
    const backup = adapter.getBackup(backupRef);
    if (!backup) throw serviceError('BACKUP_NOT_FOUND', 'backup ref is unknown');
    const action = backup.metadata.action;
    const exists = await adapter.exists(action.relative_path);
    const current = exists ? await fingerprintAction(action) : null;
    const databasePreview = action.kind === 'cc_provider_delete' || action.kind === 'cookie_delete'
      ? await adapter.previewDatabaseRestore(action.relative_path, action.kind, action.selector, await adapter.readBytes(backup.payload_path))
      : null;
    const legacyPreview = action.kind === 'legacy_json_cleanup' && exists
      ? previewLegacyRestore(
        JSON.parse(decodeBytes(await adapter.readBytes(backup.payload_path))),
        JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path))),
        action,
      )
      : null;
    const directoryPreview = action.kind === 'isolate_directory'
      ? await adapter.previewDirectoryRestore(backup.metadata.isolation_path, action.relative_path) : null;
    let recoverable = databasePreview ? databasePreview.recoverable : legacyPreview ? legacyPreview.recoverable : directoryPreview ? directoryPreview.recoverable : action.kind === 'delete_file' ? !exists : current === action.expected_after_sha256;
    if (action.kind === 'json_remove' && exists) {
      const document = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      recoverable = getNested(document, action.selector.field_path) === undefined;
    }
    if (action.kind === 'json_set' && exists) {
      const document = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      recoverable = JSON.stringify(canonicalize(getNested(document, action.selector.field_path))) === JSON.stringify(canonicalize(action.selector.value));
    }
    if (action.kind === 'site_storage_remove' && exists) {
      const document = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
      recoverable = Array.isArray(document.entries) && !document.entries.some((entry) => matchesSiteEntry(entry, action.selector));
    }
    const preview = {
      preview_id: nowId('restore-preview'),
      backup_ref: backupRef,
      action_id: action.action_id,
      current_sha256: current,
      recoverable,
      conflicts: databasePreview?.conflicts || legacyPreview?.conflicts || directoryPreview?.conflicts || (recoverable ? [] : [{code: 'RESTORE_CONFLICT', message: 'target changed since this application action'}]),
      created_at: adapter.clock(),
    };
    adapter.saveRecord('restore_preview', preview.preview_id, preview);
    return preview;
  }

  function confirmRestore({previewId, source}) {
    const preview = adapter.getRecord(previewId, 'restore_preview');
    if (!preview || source !== 'local-user') throw serviceError('NOT_CONFIRMED', 'a local confirmation of a restore preview is required');
    const confirmation = {restore_confirmation_id: nowId('restore-confirmation'), preview_id: previewId, source, confirmed_at: adapter.clock()};
    adapter.saveRecord('restore_confirmation', `restore-confirmation:${previewId}`, confirmation);
    return confirmation;
  }

  /** 恢复也是一次具体确认：请求绑定预览、动作、目标与目标在预览时刻的指纹。 */
  function restoreConfirmationRequest(action, confirmation, preview) {
    if (!confirmation) return null;
    return {
      scope: 'single_confirmation',
      plan_ref: preview.preview_id,
      plan_version: preview.version ?? 1,
      action_id: action.action_id,
      action: `restore:${action.kind}`,
      native_op: nativeOpForAction(action.kind, {restore: true}),
      target: {path: action.relative_path, kind: action.kind},
      expected_sha256: preview.current_sha256 ?? null,
      validity_ms: CONFIRMATION_VALIDITY_MS,
      summary: `将 ${action.relative_path} 恢复到备份 ${preview.backup_ref}`,
    };
  }

  async function restoreChange({previewId}) {
    const preview = adapter.getRecord(previewId, 'restore_preview');
    const confirmation = adapter.getRecord(`restore-confirmation:${previewId}`, 'restore_confirmation');
    if (!preview || !confirmation || confirmation.source !== 'local-user') throw serviceError('NOT_CONFIRMED', 'matching local restore confirmation is required');
    if (!preview.recoverable) throw serviceError('RESTORE_CONFLICT', 'restore preview has unresolved conflict');
    const backup = adapter.getBackup(preview.backup_ref);
    const action = backup.metadata.action;
    const current = await adapter.exists(action.relative_path) ? await fingerprintAction(action) : null;
    const source = action.kind === 'isolate_directory' ? null : await adapter.readBytes(backup.payload_path);
    if (action.kind === 'cc_provider_delete' || action.kind === 'cookie_delete') {
      const latest = await adapter.previewDatabaseRestore(action.relative_path, action.kind, action.selector, source);
      if (!latest.recoverable) throw serviceError('RESTORE_CONFLICT', 'selected database record changed after restore preview');
    } else if (action.kind === 'legacy_json_cleanup') {
      const latest = previewLegacyRestore(
        JSON.parse(decodeBytes(source)),
        JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path))),
        action,
      );
      if (!latest.recoverable) throw serviceError('RESTORE_CONFLICT', 'selected legacy JSON fields changed after restore preview');
    } else if (current !== preview.current_sha256) {
      throw serviceError('RESTORE_CONFLICT', 'target changed after restore preview');
    }
    const scope = (await adapter.authorize?.(restoreConfirmationRequest(action, confirmation, preview))) || null;
    try {
      if (action.kind === 'isolate_directory') {
        await adapter.restoreDirectoryIsolation(backup.metadata.isolation_path, action.relative_path);
      } else if (action.kind === 'legacy_json_cleanup') {
        const before = JSON.parse(decodeBytes(source));
        const currentDocument = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
        const merge = previewLegacyRestore(before, currentDocument, action);
        if (!merge.recoverable) throw serviceError('RESTORE_CONFLICT', 'selected legacy JSON fields cannot be merged without overwrite');
        await adapter.writeBytes(action.relative_path, jsonText(merge.proposed));
      } else if (action.kind === 'json_set') {
        const before = JSON.parse(decodeBytes(source));
        const currentDocument = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
        const originalValue = getNested(before, action.selector.field_path);
        if (originalValue === undefined) {
          if (!removeNested(currentDocument, action.selector.field_path)) throw serviceError('RESTORE_CONFLICT', 'added JSON field cannot be removed without overwriting current content');
        } else if (!upsertNested(currentDocument, action.selector.field_path, originalValue)) {
          throw serviceError('RESTORE_CONFLICT', 'selected JSON value cannot be restored without overwriting current content');
        }
        await adapter.writeBytes(action.relative_path, jsonText(currentDocument));
      } else if (action.kind === 'json_remove') {
        const before = JSON.parse(decodeBytes(source));
        const currentDocument = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
        const originalValue = getNested(before, action.selector.field_path);
        if (originalValue === undefined || !setNested(currentDocument, action.selector.field_path, originalValue)) {
          throw serviceError('RESTORE_CONFLICT', 'selected JSON field cannot be merged without overwriting current content');
        }
        await adapter.writeBytes(action.relative_path, jsonText(currentDocument));
      } else if (action.kind === 'site_storage_remove') {
        const before = JSON.parse(decodeBytes(source));
        const currentDocument = JSON.parse(decodeBytes(await adapter.readBytes(action.relative_path)));
        const original = before.entries.find((entry) => matchesSiteEntry(entry, action.selector));
        if (!original || currentDocument.entries.some((entry) => matchesSiteEntry(entry, action.selector))) {
          throw serviceError('RESTORE_CONFLICT', 'selected site storage entry conflicts with current content');
        }
        currentDocument.entries.push(original);
        await adapter.writeBytes(action.relative_path, jsonText(currentDocument));
      } else if (action.kind === 'delete_file') {
        await adapter.writeBytes(action.relative_path, source);
      } else if (action.kind === 'cc_provider_delete' || action.kind === 'cookie_delete') {
        await adapter.restoreDatabaseMutation(action.relative_path, action.kind, action.selector, source);
      } else {
        throw serviceError('UNSUPPORTED_RESTORE', 'restore is not declared for this action kind');
      }
      const result = {
        restore_id: nowId('restore'),
        preview_id: previewId,
        action_id: action.action_id,
        backup_ref: preview.backup_ref,
        restore_source: 'restricted-local-backup',
        status: 'restored',
        restored_at: adapter.clock(),
      };
      adapter.saveRecord('restore', result.restore_id, result);
      return result;
    } finally {
      scope?.release?.();
    }
  }

  async function getReport({scanId, operationId = null}) {
    const scan = findScan(scanId);
    const classification = findClassification(scanId);
    const operation = operationId ? getTask(operationId) : adapter.listRecords('operation').filter((entry) => entry.plan_id && adapter.getRecord(entry.plan_id, 'plan')?.scan_id === scanId).at(-1);
    const plan = operation ? adapter.getRecord(operation.plan_id, 'plan') : null;
    const confirmation = plan ? adapter.getRecord(`confirmation:${plan.plan_id}`, 'confirmation') : null;
    const confirmedActions = confirmation?.actions || [];
    const rechecks = plan
      ? await Promise.all(confirmedActions.map((action) => recheckAction({planId: plan.plan_id, actionId: action.action_id})))
      : [];
    const recheckByAction = new Map(rechecks.map((recheck) => [recheck.action_id, recheck]));
    const currentProblems = classification.problems.map((problem) => {
      const relatedRecommendations = classification.recommendations.filter((recommendation) => recommendation.root_cause_ref === problem.root_cause_ref);
      const hasRetainedTarget = relatedRecommendations.some((recommendation) => plan?.retained_recommendation_ids?.includes(recommendation.recommendation_id));
      const allResolved = relatedRecommendations.length > 0 && !hasRetainedTarget && relatedRecommendations.every((recommendation) => {
        const action = confirmedActions.find((entry) => entry.recommendation_id === recommendation.recommendation_id);
        return action && recheckByAction.get(action.action_id)?.status === 'verified';
      });
      return {
        ...problem,
        current_state: problem.retained || hasRetainedTarget ? 'retained' : allResolved ? 'resolved_by_recheck' : 'remaining_or_unverified',
        closed: problem.false_positive || (!problem.retained && !hasRetainedTarget && allResolved),
      };
    });
    const currentScore = scoreProblems(currentProblems, {
      complete: classification.coverage.status === 'complete',
      gaps: classification.coverage.gaps,
    });
    const accountAnswers = scan.identities.map((identity) => {
      const answer = currentAnswer(identity.identity_ref, scan);
      return answer ? {identity_ref: answer.identity_ref, status: answer.status, recorded_at: answer.recorded_at} : {identity_ref: identity.identity_ref, status: 'missing'};
    });
    const restoreSources = plan
      ? adapter.listRecords('restore').filter((restore) => plan.actions.some((action) => action.action_id === restore.action_id))
      : [];
    const report = redactForExport({
      report_id: nowId('local-report'),
      scan_id: scanId,
      operation_id: operation?.operation_id || null,
      mode: classification.mode,
      ruleset_version: classification.ruleset_version,
      score: currentScore,
      initial_score: classification.score,
      coverage: classification.coverage,
      findings: currentProblems,
      result_groups: classification.result_groups || [],
      receipts: operation?.receipts || [],
      scan_scope: scan.scopes,
      scan_status: scan.status,
      environment_snapshot: scan.environment_snapshot || null,
      account_answers: accountAnswers,
      retained_recommendation_ids: plan?.retained_recommendation_ids || [],
      problem_decisions: adapter.listRecords('problem_decision').filter((decision) => decision.scan_id === scanId),
      rechecks,
      restore_sources: restoreSources,
      source_version: scan.source_version,
      generated_at: adapter.clock(),
    });
    const base = `reports/${report.report_id}`;
    await adapter.writeBytes(`${base}.json`, jsonText(report));
    await adapter.writeBytes(`${base}.md`, makeMarkdownReport(report));
    report.json_path = `${base}.json`;
    report.markdown_path = `${base}.md`;
    adapter.saveRecord('report', report.report_id, report);
    return report;
  }

  /** 授权范围或发现结果变化后换上新的环境声明；已有扫描保留各自当时的环境快照。 */
  function updateEnvironment(next) {
    environment = next && typeof next === 'object' ? next : {};
    return environment;
  }

  return {
    discover,
    updateEnvironment,
    currentEnvironment: () => environment,
    inspectObject,
    recordAccountAnswer,
    classify,
    recordProblemDecision,
    requestSiteCommand,
    recordSiteCommandResponse,
    proposeJsonChange,
    buildActionPlan,
    buildLegacyP0Plan,
    recordLegacyP0Bridge,
    getLegacyP0Bridge,
    confirmActionPlan,
    executeConfirmedPlan,
    resumeOperation,
    listTasks,
    getTask,
    recheckAction,
    previewRestore,
    confirmRestore,
    restoreChange,
    getReport,
  };
}
