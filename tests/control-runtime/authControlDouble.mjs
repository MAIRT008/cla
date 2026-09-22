import {createHash, randomBytes} from 'node:crypto';
import {mkdirSync} from 'node:fs';
import path from 'node:path';
import {createAuthoritySim} from '../../fixtures/control/authoritySim.mjs';
import {createRemnawaveFakeTransport} from '../../fixtures/control/remnawaveTransport.mjs';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {createControlHandler} from '../../services/control/handler.mjs';
import {createEventService} from '../../services/control/eventService.mjs';
import {handleControlNetworkRoutes} from '../../services/control/networkRoutes.mjs';
import {createQuotaService} from '../../services/control/quotaService.mjs';
import {createRemnawaveQuotaAdapter} from '../../services/control/remnawave/adapter.mjs';
import {openControlStore} from '../../services/control/store.mjs';
import {validateAssignment} from '../../src/core/network/assignment.mjs';
import {validateLoopbackEndpoints} from '../../src/core/network/protectedProcesses.mjs';
import {parseYaml} from '../../src/core/network/yaml.mjs';

/**
 * Rust 控制端（services/control-rs，RC2）HTTP 契约的**替身**，只给页面与传输层的离线用例用。
 *
 * 路径、方法、请求字段与响应形状照 Rust router.rs 与各业务模块写：首启与会话、用户与会话管理、
 * 模型配置与能力、资源/模板/订阅、候选分配与发布、个人凭据、配额适配与额度、最小事件。
 * 配额与事件直接复用 Node 基线的 quotaService / eventService / networkRoutes（Rust 由它们迁移而来），
 * 权威侧是 fixtures 里的 Remnawave 合成替身；其余业务在内存里按 Rust 规则实现。
 *
 * 它不做 Argon2、不落 Rust 的库、不做 DPAPI、不走 HTTP，所以它通过的用例只证明
 * 「页面提交 → 传输适配 → 响应消费」，不能拿来证明 Rust 控制端已经编译或运行。
 */

const MODES = ['daily_single_ip', 'claude_single_ip', 'claude_dual_ip'];
const TASK_TYPES = ['cleanup', 'network_diagnosis', 'daily_analysis'];
const PROTOCOL = {
  cleanup: {prompt: 'cleanup-v1', catalog: 'cleanup-tools-v1'},
  network_diagnosis: {prompt: 'network-diagnosis-v1', catalog: 'network-diagnosis-tools-v1'},
  daily_analysis: {prompt: 'daily-analysis-v1', catalog: 'daily-analysis-tools-v1'},
};
const TEMPLATE_KEYS = new Set(['version', 'claude_domains', 'claude_processes', 'managed_browser_processes', 'protected_process_paths', 'lan_cidrs', 'loopback_endpoints', 'control_plane', 'udp_policy', 'ipv6_policy', 'dns']);
const SECRET_KEY = /password|passwd|secret|token|credential|api_key|apikey|private/i;
const REMNAWAVE_URL = 'https://remnawave.synthetic.invalid';

export function createAuthControlDouble({clock, sessionTtlMs = 12 * 60 * 60 * 1000, business = {}, modelFetch = null} = {}) {
  const setupToken = randomBytes(32).toString('hex');
  const users = [];
  const sessions = new Map();
  const requests = [];
  let initialized = false;
  let counter = 0;
  const nowMs = () => Date.parse(clock());
  const nowIso = () => new Date(nowMs()).toISOString();
  const digest = (text) => createHash('sha256').update(String(text)).digest('hex');
  const newRef = (prefix) => `${prefix}-${randomBytes(8).toString('hex')}`;

  const json = (status, body, headers = {}) => Response.json(body, {status, headers});
  const failure = (status, code, reason, extra = {}) => json(status, {...extra, code, reason, request_ref: `req-double-${(counter += 1)}`});

  // ---- Node 基线的配额与事件服务，接 Remnawave 合成权威。管理员保存配额适配前它是「未配置」。
  const storeDir = transientRun('control-runtime', 'rc2-double');
  mkdirSync(storeDir, {recursive: true});
  const nodeStore = openControlStore({databasePath: path.join(storeDir, 'baseline.sqlite')});
  const authority = createAuthoritySim({clock});
  const remnawaveFetch = createRemnawaveFakeTransport(authority, {baseUrl: REMNAWAVE_URL});
  const quotaAdapter = createRemnawaveQuotaAdapter({baseUrl: null, token: null, fetchImpl: remnawaveFetch, clock});
  const services = {quota: createQuotaService({store: nodeStore, adapter: quotaAdapter, clock}), events: createEventService({store: nodeStore, clock})};
  const adapterState = {enabled: false, base_url_display: null, token_present: false, base_url: null, token: null, timeout_ms: 15000, verification: 'NOT_TESTED', updated_at: null};

  const policies = new Map();
  const modelKeys = new Map();
  const resources = new Map();
  const templates = new Map();
  const sources = new Map();
  const sourceUrls = new Map();
  const candidates = new Map();
  const published = new Map();
  const credentials = new Map();
  /** 与 probes.rs 同一张表的形状：environment_ref → {config, version, updated_by, updated_at}。 */
  const probeServices = new Map();
  const receipts = new Map();

  function normalize(username) {
    const value = String(username ?? '').trim().toLowerCase();
    return /^[a-z0-9][a-z0-9._-]{2,63}$/.test(value) ? value : null;
  }

  function publicUser(user) {
    return {user_ref: user.user_ref, username: user.username, role: user.role, status: user.status};
  }

  function authenticate(request) {
    const match = /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') || '');
    const session = match ? sessions.get(match[1]) : null;
    if (!session || session.revoked || session.expires_at_ms <= nowMs()) return null;
    const user = users.find((item) => item.user_ref === session.user_ref);
    return user && user.status === 'ACTIVE' ? {user, session} : null;
  }

  function onlyKeys(body, allowed) {
    return body && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).every((key) => allowed.includes(key));
  }

  function activeSessions(userRef) {
    return [...sessions.values()].filter((item) => item.user_ref === userRef && !item.revoked && item.expires_at_ms > nowMs()).length;
  }

  function userView(user) {
    return {...publicUser(user), created_at: user.created_at, updated_at: user.updated_at, active_sessions: activeSessions(user.user_ref)};
  }

  function revokeUserSessions(userRef) {
    let revoked = 0;
    for (const session of sessions.values()) {
      if (session.user_ref === userRef && !session.revoked) {
        session.revoked = true;
        revoked += 1;
      }
    }
    return revoked;
  }

  function displayUrl(text) {
    const match = /^([a-z]+):\/\/([^/?#]+)(.*)$/i.exec(text);
    return match ? `${match[1].toLowerCase()}://${match[2].toLowerCase()}${match[3] ? '/…' : ''}` : '（地址格式无法显示）';
  }

  function validServiceUrl(text) {
    const match = /^([a-z]+):\/\/([^/?#]+)/i.exec(text || '');
    if (!match || match[2].includes('@')) return false;
    const host = match[2].split(':')[0].toLowerCase();
    return match[1].toLowerCase() === 'https' || (match[1].toLowerCase() === 'http' && ['127.0.0.1', 'localhost'].includes(host));
  }

  function publicAssignment(record) {
    if (!record) return null;
    const {saved_by: _savedBy, ...rest} = record;
    return structuredClone(rest);
  }

  function modelView(taskType) {
    const policy = policies.get(taskType);
    const secret = modelKeys.has(taskType);
    const reason = !policy ? 'MODEL_NOT_CONFIGURED' : !policy.enabled ? 'MODEL_DISABLED' : !policy.base_url || !policy.model ? 'MODEL_NOT_CONFIGURED' : !secret ? 'MODEL_SECRET_MISSING' : null;
    return {
      task_type: taskType,
      configured: Boolean(policy),
      provider: 'openai-compatible',
      enabled: policy?.enabled || false,
      base_url: policy?.base_url || null,
      model: policy?.model || null,
      policy_version: policy?.policy_version || null,
      max_model_calls: policy?.max_model_calls ?? 8,
      max_total_tokens: policy?.max_total_tokens ?? (taskType === 'daily_analysis' ? 16000 : 64000),
      max_output_tokens: policy?.max_output_tokens ?? 4096,
      timeout_ms: policy?.timeout_ms ?? 60000,
      secret_present: secret,
      status: reason ? 'UNAVAILABLE' : 'AVAILABLE',
      reason,
      verification: policy?.verification || 'NOT_TESTED',
      prompt_version: PROTOCOL[taskType].prompt,
      tool_catalog_version: PROTOCOL[taskType].catalog,
    };
  }

  function adapterView() {
    return {
      kind: 'remnawave',
      configured: Boolean(adapterState.enabled && adapterState.base_url && adapterState.token),
      enabled: adapterState.enabled,
      base_url_present: Boolean(adapterState.base_url),
      base_url_display: adapterState.base_url_display,
      token_present: Boolean(adapterState.token),
      timeout_ms: adapterState.timeout_ms,
      verification: adapterState.verification,
      updated_at: adapterState.updated_at,
      scope_note: '只接 Remnawave 用户额度路径；不代表任意机场订阅都能按用户硬限额',
    };
  }

  function applyAdapter() {
    const on = adapterState.enabled && adapterState.base_url && adapterState.token;
    quotaAdapter.baseUrl = on ? adapterState.base_url : null;
    quotaAdapter.token = on ? adapterState.token : null;
  }

  function sourceView(source) {
    return {...source, url_present: sourceUrls.has(source.source_id)};
  }

  function resourceUsable(resource) {
    if (!resource || resource.status !== 'ACTIVE') return false;
    return !resource.expires_at || Date.parse(resource.expires_at) > nowMs();
  }

  function sensitive(previous, next) {
    if (!previous) return false;
    const aOf = (record) => [record.roles?.A, record.resources?.[record.roles?.A]?.host];
    return JSON.stringify(aOf(previous)) !== JSON.stringify(aOf(next))
      || JSON.stringify(previous.template?.protected_process_paths || []) !== JSON.stringify(next.template?.protected_process_paths || []);
  }

  function ready(validation) {
    return validation.ok && (!validation.allowed_modes.includes('claude_dual_ip') || validation.dual_ip_ready);
  }

  async function readBody(request) {
    const text = request.method === 'GET' || request.method === 'HEAD' ? '' : await request.text();
    try {
      return text ? JSON.parse(text) : null;
    } catch {
      return null;
    }
  }

  async function adminRoute(url, method, body, found) {
    const pathname = url.pathname;
    const query = (key) => url.searchParams.get(key);
    const userByRef = (ref) => users.find((item) => item.user_ref === ref);
    const managed = (ref) => {
      const user = userByRef(ref);
      if (!user) return {error: failure(404, 'CONTROL_USER_NOT_FOUND', '没有这个应用用户')};
      if (user.role !== 'user') return {error: failure(403, 'CONTROL_ADMIN_TARGET_DENIED', '管理员账号不能在这里停用、重置或撤销会话')};
      return {user};
    };

    if (method === 'GET' && pathname === '/api/admin/users') return json(200, {users: users.map(userView)});
    if (method === 'POST' && pathname === '/api/admin/users') {
      if (!onlyKeys(body, ['username', 'password'])) return failure(400, 'CONTROL_REQUEST_INVALID', '请求只接受 username 与 password');
      const username = normalize(body.username);
      if (!username) return failure(400, 'CONTROL_REQUEST_INVALID', '账号格式不对');
      if (typeof body.password !== 'string' || body.password.length < 12) return failure(400, 'CONTROL_REQUEST_INVALID', '密码至少 12 个字符');
      if (users.some((item) => item.username === username)) return failure(409, 'CONTROL_USER_CONFLICT', '这个账号名已被使用');
      const user = {user_ref: newRef('usr'), username, secret: digest(body.password), role: 'user', status: 'ACTIVE', created_at: nowIso(), updated_at: nowIso()};
      users.push(user);
      return json(201, {user: userView(user)});
    }
    if (method === 'POST' && pathname === '/api/admin/users/status') {
      const target = managed(body?.user_ref);
      if (target.error) return target.error;
      if (!['ACTIVE', 'DISABLED'].includes(body.status)) return failure(400, 'CONTROL_REQUEST_INVALID', 'status 只能是 ACTIVE 或 DISABLED');
      target.user.status = body.status;
      target.user.updated_at = nowIso();
      const revoked = body.status === 'DISABLED' ? revokeUserSessions(target.user.user_ref) : 0;
      return json(200, {user: userView(target.user), revoked_sessions: revoked});
    }
    if (method === 'POST' && pathname === '/api/admin/users/password-reset') {
      const target = managed(body?.user_ref);
      if (target.error) return target.error;
      if (typeof body.password !== 'string' || body.password.length < 12) return failure(400, 'CONTROL_REQUEST_INVALID', '密码至少 12 个字符');
      target.user.secret = digest(body.password);
      return json(200, {user_ref: target.user.user_ref, password_reset: true, revoked_sessions: revokeUserSessions(target.user.user_ref), updated_at: nowIso()});
    }
    if (method === 'GET' && pathname === '/api/admin/sessions') {
      const user = userByRef(query('user_ref'));
      if (!user) return failure(404, 'CONTROL_USER_NOT_FOUND', '没有这个应用用户');
      const list = [...sessions.values()].filter((item) => item.user_ref === user.user_ref).map((item) => ({
        session_ref: item.session_ref,
        status: item.revoked ? 'REVOKED' : item.expires_at_ms <= nowMs() ? 'EXPIRED' : 'ACTIVE',
        created_at: item.created_at,
        expires_at: new Date(item.expires_at_ms).toISOString(),
      }));
      return json(200, {user_ref: user.user_ref, username: user.username, sessions: list});
    }
    if (method === 'POST' && pathname === '/api/admin/sessions/revoke') {
      const target = managed(body?.user_ref);
      if (target.error) return target.error;
      return json(200, {target: {user_ref: target.user.user_ref}, user_ref: target.user.user_ref, revoked: revokeUserSessions(target.user.user_ref), revoked_at: nowIso()});
    }

    if (method === 'GET' && pathname === '/api/admin/model-config') {
      return json(200, {provider: 'openai-compatible', tasks: Object.fromEntries(TASK_TYPES.map((task) => [task, modelView(task)]))});
    }
    if (method === 'PUT' && pathname === '/api/admin/model-config') {
      const allowed = ['task_type', 'enabled', 'base_url', 'model', 'policy_version', 'max_model_calls', 'max_total_tokens', 'max_output_tokens', 'timeout_ms', 'api_key', 'clear_api_key'];
      if (!onlyKeys(body, allowed)) return failure(400, 'CONTROL_REQUEST_INVALID', '请求含不接受的字段');
      if (!TASK_TYPES.includes(body.task_type)) return failure(400, 'MODEL_CONFIG_INVALID', 'task_type 不认识', {field: 'task_type'});
      if (body.base_url && !validServiceUrl(body.base_url)) return failure(400, 'CONTROL_REQUEST_INVALID', '字段 base_url 必须是 https 地址', {field: 'base_url'});
      const existing = policies.get(body.task_type);
      if (!existing && !body.policy_version) return failure(400, 'MODEL_CONFIG_INVALID', '首次保存必须给出 policy_version', {field: 'policy_version'});
      const next = {...(existing || {verification: 'NOT_TESTED'})};
      for (const key of ['enabled', 'base_url', 'model', 'policy_version', 'max_model_calls', 'max_total_tokens', 'max_output_tokens', 'timeout_ms']) {
        if (body[key] !== undefined) next[key] = body[key];
      }
      if (body.api_key) modelKeys.set(body.task_type, body.api_key);
      if (body.clear_api_key) modelKeys.delete(body.task_type);
      if (body.api_key || body.base_url || body.model || body.clear_api_key) next.verification = 'NOT_TESTED';
      policies.set(body.task_type, next);
      return json(200, {task: modelView(body.task_type)});
    }

    if (method === 'GET' && pathname === '/api/admin/quota-adapter') return json(200, {adapter: adapterView()});
    if (method === 'PUT' && pathname === '/api/admin/quota-adapter') {
      if (!onlyKeys(body, ['kind', 'enabled', 'base_url', 'token', 'timeout_ms', 'clear_secrets'])) return failure(400, 'CONTROL_REQUEST_INVALID', '请求含不接受的字段');
      if (body.base_url && !validServiceUrl(body.base_url)) return failure(400, 'QUOTA_ADAPTER_INVALID', 'base_url 必须是 https 地址', {field: 'base_url'});
      if (typeof body.enabled === 'boolean') adapterState.enabled = body.enabled;
      if (body.base_url) {
        adapterState.base_url = body.base_url;
        adapterState.base_url_display = displayUrl(body.base_url);
      }
      if (body.token) adapterState.token = body.token;
      if (body.timeout_ms) adapterState.timeout_ms = body.timeout_ms;
      if (body.base_url || body.token) adapterState.verification = 'NOT_TESTED';
      adapterState.updated_at = nowIso();
      applyAdapter();
      return json(200, {adapter: adapterView()});
    }

    if (method === 'GET' && pathname === '/api/admin/resources') return json(200, {resources: [...resources.values()], sources: [...sources.values()].map(sourceView)});
    if (method === 'PUT' && pathname === '/api/admin/resources') {
      if (!onlyKeys(body, ['resource_id', 'role', 'kind', 'host', 'port', 'sharing', 'status', 'expires_at', 'credential_ref'])) return failure(400, 'CONTROL_REQUEST_INVALID', '请求含不接受的字段');
      if (!body.resource_id || !['front', 'A', 'B'].includes(body.role) || !body.host) return failure(400, 'RESOURCE_INVALID', 'resource_id、role、host 必填');
      if (body.status && !['ACTIVE', 'DISABLED'].includes(body.status)) return failure(400, 'RESOURCE_INVALID', 'status 只能是 ACTIVE 或 DISABLED');
      const existing = resources.get(body.resource_id);
      const saved = {
        resource_id: body.resource_id,
        role: body.role,
        kind: 'socks5',
        host: String(body.host).toLowerCase(),
        port: body.port ?? 1080,
        sharing: body.sharing || 'shared',
        status: body.status || 'ACTIVE',
        expires_at: body.expires_at ? new Date(Date.parse(body.expires_at)).toISOString() : null,
        credential_ref: body.credential_ref || `cred-${body.resource_id}`,
        version: (existing?.version || 0) + 1,
        updated_at: nowIso(),
      };
      resources.set(saved.resource_id, saved);
      return json(200, {ok: true, resource: saved, created: !existing});
    }

    if (method === 'GET' && pathname === '/api/admin/templates') return json(200, {templates: [...templates.values()]});
    if (method === 'PUT' && pathname === '/api/admin/templates') {
      if (!onlyKeys(body, ['template_id', 'template', 'version', 'status', 'published'])) return failure(400, 'CONTROL_REQUEST_INVALID', '请求含不接受的字段');
      if (!body.template_id || !body.template || typeof body.template !== 'object') return failure(400, 'TEMPLATE_INVALID', 'template 必填', {path: 'template'});
      const unknown = Object.keys(body.template).find((key) => !TEMPLATE_KEYS.has(key));
      if (unknown) return failure(400, 'TEMPLATE_INVALID', `template.${unknown} 不是认识的模板字段`, {path: `template.${unknown}`});
      if (SECRET_KEY.test(JSON.stringify(Object.keys(body.template.dns || {})))) return failure(400, 'TEMPLATE_SECRET_REJECTED', '模板不保存秘密', {path: 'template.dns'});
      const loopback = validateLoopbackEndpoints(body.template.loopback_endpoints, body.template.protected_process_paths || []);
      if (!loopback.ok) return failure(400, 'TEMPLATE_INVALID', `template.${loopback.path} ${loopback.reason}`, {path: `template.${loopback.path}`});
      const existing = templates.get(body.template_id);
      const numeric = (existing?.numeric_version || 0) + 1;
      const version = body.version || `template-v${numeric}`;
      const saved = {template_id: body.template_id, version, numeric_version: numeric, status: body.status || 'ACTIVE', published: body.published === true, template: {...structuredClone(body.template), version}, updated_at: nowIso()};
      templates.set(saved.template_id, saved);
      return json(200, {ok: true, template: saved});
    }

    if (method === 'GET' && pathname === '/api/admin/subscriptions') return json(200, {sources: [...sources.values()].map(sourceView)});
    if (method === 'PUT' && pathname === '/api/admin/subscriptions') {
      if (!onlyKeys(body, ['source_id', 'format', 'status', 'url', 'clear_url'])) return failure(400, 'CONTROL_REQUEST_INVALID', '请求含不接受的字段');
      if (!body.source_id) return failure(400, 'CONTROL_REQUEST_INVALID', 'source_id 必填');
      if (body.url && !validServiceUrl(body.url)) return failure(400, 'SOURCE_INVALID', 'url 必须是 https 地址');
      const existing = sources.get(body.source_id);
      const saved = {
        source_id: body.source_id,
        format: body.format || existing?.format || 'clash-yaml',
        status: body.status || existing?.status || 'PENDING',
        url_display: body.url ? displayUrl(body.url) : existing?.url_display || null,
        version: (existing?.version || 0) + 1,
        refreshed_at: existing?.refreshed_at || null,
        proxy_count: existing?.proxy_count || 0,
        proxy_names: existing?.proxy_names || [],
        error: existing?.error || null,
        updated_at: nowIso(),
      };
      if (body.url) sourceUrls.set(body.source_id, body.url);
      if (body.clear_url) {
        sourceUrls.delete(body.source_id);
        saved.url_display = null;
      }
      sources.set(saved.source_id, saved);
      return json(200, {ok: true, source: sourceView(saved)});
    }
    if (method === 'POST' && pathname === '/api/admin/subscriptions/refresh') {
      const source = sources.get(body?.source_id);
      if (!source) return failure(404, 'SOURCE_NOT_FOUND', '没有这个订阅源');
      if (!body.body && !sourceUrls.has(source.source_id)) return failure(400, 'SOURCE_EMPTY', '没有提供订阅内容，订阅源也没有保存地址');
      const done = (status, extra) => {
        Object.assign(source, {status, refreshed_at: nowIso(), updated_at: nowIso(), error: extra.code || null});
        return json(200, {ok: status === 'ACTIVE', source: sourceView(source), ...extra});
      };
      if (!body.body) return done('FAILED', {code: 'SOURCE_FETCH_FAILED'});
      if (!['clash-yaml', 'mihomo-yaml'].includes(source.format)) return done('UNSUPPORTED', {code: 'UNSUPPORTED'});
      let parsed;
      try {
        parsed = parseYaml(body.body);
      } catch {
        return done('FAILED', {code: 'YAML_PARSE_FAILED'});
      }
      if (!Array.isArray(parsed?.proxies)) return done('UNSUPPORTED', {code: 'UNSUPPORTED'});
      source.proxy_count = parsed.proxies.length;
      source.proxy_names = parsed.proxies.map((item) => item?.name).filter(Boolean);
      return done('ACTIVE', {proxies: parsed.proxies.map((item) => ({name: item.name, type: item.type, server: item.server, port: item.port}))});
    }

    if (method === 'GET' && pathname === '/api/admin/assignments') {
      const userRef = query('user_ref');
      if (!userByRef(userRef)) return failure(404, 'CONTROL_USER_NOT_FOUND', '没有这个应用用户');
      const subject = candidates.get(userRef) || published.get(userRef) || null;
      const validation = validateAssignment(subject, {environment_ref: query('environment_ref') || undefined}, nowIso());
      return json(200, {user_ref: userRef, candidate: publicAssignment(candidates.get(userRef)), published: publicAssignment(published.get(userRef)), assignment: publicAssignment(subject), validation, ready: subject ? ready(validation) : false});
    }
    if (method === 'POST' && pathname === '/api/admin/assignments') {
      const userRef = body?.userRef || body?.user_ref;
      if (!userByRef(userRef)) return failure(404, 'CONTROL_USER_NOT_FOUND', '没有这个应用用户');
      if (!body.validUntil || !Number.isFinite(Date.parse(body.validUntil))) return failure(400, 'ASSIGNMENT_INVALID', 'validUntil 必填', {field: 'validUntil'});
      if (!body.roles?.A) return failure(400, 'ASSIGNMENT_INVALID', 'roles.A 必填', {field: 'roles'});
      const modes = body.allowedModes || [];
      if (modes.some((mode) => !MODES.includes(mode))) return failure(400, 'MODE_NOT_ALLOWED', '不认识的方案');
      const ids = [...new Set([...(body.resources || []).map((item) => (typeof item === 'string' ? item : item?.resource_id)), ...Object.values(body.roles)])].filter(Boolean);
      const snapshot = {};
      for (const id of ids) {
        const resource = resources.get(id);
        if (!resource) return failure(404, 'RESOURCE_NOT_FOUND', `没有资源 ${id}`, {resource_id: id});
        snapshot[id] = structuredClone(resource);
      }
      for (const [role, id] of Object.entries(body.roles)) {
        if (snapshot[id].role !== role) return failure(400, 'ROLE_MISMATCH', `资源 ${id} 的角色是 ${snapshot[id].role}，不能用作 ${role}`, {field: 'roles'});
      }
      const template = body.templateId ? templates.get(body.templateId) : [...templates.values()].filter((item) => item.published).at(-1);
      if (!template) return failure(body.templateId ? 404 : 409, body.templateId ? 'TEMPLATE_NOT_FOUND' : 'TEMPLATE_UNAVAILABLE', '没有可用的方案模板');
      const version = Math.max(candidates.get(userRef)?.assignment_version || 0, published.get(userRef)?.assignment_version || 0) + 1;
      const record = {
        user_ref: userRef,
        environment_ref: body.environmentRef || null,
        account_class: body.accountClass || null,
        assignment_version: version,
        allowed_modes: modes,
        roles: structuredClone(body.roles),
        resource_refs: {front: body.roles.front || Object.values(snapshot).find((item) => item.role === 'front')?.resource_id || null, exit_a: body.roles.A, exit_b: body.roles.B || null},
        resources: snapshot,
        valid_until: new Date(Date.parse(body.validUntil)).toISOString(),
        status: 'DRAFT',
        revoked: false,
        published: false,
        template_id: template.template_id,
        template_version: template.version,
        classification_version: 'product-v1',
        template: structuredClone(template.template),
        saved_by: found.user.user_ref,
      };
      candidates.set(userRef, record);
      const validation = validateAssignment(record, {environment_ref: record.environment_ref || undefined}, nowIso());
      return json(200, {ok: true, assignment: publicAssignment(record), validation, ready: ready(validation)});
    }
    if (method === 'POST' && pathname === '/api/admin/assignments/publish') {
      const userRef = body?.userRef || body?.user_ref;
      const candidate = candidates.get(userRef);
      if (!candidate) return failure(404, 'ASSIGNMENT_NOT_FOUND', '该用户没有待发布的候选分配');
      const validation = validateAssignment(candidate, {environment_ref: candidate.environment_ref || undefined}, nowIso());
      if (!ready(validation)) return json(200, {ok: false, code: validation.code === 'ASSIGNMENT_VALID' ? 'ASSIGNMENT_NOT_READY' : validation.code, ready: false, validation, assignment: publicAssignment(candidate)});
      const next = {...structuredClone(candidate), status: 'ACTIVE', revoked: false, published: true, published_at: nowIso()};
      const isSensitive = sensitive(published.get(userRef), next);
      if (isSensitive && body.confirmation?.confirmed !== true) {
        return json(200, {ok: false, code: 'SENSITIVE_CHANGE_CONFIRMATION_REQUIRED', ready: true, sensitive: true, validation, assignment: publicAssignment(next)});
      }
      published.set(userRef, next);
      candidates.delete(userRef);
      nodeStore.saveAssignment(next);
      const receipt = {receipt_id: `published:${userRef}:${next.assignment_version}`, assignment_version: next.assignment_version, published_at: next.published_at};
      return json(200, {ok: true, ready: true, validation, sensitive: isSensitive, assignment: publicAssignment(next), receipt});
    }
    if (method === 'POST' && pathname === '/api/admin/assignments/revoke') {
      const userRef = body?.userRef || body?.user_ref;
      const current = published.get(userRef);
      if (!current) return failure(404, 'ASSIGNMENT_NOT_FOUND', '该用户没有已发布的分配');
      const next = {...current, status: 'REVOKED', revoked: true, published: false, revoked_at: nowIso()};
      published.set(userRef, next);
      nodeStore.saveAssignment(next);
      return json(200, {ok: true, assignment: publicAssignment(next)});
    }

    if (method === 'GET' && pathname === '/api/admin/credentials') {
      const userRef = query('user_ref');
      if (!userByRef(userRef)) return failure(404, 'CONTROL_USER_NOT_FOUND', '没有这个应用用户');
      const list = [...credentials.entries()].filter(([key]) => key.startsWith(`${userRef} `)).map(([, item]) => ({credential_ref: item.credential_ref, status: item.status, version: item.version, secret_present: Boolean(item.material), updated_at: item.updated_at}));
      return json(200, {user_ref: userRef, credentials: list});
    }
    if (method === 'PUT' && pathname === '/api/admin/credentials') {
      if (!onlyKeys(body, ['user_ref', 'credential_ref', 'username', 'password'])) return failure(400, 'CONTROL_REQUEST_INVALID', '请求含不接受的字段');
      if (!userByRef(body.user_ref)) return failure(404, 'CONTROL_USER_NOT_FOUND', '没有这个应用用户');
      if (!body.credential_ref || !body.username) return failure(400, 'CREDENTIAL_INVALID', 'credential_ref 与 username 必填');
      const key = `${body.user_ref} ${body.credential_ref}`;
      const previous = credentials.get(key);
      const saved = {credential_ref: body.credential_ref, status: 'ACTIVE', version: (previous?.version || 0) + 1, material: {username: body.username, password: body.password ?? null}, updated_at: nowIso()};
      credentials.set(key, saved);
      return json(200, {ok: true, user_ref: body.user_ref, credential: {credential_ref: saved.credential_ref, status: saved.status, version: saved.version, secret_present: true, updated_at: saved.updated_at}});
    }
    if (method === 'POST' && pathname === '/api/admin/credentials/revoke') {
      const key = `${body?.user_ref} ${body?.credential_ref}`;
      const current = credentials.get(key);
      if (!current) return failure(404, 'CREDENTIAL_NOT_FOUND', '该用户没有这条凭据');
      Object.assign(current, {status: 'REVOKED', material: null, updated_at: nowIso()});
      return json(200, {ok: true, user_ref: body.user_ref, credential: {credential_ref: current.credential_ref, status: 'REVOKED', version: current.version, secret_present: false, updated_at: current.updated_at}});
    }

    if (method === 'GET' && pathname === '/api/admin/service-state') {
      return json(200, {control_status: 'AVAILABLE', adapter_configured: adapterView().configured, adapter: adapterView(), model_tasks_available: TASK_TYPES.filter((task) => modelView(task).status === 'AVAILABLE').length, secret_protection: 'double-in-memory', schema_version: '3', log_status: 'ok', observed_at: nowIso()});
    }

    if (method === 'GET' && pathname === '/api/admin/probe-services') {
      return json(200, {probe_services: [...probeServices.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([environment_ref, item]) => ({environment_ref, ...structuredClone(item)}))});
    }
    if (method === 'PUT' && pathname === '/api/admin/probe-services') {
      const invalid = (field, reason) => failure(400, 'PROBE_SERVICES_INVALID', reason, {field});
      if (!onlyKeys(body, ['environment_ref', 'echo_url', 'doh_url', 'probe_base_url', 'intel_url', 'stun_urls', 'client_kind', 'webrtc', 'expected_version'])) {
        return failure(400, 'CONTROL_REQUEST_INVALID', '请求含不接受的字段');
      }
      const reference = body.environment_ref;
      if (typeof reference !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(reference)) return invalid('environment_ref', 'environment_ref 只能含小写字母、数字与连字符');
      const config = {};
      for (const key of ['echo_url', 'doh_url', 'probe_base_url', 'intel_url']) {
        if (body[key] === undefined || body[key] === null) continue;
        if (!validServiceUrl(body[key])) return failure(400, 'CONTROL_REQUEST_INVALID', `字段 ${key} 必须是 https 地址（http 只允许本机回环）`, {field: key});
        config[key] = body[key];
      }
      if (!Object.keys(config).length) return invalid('echo_url', '至少要配置回显、DoH、Probe 或情报中的一个地址');
      if (body.stun_urls !== undefined) {
        const list = Array.isArray(body.stun_urls) ? body.stun_urls : null;
        if (!list || list.length > 4 || list.some((url) => typeof url !== 'string' || !/^stuns?:[A-Za-z0-9.:[\]-]+$/.test(url))) return invalid('stun_urls', 'stun_urls 只收 stun: 或 stuns: 地址，最多 4 个');
        config.stun_urls = list.slice();
      }
      if (body.client_kind !== undefined) {
        if (!['webview', 'wsl-cli', 'cli'].includes(body.client_kind)) return invalid('client_kind', 'client_kind 只能是 webview、wsl-cli 或 cli');
        config.client_kind = body.client_kind;
      }
      if (typeof body.webrtc === 'boolean') config.webrtc = body.webrtc;
      const previous = probeServices.get(reference)?.version || 0;
      if (body.expected_version !== undefined && body.expected_version !== previous) {
        return failure(409, 'PROBE_SERVICES_CONFLICT', '这个环境的配置已被改过，请刷新后再改', {current_version: previous});
      }
      const saved = {config, version: previous + 1, updated_by: found.user.user_ref, updated_at: nowIso()};
      probeServices.set(reference, saved);
      return json(200, {ok: true, probe_services: {environment_ref: reference, ...structuredClone(saved)}});
    }
    if (method === 'POST' && pathname === '/api/admin/probe-services/remove') {
      if (!probeServices.delete(body?.environment_ref)) return failure(404, 'PROBE_SERVICES_NOT_FOUND', '这个环境没有探测服务配置');
      return json(200, {ok: true, removed: body.environment_ref});
    }
    return null;
  }

  function networkCredentials(userRef) {
    const empty = (code) => ({user_ref: userRef, status: 'UNAVAILABLE', code, credentials: {}, withheld: []});
    const assignment = published.get(userRef);
    if (!assignment) return empty('ASSIGNMENT_NOT_FOUND');
    const validation = validateAssignment(assignment, {}, nowIso());
    if (!validation.ok) return empty(validation.code);
    const quotaStatus = nodeStore.getQuotaSnapshot(userRef)?.status;
    if (['DISABLED', 'EXPIRED'].includes(quotaStatus)) return empty(`QUOTA_${quotaStatus}`);
    const issued = {};
    const withheld = [];
    for (const [resourceId, snapshot] of Object.entries(assignment.resources || {})) {
      const ref = snapshot.credential_ref;
      if (!ref || issued[ref]) continue;
      if (!resourceUsable(resources.get(resourceId))) {
        withheld.push({credential_ref: ref, reason: 'RESOURCE_UNAVAILABLE'});
        continue;
      }
      const credential = credentials.get(`${userRef} ${ref}`);
      if (!credential) withheld.push({credential_ref: ref, reason: 'CREDENTIAL_NOT_ISSUED'});
      else if (credential.status !== 'ACTIVE') withheld.push({credential_ref: ref, reason: 'CREDENTIAL_REVOKED'});
      else issued[ref] = {...credential.material};
    }
    return {user_ref: userRef, status: Object.keys(issued).length ? 'AVAILABLE' : 'UNAVAILABLE', code: null, credentials: issued, withheld};
  }

  async function aiRoute(url, method, body, found, request) {
    if (method === 'GET' && url.pathname === '/api/ai/capabilities') {
      const tasks = Object.fromEntries(TASK_TYPES.map((task) => {
        const view = modelView(task);
        return [task, view.status === 'AVAILABLE'
          ? {status: 'AVAILABLE', policy_version: view.policy_version, catalog_version: view.tool_catalog_version, verification: view.verification}
          : {status: 'UNAVAILABLE', reason: view.reason}];
      }));
      return json(200, {user_ref: found.user.user_ref, tasks});
    }
    if (method === 'POST' && url.pathname === '/api/ai/turn') {
      const view = TASK_TYPES.includes(body?.task_type) ? modelView(body.task_type) : null;
      if (view && view.status !== 'AVAILABLE') return failure(503, 'AI_UNAVAILABLE', view.reason);
      const policy = policies.get(body?.task_type);
      const handler = createControlHandler({
        auth: {authenticate: () => ({user_ref: found.user.user_ref, role: found.user.role, status: 'ACTIVE'})},
        store: nodeStore,
        modelPolicies: policy ? {[body.task_type]: {status: 'AVAILABLE', version: policy.policy_version, secret_ref: body.task_type, base_url: policy.base_url, model: policy.model, maxModelCalls: policy.max_model_calls, maxTotalTokens: policy.max_total_tokens, timeoutMs: policy.timeout_ms}} : {},
        secrets: {resolve: (ref) => modelKeys.get(ref)},
        sdkFetch: modelFetch || (async () => { throw Object.assign(new Error('offline double: no model transport'), {status: 503}); }),
        clock,
      });
      const forwarded = new Request(request.url, {method: 'POST', headers: request.headers, body: JSON.stringify(body)});
      const response = await handler.handle(forwarded);
      if (response.status === 401) return json(502, await response.json());
      return response;
    }
    return null;
  }

  async function handle(request) {
    const url = new URL(request.url);
    const body = await readBody(request);
    const bearer = /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') || '')?.[1] || null;
    requests.push({
      method: request.method,
      path: url.pathname,
      query: url.search,
      bearer,
      body_keys: body && typeof body === 'object' ? Object.keys(body).sort() : [],
      setup_token_header: request.headers.has('x-steward-setup-token'),
    });

    if (request.method === 'GET' && url.pathname === '/health') {
      return json(200, {service: 'ai-steward-control', protocol: 'steward-control-1', instance_ref: 'ctl-double', status: 'ready'});
    }
    if (request.method === 'GET' && url.pathname === '/api/setup/status') return json(200, {initialized});
    if (request.method === 'POST' && url.pathname === '/api/setup/admin') {
      if (initialized) return failure(409, 'CONTROL_SETUP_CONFLICT', '控制端已经完成首次初始化，不能重复创建管理员');
      if (request.headers.get('x-steward-setup-token') !== setupToken) return failure(403, 'CONTROL_SETUP_TOKEN_INVALID', '首启凭据缺失或不匹配');
      if (!onlyKeys(body, ['username', 'password']) || typeof body.username !== 'string' || typeof body.password !== 'string') return failure(400, 'CONTROL_REQUEST_INVALID', '请求只接受 username 与 password');
      const username = normalize(body.username);
      if (!username) return failure(400, 'CONTROL_REQUEST_INVALID', '账号格式不对');
      if (body.password.length < 12) return failure(400, 'CONTROL_REQUEST_INVALID', '密码至少 12 个字符');
      const user = {user_ref: newRef('usr'), username, secret: digest(body.password), role: 'admin', status: 'ACTIVE', created_at: nowIso(), updated_at: nowIso()};
      users.push(user);
      initialized = true;
      return json(201, {initialized: true, user: publicUser(user)});
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/login') {
      if (!onlyKeys(body, ['username', 'password']) || typeof body.username !== 'string' || typeof body.password !== 'string') return failure(400, 'CONTROL_REQUEST_INVALID', '请求只接受 username 与 password');
      const user = users.find((item) => item.username === normalize(body.username));
      if (!user || user.secret !== digest(body.password) || user.status !== 'ACTIVE') {
        return failure(401, 'AUTH_LOGIN_REJECTED', '账号或密码不正确，或该账号当前不可用');
      }
      const token = randomBytes(32).toString('hex');
      const expiresAtMs = nowMs() + sessionTtlMs;
      sessions.set(token, {session_ref: newRef('ses'), user_ref: user.user_ref, expires_at_ms: expiresAtMs, revoked: false, created_at: nowIso()});
      return json(200, {access_token: token, expires_at: new Date(expiresAtMs).toISOString(), user: publicUser(user)});
    }
    if (request.method === 'GET' && url.pathname === '/api/auth/me') {
      const found = authenticate(request);
      if (!found) return failure(401, 'AUTH_SESSION_INVALID', '登录会话已失效、已注销或账号已停用，请重新登录');
      return json(200, {...publicUser(found.user), expires_at: new Date(found.session.expires_at_ms).toISOString()});
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
      if (!bearer) return failure(401, 'AUTH_SESSION_INVALID', '没有可注销的登录会话');
      const session = sessions.get(bearer);
      if (session) session.revoked = true;
      return new Response(null, {status: 204});
    }
    if (!url.pathname.startsWith('/api/')) return failure(404, 'CONTROL_NOT_FOUND', '控制端没有这个接口');

    const found = authenticate(request);
    if (!found) return failure(401, 'AUTH_SESSION_INVALID', '登录会话已失效、已注销或账号已停用，请重新登录');
    if (url.pathname.startsWith('/api/admin/') && found.user.role !== 'admin') return failure(403, 'CONTROL_FORBIDDEN', '该操作需要管理员权限');
    const override = business[url.pathname];
    if (override) return override({user: publicUser(found.user), json, body, request});

    if (url.pathname.startsWith('/api/admin/') && !url.pathname.startsWith('/api/admin/quota/') && url.pathname !== '/api/admin/events') {
      const response = await adminRoute(url, request.method, body, found);
      if (response) return response;
    }
    const ai = await aiRoute(url, request.method, body, found, request);
    if (ai) return ai;
    if (request.method === 'GET' && url.pathname === '/api/network/assignment') {
      return json(200, {user_ref: found.user.user_ref, assignment: publicAssignment(published.get(found.user.user_ref)), quota: nodeStore.getQuotaSnapshot(found.user.user_ref) || null});
    }
    if (request.method === 'GET' && url.pathname === '/api/network/probe-services') {
      return json(200, {environments: Object.fromEntries([...probeServices.entries()].map(([reference, item]) => [reference, structuredClone(item.config)]))});
    }
    if (request.method === 'GET' && url.pathname === '/api/network/credentials') {
      return json(200, networkCredentials(found.user.user_ref), {'cache-control': 'no-store'});
    }
    if (request.method === 'POST' && url.pathname === '/api/network/receipts') {
      if (!body?.operation_id) return failure(400, 'CONTROL_REQUEST_INVALID', 'operation_id 必填');
      const {yaml: _yaml, core_secret: _secret, ...kept} = body;
      receipts.set(`${found.user.user_ref} ${body.operation_id}`, {...kept, user_ref: found.user.user_ref});
      return json(200, {status: 'RECORDED', operation_id: body.operation_id});
    }
    // 配额、额度与最小事件：交给 Node 基线路由（Rust quota.rs / events.rs 由此迁移）。
    const forwarded = new Request(request.url, {method: request.method, headers: request.headers, body: body === null ? undefined : JSON.stringify(body)});
    const baseline = await handleControlNetworkRoutes(forwarded, {actor: {user_ref: found.user.user_ref, role: found.user.role, status: 'ACTIVE'}, store: nodeStore, services, clock});
    if (baseline) {
      if (baseline.status === 401) return json(502, await baseline.json());
      return baseline;
    }
    return failure(404, 'CONTROL_NOT_FOUND', '控制端没有这个接口');
  }

  return {
    handle,
    requests,
    authority,
    remnawave: {url: REMNAWAVE_URL, token: authority.token},
    users: () => users.map(publicUser),
    /** 宿主 ControlSetupAdmin 的位置：附上一次性凭据后转交，回包形状与 Rust ControlSupervisor::setup_admin 一致。 */
    async setupFromHost({username, password}) {
      const response = await handle(new Request('http://127.0.0.1/api/setup/admin', {
        method: 'POST',
        headers: {'content-type': 'application/json', 'x-steward-setup-token': setupToken},
        body: JSON.stringify({username, password}),
      }));
      const parsed = await response.json();
      if (response.status === 201) return {ok: true, status: 201, user: parsed.user};
      return {ok: false, status: response.status, code: parsed.code, reason: parsed.reason, request_ref: parsed.request_ref};
    },
    /** 直接登记一个用户（不经管理页），给只关心登录的用例用。 */
    addUser(username, password, role = 'user') {
      const user = {user_ref: newRef('usr'), username: normalize(username), secret: digest(password), role, status: 'ACTIVE', created_at: nowIso(), updated_at: nowIso()};
      users.push(user);
      return publicUser(user);
    },
    expireAllSessions() {
      for (const session of sessions.values()) session.expires_at_ms = nowMs();
    },
    sessionState(token) {
      const session = sessions.get(token);
      if (!session) return 'UNKNOWN';
      if (session.revoked) return 'REVOKED';
      return session.expires_at_ms > nowMs() ? 'ACTIVE' : 'EXPIRED';
    },
    /** 用某个会话令牌直接取凭据接口的响应（测试核对隔离用）。 */
    credentialsFor(token) {
      const session = sessions.get(token);
      return session ? networkCredentials(session.user_ref) : null;
    },
    /** 调试核对：替身内部是否存有某段文本（用于断言秘密没有出现在页面状态里，而不是替身里）。 */
    storedModelKey(taskType) {
      return modelKeys.get(taskType) || null;
    },
    close() {
      nodeStore.close();
    },
  };
}
