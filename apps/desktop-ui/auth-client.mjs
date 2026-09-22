/**
 * 登录生命周期的页面侧传输。
 *
 * 控制端接口：GET /api/setup/status、POST /api/auth/login、GET /api/auth/me、POST /api/auth/logout。
 * 宿主能力：ControlSetupAdmin（首启凭据由宿主附加，页面拿不到）、SessionLoad/Save/Clear（会话材料放在宿主保险库，
 * 不进 localStorage）。角色只取自 /api/auth/me 的服务端回报，不从 AI 或管理接口成败推断。
 */

export const CONTROL_PROTOCOL = 'steward-control-1';

/** 服务端判定会话无效的错误码：Rust 控制端与旧 Node 基线各一个。 */
export const SESSION_REJECTION_CODES = Object.freeze(new Set(['AUTH_SESSION_INVALID', 'CONTROL_UNAUTHORIZED']));

/** 宿主调用的两种失败形态统一成 {ok:false, code, reason}：Tauri 抛出 "CODE: reason" 字符串，替身直接回对象。 */
export async function callBridge(invoke, op, payload = {}) {
  try {
    const result = await invoke(op, payload, null);
    if (result && typeof result === 'object') return result;
    return {ok: false, code: 'NATIVE_RESULT_INVALID', reason: `${op} 没有返回对象`};
  } catch (error) {
    const text = String(error?.message ?? error);
    const match = /^([A-Z][A-Z0-9_]+):\s*([\s\S]*)$/.exec(text);
    return {ok: false, code: error?.code || match?.[1] || 'NATIVE_CALL_FAILED', reason: match?.[2] || text};
  }
}

/** 控制端状态里给页面看的字段；不含任何凭据。 */
export function publicControlStatus(status) {
  if (!status || typeof status !== 'object') {
    return {status: 'failed', mode: 'unknown', error: {code: 'CONTROL_STATUS_MISSING', reason: '宿主没有回报控制端状态'}};
  }
  const picked = {};
  for (const key of ['status', 'mode', 'protocol', 'instance_ref', 'base_url', 'log_file', 'log_status', 'log_dir', 'host_log', 'host_log_status', 'error', 'failure']) {
    if (status[key] !== undefined) picked[key] = status[key];
  }
  return picked;
}

/**
 * 控制端不可用时的替代传输：每个请求都回 503 与宿主给出的具体原因和日志位置。
 * 它不是合成控制端，不返回任何业务数据。
 */
export function createUnavailableControl(status) {
  const control = publicControlStatus(status);
  const error = control.error || {code: 'CONTROL_UNAVAILABLE', reason: '控制端未就绪'};
  return {
    kind: 'unavailable-control',
    base_url: null,
    status: control,
    async handle() {
      return Response.json({
        code: error.code || 'CONTROL_UNAVAILABLE',
        reason: error.reason || '控制端未就绪',
        log_file: control.log_file || null,
        log_dir: control.log_dir || null,
        host_log: control.host_log || null,
      }, {status: 503});
    },
  };
}

/** 控制端还在启动时稍等：宿主在后台线程里做握手，窗口可能先于它就绪。 */
export async function waitForControlReady({invoke, initial, sleep, timeoutMs = 20000, intervalMs = 250}) {
  let status = initial;
  let waited = 0;
  while ((!status || ['starting', 'not_started'].includes(status.status)) && waited <= timeoutMs) {
    if (status) {
      await sleep(intervalMs);
      waited += intervalMs;
    }
    const polled = await callBridge(invoke, 'ControlStatus');
    if (polled.ok !== true) return {status: 'failed', error: {code: polled.code, reason: polled.reason}};
    status = polled.control || {status: 'failed', error: {code: 'CONTROL_STATUS_MISSING', reason: '宿主没有回报控制端状态'}};
  }
  if (!status || ['starting', 'not_started'].includes(status.status)) {
    return {...(status || {}), status: 'failed', error: {code: 'CONTROL_START_TIMEOUT', reason: '控制端在限定时间内没有就绪'}};
  }
  return status;
}

export function createAuthClient({control, invoke}) {
  async function request(method, pathname, {token = null, body} = {}) {
    const headers = {accept: 'application/json'};
    if (token) headers.authorization = `Bearer ${token}`;
    const init = {method, headers};
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await control.handle(new Request(`https://application.invalid${pathname}`, init));
    } catch {
      return {status: 0, body: {code: 'CONTROL_UNREACHABLE', reason: '无法连接控制端'}};
    }
    const text = await response.text();
    if (!text) return {status: response.status, body: null};
    try {
      return {status: response.status, body: JSON.parse(text)};
    } catch {
      return {status: response.status, body: {code: 'CONTROL_RESPONSE_INVALID', reason: '控制端返回的内容无法解析'}};
    }
  }

  return {
    setupStatus: () => request('GET', '/api/setup/status'),
    login: (username, password) => request('POST', '/api/auth/login', {body: {username, password}}),
    me: (token) => request('GET', '/api/auth/me', {token}),
    logout: (token) => request('POST', '/api/auth/logout', {token}),
    get: (pathname, token) => request('GET', pathname, {token}),
    setupAdmin: (username, password) => callBridge(invoke, 'ControlSetupAdmin', {username, password}),
    async loadSession() {
      const loaded = await callBridge(invoke, 'SessionLoad');
      if (loaded.ok !== true) return {session: null, error: {code: loaded.code, reason: loaded.reason}};
      return {session: loaded.session || null, expired: loaded.expired === true};
    },
    saveSession: ({access_token, expires_at, user_ref}) => callBridge(invoke, 'SessionSave', {access_token, expires_at, user_ref}),
    clearSession: () => callBridge(invoke, 'SessionClear'),
  };
}

export function publicIdentity(body) {
  return {
    user_ref: body.user_ref,
    username: body.username || null,
    role: body.role === 'admin' ? 'admin' : 'user',
    status: body.status || null,
    expires_at: body.expires_at || null,
  };
}

/** 直接用某个会话令牌向 /api/auth/me 取服务端身份；取不到就是 null。 */
export async function readServerIdentity(control, token) {
  if (!token) return null;
  const result = await createAuthClient({control, invoke: null}).me(token);
  return result.status === 200 && result.body?.user_ref ? publicIdentity(result.body) : null;
}

function notice(result, fallbackCode, fallbackReason) {
  return {
    code: result?.body?.code || fallbackCode,
    reason: result?.body?.reason || fallbackReason,
    request_ref: result?.body?.request_ref || null,
  };
}

/**
 * 按控制端与保存的会话判断现在处在哪一步：控制端不可用 / 读取失败 / 待首启 / 待登录 / 已登录。
 * 返回的 account 给页面展示，不含令牌；token 只交给组合根装配受权消费者。
 */
export async function readAccount({authClient, control}) {
  const saved = await authClient.loadSession();
  const base = {phase: null, control: publicControlStatus(control.status), identity: null, assignment: null, ai: null, notice: null};
  if (saved.error) base.notice = {...saved.error, reason: `本机会话材料读取失败：${saved.error.reason || ''}`};
  if (control.kind !== 'remote-control') return {account: {...base, phase: 'control_unavailable'}, token: null};

  const setup = await authClient.setupStatus();
  if (setup.status !== 200 || typeof setup.body?.initialized !== 'boolean') {
    return {account: {...base, phase: 'control_error', notice: notice(setup, 'CONTROL_SETUP_STATUS_UNREADABLE', '无法读取控制端的首启状态')}, token: null};
  }
  if (!setup.body.initialized) {
    if (saved.session) await authClient.clearSession();
    return {account: {...base, phase: 'setup_required'}, token: null};
  }
  const token = saved.session?.access_token || null;
  if (!token) {
    const expired = saved.expired ? {code: 'SESSION_EXPIRED', reason: '登录已过期，请重新登录'} : null;
    return {account: {...base, phase: 'login_required', notice: base.notice || expired}, token: null};
  }
  const me = await authClient.me(token);
  if (me.status === 200 && me.body?.user_ref) {
    return {account: {...base, phase: 'authenticated', identity: publicIdentity(me.body)}, token};
  }
  if (me.status === 401) {
    await authClient.clearSession();
    return {account: {...base, phase: 'login_required', notice: notice(me, 'AUTH_SESSION_INVALID', '登录会话已失效，请重新登录')}, token: null};
  }
  return {account: {...base, phase: 'control_error', notice: notice(me, 'AUTH_IDENTITY_UNREADABLE', '无法向控制端确认登录身份')}, token: null};
}

/** 登录后读 AI 可用性与资源分配状态；未实现、未配置、未分配各自如实回报，不当成可用。 */
export async function readEntitlements(authClient, token) {
  const capabilities = await authClient.get('/api/ai/capabilities', token);
  const assigned = await authClient.get('/api/network/assignment', token);
  const tasks = capabilities.status === 200 ? Object.values(capabilities.body?.tasks || {}) : [];
  const ai = capabilities.status !== 200
    ? {available: false, ...notice(capabilities, 'AI_CAPABILITIES_UNREADABLE', 'AI 能力读取失败')}
    : tasks.some((task) => task?.status === 'AVAILABLE')
      ? {available: true}
      : {available: false, code: 'AI_UNAVAILABLE', reason: '服务端没有可用的模型配置'};
  const record = assigned.status === 200 ? assigned.body?.assignment || null : null;
  const assignment = assigned.status !== 200
    ? {status: 'UNAVAILABLE', ...notice(assigned, 'ASSIGNMENT_UNREADABLE', '资源分配读取失败')}
    : !record
      ? {status: 'UNASSIGNED', reason: '管理员尚未为该账号分配网络资源'}
      : record.revoked === true || record.status === 'REVOKED'
        ? {status: 'REVOKED', reason: '管理员已撤销该账号的网络资源分配'}
        : {status: 'ASSIGNED'};
  return {ai, assignment, assignmentRecord: assigned.status === 200 ? assigned.body?.assignment || null : null};
}
