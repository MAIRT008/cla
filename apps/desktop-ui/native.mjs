import {createBridgeWorkspaceAdapter} from '../../src/adapters/local/bridgeWorkspace.mjs';
import {createBridgeAuditStore} from '../../src/adapters/audit/bridgeStore.mjs';
import {createDiagnosticExport} from '../../src/adapters/audit/diagnosticExport.mjs';
import {loadAiNotes, loadAuditReports} from '../../src/adapters/audit/reports.mjs';
import {createAuditRuntime} from '../../src/adapters/audit/runtime.mjs';
import {createLocalService} from '../../src/core/local/index.mjs';
import {createNetworkController, productAuditMapping} from '../../src/core/network/index.mjs';
import {createDiagnosticsController} from '../../src/core/diagnostics/index.mjs';
import {createDefaultBrowserDiagnostics} from '../../src/adapters/diagnostics/defaultBrowser.mjs';
import {createAiClient} from '../../src/core/ai/index.mjs';
import {createHandlerTransport} from '../../src/core/ai/controlTransport.mjs';
import {callBridge, publicControlStatus, readServerIdentity} from './auth-client.mjs';
import {createProductRuntimeOptions} from './product-runtime.mjs';
import {createDesktopSession} from './session.mjs';

/**
 * 真实发现与授权根目录只经宿主的三个原生操作。登记变了就把宿主重新生成的环境声明交给本地核心，
 * 下一次扫描、计划与执行按新的范围走；页面自己不拼环境声明。
 */
function createDiscoveryPort({invoke, local}) {
  async function call(op, payload) {
    const result = await callBridge(invoke, op, payload);
    if (result?.ok !== true) throw Object.assign(new Error(result?.reason || `${op} failed`), {code: result?.code || 'NATIVE_DISCOVERY_FAILED'});
    return result;
  }
  async function refresh() {
    const view = await call('DiscoverEnvironment', {});
    local.updateEnvironment(view.environment || {});
    return view;
  }
  return {
    refresh,
    async authorize(rootRefs) {
      await call('AuthorizeRoots', {root_refs: rootRefs});
      return refresh();
    },
    async revoke(rootRefs) {
      await call('RevokeRoots', {root_refs: rootRefs});
      return refresh();
    },
  };
}

/** 页面里的后台节拍：WebView 里是数字句柄；在 Node 里跑页面用例时不拖住进程退出。 */
const BACKGROUND_TIMERS = Object.freeze({
  set(fn, ms) {
    const handle = setTimeout(fn, ms);
    handle?.unref?.();
    return handle;
  },
  clear(handle) {
    clearTimeout(handle);
  },
});

/** 服务端额度快照：只取控制端给的视图字段，本机字节不参与；读不到就如实为 UNKNOWN。 */
function createQuotaReader({control, sessionToken}) {
  if (!sessionToken || !control?.handle) return null;
  return async () => {
    const response = await control.handle(new Request('https://application.invalid/api/network/quota', {
      headers: {authorization: `Bearer ${sessionToken}`, accept: 'application/json'},
    }));
    if (response.status >= 400) return {source: 'server', status: 'UNKNOWN', reason: `CONTROL_HTTP_${response.status}`};
    const body = await response.json();
    const view = body?.view || {};
    return {
      source: 'server',
      status: view.status || body?.quota?.status || 'UNKNOWN',
      usedBytes: view.used_bytes ?? null,
      limitBytes: view.limit_bytes ?? null,
      remainingBytes: view.remaining_bytes ?? null,
      period: view.period ?? null,
      observedAt: view.observed_at || view.measured_at || null,
      stale: body?.stale === true,
      code: body?.code || null,
    };
  };
}

/**
 * 正式桌面的组合根：业务模块跑在 WebView，本地能力全部经受限原生桥。
 * 这里不新增 Node 后台，也不复制任何业务算法；替身只允许出现在明确注入的端口上。
 */
export async function createNativeComposition({
  invoke,
  confirm,
  control,
  environment,
  assignment,
  environmentRef,
  environments = [],
  sessionToken,
  account = null,
  accountNotice = null,
  clock = () => new Date().toISOString(),
  diagnosticPorts,
  diagnosticWorld,
  environmentPorts = null,
  networkPorts = {},
  auth,
  capabilities = {},
  logRoot = null,
  auditTimers = BACKGROUND_TIMERS,
} = {}) {
  if (typeof invoke !== 'function') throw new Error('BRIDGE_REQUIRED: native bridge invoke is required');
  if (typeof confirm !== 'function') throw new Error('CONFIRMATION_REQUIRED: the native user-confirmation channel is required');
  if (!control?.handle) throw new Error('CONTROL_REQUIRED: application control transport is required');

  // 身份与角色只取自控制端 /api/auth/me；产品启动路径已经读过就直接用那一份。
  const identity = account ? account.identity : await readServerIdentity(control, sessionToken);
  const store = await createBridgeWorkspaceAdapter({invoke, confirm, clock});
  const auditStore = createBridgeAuditStore({invoke, confirm, clock});
  const local = createLocalService({adapter: store, environment, capabilities});
  const discovery = createDiscoveryPort({invoke, local});

  const network = createNetworkController({
    store,
    control: networkPorts.control,
    core: networkPorts.core,
    protection: networkPorts.protection,
    verify: networkPorts.verify,
    emergencyHost: networkPorts.emergencyHost,
    events: networkPorts.events,
    clock,
    secrets: networkPorts.secrets,
  });

  // 分环境探测端口接到正式组合根：换环境必须换真实探测目标。
  // 只要有任一环境配了探测服务就挂上控制器；没配的环境（包括宿主本机）扫描得到
  // ENVIRONMENT_PROBE_UNAVAILABLE，不会拿别的环境的证据冒充。
  const diagnostics = diagnosticPorts || environmentPorts
    ? createDiagnosticsController({
      store,
      ports: diagnosticPorts,
      clock,
      world: diagnosticWorld,
      network,
      assignment,
      environmentRef,
      environments,
      environmentPorts,
    })
    : null;

  // 用户浏览器的证据只来自默认浏览器里的诊断页；WebView 自己的取样另标 webview，不顶替它。
  const browserDiag = diagnostics
    ? createDefaultBrowserDiagnostics({invoke, diagnostics, iceServers: diagnosticPorts?.iceServers || []})
    : null;

  const reports = await loadAuditReports(auditStore);
  const current = reports.at(-1) || null;

  // 本地应用日志：页面流程失败与监测运行时的失败都经宿主追加；宿主另外记每个失败的原生操作。
  const appLog = async (level, event, fields = {}) => { await callBridge(invoke, 'AppLogAppend', {event, level, fields}); };
  // 监测与审计运行时：用户启用后才采集；归档来源是产品网络服务的内核日志，产物在应用自己的审计目录。
  const auditRuntime = createAuditRuntime({
    invoke,
    confirm,
    auditStore,
    network,
    mapping: productAuditMapping(assignment),
    environmentRef,
    environments,
    userRef: identity?.user_ref || null,
    readQuota: createQuotaReader({control, sessionToken}),
    clock,
    timers: auditTimers,
    appLog,
    // 窗口隐藏时的危急系统通知：只给固定事件与提示编号，文案由宿主定。
    notify: (event, ref) => invoke('NotifyCritical', {event, ref}),
  });
  const diagnosticExport = createDiagnosticExport({invoke, clock, statusSummary: async () => auditRuntime.status()});

  function createAi({sessionToken: token, userRef} = {}) {
    if (!token || !userRef) return null;
    if (account && account.ai?.available !== true) return null;
    return createAiClient({
      localService: local,
      localStore: store,
      auditStore,
      controlTransport: createHandlerTransport({handler: control, sessionToken: token}),
      networkPort: network.asAiPort?.(userRef),
      diagnostics,
    });
  }

  const compose = {
    kind: 'native-composition',
    clock,
    store,
    local,
    discovery,
    network,
    diagnostics,
    browserDiag,
    auditStore,
    handler: control,
    controlAuth: {authenticate: () => (identity ? {...identity, session_ref: null} : null)},
    account,
    accountNotice,
    aiUnavailable: account?.ai && account.ai.available !== true ? account.ai : null,
    createAi,
    env: environmentRef,
    environments,
    daily: current?.report || null,
    dailyPaths: current ? {json: current.path, markdown: current.path.replace(/daily-audit\.json$/, 'daily-audit.md')} : null,
    auth,
    sessionToken,
    disconnected: false,
    aiAvailable: account ? account.ai?.available === true : true,
    nativeBridge: true,
    scanDelayMs: 0,
    executeStepDelayMs: 0,
    environmentPorts,
    async writeExport(name, text) {
      const target = `exports/${name}`;
      await store.writeBytes(target, new TextEncoder().encode(String(text)));
      return target;
    },
    async reloadAuditNotes() {
      return loadAiNotes(auditStore);
    },
    auditRuntime,
    diagnosticExport,
    appLog,
    logRoot,
    /** 整套重装配（登录、注销、会话失效）前停掉旧的运行时：分钟记录落盘，不让两个运行时同时采集。 */
    async dispose() {
      await auditRuntime.stop();
    },
  };
  await auditRuntime.start();
  return compose;
}

/**
 * 正式页面入口：把 WebView 组合根装成 bridge.js 期望的 __STEWARD__ 分发函数。
 * accountActions 是启动层提供的首启/登录/注销动作；afterAction 在每个动作之后检查控制端是否已失败、会话是否被服务端判失效。
 */
export async function installNativeSteward(target, options, {accountActions = null, afterAction = null} = {}) {
  const compose = await createNativeComposition(options);
  const session = createDesktopSession(compose, {sessionToken: options.sessionToken});
  target.__STEWARD_HOST__ = async (name, args = []) => {
    const list = Array.isArray(args) ? args : [args];
    const action = accountActions && Object.hasOwn(accountActions, name) ? accountActions[name] : session[name];
    if (typeof action !== 'function') {
      throw Object.assign(new Error(`unknown ui action ${name}`), {code: 'UI_ACTION_UNKNOWN'});
    }
    const result = await action(...list);
    return afterAction ? afterAction(result) : result;
  };
  return {compose, session, options};
}

/**
 * 正式页面的启动路径：输入只有宿主原语，运行配置全部由 DescribeCapabilities 给出。
 * 控制端未就绪或未登录时同样装配完成，账号区显示首启、登录或具体故障。
 *
 * 登录态一变（首启完成、登录、注销、会话被服务端判失效）就整套重新装配：
 * 新的会话令牌、身份、资源、AI 客户端与网络端口一起换掉，旧用户的状态不会带给下一个用户；
 * 本地业务记录在原生记录库里，不受影响。
 *
 * 控制端在运行中失败时不重装配：当前会话、本地扫描与计划都保留，只把控制端消费者切到不可用，
 * 网络控制端口转为离线缓存，账号区显示宿主回报的错误与日志位置；由用户点「重新检测」恢复。
 */
export async function bootNativeSteward(target, primitives = {}) {
  let current = null;
  let notice = null;
  let sessionRejected = false;
  let controlSuspect = false;

  async function install({afterRejection = false} = {}) {
    sessionRejected = false;
    controlSuspect = false;
    // 换装配（登录、注销、会话失效、重检）前先清掉上一份组合根在内存里的个人凭据，不带给下一个会话。
    current?.options?.networkPorts?.secrets?.clear?.();
    await current?.compose?.dispose?.();
    const options = await createProductRuntimeOptions({
      ...primitives,
      onSessionRejected: () => { sessionRejected = true; },
      onControlUnreachable: () => { controlSuspect = true; },
    });
    // 读能力、分配、凭据时服务端已经判会话失效：不装这份带着失效身份的组合根，清会话后按未登录再装一次。
    // 第二次装配没有会话令牌，不会再有带会话的请求，所以不会循环。
    if (sessionRejected && options.sessionToken && !afterRejection) {
      await options.authClient.clearSession();
      notice = {code: 'SESSION_EXPIRED', reason: '登录会话已失效，请重新登录；本地记录保留'};
      return install({afterRejection: true});
    }
    options.accountNotice = () => notice || options.account?.notice || null;
    current = await installNativeSteward(target, options, {accountActions, afterAction});
    target.__STEWARD_HOST_REPORT__ = options.hostReport;
    sessionRejected = false;
    if (controlSuspect) await reconcileControl();
    return current;
  }

  /** 请求连不上之后向宿主核对：宿主确认控制端不是 ready，就把当前消费者切到不可用并显示原因。返回是否切换。 */
  async function reconcileControl() {
    controlSuspect = false;
    const {options} = current;
    if (options.control.kind !== 'remote-control' || options.control.unavailable) return false;
    const polled = await callBridge(primitives.invoke, 'ControlStatus');
    const status = polled.ok === true
      ? polled.control || {status: 'failed', error: {code: 'CONTROL_STATUS_MISSING', reason: '宿主没有回报控制端状态'}}
      : {status: 'failed', error: {code: polled.code || 'CONTROL_STATUS_UNREADABLE', reason: polled.reason || '无法向宿主读取控制端状态'}};
    if (status.status === 'ready') return false;
    options.control.markUnavailable(status);
    options.networkPorts?.control?.setOffline?.(true);
    options.account.control = publicControlStatus(status);
    options.hostReport.control = options.account.control;
    return true;
  }

  const snapshot = () => current.session.snapshot();

  const accountActions = {
    async accountRefresh() {
      notice = null;
      await install();
      return snapshot();
    },
    async accountSetup(username, password) {
      notice = null;
      const {options} = current;
      if (options.account.phase !== 'setup_required') {
        notice = {code: 'SETUP_NOT_PENDING', reason: '控制端当前不在首次初始化状态'};
        return snapshot();
      }
      const result = await options.authClient.setupAdmin(String(username ?? ''), String(password ?? ''));
      if (result?.ok !== true) {
        notice = {code: result?.code || 'CONTROL_SETUP_FAILED', reason: result?.reason || '首次初始化没有完成', request_ref: result?.request_ref || null};
        return snapshot();
      }
      notice = null;
      await install();
      notice = {code: 'SETUP_COMPLETED', reason: `管理员 ${result.user?.username || ''} 已创建，请用刚设置的密码登录`, level: 'info'};
      return snapshot();
    },
    async accountLogin(username, password) {
      notice = null;
      const {options} = current;
      if (options.account.phase !== 'login_required') {
        notice = {code: 'LOGIN_NOT_PENDING', reason: '当前不需要登录'};
        return snapshot();
      }
      const result = await options.authClient.login(String(username ?? ''), String(password ?? ''));
      if (result.status !== 200 || !result.body?.access_token) {
        notice = {
          code: result.body?.code || 'AUTH_LOGIN_FAILED',
          reason: result.body?.reason || '登录没有完成',
          request_ref: result.body?.request_ref || null,
          retry_after_ms: result.body?.retry_after_ms ?? null,
        };
        return snapshot();
      }
      const saved = await options.authClient.saveSession({
        access_token: result.body.access_token,
        expires_at: result.body.expires_at,
        user_ref: result.body.user?.user_ref,
      });
      if (saved?.ok !== true) {
        // 存不下就不留一条悬空的服务端会话。
        await options.authClient.logout(result.body.access_token);
        notice = {code: saved?.code || 'SESSION_STORE_FAILED', reason: `登录已被控制端接受，但会话没能保存到本机宿主：${saved?.reason || ''}`};
        return snapshot();
      }
      notice = null;
      await install();
      return snapshot();
    },
    async accountLogout() {
      notice = null;
      const {options} = current;
      const token = options.sessionToken;
      const remote = token ? await options.authClient.logout(token) : null;
      const cleared = await options.authClient.clearSession();
      notice = null;
      await install();
      if (cleared?.ok !== true) {
        notice = {code: cleared?.code || 'SESSION_CLEAR_FAILED', reason: `本机会话材料没能清除：${cleared?.reason || ''}`};
      } else if (token && remote?.status !== 204) {
        notice = {code: remote?.body?.code || 'LOGOUT_UNCONFIRMED', reason: '本机已退出登录，但控制端没有确认撤销会话', request_ref: remote?.body?.request_ref || null};
      } else {
        notice = {code: 'LOGGED_OUT', reason: '已退出登录；本地记录保留', level: 'info'};
      }
      return snapshot();
    },
  };

  async function afterAction(result) {
    const controlFailed = controlSuspect && current ? await reconcileControl() : false;
    if (!sessionRejected) return controlFailed ? snapshot() : result;
    sessionRejected = false;
    if (!current?.options?.sessionToken) return controlFailed ? snapshot() : result;
    await current.options.authClient.clearSession();
    await install();
    notice = {code: 'SESSION_EXPIRED', reason: '登录会话已失效，请重新登录；本地记录保留'};
    return snapshot();
  }

  return install();
}
