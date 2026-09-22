import {createBrowserDiagnosticPorts} from '../../src/adapters/diagnostics/browser.mjs';
import {createHttpControlPort} from '../../src/adapters/network/controlClient.mjs';
import {
  createControlEventPort,
  createControlSecrets,
  createEchoVerifier,
  createNativeCorePort,
  createNativeEmergencyHost,
  createNativeProtectionPort,
} from '../../src/adapters/network/nativePorts.mjs';
import {parsePublicIPBody} from '../../src/core/diagnostics/parse.mjs';
import {
  SESSION_REJECTION_CODES,
  createAuthClient,
  createUnavailableControl,
  readAccount,
  readEntitlements,
  waitForControlReady,
} from './auth-client.mjs';

/**
 * 正式桌面的运行时装配：输入只有宿主真正提供的原语——
 * Tauri 的 invoke、WebView 的 fetch / navigator / WebRTC / Intl。
 * 控制端地址、产品网络服务身份、声明环境与 Windows 用户都从 DescribeCapabilities 取，
 * 分环境探测服务地址由控制端管理员配置、登录后从 /api/network/probe-services 取，
 * 页面不在本地假设任何一项；取不到的能力保持未接入并点名，不合成。
 * 控制端没就绪、没有会话时照样装配：本地能力可用，账号区显示首启、登录或具体故障。
 */

const NETWORK_CONFIRMATION_VALIDITY_MS = 2 * 60 * 60 * 1000;

export class ProductRuntimeError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * 带会话的请求被服务端判为会话无效时回调 onSessionRejected，由启动层清会话并退回登录。
 * 请求根本连不上时回调 onControlUnreachable，由启动层向宿主核对控制端状态；
 * 宿主确认控制端已失败后调用 markUnavailable，此后所有消费者直接拿到具体故障，不再连失效地址。
 */
function createRemoteControl({baseUrl, fetchImpl, status, onSessionRejected, onControlUnreachable}) {
  let unavailable = null;
  return {
    kind: 'remote-control',
    base_url: baseUrl,
    status,
    get unavailable() {
      return Boolean(unavailable);
    },
    markUnavailable(nextStatus) {
      unavailable = createUnavailableControl(nextStatus);
      this.status = unavailable.status;
    },
    async handle(request) {
      if (unavailable) return unavailable.handle(request);
      const source = new URL(request.url);
      const target = new URL(`${source.pathname}${source.search}`, baseUrl);
      const init = {method: request.method, headers: request.headers};
      if (request.method !== 'GET' && request.method !== 'HEAD') init.body = await request.text();
      let response;
      try {
        response = await fetchImpl(target, init);
      } catch (error) {
        onControlUnreachable?.();
        throw error;
      }
      if (response.status === 401 && request.headers.get('authorization') && typeof response.clone === 'function') {
        const body = await response.clone().json().catch(() => null);
        if (SESSION_REJECTION_CODES.has(body?.code)) onSessionRejected?.(body.code);
      }
      return response;
    },
  };
}

function selectControl({controlStatus, product, fetchImpl, onSessionRejected, onControlUnreachable}) {
  const baseUrl = controlStatus?.status === 'ready' ? controlStatus.base_url || product.control_base_url || null : null;
  if (!baseUrl) return createUnavailableControl(controlStatus);
  if (typeof fetchImpl !== 'function') {
    return createUnavailableControl({...controlStatus, status: 'failed', error: {code: 'FETCH_UNAVAILABLE', reason: '宿主页面没有 fetch，无法连接控制端'}});
  }
  return createRemoteControl({baseUrl, fetchImpl, status: controlStatus, onSessionRejected, onControlUnreachable});
}

/** 网络侧的一次用户确认：期限与引用都由本次确认产生，不复用会话串。 */
function createNetworkAuthorization({environmentRef, clock}) {
  return (userRef, extra = {}) => {
    const now = clock();
    return {
      kind: extra.kind || 'ONCE_CONFIRMED',
      user_ref: userRef,
      environment_ref: extra.environment_ref || environmentRef,
      authorization_ref: extra.authorization_ref || `confirm-${userRef}-${now}`,
      expires_at: extra.expires_at || new Date(Date.parse(now) + NETWORK_CONFIRMATION_VALIDITY_MS).toISOString(),
      allow_verify: extra.allow_verify !== false,
      allow_sensitive: extra.allow_sensitive === true,
      plan_version: extra.plan_version,
      assignment_version: extra.assignment_version,
    };
  };
}


/**
 * 从宿主原语装出正式组合根需要的全部参数。
 * 返回的对象可以直接交给 createNativeComposition / installNativeSteward。
 */
export async function createProductRuntimeOptions({
  invoke,
  confirm,
  fetchImpl,
  navigator: navigatorRef = null,
  rtcPeerConnection = null,
  intl = null,
  clock = () => new Date().toISOString(),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  controlWaitMs = 20000,
  onSessionRejected = null,
  onControlUnreachable = null,
} = {}) {
  if (typeof invoke !== 'function') throw new ProductRuntimeError('BRIDGE_REQUIRED', 'no restricted native bridge is attached');
  if (typeof confirm !== 'function') throw new ProductRuntimeError('CONFIRMATION_REQUIRED', 'this host exposes no local user-confirmation channel');

  const described = await invoke('DescribeCapabilities', {}, null);
  if (described?.ok !== true) {
    throw new ProductRuntimeError(described?.code || 'NATIVE_CAPABILITIES_UNAVAILABLE', described?.reason || 'the native host did not describe its capabilities');
  }
  const product = described.product || {};
  const environmentRef = product.environment_ref || null;
  if (!environmentRef) throw new ProductRuntimeError('ENVIRONMENT_REF_MISSING', 'the host did not report which environment this install runs in');

  const controlStatus = await waitForControlReady({invoke, initial: product.control || null, sleep, timeoutMs: controlWaitMs});
  const control = selectControl({controlStatus, product, fetchImpl, onSessionRejected, onControlUnreachable});
  const authClient = createAuthClient({control, invoke});
  const {account, token} = await readAccount({authClient, control});
  const sessionToken = token;
  let assignment = null;
  let declaredProbes = {};
  let probeSource = sessionToken ? 'control' : 'NOT_SIGNED_IN';
  if (sessionToken) {
    const entitlements = await readEntitlements(authClient, sessionToken);
    account.ai = entitlements.ai;
    account.assignment = entitlements.assignment;
    assignment = entitlements.assignmentRecord;
    const probes = await authClient.get('/api/network/probe-services', sessionToken);
    if (probes.status === 200 && probes.body?.environments && typeof probes.body.environments === 'object') declaredProbes = probes.body.environments;
    else probeSource = probes.body?.code || `PROBE_SERVICES_HTTP_${probes.status}`;
  }

  const controlPort = createHttpControlPort({handler: control, sessionToken, clock});
  const secrets = createControlSecrets({control, sessionToken});
  await secrets.load();

  const emergencyHost = createNativeEmergencyHost({invoke, confirm, clock, environmentRef});
  await emergencyHost.refresh();

  // 受管探测服务按环境分开：控制端给了哪个环境的地址，才建得出那个环境的端口。
  // 没给的环境不建端口，诊断按 ENVIRONMENT_PROBE_UNAVAILABLE 拒绝，不退回主机端口。
  const probeEnvironments = new Map();
  for (const [ref, services] of Object.entries(declaredProbes)) {
    if (!services || typeof services !== 'object') continue;
    probeEnvironments.set(ref, {
      ports: createBrowserDiagnosticPorts({
        fetchImpl,
        navigator: navigatorRef,
        rtcPeerConnection: services.webrtc === false ? null : rtcPeerConnection,
        intl,
        services,
        clientKind: services.client_kind || product.client_kind || 'webview',
        iceServers: (Array.isArray(services.stun_urls) ? services.stun_urls : []).map((url) => ({urls: [url]})),
      }),
      world: null,
    });
  }
  const diagnosticPorts = probeEnvironments.get(environmentRef)?.ports || null;

  // 受管内核只经产品网络服务访问：页面拿不到内核地址或 secret，也不直接建 HTTP/WebSocket 连接。
  const core = createNativeCorePort({invoke, confirm, environmentRef, clock});

  const unimplemented = [...(described.unimplemented || [])];
  const uncovered = (product.environments || [])
    .map((item) => item?.environment_ref)
    .filter((ref) => ref && !probeEnvironments.has(ref));
  if (uncovered.length) unimplemented.push(`diagnostics.probe_services:${uncovered.join(',')}`);
  else if (!probeEnvironments.size) unimplemented.push(`diagnostics.probe_services:${probeSource === 'control' ? 'NOT_CONFIGURED' : probeSource}`);

  return {
    invoke,
    confirm,
    control,
    environment: product.environment || {},
    environmentRef,
    environments: product.environments || [],
    assignment,
    sessionToken,
    account,
    authClient,
    clock,
    auth: createNetworkAuthorization({environmentRef, clock}),
    diagnosticPorts,
    diagnosticWorld: null,
    environmentPorts: probeEnvironments.size ? (ref) => probeEnvironments.get(ref) || null : null,
    capabilities: {},
    logRoot: product.log_root || null,
    networkPorts: {
      control: controlPort,
      core,
      protection: createNativeProtectionPort({invoke, confirm, environmentRef, clock}),
      verify: diagnosticPorts ? createEchoVerifier({echo: diagnosticPorts.echo, parseBody: parsePublicIPBody}) : null,
      emergencyHost,
      events: createControlEventPort({control: controlPort}),
      secrets,
    },
    hostReport: {
      contract: described.contract,
      groups: described.groups || [],
      unimplemented,
      windows_user: product.windows_user || null,
      control: account.control,
      account_phase: account.phase,
      credentials: secrets.status,
      core_transport: core.transport_status,
      network_service: product.network_service?.link || 'UNKNOWN',
      emergency_candidates: emergencyHost.listCandidates().length,
      probe_environments: [...probeEnvironments.keys()],
      probe_source: probeSource,
      diagnostics_attached: probeEnvironments.size > 0,
    },
  };
}
