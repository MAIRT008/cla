import {randomHex, sha256Hex} from '../platform/index.mjs';

/**
 * 正式桌面的网络端口：全部经受限原生桥到产品网络服务。
 * Mihomo 进程、受管配置、内核控制接口与 WFP 都归服务所有；页面拿不到内核地址或 secret，
 * 读取实际运行记录、下发配置、确认保护与生命周期动作都只是 ReadNetworkState / ApplyNetworkPlan /
 * ProtectEnvironment / NetworkLifecycle 这几个业务操作，服务命令由宿主签名转发。
 */

const PROTECTION_VALIDITY_MS = 12 * 60 * 60 * 1000;
const STOP_MANAGEMENT_VALIDITY_MS = 5 * 60 * 1000;

/**
 * 预授权保护的引用同样只能由原生签发。
 * 这里缓存的是引用字符串，不是授权内容；过期后再向原生要一条。
 */
function createProtectionReference({confirm, environmentRef, clock}) {
  let issued = null;
  return async function reference() {
    if (issued && Date.parse(issued.expires_at) > Date.parse(clock())) return issued.authorization_ref;
    const result = await confirm({
      scope: 'preauthorized_protection',
      environment_ref: environmentRef,
      reuse: true,
      validity_ms: PROTECTION_VALIDITY_MS,
      summary: '允许本应用在受管环境内下发配置、执行预授权保护与恢复类生命周期动作。',
    });
    if (!result?.authorization_ref) {
      throw Object.assign(
        new Error(result?.reason || 'the host did not issue a protection authorization'),
        {code: result?.code || 'NATIVE_CONFIRMATION_DECLINED'},
      );
    }
    issued = result;
    return issued.authorization_ref;
  };
}

function operationId(prefix) {
  return `${prefix}-${randomHex(12)}`;
}

/**
 * 六类用户可见状态：服务、核心、配置、实际回读、保护、应急，每类带稳定错误码；
 * 不含配置正文、摘要以外的实现细节或任何 secret。服务不可达时一律 UNKNOWN，不拿缓存或期望值补。
 */
export function summarizeRuntime(raw = {}) {
  const reachable = raw?.service?.status === 'RUNNING';
  const failed = (raw?.readback?.checks || []).filter((item) => item && item.ok === false).map((item) => item.name);
  const sessions = Array.isArray(raw?.emergency) ? raw.emergency : [];
  const core = raw?.core || {};
  const config = raw?.config || {};
  const protection = raw?.protection || {};
  return {
    service: {
      status: reachable ? 'RUNNING' : raw?.service?.status || 'UNREACHABLE',
      code: reachable ? null : raw?.service_code || raw?.service?.code || 'SERVICE_UNREACHABLE',
      link: raw?.link || null,
    },
    core: {
      status: !reachable ? 'UNKNOWN' : core.running ? 'RUNNING' : core.binary_present === false ? 'BINARY_MISSING' : 'STOPPED',
      kernel_version: reachable ? core.kernel_version ?? null : null,
      restart_count: reachable ? core.restart_count ?? 0 : null,
      gave_up: core.gave_up === true,
      code: !reachable ? null : core.binary_present === false ? 'CORE_BINARY_MISSING' : core.gave_up ? 'CORE_RESTART_EXHAUSTED' : raw?.last_failure_code || null,
    },
    config: {
      status: !reachable
        ? 'UNKNOWN'
        : !config.active_config_sha256
          ? (config.expected_config_sha256 ? 'ACTIVE_UNKNOWN' : 'NONE')
          : config.active_config_sha256 === config.last_valid_config_ref
            ? 'ACTIVE_LAST_VALID'
            : config.active_config_sha256 === config.emergency_config_ref ? 'ACTIVE_EMERGENCY_TEMPORARY' : 'ACTIVE_NOT_LAST_VALID',
      plan_version: reachable ? config.plan_version ?? null : null,
      assignment_version: reachable ? config.assignment_version ?? null : null,
      last_valid_plan_version: reachable ? config.last_valid_plan_version ?? null : null,
    },
    readback: {
      status: !reachable ? 'UNKNOWN' : raw?.readback?.status || 'NOT_RUN',
      current: reachable && raw?.readback?.current === true,
      failed_checks: reachable ? failed : [],
      code: !reachable ? null : raw?.readback?.status === 'VERIFY_FAILED' ? 'VERIFY_FAILED' : raw?.readback?.status === 'STALE_INSTANCE' ? 'READBACK_STALE_INSTANCE' : null,
    },
    protection: {
      status: !reachable ? 'UNKNOWN' : protection.effective ? 'EFFECTIVE' : protection.requested ? 'NOT_EFFECTIVE' : 'NOT_REQUESTED',
      new_connections_restricted: reachable && protection.effective === true,
      missing: reachable ? protection.missing || [] : [],
      code: reachable && protection.requested && !protection.effective ? 'PROTECTION_NOT_EFFECTIVE' : null,
      // 受管路径：受保护程序只经本产品 TUN 接口联网；关闭时它们只剩阻断，不能联网也不会直连。
      managed_path: {
        status: !reachable ? 'UNKNOWN' : protection.managed_path?.status || 'CLOSED',
        current: reachable && protection.managed_path?.current === true,
        code: reachable ? protection.managed_path?.code ?? null : null,
      },
    },
    emergency: {
      status: !reachable ? 'UNKNOWN' : sessions.some((item) => item.open && !item.expired) ? 'OPEN' : 'CLOSED',
      sessions: reachable ? sessions.map((item) => ({
        session_ref: item.session_ref,
        open: item.open === true,
        expired: item.expired === true,
        closed_safely: item.closed_safely === true,
        close_code: item.close_code ?? null,
        route_rules_present_after_close: item.route_rules_present_after_close ?? null,
      })) : [],
    },
    missing: Array.isArray(raw?.missing) ? raw.missing : [],
  };
}

export function createNativeCorePort({invoke, confirm, environmentRef, clock}) {
  const reference = createProtectionReference({confirm, environmentRef, clock});
  let lastRuntime = null;
  let inflight = null;

  /** 实际运行记录；服务不可达时 service.status 标 UNREACHABLE，其余不补。 */
  async function read(include = []) {
    const result = await invoke('ReadNetworkState', {environment_ref: environmentRef, include}, null);
    lastRuntime = {
      ...(result?.runtime || {}),
      service_code: result?.ok === true ? null : result?.code || 'SERVICE_UNREACHABLE',
      link: result?.service?.link || null,
    };
    return lastRuntime;
  }

  /** 应用后的并行回读共用一次读取，不让同一时刻的四个查询各自穿过桥。 */
  function readConfig() {
    if (!inflight) inflight = read(['config']).finally(() => { inflight = null; });
    return inflight;
  }

  async function apply(input = {}) {
    const yaml = input.yaml ?? input.payload;
    const payload = {
      operation_id: input.operation_id,
      environment_ref: environmentRef,
      plan_ref: input.plan_ref || input.plan_version,
      plan_version: input.plan_version == null ? input.plan_version : String(input.plan_version),
      assignment_version: input.assignment_version == null ? input.assignment_version : String(input.assignment_version),
      expected_config_sha256: input.expected_config_sha256 || (typeof yaml === 'string' ? sha256Hex(yaml) : null),
      yaml,
    };
    const missing = ['operation_id', 'plan_version', 'assignment_version', 'yaml'].filter((field) => !payload[field]);
    if (missing.length) {
      return {accepted: false, verified: false, http_status: null, code: 'APPLY_REQUEST_INCOMPLETE', missing};
    }
    const result = await invoke('ApplyNetworkPlan', payload, await reference());
    const receipt = result?.receipt || {};
    const stages = {...(result?.validation?.stages || {}), ...(receipt.stages || {})};
    const verified = result?.ok === true && receipt.overall === 'VERIFIED';
    return {
      accepted: stages.applied?.http_status === 204,
      verified,
      http_status: stages.applied?.http_status ?? null,
      code: verified ? null : result?.code || 'CORE_APPLY_REJECTED',
      stages,
      service_verification: stages.verified || {status: 'NOT_RUN'},
      payload_hash: payload.expected_config_sha256,
      instance_id: receipt.service_instance_id || null,
      core_pid: receipt.core_pid ?? null,
      requires_restore: receipt.requires_restore === true,
    };
  }

  async function lifecycle({event, operation_id, reason_code, processes} = {}) {
    const payload = {operation_id: operation_id || operationId(`lifecycle-${event}`), environment_ref: environmentRef, event};
    if (reason_code) payload.reason_code = reason_code;
    let authorizationRef;
    if (event === 'stop_management') {
      payload.processes = Array.isArray(processes) ? processes : [];
      const confirmed = await confirm({
        scope: 'stop_management',
        environment_ref: environmentRef,
        native_op: 'NetworkLifecycle',
        validity_ms: STOP_MANAGEMENT_VALIDITY_MS,
        summary: '停止管理并撤掉本应用在该环境的系统保护。Claude 之后不再受本应用保护；受保护程序须先退出。',
      });
      if (!confirmed?.authorization_ref) {
        return {ok: false, code: confirmed?.code || 'NATIVE_CONFIRMATION_DECLINED', event};
      }
      authorizationRef = confirmed.authorization_ref;
    } else {
      authorizationRef = await reference();
    }
    const result = await invoke('NetworkLifecycle', payload, authorizationRef);
    return {ok: result?.ok === true, code: result?.ok === true ? null : result?.code || 'LIFECYCLE_FAILED', event, command: result?.command || null, receipt: result?.receipt || null};
  }

  return {
    kind: 'native-core',
    transport_status: 'service',
    loadConfig: apply,
    putConfigs: (input = {}) => apply({...input, yaml: input.payload}),
    async getConfigs() {
      const runtime = await readConfig();
      const general = runtime.actual?.general || null;
      return {http_status: general ? 200 : 0, general, loaded_version: null, missing: runtime.missing || []};
    },
    async getRules() {
      const runtime = await readConfig();
      return {http_status: Array.isArray(runtime.actual?.rules) ? 200 : 0, rules: Array.isArray(runtime.actual?.rules) ? runtime.actual.rules : []};
    },
    async getProxies() {
      const runtime = await readConfig();
      return {http_status: runtime.actual?.proxies ? 200 : 0, proxies: runtime.actual?.proxies?.proxies || {}};
    },
    async getVersion() {
      const runtime = await readConfig();
      return {http_status: runtime.core?.kernel_version ? 200 : 0, meta: null, version: runtime.core?.kernel_version ?? null, product_plan_version: null};
    },
    async getConnections() {
      const runtime = await read(['connections']);
      const snapshot = runtime.connections || {};
      return {
        http_status: Array.isArray(snapshot.connections) ? 200 : 0,
        downloadTotal: snapshot.downloadTotal ?? 0,
        uploadTotal: snapshot.uploadTotal ?? 0,
        memory: null,
        connections: Array.isArray(snapshot.connections) ? snapshot.connections : [],
      };
    },
    async getTraffic() {
      const runtime = lastRuntime?.connections ? lastRuntime : await read(['connections']);
      return {up: null, down: null, upTotal: runtime.connections?.uploadTotal ?? null, downTotal: runtime.connections?.downloadTotal ?? null, user_quota: null};
    },
    async getLogs() {
      const runtime = await read(['logs']);
      return {lines: Array.isArray(runtime.logs) ? runtime.logs : []};
    },
    /**
     * 实时监测的一次读取：连接快照、累计计数与日志尾巴同一次经服务取得。
     * 内核实例按 pid 与启动时刻区分，内核重启后累计计数归零能被识别为重置。
     */
    async readLive() {
      const runtime = await read(['connections', 'logs']);
      const reachable = runtime?.service?.status === 'RUNNING';
      return {
        reachable,
        service_status: reachable ? 'RUNNING' : runtime?.service?.status || 'UNREACHABLE',
        service_code: runtime.service_code || null,
        core_running: reachable && runtime.core?.running === true,
        core_instance: reachable && runtime.core?.pid ? `${runtime.core.pid}:${runtime.core.started_at_ms ?? ''}` : null,
        config: {plan_version: runtime.config?.plan_version ?? null, assignment_version: runtime.config?.assignment_version ?? null},
        protection: reachable ? runtime.protection || null : null,
        snapshot: reachable && runtime.connections ? runtime.connections : {},
        lines: reachable && Array.isArray(runtime.logs) ? runtime.logs : [],
        missing: Array.isArray(runtime.missing) ? runtime.missing : [],
      };
    },
    async readRuntime() {
      return summarizeRuntime(await read([]));
    },
    /** 服务重新加载它自己回读确认过的 last-valid；是否仍在分配有效期内由调用方先核对。 */
    async restoreLastValid({operation_id, reason_code} = {}) {
      return lifecycle({event: 'restore_last_valid', operation_id, reason_code});
    },
    lifecycle,
    snapshot() {
      return {
        instance_id: lastRuntime?.service?.service_instance_id || null,
        alive: lastRuntime?.core?.running === true,
        restart_count: lastRuntime?.core?.restart_count ?? 0,
        has_payload: Boolean(lastRuntime?.config?.active_config_sha256),
        kernel_version: lastRuntime?.core?.kernel_version ?? null,
        loaded_version: null,
      };
    },
  };
}

export function createNativeProtectionPort({invoke, confirm, environmentRef, clock}) {
  const reference = createProtectionReference({confirm, environmentRef, clock});
  let last = null;
  function reasonFor(command) {
    if (command.reason_code) return command.reason_code;
    if (command.close_existing === true) return 'WRONG_ROUTE';
    if (command.action === 'ensure_ready') return 'APPLY_PRECONDITION';
    return 'LIFECYCLE_PROTECTION';
  }
  return {
    kind: 'native-protection',
    async requestProtection(command = {}) {
      const processes = Array.isArray(command.processes) ? command.processes : [];
      if (!processes.length) {
        return {status: 'FAILED', code: 'EMPTY_PROCESS_SCOPE', reason: 'EMPTY_PROCESS_SCOPE', requested: false, effective: false, new_connections_restricted: false};
      }
      const result = await invoke('ProtectEnvironment', {
        operation_id: command.operation_id || operationId('protect'),
        environment_ref: environmentRef,
        action: 'block_new',
        processes,
        loopback_policy: {
          template_version: command.loopback_policy?.template_version ?? null,
          endpoints: Array.isArray(command.loopback_policy?.endpoints) ? command.loopback_policy.endpoints : [],
        },
        reason_code: reasonFor(command),
      }, await reference());
      last = result;
      const protection = result?.protection || {};
      const effective = result?.ok === true && protection.new_connections_restricted === true;
      return {
        status: effective ? 'CONFIRMED' : protection.requested ? 'UNCONFIRMED' : 'FAILED',
        requested: protection.requested !== false,
        os_readback: protection.os_readback || 'UNKNOWN',
        effective,
        new_connections_restricted: effective,
        existing_closed: result?.close_existing?.receipt?.closed_existing === true,
        close_existing: result?.close_existing || null,
        code: effective ? null : result?.code || 'PROTECTION_NOT_EFFECTIVE',
        reason: effective ? null : result?.code || 'PROTECTION_NOT_EFFECTIVE',
      };
    },
    async readback() {
      const result = await invoke('ReadNetworkState', {environment_ref: environmentRef, include: []}, null);
      const protection = result?.ok === true ? result?.runtime?.protection || {} : null;
      if (!protection) {
        return {status: 'UNKNOWN', effective: false, new_connections_restricted: false, code: result?.code || 'SERVICE_UNREACHABLE'};
      }
      return {
        status: protection.effective ? 'CONFIRMED' : protection.requested ? 'UNCONFIRMED' : 'INACTIVE',
        requested: protection.requested === true,
        effective: protection.effective === true,
        new_connections_restricted: protection.effective === true,
        missing: protection.missing || [],
      };
    },
    /** 窗口关闭或界面退出：服务、内核与保护都不受影响，这里只如实报告最后一次保护结果。 */
    markUiExit() {
      return {protection_retained: last?.protection?.new_connections_restricted === true, core_stopped: false, service_unaffected: true};
    },
    snapshot() {
      return {last_request: last, new_connections_restricted: last?.protection?.new_connections_restricted === true};
    },
  };
}

export function createNativeEmergencyHost({invoke, confirm, clock, environmentRef}) {
  let candidates = [];
  const sessions = new Map();
  /** 开关应急第二浏览器各要一次本地确认；引用只覆盖这一个会话。 */
  async function reference(sessionId, expiresAt, summary, nativeOp) {
    const result = await confirm({
      scope: 'emergency_session',
      session_ref: sessionId,
      native_op: nativeOp,
      validity_ms: Math.max(60_000, Date.parse(expiresAt) - Date.parse(clock())),
      summary,
    });
    if (!result?.authorization_ref) {
      throw Object.assign(
        new Error(result?.reason || 'the host did not issue an emergency authorization'),
        {code: result?.code || 'NATIVE_CONFIRMATION_DECLINED'},
      );
    }
    return result.authorization_ref;
  }
  return {
    kind: 'native-emergency-host',
    /** 候选在启动时取一次：listCandidates 必须同步，业务核心按同步接口消费。 */
    async refresh() {
      const result = await invoke('EmergencyHosts', {}, null);
      candidates = (result?.hosts || []).filter((item) => item.installed !== false);
      return candidates;
    },
    listCandidates() { return candidates.map((item) => ({...item})); },
    /** 服务先证明应急路径已就绪且 Claude 仍受约束，宿主再启动浏览器；两者都成立才是 ACTIVE。 */
    async open({session_id, host_id, expires_at}) {
      const result = await invoke(
        'EmergencyOpen',
        {session_id, host_id, expires_at, environment_ref: environmentRef},
        await reference(session_id, expires_at, `打开第二浏览器用于临时应急上网，到期时间 ${expires_at}`, 'EmergencyOpen'),
      );
      if (result?.ok !== true || result?.status !== 'ACTIVE') {
        return {ok: false, code: result?.code || 'EMERGENCY_OPEN_FAILED', status: result?.status || 'FAILED', route: result?.route || null};
      }
      sessions.set(session_id, {...result.session, open: true});
      return {ok: true, status: 'ACTIVE', session: result.session, route: result.route};
    },
    async close({session_id}) {
      const expiresAt = sessions.get(session_id)?.expires_at || new Date(Date.parse(clock()) + 60_000).toISOString();
      const result = await invoke(
        'EmergencyClose',
        {session_id, environment_ref: environmentRef},
        await reference(session_id, expiresAt, '关闭应急第二浏览器会话', 'EmergencyClose'),
      );
      sessions.set(session_id, {...(result?.session || {session_id}), open: false});
      return result?.ok === true
        ? {ok: true, route: result.route || null, readback: result.session?.route_rules_present ? 'RULES_PRESENT' : 'CLOSED'}
        : {ok: false, code: result?.code || 'EMERGENCY_CLOSE_UNCONFIRMED', route: result?.route || null};
    },
    snapshot(sessionId) { return sessions.get(sessionId) || null; },
  };
}

/** 应用后的回读验证用真实出口回声，不接受由计划自我回显的结果。 */
export function createEchoVerifier({echo, parseBody}) {
  return {
    kind: 'echo-verify',
    async verify({mode, environment_ref, checks = []}) {
      let observed = null;
      let failure = null;
      try {
        const response = await echo.fetch();
        observed = response.ok ? parseBody(await response.text()) : null;
        if (!response.ok) failure = response.code || 'ECHO_HTTP_ERROR';
      } catch (error) {
        failure = error.code || 'ECHO_UNAVAILABLE';
      }
      const results = checks.map((check) => {
        const actual = check.kind === 'exit_ip' ? observed?.ip ?? null : null;
        return {
          id: check.id,
          kind: check.kind,
          target: check.target,
          expected: check.expected,
          actual,
          ok: actual !== null && actual === check.expected,
          protocol: check.protocol || 'tcp',
          environment_ref,
          mode,
          code: actual === null ? failure || 'NOT_OBSERVED' : null,
        };
      });
      return {
        status: results.length && results.every((item) => item.ok) ? 'VERIFIED' : 'VERIFY_FAILED',
        results,
        environment_ref,
        mode,
        code: failure,
      };
    },
  };
}

export function createControlEventPort({control}) {
  return {
    kind: 'control-events',
    async deliver(event) {
      const result = await control.recordNetworkEvent(event);
      return {delivered: result?.ok === true, code: result?.ok === true ? null : result?.code || 'EVENT_DELIVERY_FAILED'};
    },
  };
}

/**
 * 受管代理凭据不落客户端：只能向控制端按 credential_ref 换取。
 * 控制端没有开放这个端口时如实回报未接入，配置下发会明确失败，而不是拿空凭据蒙混。
 */
export function createControlSecrets({control, sessionToken}) {
  const cache = new Map();
  let status = 'NOT_LOADED';
  return {
    kind: 'control-secrets',
    get status() { return status; },
    async load() {
      if (!sessionToken) {
        status = 'NOT_AUTHENTICATED';
        return status;
      }
      try {
        const response = await control.handle(new Request('https://application.invalid/api/network/credentials', {
          headers: {authorization: `Bearer ${sessionToken}`, accept: 'application/json'},
        }));
        if (response.status >= 400) {
          status = 'NOT_ATTACHED';
          return status;
        }
        const body = await response.json();
        for (const [ref, value] of Object.entries(body?.credentials || {})) cache.set(ref, value);
        status = cache.size ? 'AVAILABLE' : 'NOT_ATTACHED';
      } catch {
        status = 'NOT_ATTACHED';
      }
      return status;
    },
    resolve(ref) { return cache.get(ref) || null; },
    /** 注销或整套重装配时清掉内存里的个人凭据；它们从不写入快照、记录库或 localStorage。 */
    clear() {
      cache.clear();
      status = 'CLEARED';
    },
  };
}
