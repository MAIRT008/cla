import {randomUUID} from 'node:crypto';
import {AUTHORIZATION_SCOPES, ERROR_CODES, assertPayload, checkIssuedAuthorization} from '../../apps/desktop-host/bridge-contract.mjs';
import {sha256Hex} from '../../src/adapters/platform/index.mjs';

/**
 * 站在「Rust 宿主 + 产品网络服务」位置的契约替身，只服务 RC3 页面侧用例。
 *
 * 它按 bridge-contract.mjs 核对载荷与授权，按 network_runtime.rs 的回执形状回话；
 * 服务侧的结论（回读是否通过、保护是否生效、应急路径是否就绪、服务是否可达、应急关闭是否确认）由用例直接设定，
 * 替身自己不判定这些。它证明的是页面端口与业务核心怎样消费服务回执，不证明 Rust 服务的判定已经运行。
 * 回执形状跟随 RC3 整改后的服务：回读失败时 active 置空；应急临时配置不进 last-valid；维护停内核前服务端核对保护；
 * 应急关闭由服务结束浏览器并换回基线。
 * 内核由注入的 createCoreFixture 扮演，只做加载与读出。
 */
export function createServiceBridgeDouble({environmentRef, core, clock, emergencyHosts} = {}) {
  const verdicts = {
    reachable: true,
    readback: 'VERIFIED',
    protectionEffective: true,
    routeReady: true,
    businessRunning: false,
    emergencyCloseConfirmed: true,
  };
  const calls = [];
  const confirmations = [];
  const issued = new Map();
  const service = {protectionRequested: false, lastVerdict: null, activeSha: null, expectedSha: null, lastValid: null, emergencySha: null, applied: null, sessions: new Map()};
  const hosts = emergencyHosts || [
    {id: 'browser-firefox', kind: 'second_browser', process: 'firefox.exe', installed: true, distinguishable: true, approved: true},
  ];

  function hostError(code, reason) {
    return Object.assign(new Error(`${code}: ${reason}`), {code});
  }

  async function confirm(request = {}) {
    confirmations.push({...request});
    const scope = AUTHORIZATION_SCOPES[request.scope];
    if (!scope) return {ok: false, code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID};
    if (request.reuse) {
      const reusable = [...issued.values()].find((row) => row.scope === request.scope && row.environment_ref === request.environment_ref && !row.consumed_at && Date.parse(row.expires_at) > Date.parse(clock()));
      if (reusable) return {ok: true, authorization_ref: reusable.authorization_ref, expires_at: reusable.expires_at, reused: true};
    }
    const record = {
      authorization_ref: `nat-${randomUUID().replaceAll('-', '')}`,
      scope: request.scope,
      environment_ref: request.environment_ref,
      native_op: request.native_op,
      session_ref: request.session_ref,
      confirmed: true,
      consumed_at: null,
      expires_at: new Date(Date.parse(clock()) + (request.validity_ms || 3_600_000)).toISOString(),
    };
    issued.set(record.authorization_ref, record);
    return {ok: true, authorization_ref: record.authorization_ref, expires_at: record.expires_at};
  }

  function unreachable() {
    return {ok: false, code: 'SERVICE_UNREACHABLE', receipt: {side_effects: false}};
  }

  function isEmergencyConfig(yaml) {
    return /AND,\(\(PROCESS-NAME,[^)]+\),\([A-Z-]+,[^)]+\)\),(?!CLAUDE-FIXED)[A-Z-]+/.test(String(yaml));
  }

  function runtime() {
    const effective = service.protectionRequested && verdicts.protectionEffective;
    const pathOpen = effective && core.state.alive && service.lastVerdict === 'VERIFIED' && Boolean(service.activeSha);
    const result = {
      service: {status: 'RUNNING', service_instance_id: 'svc-double'},
      core: {running: core.state.alive, pid: 4100 + core.state.restartCount, restart_count: core.state.restartCount, binary_present: true, kernel_version: 'v1.19.30', gave_up: false},
      config: {
        environment_ref: environmentRef,
        active_config_sha256: service.activeSha,
        expected_config_sha256: service.expectedSha,
        last_valid_config_ref: service.lastValid?.sha || null,
        emergency_config_ref: service.emergencySha,
        plan_version: service.applied?.plan_version || null,
        assignment_version: service.applied?.assignment_version || null,
        last_valid_plan_version: service.lastValid?.plan_version || null,
      },
      readback: {
        status: service.lastVerdict || 'NOT_RUN',
        current: service.lastVerdict === 'VERIFIED',
        checks: service.lastVerdict === 'VERIFY_FAILED' ? [{name: 'rules', ok: false}] : [],
      },
      protection: {
        environment_ref: environmentRef,
        requested: service.protectionRequested,
        effective,
        missing: effective ? [] : ['C:\\Program Files\\Claude\\claude.exe'],
        managed_path: {status: pathOpen ? 'OPEN' : 'CLOSED', current: pathOpen, code: null},
      },
      emergency: [...service.sessions.values()],
      last_failure_code: service.lastVerdict === 'VERIFY_FAILED' ? 'VERIFY_FAILED' : null,
      missing: [],
    };
    return result;
  }

  async function actual() {
    const [general, rules, proxies] = await Promise.all([core.getConfigs(), core.getRules(), core.getProxies()]);
    return {general: general.general, rules: rules.rules, proxies: {proxies: proxies.proxies}};
  }

  async function handle(op, payload, reference) {
    if (op === 'EmergencyHosts') return {ok: true, hosts: hosts.map((item) => ({...item}))};
    assertPayload(op, payload);
    const record = typeof reference === 'string' ? issued.get(reference) || null : null;
    const problem = checkIssuedAuthorization(op, payload, record, clock(), typeof reference === 'string' ? reference : null);
    if (problem) throw hostError(problem.code, problem.reason);
    if (record && AUTHORIZATION_SCOPES[record.scope]?.single_use) record.consumed_at = clock();
    if (payload.environment_ref !== environmentRef) {
      throw hostError(ERROR_CODES.AUTHORIZATION_TARGET_MISMATCH, `this install runs ${environmentRef}`);
    }

    if (op === 'ReadNetworkState') {
      if (!verdicts.reachable) return {ok: false, code: 'SERVICE_UNREACHABLE', runtime: {service: {status: 'UNREACHABLE', code: 'SERVICE_UNREACHABLE'}}};
      const result = runtime();
      if ((payload.include || []).includes('config')) result.actual = await actual();
      if ((payload.include || []).includes('connections')) result.connections = await core.getConnections();
      if ((payload.include || []).includes('logs')) result.logs = ['[TCP] synthetic --> claude.ai using CLAUDE-FIXED'];
      return {ok: true, service: {link: 'READY'}, runtime: result};
    }

    if (op === 'ApplyNetworkPlan') {
      if (!String(payload.plan_version).startsWith(`plan:${payload.assignment_version}:`)) {
        throw hostError(ERROR_CODES.PAYLOAD_INVALID, 'plan_version does not belong to assignment_version');
      }
      if (sha256Hex(payload.yaml) !== payload.expected_config_sha256) {
        return {ok: false, code: 'CONFIG_DIGEST_MISMATCH', receipt: {side_effects: false, stages: {downloaded: {status: 'FAILED'}}}};
      }
      if (!verdicts.reachable) return unreachable();
      const validation = {stages: {downloaded: {status: 'OK', sha256: payload.expected_config_sha256}, validated: {status: 'OK'}}};
      if (!(service.protectionRequested && verdicts.protectionEffective)) {
        return {ok: false, code: 'PROTECTION_NOT_READY', validation, receipt: {side_effects: false, stages: {protection: {status: 'FAILED'}}}};
      }
      const loaded = await core.loadConfig({yaml: payload.yaml, force: true});
      if (!loaded.accepted) {
        return {ok: false, code: 'LOAD_FAILED', validation, receipt: {side_effects: true, stages: {applied: {status: 'FAILED', http_status: loaded.http_status}}}};
      }
      service.lastVerdict = verdicts.readback;
      service.expectedSha = payload.expected_config_sha256;
      const previous = service.lastValid?.sha || null;
      const verified = verdicts.readback === 'VERIFIED';
      const emergency = isEmergencyConfig(payload.yaml);
      service.activeSha = verified ? payload.expected_config_sha256 : null;
      service.applied = verified ? {plan_version: payload.plan_version, assignment_version: payload.assignment_version} : null;
      if (verified && emergency) {
        service.emergencySha = payload.expected_config_sha256;
      } else if (verified) {
        service.lastValid = {sha: payload.expected_config_sha256, yaml: payload.yaml, plan_version: payload.plan_version};
        service.emergencySha = null;
      }
      return {
        ok: verified,
        code: verified ? null : 'VERIFY_FAILED',
        validation,
        receipt: {
          overall: verified ? 'VERIFIED' : 'VERIFY_FAILED',
          config_class: emergency ? 'EMERGENCY_TEMPORARY' : 'BASELINE',
          active_config_sha256: service.activeSha,
          stages: {protection: {status: 'OK'}, applied: {status: 'ACCEPTED', http_status: 204}, verified: {status: verdicts.readback}},
          service_instance_id: 'svc-double',
          core_pid: 4100 + core.state.restartCount,
          requires_restore: !verified && Boolean(previous) && previous !== payload.expected_config_sha256,
          side_effects: true,
        },
      };
    }

    if (op === 'ProtectEnvironment') {
      if (!verdicts.reachable) return {...unreachable(), protection: {requested: false, new_connections_restricted: false}, close_existing: {status: 'SKIPPED'}};
      service.protectionRequested = true;
      const effective = verdicts.protectionEffective;
      let closeExisting = {status: 'SKIPPED', reason: effective ? 'NOT_REQUESTED' : 'PROTECTION_NOT_EFFECTIVE'};
      if (effective && ['WRONG_ROUTE', 'PROTECTION_FAILED'].includes(payload.reason_code)) {
        await core.deleteConnections();
        closeExisting = {ok: true, command: 'CloseManagedConnections', receipt: {closed_existing: true, new_connections_restricted: true}};
      }
      return {
        ok: effective,
        code: effective ? null : 'PROTECTION_NOT_EFFECTIVE',
        protection: {requested: true, effective, new_connections_restricted: effective, os_readback: effective ? 'PRESENT' : 'PARTIAL', reason_code: payload.reason_code},
        close_existing: closeExisting,
      };
    }

    if (op === 'NetworkLifecycle') {
      if (!verdicts.reachable) return unreachable();
      if (payload.event === 'restore_last_valid') {
        if (!service.lastValid) return {ok: false, code: 'LAST_VALID_MISSING', command: 'RestoreLastValid', receipt: {side_effects: false}};
        await core.loadConfig({yaml: service.lastValid.yaml, force: true});
        service.activeSha = service.lastValid.sha;
        service.expectedSha = service.lastValid.sha;
        service.emergencySha = null;
        service.lastVerdict = 'VERIFIED';
        return {ok: true, command: 'RestoreLastValid', receipt: {readback: 'VERIFIED', plan_version: service.lastValid.plan_version, requires_business_recheck: true}};
      }
      if (payload.event === 'maintenance_start') {
        if (!(service.protectionRequested && verdicts.protectionEffective)) {
          return {ok: false, code: 'PROTECTION_NOT_EFFECTIVE', command: 'StopCoreForMaintenance', receipt: {core_stopped: false, protection_retained: false, side_effects: false}};
        }
        core.crash();
        service.activeSha = null;
        return {ok: true, command: 'StopCoreForMaintenance', receipt: {core_stopped: true, protection_retained: true, side_effects: true}};
      }
      if (payload.event === 'maintenance_end') {
        if (!service.lastValid) return {ok: false, code: 'LAST_VALID_MISSING', command: 'StartCore'};
        core.restart();
        return {ok: true, command: 'StartCore', receipt: {readback: 'VERIFIED', requires_business_recheck: true}};
      }
      if (payload.event === 'stop_management') {
        if (verdicts.businessRunning) return {ok: false, code: 'PROTECTED_BUSINESS_RUNNING', command: 'EnsureProtection', receipt: {side_effects: false}};
        service.protectionRequested = false;
        return {ok: true, command: 'EnsureProtection', receipt: {released: true, business_paused: true}};
      }
      throw hostError(ERROR_CODES.PAYLOAD_INVALID, `unsupported network lifecycle event ${payload.event}`);
    }

    if (op === 'EmergencyOpen') {
      const host = hosts.find((item) => item.id === payload.host_id);
      if (!host?.approved) throw hostError('EMERGENCY_HOST_DENIED', 'not an approved second browser');
      if (!verdicts.routeReady || service.lastVerdict !== 'VERIFIED') {
        return {ok: false, status: 'ROUTE_NOT_READY', code: verdicts.routeReady ? 'CONFIG_NOT_VERIFIED' : 'EMERGENCY_ROUTE_ABSENT', route: {side_effects: false}};
      }
      const route = {route_ready: true, claude_constrained: true, protection_effective: true, emergency_scope: [{outbound: 'EMERGENCY-EGRESS'}, {outbound: 'CLAUDE-FIXED'}]};
      const session = {session_id: payload.session_id, host_id: host.id, process: host.process, pid: 5100, browser_bound: true, expires_at: payload.expires_at, open: true, status: 'ACTIVE', route_ready: true, claude_constrained: true, expiry_enforced_by: 'network_service'};
      service.sessions.set(payload.session_id, {session_ref: payload.session_id, open: true, expired: false});
      return {ok: true, status: 'ACTIVE', session, route: {...route, expiry_enforced_by: 'network_service'}};
    }

    if (op === 'EmergencyClose') {
      if (!verdicts.emergencyCloseConfirmed) {
        const route = {closed: false, closed_safely: false, browser_stopped: false, browser_termination: 'PROCESS_TERMINATE_FAILED_5', route_rules_present: false};
        return {ok: false, code: 'PROCESS_TERMINATE_FAILED_5', session: {session_id: payload.session_id, open: true, process_stopped: false, route_closed: false, closed_safely: false}, route};
      }
      if (service.emergencySha && service.activeSha === service.emergencySha && service.lastValid) {
        await core.loadConfig({yaml: service.lastValid.yaml, force: true});
        service.activeSha = service.lastValid.sha;
      }
      service.emergencySha = null;
      service.sessions.set(payload.session_id, {session_ref: payload.session_id, open: false, expired: false, closed_safely: true, route_rules_present_after_close: false});
      const route = {closed: true, closed_safely: true, browser_stopped: true, browser_termination: 'TERMINATED', route_rules_present: false, requires_config_reapply: false, baseline_restored: true};
      return {ok: true, session: {session_id: payload.session_id, open: false, process_stopped: true, route_closed: true, route_rules_present: false, closed_safely: true}, route};
    }

    return {ok: false, code: ERROR_CODES.CAPABILITY_UNIMPLEMENTED};
  }

  return {
    verdicts,
    calls,
    confirmations,
    service,
    confirm,
    async invoke(op, payload = {}, reference = null) {
      calls.push({op, payload: structuredClone(payload), reference});
      return handle(op, payload, reference);
    },
  };
}
