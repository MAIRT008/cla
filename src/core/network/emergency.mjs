import {AUTH_KIND, GROUP, PROOF_SIMULATION, RECORD} from './constants.mjs';
import {applyNetworkPlan} from './apply.mjs';
import {fail} from './errors.mjs';
import {nowIso, isExpired} from './time.mjs';

const DEFAULT_MINUTES = 30;

function pickHost(candidates) {
  return (candidates || []).find((item) => item.approved && item.distinguishable && item.kind === 'second_browser')
    || null;
}

function emergencyAccessFrom(host, targets, expiresAt, sessionId, limited) {
  return {
    session_id: sessionId,
    approved_outbound: limited ? GROUP.DIRECT : GROUP.PROXY_A,
    targets: (targets || []).map((target) => ({host: target.host, match: target.match === 'exact' ? 'exact' : 'subdomains'})),
    expires_at: expiresAt,
    over_quota_support: limited,
    host_id: host.id,
    process: host.process,
  };
}

async function revokeEmergency(request, ports, sessionId) {
  return applyNetworkPlan({
    operation_id: `${sessionId}:revoke`,
    user_ref: request.user_ref,
    environment_ref: request.environment_ref,
    assignment: request.assignment,
    mode: request.mode,
    whitelist: request.whitelist,
    capabilities: request.capabilities,
    emergencyAccess: null,
    quotaSnapshot: request.quotaSnapshot,
    authorization: {
      kind: AUTH_KIND.EMERGENCY,
      user_ref: request.user_ref,
      environment_ref: request.environment_ref,
      authorization_ref: request.confirmation?.confirmation_id || sessionId,
    },
    source: 'emergency',
    verify: false,
  }, ports);
}

export async function requestEmergencyAccess(request = {}, ports = {}) {
  const now = nowIso(ports.clock);
  if (!request.confirmation || request.confirmation.confirmed !== true) {
    throw fail('EMERGENCY_NOT_CONFIRMED', 'emergency access requires this-session user confirmation');
  }
  const durationMinutes = request.duration_minutes == null ? DEFAULT_MINUTES : Number(request.duration_minutes);
  if (!Number.isFinite(durationMinutes) || durationMinutes <= 0) throw fail('EMERGENCY_DURATION_INVALID', 'duration must be a positive number of minutes');
  const expiresAt = request.expires_at || new Date(Date.parse(now) + durationMinutes * 60 * 1000).toISOString();
  const candidates = request.candidates || ports.emergencyHost?.listCandidates?.() || [];
  const host = pickHost(candidates);
  if (!host) {
    const shared = candidates.find((item) => item.kind === 'shared_webview' || item.process === 'msedgewebview2.exe');
    if (shared && request.allow_shared_webview) throw fail('EMERGENCY_WEBVIEW_DENIED', 'shared WebView cannot be used as a general emergency path');
    throw fail('EMERGENCY_HOST_UNAVAILABLE', 'no distinguishable second browser is available', {
      general_emergency: 'INCOMPLETE',
      support_only: Boolean((request.template?.control_plane?.support || []).length),
    });
  }
  const quota = request.quotaSnapshot || {};
  const limited = ['LIMITED', 'DISABLED', 'EXPIRED'].includes(quota.status);
  const supportTargets = (request.template?.control_plane?.support || []).map((item) => ({host: item.host, match: 'subdomains'}));
  const requestedTargets = request.targets || [];
  const targets = limited ? supportTargets : requestedTargets;
  const generalIncomplete = limited || !host;
  const sessionId = request.session_id || ports.store?.newId?.('emergency') || `emergency-${now}`;
  const emergencyAccess = emergencyAccessFrom(host, targets, expiresAt, sessionId, limited);

  const apply = await applyNetworkPlan({
    operation_id: request.operation_id || `${sessionId}:apply`,
    user_ref: request.user_ref,
    environment_ref: request.environment_ref,
    assignment: request.assignment,
    mode: request.mode,
    whitelist: request.whitelist,
    capabilities: request.capabilities,
    emergencyAccess,
    quotaSnapshot: request.quotaSnapshot,
    authorization: {
      kind: AUTH_KIND.EMERGENCY,
      user_ref: request.user_ref,
      environment_ref: request.environment_ref,
      authorization_ref: request.confirmation.confirmation_id,
      expires_at: expiresAt,
      allow_verify: true,
    },
    source: 'emergency',
    verify: request.verify !== false,
  }, ports);

  if (!['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED'].includes(apply.overall)) {
    return {
      session_id: sessionId,
      user_ref: request.user_ref,
      environment_ref: request.environment_ref,
      host_opened: false,
      apply_overall: apply.overall,
      apply_code: apply.code,
      temporary_scope_revoked: true,
      proof_scope: PROOF_SIMULATION,
    };
  }

  const opened = await ports.emergencyHost.open({session_id: sessionId, host_id: host.id, expires_at: expiresAt});
  if (!opened.ok) {
    await revokeEmergency(request, ports, sessionId);
    throw fail(opened.code || 'EMERGENCY_OPEN_FAILED', 'emergency host failed to open after configuration');
  }

  const session = {
    session_id: sessionId,
    user_ref: request.user_ref,
    environment_ref: request.environment_ref,
    mode: request.mode,
    purpose: request.purpose || 'temporary_web_access',
    host_id: host.id,
    process: host.process,
    host_status: opened.status || 'ACTIVE',
    route_ready: opened.route ? opened.route.route_ready === true : null,
    targets: emergencyAccess.targets,
    expires_at: expiresAt,
    duration_minutes: durationMinutes,
    duration_is_release_value: false,
    claude_protected: opened.route ? opened.route.claude_constrained === true : true,
    quota_limited: limited,
    general_emergency: generalIncomplete ? 'INCOMPLETE' : 'OPEN',
    mainline_rechecked: false,
    host_opened: true,
    apply_operation_id: apply.operation_id,
    apply_overall: apply.overall,
    proof_scope: PROOF_SIMULATION,
    confirmation: {
      purpose: request.purpose || 'temporary_web_access',
      objects: emergencyAccess.targets,
      approved_host: host,
      expires_at: expiresAt,
      original_protection_impact: 'Claude remains on A or blocked; mainline is not declared restored',
    },
  };
  ports.store?.saveRecord?.(RECORD.EMERGENCY, sessionId, session);
  return session;
}

export async function endEmergencyAccess(request = {}, ports = {}) {
  const now = nowIso(ports.clock);
  const session = ports.store?.getRecord?.(request.session_id, RECORD.EMERGENCY);
  if (!session) throw fail('EMERGENCY_NOT_FOUND', 'emergency session does not exist');
  const closed = await ports.emergencyHost.close({session_id: session.session_id});
  const expired = isExpired(session.expires_at, now);
  const reason = request.reason || (expired ? 'EXPIRED' : 'USER_ENDED');
  session.host_close = closed;
  session.mainline_rechecked = false;
  if (!closed.ok) {
    // 关闭没有确认：不写 ended_at，会话仍算打开，到期清扫会再试。
    session.visible_error = closed.code;
    session.close_failed_at = now;
    session.close_failed_reason = reason;
    ports.store?.saveRecord?.(RECORD.EMERGENCY, session.session_id, session);
    return session;
  }
  session.ended_at = now;
  session.ended_reason = reason;
  const quotaLoaded = request.quotaSnapshot || (ports.control?.getQuotaSnapshot ? (await ports.control.getQuotaSnapshot(session.user_ref)).snapshot : null);
  const apply = await applyNetworkPlan({
    operation_id: request.operation_id || `${session.session_id}:end`,
    user_ref: session.user_ref,
    environment_ref: session.environment_ref,
    assignment: request.assignment,
    mode: request.mode,
    whitelist: request.whitelist,
    capabilities: request.capabilities,
    emergencyAccess: null,
    quotaSnapshot: quotaLoaded,
    authorization: request.authorization || {
      kind: AUTH_KIND.EMERGENCY,
      user_ref: session.user_ref,
      environment_ref: session.environment_ref,
      authorization_ref: session.session_id,
    },
    source: 'emergency',
    verify: false,
  }, ports);
  session.end_apply = {operation_id: apply.operation_id, overall: apply.overall};
  session.quota_status = quotaLoaded?.status || null;
  session.open = false;
  session.mainline_restored_claim = false;
  ports.store?.saveRecord?.(RECORD.EMERGENCY, session.session_id, session);
  return session;
}
