import {sha256Hex} from '../../adapters/platform/index.mjs';
import {AUTH_KIND, PROOF_SIMULATION, RECORD} from './constants.mjs';
import {compileNetworkPlan, comparableFromConfig, publicPlanView} from './compile.mjs';
import {resolveManagedPayload, resolveYamlPayload} from './credentials.mjs';
import {fail} from './errors.mjs';
import {nowIso} from './time.mjs';
import {validateAssignment} from './assignment.mjs';
import {resolveApprovedProtection} from './protectedProcesses.mjs';

function digest(value) {
  return sha256Hex(typeof value === 'string' ? value : JSON.stringify(value));
}

function stage(status, extra = {}) {
  return {status, ...extra};
}

function loadRecord(store, type, id) {
  return store?.getRecord?.(id, type) || store?.getRecord?.(id) || null;
}

function saveRecord(store, type, id, payload) {
  if (!store?.saveRecord) return payload;
  return store.saveRecord(type, id, payload);
}

function comparableRules(list) {
  return (list || []).map((rule, index) => ({
    index: rule.index ?? index,
    type: String(rule.type || '').replaceAll('-', ''),
    payload: rule.payload || '',
    proxy: rule.proxy || '',
  }));
}

function rulesMatch(expected, actual) {
  const left = comparableRules(expected);
  const right = comparableRules(actual).map((rule) => ({
    ...rule,
    type: String(rule.type).replaceAll('-', ''),
  }));
  if (left.length !== right.length) return false;
  return left.every((rule, index) => rule.payload === right[index].payload && rule.proxy === right[index].proxy);
}

export function authorizationAllows(authorization, request, now) {
  if (!authorization) return {ok: false, code: 'AUTHORIZATION_REQUIRED', reason: 'write authorization is required'};
  if (authorization.kind === 'READ' || authorization.kind === 'SCAN') {
    return {ok: false, code: 'AUTHORIZATION_SCOPE_DENIED', reason: 'read or scan is not a write grant'};
  }
  if (!Object.values(AUTH_KIND).includes(authorization.kind) && authorization.kind !== AUTH_KIND.ONCE && authorization.kind !== AUTH_KIND.MAINTENANCE && authorization.kind !== AUTH_KIND.PROTECTION && authorization.kind !== AUTH_KIND.EMERGENCY) {
    return {ok: false, code: 'AUTHORIZATION_SCOPE_DENIED', reason: 'authorization kind is not recognized'};
  }
  if (authorization.user_ref && request.user_ref && authorization.user_ref !== request.user_ref) {
    return {ok: false, code: 'AUTHORIZATION_SCOPE_DENIED', reason: 'authorization user does not match'};
  }
  if (authorization.environment_ref && request.environment_ref && authorization.environment_ref !== request.environment_ref) {
    return {ok: false, code: 'ENVIRONMENT_MISMATCH', reason: 'authorization environment does not match'};
  }
  if (authorization.expires_at && Date.parse(authorization.expires_at) <= Date.parse(now)) {
    return {ok: false, code: 'AUTHORIZATION_EXPIRED', reason: 'authorization has expired'};
  }
  if (authorization.plan_version && request.plan_version && authorization.plan_version !== request.plan_version && authorization.kind === AUTH_KIND.ONCE) {
    return {ok: false, code: 'PLAN_STALE', reason: 'confirmed plan version does not match'};
  }
  if (authorization.assignment_version && request.assignment_version && authorization.assignment_version !== request.assignment_version) {
    return {ok: false, code: 'PLAN_STALE', reason: 'assignment version does not match authorization'};
  }
  const sensitive = request.sensitive_change === true;
  if (sensitive && authorization.kind === AUTH_KIND.MAINTENANCE && authorization.allow_sensitive !== true) {
    return {ok: false, code: 'AUTHORIZATION_SCOPE_DENIED', reason: 'A, region, protection or whitelist boundary changes are not routine updates'};
  }
  return {ok: true};
}

function emptyState(request, now) {
  return {
    user_ref: request.user_ref,
    environment_ref: request.environment_ref,
    observed_at: now,
    proof_scope: PROOF_SIMULATION,
    expected: null,
    applied: null,
    loaded: null,
    verified: null,
    core_instance: null,
    protection: {status: 'UNKNOWN'},
    emergency: null,
  };
}

export function operationRecordId(request) {
  return `network-operation:${request.user_ref}:${request.environment_ref || 'default'}:${request.operation_id}`;
}

export function requestDigest(request) {
  return digest({
    user_ref: request.user_ref,
    environment_ref: request.environment_ref || 'default',
    mode: request.mode || null,
    assignment_version: request.assignment?.assignment_version || request.assignment_version || null,
    whitelist_version: request.whitelist?.version || null,
    source: request.source || 'user',
  });
}

export async function applyNetworkPlan(request = {}, ports = {}) {
  const now = nowIso(ports.clock);
  const store = ports.store;
  const operationId = request.operation_id;
  if (!operationId) throw fail('OPERATION_REQUIRED', 'operation_id is required');
  if (!request.user_ref) throw fail('ASSIGNMENT_INVALID', 'user_ref is required');
  const recordId = operationRecordId(request);
  const digestValue = requestDigest(request);
  const existing = loadRecord(store, RECORD.OPERATION, recordId);
  if (existing && existing.user_ref === request.user_ref && existing.environment_ref === (request.environment_ref || existing.environment_ref) && existing.request_digest === digestValue && ['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED', 'RESTORED', 'CANCELLED'].includes(existing.overall)) {
    return existing;
  }
  if (existing && (existing.user_ref !== request.user_ref || existing.environment_ref !== request.environment_ref || existing.request_digest !== digestValue) && ['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED', 'RESTORED'].includes(existing.overall)) {
    return {operation_id: operationId, overall: 'FAILED', code: 'OPERATION_REPLAY_MISMATCH', reason: 'operation_id is bound to user, environment and request digest', proof_scope: PROOF_SIMULATION, observed_at: now};
  }
  const receipt = {
    operation_id: operationId,
    record_id: recordId,
    request_digest: digestValue,
    proof_scope: PROOF_SIMULATION,
    source: request.source || 'user',
    user_ref: request.user_ref,
    environment_ref: request.environment_ref,
    stages: {},
    expected: null,
    applied: null,
    loaded: {loaded_version: null},
    verified: {status: 'NOT_RUN'},
    overall: 'IN_PROGRESS',
    observed_at: now,
  };
  saveRecord(store, RECORD.OPERATION, recordId, receipt);

  const auth = authorizationAllows(request.authorization, request, now);
  receipt.stages.authorize = stage(auth.ok ? 'OK' : 'FAILED', {code: auth.code || null, kind: request.authorization?.kind || null});
  if (!auth.ok) {
    receipt.overall = 'FAILED';
    receipt.code = auth.code;
    receipt.reason = auth.reason;
    saveRecord(store, RECORD.OPERATION, recordId, receipt);
    return receipt;
  }

  let assignment = request.assignment;
  if (ports.control?.getAssignment) {
    const loaded = await ports.control.getAssignment(request.user_ref);
    assignment = loaded.assignment || null;
  }
  if (!assignment || assignment.user_ref !== request.user_ref) {
    receipt.stages.assignment = stage('FAILED', {code: 'ASSIGNMENT_USER_MISMATCH'});
    receipt.overall = 'FAILED';
    receipt.code = assignment ? 'ASSIGNMENT_USER_MISMATCH' : 'ASSIGNMENT_INVALID';
    receipt.reason = assignment ? 'assignment does not belong to the requesting user' : 'authoritative assignment is required';
    saveRecord(store, RECORD.OPERATION, recordId, receipt);
    return receipt;
  }
  if (ports.control?.getQuotaSnapshot) {
    const loadedQuota = await ports.control.getQuotaSnapshot(request.user_ref);
    request = {...request, quotaSnapshot: loadedQuota.snapshot, assignment};
  }
  const validation = validateAssignment(assignment, {environment_ref: request.environment_ref}, now);
  receipt.stages.assignment = stage(validation.ok ? 'OK' : 'FAILED', {code: validation.code, issues: validation.issues});
  if (!validation.ok) {
    receipt.overall = 'FAILED';
    receipt.code = validation.code;
    receipt.reason = validation.reason;
    saveRecord(store, RECORD.OPERATION, recordId, receipt);
    return receipt;
  }

  const currentState = loadRecord(store, RECORD.STATE, stateId(request)) || emptyState(request, now);
  const restoreMaterial = {
    restore_ref: `restore-${operationId}`,
    user_ref: request.user_ref,
    environment_ref: request.environment_ref,
    previous_plan_version: currentState.expected?.plan_version || null,
    previous_yaml: currentState.expected?.yaml || currentState.restore_yaml || null,
    previous_assignment_version: currentState.expected?.assignment_version || null,
    previous_authorization: currentState.authorization || null,
    previous_operation_id: currentState.applied?.operation_id || null,
    saved_at: now,
  };
  saveRecord(store, RECORD.RESTORE, restoreMaterial.restore_ref, restoreMaterial);
  receipt.stages.restore_saved = stage('OK', {restore_ref: restoreMaterial.restore_ref});

  if (ports.protection?.requestProtection && request.ensure_protection !== false) {
    const scope = await resolveApprovedProtection({assignment, state: currentState, control: ports.control, userRef: request.user_ref});
    const ready = await ports.protection.requestProtection({
      action: 'ensure_ready',
      environment_ref: request.environment_ref,
      authorization_ref: request.authorization?.authorization_ref,
      authorization_kind: AUTH_KIND.PROTECTION,
      processes: scope.processes,
      loopback_policy: scope.loopback_policy,
    });
    const confirmed = ready.status === 'CONFIRMED' || ready.new_connections_restricted === true;
    receipt.stages.protection_ready = stage(confirmed ? 'OK' : 'FAILED', {protection: ready.status, new_connections_restricted: ready.new_connections_restricted === true});
    if (!confirmed) {
      receipt.overall = 'FAILED';
      receipt.code = 'PROTECTION_NOT_READY';
      receipt.reason = 'new connections must be confirmed restricted before loading a managed configuration';
      saveRecord(store, RECORD.OPERATION, recordId, receipt);
      return receipt;
    }
  } else {
    receipt.stages.protection_ready = stage('SKIPPED');
  }

  let plan;
  try {
    plan = request.compiled || compileNetworkPlan({
      assignment,
      mode: request.mode,
      whitelist: request.whitelist,
      capabilities: request.capabilities,
      emergencyAccess: request.emergencyAccess,
      quotaSnapshot: request.quotaSnapshot,
      environmentScope: {environment_ref: request.environment_ref},
      now,
    });
  } catch (error) {
    receipt.stages.compiled = stage('FAILED', {code: error.code, reason: error.message});
    receipt.overall = 'FAILED';
    receipt.code = error.code;
    receipt.reason = error.message;
    saveRecord(store, RECORD.OPERATION, recordId, receipt);
    return restoreOnFailure(receipt, restoreMaterial, request, ports, now);
  }
  receipt.stages.compiled = stage('OK', {plan_version: plan.plan_version, config_hash: plan.config_hash});
  receipt.stages.static_validated = stage('OK');
  receipt.expected = {
    plan_version: plan.plan_version,
    assignment_version: plan.assignment_version,
    mode: plan.mode,
    config_hash: plan.config_hash,
    comparable: plan.comparable,
    yaml: plan.yaml,
    matrix: plan.matrix,
  };

  if (!ports.core?.loadConfig && !ports.core?.putConfigs) {
    receipt.stages.loaded = stage('FAILED', {code: 'CORE_UNAVAILABLE'});
    receipt.overall = 'FAILED';
    receipt.code = 'CORE_UNAVAILABLE';
    receipt.reason = 'core port is not connected';
    saveRecord(store, RECORD.OPERATION, recordId, receipt);
    return receipt;
  }

  let nativeYaml;
  try {
    nativeYaml = resolveManagedPayload(plan.config, ports.secrets);
  } catch (error) {
    receipt.stages.loaded = stage('FAILED', {code: error.code || 'CREDENTIAL_UNAVAILABLE', reason: error.message});
    receipt.overall = 'FAILED';
    receipt.code = error.code || 'CREDENTIAL_UNAVAILABLE';
    receipt.reason = error.message;
    saveRecord(store, RECORD.OPERATION, recordId, receipt);
    return receipt;
  }

  // 产品服务按 operation 幂等：同一次重试的同一配置在服务里重放原回执；失败后重新执行换一个尝试序号。
  const serviceAttempt = (existing?.service_attempt || 0) + 1;
  receipt.service_attempt = serviceAttempt;
  const nativeFields = {
    operation_id: `${operationId}:${digest(nativeYaml).slice(0, 16)}:${serviceAttempt}`,
    plan_ref: request.plan_ref || plan.plan_version,
    plan_version: plan.plan_version,
    assignment_version: plan.assignment_version,
    expected_config_sha256: digest(nativeYaml),
  };
  let loadResult;
  try {
    loadResult = ports.core.loadConfig
      ? await ports.core.loadConfig({yaml: nativeYaml, force: true, ...nativeFields})
      : await ports.core.putConfigs({payload: nativeYaml, force: true, ...nativeFields});
  } catch (error) {
    receipt.stages.loaded = stage('FAILED', {code: error.code || 'CORE_PROTOCOL_ERROR', reason: error.message});
    receipt.overall = 'FAILED';
    receipt.code = error.code || 'CORE_PROTOCOL_ERROR';
    receipt.reason = error.message;
    saveRecord(store, RECORD.OPERATION, recordId, receipt);
    return restoreOnFailure(receipt, restoreMaterial, request, ports, now);
  }
  receipt.applied = {
    accepted: loadResult.accepted === true,
    http_status: loadResult.http_status,
    payload_hash: loadResult.payload_hash || digest(nativeYaml),
    loaded_version: null,
  };
  for (const name of ['downloaded', 'validated']) {
    if (loadResult.stages?.[name]) receipt.stages[name] = loadResult.stages[name];
  }
  receipt.stages.loaded = stage(loadResult.accepted ? 'HTTP_ACCEPTED' : 'FAILED', {http_status: loadResult.http_status, note: '204 is not product verification'});
  if (!loadResult.accepted) {
    receipt.overall = 'FAILED';
    receipt.code = loadResult.code || 'LOAD_FAILED';
    receipt.reason = loadResult.error?.message || 'core rejected the configuration';
    saveRecord(store, RECORD.OPERATION, recordId, receipt);
    return restoreOnFailure(receipt, restoreMaterial, request, ports, now);
  }

  if (loadResult.service_verification) {
    const serviceVerified = loadResult.verified === true;
    receipt.stages.service_verified = stage(serviceVerified ? 'OK' : 'FAILED', {service_status: loadResult.service_verification.status || null, code: serviceVerified ? null : loadResult.code || 'VERIFY_FAILED'});
    if (!serviceVerified) {
      receipt.verified = {status: 'FAILED', reason: 'SERVICE_READBACK_MISMATCH'};
      receipt.overall = 'FAILED';
      receipt.code = loadResult.code || 'VERIFY_FAILED';
      receipt.reason = 'the network service did not verify the managed configuration against the running kernel';
      saveRecord(store, RECORD.OPERATION, recordId, receipt);
      return restoreOnFailure(receipt, restoreMaterial, request, ports, now);
    }
  }

  const [general, rules, proxies, version] = await Promise.all([
    ports.core.getConfigs(),
    ports.core.getRules(),
    ports.core.getProxies(),
    ports.core.getVersion(),
  ]);
  const expectedRules = plan.comparable.rules.map((rule) => ({index: rule.index, type: rule.type, payload: rule.payload, proxy: rule.proxy}));
  const actualRules = rules.rules || [];
  const inconsistencies = [];
  if (!rulesMatch(expectedRules, actualRules)) inconsistencies.push('RULES_MISMATCH');
  if (general.general?.tun && plan.config.tun.enable !== Boolean(general.general.tun.enable)) inconsistencies.push('TUN_MISMATCH');
  if (general.loaded_version) inconsistencies.push('UNEXPECTED_LOADED_VERSION_FIELD');
  const claudeNow = proxies.proxies?.['CLAUDE-FIXED']?.now;
  if (claudeNow && claudeNow !== 'PROXY-A' && claudeNow !== 'REJECT') inconsistencies.push('WRONG_CLAUDE_EXIT');
  receipt.loaded = {
    loaded_version: null,
    kernel_version: version.version || null,
    general: general.general,
    rules: actualRules,
    proxy_names: Object.keys(proxies.proxies || {}),
    inconsistencies,
    core_instance: ports.core.snapshot?.() || null,
  };
  receipt.stages.readback = stage(inconsistencies.length ? 'MISMATCH' : 'OK', {inconsistencies});
  if (inconsistencies.length) {
    receipt.verified = {status: 'FAILED', reason: inconsistencies.join(',')};
    receipt.overall = 'FAILED';
    receipt.code = 'READBACK_MISMATCH';
    receipt.reason = inconsistencies.join(',');
    saveRecord(store, RECORD.OPERATION, recordId, receipt);
    return restoreOnFailure(receipt, restoreMaterial, request, ports, now);
  }

  if (request.verify === false) {
    receipt.verified = {status: 'NOT_RUN', reason: 'VERIFY_SKIPPED'};
    receipt.stages.path_verified = stage('SKIPPED');
    receipt.overall = 'APPLIED_UNVERIFIED';
  } else if (!request.authorization?.allow_verify && request.source !== 'user' && request.source !== 'emergency' && request.source !== 'ai_confirmed') {
    receipt.verified = {status: 'NOT_RUN', reason: 'VERIFY_UNAUTHORIZED'};
    receipt.stages.path_verified = stage('SKIPPED', {code: 'VERIFY_UNAUTHORIZED'});
    receipt.overall = 'APPLIED_UNVERIFIED';
  } else if (!ports.verify?.verify) {
    receipt.verified = {status: 'NOT_RUN', reason: 'VERIFY_PORT_UNAVAILABLE'};
    receipt.stages.path_verified = stage('SKIPPED');
    receipt.overall = 'APPLIED_UNVERIFIED';
  } else {
    const checks = request.verify_checks || defaultChecks(plan);
    const verified = await ports.verify.verify({mode: plan.mode, environment_ref: request.environment_ref, checks, expected: plan.matrix});
    receipt.verified = {status: verified.status, results: verified.results};
    receipt.stages.path_verified = stage(verified.status === 'VERIFIED' ? 'OK' : 'FAILED');
    receipt.overall = verified.status === 'VERIFIED' ? 'APPLIED_VERIFIED' : 'APPLIED_UNVERIFIED';
    if (verified.status !== 'VERIFIED' && request.fail_on_verify !== false) {
      receipt.overall = 'FAILED';
      receipt.code = 'VERIFY_FAILED';
      receipt.reason = 'path verification did not match expected A/B';
      saveRecord(store, RECORD.OPERATION, recordId, receipt);
      return restoreOnFailure(receipt, restoreMaterial, request, ports, now);
    }
  }

  const approvedScope = await resolveApprovedProtection({assignment, state: currentState, control: ports.control, userRef: request.user_ref});
  const nextState = {
    ...currentState,
    observed_at: now,
    expected: receipt.expected,
    applied: {operation_id: operationId, ...receipt.applied},
    loaded: receipt.loaded,
    verified: receipt.verified,
    core_instance: receipt.loaded.core_instance,
    authorization: request.authorization,
    restore_yaml: plan.yaml,
    mode: plan.mode,
    whitelist_version: plan.whitelist?.version,
    protected_process_paths: approvedScope.processes,
    loopback_policy: approvedScope.loopback_policy,
    proof_scope: PROOF_SIMULATION,
  };
  saveRecord(store, RECORD.STATE, stateId(request), nextState);
  receipt.public_plan = publicPlanView(plan);
  receipt.stages.recorded = stage('OK');
  saveRecord(store, RECORD.OPERATION, recordId, receipt);
  if (ports.control?.saveApplyReceipt) await ports.control.saveApplyReceipt(redactReceipt(receipt));
  return receipt;
}

function defaultChecks(plan) {
  return [
    {id: 'claude-a', kind: 'exit', target: 'claude', expected: plan.matrix.claude.exit, protocol: 'tcp'},
    {id: 'other-exit', kind: 'exit', target: 'other', expected: plan.matrix.other.exit, protocol: 'tcp'},
  ];
}

async function restoreOnFailure(receipt, restoreMaterial, request, ports, now) {
  if (request.restore_on_failure === false) {
    saveRecord(ports.store, RECORD.OPERATION, receipt.operation_id, receipt);
    return receipt;
  }
  if (!restoreMaterial.previous_yaml) {
    receipt.restore = {status: 'NO_VALID_VERSION', blocked: true};
    saveRecord(ports.store, RECORD.OPERATION, receipt.operation_id, receipt);
    return receipt;
  }
  const restored = await restoreNetworkPlan({
    operation_id: `${receipt.operation_id}:restore`,
    user_ref: request.user_ref,
    environment_ref: request.environment_ref,
    restore_ref: restoreMaterial.restore_ref,
    authorization: request.authorization,
    assignment: request.assignment,
    current_assignment: request.assignment,
    quotaSnapshot: request.quotaSnapshot,
    whitelist: request.whitelist,
    mode: request.mode,
    source: 'failure_restore',
    verify: false,
    restore_on_failure: false,
    ensure_protection: false,
  }, ports);
  receipt.restore = {status: restored.overall, operation_id: restored.operation_id, code: restored.code || null};
  if (restored.overall === 'FAILED') receipt.restore.blocked = true;
  saveRecord(ports.store, RECORD.OPERATION, operationRecordId(request), receipt);
  return receipt;
}

export async function restoreNetworkPlan(request = {}, ports = {}) {
  const now = nowIso(ports.clock);
  const auth = authorizationAllows(request.authorization, request, now);
  if (!auth.ok) {
    return {operation_id: request.operation_id, overall: 'FAILED', code: auth.code, reason: auth.reason, proof_scope: PROOF_SIMULATION, observed_at: now};
  }
  const restore = (request.restore_ref ? loadRecord(ports.store, RECORD.RESTORE, request.restore_ref) : null) || request.restore_material || null;
  if (!restore?.previous_yaml && !ports.core?.restoreLastValid) {
    return {operation_id: request.operation_id, overall: 'FAILED', code: 'RESTORE_UNAVAILABLE', reason: 'no restorable configuration is recorded', proof_scope: PROOF_SIMULATION, observed_at: now};
  }
  let assignment = request.current_assignment || request.assignment;
  if (ports.control?.getAssignment) {
    assignment = (await ports.control.getAssignment(request.user_ref)).assignment || null;
  }
  if (ports.control?.getQuotaSnapshot) {
    request = {...request, quotaSnapshot: (await ports.control.getQuotaSnapshot(request.user_ref)).snapshot};
  }
  if (!assignment || assignment.user_ref !== request.user_ref) {
    return {operation_id: request.operation_id, overall: 'FAILED', code: 'ASSIGNMENT_USER_MISMATCH', reason: 'restore assignment does not belong to the requesting user', proof_scope: PROOF_SIMULATION, observed_at: now};
  }
  const validation = validateAssignment(assignment, {environment_ref: request.environment_ref}, now);
  if (!validation.ok) {
    return {operation_id: request.operation_id, overall: 'FAILED', code: validation.code, reason: 'restore refuses revoked, expired or unauthorized resources', proof_scope: PROOF_SIMULATION, observed_at: now};
  }
  const quotaLimited = request.quotaSnapshot && ['LIMITED', 'DISABLED', 'EXPIRED'].includes(request.quotaSnapshot.status);
  const current = loadRecord(ports.store, RECORD.STATE, stateId(request));
  if (request.detect_external) {
    const liveRules = ports.core?.getRules ? (await ports.core.getRules()).rules : [];
    const expected = current?.expected?.comparable?.rules || [];
    const mismatched = expected.length && liveRules.length && !rulesMatch(expected, liveRules);
    if (request.external_modified === true || mismatched) {
      return {operation_id: request.operation_id, overall: 'FAILED', code: 'EXTERNAL_MODIFICATION', reason: 'restore will not overwrite an external modification', proof_scope: PROOF_SIMULATION, observed_at: now};
    }
  }
  if (!ports.core?.loadConfig && !ports.core?.putConfigs) {
    return {operation_id: request.operation_id, overall: 'FAILED', code: 'CORE_UNAVAILABLE', proof_scope: PROOF_SIMULATION, observed_at: now};
  }
  if (!quotaLimited && ports.core.restoreLastValid) {
    // 产品服务重新加载它回读确认过的 last-valid；分配撤销、过期与额度状态已在上面按当前记录核对过。
    const restored = await ports.core.restoreLastValid({operation_id: request.operation_id, reason_code: request.source === 'failure_restore' ? 'APPLY_FAILED' : 'RESTORE_REQUESTED'});
    const serviceReceipt = restored.receipt || {};
    const receipt = {
      operation_id: request.operation_id,
      overall: restored.ok ? 'RESTORED' : 'FAILED',
      code: restored.ok ? null : restored.code || 'RESTORE_FAILED',
      applied: {accepted: restored.ok, http_status: null, loaded_version: null},
      loaded: {loaded_version: null},
      verified: {status: 'NOT_RUN', reason: 'RESTORE_REQUIRES_NORMAL_RECHECK'},
      service_readback: serviceReceipt.readback || null,
      proof_scope: PROOF_SIMULATION,
      observed_at: now,
      restored_plan_version: serviceReceipt.plan_version || null,
      service_last_valid_matches_record: serviceReceipt.plan_version ? serviceReceipt.plan_version === restore?.previous_plan_version : null,
      quota_reset: false,
      quota_enforced: false,
      revoked_resurrected: false,
    };
    saveRecord(ports.store, RECORD.OPERATION, operationRecordId(request), receipt);
    return receipt;
  }
  let payloadYaml;
  let restoredAssignmentVersion = restore?.previous_assignment_version;
  let restoredPlanVersion = restore?.previous_plan_version;
  if (quotaLimited) {
    const mode = request.mode || current?.mode;
    if (!mode) {
      return {operation_id: request.operation_id, overall: 'FAILED', code: 'QUOTA_LIMITED', reason: 'restore cannot reload an unrestricted configuration while the user is limited', proof_scope: PROOF_SIMULATION, observed_at: now};
    }
    const plan = compileNetworkPlan({
      assignment,
      mode,
      whitelist: request.whitelist,
      capabilities: request.capabilities,
      quotaSnapshot: request.quotaSnapshot,
      environmentScope: {environment_ref: request.environment_ref},
      now,
    });
    payloadYaml = resolveManagedPayload(plan.config, ports.secrets);
    restoredPlanVersion = plan.plan_version;
    restoredAssignmentVersion = plan.assignment_version;
  } else {
    payloadYaml = resolveYamlPayload(restore.previous_yaml, ports.secrets);
  }
  const restoreFields = {
    operation_id: `${request.operation_id}:${digest(payloadYaml).slice(0, 16)}`,
    plan_ref: `restore:${request.restore_ref}`,
    plan_version: restoredPlanVersion,
    assignment_version: restoredAssignmentVersion,
    expected_config_sha256: digest(payloadYaml),
  };
  const loaded = ports.core.loadConfig
    ? await ports.core.loadConfig({yaml: payloadYaml, force: true, ...restoreFields})
    : await ports.core.putConfigs({payload: payloadYaml, force: true, ...restoreFields});
  const receipt = {
    operation_id: request.operation_id,
    overall: loaded.accepted && loaded.verified !== false ? 'RESTORED' : 'FAILED',
    code: loaded.accepted && loaded.verified !== false ? null : loaded.code || 'LOAD_FAILED',
    applied: {accepted: loaded.accepted, http_status: loaded.http_status, loaded_version: null},
    loaded: {loaded_version: null},
    verified: {status: 'NOT_RUN', reason: 'RESTORE_REQUIRES_NORMAL_RECHECK'},
    proof_scope: PROOF_SIMULATION,
    observed_at: now,
    restored_plan_version: restoredPlanVersion,
    quota_reset: false,
    quota_enforced: Boolean(quotaLimited),
    revoked_resurrected: false,
  };
  saveRecord(ports.store, RECORD.OPERATION, operationRecordId(request), receipt);
  return receipt;
}

export function stateId(request) {
  return `network-state:${request.user_ref}:${request.environment_ref || 'default'}`;
}

export function redactReceipt(receipt) {
  const copy = structuredClone(receipt);
  if (copy.expected) delete copy.expected.yaml;
  if (copy.public_plan?.yaml) copy.public_plan = {...copy.public_plan, yaml: '[redacted-in-control-receipt]'};
  return copy;
}

export {comparableFromConfig, digest};
