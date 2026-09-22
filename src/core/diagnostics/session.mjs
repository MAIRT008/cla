import {randomHex, timingSafeEqualHex} from '../../adapters/platform/index.mjs';
import {SCRIPT_VERSION} from './constants.mjs';
import {persistDiagnosticReport, redactDiagnostic} from './reports.mjs';
import {issuesFromBrowserSample, scoreNetwork} from './rules.mjs';

function nowIso(clock) {
  const value = typeof clock === 'function' ? clock() : Date.now();
  return typeof value === 'string' ? value : new Date(value).toISOString();
}

function token() {
  return randomHex(16);
}

function safeEqual(left, right) {
  return timingSafeEqualHex(String(left || ''), String(right || ''));
}

const ALLOWED_SURFACES = Object.freeze(['platform', 'fingerprint', 'ice', 'errors']);

export function createBrowserSession({store, clock = () => Date.now(), taskRef, environmentRef, clientRef, profileRef, origin, returnPath, allowedSurfaces = ALLOWED_SURFACES, ttlMs = 15 * 60 * 1000} = {}) {
  if (!taskRef) throw Object.assign(new Error('task_ref is required'), {code: 'SESSION_TASK_REQUIRED'});
  if (!environmentRef) throw Object.assign(new Error('environment_ref is required'), {code: 'SESSION_ENVIRONMENT_REQUIRED'});
  if (!origin) throw Object.assign(new Error('origin is required'), {code: 'SESSION_ORIGIN_REQUIRED'});
  const task = store.getRecord(taskRef, 'diagnostic_task') || store.getRecord(taskRef, 'diagnostic_result');
  if (!task) throw Object.assign(new Error('diagnostic task is missing'), {code: 'SESSION_TASK_NOT_FOUND'});
  if (task.environment_ref && task.environment_ref !== environmentRef) {
    throw Object.assign(new Error('environment does not match the diagnostic task'), {code: 'SESSION_ENVIRONMENT_MISMATCH'});
  }
  const created = nowIso(clock);
  const expires = new Date(Date.parse(created) + ttlMs).toISOString();
  const session = {
    session_ref: `diag-session-${token()}`,
    session_nonce: token(),
    task_ref: taskRef,
    environment_ref: environmentRef,
    client_ref: clientRef || null,
    profile_ref: profileRef || null,
    origin,
    return_path: returnPath || '/diag/report',
    script_version: SCRIPT_VERSION,
    allowed_surfaces: [...allowedSurfaces],
    created_at: created,
    expires_at: expires,
    status: 'OPEN',
    profile_binding: profileRef ? 'DECLARED_ONLY' : 'UNBOUND',
  };
  store.saveRecord('browser_session', session.session_ref, session);
  return session;
}

function clipSample(sample, allowedSurfaces) {
  const allowed = new Set(allowedSurfaces || ALLOWED_SURFACES);
  const out = {};
  for (const key of allowed) {
    if (sample && Object.prototype.hasOwnProperty.call(sample, key)) out[key] = sample[key];
  }
  out.cookie_values_read = false;
  out.audio_played = false;
  return redactDiagnostic(out);
}

export function acceptBrowserReport({store, clock = () => Date.now(), request}) {
  const headers = request.headers || {};
  const origin = headers.origin || headers.Origin || request.origin;
  const body = request.body || {};
  if (!origin) return {ok: false, code: 'ORIGIN_REQUIRED', status: 403};
  if (!body.script_version) return {ok: false, code: 'SCRIPT_VERSION_REQUIRED', status: 400};
  if (!body.task_ref) return {ok: false, code: 'TASK_REF_REQUIRED', status: 400};
  if (!body.environment_ref) return {ok: false, code: 'ENVIRONMENT_REQUIRED', status: 400};
  const session = store.getRecord(body.session_ref, 'browser_session');
  if (!session) return {ok: false, code: 'SESSION_NOT_FOUND', status: 404};
  if (session.status === 'CANCELLED') return {ok: false, code: 'SESSION_CANCELLED', status: 409};
  if (Date.parse(nowIso(clock)) >= Date.parse(session.expires_at)) return {ok: false, code: 'SESSION_EXPIRED', status: 409};
  if (!safeEqual(session.session_nonce, body.session_nonce)) return {ok: false, code: 'NONCE_INVALID', status: 403};
  if (origin !== session.origin) return {ok: false, code: 'ORIGIN_DENIED', status: 403};
  if (body.script_version !== session.script_version) return {ok: false, code: 'SCRIPT_VERSION_MISMATCH', status: 409};
  if (body.task_ref !== session.task_ref) return {ok: false, code: 'TASK_MISMATCH', status: 409};
  if (body.environment_ref !== session.environment_ref) return {ok: false, code: 'ENVIRONMENT_MISMATCH', status: 409};
  if (session.profile_ref && body.profile_ref !== session.profile_ref) {
    return {ok: false, code: 'PROFILE_MISMATCH', status: 409, declared: body.profile_ref, bound: session.profile_ref};
  }
  const sample = clipSample(body.sample || {}, session.allowed_surfaces);
  const errors = redactDiagnostic(Array.isArray(body.errors) ? body.errors : []);
  const digest = JSON.stringify({sample, errors});
  if (session.received_digest === digest) {
    return {ok: true, duplicate: true, receipt_ref: session.receipt_ref, session_ref: session.session_ref, task_ref: session.task_ref};
  }
  if (session.received_digest && session.received_digest !== digest) {
    return {ok: false, code: 'REPLAY_CHANGED', status: 409, receipt_ref: session.receipt_ref};
  }
  const receiptRef = `diag-receipt-${session.session_ref}`;
  const received = {
    session_ref: session.session_ref,
    task_ref: session.task_ref,
    environment_ref: session.environment_ref,
    profile_ref: session.profile_ref,
    origin: session.origin,
    script_version: session.script_version,
    status: 'RECEIVED',
    received_at: nowIso(clock),
    receipt_ref: receiptRef,
    received_digest: digest,
    sample,
    errors,
    user_agent_declared: body.user_agent || null,
    profile_binding: session.profile_binding,
  };
  const stored = redactDiagnostic(received);
  store.saveRecord('browser_session', session.session_ref, {...session, ...stored});
  store.saveRecord('browser_receipt', receiptRef, stored);
  return {ok: true, duplicate: false, receipt_ref: receiptRef, session_ref: session.session_ref, task_ref: session.task_ref, profile_binding: received.profile_binding};
}

export function mergeBrowserReceiptIntoResult(store, receiptRef) {
  const receipt = store.getRecord(receiptRef, 'browser_receipt');
  if (!receipt?.task_ref) return null;
  const result = store.getRecord(receipt.task_ref, 'diagnostic_result');
  if (!result || result.status === 'RUNNING') return null;
  const observation = {
    task_id: receipt.task_ref,
    check_id: 'browser.session-sample',
    evidence_ref: receipt.receipt_ref,
    environment_ref: receipt.environment_ref,
    profile_ref: receipt.profile_ref || result.profile_ref || null,
    observed_at: receipt.received_at,
    source: 'browser-session',
    client_kind: receipt.sample?.platform?.client_kind || null,
    kind: 'active',
    actual: receipt.sample || null,
    status: 'OBSERVED',
    proof_scope: result.proof_scope || 'simulation',
  };
  const observations = [...(result.observations || []).filter((item) => item.evidence_ref !== receipt.receipt_ref), observation];
  // 回传进来后按扫描时留下的期望重算：浏览器证据要进问题与评分，不只是挂一条观测。
  const expected = result.expected_context || {A: result.expected_exits?.A || null, B: result.expected_exits?.B || null, timezone: null, utc_offset_minutes: null};
  const browserIssues = issuesFromBrowserSample(observation, {expected, task_id: receipt.task_ref});
  const scoring = scoreNetwork([...(result.issues || []), ...browserIssues], {
    keyChecks: (result.scoring?.missing_key_checks || []).map((checkId) => ({check_id: checkId, required: true, status: 'MISSING'})),
  });
  const scoped = result.mode === 'special';
  const next = {
    ...result,
    observations,
    issues: scoring.unique_issues,
    scoring: scoped ? {...scoring, score: null, status: 'SCOPED', scoped_score: scoring.score, full_environment_score: false} : scoring,
    status: ['CANCELLED', 'SCOPED'].includes(result.status) ? result.status : scoring.status,
  };
  store.saveRecord('diagnostic_result', receipt.task_ref, next);
  persistDiagnosticReport(store, next);
  return next;
}
