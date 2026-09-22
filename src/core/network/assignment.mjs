import {fail} from './errors.mjs';
import {MODES, RECOMMENDED_FOR} from './constants.mjs';
import {isExpired, nowIso} from './time.mjs';

function resourceOf(assignment, ref) {
  if (!ref) return null;
  return assignment.resources?.[ref] || assignment.resource_attributes?.[ref] || null;
}

function resourceStatus(resource, now) {
  if (!resource) return 'MISSING';
  if (resource.status && resource.status !== 'ACTIVE') return resource.status;
  if (isExpired(resource.expires_at, now)) return 'EXPIRED';
  return 'ACTIVE';
}

export function recommendMode(accountClass) {
  return RECOMMENDED_FOR[accountClass] || null;
}

export function explainRecommendation(accountClass, assignment) {
  const recommended = recommendMode(accountClass);
  const allowed = new Set(assignment?.allowed_modes || []);
  return {
    account_class: accountClass || null,
    recommended_mode: recommended,
    available: Boolean(recommended && allowed.has(recommended)),
    official_risk_claim: false,
    reason: recommended && !allowed.has(recommended)
      ? 'RECOMMENDED_MODE_NOT_ASSIGNED'
      : recommended
        ? 'RECOMMENDATION_ONLY'
        : 'NO_RECOMMENDATION',
  };
}

export function validateAssignment(assignment, environmentScope, nowInput) {
  const now = typeof nowInput === 'function' ? nowIso(nowInput) : nowInput || nowIso();
  const issues = [];
  if (!assignment || typeof assignment !== 'object') {
    return {ok: false, code: 'ASSIGNMENT_INVALID', reason: 'assignment is required', issues: ['MISSING_ASSIGNMENT']};
  }
  if (!assignment.user_ref) issues.push('MISSING_USER');
  if (!assignment.assignment_version) issues.push('MISSING_VERSION');
  if (assignment.status === 'REVOKED' || assignment.revoked === true) issues.push('REVOKED');
  if (isExpired(assignment.valid_until, now) || assignment.status === 'EXPIRED') issues.push('EXPIRED');
  if (assignment.valid_from && toFuture(assignment.valid_from, now)) issues.push('NOT_YET_VALID');
  const environment = environmentScope?.environment_ref || environmentScope;
  if (assignment.environment_ref && environment && assignment.environment_ref !== environment) issues.push('ENVIRONMENT_MISMATCH');
  const allowed = Array.isArray(assignment.allowed_modes) ? assignment.allowed_modes.filter((mode) => MODES.includes(mode)) : [];
  if (!allowed.length) issues.push('NO_ALLOWED_MODES');
  const exitA = resourceOf(assignment, assignment.roles?.A || assignment.resource_refs?.exit_a);
  const exitB = resourceOf(assignment, assignment.roles?.B || assignment.resource_refs?.exit_b);
  const front = resourceOf(assignment, assignment.resource_refs?.front);
  const aStatus = resourceStatus(exitA, now);
  const bStatus = resourceStatus(exitB, now);
  const frontStatus = front ? resourceStatus(front, now) : 'OPTIONAL';
  if (aStatus !== 'ACTIVE') issues.push('EXIT_A_UNAVAILABLE');
  if (front && frontStatus !== 'ACTIVE') issues.push('FRONT_UNAVAILABLE');
  const dualAllowed = allowed.includes('claude_dual_ip');
  if (dualAllowed && !exitB) issues.push('DUAL_IP_REQUIRES_B');
  if (dualAllowed && exitB && bStatus !== 'ACTIVE') issues.push('EXIT_B_UNAVAILABLE');
  const blocking = issues.filter((issue) => issue !== 'DUAL_IP_REQUIRES_B' && issue !== 'EXIT_B_UNAVAILABLE');
  const ok = blocking.length === 0;
  return {
    ok,
    code: !ok && issues.includes('REVOKED') ? 'ASSIGNMENT_REVOKED' : !ok && issues.includes('EXPIRED') ? 'ASSIGNMENT_EXPIRED' : !ok && issues.includes('EXIT_A_UNAVAILABLE') ? 'RESOURCE_UNAVAILABLE' : ok ? 'ASSIGNMENT_VALID' : 'ASSIGNMENT_INVALID',
    reason: ok ? 'assignment is usable' : issues.join(','),
    issues,
    user_ref: assignment.user_ref || null,
    environment_ref: assignment.environment_ref || environment || null,
    assignment_version: assignment.assignment_version || null,
    template_version: assignment.template_version || null,
    classification_version: assignment.classification_version || null,
    allowed_modes: allowed,
    dual_ip_ready: dualAllowed && aStatus === 'ACTIVE' && bStatus === 'ACTIVE',
    resources: {
      A: {ref: assignment.roles?.A || assignment.resource_refs?.exit_a || null, status: aStatus, sharing: exitA?.sharing || null, role: 'A'},
      B: {ref: assignment.roles?.B || assignment.resource_refs?.exit_b || null, status: exitB ? bStatus : 'MISSING', sharing: exitB?.sharing || null, role: 'B'},
      front: {ref: assignment.resource_refs?.front || null, status: front ? frontStatus : 'MISSING'},
    },
    observed_at: now,
  };
}

function toFuture(validFrom, now) {
  const start = Date.parse(validFrom);
  const current = Date.parse(now);
  return Number.isFinite(start) && Number.isFinite(current) && current < start;
}

export function assertModeAllowed(validation, mode) {
  if (!validation.ok) throw fail(validation.code, validation.reason, {issues: validation.issues});
  if (!MODES.includes(mode)) throw fail('MODE_NOT_ALLOWED', `mode ${mode} is unknown`);
  if (!validation.allowed_modes.includes(mode)) throw fail('MODE_NOT_ALLOWED', `mode ${mode} is not assigned`);
  if (mode === 'claude_dual_ip' && !validation.dual_ip_ready) throw fail('DUAL_IP_REQUIRES_B', 'dual IP requires an active B exit');
}
