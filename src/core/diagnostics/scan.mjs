import {MODES, PROOF_SIMULATION} from './constants.mjs';
import {expectedFromAssignment} from './assignmentExpected.mjs';
import {checksFor, collectCategory} from './evidence.mjs';
import {issuesFromObservations, scoreNetwork} from './rules.mjs';

function iso(clock) {
  const value = typeof clock === 'function' ? clock() : Date.now();
  return typeof value === 'string' ? value : new Date(value).toISOString();
}

function id(prefix, clock) {
  return `${prefix}-${String(iso(clock)).replace(/[:.]/g, '')}-${Math.random().toString(16).slice(2, 8)}`;
}

function attachBrowserReceipts(store, taskId, observations, observedAt, environmentRef, profileRef) {
  const receipts = (store.listRecords?.('browser_receipt') || []).filter((item) => item.task_ref === taskId);
  for (const receipt of receipts) {
    observations.push({
      task_id: taskId,
      check_id: 'browser.session-sample',
      evidence_ref: receipt.receipt_ref,
      environment_ref: environmentRef,
      profile_ref: profileRef || receipt.profile_ref || null,
      observed_at: receipt.received_at || observedAt,
      source: 'browser-session',
      kind: 'active',
      actual: receipt.sample || null,
      status: 'OBSERVED',
      proof_scope: PROOF_SIMULATION,
    });
  }
  return receipts;
}

function retainQuickIssues(previous, freshIssues, observations) {
  const issues = [...freshIssues];
  if (!previous?.issues) return issues;
  const freshChecks = new Set(observations.filter((item) => !item.stale).map((item) => item.check_id));
  for (const issue of previous.issues) {
    if (issue.closed) continue;
    if (issues.some((item) => item.root_cause_id === issue.root_cause_id || item.kind === issue.kind)) continue;
    const untouched = (issue.evidence_refs || []).some((ref) => {
      const obs = (previous.observations || []).find((item) => item.evidence_ref === ref);
      return obs && !freshChecks.has(obs.check_id);
    });
    if (untouched) issues.push({...issue, retained: true});
  }
  return issues;
}

/** 覆盖按本次真实采到的证据判定，不按扫描请求上的环境标签。 */
export function environmentCoverage(declared, environmentRef, observations = []) {
  const list = Array.isArray(declared) ? declared : [];
  const fresh = (Array.isArray(observations) ? observations : []).filter((item) => !item?.stale);
  return list.map((item) => {
    const ref = item?.environment_ref || null;
    const evidence = fresh.filter((observation) => observation?.environment_ref === ref);
    const measured = Boolean(ref) && evidence.length > 0;
    return {
      environment_ref: ref,
      kind: item?.kind || 'unknown',
      measured,
      status: measured ? 'MEASURED' : 'NOT_MEASURED',
      evidence_count: evidence.length,
      evidence_refs: evidence.slice(0, 3).map((observation) => observation.evidence_ref),
      reason: measured
        ? null
        : ref === environmentRef ? 'NO_EVIDENCE_COLLECTED_FOR_THIS_ENVIRONMENT' : item?.reason || 'NOT_SELECTED_FOR_THIS_SCAN',
    };
  });
}

export async function scan({mode = 'deep', scope, signal, store, ports, assignment, clock, environmentRef, clientRef, profileRef, previous, environments, onTask}) {
  if (!MODES.includes(mode)) throw Object.assign(new Error(`mode ${mode} is unknown`), {code: 'MODE_UNKNOWN'});
  const expected = expectedFromAssignment(assignment);
  const categories = checksFor(mode, scope?.categories);
  const taskId = id('diag', clock);
  const started = iso(clock);
  const requests = [];
  const observations = [];
  const keyChecks = [];
  const completed = [];
  store.saveRecord('diagnostic_task', taskId, {task_id: taskId, mode, status: 'RUNNING', started_at: started, environment_ref: environmentRef, proof_scope: PROOF_SIMULATION});
  onTask?.(taskId);
  try {
    for (const category of categories) {
      if (signal?.aborted) break;
      try {
        const part = await collectCategory(category, {
          ports, assignment, expected, clock, requests, signal,
          task_id: taskId, environment_ref: environmentRef, client_ref: clientRef, profile_ref: profileRef,
        });
        observations.push(...(part.observations || []));
        keyChecks.push(...(part.keyChecks || []));
        completed.push(category);
      } catch (error) {
        if (error.code === 'CANCELLED' || signal?.aborted) throw Object.assign(error, {code: 'CANCELLED'});
        observations.push({
          task_id: taskId,
          check_id: `${category}.error`,
          evidence_ref: `${taskId}:${category}:error`,
          environment_ref: environmentRef,
          observed_at: iso(clock),
          source: category,
          kind: 'active',
          actual: {error: error.code || error.message},
          status: 'REQUEST_FAILED',
          limitation: error.code || 'CATEGORY_ERROR',
          proof_scope: PROOF_SIMULATION,
        });
        completed.push(category);
      }
    }
  } catch (error) {
    if (error.code !== 'CANCELLED') throw error;
  }
  if (mode === 'quick' && previous?.observations) {
    for (const old of previous.observations) {
      if (!observations.some((item) => item.check_id === old.check_id)) {
        observations.push({...old, stale: true, retained_from: old.observed_at});
      }
    }
  }
  attachBrowserReceipts(store, taskId, observations, iso(clock), environmentRef, profileRef);
  const prior = store.getRecord(taskId, 'diagnostic_task');
  const cancelled = Boolean(signal?.aborted || prior?.status === 'CANCELLED');
  let freshIssues = issuesFromObservations(observations, {expected, task_id: taskId});
  if (mode === 'quick') freshIssues = retainQuickIssues(previous, freshIssues, observations);
  const scoring = scoreNetwork(freshIssues, {keyChecks});
  const scoped = mode === 'special';
  const result = {
    task_id: taskId,
    mode,
    environment_ref: environmentRef,
    environment_coverage: environmentCoverage(environments, environmentRef, observations),
    whole_machine_claim: false,
    client_ref: clientRef || null,
    profile_ref: profileRef || null,
    assignment_version: assignment?.assignment_version || null,
    expected_source: expected.source,
    expected_exits: {A: expected.A, B: expected.B},
    // 浏览器回传可能在扫描之后才到：把判定要用的期望一起留下，回传进来时按同一期望重算。
    expected_context: {A: expected.A, B: expected.B, timezone: expected.timezone, utc_offset_minutes: expected.utc_offset_minutes},
    started_at: started,
    finished_at: iso(clock),
    status: cancelled ? 'CANCELLED' : scoped ? 'SCOPED' : scoring.status,
    categories_requested: categories,
    categories_completed: completed,
    observations,
    issues: scoring.unique_issues,
    scoring: scoped
      ? {...scoring, score: null, status: 'SCOPED', scoped_score: scoring.score, full_environment_score: false}
      : scoring,
    requests,
    proof_scope: PROOF_SIMULATION,
    cancelled,
  };
  store.saveRecord('diagnostic_task', taskId, result);
  store.saveRecord('diagnostic_result', taskId, result);
  return result;
}
