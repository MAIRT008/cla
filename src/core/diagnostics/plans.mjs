import {SUGGESTION} from './constants.mjs';
import {suggestionFor} from './rules.mjs';

function iso(clock) {
  const value = typeof clock === 'function' ? clock() : Date.now();
  return typeof value === 'string' ? value : new Date(value).toISOString();
}

export function buildDiagnosticPlan({result, store, clock, supportedActions = []}) {
  const actions = [];
  for (const issue of result.issues || []) {
    if (issue.closed) continue;
    const suggestion = suggestionFor({...issue, supported: supportedActions.some((item) => item.issue_kind === issue.kind || item.root_cause_id === issue.root_cause_id)});
    const match = supportedActions.find((item) => item.issue_kind === issue.kind || item.root_cause_id === issue.root_cause_id);
    actions.push({
      action_id: `diag-act-${issue.issue_id}`,
      issue_id: issue.issue_id,
      root_cause_id: issue.root_cause_id,
      suggestion,
      kind: match?.kind || 'unsupported',
      target: match?.target || null,
      before: match?.before ?? null,
      after: match?.after ?? null,
      impact: match?.impact || 'none',
      backup: Boolean(match?.backup),
      recheck: match?.recheck || 'rescan-category',
      supported: Boolean(match),
      payload: match?.payload ? {...match.payload} : null,
      restore_payload: match?.restore_payload ? {...match.restore_payload} : null,
    });
  }
  const plan = {
    plan_id: `diag-plan-${result.task_id}`,
    version: 1,
    task_id: result.task_id,
    environment_ref: result.environment_ref,
    profile_ref: result.profile_ref,
    status: 'AWAITING_CONFIRMATION',
    created_at: iso(clock),
    actions,
    cards: actions.map((action) => ({
      action_id: action.action_id,
      issue_id: action.issue_id,
      suggestion: action.suggestion,
      current: action.before,
      target: action.after,
      impact: action.impact,
      restart: action.impact === 'restart',
      backup: action.backup,
    })),
  };
  store.saveRecord('diagnostic_plan', plan.plan_id, plan);
  return plan;
}

export function confirmDiagnosticPlan({store, planId, actionIds, confirmationId}) {
  const plan = store.getRecord(planId, 'diagnostic_plan');
  if (!plan) throw Object.assign(new Error('plan missing'), {code: 'PLAN_NOT_FOUND'});
  const allowed = new Set(plan.actions.map((item) => item.action_id));
  if (!actionIds?.length || actionIds.some((id) => !allowed.has(id))) throw Object.assign(new Error('action outside plan'), {code: 'OUT_OF_SCOPE'});
  const next = {
    ...plan,
    status: 'CONFIRMED',
    confirmation_id: confirmationId || `diag-confirm-${plan.plan_id}`,
    confirmed_action_ids: actionIds,
    confirmed_at: new Date().toISOString(),
  };
  store.saveRecord('diagnostic_plan', plan.plan_id, next);
  return next;
}

export async function executeConfirmedDiagnosticPlan({store, planId, ports, network, clock, signal, drift}) {
  const plan = store.getRecord(planId, 'diagnostic_plan');
  if (!plan?.confirmation_id) throw Object.assign(new Error('not confirmed'), {code: 'CONFIRMATION_REQUIRED'});
  const receipts = [];
  for (const actionId of plan.confirmed_action_ids) {
    if (signal?.aborted) break;
    const action = plan.actions.find((item) => item.action_id === actionId);
    if (drift?.has(actionId)) {
      receipts.push({action_id: actionId, status: 'PAUSED', code: 'DRIFT'});
      continue;
    }
    if (!action.supported) {
      receipts.push({action_id: actionId, status: 'UNSUPPORTED', code: 'NOT_SUPPORTED'});
      continue;
    }
    if (action.kind === 'apply_network' && network?.confirmAndApply) {
      if (!action.payload?.userRef || !action.payload?.mode || !action.payload?.authorization || !action.payload?.operation_id) {
        receipts.push({action_id: actionId, status: 'FAILED', code: 'PAYLOAD_INCOMPLETE'});
        continue;
      }
      const applied = await network.confirmAndApply(action.payload);
      const ok = applied && ['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED'].includes(applied.overall);
      const restoreRef = applied?.stages?.restore_saved?.restore_ref || applied?.restore_ref || null;
      receipts.push({
        action_id: actionId,
        status: applied?.overall === 'APPLIED_VERIFIED' ? 'APPLIED' : ok ? 'APPLIED_UNVERIFIED' : 'FAILED',
        overall: applied?.overall || null,
        loaded_version: applied?.loaded?.loaded_version || null,
        backup_ref: restoreRef,
      });
      continue;
    }
    if (action.kind === 'settings' && ports?.settings?.apply) {
      const before = await ports.settings.read?.(action.target);
      const applied = await ports.settings.apply(action.target, action.after);
      receipts.push({action_id: actionId, status: applied?.ok ? 'APPLIED' : 'FAILED', before, after: action.after, backup_ref: applied?.ok ? `diag-backup-${actionId}` : null});
      continue;
    }
    receipts.push({action_id: actionId, status: 'FAILED', code: 'PORT_UNAVAILABLE'});
  }
  const next = {...plan, status: receipts.every((item) => item.status === 'APPLIED') ? 'EXECUTED' : 'PARTIAL', receipts, executed_at: iso(clock)};
  store.saveRecord('diagnostic_plan', plan.plan_id, next);
  return next;
}

export async function recheckDiagnosticAction({store, planId, actionId, rescan}) {
  const plan = store.getRecord(planId, 'diagnostic_plan');
  const action = plan?.actions.find((item) => item.action_id === actionId);
  if (!action) throw Object.assign(new Error('action missing'), {code: 'ACTION_NOT_FOUND'});
  if (!rescan) {
    const receipt = {action_id: actionId, verified: false, remaining: true, status: 'UNVERIFIED', reason: 'NO_NEW_OBSERVATION'};
    store.saveRecord('diagnostic_recheck', `${planId}:${actionId}`, receipt);
    return receipt;
  }
  const still = (rescan.issues || []).some((issue) => !issue.closed && (issue.root_cause_id === action.root_cause_id || issue.kind === action.kind));
  const receipt = {
    action_id: actionId,
    verified: !still,
    remaining: still,
    status: still ? 'STILL_ABNORMAL' : 'VERIFIED',
  };
  store.saveRecord('diagnostic_recheck', `${planId}:${actionId}`, receipt);
  return receipt;
}

export function previewRestore({store, planId}) {
  const plan = store.getRecord(planId, 'diagnostic_plan');
  const items = (plan?.receipts || []).filter((item) => item.backup_ref).map((item) => ({
    action_id: item.action_id,
    backup_ref: item.backup_ref,
    before: plan.actions.find((action) => action.action_id === item.action_id)?.before ?? null,
  }));
  return {plan_id: planId, items, conflicts: []};
}

export async function restoreDiagnostic({store, planId, ports, network, confirmed, conflicts}) {
  if (!confirmed) throw Object.assign(new Error('restore requires confirmation'), {code: 'CONFIRMATION_REQUIRED'});
  const plan = store.getRecord(planId, 'diagnostic_plan');
  const preview = previewRestore({store, planId});
  if (conflicts?.length) return {status: 'CONFLICT', conflicts};
  const restored = [];
  for (const item of preview.items) {
    const action = plan.actions.find((entry) => entry.action_id === item.action_id);
    if (action?.kind === 'apply_network') {
      if (!network?.restore || !action.restore_payload?.userRef || !item.backup_ref) {
        restored.push({action_id: item.action_id, status: 'FAILED', code: 'RESTORE_PAYLOAD_INCOMPLETE'});
        continue;
      }
      const result = await network.restore({...action.restore_payload, restore_ref: item.backup_ref});
      const ok = result && result.overall === 'APPLIED_VERIFIED';
      restored.push({action_id: item.action_id, status: ok ? 'RESTORED' : 'FAILED', overall: result?.overall || null});
      continue;
    }
    if (action?.kind === 'settings' && ports?.settings?.apply) {
      const result = await ports.settings.apply(action.target, item.before);
      restored.push({action_id: item.action_id, status: result?.ok ? 'RESTORED' : 'FAILED'});
      continue;
    }
    restored.push({action_id: item.action_id, status: 'FAILED', code: 'PORT_UNAVAILABLE'});
  }
  const status = restored.length && restored.every((item) => item.status === 'RESTORED') ? 'RESTORED' : 'PARTIAL';
  const record = {plan_id: planId, status, restored, restored_at: iso(() => Date.now())};
  store.saveRecord('diagnostic_restore', planId, record);
  return record;
}
