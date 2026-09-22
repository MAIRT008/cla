import {acceptBrowserReport, createBrowserSession, mergeBrowserReceiptIntoResult} from './session.mjs';
import {scan} from './scan.mjs';
import {buildDiagnosticPlan, confirmDiagnosticPlan, executeConfirmedDiagnosticPlan, previewRestore, recheckDiagnosticAction, restoreDiagnostic} from './plans.mjs';
import {diagnosticSummaryForAudit, persistDiagnosticReport, redactDiagnostic, renderDiagnosticMarkdown, toDiagnosticView} from './reports.mjs';

/**
 * 每个声明环境有自己的探测端口与被测对象：换环境要换真实探测目标，不是只换标签。
 * 声明了分环境端口却没有该环境的，按未接入报错，不拿主机探测冒充客体结果。
 */
function environmentScope(deps, environmentRef) {
  const configured = deps.environmentPorts;
  if (!configured || !environmentRef) return {};
  const scoped = typeof configured === 'function' ? configured(environmentRef) : configured[environmentRef];
  if (!scoped) {
    throw Object.assign(
      new Error(`no probe ports are attached for environment ${environmentRef}`),
      {code: 'ENVIRONMENT_PROBE_UNAVAILABLE', environment_ref: environmentRef},
    );
  }
  return {
    ports: scoped.ports || deps.ports,
    world: scoped.world || deps.world,
    assignment: scoped.assignment || deps.assignment,
  };
}

export function createDiagnosticsController(deps = {}) {
  const store = deps.store;
  const inflight = new Map();
  /** 计划改的是它所属扫描那个环境：按计划记录的环境取端口；那个环境没有端口就没有设置端口，动作如实记 PORT_UNAVAILABLE。 */
  function portsForPlan(planId) {
    const plan = store.getRecord(planId, 'diagnostic_plan');
    try {
      return environmentScope(deps, plan?.environment_ref || deps.environmentRef).ports || deps.ports || null;
    } catch {
      return null;
    }
  }
  return {
    async startScan(input = {}) {
      const parent = input.signal;
      const ac = new AbortController();
      if (parent?.aborted) ac.abort();
      else parent?.addEventListener?.('abort', () => ac.abort(), {once: true});
      const {expected: _ignored, signal: _signal, assignment: _callerAssignment, ...rest} = input;
      const scoped = environmentScope(deps, rest.environmentRef || deps.environmentRef);
      return scan({
        ...deps,
        ...rest,
        ...scoped,
        store,
        assignment: scoped.assignment || deps.assignment,
        signal: ac.signal,
        onTask: (taskId) => inflight.set(taskId, ac),
      }).finally(() => {
        for (const [id, controller] of inflight) if (controller === ac) inflight.delete(id);
      });
    },
    async cancel(taskId) {
      inflight.get(taskId)?.abort();
      const result = store.getRecord(taskId, 'diagnostic_result') || store.getRecord(taskId, 'diagnostic_task');
      if (!result) throw Object.assign(new Error('task missing'), {code: 'TASK_NOT_FOUND'});
      const next = {...result, status: 'CANCELLED', cancelled: true};
      store.saveRecord('diagnostic_task', taskId, next);
      if (store.getRecord(taskId, 'diagnostic_result')) store.saveRecord('diagnostic_result', taskId, next);
      return next;
    },
    createSession(input) {
      return createBrowserSession({store, clock: deps.clock, ...input});
    },
    acceptReport(request) {
      const accepted = acceptBrowserReport({store, clock: deps.clock, request});
      if (accepted.ok && accepted.receipt_ref) mergeBrowserReceiptIntoResult(store, accepted.receipt_ref);
      return accepted;
    },
    view(taskId) {
      const result = store.getRecord(taskId, 'diagnostic_result');
      return result ? toDiagnosticView(result) : null;
    },
    result(taskId) {
      return store.getRecord(taskId, 'diagnostic_result');
    },
    plan(planId) {
      return store.getRecord(planId, 'diagnostic_plan');
    },
    buildPlan(taskId, supportedActions) {
      const result = store.getRecord(taskId, 'diagnostic_result');
      return buildDiagnosticPlan({result, store, clock: deps.clock, supportedActions: supportedActions || deps.supportedActions || []});
    },
    confirm(planId, actionIds, confirmationId) {
      return confirmDiagnosticPlan({store, planId, actionIds, confirmationId});
    },
    async execute(planId, extra = {}) {
      return executeConfirmedDiagnosticPlan({store, planId, ports: portsForPlan(planId), network: extra.network || deps.network, clock: deps.clock, ...extra});
    },
    async recheck(planId, actionId, rescan) {
      return recheckDiagnosticAction({store, planId, actionId, rescan});
    },
    previewRestore(planId) {
      return previewRestore({store, planId});
    },
    async restore(planId, confirmed, conflicts) {
      return restoreDiagnostic({store, planId, ports: portsForPlan(planId), network: deps.network, confirmed, conflicts});
    },
    report(taskId) {
      const result = store.getRecord(taskId, 'diagnostic_result');
      return persistDiagnosticReport(store, result);
    },
    history() {
      return store.listRecords('diagnostic_result');
    },
    async drill(input = {}) {
      if (input.authorization?.confirmed !== true) throw Object.assign(new Error('drill requires explicit authorization'), {code: 'DRILL_UNAUTHORIZED'});
      if (!deps.network?.handleProtection) return {status: 'UNAVAILABLE', code: 'T5_PORT_MISSING', live_scan: false, restored_claim: false};
      const protection = await deps.network.handleProtection(input.state || {}, input.event || {classification: 'WRONG_ROUTE'});
      let restore = null;
      if (input.restore === true) {
        if (!deps.network.restore || !input.restore_request) {
          return {status: 'DRILLED', protection, restored_claim: false, restore: {status: 'UNAVAILABLE'}, live_scan: false};
        }
        restore = await deps.network.restore(input.restore_request);
      }
      const restoredClaim = Boolean(restore && restore.overall === 'APPLIED_VERIFIED');
      return {status: 'DRILLED', protection, restored_claim: restoredClaim, restore, live_scan: false};
    },
  };
}

export function createDiagnosticsService(deps) {
  return createDiagnosticsController(deps);
}
