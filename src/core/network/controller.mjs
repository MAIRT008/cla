import {AUTH_KIND, RECORD} from './constants.mjs';
import {explainRecommendation, validateAssignment} from './assignment.mjs';
import {applyNetworkPlan, restoreNetworkPlan, stateId} from './apply.mjs';
import {compileNetworkPlan, explainModeChange, publicPlanView} from './compile.mjs';
import {endEmergencyAccess, requestEmergencyAccess} from './emergency.mjs';
import {fail} from './errors.mjs';
import {advanceLifecycle, executeLifecycle} from './lifecycle.mjs';
import {consumeLiveNetwork, observeNetworkEvidence} from './observe.mjs';
import {flushEventOutbox, handleProtectionEvent} from './protection.mjs';
import {readNetworkState} from './state.mjs';
import {isExpired, nowIso} from './time.mjs';
import {emptyWhitelist, mutateWhitelist} from './whitelist.mjs';
import {approvedProtectionScope} from './protectedProcesses.mjs';

function protectionStateOf(assignment, state) {
  const scope = approvedProtectionScope(assignment, state);
  return {protected_process_paths: scope.processes, loopback_policy: scope.loopback_policy};
}

function whitelistId(userRef) {
  return `whitelist:${userRef}`;
}

export function createNetworkController(dependencies = {}) {
  const store = dependencies.store;
  const ports = {
    store,
    control: dependencies.control,
    core: dependencies.core,
    protection: dependencies.protection,
    verify: dependencies.verify,
    emergencyHost: dependencies.emergencyHost,
    events: dependencies.events,
    clock: dependencies.clock,
    secrets: dependencies.secrets,
  };
  let ordinary = Promise.resolve();
  function runOrdinary(work) {
    const run = ordinary.then(work, work);
    ordinary = run.catch(() => {});
    return run;
  }

  async function assignmentFor(userRef, environmentRef) {
    const loaded = await ports.control.getAssignment(userRef);
    const assignment = loaded.assignment;
    if (!assignment) throw fail('ASSIGNMENT_INVALID', 'no assignment is recorded for this user');
    const validation = validateAssignment(assignment, {environment_ref: environmentRef}, nowIso(ports.clock));
    return {assignment, validation, control_offline: loaded.code === 'CONTROL_OFFLINE', stale: loaded.stale === true};
  }

  function whitelistFor(userRef) {
    return store.getRecord(whitelistId(userRef), RECORD.WHITELIST) || emptyWhitelist({userRef});
  }

  async function quotaFor(userRef) {
    const loaded = await ports.control.getQuotaSnapshot(userRef);
    const snapshot = loaded.snapshot || {user_ref: userRef, status: 'UNKNOWN', authority_status: 'UNKNOWN', node_new_limit_judgment: 'UNKNOWN'};
    if (snapshot.authority_status !== 'AVAILABLE') snapshot.node_new_limit_judgment = 'UNAVAILABLE';
    return snapshot;
  }

  async function closeEmergency(request) {
    const session = store.getRecord(request.session_id, RECORD.EMERGENCY);
    const userRef = session?.user_ref || request.user_ref || request.userRef;
    const loaded = await assignmentFor(userRef, session?.environment_ref || request.environment_ref);
    const quotaSnapshot = await quotaFor(userRef);
    return endEmergencyAccess({
      ...request,
      assignment: loaded.assignment,
      whitelist: request.whitelist || whitelistFor(userRef),
      quotaSnapshot,
      mode: request.mode || session?.mode,
    }, ports);
  }

  /** 到期驱动：常规读取与实时观测先清扫过期会话，关闭不依赖用户再点一次结束。 */
  async function sweepEmergency() {
    const now = nowIso(ports.clock);
    const closed = [];
    for (const session of store.listRecords?.(RECORD.EMERGENCY) || []) {
      if (!session?.session_id || session.open === false || session.ended_at) continue;
      if (!isExpired(session.expires_at, now)) continue;
      try {
        closed.push(await closeEmergency({session_id: session.session_id, reason: 'EXPIRED'}));
      } catch (error) {
        const stored = store.getRecord(session.session_id, RECORD.EMERGENCY) || {...session};
        stored.expire_error = error.code || 'EMERGENCY_EXPIRE_FAILED';
        store.saveRecord(RECORD.EMERGENCY, session.session_id, stored);
        closed.push(stored);
      }
    }
    return closed;
  }

  async function preview({userRef, environmentRef, mode, capabilities, emergencyAccess}) {
    const {assignment, validation} = await assignmentFor(userRef, environmentRef);
    const whitelist = whitelistFor(userRef);
    const quotaSnapshot = await quotaFor(userRef);
    const plan = compileNetworkPlan({assignment, mode, whitelist, capabilities, emergencyAccess, quotaSnapshot, environmentScope: {environment_ref: environmentRef}, now: ports.clock});
    const current = store.getRecord(stateId({user_ref: userRef, environment_ref: environmentRef}), RECORD.STATE);
    const currentPlan = current?.expected ? {mode: current.mode, matrix: current.expected.matrix, whitelist: {active: current.mode === 'daily_single_ip'}, config: {tun: {enable: current.expected?.comparable?.tun?.enable}}} : null;
    return {
      validation,
      recommendation: explainRecommendation(assignment.account_class, assignment),
      change: explainModeChange(currentPlan, plan),
      plan: publicPlanView(plan),
      quota: plan.quota,
    };
  }

  async function confirmAndApply(request) {
    const loaded = await assignmentFor(request.userRef, request.environmentRef);
    if (request.assignment && request.assignment.user_ref !== request.userRef) {
      throw fail('ASSIGNMENT_USER_MISMATCH', 'caller cannot apply another user assignment');
    }
    const assignment = loaded.assignment;
    return runOrdinary(() => applyNetworkPlan({
      operation_id: request.operation_id,
      user_ref: request.userRef,
      environment_ref: request.environmentRef,
      assignment,
      mode: request.mode,
      whitelist: request.whitelist || whitelistFor(request.userRef),
      capabilities: request.capabilities,
      emergencyAccess: request.emergencyAccess,
      quotaSnapshot: request.quotaSnapshot,
      authorization: request.authorization,
      source: request.source || 'user',
      verify: request.verify,
      verify_checks: request.verify_checks,
      sensitive_change: request.sensitive_change,
      assignment_version: assignment.assignment_version,
      plan_version: request.plan_version,
    }, ports));
  }

  return {
    async getAssignment(userRef, environmentRef) {
      return assignmentFor(userRef, environmentRef);
    },
    getWhitelist(userRef) {
      return whitelistFor(userRef);
    },
    async previewModeChange(input) {
      return preview(input);
    },
    async previewWhitelistChange({userRef, action, payload, mode}) {
      const current = whitelistFor(userRef);
      const mutated = mutateWhitelist(current, action, payload, {mode});
      return mutated;
    },
    async updateWhitelist({userRef, action, payload, mode, authorization, environmentRef, assignment, capabilities, operation_id}) {
      const mutated = mutateWhitelist(whitelistFor(userRef), action, payload, {mode});
      if (!mutated.ok) return mutated;
      store.saveRecord(RECORD.WHITELIST, whitelistId(userRef), mutated.whitelist);
      if (mode && authorization) {
        const quotaSnapshot = await quotaFor(userRef);
        const applied = await confirmAndApply({
          operation_id: operation_id || `${authorization.authorization_ref || 'wl'}:${mutated.whitelist.version}`,
          userRef,
          environmentRef,
          mode,
          whitelist: mutated.whitelist,
          capabilities,
          quotaSnapshot,
          authorization: {...authorization, sensitive_change: false},
          source: 'whitelist',
        });
        return {...mutated, apply: applied};
      }
      return mutated;
    },
    async confirmAndApply(request) {
      if (!request.quotaSnapshot) request = {...request, quotaSnapshot: await quotaFor(request.userRef)};
      if (!request.whitelist) request = {...request, whitelist: whitelistFor(request.userRef)};
      return confirmAndApply(request);
    },
    async restore(request) {
      const loaded = await assignmentFor(request.userRef, request.environmentRef);
      const quotaSnapshot = request.quotaSnapshot || await quotaFor(request.userRef);
      return runOrdinary(() => restoreNetworkPlan({
        operation_id: request.operation_id,
        user_ref: request.userRef,
        environment_ref: request.environmentRef,
        restore_ref: request.restore_ref,
        assignment: loaded.assignment,
        current_assignment: loaded.assignment,
        authorization: request.authorization,
        quotaSnapshot,
        whitelist: request.whitelist || whitelistFor(request.userRef),
        mode: request.mode,
        detect_external: request.detect_external,
        external_modified: request.external_modified,
      }, ports));
    },
    sweepEmergency,
    async readState(request) {
      await sweepEmergency();
      const quotaSnapshot = request.quotaSnapshot || await quotaFor(request.userRef || request.user_ref);
      return readNetworkState({...request, user_ref: request.userRef || request.user_ref, environment_ref: request.environmentRef || request.environment_ref, quotaSnapshot}, ports);
    },
    async requestEmergency(request) {
      const userRef = request.user_ref || request.userRef;
      const loaded = await assignmentFor(userRef, request.environment_ref || request.environmentRef);
      const quotaSnapshot = request.quotaSnapshot || await quotaFor(userRef);
      return requestEmergencyAccess({
        ...request,
        assignment: loaded.assignment,
        quotaSnapshot,
        whitelist: request.whitelist || whitelistFor(userRef),
      }, ports);
    },
    endEmergency: closeEmergency,
    observe(state, observation) {
      return observeNetworkEvidence(state, observation, ports);
    },
    async observeLive(state, options = {}) {
      await sweepEmergency();
      const userRef = state?.user_ref || state?.userRef;
      let assignment = null;
      // 只分类不保护时用不到分配：每秒一次的读取不去控制端查分配，保护时再查。
      try {
        if (userRef && options.protect !== false) assignment = (await assignmentFor(userRef, state.environment_ref || state.environmentRef)).assignment;
      } catch {
        assignment = null;
      }
      return consumeLiveNetwork({...state, user_ref: userRef, ...protectionStateOf(assignment, state)}, ports, options);
    },
    async observeAndProtect(state, observation) {
      const observed = observation
        ? observeNetworkEvidence(state, observation, ports)
        : await consumeLiveNetwork(state, ports);
      const protections = [];
      for (const event of observed.events || observed.observed?.events || []) {
        if (event.live && (event.classification === 'WRONG_ROUTE' || event.kind === 'PROTECTION_FAILED')) {
          protections.push(await handleProtectionEvent(state, event, ports));
        }
      }
      return {...(observed.observed ? observed : {observed, events: observed.events}), protections};
    },
    async handleProtection(state, event) {
      const userRef = state?.user_ref || event?.user_ref;
      let assignment = null;
      try {
        if (userRef) assignment = (await assignmentFor(userRef, state?.environment_ref || event?.environment_ref)).assignment;
      } catch {
        assignment = null;
      }
      return handleProtectionEvent({...state, user_ref: userRef, ...protectionStateOf(assignment, state)}, event, ports);
    },
    /** 本地待报的保护事件按同一引用补报；读出事件记录给日报与界面，不改其中的事实。 */
    flushEvents(options) {
      return flushEventOutbox(ports, options);
    },
    listIncidents() {
      return (store?.listRecords?.(RECORD.INCIDENT) || []).map((incident) => ({...incident}));
    },
    listEventOutbox() {
      return (store?.listRecords?.(RECORD.EVENT) || []).map((item) => ({...item}));
    },
    advanceLifecycle(state, event) {
      return advanceLifecycle(state, event, ports);
    },
    async executeLifecycle(state, event) {
      let assignment = null;
      try {
        if (state.user_ref) assignment = (await assignmentFor(state.user_ref, state.environment_ref)).assignment;
      } catch {
        assignment = null;
      }
      return executeLifecycle({...state, ...protectionStateOf(assignment, state)}, event, {
        ...ports,
        restore: async () => restoreNetworkPlan({
          operation_id: `lifecycle-restore-${nowIso(ports.clock)}`,
          user_ref: state.user_ref,
          environment_ref: state.environment_ref,
          restore_ref: state.restore_ref,
          assignment: (await assignmentFor(state.user_ref, state.environment_ref)).assignment,
          current_assignment: (await assignmentFor(state.user_ref, state.environment_ref)).assignment,
          authorization: event.authorization,
          quotaSnapshot: await quotaFor(state.user_ref),
          mode: state.mode,
          whitelist: whitelistFor(state.user_ref),
        }, ports),
      });
    },
    async applyNetworkPlan(input) {
      if (input?.plan?.plan_id && !input.assignment) {
        const plan = input.plan;
        if (!['apply_current', 'restore_last_valid'].includes(plan.action_id) && !String(plan.action_id).startsWith('apply_mode:')) {
          return {status: 'UNSUPPORTED', applied: false, verified: false, reason: 'AI_NETWORK_ACTION_UNSUPPORTED'};
        }
        const userRef = plan.user_ref || input.user_ref;
        const environmentRef = plan.environment_ref;
        const loaded = await assignmentFor(userRef, environmentRef);
        const mode = String(plan.action_id).startsWith('apply_mode:') ? plan.action_id.slice('apply_mode:'.length) : plan.mode || 'daily_single_ip';
        const receipt = await confirmAndApply({
          operation_id: input.operation_id || `${plan.plan_id}:${plan.version}`,
          userRef,
          environmentRef,
          assignment: loaded.assignment,
          mode,
          capabilities: plan.capabilities,
          authorization: {
            kind: AUTH_KIND.ONCE,
            user_ref: userRef,
            environment_ref: environmentRef,
            plan_version: plan.version,
            authorization_ref: input.confirmation_id || plan.plan_id,
            allow_verify: true,
          },
          source: 'ai_confirmed',
        });
        return {
          status: receipt.overall,
          applied: ['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED', 'RESTORED'].includes(receipt.overall),
          applied_version: receipt.expected?.plan_version || null,
          verified: receipt.overall === 'APPLIED_VERIFIED',
          verified_version: receipt.overall === 'APPLIED_VERIFIED' ? receipt.expected?.plan_version : null,
          receipt,
        };
      }
      return applyNetworkPlan(input, ports);
    },
    asAiPort(userRef) {
      return {
        applyNetworkPlan: ({plan}) => this.applyNetworkPlan({plan: {...plan, user_ref: userRef}, user_ref: userRef}),
        recheckNetworkPlan: ({plan}) => this.recheckNetworkPlan({plan: {...plan, user_ref: userRef}}),
      };
    },
    async recheckNetworkPlan({plan} = {}) {
      const state = await readNetworkState({user_ref: plan?.user_ref, environment_ref: plan?.environment_ref}, ports);
      return {
        status: state.verified?.status === 'VERIFIED' || state.verified?.status === 'APPLIED_VERIFIED' ? 'VERIFIED' : 'VERIFIED_FAILED',
        applied_version: state.expected?.plan_version || null,
        verified: state.verified?.status === 'VERIFIED',
        verified_version: state.verified?.status === 'VERIFIED' ? state.expected?.plan_version : null,
        reason: state.verified?.reason || state.loaded?.inconsistencies?.join(',') || 'RECHECK',
      };
    },
  };
}
