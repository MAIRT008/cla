import {appendAiNote} from '../audit/dailyReport.mjs';
import {redactForModel, redactText, safeJson} from './evidence.mjs';

const CATALOGS = {
  cleanup: {
    version: 'cleanup-tools-v1',
    tools: ['DiscoverEnvironment', 'InspectObject', 'BuildActionPlan', 'ExecuteConfirmedPlan', 'RecheckAction'],
  },
  network_diagnosis: {
    version: 'network-diagnosis-tools-v1',
    tools: ['InspectNetworkEvidence', 'BuildNetworkPlan', 'ApplyNetworkPlan', 'RecheckNetworkPlan'],
  },
  daily_analysis: {
    version: 'daily-analysis-tools-v1',
    tools: ['ReadDailyFacts', 'SaveDailyAnalysis'],
  },
};

function definition(name, parameters, description) {
  return {type: 'function', function: {name, description, parameters: {type: 'object', additionalProperties: false, ...parameters}}};
}

export function catalogFor(taskType) {
  const catalog = CATALOGS[taskType];
  if (!catalog) throw Object.assign(new Error('unknown AI task type'), {code: 'AI_TASK_TYPE_INVALID'});
  const definitions = taskType === 'cleanup'
    ? [
      definition('DiscoverEnvironment', {required: ['scan_id'], properties: {scan_id: {type: 'string'}}}, 'Read already collected permitted scan evidence.'),
      definition('InspectObject', {required: ['scan_id', 'object_ref'], properties: {scan_id: {type: 'string'}, object_ref: {type: 'string'}}}, 'Inspect one discovered object only.'),
      definition('BuildActionPlan', {required: ['scan_id'], properties: {scan_id: {type: 'string'}, recommendation_ids: {type: 'array', items: {type: 'string'}}, proposal: {type: 'object'}}}, 'Build a program-validated plan; it does not confirm or execute it.'),
      definition('ExecuteConfirmedPlan', {required: ['plan_id', 'version', 'action_ids', 'operation_id'], properties: {plan_id: {type: 'string'}, version: {}, action_ids: {type: 'array', items: {type: 'string'}}, operation_id: {type: 'string'}}}, 'Execute only an already user-confirmed plan.'),
      definition('RecheckAction', {required: ['plan_id', 'action_id'], properties: {plan_id: {type: 'string'}, action_id: {type: 'string'}}}, 'Recheck one action of the current plan.'),
    ]
    : taskType === 'network_diagnosis'
      ? [
        definition('InspectNetworkEvidence', {required: ['port'], properties: {port: {enum: ['environment', 'profile', 'configuration', 'history', 'dns', 'exit']}}}, 'Read only a supplied finite diagnostic protocol port.'),
        definition('BuildNetworkPlan', {required: ['environment_ref', 'profile_ref', 'action_id', 'reason'], properties: {environment_ref: {type: 'string'}, profile_ref: {type: 'string'}, action_id: {type: 'string'}, reason: {type: 'string'}}}, 'Build one supported finite-port network plan without applying it.'),
        definition('ApplyNetworkPlan', {required: ['plan_id'], properties: {plan_id: {type: 'string'}}}, 'Apply only an already locally confirmed finite-port plan.'),
        definition('RecheckNetworkPlan', {required: ['plan_id'], properties: {plan_id: {type: 'string'}}}, 'Read finite-port recheck evidence after application.'),
      ]
      : [
        definition('ReadDailyFacts', {required: ['report_id'], properties: {report_id: {type: 'string'}}}, 'Read the already derived daily-report facts.'),
        definition('SaveDailyAnalysis', {required: ['fact_refs', 'analysis'], properties: {fact_refs: {type: 'array', items: {type: 'string'}}, analysis: {type: 'object'}}}, 'Save a fact-referenced independent daily-analysis note.'),
      ];
  return {...catalog, definitions};
}

function parseArguments(call) {
  try {
    const value = JSON.parse(call.function?.arguments || '{}');
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('arguments must be an object');
    return value;
  } catch {
    throw Object.assign(new Error('model tool arguments are invalid'), {code: 'AI_TOOL_ARGUMENTS_INVALID'});
  }
}

function reject(code, message) {
  throw Object.assign(new Error(message), {code});
}

function allowedName(taskType, name) {
  if (!catalogFor(taskType).tools.includes(name)) reject('AI_TOOL_NOT_ALLOWED', `tool ${name} is not allowed for this task`);
}

function networkSnapshot(plan) {
  return {plan_id: plan.plan_id, version: plan.version, action_id: plan.action_id, environment_ref: plan.environment_ref, profile_ref: plan.profile_ref, reason: plan.reason};
}

function sameNetworkPlan(left, right) {
  return Boolean(left && right) && ['plan_id', 'version', 'action_id', 'environment_ref', 'profile_ref', 'reason'].every((key) => left[key] === right[key]);
}

export async function executeClientTool({task, call, localService, localStore, auditStore, networkPort, diagnostics, signal}) {
  const name = call.function?.name;
  const args = parseArguments(call);
  allowedName(task.task_type, name);
  if (name === 'DiscoverEnvironment') {
    if (args.scan_id !== task.scan_id) reject('AI_TOOL_SCOPE_DENIED', 'scan is outside the current task');
    const scan = localStore.getRecord(task.scan_id, 'scan');
    if (!scan) reject('AI_SCAN_NOT_FOUND', 'scan record is unavailable');
    return {scan_id: task.scan_id, inspectable_object_refs: task.allowed_objects.map((item) => item.object_ref), object_types: task.allowed_objects.map((item) => ({object_ref: item.object_ref, kind: item.kind})), coverage: redactForModel(scan.coverage), status: 'PERMITTED_EVIDENCE_ONLY'};
  }
  if (name === 'InspectObject') {
    if (args.scan_id !== task.scan_id || !task.allowed_objects.some((item) => item.object_ref === args.object_ref)) reject('AI_TOOL_SCOPE_DENIED', 'object is outside discovered readable scope');
    const inspection = await localService.inspectObject({scanId: task.scan_id, objectRef: args.object_ref});
    task.inspected_object_refs = [...new Set([...task.inspected_object_refs, args.object_ref])];
    return {object_ref: args.object_ref, inspection: redactForModel(inspection)};
  }
  if (name === 'BuildActionPlan') {
    if (args.scan_id !== task.scan_id) reject('AI_TOOL_SCOPE_DENIED', 'scan is outside the current task');
    const classification = localService.classify({scanId: task.scan_id});
    const allowed = new Set(classification.recommendations.map((entry) => entry.recommendation_id));
    const requested = args.recommendation_ids || classification.recommendations.map((entry) => entry.recommendation_id);
    if (!Array.isArray(requested) || requested.some((id) => !allowed.has(id))) reject('AI_TOOL_SCOPE_DENIED', 'plan contains a recommendation outside the current classification');
    let proposalIds = [];
    if (args.proposal !== undefined) {
      const proposal = args.proposal;
      if (!proposal || typeof proposal !== 'object' || !task.inspected_object_refs.includes(proposal.object_ref) || !task.allowed_objects.some((item) => item.object_ref === proposal.object_ref) || !['json_remove', 'json_set'].includes(proposal.kind) || typeof proposal.field_path !== 'string' || !proposal.field_path || typeof proposal.identity_ref !== 'string' || !proposal.identity_ref || typeof proposal.reason !== 'string' || !proposal.reason) {
        reject('AI_TOOL_SCOPE_DENIED', 'proposal is not backed by an inspected permitted object');
      }
      const accepted = await localService.proposeJsonChange({scanId: task.scan_id, objectRef: proposal.object_ref, kind: proposal.kind, fieldPath: proposal.field_path, value: proposal.value, expectedValue: proposal.expected_value, identityRef: proposal.identity_ref, source: 'validated-plan-proposal', reason: proposal.reason});
      proposalIds = [accepted.proposal_id];
    }
    const plan = await localService.buildActionPlan({scanId: task.scan_id, recommendationIds: requested, proposalIds});
    task.plan_id = plan.plan_id;
    task.plan_version = plan.version;
    task.plan_action_ids = plan.actions.map((action) => action.action_id);
    task.status = 'AWAITING_CONFIRMATION';
    return {plan_id: plan.plan_id, version: plan.version, action_ids: task.plan_action_ids, action_count: task.plan_action_ids.length, status: 'AWAITING_LOCAL_USER_CONFIRMATION'};
  }
  if (name === 'ExecuteConfirmedPlan') {
    if (!task.confirmation_id) reject('AI_CONFIRMATION_REQUIRED', 'local user confirmation is required before execution');
    if (args.plan_id !== task.plan_id || args.version !== task.plan_version || args.operation_id !== task.operation_id || JSON.stringify(args.action_ids) !== JSON.stringify(task.confirmed_action_ids)) {
      reject('AI_CONFIRMATION_SCOPE_DENIED', 'execution does not match the confirmed plan');
    }
    const operation = await localService.executeConfirmedPlan({planId: task.plan_id, version: task.plan_version, operationId: task.operation_id, signal});
    task.status = operation.status;
    task.operation_status = operation.status;
    task.operation_receipts = (operation.receipts || []).map((receipt) => ({action_id: receipt.action_id, status: receipt.status, code: receipt.code || null, backup_ref: receipt.backup_ref || null}));
    if (operation.status !== 'completed') task.last_error = {code: 'LOCAL_OPERATION_PARTIAL', operation_id: operation.operation_id, status: operation.status};
    return {operation_id: operation.operation_id, status: operation.status, receipts: redactForModel(operation.receipts || [])};
  }
  if (name === 'RecheckAction') {
    if (args.plan_id !== task.plan_id || !task.confirmed_action_ids.includes(args.action_id)) reject('AI_TOOL_SCOPE_DENIED', 'recheck is outside the confirmed plan');
    return redactForModel(await localService.recheckAction({planId: args.plan_id, actionId: args.action_id}));
  }
  if (name === 'InspectNetworkEvidence') {
    if (diagnostics && task.network_facts?.diagnostic_task_id) {
      const result = diagnostics.result(task.network_facts.diagnostic_task_id);
      if (!result) return {status: 'MISSING_EVIDENCE', port: args.port};
      const mapped = {
        environment: {environment_ref: result.environment_ref, status: result.status},
        profile: {profile_ref: result.profile_ref},
        configuration: result.scoring,
        history: result.requests,
        dns: result.observations.filter((item) => item.check_id.startsWith('dns.')),
        exit: result.observations.filter((item) => item.check_id.startsWith('exit.')),
      };
      if (!(args.port in mapped) && !(args.port in (task.network_facts || {}))) return {status: 'MISSING_EVIDENCE', port: args.port};
      return redactForModel({port: args.port, evidence: mapped[args.port] ?? task.network_facts[args.port], diagnostic_task_id: result.task_id});
    }
    if (!task.network_facts || !(args.port in task.network_facts)) return {status: 'MISSING_EVIDENCE', port: args.port};
    return redactForModel({port: args.port, evidence: task.network_facts[args.port]});
  }
  if (name === 'BuildNetworkPlan') {
    const action = (task.network_facts?.supported_actions || []).find((item) => item.action_id === args.action_id && item.environment_ref === args.environment_ref && item.profile_ref === args.profile_ref && item.status === 'SUPPORTED');
    if (!action) reject('AI_NETWORK_ACTION_DENIED', 'network action is not supported by supplied finite evidence');
    const candidate = {action_id: args.action_id, environment_ref: args.environment_ref, profile_ref: args.profile_ref, reason: redactText(args.reason)};
    const existing = task.network_plan;
    if (existing && ['action_id', 'environment_ref', 'profile_ref', 'reason'].every((key) => existing[key] === candidate[key])) return existing;
    const version = (existing?.version || 0) + 1;
    task.network_plan = {plan_id: `network-plan-${task.task_id}-v${version}`, version, ...candidate, applied: false, verified: false, status: 'AWAITING_LOCAL_USER_CONFIRMATION'};
    task.network_confirmation_id = null;
    task.network_confirmation = null;
    task.network_apply_result = null;
    task.network_recheck_result = null;
    task.status = 'AWAITING_NETWORK_CONFIRMATION';
    return task.network_plan;
  }
  if (name === 'ApplyNetworkPlan') {
    const confirmation = task.network_confirmation;
    if (!task.network_plan || !task.network_confirmation_id || !confirmation || args.plan_id !== task.network_plan.plan_id || !sameNetworkPlan(confirmation, networkSnapshot(task.network_plan))) reject('AI_CONFIRMATION_REQUIRED', 'a matching local network confirmation is required before apply');
    if (task.network_apply_result) return redactForModel(task.network_apply_result);
    if (diagnostics && task.network_facts?.diagnostic_plan_id) {
      task.network_apply_result = await diagnostics.execute(task.network_facts.diagnostic_plan_id);
      task.network_plan = {...task.network_plan, applied: task.network_apply_result.status === 'EXECUTED', status: task.network_apply_result.status};
      return redactForModel(task.network_apply_result);
    }
    if (!networkPort?.applyNetworkPlan) reject('AI_NETWORK_PORT_UNAVAILABLE', 'network protocol port is not connected');
    task.network_apply_result = await networkPort.applyNetworkPlan({plan: task.network_plan});
    task.network_plan = {...task.network_plan, applied: task.network_apply_result.applied === true, applied_version: task.network_apply_result.applied_version || null, status: task.network_apply_result.status || 'APPLIED_UNKNOWN'};
    return redactForModel(task.network_apply_result);
  }
  if (name === 'RecheckNetworkPlan') {
    if (!task.network_plan || args.plan_id !== task.network_plan.plan_id) reject('AI_NETWORK_PORT_UNAVAILABLE', 'network recheck port is not connected');
    if (task.network_recheck_result) return redactForModel({applied: task.network_plan.applied, verified: task.network_plan.verified, recheck: task.network_recheck_result});
    if (diagnostics && task.network_facts?.diagnostic_plan_id) {
      const rescan = await diagnostics.startScan({mode: 'quick', previous: diagnostics.result(task.network_facts.diagnostic_task_id)});
      const actionId = task.network_plan.action_id;
      task.network_recheck_result = await diagnostics.recheck(task.network_facts.diagnostic_plan_id, actionId, rescan);
      task.network_plan = {...task.network_plan, verified: task.network_recheck_result.status === 'VERIFIED', status: task.network_recheck_result.status};
      return redactForModel({applied: task.network_plan.applied, verified: task.network_plan.verified, recheck: task.network_recheck_result});
    }
    if (!networkPort?.recheckNetworkPlan) reject('AI_NETWORK_PORT_UNAVAILABLE', 'network recheck port is not connected');
    const recheck = await networkPort.recheckNetworkPlan({plan: task.network_plan});
    task.network_plan = {...task.network_plan, verified: recheck.verified === true, verified_version: recheck.verified_version || null, status: recheck.status || 'VERIFY_UNKNOWN'};
    task.network_recheck_result = recheck;
    return redactForModel({applied: task.network_plan.applied, verified: task.network_plan.verified, recheck});
  }
  if (name === 'ReadDailyFacts') {
    if (args.report_id !== task.report_id) reject('AI_TOOL_SCOPE_DENIED', 'report is outside the daily task');
    return task.daily_facts;
  }
  if (name === 'SaveDailyAnalysis') {
    if (!Array.isArray(args.fact_refs) || args.fact_refs.some((ref) => !task.allowed_fact_refs.includes(ref))) reject('AI_FACT_REF_INVALID', 'analysis contains an unknown fact reference');
    const analysis = redactForModel(args.analysis);
    const note = await appendAiNote({
      reportId: task.report_id,
      status: 'ANALYSIS_COMPLETE',
      reason: 'AI_DAILY_ANALYSIS',
      promptVersion: task.prompt_version,
      modelPolicyVersion: task.model_policy_version,
      fact_refs: args.fact_refs,
      analysis,
    }, {}, auditStore);
    task.note_ref = `${task.report_id}:${note.createdAt}`;
    return {status: 'ANALYSIS_NOTE_SAVED', report_id: task.report_id, fact_refs: args.fact_refs, note_ref: task.note_ref};
  }
  reject('AI_TOOL_NOT_ALLOWED', 'tool is not implemented');
}

export function toolResultMessage(call, result) {
  return {role: 'tool', tool_call_id: call.id, content: safeJson(result)};
}
