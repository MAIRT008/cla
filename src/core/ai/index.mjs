import {cleanupEvidence, dailyEvidence, inspectableObjects, redactForModel, redactText} from './evidence.mjs';
import {CLEANUP_PROMPT, CLEANUP_PROMPT_VERSION} from './prompts/cleanup.mjs';
import {DAILY_PROMPT, DAILY_PROMPT_VERSION} from './prompts/daily.mjs';
import {NETWORK_PROMPT, NETWORK_PROMPT_VERSION} from './prompts/network.mjs';
import {createTask, loadTask, saveTask, taskSummary} from './session.mjs';
import {catalogFor, executeClientTool, toolResultMessage} from './tools.mjs';

const PROMPTS = {
  cleanup: {version: CLEANUP_PROMPT_VERSION, body: CLEANUP_PROMPT},
  network_diagnosis: {version: NETWORK_PROMPT_VERSION, body: NETWORK_PROMPT},
  daily_analysis: {version: DAILY_PROMPT_VERSION, body: DAILY_PROMPT},
};

function errorInfo(error) {
  return {code: error?.code || 'AI_TRANSPORT_UNKNOWN', status: error?.status || null, retryable: error?.code === 'AI_TRANSPORT_UNKNOWN'};
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
}

function toolFingerprint(call) {
  const text = JSON.stringify(canonicalize({name: call.function?.name, arguments: call.function?.arguments || '{}'}));
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) { hash ^= text.charCodeAt(index); hash = Math.imul(hash, 16777619); }
  return `fnv1a-${(hash >>> 0).toString(16)}`;
}

export function createAiClient({localService, localStore, auditStore, controlTransport, networkPort, diagnostics, budgets = {maxTurns: 8, maxToolCalls: 8, maxEvidenceBytes: 64000}} = {}) {
  if (!localService || !localStore || !auditStore || !controlTransport?.turn) throw new Error('local service, local store, audit store, and control transport are required');

  const activeRuns = new Map();
  function save(task) { saveTask(localStore, task); return task; }
  function mergeOperationFacts(task, operationId) {
    if (!operationId) return task;
    const operation = localService.getTask(operationId);
    if (!operation) return task;
    task.operation_id = operation.operation_id;
    task.operation_status = operation.status;
    task.operation_receipts = (operation.receipts || []).map((receipt) => ({
      action_id: receipt.action_id,
      status: receipt.status,
      code: receipt.code || null,
      backup_ref: receipt.backup_ref || null,
    }));
    return task;
  }

  async function run(task, {signal} = {}) {
    const controller = new AbortController();
    const abortFromCaller = () => controller.abort();
    if (signal?.aborted) controller.abort();
    else signal?.addEventListener?.('abort', abortFromCaller, {once: true});
    activeRuns.set(task.task_id, controller);
    try {
    if (controller.signal.aborted) {
      task.status = 'CANCELLED';
      task.last_error = {code: 'AI_ABORTED'};
      save(task);
      return taskSummary(task);
    }
    if (task.status === 'CANCELLED' || task.status === 'AWAITING_CONFIRMATION') return taskSummary(task);
    while (true) {
      if (task.turn_count >= budgets.maxTurns || task.tool_call_count >= budgets.maxToolCalls) {
        task.status = 'BUDGET_EXHAUSTED';
        task.last_error = {code: 'AI_BUDGET_EXHAUSTED'};
        save(task);
        return taskSummary(task);
      }
      const turnRef = task.pending_turn?.turn_ref || localStore.newId('ai-turn');
      task.pending_turn = {turn_ref: turnRef, message_count: task.messages.length};
      if (task.status !== 'AWAITING_MODEL_EXECUTION') task.status = 'REQUESTING_MODEL';
      save(task);
      let response;
      try {
        response = await controlTransport.turn({
          task_ref: task.task_ref,
          task_type: task.task_type,
          turn_ref: turnRef,
          prompt_version: task.prompt_version,
          prompt_body: PROMPTS[task.task_type].body,
          tool_catalog_version: task.tool_catalog_version,
          messages: task.messages,
        }, {signal: controller.signal});
      } catch (error) {
        const stored = loadTask(localStore, task.task_id);
        if (stored.status === 'CANCELLED') return taskSummary(stored);
        task = stored;
        task.status = controller.signal.aborted || error?.code === 'AI_ABORTED' ? 'CANCELLED' : error?.code === 'AI_TRANSPORT_UNKNOWN' ? 'REMOTE_RESPONSE_UNKNOWN' : 'MODEL_FAILED';
        task.last_error = errorInfo(error);
        save(task);
        return taskSummary(task);
      }
      const stored = loadTask(localStore, task.task_id);
      if (stored.status === 'CANCELLED' || controller.signal.aborted) {
        if (stored.status !== 'CANCELLED') {
          stored.status = 'CANCELLED';
          stored.last_error = {code: 'AI_ABORTED'};
          save(stored);
        }
        return taskSummary(stored);
      }
      task = stored;
      task.pending_turn = null;
      task.turn_count += 1;
      task.model_policy_version = response.model_policy_version;
      task.used_usage.push(response.usage || {status: 'UNKNOWN'});
      const assistant = {role: 'assistant', content: redactText(response.assistant?.content || ''), tool_calls: response.assistant?.tool_calls || []};
      task.messages.push(assistant);
      // Tool execution reloads the persisted task to observe cancellation. Persist the
      // assistant's tool calls first so the next model turn receives their history.
      save(task);
      if (!assistant.tool_calls.length) {
        if (task.operation_status && task.operation_status !== 'completed') {
          task.status = task.operation_status === 'cancelled' ? 'CANCELLED' : 'PARTIAL';
          task.last_error ||= {code: 'LOCAL_OPERATION_PARTIAL', operation_id: task.operation_id, status: task.operation_status};
        } else task.status = task.plan_id && !task.confirmation_id ? 'AWAITING_CONFIRMATION' : task.network_plan && !task.network_confirmation_id ? 'AWAITING_NETWORK_CONFIRMATION' : 'COMPLETED';
        save(task);
        return taskSummary(task);
      }
      for (const call of assistant.tool_calls) {
        task = loadTask(localStore, task.task_id);
        if (task.status === 'CANCELLED' || controller.signal.aborted) {
          if (task.status !== 'CANCELLED') {
            task.status = 'CANCELLED';
            task.last_error = {code: 'AI_ABORTED'};
            save(task);
          }
          return taskSummary(task);
        }
        if (task.tool_call_count >= budgets.maxToolCalls) {
          task.status = 'BUDGET_EXHAUSTED';
          task.last_error = {code: 'AI_TOOL_BUDGET_EXHAUSTED'};
          save(task);
          return taskSummary(task);
        }
        task.tool_call_count += 1;
        let result;
        const signature = toolFingerprint(call);
        const prior = task.tool_call_receipts.find((item) => item.tool_call_id === call.id);
        if (prior) {
          result = prior.signature === signature ? prior.result : {status: 'TOOL_REJECTED', code: 'AI_TOOL_REPLAY_MISMATCH', reason: 'tool identifier was reused with changed arguments'};
        } else {
          try {
            result = await executeClientTool({task, call, localService, localStore, auditStore, networkPort, diagnostics, signal: controller.signal});
          } catch (error) {
            result = {status: 'TOOL_REJECTED', code: error?.code || 'AI_TOOL_FAILED', reason: redactText(error?.message)};
          }
          const latest = loadTask(localStore, task.task_id);
          if (latest.status === 'CANCELLED' || controller.signal.aborted) {
            mergeOperationFacts(latest, task.operation_id);
            if (latest.status !== 'CANCELLED') {
              latest.status = 'CANCELLED';
              latest.last_error = {code: 'AI_ABORTED'};
            }
            save(latest);
            return taskSummary(latest);
          }
          task.tool_call_receipts.push({tool_call_id: call.id, signature, result: redactForModel(result)});
        }
        const toolMessage = toolResultMessage(call, result);
        task.evidence_bytes += new TextEncoder().encode(toolMessage.content).byteLength;
        if (task.evidence_bytes > budgets.maxEvidenceBytes) {
          task.status = 'BUDGET_EXHAUSTED';
          task.last_error = {code: 'AI_EVIDENCE_BUDGET_EXHAUSTED'};
          save(task);
          return taskSummary(task);
        }
        task.messages.push(toolMessage);
        save(task);
      }
    }
    } finally {
      signal?.removeEventListener?.('abort', abortFromCaller);
      if (activeRuns.get(task.task_id) === controller) activeRuns.delete(task.task_id);
    }
  }

  async function startCleanup({scanId, input = 'Inspect permitted evidence and prepare a cleanup plan.', signal} = {}) {
    const scan = localStore.getRecord(scanId, 'scan');
    if (!scan) throw Object.assign(new Error('scan record is required'), {code: 'AI_SCAN_NOT_FOUND'});
    const catalog = catalogFor('cleanup');
    const readable = inspectableObjects(scan);
    const task = createTask(localStore, {
      taskType: 'cleanup', promptVersion: CLEANUP_PROMPT_VERSION, toolCatalogVersion: catalog.version, scanId,
      allowedObjectRefs: readable.map((item) => item.object_ref), allowedObjects: readable, userInput: `${input}\n${JSON.stringify(cleanupEvidence(scan))}`,
    });
    save(task);
    return run(task, {signal});
  }

  async function startNetworkDiagnosis({networkFacts, diagnosticTaskId, input = 'Explain the available diagnostic evidence.', signal} = {}) {
    const catalog = catalogFor('network_diagnosis');
    let facts = networkFacts;
    if (diagnostics && !networkFacts) {
      const result = diagnosticTaskId ? diagnostics.result(diagnosticTaskId) : await diagnostics.startScan({mode: 'deep'});
      const plan = diagnostics.buildPlan(result.task_id);
      facts = {
        diagnostic_task_id: result.task_id,
        diagnostic_plan_id: plan.plan_id,
        environment: {environment_ref: result.environment_ref, status: result.status},
        profile: {profile_ref: result.profile_ref},
        configuration: result.scoring,
        history: result.requests,
        dns: result.observations.filter((item) => item.check_id.startsWith('dns.')),
        exit: result.observations.filter((item) => item.check_id.startsWith('exit.')),
        issues: result.issues,
        supported_actions: (plan.actions || []).filter((item) => item.supported).map((item) => ({
          action_id: item.action_id,
          environment_ref: result.environment_ref,
          profile_ref: result.profile_ref || 'Default',
          status: 'SUPPORTED',
        })),
      };
    }
    const task = createTask(localStore, {taskType: 'network_diagnosis', promptVersion: NETWORK_PROMPT_VERSION, toolCatalogVersion: catalog.version, networkFacts: redactForModel(facts), userInput: input});
    save(task);
    return run(task, {signal});
  }

  async function startDailyAnalysis({report, input = 'Analyze this daily report using factual citations only.', signal} = {}) {
    const facts = dailyEvidence(report);
    const catalog = catalogFor('daily_analysis');
    const task = createTask(localStore, {taskType: 'daily_analysis', promptVersion: DAILY_PROMPT_VERSION, toolCatalogVersion: catalog.version, reportId: report.reportId, dailyFacts: facts, allowedFactRefs: facts.fact_refs, userInput: `${input}\n${JSON.stringify(facts)}`});
    save(task);
    return run(task, {signal});
  }

  async function confirmCleanup({taskId, planId, version, actionIds}) {
    const task = loadTask(localStore, taskId);
    if (task.task_type !== 'cleanup' || task.status !== 'AWAITING_CONFIRMATION' || planId !== task.plan_id || version !== task.plan_version) throw Object.assign(new Error('task is not awaiting this cleanup confirmation'), {code: 'AI_CONFIRMATION_REQUIRED'});
    if (!Array.isArray(actionIds) || !actionIds.length || actionIds.some((id) => !task.plan_action_ids.includes(id))) throw Object.assign(new Error('confirmation selection is outside the plan'), {code: 'AI_CONFIRMATION_SCOPE_DENIED'});
    const confirmation = await localService.confirmActionPlan({planId, version, actionIds, source: 'local-user'});
    task.confirmation_id = confirmation.confirmation_id;
    task.confirmed_action_ids = [...actionIds];
    task.operation_id = localStore.newId('ai-operation');
    task.status = 'AWAITING_MODEL_EXECUTION';
    task.messages.push({role: 'user', content: JSON.stringify({event: 'LOCAL_USER_CONFIRMATION', plan_id: task.plan_id, version: task.plan_version, action_ids: task.confirmed_action_ids, operation_id: task.operation_id})});
    save(task);
    return taskSummary(task);
  }

  function confirmNetwork({taskId, planId}) {
    const task = loadTask(localStore, taskId);
    if (task.task_type !== 'network_diagnosis' || task.status !== 'AWAITING_NETWORK_CONFIRMATION' || task.network_plan?.plan_id !== planId) throw Object.assign(new Error('task is not awaiting this network confirmation'), {code: 'AI_CONFIRMATION_REQUIRED'});
    task.network_confirmation_id = localStore.newId('network-confirmation');
    task.network_confirmation = {
      confirmation_id: task.network_confirmation_id,
      plan_id: task.network_plan.plan_id,
      version: task.network_plan.version,
      action_id: task.network_plan.action_id,
      environment_ref: task.network_plan.environment_ref,
      profile_ref: task.network_plan.profile_ref,
      reason: task.network_plan.reason,
    };
    task.status = 'AWAITING_MODEL_EXECUTION';
    task.messages.push({role: 'user', content: JSON.stringify({event: 'LOCAL_NETWORK_CONFIRMATION', ...task.network_confirmation})});
    if (diagnostics && task.network_facts?.diagnostic_plan_id) {
      const diagPlan = diagnostics.plan?.(task.network_facts.diagnostic_plan_id);
      const selected = task.network_plan.action_id;
      const allowed = new Set((diagPlan?.actions || []).map((item) => item.action_id));
      if (selected && allowed.has(selected)) {
        diagnostics.confirm(task.network_facts.diagnostic_plan_id, [selected], task.network_confirmation_id);
      }
    }
    save(task);
    return taskSummary(task);
  }

  async function resume({taskId, signal} = {}) {
    const task = loadTask(localStore, taskId);
    if (!['REMOTE_RESPONSE_UNKNOWN', 'MODEL_FAILED', 'AWAITING_MODEL_EXECUTION', 'REQUESTING_MODEL'].includes(task.status)) throw Object.assign(new Error('task cannot be resumed in its current state'), {code: 'AI_RESUME_NOT_ALLOWED'});
    return run(task, {signal});
  }

  function cancel({taskId}) {
    activeRuns.get(taskId)?.abort();
    const task = loadTask(localStore, taskId);
    task.status = 'CANCELLED';
    task.last_error = {code: 'AI_ABORTED'};
    save(task);
    return taskSummary(task);
  }

  return {startCleanup, startNetworkDiagnosis, startDailyAnalysis, confirmCleanup, confirmNetwork, resume, cancel, getTask: (taskId) => taskSummary(loadTask(localStore, taskId))};
}
