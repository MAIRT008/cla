import {redactForModel, redactText} from './evidence.mjs';

const TYPE = 'ai_task_v1';

export function createTask(localStore, input) {
  const taskId = localStore.newId('ai-task');
  return redactForModel({
    schema_version: 1,
    task_id: taskId,
    task_type: input.taskType,
    task_ref: taskId,
    prompt_version: input.promptVersion,
    tool_catalog_version: input.toolCatalogVersion,
    status: 'CREATED',
    scan_id: input.scanId || null,
    report_id: input.reportId || null,
    allowed_fact_refs: input.allowedFactRefs || [],
    allowed_object_refs: input.allowedObjectRefs || [],
    allowed_objects: input.allowedObjects || [],
    network_facts: input.networkFacts || null,
    daily_facts: input.dailyFacts || null,
    messages: [{role: 'user', content: redactText(input.userInput || '')}],
    turn_count: 0,
    tool_call_count: 0,
    used_usage: [],
    plan_id: null,
    plan_version: null,
    plan_action_ids: [],
    confirmation_id: null,
    confirmed_action_ids: [],
    operation_id: null,
    operation_status: null,
    operation_receipts: [],
    inspected_object_refs: [],
    tool_call_receipts: [],
    evidence_bytes: 0,
    network_plan: null,
    network_confirmation_id: null,
    network_confirmation: null,
    network_apply_result: null,
    network_recheck_result: null,
    pending_turn: null,
    model_policy_version: null,
    note_ref: null,
  });
}

export function saveTask(localStore, task) {
  const safe = {
    ...task,
    messages: task.messages.map((message) => ({
      ...message,
      content: redactText(message.content),
      ...(message.tool_calls ? {tool_calls: message.tool_calls.map((call) => ({
        id: call.id,
        type: 'function',
        function: {name: call.function?.name, arguments: redactText(call.function?.arguments || '{}')},
      }))} : {}),
    })),
  };
  return localStore.saveRecord(TYPE, task.task_id, safe);
}

export function loadTask(localStore, taskId) {
  const task = localStore.getRecord(taskId, TYPE);
  if (!task) {
    const error = new Error('AI task was not found in the local store');
    error.code = 'AI_TASK_NOT_FOUND';
    throw error;
  }
  return task;
}

export function taskSummary(task) {
  return {
    taskId: task.task_id,
    taskType: task.task_type,
    status: task.status,
    scanId: task.scan_id,
    reportId: task.report_id,
    planId: task.plan_id,
    version: task.plan_version,
    actionIds: task.plan_action_ids,
    confirmationId: task.confirmation_id,
    operationId: task.operation_id,
    operationStatus: task.operation_status || null,
    operationReceipts: task.operation_receipts || [],
    modelPolicyVersion: task.model_policy_version,
    usage: task.used_usage,
    lastError: task.last_error || null,
    assistantText: redactText([...task.messages].reverse().find((message) => message.role === 'assistant')?.content || ''),
  };
}
