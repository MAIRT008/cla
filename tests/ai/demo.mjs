import path from 'node:path';
import {assertTransient} from '../../fixtures/transientRoot.mjs';
import {TextEncoder} from 'node:util';
import {initializeSyntheticRuntime, loadSyntheticReport, openSyntheticRuntime} from '../../fixtures/ai/syntheticRuntime.mjs';

const [command, flag, workspaceValue] = process.argv.slice(2);
if (flag !== '--workspace' || !workspaceValue) throw new Error('usage: demo.mjs <command> --workspace fixtures/_transient/ai/runs/<name>');
// 守卫要在这里，不能只放在 run-synthetic.mjs：这个文件可以被直接执行。
const workspace = assertTransient(workspaceValue, {suite: 'ai'});
if (command === 'init') {
  const initialized = await initializeSyntheticRuntime(workspace);
  process.stdout.write(JSON.stringify({command, workspace, ...initialized.state, status: 'INITIALIZED'}) + '\n');
  process.exit(0);
}
const runtime = await openSyntheticRuntime(workspace, {dropFinalResponse: command === 'cleanup-execute-lost-response'});
const prior = runtime.adapter.getRecord('t4-demo-flow', 'ai_demo_flow_v1') || {};
let result;
if (command === 'cleanup-plan') {
  result = await runtime.client.startCleanup({scanId: runtime.state.scan_id});
  runtime.adapter.saveRecord('ai_demo_flow_v1', 't4-demo-flow', {...prior, cleanup_task_id: result.taskId});
} else if (command === 'confirm-cleanup') {
  const task = runtime.client.getTask(prior.cleanup_task_id);
  result = await runtime.client.confirmCleanup({taskId: task.taskId, planId: task.planId, version: task.version, actionIds: task.actionIds});
} else if (command === 'cleanup-execute-lost-response' || command === 'resume') {
  result = await runtime.client.resume({taskId: prior.cleanup_task_id});
} else if (command === 'network') {
  result = await runtime.client.startNetworkDiagnosis({networkFacts: {environment: {status: 'DECLARED'}, profile: {status: 'DEFAULT_ONLY'}, configuration: {status: 'DECLARED'}, history: {status: 'UNAVAILABLE'}, dns: {status: 'MISSING'}, exit: {status: 'UNKNOWN'}, supported_actions: [{action_id: 'synthetic-recheck-route', environment_ref: 'synthetic-windows', profile_ref: 'Default', status: 'SUPPORTED'}]}});
  runtime.adapter.saveRecord('ai_demo_flow_v1', 't4-demo-flow', {...prior, network_task_id: result.taskId});
  if (result.status === 'AWAITING_NETWORK_CONFIRMATION') {
    const task = runtime.adapter.getRecord(result.taskId, 'ai_task_v1');
    const confirmed = runtime.client.confirmNetwork({taskId: result.taskId, planId: task.network_plan.plan_id});
    result = await runtime.client.resume({taskId: confirmed.taskId});
  }
} else if (command === 'daily') {
  result = await runtime.client.startDailyAnalysis({report: await loadSyntheticReport(runtime)});
  runtime.adapter.saveRecord('ai_demo_flow_v1', 't4-demo-flow', {...prior, daily_task_id: result.taskId});
} else if (command === 'failures') {
  const expired = await runtime.handler.handle(new Request('https://application.synthetic.invalid/api/ai/capabilities', {headers: {authorization: 'Bearer token-expired'}}));
  const disabled = await runtime.handler.handle(new Request('https://application.synthetic.invalid/api/ai/capabilities', {headers: {authorization: 'Bearer token-disabled'}}));
  result = {expired_status: expired.status, disabled_status: disabled.status, outbound_requests: runtime.outbound.length};
} else if (command === 'status') {
  result = {cleanup: prior.cleanup_task_id ? runtime.client.getTask(prior.cleanup_task_id) : null, network: prior.network_task_id ? runtime.client.getTask(prior.network_task_id) : null, daily: prior.daily_task_id ? runtime.client.getTask(prior.daily_task_id) : null};
} else {
  throw new Error(`unsupported demo command: ${command}`);
}
const evidencePath = `state/t4-demo-${command}-request-evidence.json`;
const outboundEvidence = runtime.outbound.map((request) => ({url: request.url, model: request.body.model, tool_names: request.body.tools?.map((item) => item.function.name) || [], message_count: request.body.messages?.length || 0, authorization: '[SERVER_SYNTHETIC_AUTH_HEADER_NOT_PERSISTED]'}));
await runtime.adapter.writeBytes(evidencePath, new TextEncoder().encode(JSON.stringify({command, outbound_requests: outboundEvidence, actual_network_requests: 0}, null, 2)));
process.stdout.write(JSON.stringify({command, workspace, result, outbound_requests: runtime.outbound.length, evidence_path: evidencePath}) + '\n');
