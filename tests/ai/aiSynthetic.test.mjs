import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import path from 'node:path';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import test from 'node:test';
import {createLocalService} from '../../src/core/local/index.mjs';
import {createWorkspaceAdapter} from '../../src/adapters/local/index.mjs';
import {buildDailyReport, deliverDailyReport} from '../../src/core/audit/dailyReport.mjs';
import {createAiClient} from '../../src/core/ai/index.mjs';
import {createHandlerTransport} from '../../src/core/ai/controlTransport.mjs';
import {createApplicationControl} from '../../services/control/index.mjs';
import {createControlStore, openControlStore} from '../../services/control/store.mjs';
import {createModelProvider} from '../../services/control/modelProvider.mjs';
import {createSyntheticFixture, SYNTHETIC_ENVIRONMENT} from '../local/demo.mjs';
import {completion, tool} from '../../fixtures/ai/model-scripts.mjs';

function auditStore() {
  const files = new Map();
  return {
    async exists(file) { return files.has(file); },
    async readText(file) { return files.get(file); },
    async writeText(file, value, {overwrite = false} = {}) { if (files.has(file) && !overwrite) { const error = new Error('exists'); error.code = 'EEXIST'; throw error; } files.set(file, value); },
    async listFiles(prefix = '') { return [...files.entries()].filter(([file]) => file.startsWith(prefix)).map(([file, value]) => ({path: file, bytes: new TextEncoder().encode(value)})); },
    files,
  };
}

async function setup(label, script) {
  const root = transientRun('ai', `test-${label}`);
  await mkdir(path.dirname(root), {recursive: true});
  await createSyntheticFixture(root);
  const adapter = createWorkspaceAdapter({workspaceRoot: root});
  const localService = createLocalService({workspaceRoot: root, environment: SYNTHETIC_ENVIRONMENT, adapter});
  const scan = await localService.discover({mode: 'deep'});
  for (const identity of scan.identities) localService.recordAccountAnswer({scanId: scan.scan_id, identityRef: identity.identity_ref, identityFingerprint: identity.identity_fingerprint, status: identity.identity_ref === 'restricted-account' ? 'restricted' : 'normal'});
  const audits = auditStore();
  const report = buildDailyReport({now: '2026-09-12T20:00:00.000Z', window: {start: '2026-09-11T20:00:00.000Z', end: '2026-09-12T20:00:00.000Z'}, records: [{timestamp: '2026-09-12T01:00:00.000Z', classification: 'UNKNOWN', reason: 'SYNTHETIC_GAP', eventId: 'synthetic-event'}], traffic: {totals: {uploadBytes: 1, downloadBytes: 2}, coverageIssues: []}, archive: {entries: [{sourcePath: 'synthetic.log', sha256: 'synthetic'}], issues: [], restrictedExceptions: []}, quota: {status: 'UNKNOWN'}, protection: {status: 'UNKNOWN'}, collectionEvidence: {environmentRef: 'synthetic', sourceRefs: ['synthetic.log'], continuous: true, coverageStart: '2026-09-11T20:00:00.000Z', coverageEnd: '2026-09-12T20:00:00.000Z', gaps: []}});
  await deliverDailyReport(report, {}, audits);
  const requests = [];
  const users = [{user_ref: 'user-a', status: 'ACTIVE'}, {user_ref: 'user-b', status: 'ACTIVE'}, {user_ref: 'user-disabled', status: 'DISABLED'}];
  const sessions = [{session_ref: 's-a', user_ref: 'user-a', token: 'token-a', expires_at: '2030-01-01T00:00:00.000Z'}, {session_ref: 's-b', user_ref: 'user-b', token: 'token-b', expires_at: '2030-01-01T00:00:00.000Z'}, {session_ref: 's-disabled', user_ref: 'user-disabled', token: 'token-disabled', expires_at: '2030-01-01T00:00:00.000Z'}, {session_ref: 's-expired', user_ref: 'user-a', token: 'token-expired', expires_at: '2000-01-01T00:00:00.000Z'}];
  const store = createControlStore({databasePath: path.join(root, 'state', 'control.sqlite'), users, sessions});
  const sdkFetch = async (url, init) => { const body = JSON.parse(init.body); requests.push({url: String(url), headers: Object.fromEntries(init.headers), body}); return script(body, requests, {scanId: scan.scan_id, reportId: report.reportId}); };
  const modelPolicies = Object.fromEntries(['cleanup', 'network_diagnosis', 'daily_analysis'].map((taskType) => [taskType, {status: 'AVAILABLE', version: `policy-${taskType}-v1`, secret_ref: 'synthetic-secret', base_url: 'https://synthetic-model.invalid/v1', model: 'synthetic-server-selected-model', organization: 'synthetic-org', project: 'synthetic-project', timeoutMs: 60000}]));
  const handler = createApplicationControl({store, modelPolicies, secrets: {resolve: (ref) => ref === 'synthetic-secret' ? 'SYNTHETIC_SERVER_KEY' : (() => { throw new Error('unknown secret'); })()}, sdkFetch});
  const client = createAiClient({localService, localStore: adapter, auditStore: audits, controlTransport: createHandlerTransport({handler, sessionToken: 'token-a'})});
  return {root, adapter, localService, scan, audits, report, requests, handler, client, store};
}

test('control store reopens the same persistent task and budget ledger', () => {
  const databasePath = path.join(transientRun('ai', 'control-store'), 'control.sqlite');
  const users = [{user_ref: 'user-a', status: 'ACTIVE'}];
  const sessions = [{session_ref: 's-a', user_ref: 'user-a', token: 'token-a', expires_at: '2030-01-01T00:00:00.000Z'}];
  const first = createControlStore({databasePath, users, sessions});
  first.saveTask({task_ref: 'persisted-task', user_ref: 'user-a', task_type: 'cleanup'});
  first.recordEvent({task_ref: 'persisted-task', user_ref: 'user-a', usage: {total_tokens: 7}, status: 'OK'});
  first.close();
  const reopened = openControlStore({databasePath, users, sessions});
  assert.equal(reopened.getTask('persisted-task').user_ref, 'user-a');
  assert.equal(reopened.turnCountForTask('persisted-task'), 1);
  assert.equal(reopened.usageForTask('persisted-task'), 7);
  reopened.close();
});

test('cleanup consumes actual first-round T3 inspection, waits for local confirmation, executes once, and resumes a lost response without re-executing', async () => {
  let phase = 0;
  let plan = null;
  let inspectedObject = null;
  const context = await setup('cleanup', (body, _requests, refs) => {
    const toolMessages = body.messages.filter((message) => message.role === 'tool');
    if (phase === 0) { phase += 1; return completion({toolCalls: [tool('discover', 'DiscoverEnvironment', {scan_id: refs.scanId})]}); }
    if (phase === 1) { const discovered = JSON.parse(toolMessages[0].content); inspectedObject = discovered.inspectable_object_refs[0]; assert.ok(inspectedObject, JSON.stringify(discovered)); phase += 1; return completion({toolCalls: [tool('inspect', 'InspectObject', {scan_id: discovered.scan_id, object_ref: inspectedObject})]}); }
    if (phase === 2) { phase += 1; return completion({toolCalls: [tool('plan', 'BuildActionPlan', {scan_id: JSON.parse(toolMessages[0].content).scan_id})]}); }
    if (phase === 3) { plan = JSON.parse(toolMessages.at(-1).content); phase += 1; return completion({content: 'A concrete plan is ready; await local confirmation.'}); }
    if (phase === 4) { const confirmation = JSON.parse(body.messages.find((message) => message.role === 'user' && message.content.includes('LOCAL_USER_CONFIRMATION')).content); phase += 1; return completion({toolCalls: [tool('execute', 'ExecuteConfirmedPlan', {plan_id: confirmation.plan_id, version: confirmation.version, action_ids: confirmation.action_ids, operation_id: confirmation.operation_id})]}); }
    if (phase === 5) { phase += 1; return completion({toolCalls: [tool('recheck', 'RecheckAction', {plan_id: plan.plan_id, action_id: plan.action_ids[0]})]}); }
    return completion({content: 'Execution and recheck results are recorded by the local executor.'});
  });
  const initial = await context.client.startCleanup({scanId: context.scan.scan_id});
  assert.equal(initial.status, 'AWAITING_CONFIRMATION', JSON.stringify(initial));
  assert.ok(initial.planId);
  const confirmed = await context.client.confirmCleanup({taskId: initial.taskId, planId: initial.planId, version: initial.version, actionIds: initial.actionIds});
  assert.equal(confirmed.status, 'AWAITING_MODEL_EXECUTION');
  const task = context.adapter.getRecord(initial.taskId, 'ai_task_v1');
  const droppedTransport = createHandlerTransport({handler: context.handler, sessionToken: 'token-a', dropResponse: (body) => body.assistant?.content === 'Execution and recheck results are recorded by the local executor.'});
  const droppedClient = createAiClient({localService: context.localService, localStore: context.adapter, auditStore: context.audits, controlTransport: droppedTransport});
  const dropped = await droppedClient.resume({taskId: task.task_id});
  assert.equal(dropped.status, 'REMOTE_RESPONSE_UNKNOWN');
  const operationAfterLoss = context.localService.getTask(dropped.operationId);
  const receiptCount = operationAfterLoss.receipts.length;
  const validTransport = createHandlerTransport({handler: context.handler, sessionToken: 'token-a'});
  const retryClient = createAiClient({localService: context.localService, localStore: context.adapter, auditStore: context.audits, controlTransport: validTransport});
  const resumed = await retryClient.resume({taskId: task.task_id});
  assert.equal(resumed.status, 'COMPLETED', JSON.stringify(resumed));
  assert.equal(context.localService.getTask(resumed.operationId).receipts.length, receiptCount);
  assert.ok(context.requests.every((request) => request.url.startsWith('https://synthetic-model.invalid/v1/')));
  assert.ok(context.requests.every((request) => request.body.model === 'synthetic-server-selected-model'));
  assert.ok(context.requests.every((request) => request.headers.authorization === 'Bearer SYNTHETIC_SERVER_KEY'));
  assert.doesNotMatch(JSON.stringify(context.requests.map((request) => request.body)), /SYNTHETIC_SERVER_KEY|SYNTHETIC_RESTRICTED_TOKEN/);
});

test('handler authenticates application users and rejects client model control', async () => {
  const context = await setup('auth', () => Response.json({error: {message: 'synthetic auth error'}}, {status: 401}));
  const bad = await context.handler.handle(new Request('https://application.synthetic.invalid/api/ai/capabilities', {headers: {authorization: 'Bearer token-expired'}}));
  assert.equal(bad.status, 401);
  const injected = await context.handler.handle(new Request('https://application.synthetic.invalid/api/ai/turn', {method: 'POST', headers: {'content-type': 'application/json', authorization: 'Bearer token-a'}, body: JSON.stringify({task_ref: 'x', task_type: 'cleanup', turn_ref: 'x1', prompt_version: 'cleanup-v1', prompt_body: 'x', tool_catalog_version: 'cleanup-tools-v1', messages: [], model: 'attacker-model'})}));
  assert.equal(injected.status, 400);
  assert.equal(context.requests.length, 0);
});

test('the product model provider uses fixed SDK typed 401 and SSE parsing', async () => {
  const policy = {secret_ref: 'synthetic-secret', base_url: 'https://synthetic-model.invalid/v1', model: 'synthetic-server-selected-model', timeoutMs: 60000};
  const provider = createModelProvider({policy, secrets: {resolve: () => 'SYNTHETIC_SERVER_KEY'}, sdkFetch: async () => new Response('data: {"id":"stream","object":"chat.completion.chunk","created":1,"model":"synthetic-server-selected-model","choices":[{"index":0,"delta":{"content":"stream"},"finish_reason":null}]}\n\ndata: {"id":"stream","object":"chat.completion.chunk","created":1,"model":"synthetic-server-selected-model","choices":[{"index":0,"delta":{"content":"ed"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', {headers: {'content-type': 'text/event-stream'}})});
  const stream = await provider.complete({messages: [{role: 'user', content: 'synthetic'}], tools: [], stream: true});
  assert.equal(stream.assistant.content, 'streamed');
  const rejected = createModelProvider({policy, secrets: {resolve: () => 'SYNTHETIC_SERVER_KEY'}, sdkFetch: async () => Response.json({error: {message: 'synthetic reject'}}, {status: 401})});
  await assert.rejects(() => rejected.complete({messages: [], tools: []}), (error) => error.code === 'AI_AUTH_FAILED');
});

test('daily analysis writes a fact-referenced T2 note without changing the standard report and network keeps applied separate from failed verification', async () => {
  let calls = 0;
  let dailyCalls = 0;
  let networkCalls = 0;
  const context = await setup('daily', (body, _requests, refs) => {
    const names = body.tools.map((entry) => entry.function.name);
    if (names.includes('ReadDailyFacts')) {
      if (dailyCalls++ === 0) return completion({toolCalls: [tool('daily-read', 'ReadDailyFacts', {report_id: refs.reportId})]});
      if (dailyCalls === 2) return completion({toolCalls: [tool('daily-save', 'SaveDailyAnalysis', {fact_refs: ['report.route_result', 'report.coverage_status'], analysis: {facts: ['report.route_result'], inference: 'coverage requires follow-up', unknowns: ['missing source'], actions: ['review collection evidence']}})]});
      return completion({content: 'Coverage requires a fact-referenced follow-up.'});
    }
    const networkToolNames = body.messages.filter((message) => message.role === 'assistant').flatMap((message) => message.tool_calls || []).map((call) => call.function.name);
    if (!networkToolNames.includes('InspectNetworkEvidence')) return completion({toolCalls: [tool('network-read', 'InspectNetworkEvidence', {port: 'dns'})]});
    if (!networkToolNames.includes('BuildNetworkPlan')) return completion({toolCalls: [tool('network-plan', 'BuildNetworkPlan', {environment_ref: 'synthetic-windows', profile_ref: 'Default', action_id: 'synthetic-route-check', reason: 'DNS is missing'})]});
    const confirmation = body.messages.find((message) => message.role === 'user' && message.content.includes('LOCAL_NETWORK_CONFIRMATION'));
    if (!confirmation) return completion({content: 'Network candidate awaits local confirmation.'});
    const planId = JSON.parse(confirmation.content).plan_id;
    if (!networkToolNames.includes('ApplyNetworkPlan')) return completion({toolCalls: [tool('network-apply', 'ApplyNetworkPlan', {plan_id: planId})]});
    if (!networkToolNames.includes('RecheckNetworkPlan')) return completion({toolCalls: [tool('network-recheck', 'RecheckNetworkPlan', {plan_id: planId})]});
    return completion({content: 'The supported action was applied, but DNS remains unverified.'});
  });
  const before = context.audits.files.get(`reports/${context.report.reportDate}/daily-audit.json`);
  const daily = await context.client.startDailyAnalysis({report: context.report, input: 'Analyze this daily report.'});
  assert.equal(daily.status, 'COMPLETED');
  assert.equal(context.audits.files.get(`reports/${context.report.reportDate}/daily-audit.json`), before);
  assert.ok([...context.audits.files.keys()].some((key) => key.includes('ai-notes')), JSON.stringify(context.adapter.listRecords('ai_task_v1')));
  let applied = 0;
  const networkPort = {
    async applyNetworkPlan() { applied += 1; return {status: 'APPLIED', applied: true, applied_version: applied, verified: false}; },
    async recheckNetworkPlan() { return {status: 'VERIFIED_FAILED', applied_version: applied, verified: false, reason: 'SYNTHETIC_DNS_MISSING_AFTER_APPLY'}; },
  };
  const networkClient = createAiClient({localService: context.localService, localStore: context.adapter, auditStore: context.audits, controlTransport: createHandlerTransport({handler: context.handler, sessionToken: 'token-a'}), networkPort});
  const network = await networkClient.startNetworkDiagnosis({networkFacts: {dns: {status: 'MISSING'}, environment: {status: 'DECLARED'}, profile: {status: 'DEFAULT_ONLY'}, supported_actions: [{action_id: 'synthetic-route-check', environment_ref: 'synthetic-windows', profile_ref: 'Default', status: 'SUPPORTED'}]}});
  assert.equal(network.status, 'AWAITING_NETWORK_CONFIRMATION', JSON.stringify(network));
  const networkTask = context.adapter.getRecord(network.taskId, 'ai_task_v1');
  networkClient.confirmNetwork({taskId: network.taskId, planId: networkTask.network_plan.plan_id});
  const completed = await networkClient.resume({taskId: network.taskId});
  assert.equal(completed.status, 'COMPLETED');
  const persistedNetwork = context.adapter.getRecord(network.taskId, 'ai_task_v1').network_plan;
  assert.equal(persistedNetwork.applied, true);
  assert.equal(persistedNetwork.verified, false);
  assert.equal(persistedNetwork.status, 'VERIFIED_FAILED');
});
