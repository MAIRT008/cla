import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import path from 'node:path';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import test from 'node:test';
import {createAiClient} from '../../src/core/ai/index.mjs';
import {createHandlerTransport} from '../../src/core/ai/controlTransport.mjs';
import {createLocalService} from '../../src/core/local/index.mjs';
import {createWorkspaceAdapter} from '../../src/adapters/local/index.mjs';
import {createApplicationControl, seedControlNetwork} from '../../services/control/index.mjs';
import {createControlStore} from '../../services/control/store.mjs';
import {createSyntheticFixture, SYNTHETIC_ENVIRONMENT} from '../local/demo.mjs';
import {completion, tool} from '../../fixtures/ai/model-scripts.mjs';
import {threeUsers, createHarness, ENV} from '../../fixtures/network/harness.mjs';

test('T5 网络口接入 AI 已确认计划且不另建配置工具', async () => {
  const harness = await createHarness('ai-t5');
  const root = transientRun('ai', 't5-network');
  await mkdir(path.dirname(root), {recursive: true});
  await createSyntheticFixture(root);
  const adapter = createWorkspaceAdapter({workspaceRoot: root});
  const localService = createLocalService({workspaceRoot: root, environment: SYNTHETIC_ENVIRONMENT, adapter});
  const users = [{user_ref: 'user-max', status: 'ACTIVE'}];
  const sessions = [{session_ref: 's-max', user_ref: 'user-max', token: 'token-max', expires_at: '2030-01-01T00:00:00.000Z'}];
  const store = createControlStore({databasePath: path.join(root, 'state', 'control.sqlite'), users, sessions});
  seedControlNetwork(store, threeUsers());
  let calls = [];
  const sdkFetch = async (_url, init) => {
    const body = JSON.parse(init.body);
    const names = body.messages.filter((message) => message.role === 'assistant').flatMap((message) => message.tool_calls || []).map((call) => call.function.name);
    calls = names;
    if (!names.includes('BuildNetworkPlan')) return completion({toolCalls: [tool('network-plan', 'BuildNetworkPlan', {environment_ref: ENV, profile_ref: 'Default', action_id: 'apply_mode:daily_single_ip', reason: 'switch after confirmation'})]});
    const confirmation = body.messages.find((message) => message.role === 'user' && String(message.content).includes('LOCAL_NETWORK_CONFIRMATION'));
    if (!confirmation) return completion({content: 'awaiting confirmation'});
    const planId = JSON.parse(confirmation.content).plan_id;
    if (!names.includes('ApplyNetworkPlan')) return completion({toolCalls: [tool('network-apply', 'ApplyNetworkPlan', {plan_id: planId})]});
    if (!names.includes('RecheckNetworkPlan')) return completion({toolCalls: [tool('network-recheck', 'RecheckNetworkPlan', {plan_id: planId})]});
    return completion({content: 'applied via T5 controller'});
  };
  const modelPolicies = Object.fromEntries(['cleanup', 'network_diagnosis', 'daily_analysis'].map((taskType) => [taskType, {status: 'AVAILABLE', version: `policy-${taskType}-v1`, secret_ref: 'synthetic-secret', base_url: 'https://synthetic-model.invalid/v1', model: 'synthetic-server-selected-model', organization: 'synthetic-org', project: 'synthetic-project', timeoutMs: 60000}]));
  const handler = createApplicationControl({store, modelPolicies, secrets: {resolve: () => 'SYNTHETIC_SERVER_KEY'}, sdkFetch});
  const client = createAiClient({
    localService,
    localStore: adapter,
    auditStore: {async exists() { return false; }, async writeText() {}, async readText() { return ''; }, async listFiles() { return []; }},
    controlTransport: createHandlerTransport({handler, sessionToken: 'token-max'}),
    networkPort: harness.controller.asAiPort('user-max'),
  });
  const network = await client.startNetworkDiagnosis({networkFacts: {supported_actions: [{action_id: 'apply_mode:daily_single_ip', environment_ref: ENV, profile_ref: 'Default', status: 'SUPPORTED'}], dns: {status: 'DECLARED'}}});
  assert.equal(network.status, 'AWAITING_NETWORK_CONFIRMATION');
  const task = adapter.getRecord(network.taskId, 'ai_task_v1');
  client.confirmNetwork({taskId: network.taskId, planId: task.network_plan.plan_id});
  const completed = await client.resume({taskId: network.taskId});
  assert.equal(completed.status, 'COMPLETED');
  const persisted = adapter.getRecord(network.taskId, 'ai_task_v1');
  assert.equal(persisted.network_plan.applied, true);
  assert.equal(persisted.network_apply_result.receipt.loaded.loaded_version, null);
  store.close();
  harness.controlStore.close();
});
