import assert from 'node:assert/strict';
import test from 'node:test';
import {
  decodeGetConfigs,
  decodePutConfigs,
  encodePutConfigs,
  MIHOMO_PROTOCOL,
} from '../../src/adapters/network/index.mjs';
import {createLiveMihomoTransport} from '../../src/adapters/network/liveTransport.mjs';
import {auth, createHarness, ENV} from '../../fixtures/network/harness.mjs';

test('FD-03/A27 A32-A34 协议适配与控制器消费', async () => {
  const encoded = encodePutConfigs({payload: 'mode: rule\n', force: true, secret: 'synthetic'});
  assert.equal(encoded.method, 'PUT');
  assert.equal(encoded.url, '/configs?force=true');
  assert.equal(encoded.body.payload.startsWith('mode:'), true);
  assert.equal(encoded.headers.Authorization, 'Bearer synthetic');
  const decoded = decodePutConfigs({status: 204});
  assert.equal(decoded.accepted, true);
  assert.equal(decoded.loaded_version, null);
  const general = decodeGetConfigs({status: 200, body: {mode: 'rule', tun: {enable: true}, authentication: ['secret'], 'ss-config': 'hidden'}});
  assert.equal(general.loaded_version, null);
  assert.equal(general.general.authentication, undefined);
  assert.equal(MIHOMO_PROTOCOL.commit, 'ac017cdd246ce8bd547653d927e7bf77d7ee73d5');

  const live = createLiveMihomoTransport();
  await assert.rejects(() => live.putConfigs({payload: 'x'}), {code: 'CORE_UNAVAILABLE'});
  assert.throws(() => createLiveMihomoTransport({baseUrl: 'http://127.0.0.1:9090', fetchImpl: () => {}}), {code: 'CORE_UNAVAILABLE'});

  const harness = await createHarness('protocol');
  const {controller, core, controlStore} = harness;
  const receipt = await controller.confirmAndApply({
    operation_id: 'proto-1',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  assert.equal(receipt.loaded.loaded_version, null);
  assert.equal(receipt.loaded.kernel_version, 'v1.19.30');
  assert.equal(core.snapshot().loaded_version, null);
  const state = await controller.readState({userRef: 'user-max', environmentRef: ENV});
  assert.equal(state.whole_machine_claim, false);
  assert.equal(state.loaded.loaded_version, null);
  assert.equal(state.expected.matrix.claude.exit, 'A');

  const aiPort = controller.asAiPort('user-max');
  const applied = await aiPort.applyNetworkPlan({plan: {plan_id: 'n1', version: 1, action_id: 'apply_mode:daily_single_ip', environment_ref: ENV, profile_ref: 'Default', reason: 'switch'}});
  assert.equal(applied.applied, true);
  const {createWorkspaceAdapter} = await import('../../src/adapters/local/workspace.mjs');
  const reopened = createWorkspaceAdapter({workspaceRoot: harness.root, clock: harness.clock});
  const persisted = reopened.getRecord(`network-state:user-max:${ENV}`, 'network_state_v1');
  assert.equal(persisted.mode, 'daily_single_ip');
  assert.equal(persisted.expected.plan_version, applied.receipt.expected.plan_version);
  controlStore.close();
});
