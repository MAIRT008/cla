import assert from 'node:assert/strict';
import test from 'node:test';
import {createDiagnosticsController} from '../../src/core/diagnostics/index.mjs';

function memoryStore() {
  const records = new Map();
  return {
    saveRecord(type, id, payload) { records.set(`${type}:${id}`, structuredClone(payload)); },
    getRecord(id, type) { return structuredClone(records.get(`${type}:${id}`) ?? null); },
    listRecords(type) { return [...records.entries()].filter(([key]) => key.startsWith(`${type}:`)).map(([, value]) => structuredClone(value)); },
  };
}

function settingsPort(label, applied) {
  return {settings: {read: async () => ({label}), apply: async (target, value) => { applied.push({label, target, value}); return {ok: true}; }}};
}

function confirmedSettingsPlan(store, environmentRef) {
  const plan = {
    plan_id: `diag-plan-${environmentRef}`,
    task_id: `diag-${environmentRef}`,
    environment_ref: environmentRef,
    confirmation_id: 'c1',
    confirmed_action_ids: ['a1'],
    actions: [{action_id: 'a1', kind: 'settings', supported: true, target: 'timezone', after: 'America/Los_Angeles'}],
  };
  store.saveRecord('diagnostic_plan', plan.plan_id, plan);
  return plan.plan_id;
}

test('MAJOR 诊断计划按所属环境取设置端口；那个环境没有端口时如实失败，不借宿主端口也不崩', async () => {
  const store = memoryStore();
  const applied = [];
  const controller = createDiagnosticsController({
    store,
    ports: null,
    environmentRef: 'windows-host',
    environmentPorts: (ref) => (ref === 'wsl-guest' ? {ports: settingsPort('wsl-guest', applied)} : null),
  });
  const guest = await controller.execute(confirmedSettingsPlan(store, 'wsl-guest'));
  assert.equal(guest.receipts[0].status, 'APPLIED');
  assert.deepEqual(applied.map((item) => item.label), ['wsl-guest'], '客体计划用客体的端口');

  const host = await controller.execute(confirmedSettingsPlan(store, 'windows-host'));
  assert.equal(host.receipts[0].status, 'FAILED');
  assert.equal(host.receipts[0].code, 'PORT_UNAVAILABLE', '宿主没有端口就如实失败');
  const restored = await controller.restore('diag-plan-windows-host', true, []);
  assert.equal(restored.status, 'PARTIAL');
});
