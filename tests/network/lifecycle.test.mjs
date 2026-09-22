import assert from 'node:assert/strict';
import test from 'node:test';
import {createHarness} from '../../fixtures/network/harness.mjs';

test('FD-03/A30 RUNTIME §1 生命周期动作与效果分开', async () => {
  const {controller, controlStore} = await createHarness('life');
  const base = {user_ref: 'user-max', environment_ref: 'synthetic-windows', last_valid_plan: 'plan-1'};
  const first = controller.advanceLifecycle(base, {type: 'first_open'});
  assert.equal(first.effects.proxy_changed, false);
  const enabled = controller.advanceLifecycle(first, {type: 'confirm_enable', boot_authorized: true});
  assert.equal(enabled.effects.protection_ready_required, true);
  const closed = controller.advanceLifecycle(enabled, {type: 'close_window'});
  assert.equal(closed.effects.core_stopped, false);
  assert.equal(closed.effects.service_running, true);
  const crash = await controller.executeLifecycle(closed, {type: 'core_crash'});
  assert.equal(crash.effects.direct_released, false);
  assert.equal(crash.effects.retry, true);
  assert.ok(crash.executed.some((item) => item.action === 'keep_os_protection' || item.action === 'limited_restart'));
  const exitUi = controller.advanceLifecycle(crash, {type: 'exit_ui'});
  assert.equal(exitUi.effects.management_stopped, false);
  const stop = controller.advanceLifecycle(exitUi, {type: 'stop_management'});
  assert.equal(stop.effects.management_stopped, true);
  const upgrade = controller.advanceLifecycle(stop, {type: 'upgrade_failed'});
  assert.equal(upgrade.effects.quota_reset, false);
  const uninstall = controller.advanceLifecycle(upgrade, {type: 'uninstall', settings: [
    {id: 'sysproxy', owned_by: 'this_app', externally_modified: false},
    {id: 'foreign-tun', owned_by: 'other', externally_modified: false},
    {id: 'edited', owned_by: 'this_app', externally_modified: true},
  ]});
  assert.deepEqual(uninstall.effects.revoked, ['sysproxy']);
  assert.equal(uninstall.effects.skipped.length, 2);
  const conflict = controller.advanceLifecycle(uninstall, {type: 'external_proxy_conflict', names: ['clash.exe']});
  assert.equal(conflict.effects.external_stopped, false);
  const disk = controller.advanceLifecycle(conflict, {type: 'disk_full'});
  assert.equal(disk.effects.evidence_deleted, false);
  const wake = controller.advanceLifecycle(disk, {type: 'wake'});
  assert.equal(wake.effects.unknown_proxy_released, false);
  controlStore.close();
});
