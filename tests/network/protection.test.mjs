import assert from 'node:assert/strict';
import test from 'node:test';
import {auth, createHarness, ENV} from '../../fixtures/network/harness.mjs';
import {createProtectionFixture} from '../../src/adapters/network/index.mjs';

test('FD-04/A06-A11 A16-A20 即时保护与事件引用', async () => {
  const hanging = {
    async recordNetworkEvent() { return new Promise(() => {}); },
    async getAssignment(userRef) { return {ok: true, assignment: null}; },
    async getQuotaSnapshot() { return {ok: true, snapshot: {status: 'UNKNOWN'}}; },
  };
  const harness = await createHarness('protect');
  const applied = await harness.controller.confirmAndApply({
    operation_id: 'protect-apply',
    userRef: 'user-max',
    environmentRef: ENV,
    mode: 'claude_dual_ip',
    authorization: auth('user-max'),
  });
  const state = {expected: applied.expected, environment_ref: ENV, user_ref: 'user-max', protected_process_paths: ['C:\\Program Files\\Claude\\claude.exe']};
  const live = await harness.controller.handleProtection(state, {
    live: true,
    source: 'live',
    classification: 'WRONG_ROUTE',
    process: 'claude.exe',
    destination: 'api.anthropic.com',
    environment_ref: ENV,
  });
  assert.equal(live.protection.requested, true);
  assert.equal(live.protection.waited_for_ai, false);
  assert.equal(live.incident.count, 1);
  const again = await harness.controller.handleProtection(state, {
    live: true,
    source: 'live',
    classification: 'WRONG_ROUTE',
    process: 'claude.exe',
    destination: 'api.anthropic.com',
    environment_ref: ENV,
  });
  assert.equal(again.incident.event_ref, live.incident.event_ref);
  assert.equal(again.incident.count, 2);

  const archive = await harness.controller.handleProtection(state, {
    live: false,
    source: 'archive',
    classification: 'WRONG_ROUTE',
    process: 'claude.exe',
    destination: 'api.anthropic.com',
  });
  assert.equal(archive.action, 'REPORT_ONLY');
  assert.equal(archive.protection.requested, false);

  const reject = await harness.controller.handleProtection(state, {live: true, classification: 'SAFE_REJECT'});
  assert.equal(reject.reason, 'SAFE_REJECT_NOT_CRITICAL');
  const error = await harness.controller.handleProtection(state, {live: true, classification: 'ROUTE_ERROR'});
  assert.equal(error.action, 'KEEP_EXISTING_PROTECTION');

  const reconnect = createProtectionFixture({inject: {reconnectAllowed: true, commandOnly: true}});
  const other = await createHarness('protect-reconnect', {protection: reconnect});
  const unconfirmed = await other.controller.handleProtection(state, {
    live: true,
    source: 'live',
    classification: 'WRONG_ROUTE',
    process: 'claude.exe',
    destination: 'claude.ai',
    environment_ref: ENV,
  });
  assert.equal(unconfirmed.protection.status, 'UNCONFIRMED');
  assert.equal(unconfirmed.protection.command_success_without_new_connection_block, true);

  const stuck = await createHarness('protect-stuck', {control: hanging, events: {deliver: () => new Promise(() => {})}});
  const protectedWhileStuck = await stuck.controller.handleProtection(state, {
    live: true,
    source: 'live',
    classification: 'WRONG_ROUTE',
    process: 'claude.exe',
    destination: 'api.anthropic.com',
    environment_ref: ENV,
  });
  assert.equal(protectedWhileStuck.protection.requested, true);
  assert.equal(protectedWhileStuck.ai_or_control_stuck_still_protected, true);

  const observed = harness.controller.observe(state, {
    live: true,
    connections: [{id: 'c1', metadata: {process: 'claude.exe', host: 'api.anthropic.com'}, chains: ['DIRECT'], upload: 10, download: 20, outcome: 'connected'}],
    classification_version: 'product-v1',
    managedBrowserProcesses: ['claude-browser.exe'],
    fixedA: {route: 'CLAUDE-FIXED', member: 'PROXY-A'},
  });
  assert.equal(observed.events[0].classification, 'WRONG_ROUTE');
  assert.equal(observed.events[0].unknown_filled_as_claude, false);
  harness.controlStore.close();
  other.controlStore.close();
  stuck.controlStore.close();
});
