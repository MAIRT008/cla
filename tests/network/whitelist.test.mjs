import assert from 'node:assert/strict';
import test from 'node:test';
import {mutateWhitelist, normalizeHost} from '../../src/core/network/index.mjs';
import {auth, createHarness, ENV} from '../../fixtures/network/harness.mjs';

test('FD-03/A05-A08 白名单范围、冲突与模式保留', async () => {
  const {controller, controlStore} = await createHarness('whitelist');
  const exact = await controller.updateWhitelist({userRef: 'user-free', action: 'add', payload: {input: 'https://WWW.Example.COM/path', match: 'exact'}});
  assert.equal(exact.whitelist.entries[0].host, 'www.example.com');
  assert.equal(exact.whitelist.entries[0].match, 'exact');
  const sub = await controller.updateWhitelist({userRef: 'user-free', action: 'add', payload: {input: '*.news.example', match: 'subdomains'}});
  assert.equal(sub.whitelist.entries[1].match, 'subdomains');
  await assert.rejects(() => controller.updateWhitelist({userRef: 'user-free', action: 'add', payload: {input: 'https://user:pass@evil.example'}}), {code: 'WHITELIST_CREDENTIALS'});
  await assert.rejects(() => controller.updateWhitelist({userRef: 'user-free', action: 'add', payload: {input: 'com'}}), {code: 'WHITELIST_BROAD'});
  const before = controller.getWhitelist('user-free').entries.length;
  await assert.rejects(() => controller.updateWhitelist({userRef: 'user-free', action: 'add', payload: {input: 'api.anthropic.com'}}), {code: 'WHITELIST_CLAUDE_CONFLICT'});
  assert.equal(controller.getWhitelist('user-free').entries.length, before);

  const idn = normalizeHost('https://例子.测试/');
  assert.equal(idn.ok, true);

  const assignment = (await controller.getAssignment('user-free', ENV)).assignment;
  const enabled = await controller.updateWhitelist({
    userRef: 'user-free',
    action: 'add',
    payload: {input: 'direct.example', match: 'exact'},
    mode: 'daily_single_ip',
    environmentRef: ENV,
    assignment,
    authorization: auth('user-free'),
    operation_id: 'wl-apply-1',
  });
  assert.equal(enabled.apply.overall === 'APPLIED_VERIFIED' || enabled.apply.overall === 'APPLIED_UNVERIFIED', true);
  assert.match(enabled.apply.expected.yaml, /DOMAIN,direct.example,DIRECT/);

  const dedicated = await controller.confirmAndApply({
    operation_id: 'wl-dedicated',
    userRef: 'user-pro',
    environmentRef: ENV,
    mode: 'claude_single_ip',
    authorization: auth('user-pro'),
  });
  await controller.updateWhitelist({userRef: 'user-pro', action: 'add', payload: {input: 'keep.example', match: 'exact'}});
  assert.equal(controller.getWhitelist('user-pro').entries.some((entry) => entry.host === 'keep.example'), true);
  assert.doesNotMatch(dedicated.expected.yaml, /keep\.example/);
  const back = await controller.confirmAndApply({
    operation_id: 'wl-back-daily',
    userRef: 'user-pro',
    environmentRef: ENV,
    mode: 'daily_single_ip',
    authorization: auth('user-pro'),
  });
  assert.match(back.expected.yaml, /DOMAIN,keep.example,DIRECT/);

  const mutated = mutateWhitelist(controller.getWhitelist('user-free'), 'disable', {entry_id: controller.getWhitelist('user-free').entries[0].entry_id}, {mode: 'daily_single_ip'});
  assert.equal(mutated.impact.active_in_current_mode, true);
  controlStore.close();
});
