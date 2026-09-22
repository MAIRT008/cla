import assert from 'node:assert/strict';
import test from 'node:test';
import {createApplicationControl} from '../../services/control/index.mjs';
import {compileNetworkPlan} from '../../src/core/network/index.mjs';
import {consumeLiveNetwork} from '../../src/core/network/observe.mjs';
import {createLiveMihomoTransport} from '../../src/adapters/network/liveTransport.mjs';
import {createHarness, ENV} from '../../fixtures/network/harness.mjs';

test('MAJOR6 正式 HTTP Assignment 下发受管模板，编译不回落硬编码 DNS', async () => {
  const {controlStore} = await createHarness('http-template');
  const handler = createApplicationControl({
    store: controlStore,
    modelPolicies: {},
    secrets: {resolve: () => 'x'},
  });
  const response = await handler.handle(new Request('https://application.synthetic.invalid/api/network/assignment', {
    method: 'GET',
    headers: {authorization: 'Bearer token-max'},
  }));
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.assignment.user_ref, 'user-max');
  assert.equal(Boolean(body.assignment.template), true);
  assert.notEqual(body.assignment.template, null);
  assert.deepEqual(body.assignment.template.dns.nameserver, ['https://dns.steward.test/dns-query']);
  assert.ok(body.assignment.template.control_plane.login.length > 0);
  assert.equal(body.assignment.template_version, body.assignment.template.version);

  const plan = compileNetworkPlan({
    assignment: body.assignment,
    mode: 'claude_dual_ip',
    environmentScope: {environment_ref: ENV},
  });
  assert.match(plan.yaml, /dns\.steward\.test/);
  assert.doesNotMatch(plan.yaml, /dns\.example\.invalid/);
  assert.match(plan.yaml, /login\.steward\.test/);

  assert.throws(
    () => compileNetworkPlan({
      assignment: {...body.assignment, template: null},
      mode: 'daily_single_ip',
      environmentScope: {environment_ref: ENV},
    }),
    {code: 'TEMPLATE_UNAVAILABLE'},
  );
  controlStore.close();
});

test('BLOCK5 liveTransport 连接快照不是配置投影，并提供 traffic/logs 流', async () => {
  const snapshot = {
    downloadTotal: 9,
    uploadTotal: 8,
    memory: 1,
    connections: [{id: 'c-http', metadata: {process: 'claude.exe', host: 'api.anthropic.com'}, chains: ['DIRECT'], upload: 1, download: 2}],
  };
  const trafficLines = `${JSON.stringify({up: 1, down: 2, upTotal: 8, downTotal: 9})}\n${JSON.stringify({up: 3, down: 4, upTotal: 11, downTotal: 13})}\n`;
  const logLines = `${JSON.stringify({type: 'info', payload: 'time="2026-09-13T17:00:00Z" (claude.exe) --> api.anthropic.com:443 using DIRECT'})}\n`;
  const transport = createLiveMihomoTransport({
    baseUrl: 'https://mihomo.synthetic.invalid',
    secret: 'synthetic',
    fetchImpl: async (url) => {
      const path = String(url);
      if (path.includes('/connections')) return {status: 200, text: async () => JSON.stringify(snapshot)};
      if (path.includes('/traffic')) return {status: 200, text: async () => trafficLines};
      if (path.includes('/logs')) return {status: 200, text: async () => logLines};
      return {status: 404, text: async () => '{"message":"not found"}'};
    },
  });
  const connections = await transport.getConnections();
  assert.equal(connections.general, undefined);
  assert.equal(connections.connections.length, 1);
  assert.equal(connections.connections[0].id, 'c-http');
  assert.equal(connections.uploadTotal, 8);

  const samples = [];
  for await (const sample of transport.streamTraffic()) samples.push(sample);
  assert.equal(samples.length, 2);
  assert.equal(samples[1].downTotal, 13);
  assert.equal(samples[0].user_quota, null);

  const logs = await transport.getLogs();
  assert.equal(logs.lines.length, 1);
  assert.match(logs.lines[0].payload, /DIRECT/);

  const consumed = await consumeLiveNetwork({
    expected: {classification_version: 'product-v1', assignment_version: 1, plan_version: 'plan-x', matrix: {claude: {exit: 'A'}}},
    environment_ref: ENV,
  }, {
    core: {
      getConnections: () => transport.getConnections(),
      getTraffic: () => transport.getTraffic(),
      getLogs: () => transport.getLogs(),
    },
    protection: {async requestProtection(command) { return {status: 'CONFIRMED', requested: true, new_connections_restricted: true, os_readback: 'APPLIED', existing_closed: true}; }},
  });
  assert.equal(consumed.events.some((event) => event.classification === 'WRONG_ROUTE'), true);
  assert.equal(consumed.protections[0].protection.requested, true);
});
