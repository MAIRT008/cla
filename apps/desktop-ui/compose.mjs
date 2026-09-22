import {mkdir, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {createWorkspaceAdapter} from '../../src/adapters/local/workspace.mjs';
import {createSyntheticLocalService} from '../../src/adapters/local/index.mjs';
import {createSyntheticFixture, SYNTHETIC_ENVIRONMENT} from '../../tests/local/demo.mjs';
import {createDiagnosticPorts, createDiagnosticWorld} from '../../src/adapters/diagnostics/index.mjs';
import {createDiagnosticsController} from '../../src/core/diagnostics/index.mjs';
import {createDefaultBrowserDiagnostics} from '../../src/adapters/diagnostics/defaultBrowser.mjs';
import {createSyntheticBrowserHost} from '../../tests/diagnostics/browserHost.mjs';
import {createFakePeer} from '../../fixtures/diagnostics/harness.mjs';
import {
  createControlPort,
  createCoreFixture,
  createEmergencyHostFixture,
  createEventDeliveryFixture,
  createProtectionFixture,
  createVerifyFixture,
} from '../../src/adapters/network/index.mjs';
import {createNetworkController} from '../../src/core/network/index.mjs';
import {createApplicationControl, createControlAuth, createControlServices, createControlStore, createRemnawaveQuotaAdapter, seedControlNetwork} from '../../services/control/index.mjs';
import {createAuthoritySim} from '../../fixtures/control/authoritySim.mjs';
import {createRemnawaveFakeTransport} from '../../fixtures/control/remnawaveTransport.mjs';
import {auth, ENV, threeUsers} from '../../fixtures/network/harness.mjs';
import {runAuditPipeline} from '../../src/core/audit/index.mjs';
import {FixtureAuditStore} from '../../src/adapters/audit/fixtureStore.mjs';
import {createUiModelScript, createUnavailableModelScript} from '../../fixtures/ui/aiModelScript.mjs';
import {loadAiNotes, loadAuditReports} from '../../src/adapters/audit/reports.mjs';

export {loadAiNotes, loadAuditReports};
import {createAiClient} from '../../src/core/ai/index.mjs';
import {createHandlerTransport} from '../../src/core/ai/controlTransport.mjs';

const PREF_KEYS = Object.freeze(['steward-theme', 'steward-lang']);

export function preferenceKeys() {
  return PREF_KEYS;
}

const AUDIT_ROOT = 'audit';
const REPORT_ROOT = 'reports';
const ROUTE_MAPPING = {version: 'legacy-v2', fixedA: {route: 'CLAUDE-FIXED', member: 'COX-Fixed-Chain'}};
const DECLARED_ENVIRONMENTS = Object.freeze([
  {environment_ref: 'synthetic-windows', kind: 'host'},
  {environment_ref: 'wsl-synthetic', kind: 'wsl', reason: 'GUEST_NOT_AUTHORIZED_FOR_THIS_SCAN'},
]);
const HISTORY_LINE = 'time="2026-09-12T15:00:00Z" [TCP] (claude.exe) --> api.anthropic.com:443 using CLAUDE-FIXED[COX-Fixed-Chain]';
const CURRENT_LINE = 'time="2026-09-13T12:00:00Z" [TCP] dial DIRECT (match DomainSuffix/anthropic.com) (claude.exe) --> api.anthropic.com:443 error: retry using CLAUDE-FIXED[COX-Fixed-Chain] timeout';

/**
 * 主机与客体各有自己的探测世界与端口：出口回声、DNS 解析器、探测基址和客户端形态都不同，
 * 换环境扫描时被测对象真的换掉，而不是给同一份证据改个标签。
 */
function createEnvironmentProbes(environmentRef, kind = 'host') {
  if (kind === 'host') {
    const world = createDiagnosticWorld({echoIp: '198.51.100.8', expectedA: '203.0.113.10', expectedB: '203.0.113.20'});
    return {world, ports: createDiagnosticPorts(world, {peerConnection: createFakePeer()})};
  }
  const world = createDiagnosticWorld({
    echoIp: '198.51.100.24',
    expectedA: '203.0.113.10',
    expectedB: '203.0.113.20',
    dnsResolver: '192.0.2.61',
  });
  const ports = createDiagnosticPorts(world, {
    peerConnection: null,
    clientKind: 'wsl-cli',
    echoUrl: `https://echo-${environmentRef}.synthetic.invalid/ip`,
    dohUrl: `https://dns-${environmentRef}.synthetic.invalid/dns-query`,
    probeBaseUrl: `https://probe-${environmentRef}.synthetic.invalid`,
    navigator: {
      language: 'en-US',
      languages: ['en-US'],
      userAgent: `synthetic-${environmentRef}-cli`,
      onLine: true,
      hardwareConcurrency: 4,
      cookieEnabled: false,
    },
  });
  return {world, ports};
}

function auditRequest(now, trafficState, samples) {
  return {
    now,
    timezone: 'America/Los_Angeles',
    sourceRoot: 'source',
    archiveRoot: 'archive',
    approvedSourceNames: ['service_latest.log'],
    mapping: ROUTE_MAPPING,
    trafficState,
    trafficSamples: samples,
    quota: {source: 'server', status: 'ACTIVE', usedBytes: 30, limitBytes: 250000000000, observedAt: now},
    protection: {status: 'CONFIRMED'},
    collectionEvidence: {
      environmentRef: ENV,
      continuous: false,
      gaps: [{code: 'COLLECTOR_WINDOW_INCOMPLETE'}],
      environments: DECLARED_ENVIRONMENTS.map((item) => ({...item})),
    },
    reportRoot: REPORT_ROOT,
  };
}

async function buildAuditArtifacts(auditStore) {
  await auditStore.writeText('source/service_latest.log', HISTORY_LINE, {overwrite: false});
  const history = await runAuditPipeline(auditRequest(
    '2026-09-12T16:00:00.000Z',
    {totals: {uploadBytes: 0, downloadBytes: 0}, observations: {}, coverageIssues: []},
    [{sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-1', uploadBytes: 4_000_000, downloadBytes: 22_000_000, observedAt: '2026-09-12T15:30:00Z'}],
  ), auditStore);
  await auditStore.writeText('source/service_latest.log', [HISTORY_LINE, CURRENT_LINE].join('\n'), {overwrite: true});
  const current = await runAuditPipeline(auditRequest(
    '2026-09-13T16:00:00.000Z',
    history.evidence.trafficState,
    [{sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-1', uploadBytes: 16_000_000, downloadBytes: 88_000_000, observedAt: '2026-09-13T15:30:00Z'}],
  ), auditStore);
  return current;
}

export async function createDesktopComposition(label = 'ui', options = {}) {
  const root = options.root || transientRun('ui', label);
  const mounting = options.mountExistingRoot === true;
  if (!mounting) await createSyntheticFixture(root);
  await mkdir(path.join(root, 'state'), {recursive: true});
  let now = options.now || '2026-09-13T17:00:00.000Z';
  const clock = () => now;
  clock.set = (value) => { now = value; };

  const store = createWorkspaceAdapter({workspaceRoot: root, clock});
  if (options.executeStepDelayMs) {
    for (const method of ['writeBackup', 'beginDirectoryIsolation']) {
      const original = store[method]?.bind(store);
      if (!original) continue;
      store[method] = async (...args) => {
        await new Promise((resolve) => setTimeout(resolve, options.executeStepDelayMs));
        return original(...args);
      };
    }
  }
  const local = createSyntheticLocalService({workspaceRoot: root, environment: SYNTHETIC_ENVIRONMENT, adapter: store, clock, capabilities: options.localCapabilities || {}});

  const users = options.users || [
    {user_ref: 'user-max', status: 'ACTIVE', role: 'user'},
    {user_ref: 'user-pro', status: 'ACTIVE', role: 'user'},
    {user_ref: 'user-free', status: 'ACTIVE', role: 'user'},
    {user_ref: 'admin', status: 'ACTIVE', role: 'admin'},
  ];
  const sessions = options.sessions || [
    {session_ref: 's-max', user_ref: 'user-max', token: 'token-max', expires_at: '2030-01-01T00:00:00.000Z'},
    {session_ref: 's-pro', user_ref: 'user-pro', token: 'token-pro', expires_at: '2030-01-01T00:00:00.000Z'},
    {session_ref: 's-free', user_ref: 'user-free', token: 'token-free', expires_at: '2030-01-01T00:00:00.000Z'},
    {session_ref: 's-admin', user_ref: 'admin', token: 'token-admin', expires_at: '2030-01-01T00:00:00.000Z', role: 'admin'},
  ];
  const controlStore = createControlStore({databasePath: path.join(root, 'state', 'control.sqlite'), users, sessions});
  if (!mounting) seedControlNetwork(controlStore, threeUsers());
  const authority = options.authority || createAuthoritySim({clock});
  const remnawaveFetch = options.remnawaveFetch || createRemnawaveFakeTransport(authority, {baseUrl: 'https://remnawave.synthetic.invalid'});
  const quotaAdapter = createRemnawaveQuotaAdapter({
    baseUrl: 'https://remnawave.synthetic.invalid',
    token: authority.token,
    fetchImpl: remnawaveFetch,
    clock,
  });
  const controlServices = createControlServices({store: controlStore, quotaAdapter, clock, fetchImpl: remnawaveFetch});
  const core = options.core || createCoreFixture();
  const protection = options.protection || createProtectionFixture();
  const verify = options.verify || createVerifyFixture();
  const emergencyHost = options.emergencyHost || createEmergencyHostFixture();
  const events = options.events || createEventDeliveryFixture();
  const control = createControlPort({store: controlStore, clock});
  const network = createNetworkController({
    store,
    control,
    core,
    protection,
    verify,
    emergencyHost,
    events,
    clock,
    secrets: {resolve: (ref) => (ref ? {username: `synth-${ref}`, password: `synth-pass-${ref}`} : null)},
  });

  const declaredEnvironments = options.environments || DECLARED_ENVIRONMENTS.map((item) => ({...item}));
  const environmentProbes = new Map(declaredEnvironments.map((item) => [item.environment_ref, createEnvironmentProbes(item.environment_ref, item.kind)]));
  if (!environmentProbes.has(ENV)) environmentProbes.set(ENV, createEnvironmentProbes(ENV, 'host'));
  const {world, ports} = environmentProbes.get(ENV);
  const assignment = {
    user_ref: 'user-max',
    environment_ref: ENV,
    assignment_version: 1,
    roles: {A: 'res-a-max', B: 'res-b-max'},
    resources: {
      'res-a-max': {public_ip: '203.0.113.10', role: 'A'},
      'res-b-max': {public_ip: '203.0.113.20', role: 'B'},
    },
    expected_exits: {A: '203.0.113.10', B: '203.0.113.20'},
    expected_timezone: 'America/Los_Angeles',
    expected_utc_offset_minutes: -420,
  };
  const diagnostics = createDiagnosticsController({
    store,
    ports,
    clock,
    world,
    network,
    assignment,
    environmentRef: ENV,
    environments: declaredEnvironments,
    environmentPorts: (ref) => environmentProbes.get(ref) || null,
  });
  // 合成组合根没有真实宿主：「默认浏览器」是在合成浏览器里执行同一份诊断页，校验走同一条核心路径。
  const syntheticBrowser = createSyntheticBrowserHost({
    hostEnvironment: ENV,
    clock,
    browser: options.defaultBrowser || {timezone: 'America/Los_Angeles', utc_offset_minutes: -420, locale: 'en-US', candidates: []},
  });
  const browserDiag = createDefaultBrowserDiagnostics({invoke: syntheticBrowser.invoke, diagnostics});

  const modelPolicies = Object.fromEntries(['cleanup', 'network_diagnosis', 'daily_analysis'].map((taskType) => [taskType, {
    status: options.aiAvailable === false ? 'UNAVAILABLE' : 'AVAILABLE',
    version: `policy-${taskType}-v1`,
    secret_ref: 'synthetic-secret',
    base_url: 'https://synthetic-model.invalid/v1',
    model: 'synthetic-server-selected-model',
    timeoutMs: 60000,
  }]));
  const controlAuth = createControlAuth({store: controlStore, clock});
  const auditStore = new FixtureAuditStore(path.join(root, AUDIT_ROOT));
  if (!mounting) await buildAuditArtifacts(auditStore);
  const auditReports = await loadAuditReports(auditStore);
  const currentReport = auditReports.at(-1) || null;
  const modelOutbound = [];
  const handler = createApplicationControl({
    store: controlStore,
    modelPolicies,
    secrets: {resolve: () => 'SYNTHETIC_SERVER_KEY'},
    sdkFetch: options.sdkFetch
      || (options.aiFailure === true ? createUnavailableModelScript() : createUiModelScript({reportId: () => currentReport?.report?.reportId || null, outbound: modelOutbound})),
    clock,
    quotaAdapter,
    fetchImpl: remnawaveFetch,
  });
  function createAi({sessionToken, userRef} = {}) {
    if (options.aiAvailable === false || !sessionToken || !userRef) return null;
    return createAiClient({
      localService: local,
      localStore: store,
      auditStore,
      controlTransport: createHandlerTransport({handler, sessionToken}),
      networkPort: network.asAiPort?.(userRef),
      diagnostics,
      ...(options.aiBudgets ? {budgets: options.aiBudgets} : {}),
    });
  }

  return {
    root,
    clock,
    store,
    local,
    network,
    diagnostics,
    browserDiag,
    syntheticBrowser,
    controlStore,
    handler,
    controlServices,
    authority,
    quotaAdapter,
    createAi,
    networkControl: control,
    core,
    protection,
    verify,
    emergencyHost,
    events,
    world,
    ports,
    env: ENV,
    async writeExport(name, text) {
      const dir = path.join(root, 'exports');
      await mkdir(dir, {recursive: true});
      const target = path.join(dir, name);
      await writeFile(target, text, 'utf8');
      return target;
    },
    environments: declaredEnvironments,
    environmentProbes,
    auditStore,
    auditReportRoot: REPORT_ROOT,
    auditReports,
    daily: currentReport?.report || null,
    dailyPaths: currentReport ? {json: currentReport.path, markdown: currentReport.path.replace(/\.json$/, '.md')} : null,
    modelOutbound,
    auth: (userRef, extra = {}) => auth(userRef, {expires_at: '2030-01-01T00:00:00.000Z', ...extra}),
    disconnected: options.disconnected === true,
    aiAvailable: options.aiAvailable !== false,
    aiFailure: options.aiFailure === true,
    mounted: mounting,
    nativeBridge: options.nativeBridge !== false,
    scanDelayMs: options.scanDelayMs || 0,
    executeStepDelayMs: options.executeStepDelayMs || 0,
    sessionToken: options.sessionToken || 'token-max',
    controlAuth,
    close() {
      controlStore.close?.();
    },
  };
}
