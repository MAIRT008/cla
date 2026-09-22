import {CATEGORIES, CHECKS, PROOF_SIMULATION} from './constants.mjs';
import {parseDoHJSON, parsePublicIPBody, parseTlsInfo, timezoneMatch} from './parse.mjs';
import {collectPlatform} from './platform.mjs';
import {collectFingerprint} from './fingerprint.mjs';
import {collectIce} from './webrtc.mjs';
import {guardedFetch} from '../../adapters/diagnostics/fetchPolicy.mjs';

function iso(clock) {
  const value = typeof clock === 'function' ? clock() : Date.now();
  return typeof value === 'string' ? value : new Date(value).toISOString();
}

function observation(base) {
  return {
    task_id: base.task_id,
    check_id: base.check_id,
    evidence_ref: base.evidence_ref,
    environment_ref: base.environment_ref,
    client_ref: base.client_ref || null,
    profile_ref: base.profile_ref || null,
    observed_at: base.observed_at,
    source: base.source,
    source_version: base.source_version || null,
    kind: base.kind,
    target: base.target || null,
    expected: base.expected ?? null,
    actual: base.actual ?? null,
    status: base.status,
    limitation: base.limitation || null,
    proof_scope: PROOF_SIMULATION,
  };
}

export function checksFor(mode, selected) {
  if (mode === 'special') return (selected || []).filter((item) => CATEGORIES.includes(item));
  return CHECKS[mode] || CHECKS.deep;
}

export async function collectCategory(category, ctx) {
  const {ports, assignment, expected, clock, requests, task_id, environment_ref, client_ref, profile_ref, signal} = ctx;
  if (signal?.aborted) throw Object.assign(new Error('scan cancelled'), {code: 'CANCELLED'});
  const observedAt = iso(clock);
  if (category === 'exit_ip') return collectExit(ctx, observedAt);
  if (category === 'multipath') return collectMultipath(ctx, observedAt);
  if (category === 'browser') return collectBrowser(ctx, observedAt);
  if (category === 'fingerprint') return collectFp(ctx, observedAt);
  if (category === 'claude_tls') return collectClaude(ctx, observedAt);
  if (category === 'kernel') return collectKernel(ctx, observedAt);
  return {category, observations: [], issues: [], keyChecks: []};
}

async function collectExit(ctx, observedAt) {
  const {ports, expected, requests, task_id, environment_ref, assignment} = ctx;
  const service = ports.echo;
  const observations = [];
  const keyChecks = [{check_id: 'expected-ab', required: true, status: expected?.A ? 'PRESENT' : 'MISSING'}];
  if (!service?.fetch) {
    observations.push(observation({
      task_id, check_id: 'exit.echo', evidence_ref: `${task_id}:exit:unconfigured`, environment_ref,
      observed_at: observedAt, source: 'echo', kind: 'external_intel', status: 'SERVICE_NOT_CONFIGURED', limitation: 'ECHO_UNCONFIGURED',
    }));
    return {category: 'exit_ip', observations, keyChecks};
  }
  const url = service.url || 'https://echo.synthetic.invalid/ip';
  requests.push({at: observedAt, method: 'GET', url, category: 'exit_ip'});
  const response = await service.fetch(url, {signal: ctx.signal});
  if (response.ok === false || (Number(response.status) >= 400)) {
    observations.push(observation({
      task_id, check_id: 'exit.echo', evidence_ref: `${task_id}:exit:echo`, environment_ref,
      observed_at: observedAt, source: 'echo', kind: 'active', target: url, expected: {A: expected?.A || null, B: expected?.B || null}, actual: null,
      status: 'REQUEST_FAILED', limitation: response.code || `HTTP_${response.status}`,
    }));
    return {category: 'exit_ip', observations, keyChecks};
  }
  const parsed = parsePublicIPBody(typeof response.text === 'function' ? await response.text() : response.body);
  const actual = parsed.ok ? parsed.ip : null;
  observations.push(observation({
    task_id, check_id: 'exit.echo', evidence_ref: `${task_id}:exit:echo`, environment_ref,
    observed_at: observedAt, source: 'echo', kind: 'active', target: url, expected: {A: expected?.A || null, B: expected?.B || null}, actual,
    status: parsed.ok ? 'OBSERVED' : parsed.code, limitation: parsed.ok ? null : parsed.code,
  }));
  const intel = ports.intel;
  if (!intel?.fetch) {
    observations.push(observation({
      task_id, check_id: 'exit.intel', evidence_ref: `${task_id}:exit:intel`, environment_ref,
      observed_at: observedAt, source: 'intel', kind: 'external_intel', status: 'SERVICE_NOT_CONFIGURED', limitation: 'INTEL_UNCONFIGURED',
    }));
  } else if (actual) {
    requests.push({at: observedAt, method: 'GET', url: intel.url, category: 'exit_ip'});
    try {
      const intelRes = await guardedFetch(intel.fetch, `${intel.url}?ip=${encodeURIComponent(actual)}`, {signal: ctx.signal});
      const body = intelRes.json || {};
      const listed = body?.listed === true;
      const failed = !intelRes.ok || body?.error;
      const missing = !failed && body?.listed !== true && body?.listed !== false;
      observations.push(observation({
        task_id, check_id: 'exit.intel', evidence_ref: `${task_id}:exit:intel`, environment_ref,
        observed_at: observedAt, source: 'intel', kind: 'external_intel', actual: {listed, tags: body?.tags || [], failed, missing},
        status: failed ? 'REQUEST_FAILED' : missing ? 'NO_DATA' : listed ? 'LISTED' : 'NOT_LISTED',
      }));
    } catch (error) {
      if (error.code === 'CANCELLED') throw error;
      observations.push(observation({
        task_id, check_id: 'exit.intel', evidence_ref: `${task_id}:exit:intel`, environment_ref,
        observed_at: observedAt, source: 'intel', kind: 'external_intel', actual: {error: error.code || error.message},
        status: 'REQUEST_FAILED', limitation: error.code || 'INTEL_ERROR',
      }));
    }
  }
  return {category: 'exit_ip', observations, keyChecks, parsed};
}

async function collectMultipath(ctx, observedAt) {
  const {ports, requests, task_id, environment_ref} = ctx;
  const observations = [];
  const dnsConfigured = ports.system?.dns || {servers: [], status: 'UNAVAILABLE'};
  observations.push(observation({
    task_id, check_id: 'dns.config', evidence_ref: `${task_id}:dns:config`, environment_ref,
    observed_at: observedAt, source: 'system', kind: 'config', actual: dnsConfigured, status: dnsConfigured.servers?.length ? 'DECLARED' : 'UNAVAILABLE',
  }));
  if (ports.doh?.fetch) {
    requests.push({at: observedAt, method: 'GET', url: ports.doh.url, category: 'multipath'});
    try {
      const res = await guardedFetch(ports.doh.fetch, ports.doh.url, {signal: ctx.signal});
      if (!res.ok) {
        observations.push(observation({
          task_id, check_id: 'dns.doh', evidence_ref: `${task_id}:dns:doh`, environment_ref,
          observed_at: observedAt, source: 'doh', kind: 'active', actual: null, status: 'REQUEST_FAILED', limitation: res.code || `HTTP_${res.status}`,
        }));
      } else {
        const parsed = parseDoHJSON(res.json);
        observations.push(observation({
          task_id, check_id: 'dns.doh', evidence_ref: `${task_id}:dns:doh`, environment_ref,
          observed_at: observedAt, source: 'doh', kind: 'active', actual: parsed, status: parsed.ok ? 'OBSERVED' : parsed.code,
        }));
      }
    } catch (error) {
      if (error.code === 'CANCELLED') throw error;
      observations.push(observation({
        task_id, check_id: 'dns.doh', evidence_ref: `${task_id}:dns:doh`, environment_ref,
        observed_at: observedAt, source: 'doh', kind: 'active', actual: {error: error.code || error.message},
        status: 'REQUEST_FAILED', limitation: error.code || 'DOH_ERROR',
      }));
    }
  }
  const probe = ports.probe;
  if (probe?.observeDns) {
    try {
      const dns = await probe.observeDns({signal: ctx.signal});
      observations.push(observation({
        task_id, check_id: 'dns.probe', evidence_ref: `${task_id}:dns:probe`, environment_ref,
        observed_at: observedAt, source: 'probe', kind: 'active', actual: dns, status: dns.observed ? 'OBSERVED' : 'NOT_CAPTURED',
        limitation: dns.observed ? null : 'DNS_NOT_CAPTURED',
      }));
    } catch (error) {
      if (error.code === 'CANCELLED') throw error;
      observations.push(observation({
        task_id, check_id: 'dns.probe', evidence_ref: `${task_id}:dns:probe`, environment_ref,
        observed_at: observedAt, source: 'probe', kind: 'active', actual: {error: error.code || error.message},
        status: 'REQUEST_FAILED', limitation: error.code || 'PROBE_ERROR',
      }));
    }
  }
  const ice = await collectIce({peerConnection: ports.peerConnection, iceServers: ports.iceServers, clock: ctx.clock});
  observations.push(observation({
    task_id, check_id: 'webrtc.ice', evidence_ref: `${task_id}:webrtc`, environment_ref,
    observed_at: observedAt, source: 'webrtc', kind: 'active', actual: ice, status: ice.status,
    limitation: ice.limitation,
  }));
  const ipv6 = ports.ipv6 || {status: 'NO_RESULT'};
  observations.push(observation({
    task_id, check_id: 'ipv6.path', evidence_ref: `${task_id}:ipv6`, environment_ref,
    observed_at: observedAt, source: 'ipv6', kind: 'active', actual: ipv6, status: ipv6.status || 'NO_RESULT',
    limitation: ipv6.status === 'NO_RESULT' ? 'IPV6_NO_RESULT' : null,
  }));
  const keyChecks = [
    {check_id: 'dns-or-block', required: true, status: observations.some((item) => item.check_id.startsWith('dns.') && ['OBSERVED', 'NOT_CAPTURED', 'DECLARED'].includes(item.status)) ? 'PRESENT' : 'MISSING'},
    {check_id: 'webrtc-or-block', required: true, status: ice.status ? 'PRESENT' : 'MISSING'},
  ];
  return {category: 'multipath', observations, keyChecks};
}

async function collectBrowser(ctx, observedAt) {
  const {ports, task_id, environment_ref, profile_ref, expected} = ctx;
  const platform = collectPlatform({navigator: ports.navigator, intl: ports.intl, clock: ctx.clock});
  const match = timezoneMatch({
    iana: platform.timezone,
    offsetMinutes: platform.utc_offset_minutes,
    expectedIana: expected?.timezone,
    expectedOffsetMinutes: expected?.utc_offset_minutes,
  });
  const clientKind = ports.clientKind || 'chrome';
  return {
    category: 'browser',
    observations: [observation({
      task_id, check_id: 'browser.platform', evidence_ref: `${task_id}:browser:platform`, environment_ref, profile_ref,
      observed_at: observedAt, source: 'intl-navigator', kind: 'config', actual: {...platform, timezone_match: match, client_kind: clientKind},
      status: 'OBSERVED',
    })],
    keyChecks: [{check_id: 'selected-browser', required: true, status: profile_ref || ports.navigator ? 'PRESENT' : 'MISSING'}],
  };
}

async function collectFp(ctx, observedAt) {
  const {ports, task_id, environment_ref, profile_ref} = ctx;
  const fp = await collectFingerprint({...ports.fingerprint, clock: ctx.clock});
  return {
    category: 'fingerprint',
    observations: [observation({
      task_id, check_id: 'browser.fingerprint', evidence_ref: `${task_id}:fp`, environment_ref, profile_ref,
      observed_at: observedAt, source: 'web-api', kind: 'active', actual: fp, status: 'OBSERVED',
    })],
    keyChecks: [],
  };
}

async function invokeClaudeLayer(ports, layer, signal, requests, observedAt) {
  const fn = ports.claude?.[layer];
  if (typeof fn !== 'function') return {status: 'UNAVAILABLE', limitation: 'NO_IO'};
  const url = ports.claudeHttp?.url || `https://claude.synthetic.invalid/${layer}`;
  requests.push({at: observedAt, method: 'GET', url, category: 'claude_tls', layer});
  return fn({signal, url});
}

async function collectClaude(ctx, observedAt) {
  const {ports, requests, task_id, environment_ref, signal} = ctx;
  const observations = [];
  for (const layer of ['dns', 'connect', 'tls', 'http']) {
    const item = await invokeClaudeLayer(ports, layer, signal, requests, observedAt);
    if (layer === 'tls' && item && item.status !== 'UNAVAILABLE') item.tls = parseTlsInfo(item.tls || item);
    observations.push(observation({
      task_id, check_id: `claude.${layer}`, evidence_ref: `${task_id}:claude:${layer}`, environment_ref,
      observed_at: observedAt, source: 'claude-probe', kind: 'active', actual: item, status: item.status,
      limitation: item.limitation || (item.status === 'UNAVAILABLE' ? `${layer.toUpperCase()}_UNAVAILABLE` : null),
    }));
  }
  const http = observations.find((item) => item.check_id === 'claude.http')?.actual || {};
  if (http.status_code && [401, 403, 451].includes(http.status_code)) {
    observations.push(observation({
      task_id, check_id: 'claude.http-status', evidence_ref: `${task_id}:claude:http-status`, environment_ref,
      observed_at: observedAt, source: 'claude-probe', kind: 'active', actual: {status_code: http.status_code, account: 'NOT_INFERRED'},
      status: 'SERVICE_RESPONSE',
    }));
  }
  return {
    category: 'claude_tls',
    observations,
    keyChecks: [],
  };
}

async function collectKernel(ctx, observedAt) {
  const {ports, task_id, environment_ref} = ctx;
  const state = ports.networkState || {status: 'UNAVAILABLE'};
  const protection = state.protection || {};
  const observations = [observation({
    task_id, check_id: 'kernel.state', evidence_ref: `${task_id}:kernel`, environment_ref,
    observed_at: observedAt, source: 't5', kind: 'runtime', actual: state, status: state.core || state.status || 'UNAVAILABLE',
  })];
  const keyChecks = [
    {check_id: 'config-readable', required: true, status: state.status && state.status !== 'UNAVAILABLE' ? 'PRESENT' : 'MISSING'},
    {check_id: 'protection-readable', required: true, status: protection.status ? 'PRESENT' : 'MISSING'},
  ];
  return {category: 'kernel', observations, keyChecks};
}
