import {createEchoAdapter} from './echo.mjs';
import {createProbeAdapter} from './probe.mjs';

function jsonResponse(status, body) {
  return {
    status,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
  };
}

export function createDiagnosticWorld(options = {}) {
  const state = {
    echoIp: options.echoIp || '203.0.113.10',
    expectedA: options.expectedA || '203.0.113.10',
    expectedB: options.expectedB || '203.0.113.20',
    intelListed: options.intelListed === true,
    intelMissing: options.intelMissing === true,
    intelFailed: options.intelFailed === true,
    dnsCaptured: options.dnsCaptured !== false,
    dnsResolver: options.dnsResolver || '192.0.2.53',
    expectedDnsResolvers: options.expectedDnsResolvers || [],
    dohIp: options.dohIp || (options.dnsViolation ? '198.51.100.9' : (options.expectedA || '203.0.113.10')),
    ipv6: options.ipv6 || {status: 'NO_RESULT'},
    bypass: options.bypass === true,
    forbiddenOpen: options.forbiddenOpen === true,
    protection: options.protection || {status: 'CONFIRMED', new_connections_restricted: true},
    chainUnavailable: options.chainUnavailable === true,
    timezone: options.timezone || 'America/Los_Angeles',
    httpStatus: options.httpStatus || 200,
    ja3: options.ja3 || null,
    requests: [],
    sessions: new Map(),
    ...options.extra,
  };
  return {
    state,
    fetchImpl: async (url, init = {}) => {
      state.requests.push({url: String(url), method: init.method || 'GET', at: Date.now()});
      if (String(url).includes('/ip') || String(url).includes('echo')) {
        return jsonResponse(200, {ip: state.echoIp, country: 'United States', country_code: 'US', asn: 'AS64500', org: 'SYNTHETIC-A'});
      }
      if (String(url).includes('intel')) {
        if (state.intelFailed) return jsonResponse(503, {error: true});
        if (state.intelMissing) return jsonResponse(200, {});
        return jsonResponse(200, {listed: state.intelListed, tags: state.intelListed ? ['proxy'] : []});
      }
      if (String(url).includes('/dns-query') || String(url).includes('doh')) {
        return jsonResponse(200, {Status: 0, Answer: [{name: 'api.anthropic.com.', type: 1, data: state.dohIp}]});
      }
      if (String(url).endsWith('/v1/session') && (init.method || 'GET') === 'POST') {
        const token = `probe-${state.sessions.size + 1}`;
        const session = {token, dns_name: 'once.synthetic.invalid.', expires_in: 30};
        state.sessions.set(token, session);
        return jsonResponse(200, session);
      }
      if (String(url).includes('/v1/observe')) {
        return jsonResponse(200, {ip: state.echoIp, country_code: 'US', asn: 'AS64500', organization: 'SYNTHETIC'});
      }
      if (String(url).includes('/dns')) {
        return jsonResponse(200, {observed: state.dnsCaptured, resolver_ip: state.dnsCaptured ? state.dnsResolver : null, country_code: state.dnsCaptured ? 'US' : null});
      }
      if (String(url).includes('claude') || String(url).includes('anthropic')) {
        return jsonResponse(state.httpStatus, {ok: state.httpStatus === 200});
      }
      return jsonResponse(404, {message: 'unknown'});
    },
  };
}

export function createDiagnosticPorts(world, extra = {}) {
  const echo = createEchoAdapter({fetchImpl: world.fetchImpl, url: extra.echoUrl || 'https://echo.synthetic.invalid/ip'});
  const intel = {url: extra.intelUrl || 'https://intel.synthetic.invalid/lookup', fetch: world.fetchImpl};
  const doh = {url: extra.dohUrl || 'https://dns.synthetic.invalid/dns-query', fetch: world.fetchImpl};
  const probeState = {};
  const probe = createProbeAdapter({state: probeState, fetchImpl: world.fetchImpl, baseUrl: extra.probeBaseUrl || 'https://probe.synthetic.invalid'});
  return {
    echo: extra.echo || echo,
    intel: extra.intel || intel,
    doh: extra.doh || doh,
    probe: extra.probe || probe,
    ipv6: world.state.ipv6,
    navigator: extra.navigator || {
      language: 'en-US',
      languages: ['en-US'],
      userAgent: 'synthetic-chrome',
      onLine: true,
      hardwareConcurrency: 8,
      cookieEnabled: true,
    },
    clientKind: extra.clientKind || 'chrome',
    fingerprint: extra.fingerprint || {
      canvas: {fillText() {}, toDataURL: () => 'data:image/png;base64,AAA'},
      webgl: {VENDOR: 0x1F00, RENDERER: 0x1F01, getParameter: (key) => (key === 0x1F00 ? 'synthetic' : 'renderer')},
      audio: {getChannelData: () => [0.1, 0.2, 0.3]},
      screen: {width: 1920, height: 1080, colorDepth: 24, devicePixelRatio: 1},
    },
    peerConnection: extra.peerConnection || null,
    iceServers: extra.iceServers || [],
    claudeHttp: {url: 'https://api.anthropic.com/'},
    claude: extra.claude || {
      async dns({signal} = {}) {
        const response = await world.fetchImpl('https://dns.synthetic.invalid/dns-query', {signal});
        return {status: 'OBSERVED', ms: 12, http_status: response.status};
      },
      async connect({signal} = {}) {
        const response = await world.fetchImpl('https://api.anthropic.com/', {signal});
        return {status: response.status >= 500 ? 'FAILED' : 'OBSERVED', ms: 40, http_status: response.status};
      },
      async tls({signal} = {}) {
        const response = await world.fetchImpl('https://api.anthropic.com/', {signal});
        return {status: 'OBSERVED', alpn: 'h2', certificate_digest: 'abc', ja3: world.state.ja3, source: 'tool', http_status: response.status};
      },
      async http({signal} = {}) {
        const response = await world.fetchImpl('https://api.anthropic.com/', {signal});
        return {status: 'OBSERVED', status_code: response.status, ms: 80};
      },
    },
    intl: extra.intl || {
      DateTimeFormat: class {
        resolvedOptions() { return {timeZone: world.state.timezone || 'America/Los_Angeles', locale: 'en-US', calendar: 'gregory', numberingSystem: 'latn'}; }
      },
      NumberFormat: class {
        formatToParts() { return [{type: 'decimal', value: '.'}, {type: 'group', value: ','}]; }
      },
    },
    networkState: extra.networkState || {
      status: 'AVAILABLE',
      core: 'RUNNING',
      protection: world.state.protection,
      chain_unavailable: world.state.chainUnavailable,
    },
    system: extra.system || {dns: {servers: ['10.0.0.1'], status: 'DECLARED'}},
    settings: extra.settings || createSettingsPort(),
  };
}

export function createSettingsPort() {
  const values = new Map();
  return {
    async read(key) { return values.get(key) ?? null; },
    async apply(key, value) {
      values.set(key, value);
      return {ok: true, key, value};
    },
  };
}
