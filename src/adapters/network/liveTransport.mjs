import {
  decodeConnectionsSnapshot,
  decodeDeleteConnections,
  decodeGetConfigs,
  decodeGetProxies,
  decodeGetRules,
  decodeGetVersion,
  decodeLogLine,
  decodePutConfigs,
  decodeTrafficSample,
  encodeDeleteConnections,
  encodeGet,
  encodePutConfigs,
  encodeWsUrl,
} from './mihomoProtocol.mjs';

function rejectLive() {
  return Object.assign(new Error('live Mihomo transport is not configured; default 9090 and existing pipes are never used'), {code: 'CORE_UNAVAILABLE'});
}

function unavailable() {
  const deny = async () => { throw rejectLive(); };
  async function* denyStream() { throw rejectLive(); }
  return {
    kind: 'live',
    status: 'unavailable',
    reason: 'LIVE_TRANSPORT_NOT_CONFIGURED',
    putConfigs: deny,
    getConfigs: deny,
    getRules: deny,
    getProxies: deny,
    getVersion: deny,
    getConnections: deny,
    getTraffic: deny,
    getLogs: deny,
    streamTraffic: denyStream,
    streamLogs: denyStream,
    deleteConnections: deny,
  };
}

async function* iterateNdjson(text) {
  for (const line of String(text || '').split(/\n+/)) {
    if (line.trim()) yield line.trim();
  }
}

export function createLiveMihomoTransport({baseUrl, secret, fetchImpl, webSocketImpl} = {}) {
  if (!baseUrl || !fetchImpl) return unavailable();
  if (/^https?:\/\/(127\.0\.0\.1|localhost):9090\b/i.test(baseUrl)) {
    throw Object.assign(new Error('refusing the default Mihomo controller address'), {code: 'CORE_UNAVAILABLE'});
  }

  async function send(encoded) {
    const response = await fetchImpl(new URL(encoded.url, baseUrl), {
      method: encoded.method,
      headers: encoded.headers,
      body: encoded.body ? JSON.stringify(encoded.body) : undefined,
    });
    const text = response.status === 204 ? null : await response.text();
    return {status: response.status, body: text};
  }

  async function* streamPath(path, decode, {query} = {}) {
    if (webSocketImpl) {
      const url = encodeWsUrl(path, {baseUrl, secret});
      const socket = webSocketImpl(url);
      if (socket?.[Symbol.asyncIterator]) {
        for await (const frame of socket) yield decode(frame);
        return;
      }
    }
    const response = await send(encodeGet(path, {secret, query}));
    for await (const line of iterateNdjson(response.body)) yield decode(line);
  }

  return {
    kind: 'live',
    status: 'configured',
    async putConfigs(input) { return decodePutConfigs(await send(encodePutConfigs({...input, secret}))); },
    async loadConfig({yaml, force = true} = {}) { return decodePutConfigs(await send(encodePutConfigs({payload: yaml, force, secret}))); },
    async getConfigs() { return decodeGetConfigs(await send(encodeGet('/configs', {secret}))); },
    async getRules() { return decodeGetRules(await send(encodeGet('/rules', {secret}))); },
    async getProxies() { return decodeGetProxies(await send(encodeGet('/proxies', {secret}))); },
    async getVersion() { return decodeGetVersion(await send(encodeGet('/version', {secret}))); },
    async getConnections() {
      const decoded = decodeConnectionsSnapshot(await send(encodeGet('/connections', {secret})));
      return {
        http_status: decoded.http_status,
        downloadTotal: decoded.downloadTotal,
        uploadTotal: decoded.uploadTotal,
        memory: decoded.memory,
        connections: decoded.connections,
      };
    },
    async *streamTraffic() {
      yield* streamPath('/traffic', decodeTrafficSample);
    },
    async getTraffic() {
      const first = await this.streamTraffic().next();
      return first.value || decodeTrafficSample(null);
    },
    async *streamLogs({level} = {}) {
      yield* streamPath('/logs', (line) => decodeLogLine(line), {query: level ? {level} : undefined});
    },
    async getLogs({level} = {}) {
      const lines = [];
      for await (const line of this.streamLogs({level})) lines.push(line);
      return {lines};
    },
    async deleteConnections(id) { return decodeDeleteConnections(await send(encodeDeleteConnections({id, secret}))); },
  };
}
