import {guardedFetch} from './fetchPolicy.mjs';

export function createProbeAdapter({state, fetchImpl, baseUrl, timeoutMs = 5000} = {}) {
  return {
    configured: Boolean(fetchImpl && baseUrl),
    async createSession({signal} = {}) {
      const response = await guardedFetch(fetchImpl, `${baseUrl}/v1/session`, {method: 'POST', signal, timeoutMs});
      const body = response.json || {};
      if (!response.ok || !body.token) {
        throw Object.assign(new Error('Probe 未返回 token'), {code: response.ok ? 'PROBE_NO_TOKEN' : (response.code || 'REQUEST_FAILED')});
      }
      state.session = body;
      return body;
    },
    async observe({signal} = {}) {
      const response = await guardedFetch(fetchImpl, `${baseUrl}/v1/observe?session=${encodeURIComponent(state.session.token)}`, {signal, timeoutMs});
      return response.json;
    },
    async observeDns({signal} = {}) {
      if (!state.session?.token) await this.createSession({signal});
      if (!state.session?.token) return {observed: false};
      const response = await guardedFetch(fetchImpl, `${baseUrl}/v1/session/${encodeURIComponent(state.session.token)}/dns`, {signal, timeoutMs});
      if (!response.ok) return {observed: false, status: 'REQUEST_FAILED', http_status: response.status};
      return response.json || {observed: false};
    },
  };
}
