function fail(code, reason) {
  return Object.assign(new Error(reason), {code});
}

export function createEchoAdapter({fetchImpl, url, serviceRef = 'echo-v1', timeoutMs = 5000, maxBytes = 8192} = {}) {
  return {
    service_ref: serviceRef,
    url,
    timeoutMs,
    maxBytes,
    configured: Boolean(fetchImpl && url),
    async fetch(target, {signal} = {}) {
      if (!fetchImpl) throw fail('SERVICE_NOT_CONFIGURED', 'echo service is not configured');
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      if (signal) {
        if (signal.aborted) ac.abort();
        else signal.addEventListener('abort', () => ac.abort(), {once: true});
      }
      try {
        if (ac.signal.aborted) throw fail(signal?.aborted ? 'CANCELLED' : 'ECHO_TIMEOUT', 'echo request aborted');
        const aborted = new Promise((_, reject) => {
          ac.signal.addEventListener('abort', () => reject(fail(signal?.aborted ? 'CANCELLED' : 'ECHO_TIMEOUT', 'echo request aborted')), {once: true});
        });
        const response = await Promise.race([
          fetchImpl(target || url, {method: 'GET', headers: {accept: 'application/json'}, signal: ac.signal}),
          aborted,
        ]);
        const status = Number(response.status) || 0;
        const raw = typeof response.text === 'function' ? await Promise.race([response.text(), aborted]) : String(response.body || '');
        if (raw.length > maxBytes) return {ok: false, status, code: 'BODY_TOO_LARGE', text: async () => '', body: ''};
        if (status >= 400) return {ok: false, status, code: 'HTTP_ERROR', text: async () => raw, body: raw};
        return {ok: true, status, text: async () => raw, body: raw};
      } catch (error) {
        if (error?.code === 'CANCELLED' || signal?.aborted) throw fail('CANCELLED', 'echo cancelled');
        if (error?.code === 'ECHO_TIMEOUT' || error?.name === 'AbortError') throw fail('ECHO_TIMEOUT', 'echo timed out');
        throw error;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
