function fail(code, reason) {
  return Object.assign(new Error(reason), {code});
}

export async function guardedFetch(fetchImpl, url, {method = 'GET', signal, timeoutMs = 5000, maxBytes = 8192} = {}) {
  if (!fetchImpl) throw fail('SERVICE_NOT_CONFIGURED', 'fetch is not configured');
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  if (signal) {
    if (signal.aborted) ac.abort();
    else signal.addEventListener('abort', () => ac.abort(), {once: true});
  }
  try {
    if (ac.signal.aborted) throw fail(signal?.aborted ? 'CANCELLED' : 'TIMEOUT', 'request aborted');
    const aborted = new Promise((_, reject) => {
      ac.signal.addEventListener('abort', () => reject(fail(signal?.aborted ? 'CANCELLED' : 'TIMEOUT', 'request aborted')), {once: true});
    });
    const response = await Promise.race([fetchImpl(url, {method, signal: ac.signal}), aborted]);
    const status = Number(response.status) || 0;
    const raw = typeof response.text === 'function'
      ? await Promise.race([response.text(), aborted])
      : String(response.body || '');
    if (raw.length > maxBytes) return {ok: false, status, code: 'BODY_TOO_LARGE', body: '', json: null};
    let json = null;
    try { json = raw ? JSON.parse(raw) : null; } catch { json = null; }
    if (status >= 400) return {ok: false, status, code: 'HTTP_ERROR', body: raw, json};
    return {ok: true, status, body: raw, json};
  } catch (error) {
    if (error?.code === 'CANCELLED' || signal?.aborted) throw fail('CANCELLED', 'request cancelled');
    if (error?.code === 'TIMEOUT' || error?.name === 'AbortError') throw fail('TIMEOUT', 'request timed out');
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
