export function createHandlerTransport({handler, sessionToken, dropResponse} = {}) {
  if (!handler?.handle || typeof sessionToken !== 'string') throw new Error('handler and opaque session token are required');
  return {
    async turn(payload, {signal} = {}) {
      const request = new Request('https://application.synthetic.invalid/api/ai/turn', {
        method: 'POST',
        headers: {'content-type': 'application/json', authorization: `Bearer ${sessionToken}`},
        body: JSON.stringify(payload),
        signal,
      });
      const response = await handler.handle(request);
      const body = await response.json();
      if (dropResponse?.(body)) throw Object.assign(new Error('synthetic response loss after server completion'), {code: 'AI_TRANSPORT_UNKNOWN'});
      if (!response.ok) throw Object.assign(new Error(body.reason || 'control transport failed'), {code: body.code || 'AI_TRANSPORT_UNKNOWN', status: response.status});
      return body;
    },
  };
}
