export function fail(code, message, extra = {}) {
  const error = Object.assign(new Error(message), {code, ...extra});
  return error;
}

export function reject(code, message, extra = {}) {
  throw fail(code, message, extra);
}

export function resultError(code, message, extra = {}) {
  return {ok: false, status: 'FAILED', code, reason: message, ...extra};
}
