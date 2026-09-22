export function nowIso(clock) {
  if (typeof clock === 'function') {
    const value = clock();
    if (typeof value === 'string') return value;
    if (typeof value === 'number') return new Date(value).toISOString();
    if (value instanceof Date) return value.toISOString();
  }
  return new Date().toISOString();
}

export function toMillis(value) {
  if (value == null) return NaN;
  if (typeof value === 'number') return value;
  const millis = Date.parse(value);
  return Number.isFinite(millis) ? millis : NaN;
}

export function isExpired(expiresAt, now) {
  if (!expiresAt) return false;
  const end = toMillis(expiresAt);
  const current = toMillis(now);
  if (!Number.isFinite(end) || !Number.isFinite(current)) return false;
  return current >= end;
}
