function offsetMinutes(clock) {
  const now = typeof clock === 'function' ? clock() : Date.now();
  const date = typeof now === 'string' ? new Date(now) : new Date(now);
  return -date.getTimezoneOffset();
}

export function collectPlatform({navigator = globalThis.navigator, intl, clock = () => Date.now()} = {}) {
  const dateIntl = intl?.DateTimeFormat ? new intl.DateTimeFormat() : new Intl.DateTimeFormat();
  const numberIntl = intl?.NumberFormat ? new intl.NumberFormat() : new Intl.NumberFormat();
  const resolved = dateIntl.resolvedOptions();
  const parts = numberIntl.formatToParts(12345.6);
  const nav = navigator || {};
  return {
    timezone: resolved.timeZone || '',
    utc_offset_minutes: offsetMinutes(clock),
    locale: nav.language || resolved.locale || '',
    system_locale: resolved.locale || nav.language || '',
    user_languages: Array.from(nav.languages || []),
    format_settings: {
      decimal: parts.find((part) => part.type === 'decimal')?.value || '',
      group: parts.find((part) => part.type === 'group')?.value || '',
      calendar: resolved.calendar,
      numbering_system: resolved.numberingSystem,
    },
    online: nav.onLine,
    hardware_concurrency: nav.hardwareConcurrency ?? null,
    device_memory_gb: nav.deviceMemory ?? null,
    user_agent: nav.userAgent || '',
    cookie_enabled: nav.cookieEnabled ?? null,
    proof_scope: 'simulation',
  };
}
