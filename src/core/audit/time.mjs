export const AUDIT_TIMEZONE = 'America/Los_Angeles';

function partsAt(value, timeZone = AUDIT_TIMEZONE) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`invalid timestamp: ${value}`);
  }
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  return Object.fromEntries(parts.filter((part) => part.type !== 'literal').map((part) => [part.type, part.value]));
}

export function localDateKey(value, timeZone = AUDIT_TIMEZONE) {
  const parts = partsAt(value, timeZone);
  return `${parts.year}-${parts.month}-${parts.day}`;
}

export function localHour(value, timeZone = AUDIT_TIMEZONE) {
  return Number(partsAt(value, timeZone).hour);
}

export function localTimestampKey(value, timeZone = AUDIT_TIMEZONE) {
  const parts = partsAt(value, timeZone);
  const millis = String(new Date(value).getUTCMilliseconds()).padStart(3, '0');
  return `${parts.year}${parts.month}${parts.day}-${parts.hour}${parts.minute}${parts.second}${millis}`;
}

export function iso(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`invalid timestamp: ${value}`);
  }
  return date.toISOString();
}
