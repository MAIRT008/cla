import {sha256Hex as pureSha256Hex} from './sha256.mjs';

const nodeCrypto = await loadNodeCrypto();
const nodeUrl = await loadNodeUrl();

async function loadNodeCrypto() {
  if (typeof process === 'undefined' || !process.versions?.node) return null;
  try { return await import('node:crypto'); } catch { return null; }
}

async function loadNodeUrl() {
  if (typeof process === 'undefined' || !process.versions?.node) return null;
  try { return await import('node:url'); } catch { return null; }
}

export const platformKind = nodeCrypto ? 'node' : 'web';

export function sha256Hex(value) {
  if (nodeCrypto) return nodeCrypto.createHash('sha256').update(value).digest('hex');
  return pureSha256Hex(value);
}

export function randomHex(byteLength) {
  if (nodeCrypto) return nodeCrypto.randomBytes(byteLength).toString('hex');
  const bytes = new Uint8Array(byteLength);
  const source = globalThis.crypto;
  if (!source?.getRandomValues) throw Object.assign(new Error('no cryptographic random source'), {code: 'PLATFORM_RANDOM_UNAVAILABLE'});
  source.getRandomValues(bytes);
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

/** Constant-time comparison of two equal-length hex strings. */
export function timingSafeEqualHex(left, right) {
  const a = String(left ?? '');
  const b = String(right ?? '');
  if (a.length !== b.length) return false;
  if (nodeCrypto) {
    return nodeCrypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  }
  let different = 0;
  for (let index = 0; index < a.length; index += 1) different |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return different === 0;
}

export function toAsciiDomain(value) {
  if (nodeUrl) return nodeUrl.domainToASCII(value);
  try {
    return new URL(`https://${value}`).hostname;
  } catch {
    return '';
  }
}
