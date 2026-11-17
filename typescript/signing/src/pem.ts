/**
 * PEM <-> DER helpers and platform-neutral base64 decoding.
 *
 * Avoids Node's `Buffer` entirely so the module works unchanged in the browser,
 * Node, Bun, and Deno.
 */

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_LOOKUP: Int16Array = (() => {
  const table = new Int16Array(256).fill(-1);
  for (let i = 0; i < BASE64_CHARS.length; i++) table[BASE64_CHARS.charCodeAt(i)] = i;
  return table;
})();

/** Decode a standard base64 string to bytes (whitespace tolerated, padding optional). */
export function base64ToBytes(base64: string): Uint8Array {
  const clean = base64.replace(/[^A-Za-z0-9+/]/g, '');
  const len = clean.length;
  const outLen = Math.floor((len * 3) / 4);
  const out = new Uint8Array(outLen);
  let o = 0;
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < len; i++) {
    const value = BASE64_LOOKUP[clean.charCodeAt(i)];
    if (value < 0) continue;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buffer >> bits) & 0xff;
    }
  }
  return o === outLen ? out : out.subarray(0, o);
}

/** Encode bytes to a standard base64 string. */
export function bytesToBase64(bytes: Uint8Array): string {
  let result = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    result +=
      BASE64_CHARS[(n >> 18) & 63] + BASE64_CHARS[(n >> 12) & 63] + BASE64_CHARS[(n >> 6) & 63] + BASE64_CHARS[n & 63];
  }
  const remaining = bytes.length - i;
  if (remaining === 1) {
    const n = bytes[i] << 16;
    result += BASE64_CHARS[(n >> 18) & 63] + BASE64_CHARS[(n >> 12) & 63] + '==';
  } else if (remaining === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    result += BASE64_CHARS[(n >> 18) & 63] + BASE64_CHARS[(n >> 12) & 63] + BASE64_CHARS[(n >> 6) & 63] + '=';
  }
  return result;
}

/**
 * Strip the PEM armor (`-----BEGIN ...-----` / `-----END ...-----`) and
 * base64-decode the body to DER. Throws if no PEM block is present.
 */
export function pemToDer(pem: string): Uint8Array {
  const match = pem.match(/-----BEGIN [^-]+-----([\s\S]+?)-----END [^-]+-----/);
  if (!match) throw new Error('not a PEM block: missing BEGIN/END armor');
  return base64ToBytes(match[1]);
}

/** Wrap DER bytes in PEM armor with the given label (e.g. `CERTIFICATE`). */
export function derToPem(der: Uint8Array, label: string): string {
  const body = bytesToBase64(der)
    .replace(/(.{64})/g, '$1\n')
    .replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}
