/**
 * Minimal ASN.1 DER encoder and reader.
 *
 * Hand-rolled to preserve BonniePDF's zero-dependency philosophy. Only the
 * subset of DER needed to build a CMS `SignedData` envelope and to read an
 * X.509 certificate's issuer + serial number is implemented.
 *
 * All functions operate on plain `Uint8Array` - no Node `Buffer`, so this runs
 * unchanged in the browser, Node, Bun, and Deno.
 */

/** DER universal tag numbers (and the constructed bit) used by this package. */
export const Tag = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

/** Concatenate a list of byte arrays into one. */
export function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Encode a DER length (short form < 128, otherwise long form). */
export function encodeLength(length: number): Uint8Array {
  if (length < 0x80) return new Uint8Array([length]);
  const bytes: number[] = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

/** Wrap a value in a tag-length-value triple. */
export function tlv(tag: number, value: Uint8Array): Uint8Array {
  return concatBytes([new Uint8Array([tag]), encodeLength(value.length), value]);
}

/** SEQUENCE of the given pre-encoded children. */
export function sequence(...children: Uint8Array[]): Uint8Array {
  return tlv(Tag.SEQUENCE, concatBytes(children));
}

/** SET of the given pre-encoded children (order preserved). */
export function set(...children: Uint8Array[]): Uint8Array {
  return tlv(Tag.SET, concatBytes(children));
}

/**
 * SET OF the given pre-encoded children, sorted by their DER encoding as
 * required for a DER `SET OF` (X.690 §11.6). Used for CMS signed attributes.
 */
export function setOf(children: Uint8Array[]): Uint8Array {
  const sorted = [...children].sort(compareBytes);
  return tlv(Tag.SET, concatBytes(sorted));
}

/** Lexicographically compare two byte arrays (for DER SET OF ordering). */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/** Encode an OBJECT IDENTIFIER from its dotted-decimal string. */
export function oid(dotted: string): Uint8Array {
  const parts = dotted.split('.').map(s => parseInt(s, 10));
  if (parts.length < 2) throw new Error(`invalid OID: ${dotted}`);
  const body: number[] = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let value = parts[i];
    const stack: number[] = [value & 0x7f];
    value = Math.floor(value / 128);
    while (value > 0) {
      stack.unshift((value & 0x7f) | 0x80);
      value = Math.floor(value / 128);
    }
    body.push(...stack);
  }
  return tlv(Tag.OID, new Uint8Array(body));
}

/** Encode an INTEGER from a non-negative big-endian magnitude. */
export function integerFromBytes(magnitude: Uint8Array): Uint8Array {
  let start = 0;
  while (start < magnitude.length - 1 && magnitude[start] === 0) start++;
  let value = magnitude.subarray(start);
  // Prepend 0x00 if the high bit is set so the value reads as positive.
  if (value.length === 0) value = new Uint8Array([0]);
  if (value[0] & 0x80) value = concatBytes([new Uint8Array([0]), value]);
  return tlv(Tag.INTEGER, value);
}

/** Encode a small non-negative INTEGER (e.g. CMS version numbers). */
export function integer(value: number): Uint8Array {
  if (value === 0) return tlv(Tag.INTEGER, new Uint8Array([0]));
  const bytes: number[] = [];
  let n = value;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(Tag.INTEGER, new Uint8Array(bytes));
}

/** OCTET STRING. */
export function octetString(value: Uint8Array): Uint8Array {
  return tlv(Tag.OCTET_STRING, value);
}

/** BIT STRING with zero unused bits (the only case CMS needs). */
export function bitString(value: Uint8Array): Uint8Array {
  return tlv(Tag.BIT_STRING, concatBytes([new Uint8Array([0]), value]));
}

/** NULL. */
export function nullValue(): Uint8Array {
  return tlv(Tag.NULL, new Uint8Array(0));
}

/** UTF8String. */
export function utf8String(text: string): Uint8Array {
  return tlv(Tag.UTF8_STRING, new TextEncoder().encode(text));
}

/** IA5String (ASCII). */
export function ia5String(text: string): Uint8Array {
  return tlv(Tag.IA5_STRING, new TextEncoder().encode(text));
}

/**
 * UTCTime in the `YYMMDDHHMMSSZ` form CMS uses for signing time
 * (valid for years 1950-2049, which covers all realistic signing dates).
 */
export function utcTime(date: Date): Uint8Array {
  const p = (n: number, w = 2) => n.toString().padStart(w, '0');
  const yy = date.getUTCFullYear() % 100;
  const text =
    `${p(yy)}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}` +
    `${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
  return tlv(Tag.UTC_TIME, new TextEncoder().encode(text));
}

/**
 * GeneralizedTime `YYYYMMDDHHMMSSZ`.
 *
 * The form RFC 3161 `TSTInfo` and RFC 6960 OCSP responses use, and the one
 * required for any year outside UTCTime's 1950-2049 window.
 */
export function generalizedTime(date: Date): Uint8Array {
  const p = (n: number, w = 2) => n.toString().padStart(w, '0');
  const text =
    `${p(date.getUTCFullYear(), 4)}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}` +
    `${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
  return tlv(Tag.GENERALIZED_TIME, new TextEncoder().encode(text));
}

/** ENUMERATED, as used by an OCSP `responseStatus`. */
export function enumerated(value: number): Uint8Array {
  return tlv(0x0a, new Uint8Array([value]));
}

/** BOOLEAN. */
export function boolean(value: boolean): Uint8Array {
  return tlv(0x01, new Uint8Array([value ? 0xff : 0x00]));
}

/** Context-specific constructed `[n]` wrapper (e.g. `[0]` IMPLICIT certificates). */
export function contextConstructed(n: number, value: Uint8Array): Uint8Array {
  return tlv(0xa0 | n, value);
}

/** Pass an already-DER-encoded blob through unchanged. */
export function raw(bytes: Uint8Array): Uint8Array {
  return bytes;
}

// ───────────────────────────── reader ──────────────────────────────────────

/** A parsed tag-length-value triple, with byte offsets into the source. */
export interface DerNode {
  tag: number;
  /** Offset of the tag byte (start of the whole TLV). */
  start: number;
  /** Offset of the first content byte. */
  contentStart: number;
  /** Offset just past the last content byte. */
  contentEnd: number;
  /** Offset just past the whole TLV (tag + length + content). */
  end: number;
}

/** Read a single TLV starting at `offset`. */
export function readNode(bytes: Uint8Array, offset: number): DerNode {
  const tag = bytes[offset];
  let pos = offset + 1;
  let length = bytes[pos++];
  if (length & 0x80) {
    const numBytes = length & 0x7f;
    if (numBytes === 0 || numBytes > 4) throw new Error('unsupported DER length');
    length = 0;
    for (let i = 0; i < numBytes; i++) length = length * 256 + bytes[pos++];
  }
  const contentStart = pos;
  const contentEnd = pos + length;
  return { tag, start: offset, contentStart, contentEnd, end: contentEnd };
}

/** Read the immediate children of a constructed node's content range. */
export function readChildren(bytes: Uint8Array, contentStart: number, contentEnd: number): DerNode[] {
  const out: DerNode[] = [];
  let pos = contentStart;
  while (pos < contentEnd) {
    const node = readNode(bytes, pos);
    out.push(node);
    pos = node.end;
  }
  return out;
}

/** Return the full TLV byte slice (tag through last content byte) of a node. */
export function nodeBytes(bytes: Uint8Array, node: DerNode): Uint8Array {
  return bytes.slice(node.start, node.end);
}
