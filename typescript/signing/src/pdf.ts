/**
 * Minimal PDF reading + incremental-update construction for signing
 * BonniePDF-generated output.
 *
 * This is NOT a general PDF parser. It understands only the classic
 * cross-reference / `trailer` structure that `@bonniepdf/core` emits: a Latin-1
 * body of `id 0 obj << ... >> endobj` objects, an `xref` table, a `trailer`
 * dictionary, and a `startxref` pointer. Pointing it at arbitrary third-party
 * PDFs (xref streams, object streams) is out of scope by design.
 */

const ASTERISKS = '**********'; // 10 chars -> offsets up to ~10 GB
export const BYTE_RANGE_PLACEHOLDER = `[0 ${ASTERISKS} ${ASTERISKS} ${ASTERISKS}]`;
/** Hex characters reserved for the CMS envelope (16384 hex = 8 KB binary). */
export const SIGNATURE_HEX_LENGTH = 16384;

/** Decode bytes to a Latin-1 string (1 byte -> 1 char, lossless round-trip). */
export function latin1Decode(bytes: Uint8Array): string {
  let out = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    out += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return out;
}

/** Encode a Latin-1 string back to bytes (each char code is masked to 8 bits). */
export function latin1Encode(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

/** Find the byte offset of an ASCII needle, or -1. */
export function indexOfAscii(haystack: Uint8Array, needle: string, from = 0): number {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle.charCodeAt(j)) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * Escape a string for a PDF literal `( ... )` string. Only printable ASCII
 * reaches here (see pdfTextString), so the delimiters and the backslash are all
 * there is to escape.
 */
function escapeLiteral(text: string): string {
  return text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

/** Render a value as a PDF text string: literal for ASCII, UTF-16BE hex otherwise. */
export function pdfTextString(text: string): string {
  if (/^[\x20-\x7e]*$/.test(text)) return `(${escapeLiteral(text)})`;
  let hex = 'FEFF';
  for (let i = 0; i < text.length; i++) {
    hex += text.charCodeAt(i).toString(16).padStart(4, '0').toUpperCase();
  }
  return `<${hex}>`;
}

/** Format a Date as a PDF date string `D:YYYYMMDDHHmmSS+00'00'` (UTC). */
export function pdfDate(date: Date): string {
  const p = (n: number) => n.toString().padStart(2, '0');
  return (
    `D:${date.getUTCFullYear()}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}` +
    `${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}+00'00'`
  );
}

/** Parsed facts about a BonniePDF document, used to build the update. */
export interface PdfInfo {
  /** Object number of the document catalog (`/Root`). */
  rootId: number;
  /** Raw text of the catalog object's dictionary body (between `<<` and `>>`). */
  catalogBody: string;
  /** Object number of the page the signature widget is placed on. */
  targetPageId: number;
  /** Raw text of the target page object's dictionary body. */
  targetPageBody: string;
  /** Highest object number currently in use (= trailer `/Size` - 1). */
  size: number;
  /** Verbatim trailer `/ID [<..> <..>]` value, or undefined if absent. */
  idArray?: string;
  /** Byte offset of the previous `startxref` (for the new trailer `/Prev`). */
  prevStartxref: number;
}

/**
 * Locate `id 0 obj << ... >>` and return the dictionary body text.
 *
 * Takes the **last** definition in the file, not the first: once a document
 * carries incremental updates, an object it overrode appears more than once and
 * the latest revision is the one in force. Reading the first would hand back a
 * catalog without the `/AcroForm` a previous revision added, and the next
 * revision would silently drop the signature field.
 */
function readObjectDict(text: string, id: number): string {
  const marker = new RegExp(`(?:^|[^0-9])${id} 0 obj`, 'g');
  let m: RegExpExecArray | null = null;
  for (let hit = marker.exec(text); hit; hit = marker.exec(text)) m = hit;
  if (!m) throw new Error(`object ${id} not found`);
  const objStart = m.index + m[0].length;
  const dictStart = text.indexOf('<<', objStart);
  if (dictStart < 0) throw new Error(`object ${id}: no dictionary`);
  // Depth-match nested << >> so /MarkInfo << ... >> etc. don't end it early.
  let depth = 0;
  let i = dictStart;
  for (; i < text.length; i++) {
    if (text[i] === '<' && text[i + 1] === '<') {
      depth++;
      i++;
    } else if (text[i] === '>' && text[i + 1] === '>') {
      depth--;
      i++;
      if (depth === 0) break;
    }
  }
  return text.slice(dictStart + 2, i - 1);
}

/**
 * The raw dictionary body of an object, by number, from the latest revision
 * that defines it. Exposed so the DSS and document-timestamp revisions can read
 * structures an earlier revision of this package wrote.
 */
export function readObjectBody(bytes: Uint8Array, id: number): string {
  return readObjectDict(latin1Decode(bytes), id);
}

/** Parse the `N 0 R` object number for a named key, or undefined when absent. */
export function readOptionalRef(dictBody: string, key: string): number | undefined {
  const m = new RegExp(`${key}\\s*(\\d+)\\s+0\\s+R`).exec(dictBody);
  return m ? parseInt(m[1], 10) : undefined;
}

/** Every `N 0 R` reference inside a named array, e.g. an AcroForm's `/Fields`. */
export function readRefArray(dictBody: string, key: string): string[] {
  const m = new RegExp(`${key}\\s*\\[([^\\]]*)\\]`).exec(dictBody);
  if (!m) return [];
  return [...m[1].matchAll(/(\d+)\s+0\s+R/g)].map(x => `${x[1]} 0 R`);
}

/** Parse the `N 0 R` object number for a named key from a dictionary body. */
function readRef(dictBody: string, key: string): number {
  // Handles both `/Root 5 0 R` and `/Kids [ 5 0 R ... ]` (first kid).
  const m = new RegExp(`${key}\\s*\\[?\\s*(\\d+)\\s+0\\s+R`).exec(dictBody);
  if (!m) throw new Error(`reference ${key} not found`);
  return parseInt(m[1], 10);
}

/** Parse every `N 0 R` object number inside a `/Kids [ ... ]` array. */
function readKids(pagesBody: string): number[] {
  const m = /\/Kids\s*\[([^\]]*)\]/.exec(pagesBody);
  if (!m) throw new Error('reference /Kids not found');
  return [...m[1].matchAll(/(\d+)\s+0\s+R/g)].map(x => parseInt(x[1], 10));
}

/**
 * Parse the structural facts needed to append a signature.
 * @param pageIndex 0-based page the (visible) widget will be placed on.
 */
export function parsePdf(bytes: Uint8Array, pageIndex = 0): PdfInfo {
  const text = latin1Decode(bytes);

  const lastStartxref = text.lastIndexOf('startxref');
  if (lastStartxref < 0) throw new Error('not a classic-xref PDF: no startxref');
  const prevStartxref = parseInt(/startxref\s+(\d+)/.exec(text.slice(lastStartxref))![1], 10);

  const trailerStart = text.lastIndexOf('trailer');
  if (trailerStart < 0) throw new Error('not a classic-xref PDF: no trailer');
  const trailer = text.slice(trailerStart);
  const rootId = readRef(trailer, '/Root');
  const size = parseInt(/\/Size\s+(\d+)/.exec(trailer)![1], 10);
  const idMatch = /\/ID\s*(\[[^\]]*\])/.exec(trailer);

  const catalogBody = readObjectDict(text, rootId);
  const pagesId = readRef(catalogBody, '/Pages');
  const pagesBody = readObjectDict(text, pagesId);
  const pageIds = readKids(pagesBody);
  const targetIndex = Math.max(0, Math.min(pageIndex, pageIds.length - 1));
  const targetPageId = pageIds[targetIndex];
  const targetPageBody = readObjectDict(text, targetPageId);

  return {
    rootId,
    catalogBody,
    targetPageId,
    targetPageBody,
    size: size - 1,
    idArray: idMatch?.[1],
    prevStartxref,
  };
}

/** Metadata embedded in the `/Sig` dictionary. */
export interface SignatureDictMeta {
  reason?: string;
  location?: string;
  contactInfo?: string;
  name?: string;
  signingTime: Date;
  /** `/SubFilter` value (default `adbe.pkcs7.detached`; `ETSI.CAdES.detached` for PAdES). */
  subFilter?: string;
}

/** A precomputed visible-signature appearance to wire into the widget. */
export interface VisibleSignature {
  /** Widget rectangle `[x, y, width, height]` in PDF points. */
  rect: [number, number, number, number];
  /** Appearance form XObject content stream. */
  contentStream: string;
}

/**
 * Append a signature revision (sig value, signature field/widget, AcroForm,
 * plus overridden catalog and first page) and a new classic xref section.
 * The returned bytes still carry the `/ByteRange` and `/Contents` placeholders.
 */
export function buildIncrementalUpdate(
  original: Uint8Array,
  info: PdfInfo,
  meta: SignatureDictMeta,
  visible?: VisibleSignature
): Uint8Array {
  let nextId = info.size;
  const sigId = ++nextId;
  const widgetId = ++nextId;
  const acroFormId = ++nextId;
  const apId = visible ? ++nextId : 0;
  const fontId = visible ? ++nextId : 0;
  const newSize = nextId + 1;

  const sigDict = buildSigDict(meta);

  // The caller gives `[x, y, width, height]`; a PDF annotation's /Rect is `[llx lly urx ury]`, two corners.
  const rect = visible
    ? `[${[visible.rect[0], visible.rect[1], visible.rect[0] + visible.rect[2], visible.rect[1] + visible.rect[3]]
        .map(n => n.toString())
        .join(' ')}]`
    : '[0 0 0 0]';
  let widgetDict =
    `<<\n  /Type /Annot\n  /Subtype /Widget\n  /FT /Sig\n  /Rect ${rect}\n` +
    `  /V ${sigId} 0 R\n  /T (Signature1)\n  /F 132\n  /P ${info.targetPageId} 0 R\n`;
  if (visible) widgetDict += `  /AP << /N ${apId} 0 R >>\n`;
  widgetDict += '>>';

  const acroFormDict = `<<\n  /Fields [${widgetId} 0 R]\n  /SigFlags 3\n>>`;
  const catalogDict = `<<${injectKey(info.catalogBody, `  /AcroForm ${acroFormId} 0 R\n`)}>>`;
  const pageDict = `<<${injectAnnot(info.targetPageBody, widgetId)}>>`;

  const objects: RevisionObject[] = [
    { id: sigId, body: sigDict },
    { id: widgetId, body: widgetDict },
    { id: acroFormId, body: acroFormDict },
  ];
  if (visible) {
    const w = visible.rect[2];
    const h = visible.rect[3];
    const content = visible.contentStream;
    objects.push({
      id: apId,
      body:
        `<< /Type /XObject /Subtype /Form /FormType 1 /BBox [0 0 ${w} ${h}]` +
        ` /Resources << /Font << /Helv ${fontId} 0 R >> >> /Length ${latin1Encode(content).length} >>\n` +
        `stream\n${content}\nendstream`,
    });
    objects.push({
      id: fontId,
      body: `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`,
    });
  }
  objects.push({ id: info.rootId, body: catalogDict });
  objects.push({ id: info.targetPageId, body: pageDict });

  return appendRevision(original, objects, {
    rootId: info.rootId,
    newSize,
    prevStartxref: info.prevStartxref,
    idArray: info.idArray,
  });
}

/** One object written into an appended revision. */
export interface RevisionObject {
  /** Object number. Reusing an existing number overrides that object. */
  id: number;
  /** Everything between `N 0 obj` and `endobj`, dictionary and any stream. */
  body: string;
}

/** Trailer facts an appended revision needs. */
export interface RevisionTrailer {
  rootId: number;
  /** Trailer `/Size`: one past the highest object number now in use. */
  newSize: number;
  /** Byte offset of the previous `startxref`, written as `/Prev`. */
  prevStartxref: number;
  /** Verbatim `/ID [<..> <..>]` value carried forward, or undefined. */
  idArray?: string;
}

/**
 * Append one incremental revision: the given objects, a classic cross-reference
 * section covering exactly them, and a trailer chained to the previous one.
 *
 * Shared by every revision this package writes - the signature, the DSS, and the
 * document timestamp - so all three agree on offsets, the `/Prev` chain, and the
 * leading newline that separates the revision from the `%%EOF` before it.
 */
export function appendRevision(
  original: Uint8Array,
  objects: readonly RevisionObject[],
  trailer: RevisionTrailer
): Uint8Array {
  const offsets = new Map<number, number>();
  const startBase = original.length;
  // The document ends in `%%EOF` with no trailing newline; separate cleanly.
  let appended = '\n';

  for (const object of objects) {
    offsets.set(object.id, startBase + appended.length);
    appended += `${object.id} 0 obj\n${object.body}\nendobj\n`;
  }

  const xrefOffset = startBase + appended.length;
  appended += buildXref(offsets);

  const parts = [`/Size ${trailer.newSize}`, `/Root ${trailer.rootId} 0 R`, `/Prev ${trailer.prevStartxref}`];
  if (trailer.idArray) parts.push(`/ID ${trailer.idArray}`);
  appended += `trailer\n<< ${parts.join(' ')} >>\nstartxref\n${xrefOffset}\n%%EOF`;

  const appendedBytes = latin1Encode(appended);
  const out = new Uint8Array(original.length + appendedBytes.length);
  out.set(original, 0);
  out.set(appendedBytes, original.length);
  return out;
}

/** Build the `/Sig` value dictionary with placeholders. */
function buildSigDict(meta: SignatureDictMeta): string {
  const lines = [
    '<<',
    '  /Type /Sig',
    '  /Filter /Adobe.PPKLite',
    `  /SubFilter /${meta.subFilter ?? 'adbe.pkcs7.detached'}`,
    `  /ByteRange ${BYTE_RANGE_PLACEHOLDER}`,
    `  /Contents <${'0'.repeat(SIGNATURE_HEX_LENGTH)}>`,
  ];
  if (meta.reason) lines.push(`  /Reason ${pdfTextString(meta.reason)}`);
  if (meta.location) lines.push(`  /Location ${pdfTextString(meta.location)}`);
  if (meta.contactInfo) lines.push(`  /ContactInfo ${pdfTextString(meta.contactInfo)}`);
  if (meta.name) lines.push(`  /Name ${pdfTextString(meta.name)}`);
  lines.push(`  /M (${pdfDate(meta.signingTime)})`);
  lines.push('>>');
  return lines.join('\n');
}

/** Insert a key line right after the opening of a dictionary body. */
function injectKey(dictBody: string, keyLine: string): string {
  // dictBody starts after `<<`; prepend the new key, keep a leading newline.
  return `\n${keyLine}${dictBody.replace(/^\n/, '')}`;
}

/**
 * Add a widget to a page's `/Annots`, merging if one already exists. Shared by
 * the signature and document-timestamp revisions.
 */
export function injectAnnot(pageBody: string, widgetId: number): string {
  const ref = `${widgetId} 0 R`;
  if (/\/Annots\s*\[/.test(pageBody)) {
    // Merge into the existing inline array (BonniePDF writes it inline).
    return `\n${pageBody.replace(/(\/Annots\s*\[)([^\]]*)\]/, (_m, open, inner) => `${open}${inner.trim()} ${ref}]`).replace(/^\n/, '')}`;
  }
  return injectKey(pageBody, `  /Annots [${ref}]\n`);
}

/** Build a classic xref section from a map of object id -> byte offset. */
function buildXref(offsets: Map<number, number>): string {
  const ids = [...offsets.keys()].sort((a, b) => a - b);
  // Group contiguous ids into subsections.
  const groups: number[][] = [];
  for (const id of ids) {
    const last = groups[groups.length - 1];
    if (last && id === last[last.length - 1] + 1) last.push(id);
    else groups.push([id]);
  }
  let xref = 'xref\n';
  for (const group of groups) {
    xref += `${group[0]} ${group.length}\n`;
    for (const id of group) {
      xref += `${offsets.get(id)!.toString().padStart(10, '0')} 00000 n \n`;
    }
  }
  return xref;
}

/**
 * Back-patch the `/ByteRange` placeholder with real offsets and return the
 * byte spans the signature covers.
 */
export function patchByteRange(bytes: Uint8Array): { signed: Uint8Array; contentsStart: number; contentsEnd: number } {
  const brIndex = indexOfAscii(bytes, BYTE_RANGE_PLACEHOLDER);
  if (brIndex < 0) throw new Error('byte-range placeholder not found');

  // Locate the /Contents hex string that follows the byte range.
  const contentsTag = indexOfAscii(bytes, '/Contents <', brIndex);
  const open = indexOfAscii(bytes, '<', contentsTag);
  const close = indexOfAscii(bytes, '>', open);
  const contentsStart = open; // offset of '<'
  const contentsEnd = close + 1; // offset just past '>'

  const range = [0, contentsStart, contentsEnd, bytes.length - contentsEnd];
  let replacement = `[0 ${range[1]} ${range[2]} ${range[3]}`;
  const padTo = BYTE_RANGE_PLACEHOLDER.length;
  replacement = replacement + ' '.repeat(padTo - replacement.length - 1) + ']';
  if (replacement.length !== padTo) throw new Error('byte range too large for placeholder');
  for (let i = 0; i < replacement.length; i++) bytes[brIndex + i] = replacement.charCodeAt(i);

  // The signed content is everything except the `<...>` hex string.
  const range1 = bytes.subarray(0, contentsStart);
  const range2 = bytes.subarray(contentsEnd);
  const signed = new Uint8Array(range1.length + range2.length);
  signed.set(range1, 0);
  signed.set(range2, range1.length);
  return { signed, contentsStart, contentsEnd };
}

/** Write the hex-encoded CMS envelope into the `/Contents` placeholder. */
export function injectContents(bytes: Uint8Array, contentsStart: number, contentsEnd: number, cms: Uint8Array): void {
  const capacity = contentsEnd - contentsStart - 2; // exclude '<' and '>'
  if (cms.length * 2 > capacity) {
    throw new Error(`CMS envelope (${cms.length} bytes) exceeds /Contents capacity (${capacity / 2} bytes)`);
  }
  let pos = contentsStart + 1; // first hex char (after '<')
  for (let i = 0; i < cms.length; i++) {
    const hi = (cms[i] >> 4) & 0xf;
    const lo = cms[i] & 0xf;
    bytes[pos++] = hexCharCode(hi);
    bytes[pos++] = hexCharCode(lo);
  }
  // Remaining placeholder zeros stay as '0' padding up to the '>'.
}

/**
 * Decode the ASCII hex digits of a PDF hex string (without its `<` `>`) to the
 * bytes it denotes. A hex string's value is these bytes, not its digits.
 */
export function hexDecode(hex: Uint8Array): Uint8Array {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(String.fromCharCode(hex[2 * i], hex[2 * i + 1]), 16);
  }
  return out;
}

function hexCharCode(nibble: number): number {
  return nibble < 10 ? 48 + nibble : 65 + (nibble - 10); // '0'-'9', 'A'-'F'
}
