/**
 * The Document Security Store: where a PAdES B-LT signature keeps the evidence
 * that makes it verifiable long after the certificates involved have expired.
 *
 * Structurally it is a dictionary hung off the catalog, holding three arrays of
 * streams - certificates, OCSP responses, CRLs - plus an optional per-signature
 * index (`/VRI`) that says which of them belong to which signature. It is written
 * as its own incremental revision, appended after the signature it describes, so
 * the signature's own byte range is untouched and stays valid.
 *
 * See ETSI EN 319 142-1 §5.4 and ISO 32000-2 §12.8.4.3.
 */
import { appendRevision, latin1Decode, latin1Encode, parsePdf, PdfInfo, RevisionObject, pdfDate } from './pdf';
import { ValidationMaterial } from './validation';

/** What `buildDssRevision` needs beyond the document itself. */
export interface DssOptions {
  /** The blobs to store. Empty categories are omitted from the dictionary. */
  material: ValidationMaterial;
  /**
   * The value of the signature's `/Contents` string - its decoded bytes, zero
   * padding included - used to key the `/VRI` entry. Omit to write a
   * document-level DSS with no per-signature index.
   */
  signatureContents?: Uint8Array;
  /** Time recorded in the `/VRI` `/TU` entry. Defaults to now. */
  time?: Date;
  /**
   * When true, declare the ESIC developer extension. Required by ETSI for PAdES
   * structures in a PDF older than 2.0, and harmless in 2.0.
   */
  declareEsicExtension?: boolean;
}

/**
 * The `/VRI` key for a signature: the uppercase base-16 SHA-1 of its
 * `/Contents` value (ETSI EN 319 142-1 §5.4.2).
 *
 * The value of a hex string is the bytes its digits denote, so the hash covers
 * the decoded octet string, zero padding included - not the hex digits as they
 * appear in the file. A validator recomputes the key from the string it reads,
 * not from the CMS it parses out of it, which is why the padding counts.
 */
export async function vriKey(signatureContents: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', signatureContents as BufferSource));
  let hex = '';
  for (const byte of digest) hex += byte.toString(16).padStart(2, '0').toUpperCase();
  return hex;
}

/** Append the DSS revision to an already-signed document. */
export async function buildDssRevision(signed: Uint8Array, options: DssOptions): Promise<Uint8Array> {
  const info = parsePdf(signed);
  const { material } = options;

  let nextId = info.size;
  const objects: RevisionObject[] = [];

  /** Write each blob as its own stream object and collect the references. */
  const streamRefs = (blobs: readonly Uint8Array[]): string[] =>
    blobs.map(blob => {
      const id = ++nextId;
      objects.push({ id, body: `<< /Length ${blob.length} >>\nstream\n${latin1Decode(blob)}\nendstream` });
      return `${id} 0 R`;
    });

  const certRefs = streamRefs(material.certificates);
  const ocspRefs = streamRefs(material.ocspResponses);
  const crlRefs = streamRefs(material.crls);

  const entries: string[] = [];
  if (certRefs.length > 0) entries.push(`/Certs [${certRefs.join(' ')}]`);
  if (ocspRefs.length > 0) entries.push(`/OCSPs [${ocspRefs.join(' ')}]`);
  if (crlRefs.length > 0) entries.push(`/CRLs [${crlRefs.join(' ')}]`);

  if (options.signatureContents) {
    const vriId = ++nextId;
    const key = await vriKey(options.signatureContents);
    const vriEntry: string[] = [];
    if (certRefs.length > 0) vriEntry.push(`/Cert [${certRefs.join(' ')}]`);
    if (ocspRefs.length > 0) vriEntry.push(`/OCSP [${ocspRefs.join(' ')}]`);
    if (crlRefs.length > 0) vriEntry.push(`/CRL [${crlRefs.join(' ')}]`);
    vriEntry.push(`/TU (${pdfDate(options.time ?? new Date())})`);

    objects.push({ id: vriId, body: `<< /${key} << ${vriEntry.join(' ')} >> >>` });
    entries.push(`/VRI ${vriId} 0 R`);
  }

  const dssId = ++nextId;
  objects.push({ id: dssId, body: `<< ${entries.join(' ')} >>` });

  objects.push({
    id: info.rootId,
    body: `<<${catalogWithDss(info, dssId, options.declareEsicExtension === true)}>>`,
  });

  return appendRevision(signed, objects, {
    rootId: info.rootId,
    newSize: nextId + 1,
    prevStartxref: info.prevStartxref,
    idArray: info.idArray,
  });
}

/**
 * Rewrite the catalog body with `/DSS` (and, where asked, `/Extensions`).
 *
 * An existing `/DSS` is replaced rather than merged: this package writes the
 * whole store in one go, and a second pass that appended to a store it did not
 * write could leave a validator with two disagreeing indexes.
 */
function catalogWithDss(info: PdfInfo, dssId: number, declareEsic: boolean): string {
  let body = info.catalogBody.replace(/\s*\/DSS\s+\d+\s+0\s+R/g, '');
  let added = `  /DSS ${dssId} 0 R\n`;

  if (declareEsic && !/\/Extensions\s*<</.test(body)) {
    // ETSI EN 319 142-1 §5.1: PAdES structures in a pre-2.0 file are declared
    // through the ESIC developer extension.
    added += '  /Extensions << /ESIC << /BaseVersion /1.7 /ExtensionLevel 1 >> >>\n';
  }

  return `\n${added}${body.replace(/^\n/, '')}`;
}

/** The PDF header version, e.g. `'1.7'`, or undefined when the header is unusual. */
export function pdfHeaderVersion(bytes: Uint8Array): string | undefined {
  const head = latin1Decode(bytes.subarray(0, 16));
  return /^%PDF-(\d+\.\d+)/.exec(head)?.[1];
}

/** True when the document predates PDF 2.0 and therefore needs the ESIC extension. */
export function needsEsicExtension(bytes: Uint8Array): boolean {
  const version = pdfHeaderVersion(bytes);
  if (!version) return true;
  return parseFloat(version) < 2;
}

/** Re-encode a latin-1 string to bytes. Re-exported for the tests' convenience. */
export { latin1Encode };
