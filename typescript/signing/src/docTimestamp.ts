/**
 * Document timestamps: the revision that turns a PAdES B-LT signature into
 * B-LTA.
 *
 * A signature timestamp proves when the *signature* was made. A document
 * timestamp proves when the *whole file, validation material included*, looked
 * the way it does - which is what lets the evidence in the Document Security
 * Store be trusted later, and what a fresh timestamp renews before the previous
 * one's algorithms age out.
 *
 * Structurally it is a signature dictionary with no CMS signature in it: the
 * `/Contents` holds an RFC 3161 `TimeStampToken` directly, under
 * `/SubFilter /ETSI.RFC3161` (ETSI EN 319 142-1 §5.4.3, ISO 32000-2 §12.8.5).
 */
import {
  appendRevision,
  injectAnnot,
  injectContents,
  parsePdf,
  patchByteRange,
  readObjectBody,
  readOptionalRef,
  readRefArray,
  RevisionObject,
  BYTE_RANGE_PLACEHOLDER,
  SIGNATURE_HEX_LENGTH,
} from './pdf';
import { requestTimestamp } from './timestamp';
import { HttpClient } from './http';

/** What `appendDocumentTimestamp` needs beyond the document. */
export interface DocumentTimestampOptions {
  /** RFC 3161 Time-Stamp Authority endpoint. */
  timestampUrl: string;
  /** Digest for the timestamp's message imprint. Defaults to SHA-256. */
  hashName?: 'SHA-256' | 'SHA-384' | 'SHA-512';
  /** Transport for the TSA request. */
  httpClient?: HttpClient;
  /** 0-based page the (invisible) timestamp widget is attached to. */
  page?: number;
  /** Optional cancellation signal forwarded to the TSA request. */
  signal?: AbortSignal;
}

/**
 * Append a document timestamp revision covering everything written so far.
 *
 * The imprint is taken over the document's whole byte range excluding only the
 * `/Contents` placeholder, exactly as for a signature - so the token attests to
 * the original document, every earlier signature, and the DSS in one go.
 */
export async function appendDocumentTimestamp(
  document: Uint8Array,
  options: DocumentTimestampOptions
): Promise<Uint8Array> {
  options.signal?.throwIfAborted();
  const info = parsePdf(document, options.page ?? 0);

  let nextId = info.size;
  const timestampId = ++nextId;
  const widgetId = ++nextId;
  const acroFormId = ++nextId;

  // Carry forward the fields an earlier signature revision registered, so the
  // timestamp is added to the form rather than replacing what is already there.
  const existingAcroFormId = readOptionalRef(info.catalogBody, '/AcroForm');
  const existingFields =
    existingAcroFormId === undefined ? [] : readRefArray(readObjectBody(document, existingAcroFormId), '/Fields');
  const fields = [...existingFields, `${widgetId} 0 R`];

  const objects: RevisionObject[] = [
    {
      id: timestampId,
      body: [
        '<<',
        '  /Type /DocTimeStamp',
        '  /Filter /Adobe.PPKLite',
        '  /SubFilter /ETSI.RFC3161',
        `  /ByteRange ${BYTE_RANGE_PLACEHOLDER}`,
        `  /Contents <${'0'.repeat(SIGNATURE_HEX_LENGTH)}>`,
        '>>',
      ].join('\n'),
    },
    {
      id: widgetId,
      body:
        '<<\n  /Type /Annot\n  /Subtype /Widget\n  /FT /Sig\n  /Rect [0 0 0 0]\n' +
        `  /V ${timestampId} 0 R\n  /T (Timestamp${fields.length})\n  /F 132\n  /P ${info.targetPageId} 0 R\n>>`,
    },
    { id: acroFormId, body: `<<\n  /Fields [${fields.join(' ')}]\n  /SigFlags 3\n>>` },
    { id: info.rootId, body: `<<${catalogWithAcroForm(info.catalogBody, acroFormId)}>>` },
    { id: info.targetPageId, body: `<<${injectAnnot(info.targetPageBody, widgetId)}>>` },
  ];

  const withPlaceholders = appendRevision(document, objects, {
    rootId: info.rootId,
    newSize: nextId + 1,
    prevStartxref: info.prevStartxref,
    idArray: info.idArray,
  });

  const { signed, contentsStart, contentsEnd } = patchByteRange(withPlaceholders);
  const token = await requestTimestamp(signed, {
    url: options.timestampUrl,
    hashName: options.hashName ?? 'SHA-256',
    httpClient: options.httpClient,
    signal: options.signal,
  });

  injectContents(withPlaceholders, contentsStart, contentsEnd, token);
  return withPlaceholders;
}

/** Point the catalog at the new AcroForm, replacing any earlier reference. */
function catalogWithAcroForm(catalogBody: string, acroFormId: number): string {
  const body = catalogBody.replace(/\s*\/AcroForm\s+\d+\s+0\s+R/g, '');
  return `\n  /AcroForm ${acroFormId} 0 R\n${body.replace(/^\n/, '')}`;
}
