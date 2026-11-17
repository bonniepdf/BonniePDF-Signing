/**
 * RFC 3161 timestamping: build a `TimeStampReq`, send it to a Time-Stamp
 * Authority, and extract the `TimeStampToken` from the `TimeStampResp`.
 *
 * The token is embedded by the CMS builder as the signature-timestamp unsigned
 * attribute, upgrading a PAdES B-B signature to **B-T**.
 *
 * Network I/O goes through a pluggable transport so the package stays
 * platform-neutral. The default uses the global `fetch` (Node 18+, browsers,
 * Bun, Deno). **Note:** most TSAs do not send CORS headers, so timestamping in
 * a browser usually needs a same-origin proxy supplied via `httpClient`.
 */
import * as der from './asn1/der';
import { Oids } from './asn1/oids';

/** A minimal HTTP transport: POST `body` to `url`, return the response bytes. */
export type HttpClient = (
  url: string,
  body: Uint8Array,
  headers: Record<string, string>
) => Promise<{ status: number; body: Uint8Array }>;

export interface TimestampOptions {
  /** TSA endpoint (RFC 3161 over HTTP). */
  url: string;
  /** Web Crypto digest name for the message imprint (defaults to SHA-256). */
  hashName?: 'SHA-256' | 'SHA-384' | 'SHA-512';
  /** Optional transport override (defaults to global `fetch`). */
  httpClient?: HttpClient;
}

const HASH_OID: Record<string, string> = {
  'SHA-256': Oids.sha256,
  'SHA-384': Oids.sha384,
  'SHA-512': Oids.sha512,
};

/** Default transport built on the global `fetch`. */
const defaultHttpClient: HttpClient = async (url, body, headers) => {
  if (typeof fetch !== 'function') {
    throw new Error('no global fetch available; supply settings.httpClient for timestamping');
  }
  const res = await fetch(url, { method: 'POST', headers, body: body as BufferSource });
  const buf = new Uint8Array(await res.arrayBuffer());
  return { status: res.status, body: buf };
};

/**
 * Build a DER `TimeStampReq` over the given message imprint.
 *
 * TimeStampReq ::= SEQUENCE {
 *   version INTEGER (1),
 *   messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING },
 *   nonce INTEGER OPTIONAL,
 *   certReq BOOLEAN }
 */
export function buildTimeStampReq(imprint: Uint8Array, hashName: string, nonce: Uint8Array): Uint8Array {
  const hashOid = HASH_OID[hashName];
  if (!hashOid) throw new Error(`unsupported timestamp hash: ${hashName}`);
  const messageImprint = der.sequence(der.sequence(der.oid(hashOid), der.nullValue()), der.octetString(imprint));
  return der.sequence(
    der.integer(1), // version
    messageImprint,
    der.integerFromBytes(nonce), // nonce (replay protection)
    der.tlv(0x01, new Uint8Array([0xff])) // certReq BOOLEAN TRUE (include TSA cert)
  );
}

/**
 * Extract the `TimeStampToken` (a CMS ContentInfo) from a DER `TimeStampResp`.
 *
 * TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
 * PKIStatusInfo ::= SEQUENCE { status INTEGER, ... }  // 0 granted, 1 grantedWithMods
 */
export function extractTokenFromResponse(response: Uint8Array): Uint8Array {
  const root = der.readNode(response, 0);
  const children = der.readChildren(response, root.contentStart, root.contentEnd);
  const statusInfo = children[0];
  const statusNode = der.readChildren(response, statusInfo.contentStart, statusInfo.contentEnd)[0];
  const status = response[statusNode.contentStart]; // small integer
  if (status !== 0 && status !== 1) {
    throw new Error(`TSA rejected the request (PKIStatus ${status})`);
  }
  const token = children[1];
  if (!token) throw new Error('TSA response contained no timeStampToken');
  return der.nodeBytes(response, token);
}

/**
 * Request an RFC 3161 timestamp for `data`: hash it, build the request, POST it
 * to the TSA, and return the DER `TimeStampToken` ready to embed in CMS.
 */
export async function requestTimestamp(data: Uint8Array, options: TimestampOptions): Promise<Uint8Array> {
  const hashName = options.hashName ?? 'SHA-256';
  const imprint = new Uint8Array(await crypto.subtle.digest(hashName, data as BufferSource));
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const req = buildTimeStampReq(imprint, hashName, nonce);

  const httpClient = options.httpClient ?? defaultHttpClient;
  const { status, body } = await httpClient(options.url, req, {
    'Content-Type': 'application/timestamp-query',
    Accept: 'application/timestamp-reply',
  });
  if (status < 200 || status >= 300) throw new Error(`TSA HTTP ${status}`);
  return extractTokenFromResponse(body);
}
