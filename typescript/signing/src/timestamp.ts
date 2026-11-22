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
import { HttpClient, defaultHttpClient, fetchBytes } from './http';

export type { HttpClient };

export interface TimestampOptions {
  /** TSA endpoint (RFC 3161 over HTTP). */
  url: string;
  /** Web Crypto digest name for the message imprint (defaults to SHA-256). */
  hashName?: 'SHA-256' | 'SHA-384' | 'SHA-512';
  /** Optional transport override (defaults to global `fetch`). */
  httpClient?: HttpClient;
  /** Optional cancellation signal forwarded to the HTTP transport. */
  signal?: AbortSignal;
}

const HASH_OID: Record<string, string> = {
  'SHA-256': Oids.sha256,
  'SHA-384': Oids.sha384,
  'SHA-512': Oids.sha512,
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
    der.integerFromBytes(nonce), // nonce: checkTimeStampToken requires it echoed back
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
 * Check that a `TimeStampToken` answers the request that was sent (RFC 3161
 * §2.4.2): its `TSTInfo` must carry the requested hash algorithm and imprint,
 * and echo the request's nonce. Throws otherwise.
 *
 * Without this a token for different data - from a misrouted request, a
 * misbehaving authority, or a replayed response - would be embedded silently
 * and only fail when someone came to validate the signature. The nonce is what
 * makes a replayed response detectable; sending one without checking it
 * protects nothing.
 *
 * This checks the token's content, not its signature: whether to trust the
 * authority is the validator's decision, made against its own trust anchors.
 */
export function checkTimeStampToken(
  token: Uint8Array,
  hashName: string,
  imprint: Uint8Array,
  nonce: Uint8Array
): void {
  const fail = (why: string): never => {
    throw new Error(`timestamp token does not answer this request: ${why}`);
  };
  const children = (node: der.DerNode): der.DerNode[] => der.readChildren(token, node.contentStart, node.contentEnd);

  let fields: der.DerNode[];
  try {
    // ContentInfo > [0] > SignedData > encapContentInfo > [0] > OCTET STRING > TSTInfo
    const signedData = children(children(der.readNode(token, 0))[1])[0];
    const eContent = children(children(children(signedData)[2])[1])[0];
    fields = children(der.readNode(token, eContent.contentStart));
  } catch {
    return fail('its TSTInfo cannot be read');
  }

  // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime,
  //   accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL, ... }
  const [algorithm, hashed] = children(fields[2]);
  const algorithmOid = children(algorithm)[0];
  if (!equalBytes(der.nodeBytes(token, algorithmOid), der.oid(HASH_OID[hashName]))) {
    fail('different hash algorithm');
  }
  if (!equalBytes(token.subarray(hashed.contentStart, hashed.contentEnd), imprint)) {
    fail('different message imprint');
  }
  const echoed = fields.slice(5).find(field => field.tag === der.Tag.INTEGER);
  if (!echoed) fail('no nonce');
  if (!equalBytes(integerMagnitude(token.subarray(echoed!.contentStart, echoed!.contentEnd)), integerMagnitude(nonce))) {
    fail('different nonce');
  }
}

/** A non-negative big-endian integer with its leading zero bytes removed. */
function integerMagnitude(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) start++;
  return bytes.subarray(start);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/**
 * Request an RFC 3161 timestamp for `data`: hash it, build the request, POST it
 * to the TSA, check the token answers that request, and return the DER
 * `TimeStampToken` ready to embed in CMS.
 */
export async function requestTimestamp(data: Uint8Array, options: TimestampOptions): Promise<Uint8Array> {
  options.signal?.throwIfAborted();
  const hashName = options.hashName ?? 'SHA-256';
  const imprint = new Uint8Array(await crypto.subtle.digest(hashName, data as BufferSource));
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const req = buildTimeStampReq(imprint, hashName, nonce);

  const body = await fetchBytes(
    options.httpClient ?? defaultHttpClient,
    {
      url: options.url,
      method: 'POST',
      headers: {
        'Content-Type': 'application/timestamp-query',
        Accept: 'application/timestamp-reply',
      },
      body: req,
      signal: options.signal,
    },
    'timestamp request'
  );
  const token = extractTokenFromResponse(body);
  checkTimeStampToken(token, hashName, imprint, nonce);
  return token;
}
