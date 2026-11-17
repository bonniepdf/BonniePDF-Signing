/**
 * OCSP (RFC 6960): ask a responder whether a certificate is still valid, and
 * keep the signed answer.
 *
 * For long-term validation the answer itself is the point. A PAdES B-LT
 * signature embeds the responder's DER `OCSPResponse` in the document's
 * Document Security Store, so a validator years from now can establish that the
 * certificate was good at signing time without asking anyone.
 *
 * This builds the request and checks that the response was granted; it does not
 * verify the responder's signature or interpret the certificate status. That is
 * the validator's job, and doing it here would mean deciding on the spot whether
 * to refuse to sign - a policy call that belongs to the caller.
 */
import * as der from './asn1/der';
import { Oids } from './asn1/oids';
import { oidString, extractPublicKeyBits, extractSubject } from './asn1/extensions';
import { extractIssuerAndSerial } from './asn1/x509';
import { HttpClient, fetchBytes } from './http';

/** `OCSPResponseStatus` values (RFC 6960 §4.2.1). */
const RESPONSE_STATUS: Record<number, string> = {
  0: 'successful',
  1: 'malformedRequest',
  2: 'internalError',
  3: 'tryLater',
  5: 'sigRequired',
  6: 'unauthorized',
};

/**
 * Build the `CertID` that names the certificate being asked about.
 *
 * CertID ::= SEQUENCE {
 *   hashAlgorithm AlgorithmIdentifier,
 *   issuerNameHash OCTET STRING,   -- hash of the issuer's DER Name
 *   issuerKeyHash  OCTET STRING,   -- hash of the issuer's public key bits
 *   serialNumber   CertificateSerialNumber }
 *
 * SHA-1 is not a choice here: RFC 6960 mandates it for `CertID`, and responders
 * key their databases on it. It identifies a certificate; it signs nothing.
 */
export async function buildCertId(certDer: Uint8Array, issuerDer: Uint8Array): Promise<Uint8Array> {
  const { serialNumber } = extractIssuerAndSerial(certDer);
  const issuerName = extractSubject(issuerDer);
  const issuerNameHash = new Uint8Array(await crypto.subtle.digest('SHA-1', issuerName as BufferSource));
  const issuerKeyHash = new Uint8Array(
    await crypto.subtle.digest('SHA-1', extractPublicKeyBits(issuerDer) as BufferSource)
  );

  return der.sequence(
    der.sequence(der.oid(Oids.sha1), der.nullValue()),
    der.octetString(issuerNameHash),
    der.octetString(issuerKeyHash),
    serialNumber
  );
}

/**
 * Build a DER `OCSPRequest` for one certificate.
 *
 * OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0] OPTIONAL }
 * TBSRequest  ::= SEQUENCE { version [0] DEFAULT v1, requestorName [1] OPTIONAL,
 *                            requestList SEQUENCE OF Request, requestExtensions [2] OPTIONAL }
 *
 * The request is unsigned, which is the norm: responders answer anonymously and
 * a signed request would only leak who is asking.
 */
export async function buildOcspRequest(certDer: Uint8Array, issuerDer: Uint8Array): Promise<Uint8Array> {
  const certId = await buildCertId(certDer, issuerDer);
  const request = der.sequence(certId); // Request ::= SEQUENCE { reqCert CertID, ... }
  const tbsRequest = der.sequence(der.sequence(request));
  return der.sequence(tbsRequest);
}

/**
 * Check an `OCSPResponse`'s top-level status and hand back the DER unchanged.
 *
 * OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] OPTIONAL }
 *
 * The bytes are stored verbatim in the DSS, so this deliberately re-encodes
 * nothing: a responder's exact signed octets are what a validator needs.
 */
export function checkOcspResponse(response: Uint8Array): Uint8Array {
  const root = der.readNode(response, 0);
  const children = der.readChildren(response, root.contentStart, root.contentEnd);
  const statusNode = children[0];
  if (!statusNode) throw new Error('OCSP response is empty');

  const status = response[statusNode.contentStart];
  if (status !== 0) {
    throw new Error(`OCSP responder returned ${RESPONSE_STATUS[status] ?? `status ${status}`}`);
  }

  const bytes = children[1];
  if (!bytes) throw new Error('OCSP response carried no responseBytes');

  // responseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
  const inner = der.readChildren(response, bytes.contentStart, bytes.contentEnd)[0];
  const parts = der.readChildren(response, inner.contentStart, inner.contentEnd);
  if (parts[0] && oidString(response, parts[0]) !== Oids.ocspBasicResponse) {
    throw new Error('OCSP response is not a BasicOCSPResponse');
  }
  return response;
}

/** Ask `url` about `certDer`, returning the responder's DER `OCSPResponse`. */
export async function requestOcsp(
  url: string,
  certDer: Uint8Array,
  issuerDer: Uint8Array,
  httpClient: HttpClient
): Promise<Uint8Array> {
  const request = await buildOcspRequest(certDer, issuerDer);
  const body = await fetchBytes(
    httpClient,
    {
      url,
      method: 'POST',
      headers: { 'Content-Type': 'application/ocsp-request', Accept: 'application/ocsp-response' },
      body: request,
    },
    'OCSP request'
  );
  return checkOcspResponse(body);
}
