/**
 * The tiny slice of X.509 parsing CMS needs: the issuer `Name` and the
 * `serialNumber`, used to build the SignerInfo `issuerAndSerialNumber`
 * (RFC 5652 §5.3). This is a reader of well-formed DER certificates, not a
 * validating parser - it deliberately does no expiry/chain/signature checking.
 */
import { readNode, readChildren, nodeBytes, Tag } from './der';

export interface IssuerAndSerial {
  /** Full DER TLV of the issuer `Name` SEQUENCE. */
  issuer: Uint8Array;
  /** Full DER TLV of the `serialNumber` INTEGER. */
  serialNumber: Uint8Array;
}

const CONTEXT_0 = 0xa0; // [0] EXPLICIT version wrapper

/**
 * Extract issuer + serial from a DER-encoded X.509 certificate.
 *
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 * TBSCertificate ::= SEQUENCE {
 *   [0] version DEFAULT v1, serialNumber INTEGER,
 *   signature AlgorithmIdentifier, issuer Name, ... }
 */
export function extractIssuerAndSerial(certDer: Uint8Array): IssuerAndSerial {
  const cert = readNode(certDer, 0);
  if (cert.tag !== Tag.SEQUENCE) throw new Error('certificate: expected SEQUENCE');

  const certChildren = readChildren(certDer, cert.contentStart, cert.contentEnd);
  const tbs = certChildren[0];
  if (!tbs || tbs.tag !== Tag.SEQUENCE) throw new Error('certificate: missing tbsCertificate');

  const tbsChildren = readChildren(certDer, tbs.contentStart, tbs.contentEnd);

  let index = 0;
  // Skip the optional [0] EXPLICIT version.
  if (tbsChildren[index] && tbsChildren[index].tag === CONTEXT_0) index++;

  const serialNode = tbsChildren[index++];
  if (!serialNode || serialNode.tag !== Tag.INTEGER) {
    throw new Error('certificate: missing serialNumber');
  }
  // Skip the inner signature AlgorithmIdentifier.
  index++;
  const issuerNode = tbsChildren[index];
  if (!issuerNode || issuerNode.tag !== Tag.SEQUENCE) {
    throw new Error('certificate: missing issuer');
  }

  return {
    serialNumber: nodeBytes(certDer, serialNode),
    issuer: nodeBytes(certDer, issuerNode),
  };
}

/**
 * Extract the DER `SubjectPublicKeyInfo` from a certificate, suitable for
 * `crypto.subtle.importKey('spki', ...)`. Used to verify a signature against
 * the embedded signer certificate.
 *
 * It is the element after `subject` in the TBSCertificate:
 * [0] version?, serialNumber, signature, issuer, validity, subject, spki.
 */
export function extractSubjectPublicKeyInfo(certDer: Uint8Array): Uint8Array {
  const cert = readNode(certDer, 0);
  const tbs = readChildren(certDer, cert.contentStart, cert.contentEnd)[0];
  const tbsChildren = readChildren(certDer, tbs.contentStart, tbs.contentEnd);
  let index = 0;
  if (tbsChildren[index] && tbsChildren[index].tag === CONTEXT_0) index++;
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  const spki = tbsChildren[index + 5];
  if (!spki || spki.tag !== Tag.SEQUENCE) throw new Error('certificate: missing subjectPublicKeyInfo');
  return nodeBytes(certDer, spki);
}
