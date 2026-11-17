/**
 * The slice of X.509 extension parsing needed to find a certificate's
 * revocation information: where its OCSP responder lives, where its CRL is
 * published, and the issuer key hash an OCSP request has to carry.
 *
 * A reader of well-formed DER, not a validating parser - it deliberately does no
 * expiry, chain, or signature checking. Anything it cannot make sense of it
 * reports as absent rather than throwing, because a certificate without
 * revocation pointers is a normal thing to meet, not an error.
 */
import { readNode, readChildren, nodeBytes, DerNode, Tag } from './der';
import { Oids } from './oids';

const CONTEXT_0 = 0xa0;

/** Decode a DER OBJECT IDENTIFIER's content bytes to dotted-decimal. */
export function oidString(bytes: Uint8Array, node: DerNode): string {
  const content = bytes.subarray(node.contentStart, node.contentEnd);
  if (content.length === 0) return '';
  const parts: number[] = [Math.floor(content[0] / 40), content[0] % 40];
  let value = 0;
  for (let i = 1; i < content.length; i++) {
    value = value * 128 + (content[i] & 0x7f);
    if (!(content[i] & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/** The TBSCertificate fields, in order, skipping the optional `[0]` version. */
function tbsFields(certDer: Uint8Array): { fields: DerNode[]; firstIndex: number } {
  const cert = readNode(certDer, 0);
  const tbs = readChildren(certDer, cert.contentStart, cert.contentEnd)[0];
  const fields = readChildren(certDer, tbs.contentStart, tbs.contentEnd);
  return { fields, firstIndex: fields[0]?.tag === CONTEXT_0 ? 1 : 0 };
}

/**
 * The certificate's extensions, as a map from OID to the extension's
 * `extnValue` OCTET STRING content. Empty when the certificate has none.
 *
 * Extensions are `[3] EXPLICIT Extensions` - the last TBSCertificate field.
 */
export function readExtensions(certDer: Uint8Array): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  let fields: DerNode[];
  try {
    ({ fields } = tbsFields(certDer));
  } catch {
    return out;
  }

  const wrapper = fields.find(f => f.tag === 0xa3);
  if (!wrapper) return out;

  const sequence = readChildren(certDer, wrapper.contentStart, wrapper.contentEnd)[0];
  if (!sequence) return out;

  for (const extension of readChildren(certDer, sequence.contentStart, sequence.contentEnd)) {
    const parts = readChildren(certDer, extension.contentStart, extension.contentEnd);
    if (parts.length === 0 || parts[0].tag !== Tag.OID) continue;
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    const value = parts[parts.length - 1];
    if (value.tag !== Tag.OCTET_STRING) continue;
    out.set(oidString(certDer, parts[0]), certDer.slice(value.contentStart, value.contentEnd));
  }
  return out;
}

/** Collect every `uniformResourceIdentifier` (`[6] IA5String`) in a DER subtree. */
function collectUris(bytes: Uint8Array, start: number, end: number, into: string[]): void {
  for (const node of readChildren(bytes, start, end)) {
    if (node.tag === 0x86) {
      into.push(latin1(bytes.subarray(node.contentStart, node.contentEnd)));
    } else if ((node.tag & 0x20) !== 0) {
      // Constructed: recurse. GeneralNames nest several levels deep inside a
      // DistributionPoint, and the exact depth varies between issuers.
      collectUris(bytes, node.contentStart, node.contentEnd, into);
    }
  }
}

function latin1(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
}

/**
 * OCSP responder URLs from the Authority Information Access extension
 * (RFC 5280 §4.2.2.1), in the order the certificate lists them.
 */
export function ocspUrls(certDer: Uint8Array): string[] {
  return accessUrls(certDer, Oids.adOcsp);
}

/** `caIssuers` URLs from the same extension - where to fetch the issuer certificate. */
export function caIssuerUrls(certDer: Uint8Array): string[] {
  return accessUrls(certDer, Oids.adCaIssuers);
}

function accessUrls(certDer: Uint8Array, method: string): string[] {
  const value = readExtensions(certDer).get(Oids.authorityInfoAccess);
  if (!value) return [];

  const out: string[] = [];
  try {
    const sequence = readNode(value, 0);
    for (const description of readChildren(value, sequence.contentStart, sequence.contentEnd)) {
      const parts = readChildren(value, description.contentStart, description.contentEnd);
      if (parts.length < 2 || parts[0].tag !== Tag.OID) continue;
      if (oidString(value, parts[0]) !== method) continue;
      if (parts[1].tag === 0x86) out.push(latin1(value.subarray(parts[1].contentStart, parts[1].contentEnd)));
    }
  } catch {
    return [];
  }
  return out;
}

/** CRL distribution-point URLs (RFC 5280 §4.2.1.13), in certificate order. */
export function crlUrls(certDer: Uint8Array): string[] {
  const value = readExtensions(certDer).get(Oids.crlDistributionPoints);
  if (!value) return [];

  const out: string[] = [];
  try {
    const sequence = readNode(value, 0);
    collectUris(value, sequence.contentStart, sequence.contentEnd, out);
  } catch {
    return [];
  }
  return out.filter(url => /^https?:/i.test(url));
}

/** The DER `subject` Name of a certificate, as a full TLV. */
export function extractSubject(certDer: Uint8Array): Uint8Array {
  const { fields, firstIndex } = tbsFields(certDer);
  // serialNumber, signature, issuer, validity, subject
  const subject = fields[firstIndex + 4];
  if (!subject || subject.tag !== Tag.SEQUENCE) throw new Error('certificate: missing subject');
  return nodeBytes(certDer, subject);
}

/** The DER `issuer` Name of a certificate, as a full TLV. */
export function extractIssuerName(certDer: Uint8Array): Uint8Array {
  const { fields, firstIndex } = tbsFields(certDer);
  // serialNumber, signature, issuer
  const issuer = fields[firstIndex + 2];
  if (!issuer || issuer.tag !== Tag.SEQUENCE) throw new Error('certificate: missing issuer');
  return nodeBytes(certDer, issuer);
}

/**
 * The raw public-key bits of a certificate's SubjectPublicKeyInfo - the BIT
 * STRING content with its "unused bits" prefix byte removed.
 *
 * This is what an OCSP `CertID.issuerKeyHash` is computed over (RFC 6960
 * §4.1.1): the key itself, not the algorithm identifier wrapped around it.
 */
export function extractPublicKeyBits(certDer: Uint8Array): Uint8Array {
  const { fields, firstIndex } = tbsFields(certDer);
  const spki = fields[firstIndex + 5];
  if (!spki || spki.tag !== Tag.SEQUENCE) throw new Error('certificate: missing subjectPublicKeyInfo');

  const parts = readChildren(certDer, spki.contentStart, spki.contentEnd);
  const bitString = parts.find(node => node.tag === Tag.BIT_STRING);
  if (!bitString) throw new Error('certificate: subjectPublicKeyInfo has no key');
  // Skip the leading "unused bits" count, which is always 0 for a public key.
  return certDer.slice(bitString.contentStart + 1, bitString.contentEnd);
}
