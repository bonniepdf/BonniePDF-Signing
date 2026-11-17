/**
 * RFC 5652 CMS `SignedData` builder for a detached PDF signature.
 *
 * Produces the DER `ContentInfo` envelope that goes into the `/Contents`
 * entry of a PDF `/Sig` dictionary. Uses CMS signed attributes (contentType,
 * messageDigest, signingTime) - the form Adobe Acrobat and most validators
 * expect - so the signature is computed over the DER of the signed attributes
 * rather than over the document hash directly.
 *
 * When `pades` is set it also adds the ESS `signing-certificate-v2` signed
 * attribute required by the CAdES/PAdES baseline. An optional async
 * `timestamp` callback turns the finished signature into a PAdES B-T signature
 * by embedding an RFC 3161 token as an unsigned attribute.
 */
import * as der from './asn1/der';
import { Oids } from './asn1/oids';
import { extractIssuerAndSerial } from './asn1/x509';
import { AlgorithmParams } from './SigningAlgorithm';

export interface CmsInput {
  /** Resolved algorithm parameters. */
  params: AlgorithmParams;
  /** SHA digest of the signed PDF byte range (the messageDigest attribute). */
  messageDigest: Uint8Array;
  /** DER bytes of the signer's X.509 certificate. */
  certDer: Uint8Array;
  /** DER bytes of any intermediate certificates (included in the bag). */
  chainDer: Uint8Array[];
  /** The imported PKCS#8 private key. */
  privateKey: CryptoKey;
  /** Signing time recorded as a signed attribute. */
  signingTime: Date;
  /** Add the ESS signing-certificate-v2 signed attribute (PAdES baseline). */
  pades?: boolean;
  /**
   * Optional RFC 3161 timestamp provider. Given the raw signature value, it
   * returns the DER `TimeStampToken` (a CMS ContentInfo) to embed as the
   * signature-timestamp unsigned attribute (PAdES B-T).
   */
  timestamp?: (signatureValue: Uint8Array) => Promise<Uint8Array>;
}

/** AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters OPTIONAL }. */
function algorithmIdentifier(algOid: string, includeNull: boolean): Uint8Array {
  return includeNull ? der.sequence(der.oid(algOid), der.nullValue()) : der.sequence(der.oid(algOid));
}

/** Build a single CMS Attribute: SEQUENCE { attrType OID, attrValues SET }. */
function attribute(typeOid: string, value: Uint8Array): Uint8Array {
  return der.sequence(der.oid(typeOid), der.set(value));
}

/**
 * ESS signing-certificate-v2 (RFC 5035):
 *   SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
 *   ESSCertIDv2 ::= SEQUENCE { hashAlgorithm [DEFAULT sha256], certHash OCTET STRING, ... }
 * The certHash is the SHA-256 digest of the DER certificate; since SHA-256 is
 * the DEFAULT hashAlgorithm it is omitted (DER requires omitting defaults).
 */
async function signingCertificateV2(certDer: Uint8Array): Promise<Uint8Array> {
  const certHash = new Uint8Array(await crypto.subtle.digest('SHA-256', certDer as BufferSource));
  const essCertId = der.sequence(der.octetString(certHash));
  const signingCert = der.sequence(der.sequence(essCertId));
  return attribute(Oids.signingCertificateV2, signingCert);
}

/**
 * Build the signed attributes (order-independent; DER SET OF sorts them).
 *
 * `signing-time` is deliberately conditional. A legacy Adobe signature carries
 * it, and Acrobat reads it. PAdES does not: ETSI EN 319 142-1 lists the CMS
 * signing-time attribute as "shall not be present", because the signing time of
 * a PAdES signature is the `/M` entry of the signature dictionary. Emitting both
 * leaves two claims that can disagree, and a validator downgrades the signature
 * out of the baseline profile for it.
 */
async function buildSignedAttributes(input: CmsInput): Promise<Uint8Array[]> {
  const attrs = [
    attribute(Oids.contentType, der.oid(Oids.data)),
    attribute(Oids.messageDigest, der.octetString(input.messageDigest)),
  ];
  if (input.pades) attrs.push(await signingCertificateV2(input.certDer));
  else attrs.push(attribute(Oids.signingTime, der.utcTime(input.signingTime)));
  return attrs;
}

/**
 * Convert an ECDSA signature from Web Crypto's raw IEEE-P1363 `r || s` form to
 * the DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` CMS requires.
 */
function ecdsaP1363ToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const r = raw.subarray(0, half);
  const s = raw.subarray(half);
  return der.sequence(der.integerFromBytes(r), der.integerFromBytes(s));
}

/** The finished envelope, plus the timestamp token embedded in it. */
export interface CmsResult {
  /** The DER `ContentInfo` to place in `/Contents`. */
  cms: Uint8Array;
  /**
   * The RFC 3161 token, when one was requested.
   *
   * Handed back because a long-term signature has to carry validation material
   * for the timestamp authority as well as for the signer (ETSI EN 319 142-1
   * §5.5) - and the authority's certificates arrive inside the token, not from
   * the caller.
   */
  timestampToken?: Uint8Array;
}

/** Build the complete DER `ContentInfo` (signedData) envelope. */
export async function buildSignedData(input: CmsInput): Promise<CmsResult> {
  const { params } = input;
  const digestAlg = algorithmIdentifier(params.digestOid, true);
  const isRsa = params.keyType === 'rsa';

  // 1. Signed attributes. Sign over the DER `SET OF` (explicit 0x31 tag).
  const attrs = await buildSignedAttributes(input);
  const signedAttrsForSigning = der.setOf(attrs);
  // In SignerInfo the same content carries the implicit [0] tag (0xA0).
  const signedAttrsTagged = der.contextConstructed(0, stripOuterTag(signedAttrsForSigning));

  // 2. Produce the signature over the signed attributes.
  let signature: Uint8Array = new Uint8Array(
    await crypto.subtle.sign(params.signParams, input.privateKey, signedAttrsForSigning as BufferSource)
  );
  if (params.keyType === 'ec') signature = ecdsaP1363ToDer(signature);

  // 3. Optional RFC 3161 signature timestamp -> unsigned attribute (PAdES B-T).
  let unsignedAttrsTagged: Uint8Array | undefined;
  let timestampToken: Uint8Array | undefined;
  if (input.timestamp) {
    const token = await input.timestamp(signature);
    timestampToken = token;
    const tsAttr = attribute(Oids.signatureTimeStampToken, token);
    // unsignedAttrs is [1] IMPLICIT SET OF Attribute.
    unsignedAttrsTagged = der.tlv(0xa1, stripOuterTag(der.setOf([tsAttr])));
  }

  // 4. issuerAndSerialNumber from the certificate.
  const { issuer, serialNumber } = extractIssuerAndSerial(input.certDer);
  const issuerAndSerial = der.sequence(issuer, serialNumber);

  // 5. SignerInfo.
  const signerInfoFields = [
    der.integer(1), // version (issuerAndSerialNumber => v1)
    issuerAndSerial,
    digestAlg,
    signedAttrsTagged,
    algorithmIdentifier(params.signatureOid, isRsa), // ECDSA omits NULL params
    der.octetString(signature),
  ];
  if (unsignedAttrsTagged) signerInfoFields.push(unsignedAttrsTagged);
  const signerInfo = der.sequence(...signerInfoFields);

  // 6. Certificate bag: [0] IMPLICIT SET/SEQUENCE OF Certificate.
  const certBytes = der.concatBytes([input.certDer, ...input.chainDer]);
  const certificates = der.contextConstructed(0, certBytes);

  // 7. SignedData.
  const signedData = der.sequence(
    der.integer(1), // version
    der.set(digestAlg), // digestAlgorithms
    der.sequence(der.oid(Oids.data)), // encapContentInfo (detached: no eContent)
    certificates,
    der.set(signerInfo) // signerInfos
  );

  // 8. ContentInfo { signedData OID, [0] EXPLICIT SignedData }.
  return {
    cms: der.sequence(der.oid(Oids.signedData), der.contextConstructed(0, signedData)),
    timestampToken,
  };
}

/**
 * The DER certificates carried inside a CMS `SignedData` - used to recover a
 * timestamp authority's own certificates from the token it issued.
 *
 * Returns an empty list for anything it cannot make sense of: a token without
 * certificates is unusual but not an error worth failing a signature over.
 */
export function certificatesFromCms(cms: Uint8Array): Uint8Array[] {
  try {
    const root = der.readNode(cms, 0);
    const contentInfo = der.readChildren(cms, root.contentStart, root.contentEnd);
    const explicit = contentInfo[1];
    if (!explicit) return [];
    const signedData = der.readChildren(cms, explicit.contentStart, explicit.contentEnd)[0];
    const fields = der.readChildren(cms, signedData.contentStart, signedData.contentEnd);
    // certificates is [0] IMPLICIT CertificateSet, after encapContentInfo.
    const certs = fields.find(node => node.tag === 0xa0);
    if (!certs) return [];
    return der
      .readChildren(cms, certs.contentStart, certs.contentEnd)
      .filter(node => node.tag === der.Tag.SEQUENCE)
      .map(node => der.nodeBytes(cms, node));
  } catch {
    return [];
  }
}

/** Remove the outer tag+length from a TLV, returning just its content bytes. */
function stripOuterTag(tlv: Uint8Array): Uint8Array {
  const node = der.readNode(tlv, 0);
  return tlv.subarray(node.contentStart, node.contentEnd);
}
