/**
 * A throwaway public-key infrastructure, built at test time.
 *
 * The signing package must never ship committed private keys, so every
 * certificate, responder and authority the long-term-validation tests need is
 * generated here, in-process, and lives only as long as the test run.
 *
 * It is a real PKI, not a set of stubs: the certificates are DER-encoded X.509
 * with the extensions the collector reads, the timestamp tokens are RFC 3161
 * `TimeStampToken`s signed by a TSA key, and the OCSP responses are signed
 * `BasicOCSPResponse`s. That matters - a test that fed the implementation
 * handmade DER would prove only that our own parser agrees with our own writer.
 */
import * as der from '../../src/asn1/der';
import { Oids } from '../../src/asn1/oids';
import { extractSubject, extractPublicKeyBits } from '../../src/asn1/extensions';
import { extractIssuerAndSerial } from '../../src/asn1/x509';
import { bytesToBase64 } from '../../src/pem';

const SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
const OID_COMMON_NAME = '2.5.4.3';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_TSA_POLICY = '1.3.6.1.4.1.13762.3'; // arbitrary test policy

/** A generated key pair plus the SPKI bytes its certificate needs. */
export interface TestKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  spki: Uint8Array;
  pkcs8: Uint8Array;
}

/** A certificate and the key that signs with it. */
export interface TestIdentity {
  certDer: Uint8Array;
  certPem: string;
  keyPem: string;
  keys: TestKeyPair;
}

/** Generate an extractable RSA-2048 key pair. */
export async function generateKeyPair(): Promise<TestKeyPair> {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    spki: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
    pkcs8: new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)),
  };
}

/** `Name` holding a single common-name RDN. */
export function commonName(value: string): Uint8Array {
  return der.sequence(der.set(der.sequence(der.oid(OID_COMMON_NAME), der.utf8String(value))));
}

/** `Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue OCTET STRING }`. */
function extension(oid: string, value: Uint8Array, critical = false): Uint8Array {
  const parts = critical
    ? [der.oid(oid), der.boolean(true), der.octetString(value)]
    : [der.oid(oid), der.octetString(value)];
  return der.sequence(...parts);
}

/** `AuthorityInfoAccess` naming an OCSP responder. */
export function aiaOcsp(url: string): Uint8Array {
  const description = der.sequence(der.oid(Oids.adOcsp), der.tlv(0x86, new TextEncoder().encode(url)));
  return extension(Oids.authorityInfoAccess, der.sequence(description));
}

/** `CRLDistributionPoints` naming one HTTP distribution point. */
export function crlDistributionPoint(url: string): Uint8Array {
  const fullName = der.tlv(0xa0, der.tlv(0x86, new TextEncoder().encode(url)));
  const distributionPoint = der.sequence(der.tlv(0xa0, fullName));
  return extension(Oids.crlDistributionPoints, der.sequence(distributionPoint));
}

/** `BasicConstraints { cA TRUE }`, marking a certificate as an issuer. */
export function basicConstraintsCa(): Uint8Array {
  return extension(OID_BASIC_CONSTRAINTS, der.sequence(der.boolean(true)), true);
}

export interface CertificateSpec {
  subject: string;
  serial: number;
  subjectKeys: TestKeyPair;
  /** Omit for a self-signed certificate. */
  issuer?: TestIdentity;
  extensions?: Uint8Array[];
  notBefore?: Date;
  notAfter?: Date;
}

/** Build and sign an X.509 v3 certificate. */
export async function issueCertificate(spec: CertificateSpec): Promise<TestIdentity> {
  const issuerName = spec.issuer ? extractSubject(spec.issuer.certDer) : commonName(spec.subject);
  const signingKey = spec.issuer ? spec.issuer.keys.privateKey : spec.subjectKeys.privateKey;

  const notBefore = spec.notBefore ?? new Date(Date.now() - 86_400_000);
  const notAfter = spec.notAfter ?? new Date(Date.now() + 365 * 86_400_000);

  const algorithm = der.sequence(der.oid(SHA256_WITH_RSA), der.nullValue());
  const fields: Uint8Array[] = [
    der.contextConstructed(0, der.integer(2)), // v3
    der.integer(spec.serial),
    algorithm,
    issuerName,
    der.sequence(der.utcTime(notBefore), der.utcTime(notAfter)),
    commonName(spec.subject),
    spec.subjectKeys.spki,
  ];
  if (spec.extensions?.length) {
    fields.push(der.tlv(0xa3, der.sequence(...spec.extensions)));
  }

  const tbs = der.sequence(...fields);
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, signingKey, tbs as BufferSource)
  );
  const certDer = der.sequence(tbs, algorithm, der.bitString(signature));

  return {
    certDer,
    certPem: toPem('CERTIFICATE', certDer),
    keyPem: toPem('PRIVATE KEY', spec.subjectKeys.pkcs8),
    keys: spec.subjectKeys,
  };
}

/** Wrap DER in PEM armour, 64 characters to a line. */
export function toPem(label: string, derBytes: Uint8Array): string {
  const body = bytesToBase64(derBytes).replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

// ───────────────────────────── CMS signing ─────────────────────────────────

/**
 * Build a CMS `SignedData` carrying `content` under `contentTypeOid`.
 *
 * Used for both the timestamp tokens and the OCSP responses below, which are the
 * same shape with different payloads.
 */
async function buildAttachedSignedData(
  contentTypeOid: string,
  content: Uint8Array,
  signer: TestIdentity,
  includeSigningCertificate = false
): Promise<Uint8Array> {
  const digestAlgorithm = der.sequence(der.oid(Oids.sha256), der.nullValue());
  const messageDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', content as BufferSource));

  const attributes = [
    der.sequence(der.oid(Oids.contentType), der.set(der.oid(contentTypeOid))),
    der.sequence(der.oid(Oids.signingTime), der.set(der.utcTime(new Date()))),
    der.sequence(der.oid(Oids.messageDigest), der.set(der.octetString(messageDigest))),
  ];
  if (includeSigningCertificate) {
    // RFC 3161 §2.4.1: the token's SignerInfo must carry an ESS
    // signing-certificate attribute binding the token to the TSA's certificate.
    // Without it a validator discards the token outright, so a test authority
    // that omits it would quietly certify tokens no real validator accepts.
    const certHash = new Uint8Array(await crypto.subtle.digest('SHA-256', signer.certDer as BufferSource));
    const essCertId = der.sequence(der.octetString(certHash));
    attributes.push(
      der.sequence(der.oid(Oids.signingCertificateV2), der.set(der.sequence(der.sequence(essCertId))))
    );
  }
  const signedAttrsSet = der.setOf(attributes);
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, signer.keys.privateKey, signedAttrsSet as BufferSource)
  );

  const { issuer, serialNumber } = extractIssuerAndSerial(signer.certDer);
  const signerInfo = der.sequence(
    der.integer(1),
    der.sequence(issuer, serialNumber),
    digestAlgorithm,
    der.tlv(0xa0, stripTag(signedAttrsSet)),
    der.sequence(der.oid(Oids.rsaEncryption), der.nullValue()),
    der.octetString(signature)
  );

  const signedData = der.sequence(
    der.integer(3),
    der.set(digestAlgorithm),
    der.sequence(der.oid(contentTypeOid), der.contextConstructed(0, der.octetString(content))),
    der.contextConstructed(0, signer.certDer),
    der.set(signerInfo)
  );

  return der.sequence(der.oid(Oids.signedData), der.contextConstructed(0, signedData));
}

function stripTag(tlv: Uint8Array): Uint8Array {
  const node = der.readNode(tlv, 0);
  return tlv.subarray(node.contentStart, node.contentEnd);
}

// ───────────────────────── Time-Stamp Authority ────────────────────────────

/** A test TSA: answers `TimeStampReq`s with real signed tokens. */
export class TestTsa {
  private serial = 1;

  /** Imprints this authority has been asked to stamp, in order. */
  public readonly imprints: Uint8Array[] = [];

  constructor(private readonly identity: TestIdentity) {}

  /** Handle a DER `TimeStampReq` and return a DER `TimeStampResp`. */
  public async respond(request: Uint8Array): Promise<Uint8Array> {
    const root = der.readNode(request, 0);
    const children = der.readChildren(request, root.contentStart, root.contentEnd);
    const messageImprint = children[1];
    const imprintParts = der.readChildren(request, messageImprint.contentStart, messageImprint.contentEnd);
    const hashed = imprintParts[1];
    this.imprints.push(request.slice(hashed.contentStart, hashed.contentEnd));

    const tstInfo = der.sequence(
      der.integer(1),
      der.oid(OID_TSA_POLICY),
      der.nodeBytes(request, messageImprint),
      der.integer(this.serial++),
      der.generalizedTime(new Date())
    );

    const token = await buildAttachedSignedData(Oids.tstInfo, tstInfo, this.identity, true);
    return der.sequence(der.sequence(der.integer(0)), token);
  }
}

// ──────────────────────────── OCSP responder ───────────────────────────────

/** A test OCSP responder that answers `good` for everything it is asked. */
export class TestOcspResponder {
  /** Requests this responder has served, in order. */
  public requests = 0;

  constructor(private readonly identity: TestIdentity) {}

  /** Handle a DER `OCSPRequest` and return a DER `OCSPResponse`. */
  public async respond(request: Uint8Array): Promise<Uint8Array> {
    this.requests++;

    // OCSPRequest > tbsRequest > requestList > Request > reqCert (CertID)
    const root = der.readNode(request, 0);
    const tbsRequest = der.readChildren(request, root.contentStart, root.contentEnd)[0];
    const requestList = der.readChildren(request, tbsRequest.contentStart, tbsRequest.contentEnd).pop()!;
    const first = der.readChildren(request, requestList.contentStart, requestList.contentEnd)[0];
    const certId = der.readChildren(request, first.contentStart, first.contentEnd)[0];

    const singleResponse = der.sequence(
      der.nodeBytes(request, certId),
      der.tlv(0x80, new Uint8Array(0)), // certStatus: good [0] IMPLICIT NULL
      der.generalizedTime(new Date())
    );

    // ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }. Name is
    // itself a CHOICE, so [1] is EXPLICIT: the whole Name TLV goes inside the
    // tag, not its content. Tagging it implicitly produces DER that decodes as
    // "unexpected explicit encoding" and is discarded by a real validator.
    const responseData = der.sequence(
      der.contextConstructed(0, der.integer(0)), // version v1
      der.contextConstructed(1, extractSubject(this.identity.certDer)), // responderID byName
      der.generalizedTime(new Date()),
      der.sequence(singleResponse)
    );

    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: 'RSASSA-PKCS1-v1_5' },
        this.identity.keys.privateKey,
        responseData as BufferSource
      )
    );
    const basic = der.sequence(
      responseData,
      der.sequence(der.oid(SHA256_WITH_RSA), der.nullValue()),
      der.bitString(signature),
      der.contextConstructed(0, der.sequence(this.identity.certDer))
    );

    return der.sequence(
      der.enumerated(0), // responseStatus: successful
      der.contextConstructed(0, der.sequence(der.oid(Oids.ocspBasicResponse), der.octetString(basic)))
    );
  }
}

/** The key hash an OCSP `CertID` carries for a given issuer, for assertions. */
export async function issuerKeyHash(issuerDer: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-1', extractPublicKeyBits(issuerDer) as BufferSource));
}
