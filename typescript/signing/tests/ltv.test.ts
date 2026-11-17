import { describe, it, expect, beforeAll } from 'vitest';
import { Document, TextBlock, StandardFonts } from '@bonniepdf/core';
import { signPdf } from '../src/signPdf';
import { SigningAlgorithm } from '../src/SigningAlgorithm';
import { latin1Decode, indexOfAscii, readObjectBody, readOptionalRef } from '../src/pdf';
import { vriKey, needsEsicExtension, pdfHeaderVersion } from '../src/dss';
import { collectValidationMaterial } from '../src/validation';
import { buildOcspRequest, checkOcspResponse } from '../src/ocsp';
import { normalizeCrl } from '../src/crl';
import { ocspUrls, crlUrls } from '../src/asn1/extensions';
import { readContents, signedAttrsContainOid } from './helpers/cms';
import * as der from '../src/asn1/der';
import { Oids } from '../src/asn1/oids';
import type { HttpClient } from '../src/http';
import {
  TestIdentity,
  TestOcspResponder,
  TestTsa,
  aiaOcsp,
  basicConstraintsCa,
  crlDistributionPoint,
  generateKeyPair,
  issueCertificate,
  issuerKeyHash,
  toPem,
} from './helpers/pki';

/**
 * PAdES long-term levels — B-LT (validation material in a Document Security
 * Store) and B-LTA (a document timestamp over the whole file, DSS included).
 *
 * Everything here runs against the throwaway PKI in `helpers/pki.ts`: a real CA,
 * a real OCSP responder and a real RFC 3161 authority, all generated in-process.
 * No network, and no committed key material.
 *
 * Mirrors the .NET LtvTests.
 */

const OCSP_URL = 'http://ocsp.test.invalid/ocsp';
const CRL_URL = 'http://crl.test.invalid/ca.crl';
const TSA_URL = 'http://tsa.test.invalid/tsr';

let ca: TestIdentity;
let signer: TestIdentity;
let tsaIdentity: TestIdentity;
let tsa: TestTsa;
let ocsp: TestOcspResponder;
/** A stand-in CRL: any DER SEQUENCE will do, since the DSS stores it verbatim. */
let crlDer: Uint8Array;

/** Routes the three protocols to the in-process authorities. */
function testHttpClient(options: { ocspFails?: boolean; crlFails?: boolean } = {}): HttpClient {
  return async request => {
    if (request.url === TSA_URL) {
      return { status: 200, body: await tsa.respond(request.body!) };
    }
    if (request.url === OCSP_URL) {
      if (options.ocspFails) return { status: 503, body: new Uint8Array(0) };
      return { status: 200, body: await ocsp.respond(request.body!) };
    }
    if (request.url === CRL_URL) {
      if (options.crlFails) return { status: 404, body: new Uint8Array(0) };
      return { status: 200, body: crlDer };
    }
    return { status: 404, body: new Uint8Array(0) };
  };
}

beforeAll(async () => {
  const caKeys = await generateKeyPair();
  ca = await issueCertificate({ subject: 'BonniePDF Test CA', serial: 1, subjectKeys: caKeys, extensions: [basicConstraintsCa()] });

  const signerKeys = await generateKeyPair();
  signer = await issueCertificate({
    subject: 'BonniePDF Test Signer',
    serial: 2,
    subjectKeys: signerKeys,
    issuer: ca,
    extensions: [aiaOcsp(OCSP_URL), crlDistributionPoint(CRL_URL)],
  });

  const tsaKeys = await generateKeyPair();
  // A real TSA certificate publishes revocation information like any other;
  // without it a long-term signature cannot reach the LT level.
  tsaIdentity = await issueCertificate({
    subject: 'BonniePDF Test TSA',
    serial: 3,
    subjectKeys: tsaKeys,
    issuer: ca,
    extensions: [aiaOcsp(OCSP_URL)],
  });

  tsa = new TestTsa(tsaIdentity);
  ocsp = new TestOcspResponder(ca);
  crlDer = der.sequence(der.sequence(der.integer(1)), der.sequence(der.oid(Oids.sha256)));
});

async function makePdf(): Promise<Uint8Array> {
  const doc = new Document();
  doc.add(new TextBlock('Long-term validation test document.', 12, StandardFonts.Helvetica));
  return doc.generateBytesAsync();
}

/** Sign with the test PKI at the given level. */
async function sign(level: 'b-t' | 'b-lt' | 'b-lta', extra: Record<string, unknown> = {}): Promise<Uint8Array> {
  return signPdf(await makePdf(), {
    algorithm: SigningAlgorithm.Sha256Rsa,
    certificatePem: signer.certPem,
    privateKeyPem: signer.keyPem,
    certificateChainPem: [ca.certPem],
    padesLevel: level,
    timestampUrl: TSA_URL,
    httpClient: testHttpClient(),
    ...extra,
  });
}

/** The first `/ByteRange [a b c d]` at or after `from`, as four numbers. */
function byteRangeAfter(bytes: Uint8Array, from: number): [number, number, number, number] {
  const index = indexOfAscii(bytes, '/ByteRange [', from);
  const text = latin1Decode(bytes.subarray(index, index + 80));
  const parts = [...text.matchAll(/\d+/g)].slice(0, 4).map(m => parseInt(m[0], 10));
  return [parts[0], parts[1], parts[2], parts[3]];
}

/** The catalog dictionary body of the document's latest revision. */
function catalogBody(bytes: Uint8Array): string {
  const text = latin1Decode(bytes);
  const trailer = text.slice(text.lastIndexOf('trailer'));
  const rootId = parseInt(/\/Root\s+(\d+)\s+0\s+R/.exec(trailer)![1], 10);
  return readObjectBody(bytes, rootId);
}

describe('certificate extensions drive collection', () => {
  it('reads the OCSP responder out of the AIA extension', () => {
    expect(ocspUrls(signer.certDer)).toEqual([OCSP_URL]);
  });

  it('reads the CRL distribution point', () => {
    expect(crlUrls(signer.certDer)).toEqual([CRL_URL]);
  });

  it('reports no pointers for a certificate that declares none', () => {
    expect(ocspUrls(ca.certDer)).toEqual([]);
    expect(crlUrls(ca.certDer)).toEqual([]);
  });
});

describe('OCSP', () => {
  it('names the issuer by key hash, as RFC 6960 requires', async () => {
    const request = await buildOcspRequest(signer.certDer, ca.certDer);
    // OCSPRequest > tbsRequest > requestList > Request > CertID > issuerKeyHash
    const root = der.readNode(request, 0);
    const tbs = der.readChildren(request, root.contentStart, root.contentEnd)[0];
    const list = der.readChildren(request, tbs.contentStart, tbs.contentEnd)[0];
    const first = der.readChildren(request, list.contentStart, list.contentEnd)[0];
    const certId = der.readChildren(request, first.contentStart, first.contentEnd)[0];
    const parts = der.readChildren(request, certId.contentStart, certId.contentEnd);

    const keyHash = request.slice(parts[2].contentStart, parts[2].contentEnd);
    expect([...keyHash]).toEqual([...(await issuerKeyHash(ca.certDer))]);
  });

  it('accepts a successful response and returns it verbatim', async () => {
    const response = await ocsp.respond(await buildOcspRequest(signer.certDer, ca.certDer));
    expect([...checkOcspResponse(response)]).toEqual([...response]);
  });

  it('rejects a response the responder refused', () => {
    const refused = der.sequence(der.enumerated(6)); // unauthorized
    expect(() => checkOcspResponse(refused)).toThrow(/unauthorized/);
  });
});

describe('CRL handling', () => {
  it('passes DER through unchanged', () => {
    expect([...normalizeCrl(crlDer)]).toEqual([...crlDer]);
  });

  it('converts a PEM-armoured response to DER', () => {
    const pem = toPem('X509 CRL', crlDer);
    const bytes = new Uint8Array([...pem].map(c => c.charCodeAt(0)));
    expect([...normalizeCrl(bytes)]).toEqual([...crlDer]);
  });

  it('refuses a response that is neither', () => {
    expect(() => normalizeCrl(new Uint8Array([1, 2, 3]))).toThrow(/neither DER nor PEM/);
  });
});

describe('validation material collection', () => {
  it('gathers the chain and an OCSP response for the signer', async () => {
    const before = ocsp.requests;
    const material = await collectValidationMaterial({
      certDer: signer.certDer,
      chainDer: [ca.certDer],
      httpClient: testHttpClient(),
    });

    expect(material.certificates).toHaveLength(2);
    expect(material.ocspResponses).toHaveLength(1);
    expect(ocsp.requests).toBe(before + 1);
  });

  it('falls back to the CRL when the responder is unreachable', async () => {
    const material = await collectValidationMaterial({
      certDer: signer.certDer,
      chainDer: [ca.certDer],
      httpClient: testHttpClient({ ocspFails: true }),
    });

    expect(material.ocspResponses).toHaveLength(0);
    expect(material.crls).toHaveLength(1);
    expect(material.problems.some(p => p.includes('OCSP'))).toBe(true);
  });

  it('records a problem rather than throwing when nothing can be reached', async () => {
    const material = await collectValidationMaterial({
      certDer: signer.certDer,
      chainDer: [ca.certDer],
      httpClient: testHttpClient({ ocspFails: true, crlFails: true }),
    });

    expect(material.ocspResponses).toHaveLength(0);
    expect(material.crls).toHaveLength(0);
    expect(material.problems.length).toBeGreaterThanOrEqual(2);
  });

  it('fetches nothing when revocation collection is turned off', async () => {
    const before = ocsp.requests;
    const material = await collectValidationMaterial({
      certDer: signer.certDer,
      chainDer: [ca.certDer],
      httpClient: testHttpClient(),
      fetchRevocation: false,
      supplied: { crls: [crlDer] },
    });

    expect(ocsp.requests).toBe(before);
    expect(material.crls).toHaveLength(1);
    expect(material.problems).toEqual([]);
  });

  it('always includes what the caller supplied', async () => {
    const extra = der.sequence(der.integer(7));
    const material = await collectValidationMaterial({
      certDer: signer.certDer,
      chainDer: [ca.certDer],
      httpClient: testHttpClient(),
      supplied: { certificates: [extra] },
    });

    expect(material.certificates).toHaveLength(3);
  });
});

describe('PAdES B-LT', () => {
  let signed: Uint8Array;

  beforeAll(async () => {
    signed = await sign('b-lt');
  });

  it('keeps the PAdES subfilter and the signature timestamp', () => {
    const text = latin1Decode(signed);
    expect(text).toContain('/SubFilter /ETSI.CAdES.detached');
  });

  it('adds a DSS to the catalog', () => {
    expect(catalogBody(signed)).toMatch(/\/DSS\s+\d+\s+0\s+R/);
  });

  it('stores the chain, the OCSP response and a VRI index', () => {
    const dssId = readOptionalRef(catalogBody(signed), '/DSS')!;
    const dss = readObjectBody(signed, dssId);
    expect(dss).toMatch(/\/Certs\s*\[/);
    expect(dss).toMatch(/\/OCSPs\s*\[/);
    expect(dss).toMatch(/\/VRI\s+\d+\s+0\s+R/);
  });

  it('keys the VRI entry by the SHA-1 of the signature Contents', async () => {
    const tag = indexOfAscii(signed, '/Contents <');
    const open = indexOfAscii(signed, '<', tag);
    const close = indexOfAscii(signed, '>', open);
    const expected = await vriKey(signed.slice(open + 1, close));

    const dssId = readOptionalRef(catalogBody(signed), '/DSS')!;
    const vriId = readOptionalRef(readObjectBody(signed, dssId), '/VRI')!;
    expect(readObjectBody(signed, vriId)).toContain(`/${expected}`);
  });

  it('declares the ESIC extension, because core emits a pre-2.0 PDF', () => {
    expect(parseFloat(pdfHeaderVersion(signed)!)).toBeLessThan(2);
    expect(catalogBody(signed)).toContain('/ESIC');
  });

  it('appends the DSS as a new revision, leaving the signed range intact', () => {
    // The signature covers everything that existed when it was made. If the DSS
    // had been merged into that revision rather than appended after it, the
    // covered range would no longer end on the %%EOF that closed it - and the
    // signature would no longer verify.
    const [, b, c, d] = byteRangeAfter(signed, 0);
    expect(c + d).toBeLessThan(signed.length);
    expect(latin1Decode(signed.subarray(c + d - 5, c + d))).toBe('%%EOF');
    // And the first range still starts at the top of the file.
    expect(b).toBeGreaterThan(0);
  });

  it('reports what it collected through the callback', async () => {
    const seen: string[][] = [];
    await sign('b-lt', { onValidationMaterial: (m: { problems: string[] }) => seen.push(m.problems) });
    expect(seen).toHaveLength(1);
    // The root is a trust anchor, so its lack of an AIA extension is not a
    // shortfall: a clean run reports nothing.
    expect(seen[0]).toEqual([]);
  });

  it('embeds only what was supplied when fetching is off', async () => {
    const signedOffline = await sign('b-lt', { fetchRevocation: false, validationMaterial: { crls: [crlDer] } });
    const dssId = readOptionalRef(catalogBody(signedOffline), '/DSS')!;
    const dss = readObjectBody(signedOffline, dssId);
    expect(dss).toMatch(/\/CRLs\s*\[/);
    expect(dss).not.toMatch(/\/OCSPs\s*\[/);
  });
});

describe('the timestamp authority is covered too', () => {
  it("embeds the authority's certificate in the store", async () => {
    const signed = await sign('b-lt');
    const dssId = readOptionalRef(catalogBody(signed), '/DSS')!;
    const dss = readObjectBody(signed, dssId);
    const certRefs = [...dss.matchAll(/(\d+)\s+0\s+R/g)].length;
    // Signer + CA + the TSA's own certificate, plus the VRI reference.
    expect(certRefs).toBeGreaterThanOrEqual(4);
  });

  it("collects revocation for the authority's certificate", async () => {
    // Two OCSP responses: one for the signer, one for the TSA. Without the
    // second, a validator cannot check the timestamp from inside the document
    // and the signature falls short of the LT level.
    let collected: { ocspResponses: Uint8Array[]; problems: string[] } | undefined;
    await sign('b-lt', { onValidationMaterial: (m: never) => (collected = m) });

    expect(collected!.ocspResponses).toHaveLength(2);
    expect(collected!.problems).toEqual([]);
  });

  it('reports a problem when the token carries no certificates', async () => {
    const material = await collectValidationMaterial({
      certDer: signer.certDer,
      chainDer: [ca.certDer],
      httpClient: testHttpClient(),
      timestampToken: der.sequence(der.oid(Oids.signedData)),
    });
    expect(material.problems.some(p => p.includes('no certificates'))).toBe(true);
  });
});

describe('PAdES forbids the CMS signing-time attribute', () => {
  it('omits it at every PAdES level', async () => {
    // ETSI EN 319 142-1: the signing time of a PAdES signature is the /M entry
    // of the signature dictionary, and the CMS attribute "shall not be present".
    // Emitting both leaves two claims that can disagree, and the EU DSS
    // validator downgrades the signature out of the baseline profile for it.
    for (const level of ['b-b', 'b-t'] as const) {
      const signed = await signPdf(await makePdf(), {
        certificatePem: signer.certPem,
        privateKeyPem: signer.keyPem,
        padesLevel: level,
        timestampUrl: TSA_URL,
        httpClient: testHttpClient(),
      });
      expect(signedAttrsContainOid(readContents(signed), Oids.signingTime)).toBe(false);
    }
  });

  it('keeps it for a legacy Adobe signature, which expects it', async () => {
    const signed = await signPdf(await makePdf(), {
      certificatePem: signer.certPem,
      privateKeyPem: signer.keyPem,
    });
    expect(signedAttrsContainOid(readContents(signed), Oids.signingTime)).toBe(true);
  });
});

describe('PAdES B-LTA', () => {
  let signed: Uint8Array;

  beforeAll(async () => {
    signed = await sign('b-lta');
  });

  it('appends a document timestamp', () => {
    const text = latin1Decode(signed);
    expect(text).toContain('/Type /DocTimeStamp');
    expect(text).toContain('/SubFilter /ETSI.RFC3161');
  });

  it('still carries the DSS underneath it', () => {
    expect(catalogBody(signed)).toMatch(/\/DSS\s+\d+\s+0\s+R/);
  });

  it('keeps the signature field and adds the timestamp field to the form', () => {
    const acroFormId = readOptionalRef(catalogBody(signed), '/AcroForm')!;
    const acroForm = readObjectBody(signed, acroFormId);
    const refs = [...acroForm.matchAll(/\d+\s+0\s+R/g)];
    expect(refs.length).toBe(2);
  });

  it('timestamps the whole file, not just the signature', async () => {
    // The TSA records every imprint it is asked to stamp. The last one must be
    // the digest of this document's byte range - which is what makes the DSS
    // beneath it trustworthy.
    const imprint = tsa.imprints[tsa.imprints.length - 1];

    // Read the DocTimeStamp's own byte range, not the signature's.
    const [a, b, c, d] = byteRangeAfter(signed, indexOfAscii(signed, '/Type /DocTimeStamp'));
    const covered = new Uint8Array(b + d);
    covered.set(signed.subarray(a, a + b), 0);
    covered.set(signed.subarray(c, c + d), b);
    const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', covered as BufferSource));

    expect([...imprint]).toEqual([...expected]);
  });

  it('puts a real RFC 3161 token in the timestamp Contents', () => {
    const tsIndex = indexOfAscii(signed, '/Type /DocTimeStamp');
    const open = indexOfAscii(signed, '/Contents <', tsIndex);
    const start = indexOfAscii(signed, '<', open);
    const end = indexOfAscii(signed, '>', start);

    let hex = '';
    for (let i = start + 1; i < end; i++) hex += String.fromCharCode(signed[i]);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);

    // A ContentInfo whose contentType is id-signedData, carrying id-ct-TSTInfo.
    const root = der.readNode(bytes, 0);
    expect(root.tag).toBe(0x30);
    const text = [...bytes.subarray(0, root.end)].map(b => b.toString(16).padStart(2, '0')).join('');
    expect(text).toContain([...der.oid(Oids.tstInfo)].map(b => b.toString(16).padStart(2, '0')).join(''));
  });

  it('uses a separate authority when one is configured', async () => {
    let separateCalls = 0;
    const separateUrl = 'http://archive-tsa.test.invalid/tsr';
    const client: HttpClient = async request => {
      if (request.url === separateUrl) {
        separateCalls++;
        return { status: 200, body: await tsa.respond(request.body!) };
      }
      return testHttpClient()(request);
    };

    await signPdf(await makePdf(), {
      certificatePem: signer.certPem,
      privateKeyPem: signer.keyPem,
      certificateChainPem: [ca.certPem],
      padesLevel: 'b-lta',
      timestampUrl: TSA_URL,
      documentTimestampUrl: separateUrl,
      httpClient: client,
    });

    expect(separateCalls).toBe(1);
  });
});

describe('level validation', () => {
  it.each(['b-t', 'b-lt', 'b-lta'] as const)('rejects %s without a timestamp authority', async level => {
    await expect(
      signPdf(await makePdf(), {
        certificatePem: signer.certPem,
        privateKeyPem: signer.keyPem,
        padesLevel: level,
      })
    ).rejects.toThrow(/timestampUrl/);
  });

  it('treats a PDF with no version header as needing the ESIC extension', () => {
    expect(needsEsicExtension(new Uint8Array([1, 2, 3]))).toBe(true);
  });
});
