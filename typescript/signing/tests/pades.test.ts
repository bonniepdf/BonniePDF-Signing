import { describe, it, expect, beforeAll } from 'vitest';
import { Document, TextBlock, StandardFonts } from '@bonniepdf/core';
import { signPdf } from '../src/signPdf';
import { SigningAlgorithm } from '../src/SigningAlgorithm';
import { latin1Decode, indexOfAscii } from '../src/pdf';
import { buildTimeStampReq, checkTimeStampToken, extractTokenFromResponse } from '../src/timestamp';
import { TestTsa, generateKeyPair, issueCertificate } from './helpers/pki';
import { verifyCms, parseCms, readContents, signedAttrsContainOid } from './helpers/cms';
import * as der from '../src/asn1/der';
import { Oids } from '../src/asn1/oids';
import { readNode } from '../src/asn1/der';
import { readFileSync } from 'fs';
import { join } from 'path';

const fixtures = join(__dirname, 'fixtures', 'signing');
const certRsa = readFileSync(join(fixtures, 'cert-rsa.pem'), 'utf8');
const keyRsa = readFileSync(join(fixtures, 'key-rsa.pem'), 'utf8');

/** An in-process RFC 3161 authority that answers what it is asked. */
let tsa: TestTsa;
beforeAll(async () => {
  tsa = new TestTsa(
    await issueCertificate({ subject: 'BonniePDF Test TSA', serial: 1, subjectKeys: await generateKeyPair() })
  );
});

async function makePdf(): Promise<Uint8Array> {
  const doc = new Document();
  doc.add(new TextBlock('PAdES test document.', 12, StandardFonts.Helvetica));
  const bytes = await doc.generateBytesAsync();
  doc.dispose?.();
  return bytes;
}

describe('PAdES B-B', () => {
  let signed: Uint8Array;

  beforeAll(async () => {
    signed = await signPdf(await makePdf(), {
      algorithm: SigningAlgorithm.Sha256Rsa,
      certificatePem: certRsa,
      privateKeyPem: keyRsa,
      padesLevel: 'b-b',
      reason: 'Approved',
    });
  });

  it('uses the ETSI.CAdES.detached subfilter', () => {
    expect(latin1Decode(signed)).toContain('/SubFilter /ETSI.CAdES.detached');
  });

  it('adds the signing-certificate-v2 signed attribute', () => {
    const cms = readContents(signed);
    expect(signedAttrsContainOid(cms, Oids.signingCertificateV2)).toBe(true);
  });

  it('still verifies cryptographically (RSA)', async () => {
    const cms = readContents(signed);
    expect(await verifyCms(cms, certRsa, { hashName: 'SHA-256', keyType: 'rsa' })).toBe(true);
  });
});

describe('RFC 3161 timestamp encoding', () => {
  it('builds a TimeStampReq with version, imprint and certReq', () => {
    const imprint = new Uint8Array(32).fill(7);
    const req = buildTimeStampReq(imprint, 'SHA-256', new Uint8Array([1, 2, 3]));
    const root = der.readNode(req, 0);
    expect(root.tag).toBe(0x30);
    const children = der.readChildren(req, root.contentStart, root.contentEnd);
    expect(children[0].tag).toBe(0x02); // version INTEGER
    expect(children[1].tag).toBe(0x30); // messageImprint SEQUENCE
    // certReq BOOLEAN TRUE is the last element.
    const last = children[children.length - 1];
    expect(last.tag).toBe(0x01);
    expect(req[last.contentStart]).toBe(0xff);
  });

  it('extracts the token from a granted TimeStampResp', () => {
    // status granted (0); timeStampToken = a minimal ContentInfo SEQUENCE.
    const token = der.sequence(der.oid(Oids.signedData));
    const resp = der.sequence(der.sequence(der.integer(0)), token);
    const extracted = extractTokenFromResponse(resp);
    expect([...extracted]).toEqual([...token]);
  });

  it('throws when the TSA rejects the request', () => {
    const resp = der.sequence(der.sequence(der.integer(2))); // status rejection
    expect(() => extractTokenFromResponse(resp)).toThrow();
  });

  // RFC 3161 section 2.4.2: a token is accepted only if it answers the request
  // that was sent - same hash algorithm and imprint, and the nonce echoed back.
  const imprint = new Uint8Array(32).fill(7);
  const nonce = new Uint8Array([0x80, 1, 2, 3]);
  const tokenFor = async (request: Uint8Array): Promise<Uint8Array> =>
    extractTokenFromResponse(await tsa.respond(request));

  it('accepts a token that answers the request', async () => {
    const token = await tokenFor(buildTimeStampReq(imprint, 'SHA-256', nonce));
    expect(() => checkTimeStampToken(token, 'SHA-256', imprint, nonce)).not.toThrow();
  });

  it('rejects a token for a different imprint', async () => {
    const token = await tokenFor(buildTimeStampReq(new Uint8Array(32).fill(8), 'SHA-256', nonce));
    expect(() => checkTimeStampToken(token, 'SHA-256', imprint, nonce)).toThrow(/imprint/);
  });

  it('rejects a token for a different hash algorithm', async () => {
    const token = await tokenFor(buildTimeStampReq(imprint, 'SHA-384', nonce));
    expect(() => checkTimeStampToken(token, 'SHA-256', imprint, nonce)).toThrow(/hash algorithm/);
  });

  it('rejects a token that echoes a different nonce, as a replayed response would', async () => {
    const token = await tokenFor(buildTimeStampReq(imprint, 'SHA-256', new Uint8Array([9, 9])));
    expect(() => checkTimeStampToken(token, 'SHA-256', imprint, nonce)).toThrow(/different nonce/);
  });

  it('rejects a token that carries no nonce', async () => {
    const withoutNonce = der.sequence(
      der.integer(1),
      der.sequence(der.sequence(der.oid(Oids.sha256), der.nullValue()), der.octetString(imprint))
    );
    const token = await tokenFor(withoutNonce);
    expect(() => checkTimeStampToken(token, 'SHA-256', imprint, nonce)).toThrow(/no nonce/);
  });
});

describe('PAdES B-T (timestamp embedding via a test TSA)', () => {
  it('embeds a signature-timestamp unsigned attribute and still verifies', async () => {
    const httpClient = async (request: { body?: Uint8Array }) => ({
      status: 200,
      body: await tsa.respond(request.body!),
    });

    const signed = await signPdf(await makePdf(), {
      algorithm: SigningAlgorithm.Sha256Rsa,
      certificatePem: certRsa,
      privateKeyPem: keyRsa,
      padesLevel: 'b-t',
      timestampUrl: 'https://tsa.example/tsr',
      httpClient,
    });

    const cms = readContents(signed);
    expect(signedAttrsContainOid(cms, Oids.signatureTimeStampToken)).toBe(true);
    // The signature itself (over the signed attributes) is unaffected by the
    // unsigned timestamp attribute, so it must still verify.
    expect(await verifyCms(cms, certRsa, { hashName: 'SHA-256', keyType: 'rsa' })).toBe(true);
    // messageDigest binding intact.
    expect(parseCms(cms).messageDigest.length).toBe(32);
  });

  it('rejects b-t without a timestampUrl', async () => {
    await expect(
      signPdf(await makePdf(), {
        certificatePem: certRsa,
        privateKeyPem: keyRsa,
        padesLevel: 'b-t',
      } as any)
    ).rejects.toThrow();
  });
});
