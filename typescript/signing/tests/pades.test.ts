import { describe, it, expect, beforeAll } from 'vitest';
import { Document, TextBlock, StandardFonts } from '@bonniepdf/core';
import { signPdf } from '../src/signPdf';
import { SigningAlgorithm } from '../src/SigningAlgorithm';
import { latin1Decode, indexOfAscii } from '../src/pdf';
import { buildTimeStampReq, extractTokenFromResponse } from '../src/timestamp';
import { verifyCms, parseCms, readContents, signedAttrsContainOid } from './helpers/cms';
import * as der from '../src/asn1/der';
import { Oids } from '../src/asn1/oids';
import { readNode } from '../src/asn1/der';
import { readFileSync } from 'fs';
import { join } from 'path';

const fixtures = join(__dirname, 'fixtures', 'signing');
const certRsa = readFileSync(join(fixtures, 'cert-rsa.pem'), 'utf8');
const keyRsa = readFileSync(join(fixtures, 'key-rsa.pem'), 'utf8');

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
});

describe('PAdES B-T (timestamp embedding via mock TSA)', () => {
  it('embeds a signature-timestamp unsigned attribute and still verifies', async () => {
    // Mock TSA: ignore the request, return a granted response wrapping a token.
    const fakeToken = der.sequence(der.oid(Oids.signedData), der.octetString(new Uint8Array([9, 9, 9])));
    const httpClient = async () => ({
      status: 200,
      body: der.sequence(der.sequence(der.integer(0)), fakeToken),
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
