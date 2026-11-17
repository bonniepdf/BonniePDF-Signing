import { describe, it, expect, beforeAll } from 'vitest';
import { Document, TextBlock, StandardFonts } from '@bonniepdf/core';
import { signPdf } from '../src/signPdf';
import { SignatureOptions } from '../src/SignatureOptions';
import { SigningAlgorithm } from '../src/SigningAlgorithm';
import { latin1Decode, indexOfAscii } from '../src/pdf';
import { readNode } from '../src/asn1/der';
import { verifyCms } from './helpers/cms';
import { readFileSync } from 'fs';
import { join } from 'path';

const fixtures = join(__dirname, 'fixtures', 'signing');
const certRsa = readFileSync(join(fixtures, 'cert-rsa.pem'), 'utf8');
const keyRsa = readFileSync(join(fixtures, 'key-rsa.pem'), 'utf8');
const certEc = readFileSync(join(fixtures, 'cert-ec.pem'), 'utf8');
const keyEc = readFileSync(join(fixtures, 'key-ec.pem'), 'utf8');

/** Generate a simple one-page PDF with BonniePDF. */
async function makePdf(): Promise<Uint8Array> {
  const doc = new Document();
  doc.add(new TextBlock('Document to be signed.', 12, StandardFonts.Helvetica));
  const bytes = await doc.generateBytesAsync();
  doc.dispose?.();
  return bytes;
}

/** Read the four integers of the (back-patched) /ByteRange array. */
function readByteRange(bytes: Uint8Array): number[] {
  const text = latin1Decode(bytes);
  const m = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/.exec(text);
  if (!m) throw new Error('no ByteRange');
  return [m[1], m[2], m[3], m[4]].map(Number);
}

/** Extract the CMS DER bytes from the /Contents hex string. */
function readContents(bytes: Uint8Array): Uint8Array {
  const tag = indexOfAscii(bytes, '/Contents <');
  const open = indexOfAscii(bytes, '<', tag);
  const close = indexOfAscii(bytes, '>', open);
  let hex = '';
  for (let i = open + 1; i < close; i++) hex += String.fromCharCode(bytes[i]);
  const all = new Uint8Array(hex.length / 2);
  for (let i = 0; i < all.length; i++) all[i] = parseInt(hex.substr(i * 2, 2), 16);
  // Slice to the exact DER length so trailing 0x00 padding is excluded
  // without corrupting an envelope that genuinely ends in zero bytes.
  const node = readNode(all, 0);
  return all.slice(0, node.end);
}

describe('signPdf - structure', () => {
  let signed: Uint8Array;
  let unsigned: Uint8Array;

  beforeAll(async () => {
    unsigned = await makePdf();
    signed = await signPdf(unsigned, {
      algorithm: SigningAlgorithm.Sha256Rsa,
      certificatePem: certRsa,
      privateKeyPem: keyRsa,
      reason: 'Approved',
      location: 'London, UK',
      contactInfo: 'signer@example.com',
    });
  });

  it('appends rather than rewriting the original bytes', () => {
    expect(signed.length).toBeGreaterThan(unsigned.length);
    expect([...signed.subarray(0, unsigned.length)]).toEqual([...unsigned]);
  });

  it('emits a signature dictionary and AcroForm', () => {
    const text = latin1Decode(signed);
    expect(text).toContain('/Type /Sig');
    expect(text).toContain('/SubFilter /adbe.pkcs7.detached');
    expect(text).toContain('/ByteRange');
    expect(text).toContain('/Contents <');
    expect(text).toContain('/AcroForm');
    expect(text).toContain('/SigFlags 3');
    expect(text).toContain('/FT /Sig');
    expect(text).toContain('(Approved)');
    expect(text).toContain('(London, UK)');
  });

  it('writes a second xref section with /Prev (incremental update)', () => {
    const text = latin1Decode(signed);
    expect(text).toContain('/Prev');
    expect((text.match(/startxref/g) || []).length).toBe(2);
    expect((text.match(/%%EOF/g) || []).length).toBe(2);
  });

  it('produces a /ByteRange consistent with the file length', () => {
    const [start1, len1, start2, len2] = readByteRange(signed);
    expect(start1).toBe(0);
    expect(start2).toBe(len1 + (start2 - len1)); // start2 > len1 (gap is the hex string)
    expect(start2).toBeGreaterThan(len1);
    expect(start2 + len2).toBe(signed.length);
  });

  it('fills /Contents with a real (non-zero) CMS envelope', () => {
    const cms = readContents(signed);
    expect(cms.length).toBeGreaterThan(0);
    expect(cms[0]).toBe(0x30); // CMS ContentInfo SEQUENCE
    expect(cms.some(b => b !== 0)).toBe(true);
  });
});

describe('signPdf - cryptographic validity', () => {
  it('signs verifiably with RSA (SHA-256) via the fluent builder', async () => {
    const pdf = await makePdf();
    const settings = new SignatureOptions()
      .withCertificate(certRsa)
      .withPrivateKey(keyRsa)
      .withReason('Contract signed')
      .usingAlgorithm(SigningAlgorithm.Sha256Rsa)
      .build();
    const signed = await signPdf(pdf, settings);

    // The messageDigest in the CMS must equal SHA-256 over the byte range.
    const [s1, l1, s2, l2] = readByteRange(signed);
    const range = new Uint8Array(l1 + l2);
    range.set(signed.subarray(s1, s1 + l1), 0);
    range.set(signed.subarray(s2, s2 + l2), l1);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', range));

    const cms = readContents(signed);
    const { parseCms } = await import('./helpers/cms');
    expect([...parseCms(cms).messageDigest]).toEqual([...digest]);

    const ok = await verifyCms(cms, certRsa, { hashName: 'SHA-256', keyType: 'rsa' });
    expect(ok).toBe(true);
  });

  it('signs verifiably with ECDSA (P-256 / SHA-256)', async () => {
    const pdf = await makePdf();
    const signed = await signPdf(pdf, {
      algorithm: SigningAlgorithm.Sha256Ecdsa,
      certificatePem: certEc,
      privateKeyPem: keyEc,
    });
    const cms = readContents(signed);
    const ok = await verifyCms(cms, certEc, { hashName: 'SHA-256', keyType: 'ec', curveSize: 32 });
    expect(ok).toBe(true);
  });

  it('throws if signing settings are incomplete', async () => {
    const pdf = await makePdf();
    await expect(signPdf(pdf, { certificatePem: certRsa, privateKeyPem: '' } as any)).rejects.toThrow();
  });
});
