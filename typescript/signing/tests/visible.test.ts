import { describe, it, expect, beforeAll } from 'vitest';
import { Document, TextBlock, StandardFonts } from '@bonniepdf/core';
import { signPdf } from '../src/signPdf';
import { SignatureOptions } from '../src/SignatureOptions';
import { SigningAlgorithm } from '../src/SigningAlgorithm';
import { latin1Decode, indexOfAscii } from '../src/pdf';
import { verifyCms } from './helpers/cms';
import { readNode } from '../src/asn1/der';
import { readFileSync } from 'fs';
import { join } from 'path';

const fixtures = join(__dirname, 'fixtures', 'signing');
const certRsa = readFileSync(join(fixtures, 'cert-rsa.pem'), 'utf8');
const keyRsa = readFileSync(join(fixtures, 'key-rsa.pem'), 'utf8');

async function makePdf(): Promise<Uint8Array> {
  const doc = new Document();
  doc.add(new TextBlock('Visible signature test.', 12, StandardFonts.Helvetica));
  const bytes = await doc.generateBytesAsync();
  doc.dispose?.();
  return bytes;
}

function readContents(bytes: Uint8Array): Uint8Array {
  const tag = indexOfAscii(bytes, '/Contents <');
  const open = indexOfAscii(bytes, '<', tag);
  const close = indexOfAscii(bytes, '>', open);
  let hex = '';
  for (let i = open + 1; i < close; i++) hex += String.fromCharCode(bytes[i]);
  const all = new Uint8Array(hex.length / 2);
  for (let i = 0; i < all.length; i++) all[i] = parseInt(hex.substr(i * 2, 2), 16);
  return all.slice(0, readNode(all, 0).end);
}

describe('Visible signature widget', () => {
  let signed: Uint8Array;

  beforeAll(async () => {
    signed = await signPdf(
      await makePdf(),
      new SignatureOptions()
        .withCertificate(certRsa)
        .withPrivateKey(keyRsa)
        .withReason('Approved')
        .withVisibleSignature({ rect: [72, 72, 200, 60], text: ['Signed by Test', 'BonniePDF'] })
        .build()
    );
  });

  it('gives the widget a non-zero /Rect', () => {
    const text = latin1Decode(signed);
    // [x, y, width, height] = [72, 72, 200, 60] is the box from (72, 72) to (272, 132).
    expect(text).toContain('/Rect [72 72 272 132]');
    expect(text).toContain('/BBox [0 0 200 60]');
    expect(text).not.toContain('/Rect [0 0 0 0]');
  });

  it('wires an appearance stream (/AP /N) with a form XObject', () => {
    const text = latin1Decode(signed);
    expect(text).toContain('/AP << /N');
    expect(text).toContain('/Subtype /Form');
    expect(text).toContain('/BBox [0 0 200 60]');
    expect(text).toContain('/BaseFont /Helvetica');
    expect(text).toContain('(Signed by Test) Tj');
  });

  it('still produces a cryptographically valid signature', async () => {
    expect(await verifyCms(readContents(signed), certRsa, { hashName: 'SHA-256', keyType: 'rsa' })).toBe(true);
  });

  it('combines visible + PAdES B-B', async () => {
    const out = await signPdf(await makePdf(), {
      certificatePem: certRsa,
      privateKeyPem: keyRsa,
      padesLevel: 'b-b',
      appearance: { rect: [50, 50, 180, 50] },
    });
    const text = latin1Decode(out);
    expect(text).toContain('/SubFilter /ETSI.CAdES.detached');
    expect(text).toContain('/AP << /N');
    expect(await verifyCms(readContents(out), certRsa, { hashName: 'SHA-256', keyType: 'rsa' })).toBe(true);
  });
});
