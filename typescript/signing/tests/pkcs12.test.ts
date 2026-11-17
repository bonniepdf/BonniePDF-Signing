import { describe, it, expect } from 'vitest';
import { Document, TextBlock, StandardFonts } from '@bonniepdf/core';
import { signPdf } from '../src/signPdf';
import { SignatureOptions } from '../src/SignatureOptions';
import { SigningAlgorithm } from '../src/SigningAlgorithm';
import { parsePkcs12 } from '../src/pkcs12';
import { indexOfAscii } from '../src/pdf';
import { readNode } from '../src/asn1/der';
import { verifyCms } from './helpers/cms';
import { signingFixtures, PFX_PASSWORD as PASSWORD } from './helpers/fixtures';

const { pfxRsa, pfxEc, pfxLegacy, certRsa, certEc } = await signingFixtures();

async function makePdf(): Promise<Uint8Array> {
  const doc = new Document();
  doc.add(new TextBlock('PKCS#12 signing test.', 12, StandardFonts.Helvetica));
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

describe('parsePkcs12', () => {
  it('extracts cert + key from a modern PBES2/AES container', async () => {
    const { certDer, keyPkcs8Der } = await parsePkcs12(pfxRsa, PASSWORD);
    expect(certDer[0]).toBe(0x30);
    expect(keyPkcs8Der[0]).toBe(0x30);
    const key = await crypto.subtle.importKey(
      'pkcs8',
      keyPkcs8Der,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );
    expect(key.type).toBe('private');
  });

  it('throws a clear error on a wrong password', async () => {
    await expect(parsePkcs12(pfxRsa, 'wrong')).rejects.toThrow(/decryption failed|wrong password/i);
  });

  it('throws a guided error on a legacy 3DES container', async () => {
    await expect(parsePkcs12(pfxLegacy, PASSWORD)).rejects.toThrow(/legacy|AES|PEM/i);
  });
});

describe('signPdf with PKCS#12 input', () => {
  it('signs with an RSA .pfx and verifies (pdfsig-equivalent CMS check)', async () => {
    const signed = await signPdf(await makePdf(), {
      pkcs12: pfxRsa,
      pkcs12Password: PASSWORD,
      reason: 'Approved',
    });
    expect(await verifyCms(readContents(signed), certRsa, { hashName: 'SHA-256', keyType: 'rsa' })).toBe(true);
  });

  it('signs with an EC .pfx and verifies', async () => {
    const signed = await signPdf(await makePdf(), {
      algorithm: SigningAlgorithm.Sha256Ecdsa,
      pkcs12: pfxEc,
      pkcs12Password: PASSWORD,
    });
    expect(await verifyCms(readContents(signed), certEc, { hashName: 'SHA-256', keyType: 'ec', curveSize: 32 })).toBe(
      true
    );
  });

  it('works via the fluent builder withPkcs12 + PAdES B-B', async () => {
    const settings = new SignatureOptions()
      .withPkcs12(pfxRsa, PASSWORD)
      .usingPades('b-b')
      .withReason('Approved')
      .build();
    const signed = await signPdf(await makePdf(), settings);
    expect(await verifyCms(readContents(signed), certRsa, { hashName: 'SHA-256', keyType: 'rsa' })).toBe(true);
  });

  it('rejects when neither PEM nor pkcs12 is provided', async () => {
    await expect(signPdf(await makePdf(), {} as any)).rejects.toThrow(/certificatePem|pkcs12/i);
  });
});
