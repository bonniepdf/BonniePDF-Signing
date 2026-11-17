import { describe, it, expect } from 'vitest';
import { base64ToBytes, bytesToBase64, pemToDer, derToPem } from '../src/pem';
import { readFileSync } from 'fs';
import { join } from 'path';

const fixtures = join(__dirname, 'fixtures', 'signing');
const keyRsa = readFileSync(join(fixtures, 'key-rsa.pem'), 'utf8');

describe('base64', () => {
  it('round-trips arbitrary bytes', () => {
    for (const len of [0, 1, 2, 3, 4, 5, 31, 32, 33, 255]) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 11) & 0xff;
      const round = base64ToBytes(bytesToBase64(bytes));
      expect([...round]).toEqual([...bytes]);
    }
  });

  it('matches a known vector', () => {
    expect(bytesToBase64(new TextEncoder().encode('Man'))).toBe('TWFu');
    expect([...base64ToBytes('TWFu')]).toEqual([...new TextEncoder().encode('Man')]);
  });
});

describe('PEM', () => {
  it('parses a PKCS#8 private key into importable DER', async () => {
    const der = pemToDer(keyRsa);
    expect(der[0]).toBe(0x30); // SEQUENCE
    const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
      'sign',
    ]);
    expect(key.type).toBe('private');
  });

  it('round-trips DER -> PEM -> DER', () => {
    const der = pemToDer(keyRsa);
    const pem = derToPem(der, 'PRIVATE KEY');
    expect([...pemToDer(pem)]).toEqual([...der]);
  });

  it('throws on non-PEM input', () => {
    expect(() => pemToDer('not a pem')).toThrow();
  });
});
