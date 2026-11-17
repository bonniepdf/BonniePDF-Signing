import { describe, it, expect } from 'vitest';
import * as der from '../src/asn1/der';
import { extractIssuerAndSerial, extractSubjectPublicKeyInfo } from '../src/asn1/x509';
import { pemToDer } from '../src/pem';
import { signingFixtures } from './helpers/fixtures';

const { certRsa } = await signingFixtures();

describe('DER encoder', () => {
  it('encodes OID 1.2.840.113549.1.7.2 (signedData)', () => {
    // Known DER for this OID: 06 09 2A 86 48 86 F7 0D 01 07 02
    const bytes = der.oid('1.2.840.113549.1.7.2');
    expect([...bytes]).toEqual([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
  });

  it('encodes SHA-256 OID 2.16.840.1.101.3.4.2.1', () => {
    const bytes = der.oid('2.16.840.1.101.3.4.2.1');
    expect([...bytes]).toEqual([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
  });

  it('encodes small INTEGER with high-bit padding', () => {
    expect([...der.integer(0)]).toEqual([0x02, 0x01, 0x00]);
    expect([...der.integer(1)]).toEqual([0x02, 0x01, 0x01]);
    expect([...der.integer(255)]).toEqual([0x02, 0x02, 0x00, 0xff]); // leading 0x00 keeps it positive
  });

  it('encodes long-form lengths', () => {
    const value = new Uint8Array(200);
    const wrapped = der.octetString(value);
    expect(wrapped[0]).toBe(0x04);
    expect(wrapped[1]).toBe(0x81); // long form, 1 length octet
    expect(wrapped[2]).toBe(200);
    expect(wrapped.length).toBe(203);
  });

  it('SET OF sorts children by DER encoding', () => {
    const a = der.octetString(new Uint8Array([0x02]));
    const b = der.octetString(new Uint8Array([0x01]));
    const out = der.setOf([a, b]);
    // First child after the SET header must be the smaller encoding (0x01).
    expect(out[0]).toBe(0x31);
    expect(out[2]).toBe(0x04);
    expect(out[4]).toBe(0x01);
  });

  it('round-trips a SEQUENCE through the reader', () => {
    const seq = der.sequence(der.integer(1), der.oid('1.2.840.113549.1.7.1'));
    const node = der.readNode(seq, 0);
    expect(node.tag).toBe(0x30);
    const children = der.readChildren(seq, node.contentStart, node.contentEnd);
    expect(children).toHaveLength(2);
    expect(children[0].tag).toBe(0x02);
    expect(children[1].tag).toBe(0x06);
  });
});

describe('X.509 reader', () => {
  it('extracts issuer and serial from a real certificate', () => {
    const certDer = pemToDer(certRsa);
    const { issuer, serialNumber } = extractIssuerAndSerial(certDer);
    expect(issuer[0]).toBe(0x30); // issuer is a Name SEQUENCE
    expect(serialNumber[0]).toBe(0x02); // serial is an INTEGER
    expect(serialNumber.length).toBeGreaterThan(2);
  });

  it('extracts a SubjectPublicKeyInfo importable by Web Crypto', async () => {
    const spki = extractSubjectPublicKeyInfo(pemToDer(certRsa));
    expect(spki[0]).toBe(0x30);
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
      'verify',
    ]);
    expect(key.type).toBe('public');
  });
});
