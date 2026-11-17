import { describe, it, expect } from 'vitest';
import { buildSignedData } from '../src/cms';
import { getAlgorithmParams, SigningAlgorithm } from '../src/SigningAlgorithm';
import { pemToDer } from '../src/pem';
import { parseCms, verifyCms } from './helpers/cms';
import { signingFixtures } from './helpers/fixtures';

const { certRsa, keyRsa, certEc } = await signingFixtures();

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

async function buildRsaCms(message: Uint8Array) {
  const params = getAlgorithmParams(SigningAlgorithm.Sha256Rsa);
  const privateKey = await crypto.subtle.importKey('pkcs8', pemToDer(keyRsa), params.importParams, false, ['sign']);
  const messageDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', message));
  const { cms } = await buildSignedData({
    params,
    messageDigest,
    certDer: pemToDer(certRsa),
    chainDer: [],
    privateKey,
    signingTime: new Date('2026-06-24T12:00:00Z'),
  });
  return { cms, messageDigest };
}

describe('CMS SignedData builder', () => {
  it('produces a ContentInfo wrapping signedData', async () => {
    const { cms } = await buildRsaCms(new TextEncoder().encode('hello world'));
    const parsed = parseCms(cms);
    expect(parsed.contentTypeOid).toBe(OID_SIGNED_DATA);
    expect(cms[0]).toBe(0x30); // outer SEQUENCE
  });

  it('embeds the messageDigest of the signed content', async () => {
    const message = new TextEncoder().encode('the quick brown fox');
    const { cms, messageDigest } = await buildRsaCms(message);
    const parsed = parseCms(cms);
    expect([...parsed.messageDigest]).toEqual([...messageDigest]);
  });

  it('signs the signed attributes verifiably (RSA)', async () => {
    const { cms } = await buildRsaCms(new TextEncoder().encode('payload'));
    const ok = await verifyCms(cms, certRsa, { hashName: 'SHA-256', keyType: 'rsa' });
    expect(ok).toBe(true);
  });

  it('fails verification if the certificate does not match', async () => {
    const { cms } = await buildRsaCms(new TextEncoder().encode('payload'));
    // Verifying an RSA-signed envelope against the EC cert should not succeed.
    await expect(verifyCms(cms, certEc, { hashName: 'SHA-256', keyType: 'rsa' })).rejects.toBeDefined();
  });
});
