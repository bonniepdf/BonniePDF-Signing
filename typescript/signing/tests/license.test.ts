import { describe, it, expect, beforeEach } from 'vitest';
import {
  verifyLicense,
  enforceLicense,
  resolveLicenseKey,
  resetLicenseWarning,
  type LicenseClaims,
} from '../src/license';
import { derToPem, bytesToBase64 } from '../src/pem';
import { mintLicense } from '../scripts/mint-license';

/** Generate an ephemeral EC P-256 keypair: PEM private key + SPKI base64 public. */
async function makeKeypair(): Promise<{ privPem: string; pubSpki: string }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  return { privPem: derToPem(pkcs8, 'PRIVATE KEY'), pubSpki: bytesToBase64(spki) };
}

const today = () => new Date().toISOString().slice(0, 10);
const plusDays = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString().slice(0, 10);

describe('verifyLicense', () => {
  beforeEach(() => resetLicenseWarning());

  it('accepts a well-formed, current key signed by the matching private key', async () => {
    const { privPem, pubSpki } = await makeKeypair();
    const claims: LicenseClaims = { sub: 'acme-corp', edition: 'enterprise', iat: today(), exp: plusDays(365) };
    const token = await mintLicense(privPem, claims);
    const result = await verifyLicense(token, { publicKeySpki: pubSpki });
    expect(result.ok).toBe(true);
    expect(result.status).toBe('valid');
    expect(result.claims?.sub).toBe('acme-corp');
    expect(result.claims?.edition).toBe('enterprise');
  });

  it('rejects a forged key (signature from a different private key)', async () => {
    const minter = await makeKeypair();
    const attacker = await makeKeypair();
    const token = await mintLicense(attacker.privPem, { sub: 'free-loader', edition: 'enterprise' });
    // Verified against the *real* public key, the attacker's signature fails.
    const result = await verifyLicense(token, { publicKeySpki: minter.pubSpki });
    expect(result.ok).toBe(false);
    expect(result.status).toBe('invalid');
  });

  it('rejects a tampered payload', async () => {
    const { privPem, pubSpki } = await makeKeypair();
    const token = await mintLicense(privPem, { sub: 'acme', edition: 'professional' });
    const [prefix, , sig] = token.split('.');
    // Swap in a payload that claims enterprise; the signature no longer matches.
    const forgedPayload = bytesToBase64(
      new TextEncoder().encode(JSON.stringify({ sub: 'acme', edition: 'enterprise' }))
    )
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const result = await verifyLicense(`${prefix}.${forgedPayload}.${sig}`, { publicKeySpki: pubSpki });
    expect(result.status).toBe('invalid');
  });

  it('reports grace when expired within the grace window', async () => {
    const { privPem, pubSpki } = await makeKeypair();
    const token = await mintLicense(privPem, { sub: 'acme', edition: 'enterprise', exp: plusDays(-5) });
    const result = await verifyLicense(token, { publicKeySpki: pubSpki, graceDays: 30 });
    expect(result.ok).toBe(true);
    expect(result.status).toBe('grace');
  });

  it('reports expired beyond the grace window', async () => {
    const { privPem, pubSpki } = await makeKeypair();
    const token = await mintLicense(privPem, { sub: 'acme', edition: 'enterprise', exp: plusDays(-90) });
    const result = await verifyLicense(token, { publicKeySpki: pubSpki, graceDays: 30 });
    expect(result.ok).toBe(false);
    expect(result.status).toBe('expired');
  });

  it('treats an absent key as unlicensed', async () => {
    expect((await verifyLicense(undefined)).status).toBe('unlicensed');
    expect((await verifyLicense('')).status).toBe('unlicensed');
  });

  it('treats a malformed key as invalid', async () => {
    expect((await verifyLicense('not-a-real-key')).status).toBe('invalid');
    expect((await verifyLicense('BPDF1.only-two-parts')).status).toBe('invalid');
  });
});

describe('resolveLicenseKey', () => {
  beforeEach(() => {
    delete process.env.BONNIEPDF_LICENSE_KEY;
    delete process.env.BONNIEPDF_LICENSE_FILE;
  });

  it('prefers the explicit argument', async () => {
    process.env.BONNIEPDF_LICENSE_KEY = 'from-env';
    expect(await resolveLicenseKey('explicit')).toBe('explicit');
  });

  it('falls back to the environment variable', async () => {
    process.env.BONNIEPDF_LICENSE_KEY = 'BPDF1.env';
    expect(await resolveLicenseKey()).toBe('BPDF1.env');
  });

  it('returns undefined when nothing is configured', async () => {
    expect(await resolveLicenseKey()).toBeUndefined();
  });
});

describe('enforceLicense', () => {
  beforeEach(() => {
    resetLicenseWarning();
    delete process.env.BONNIEPDF_LICENSE_KEY;
    delete process.env.BONNIEPDF_LICENSE_REQUIRE;
  });

  it('allows evaluation mode (no key) by default', async () => {
    const result = await enforceLicense();
    expect(result.status).toBe('unlicensed');
    expect(result.ok).toBe(false);
  });

  it('throws when a licence is required but none is present', async () => {
    await expect(enforceLicense(undefined, true)).rejects.toThrow(/requires a licence key/i);
  });

  it('throws on a present-but-invalid key', async () => {
    await expect(enforceLicense('BPDF1.garbage.sig')).rejects.toThrow(/licence error/i);
  });
});
