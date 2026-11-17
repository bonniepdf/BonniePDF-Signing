import { SigningAlgorithm } from './SigningAlgorithm';
import type { SignatureAppearance } from './appearance';
import type { HttpClient } from './timestamp';

/**
 * PAdES baseline level (ETSI EN 319 142):
 * - `none` — legacy Adobe signature (`adbe.pkcs7.detached`), the default.
 * - `b-b`  — PAdES baseline (`ETSI.CAdES.detached` + signing-certificate-v2).
 * - `b-t`  — `b-b` plus an RFC 3161 signature timestamp (requires `timestampUrl`).
 */
export type PadesLevel = 'none' | 'b-b' | 'b-t';

/**
 * Configuration for an invisible PDF digital signature.
 *
 * Mirrors the shape of `@bonniepdf/core`'s `EncryptionSettings` and the
 * .NET `BonniePDF.Signing.SignatureSettings`. Provide a PEM-encoded X.509
 * certificate and its PKCS#8 private key; everything else is optional metadata.
 */
export interface SignatureSettings {
  /** Signing algorithm. Default {@link SigningAlgorithm.Sha256Rsa}. */
  algorithm?: SigningAlgorithm;
  /**
   * X.509 signer certificate, PEM-encoded (`-----BEGIN CERTIFICATE-----`).
   * Optional when {@link pkcs12} is supplied instead.
   */
  certificatePem?: string;
  /**
   * PKCS#8 private key, PEM-encoded (`-----BEGIN PRIVATE KEY-----`).
   * Optional when {@link pkcs12} is supplied instead.
   */
  privateKeyPem?: string;
  /**
   * PKCS#12 (`.pfx`/`.p12`) container holding the certificate + key, as raw
   * bytes. An alternative to {@link certificatePem} + {@link privateKeyPem}.
   * Only the **modern PBES2** form (AES-CBC, the OpenSSL 3 / .NET default) is
   * supported; legacy 3DES/RC2 containers throw with guidance to re-export.
   */
  pkcs12?: Uint8Array;
  /** Password for {@link pkcs12} (empty string if none). */
  pkcs12Password?: string;
  /** Optional intermediate certificate chain (PEM), leaf-to-root order. */
  certificateChainPem?: string[];
  /** Optional reason, e.g. `"Approved"`. Recorded in the `/Sig` dictionary. */
  reason?: string;
  /** Optional location, e.g. `"London, UK"`. */
  location?: string;
  /** Optional contact info (email or phone). */
  contactInfo?: string;
  /** Optional signer name, written to the `/Sig` `/Name` entry. */
  name?: string;
  /**
   * Signing time. Defaults to the current time at signing. Recorded both in
   * the `/Sig` `/M` entry and as a CMS `signingTime` signed attribute.
   */
  signingTime?: Date;
  /**
   * PAdES baseline level (default `none`). `b-b`/`b-t` switch the subfilter to
   * `ETSI.CAdES.detached` and add the ESS signing-certificate-v2 attribute.
   * `b-t` additionally embeds an RFC 3161 timestamp and requires `timestampUrl`.
   */
  padesLevel?: PadesLevel;
  /**
   * RFC 3161 Time-Stamp Authority URL. When set, a signature timestamp is
   * embedded (PAdES B-T). Independently usable with `padesLevel: 'none'` to add
   * a trusted timestamp to a legacy signature.
   */
  timestampUrl?: string;
  /** Optional HTTP transport for timestamping (defaults to global `fetch`). */
  httpClient?: HttpClient;
  /**
   * When set, produces a **visible** signature: the widget gets this rectangle
   * and an appearance stream instead of the default invisible `[0 0 0 0]`.
   */
  appearance?: SignatureAppearance;
}

/** Fill in defaults and validate required fields, returning a normalized copy. */
export function normalizeSettings(
  settings: SignatureSettings
): Required<Pick<SignatureSettings, 'algorithm'>> & SignatureSettings {
  if (!settings) throw new Error('signature settings are required');
  const hasPem = !!settings.certificatePem && !!settings.privateKeyPem;
  const hasPfx = settings.pkcs12 instanceof Uint8Array && settings.pkcs12.length > 0;
  if (!hasPem && !hasPfx) {
    throw new Error('provide either certificatePem + privateKeyPem, or a pkcs12 container');
  }
  if (!hasPfx) {
    if (!settings.certificatePem!.includes('BEGIN')) {
      throw new Error('certificatePem must be a PEM-encoded X.509 certificate');
    }
    if (!settings.privateKeyPem!.includes('BEGIN')) {
      throw new Error('privateKeyPem must be a PEM-encoded PKCS#8 private key');
    }
  }
  if (settings.padesLevel === 'b-t' && !settings.timestampUrl) {
    throw new Error("padesLevel 'b-t' requires a timestampUrl");
  }
  return {
    ...settings,
    algorithm: settings.algorithm ?? SigningAlgorithm.Sha256Rsa,
  };
}
