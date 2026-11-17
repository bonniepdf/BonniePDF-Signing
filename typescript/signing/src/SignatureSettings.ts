import { SigningAlgorithm } from './SigningAlgorithm';
import type { SignatureAppearance } from './appearance';
import type { HttpClient } from './http';
import type { SuppliedValidationMaterial, ValidationMaterial } from './validation';

/**
 * PAdES baseline level (ETSI EN 319 142-1). Each level is a superset of the one
 * before it:
 *
 * - `none`  — legacy Adobe signature (`adbe.pkcs7.detached`), the default.
 * - `b-b`   — PAdES baseline (`ETSI.CAdES.detached` + signing-certificate-v2).
 * - `b-t`   — `b-b` plus an RFC 3161 signature timestamp, proving *when* the
 *   signature was made. Requires `timestampUrl`.
 * - `b-lt`  — `b-t` plus the certificate chain and revocation evidence, stored
 *   in the document's Document Security Store so the signature still verifies
 *   once the certificates have expired or the responders are gone.
 * - `b-lta` — `b-lt` plus a document timestamp over the whole file, DSS
 *   included. This is the level that can be *renewed*: a fresh document
 *   timestamp applied before the previous one's algorithms weaken extends the
 *   life of the evidence indefinitely.
 *
 * Levels above `b-t` are about surviving time, not about stronger cryptography.
 * Pick `b-lt` when the document must be checkable after the signer's certificate
 * expires, and `b-lta` when it must outlive the algorithms themselves — archival
 * retention, long-dated contracts, regulated record-keeping.
 */
export type PadesLevel = 'none' | 'b-b' | 'b-t' | 'b-lt' | 'b-lta';

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
   * PAdES baseline level (default `none`). Any level above `none` switches the
   * subfilter to `ETSI.CAdES.detached` and adds the ESS signing-certificate-v2
   * attribute; `b-t` and above embed an RFC 3161 timestamp and require
   * {@link timestampUrl}.
   */
  padesLevel?: PadesLevel;

  /**
   * Validation material to embed, for `b-lt` and `b-lta`.
   *
   * Anything supplied here is always embedded. By default the signer also tries
   * to fetch what the certificates point at — see {@link fetchRevocation} to
   * turn that off and rely on this alone.
   */
  validationMaterial?: SuppliedValidationMaterial;

  /**
   * Whether to fetch revocation evidence (OCSP, then CRL) for the chain when
   * building a `b-lt` or `b-lta` signature. Default `true`.
   *
   * Set it to `false` for an offline or air-gapped signer, or where your own PKI
   * tooling already produced the evidence and passed it in
   * {@link validationMaterial}. Collection is best-effort either way: what could
   * not be gathered is reported, never thrown.
   */
  fetchRevocation?: boolean;

  /**
   * Called with the material actually embedded, once a `b-lt` or `b-lta`
   * signature has gathered it.
   *
   * Collection is best-effort - a responder that is down does not fail a
   * signature - so this is how a caller learns that the document carries less
   * evidence than it asked for:
   *
   * ```typescript
   * onValidationMaterial: m => m.problems.forEach(p => console.warn(p)),
   * ```
   *
   * A callback rather than a return value or a module-level record, so that two
   * documents signed concurrently in the same process cannot read each other's.
   */
  onValidationMaterial?: (material: ValidationMaterial) => void;

  /**
   * TSA endpoint for the `b-lta` document timestamp. Defaults to
   * {@link timestampUrl}.
   *
   * Worth setting separately when the archival timestamp should come from a
   * different authority than the signature timestamp — a common requirement
   * where the two have different retention guarantees.
   */
  documentTimestampUrl?: string;
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

/** Levels that embed an RFC 3161 signature timestamp and therefore need a TSA. */
const TIMESTAMPED_LEVELS: ReadonlySet<PadesLevel> = new Set<PadesLevel>(['b-t', 'b-lt', 'b-lta']);

/** True for the levels that carry validation material in a DSS. */
export function isLongTermLevel(level: PadesLevel | undefined): boolean {
  return level === 'b-lt' || level === 'b-lta';
}

/** True for the levels that switch to the PAdES subfilter. */
export function isPadesLevel(level: PadesLevel | undefined): boolean {
  return level !== undefined && level !== 'none';
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
  const level = settings.padesLevel ?? 'none';
  if (TIMESTAMPED_LEVELS.has(level) && !settings.timestampUrl) {
    throw new Error(`padesLevel '${level}' requires a timestampUrl`);
  }
  if (level === 'b-lta' && !settings.timestampUrl && !settings.documentTimestampUrl) {
    throw new Error("padesLevel 'b-lta' requires a timestampUrl or documentTimestampUrl");
  }
  return {
    ...settings,
    algorithm: settings.algorithm ?? SigningAlgorithm.Sha256Rsa,
  };
}
