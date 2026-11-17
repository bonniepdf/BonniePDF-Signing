/**
 * Offline licence-key verification for the commercial signing add-on.
 *
 * A licence key is a short, signed token the customer pastes in. It is verified
 * **entirely offline** against an embedded public key - there is no licence
 * server, no network call, and it works air-gapped. The mechanism deters
 * *forgery* (you cannot mint a valid key without the vendor's private key) while
 * keeping zero-friction setup. It is intentionally **not** DRM:
 * the package is source-available, so the check can be patched out. The goal is
 * to make the honest path the easy path and any bypass a deliberate,
 * attributable act of circumvention.
 *
 * Token format (`BPDF1`):
 *   `BPDF1.<base64url(claimsJson)>.<base64url(signature)>`
 * The signature is ECDSA P-256 / SHA-256 over the UTF-8 bytes of
 * `BPDF1.<base64url(claimsJson)>`. P-256 is used (not Ed25519) because it is
 * natively supported by both the Web Crypto API and the .NET BCL, so the same
 * token verifies in the browser, Node, Bun, Deno, and the .NET port.
 *
 * All crypto runs on the Web Crypto API, so this module is platform-neutral.
 */
import { base64ToBytes } from './pem';

/** Licence edition. `free` is the unlicensed/evaluation tier (no signed key). */
export type LicenseEdition = 'free' | 'professional' | 'enterprise';

/**
 * Outcome of verifying a licence key:
 * - `valid`      — signature verifies and the key is current.
 * - `grace`      — expired, but within the grace window; still usable (warns).
 * - `expired`    — expired beyond the grace window.
 * - `invalid`    — malformed or the signature does not verify (forged/corrupt).
 * - `revoked`    — the customer id is on the embedded revocation list.
 * - `unlicensed` — no key was supplied at all (evaluation mode).
 */
export type LicenseStatus = 'valid' | 'grace' | 'expired' | 'invalid' | 'revoked' | 'unlicensed';

/** Claims carried by a licence key. Minted and signed by the vendor. */
export interface LicenseClaims {
  /** Customer id (subject). Used for attribution and revocation. */
  sub: string;
  /** Licensed edition. */
  edition: LicenseEdition;
  /** Optional seat count (informational; not enforced at runtime). */
  seats?: number;
  /** Optional feature flags this licence unlocks (e.g. `["pades","ltv"]`). */
  features?: string[];
  /** Issued-at date (ISO `YYYY-MM-DD` or full ISO 8601). */
  iat?: string;
  /** Expiry date (ISO `YYYY-MM-DD` or full ISO 8601). Absent = perpetual. */
  exp?: string;
}

/** Result of {@link verifyLicense}. */
export interface LicenseVerification {
  /** Whether signing may proceed (true for `valid` and `grace`). */
  ok: boolean;
  status: LicenseStatus;
  /** Parsed claims, when the token was well-formed (even if expired/revoked). */
  claims?: LicenseClaims;
  /** Human-readable explanation, suitable for logging. */
  message: string;
}

/** Days a key keeps working after `exp` before signing is blocked. */
export const DEFAULT_GRACE_DAYS = 30;

/**
 * Vendor public key (SPKI, base64), used to verify licence signatures.
 *
 * PLACEHOLDER — replace with your own key before publishing. Generate a keypair
 * with `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`, embed
 * the **public** half here, and keep the private half offline (see
 * `scripts/mint-license.ts`). The private key that matches this placeholder is
 * intentionally not committed, so no real key can be minted against it.
 */
export const LICENSE_PUBLIC_KEY_SPKI =
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdurRtkqh1iLxsOoCJ1yNFV8/dDg0J7TU8zCrtx3C4b+2nbRVzQOb70VNjIWhzPc3mT1ntb3lf9n0vxC1O/1tVQ==';

/**
 * Revoked customer ids. A leaked key keeps working on already-released versions
 * but dies on upgrade once its `sub` is listed here and a new build ships.
 */
export const REVOKED_CUSTOMERS: readonly string[] = [];

const PREFIX = 'BPDF1';

function b64urlToBytes(s: string): Uint8Array {
  return base64ToBytes(s.replace(/-/g, '+').replace(/_/g, '/'));
}

function getEnv(name: string): string | undefined {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  const value = env?.[name];
  return value && value.length > 0 ? value : undefined;
}

function fail(status: LicenseStatus, message: string, claims?: LicenseClaims): LicenseVerification {
  return { ok: false, status, message, claims };
}

function pass(status: LicenseStatus, message: string, claims: LicenseClaims): LicenseVerification {
  return { ok: true, status, message, claims };
}

/**
 * Verify a licence token offline against the embedded public key.
 *
 * @param token   The `BPDF1.…` key, or `undefined`/empty for `unlicensed`.
 * @param options `now` (clock, for testing), `graceDays`, and `publicKeySpki`
 *                (test override — production verifies against the embedded key).
 */
export async function verifyLicense(
  token: string | undefined,
  options: { now?: Date; graceDays?: number; publicKeySpki?: string } = {}
): Promise<LicenseVerification> {
  const now = options.now ?? new Date();
  const graceDays = options.graceDays ?? DEFAULT_GRACE_DAYS;

  if (!token || token.trim().length === 0) {
    return fail('unlicensed', 'no licence key provided');
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts[0] !== PREFIX) {
    return fail('invalid', `malformed licence key (expected "${PREFIX}.<payload>.<signature>")`);
  }
  const [, payloadB64, sigB64] = parts;

  let claims: LicenseClaims;
  try {
    claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64))) as LicenseClaims;
  } catch {
    return fail('invalid', 'licence payload is not valid JSON');
  }

  const signingInput = new TextEncoder().encode(`${PREFIX}.${payloadB64}`);
  const signature = b64urlToBytes(sigB64);
  let verified: boolean;
  try {
    const key = await crypto.subtle.importKey(
      'spki',
      base64ToBytes(options.publicKeySpki ?? LICENSE_PUBLIC_KEY_SPKI) as BufferSource,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    verified = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      signature as BufferSource,
      signingInput as BufferSource
    );
  } catch {
    return fail('invalid', 'licence signature could not be checked', claims);
  }
  if (!verified) {
    return fail('invalid', 'licence signature does not verify (forged or corrupted key)', claims);
  }

  if (claims.sub && REVOKED_CUSTOMERS.includes(claims.sub)) {
    return fail('revoked', `licence for "${claims.sub}" has been revoked`, claims);
  }

  if (claims.exp) {
    const expMs = Date.parse(claims.exp);
    if (!Number.isNaN(expMs)) {
      const graceMs = expMs + graceDays * 86_400_000;
      if (now.getTime() > graceMs) {
        return fail('expired', `licence expired on ${claims.exp} (past the ${graceDays}-day grace period)`, claims);
      }
      if (now.getTime() > expMs) {
        return pass('grace', `licence expired on ${claims.exp}; within the ${graceDays}-day grace period`, claims);
      }
    }
  }

  return pass('valid', `licensed to "${claims.sub}" (${claims.edition})`, claims);
}

/**
 * Resolve a licence key string from (in order): the explicit argument, the
 * `BONNIEPDF_LICENSE_KEY` environment variable, then a licence file
 * (`BONNIEPDF_LICENSE_FILE`, or `bonniepdf.license` in the working directory).
 * File lookup only runs under Node/Bun/Deno; in the browser, pass the key
 * explicitly or via your bundler's env. Returns `undefined` if none is found.
 */
export async function resolveLicenseKey(explicit?: string): Promise<string | undefined> {
  if (explicit && explicit.trim().length > 0) return explicit.trim();

  const fromEnv = getEnv('BONNIEPDF_LICENSE_KEY');
  if (fromEnv) return fromEnv.trim();

  const explicitFile = getEnv('BONNIEPDF_LICENSE_FILE');
  const content = await tryReadFile(explicitFile ?? 'bonniepdf.license', Boolean(explicitFile));
  if (content && content.trim().length > 0) return content.trim();

  return undefined;
}

async function tryReadFile(path: string, required: boolean): Promise<string | undefined> {
  const proc = (globalThis as { process?: { versions?: { node?: string } } }).process;
  if (!proc?.versions?.node) return undefined;
  try {
    // Variable specifier keeps bundlers (esbuild/tsup) from pulling 'fs' into
    // the browser graph; this branch only runs under Node.
    const specifier = 'node:' + 'fs';
    const fs = (await import(/* @vite-ignore */ specifier)) as typeof import('fs');
    if (!fs.existsSync(path)) {
      if (required) throw new Error(`licence file not found: ${path}`);
      return undefined;
    }
    return fs.readFileSync(path, 'utf8');
  } catch (err) {
    if (required) throw err;
    return undefined;
  }
}

let warned = false;
function warnOnce(message: string): void {
  if (warned) return;
  warned = true;
  if (typeof console !== 'undefined' && typeof console.warn === 'function') {
    console.warn(message);
  }
}

/** Reset the one-time warning latch. Test-only. */
export function resetLicenseWarning(): void {
  warned = false;
}

/**
 * Resolve + verify the licence and apply the enforcement policy used by
 * {@link signPdf}:
 * - `valid`  → proceed silently.
 * - `grace`  → proceed, warn once to renew.
 * - `invalid` / `expired` / `revoked` → **throw** (a present-but-bad key is
 *   always an error).
 * - `unlicensed` → if a licence is required (`requireLicense`, or the
 *   `BONNIEPDF_LICENSE_REQUIRE=1` env var), throw; otherwise warn once and run
 *   in evaluation mode.
 *
 * @returns The verification result (for callers that want the claims).
 */
export async function enforceLicense(explicit?: string, requireLicense?: boolean): Promise<LicenseVerification> {
  const token = await resolveLicenseKey(explicit);
  const result = await verifyLicense(token);
  const required = requireLicense ?? getEnv('BONNIEPDF_LICENSE_REQUIRE') === '1';

  switch (result.status) {
    case 'valid':
      return result;
    case 'grace':
      warnOnce(`BonniePDF.Signing: ${result.message}. Renew your licence to avoid interruption.`);
      return result;
    case 'unlicensed':
      if (required) {
        throw new Error(
          'BonniePDF.Signing requires a licence key. Set settings.license, the ' +
            'BONNIEPDF_LICENSE_KEY env var, or a bonniepdf.license file. See LICENSING.md.'
        );
      }
      warnOnce(
        'BonniePDF.Signing: no licence key found — running in EVALUATION mode. ' +
          'A paid licence is required for production use. See LICENSING.md.'
      );
      return result;
    default:
      // invalid | expired | revoked
      throw new Error(`BonniePDF.Signing licence error: ${result.message}. See LICENSING.md.`);
  }
}
