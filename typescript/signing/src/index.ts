/**
 * @bonniepdf/signing - invisible PKCS#7 / CMS digital signatures for
 * BonniePDF-generated PDFs. Zero runtime dependencies; all crypto runs on the
 * Web Crypto API, so the same code works in the browser, Node, Bun, and Deno.
 *
 * Commercial add-on: requires a paid BonniePDF licence. Not part of the free
 * `@bonniepdf/core`.
 */
export { signPdf } from './signPdf';
export { SigningAlgorithm } from './SigningAlgorithm';
export type { AlgorithmParams } from './SigningAlgorithm';
export type { SignatureSettings, PadesLevel } from './SignatureSettings';
export { SignatureOptions } from './SignatureOptions';
export type { SignatureAppearance } from './appearance';
export type { HttpClient } from './timestamp';

// Licence verification (offline; commercial add-on).
export {
  verifyLicense,
  resolveLicenseKey,
  enforceLicense,
  LICENSE_PUBLIC_KEY_SPKI,
  REVOKED_CUSTOMERS,
} from './license';
export type { LicenseClaims, LicenseEdition, LicenseStatus, LicenseVerification } from './license';

// Lower-level building blocks, exported for advanced use and testing.
export { pemToDer, derToPem, base64ToBytes, bytesToBase64 } from './pem';
export { parsePkcs12 } from './pkcs12';
export type { Pkcs12Contents } from './pkcs12';
