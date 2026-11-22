/**
 * @bonniepdf/signing - digital signatures for BonniePDF-generated PDFs:
 * invisible and visible CMS signatures, the PAdES baseline levels B-B through
 * B-LTA, RFC 3161 timestamps, and PKCS#12 input. Zero runtime dependencies; all
 * crypto runs on the Web Crypto API, so the same code works in the browser,
 * Node, Bun, and Deno.
 *
 * Commercial add-on: requires a paid BonniePDF licence. Not part of the free
 * `@bonniepdf/core`.
 */
export { signPdf } from './signPdf';
export type { SignPdfOptions } from './signPdf';
export { SigningAlgorithm } from './SigningAlgorithm';
export type { AlgorithmParams } from './SigningAlgorithm';
export type { SignatureSettings, PadesLevel } from './SignatureSettings';
export { isLongTermLevel, isPadesLevel } from './SignatureSettings';
export { SignatureOptions } from './SignatureOptions';
export type { SignatureAppearance } from './appearance';
export type { HttpClient, HttpRequest, HttpResponse } from './http';
export { defaultHttpClient } from './http';

// Long-term validation (PAdES B-LT / B-LTA).
export type { ValidationMaterial, SuppliedValidationMaterial } from './validation';
export { collectValidationMaterial, fetchIssuerCertificate } from './validation';
export { buildDssRevision, vriKey, pdfHeaderVersion, needsEsicExtension } from './dss';
export type { DssOptions } from './dss';
export { appendDocumentTimestamp } from './docTimestamp';
export type { DocumentTimestampOptions } from './docTimestamp';
export { requestOcsp, buildOcspRequest, checkOcspResponse } from './ocsp';
export { fetchCrl } from './crl';
export { ocspUrls, crlUrls, caIssuerUrls, readExtensions } from './asn1/extensions';

// Lower-level building blocks, exported for advanced use and testing.
export { pemToDer, derToPem, base64ToBytes, bytesToBase64 } from './pem';
export { parsePkcs12 } from './pkcs12';
export type { Pkcs12Contents } from './pkcs12';
