/**
 * Public entry point: sign a BonniePDF-generated PDF.
 */
import { SignatureSettings, normalizeSettings, isLongTermLevel, isPadesLevel } from './SignatureSettings';
import { getAlgorithmParams } from './SigningAlgorithm';
import { pemToDer } from './pem';
import { buildSignedData } from './cms';
import { requestTimestamp } from './timestamp';
import { parsePkcs12 } from './pkcs12';
import { buildAppearanceStream } from './appearance';
import { parsePdf, buildIncrementalUpdate, patchByteRange, injectContents, pdfDate, VisibleSignature } from './pdf';
import { defaultHttpClient } from './http';
import { buildDssRevision, needsEsicExtension } from './dss';
import { appendDocumentTimestamp } from './docTimestamp';
import { collectValidationMaterial } from './validation';

/**
 * Embed a digital signature into a PDF produced by `@bonniepdf/core`, applied as
 * a minimal incremental update.
 *
 * Supports invisible and **visible** signatures, **PAdES** baseline profiles
 * (`b-b` / `b-t`), and **RFC 3161** timestamps. Signing is asynchronous because
 * all cryptography runs on the Web Crypto API.
 *
 * @param pdfBytes The finished PDF from `Document.generateBytesAsync()`.
 * @param settings Certificate, key, algorithm, profile, and optional metadata.
 * @returns A new `Uint8Array` containing the signed PDF.
 */
export async function signPdf(pdfBytes: Uint8Array, settings: SignatureSettings): Promise<Uint8Array> {
  if (!(pdfBytes instanceof Uint8Array)) throw new Error('pdfBytes must be a Uint8Array');
  const config = normalizeSettings(settings);
  const params = getAlgorithmParams(config.algorithm);

  let certDer: Uint8Array;
  let keyPkcs8Der: Uint8Array;
  if (config.pkcs12) {
    ({ certDer, keyPkcs8Der } = await parsePkcs12(config.pkcs12, config.pkcs12Password ?? ''));
  } else {
    certDer = pemToDer(config.certificatePem!);
    keyPkcs8Der = pemToDer(config.privateKeyPem!);
  }
  const chainDer = (config.certificateChainPem ?? []).map(pemToDer);
  const privateKey = await crypto.subtle.importKey('pkcs8', keyPkcs8Der as BufferSource, params.importParams, false, [
    'sign',
  ]);

  const signingTime = config.signingTime ?? new Date();
  const pades = isPadesLevel(config.padesLevel);
  const subFilter = pades ? 'ETSI.CAdES.detached' : 'adbe.pkcs7.detached';

  // Visible appearance (optional).
  let visible: VisibleSignature | undefined;
  if (config.appearance) {
    const [, , width, height] = config.appearance.rect;
    const lines = config.appearance.text ?? defaultAppearanceLines(config, signingTime);
    const fontSize = config.appearance.fontSize ?? 8;
    const border = config.appearance.border ?? true;
    visible = {
      rect: config.appearance.rect,
      contentStream: buildAppearanceStream(width, height, lines, fontSize, border),
    };
  }

  // 1. Append the signature revision with placeholders.
  const info = parsePdf(pdfBytes, config.appearance?.page ?? 0);
  const withPlaceholders = buildIncrementalUpdate(
    pdfBytes,
    info,
    {
      reason: config.reason,
      location: config.location,
      contactInfo: config.contactInfo,
      name: config.name,
      signingTime,
      subFilter,
    },
    visible
  );

  // 2. Patch /ByteRange and extract the signed spans.
  const { signed, contentsStart, contentsEnd } = patchByteRange(withPlaceholders);

  // 3. Hash the signed content (the CMS messageDigest attribute).
  const messageDigest = new Uint8Array(await crypto.subtle.digest(params.hashName, signed as BufferSource));

  // 4. Build the CMS SignedData envelope (with optional RFC 3161 timestamp).
  const timestamp = config.timestampUrl
    ? (signatureValue: Uint8Array) =>
        requestTimestamp(signatureValue, {
          url: config.timestampUrl!,
          hashName: params.hashName,
          httpClient: config.httpClient,
        })
    : undefined;

  const { cms, timestampToken } = await buildSignedData({
    params,
    messageDigest,
    certDer,
    chainDer,
    privateKey,
    signingTime,
    pades,
    timestamp,
  });

  // 5. Inject the hex-encoded envelope into /Contents.
  injectContents(withPlaceholders, contentsStart, contentsEnd, cms);

  if (!isLongTermLevel(config.padesLevel)) return withPlaceholders;

  // 6. B-LT: append the validation material as a Document Security Store, in
  // its own revision so the signature's byte range stays untouched.
  const httpClient = config.httpClient ?? defaultHttpClient;
  const material = await collectValidationMaterial({
    certDer,
    chainDer,
    httpClient,
    supplied: config.validationMaterial,
    fetchRevocation: config.fetchRevocation,
    timestampToken,
  });
  config.onValidationMaterial?.(material);

  let out = await buildDssRevision(withPlaceholders, {
    material,
    // The /VRI key names the signature by the bytes of its /Contents entry,
    // padding included - which is exactly the span we just wrote into.
    signatureContents: withPlaceholders.slice(contentsStart + 1, contentsEnd - 1),
    time: signingTime,
    declareEsicExtension: needsEsicExtension(pdfBytes),
  });

  if (config.padesLevel !== 'b-lta') return out;

  // 7. B-LTA: a document timestamp over everything above, DSS included.
  out = await appendDocumentTimestamp(out, {
    timestampUrl: config.documentTimestampUrl ?? config.timestampUrl!,
    hashName: params.hashName as 'SHA-256' | 'SHA-384' | 'SHA-512',
    httpClient: config.httpClient,
  });
  return out;
}


/** Derive default visible-appearance text from the signature metadata. */
function defaultAppearanceLines(config: SignatureSettings, signingTime: Date): string[] {
  const lines = [`Digitally signed by ${config.name ?? 'BonniePDF'}`];
  if (config.reason) lines.push(`Reason: ${config.reason}`);
  if (config.location) lines.push(`Location: ${config.location}`);
  lines.push(pdfDate(signingTime).replace(/^D:/, 'Date: '));
  return lines;
}
