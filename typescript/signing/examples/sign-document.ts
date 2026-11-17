/**
 * Example: generate a PDF with BonniePDF and apply an invisible digital
 * signature with @bonniepdf/signing.
 *
 * Run (Node 18+):
 *   tsx examples/sign-document.ts <cert.pem> <key-pkcs8.pem> [out.pdf]
 *
 * Generate a throwaway self-signed cert + PKCS#8 key for testing with:
 *   openssl req -x509 -newkey rsa:2048 -keyout k.pem -out cert.pem -days 365 -nodes -subj "/CN=Test Signer"
 *   openssl pkcs8 -topk8 -nocrypt -in k.pem -out key-pkcs8.pem
 *
 * This is a commercial-add-on example; it is intentionally NOT part of the
 * public `@bonniepdf/examples` registry (that catalogue is core-only, its
 * examples return a `Document`, and signed output is non-deterministic).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { Document, TextBlock, StandardFonts, settings } from '@bonniepdf/core';
import { signPdf, SignatureOptions, SigningAlgorithm } from '../src/index';

async function main(): Promise<void> {
  // Running an example is not production use, so `evaluation` is the honest declaration.
  settings.license = 'evaluation';
  const [certPath, keyPath, outPath = 'signed.pdf'] = process.argv.slice(2);
  if (!certPath || !keyPath) {
    console.error('usage: tsx examples/sign-document.ts <cert.pem> <key-pkcs8.pem> [out.pdf]');
    process.exit(1);
  }

  // 1. Build a document with BonniePDF as usual.
  const doc = new Document();
  doc.add(new TextBlock('Service Agreement', { fontSize: 20, fontName: StandardFonts.HelveticaBold }));
  doc.add(
    new TextBlock('This document is digitally signed with BonniePDF.', {
      fontSize: 12,
      fontName: StandardFonts.Helvetica,
    })
  );
  const pdfBytes = await doc.generateBytesAsync();

  // 2. Sign it (async: all crypto runs on the Web Crypto API).
  const signatureSettings = new SignatureOptions()
    .withCertificate(readFileSync(certPath, 'utf8'))
    .withPrivateKey(readFileSync(keyPath, 'utf8'))
    .withReason('Approved')
    .withLocation('London, UK')
    .withContactInfo('signer@example.com')
    .usingAlgorithm(SigningAlgorithm.Sha256Rsa)
    .build();

  const signed = await signPdf(pdfBytes, signatureSettings);

  writeFileSync(outPath, signed);
  console.log(`Signed PDF written to ${outPath} (${signed.length} bytes).`);
  console.log('Verify the signature in Adobe Acrobat / Foxit, or with: pdfsig ' + outPath);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
