/**
 * Generate a set of signed sample PDFs for external validation with `pdfsig`
 * (Poppler). The same sample set is produced by the .NET port's SampleGen, so
 * both libraries are validated by the identical external gate.
 *
 * Usage:  tsx signing/scripts/generate-signed-samples.ts [outDir]
 */
// Imported by package specifier rather than a relative path into core's source:
// the signing package declares `@bonniepdf/core` as a dependency, and resolving
// it the way a consumer would keeps this script working wherever core happens to
// sit in the checkout.
import { Document, TextBlock, StandardFonts, settings } from '@bonniepdf/core';
import { signPdf } from '../src/signPdf';
import { SigningAlgorithm } from '../src/SigningAlgorithm';
import type { PadesLevel } from '../src/SignatureSettings';
import { createDemoPki, TSA_URL } from '../examples/support/demo-pki';
import { buildSignedAgreement } from '../examples/signed-agreement';
import { buildSealedCertificate } from '../examples/sealed-certificate';
import { writeFileSync, readFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, '..', 'tests', 'fixtures', 'signing');
const certRsa = readFileSync(join(fixtures, 'cert-rsa.pem'), 'utf8');
const keyRsa = readFileSync(join(fixtures, 'key-rsa.pem'), 'utf8');
const certEc = readFileSync(join(fixtures, 'cert-ec.pem'), 'utf8');
const keyEc = readFileSync(join(fixtures, 'key-ec.pem'), 'utf8');
const pfxRsa = new Uint8Array(readFileSync(join(fixtures, 'test-rsa.pfx')));

// Every first-party surface that generates documents declares its own tier.
// Sample generation is tooling, not production use, so `evaluation` is honest.
settings.license = 'evaluation';

const outDir = process.argv[2] ?? 'signed-samples';
mkdirSync(outDir, { recursive: true });

async function makePdf(): Promise<Uint8Array> {
  const doc = new Document();
  doc.add(new TextBlock('External validation sample.', 12, StandardFonts.Helvetica));
  const bytes = await doc.generateBytesAsync();
  doc.dispose?.();
  return bytes;
}

async function main(): Promise<void> {
  writeFileSync(
    join(outDir, 'invisible-rsa.pdf'),
    await signPdf(await makePdf(), {
      algorithm: SigningAlgorithm.Sha256Rsa,
      certificatePem: certRsa,
      privateKeyPem: keyRsa,
      reason: 'Approved',
    })
  );
  writeFileSync(
    join(outDir, 'visible-rsa.pdf'),
    await signPdf(await makePdf(), {
      certificatePem: certRsa,
      privateKeyPem: keyRsa,
      appearance: { rect: [72, 72, 220, 64], text: ['Signed by BonniePDF', 'External validation'] },
    })
  );
  writeFileSync(
    join(outDir, 'pades-bb-rsa.pdf'),
    await signPdf(await makePdf(), {
      certificatePem: certRsa,
      privateKeyPem: keyRsa,
      padesLevel: 'b-b',
      reason: 'Approved',
    })
  );
  writeFileSync(
    join(outDir, 'invisible-ecdsa.pdf'),
    await signPdf(await makePdf(), {
      algorithm: SigningAlgorithm.Sha256Ecdsa,
      certificatePem: certEc,
      privateKeyPem: keyEc,
    })
  );
  writeFileSync(
    join(outDir, 'pades-bb-pfx.pdf'),
    await signPdf(await makePdf(), {
      pkcs12: pfxRsa,
      pkcs12Password: 'pfxpw',
      padesLevel: 'b-b',
      reason: 'Approved',
    })
  );
  await writePadesSamples();
  console.log(`Wrote signed samples to ${outDir}/`);
}

/**
 * PAdES levels, signed against a throwaway PKI built here: a CA, an OCSP
 * responder and an RFC 3161 authority, all in-process.
 *
 * These are the samples the EU DSS gate checks. It asserts the level each file
 * actually reaches, which is the claim the product makes and the one a buyer's
 * validator will test. The two signed demos are signed by the same authority, so
 * the same gates cover them.
 */
async function writePadesSamples(): Promise<void> {
  const pki = await createDemoPki();
  const { ca, httpClient } = pki;
  const signer = await pki.issueSigner('BonniePDF Test Signer');

  // The format DSS must report, and the indication it must reach. B and T carry
  // no revocation material, so an offline validator cannot complete the chain
  // check - INDETERMINATE there is the correct result for those levels, not a
  // defect.
  const samples: ReadonlyArray<readonly [string, PadesLevel, string, string]> = [
    ['pades-bb', 'b-b', 'PAdES-BASELINE-B', 'INDETERMINATE'],
    ['pades-bt', 'b-t', 'PAdES-BASELINE-T', 'INDETERMINATE'],
    ['pades-blt', 'b-lt', 'PAdES-BASELINE-LT', 'TOTAL_PASSED'],
    ['pades-blta', 'b-lta', 'PAdES-BASELINE-LTA', 'TOTAL_PASSED'],
  ];

  let manifest = '';
  for (const [name, level, format, indication] of samples) {
    const signed = await signPdf(await makePdf(), {
      certificatePem: signer.certPem,
      privateKeyPem: signer.keyPem,
      certificateChainPem: [ca.certPem],
      padesLevel: level,
      timestampUrl: level === 'b-b' ? undefined : TSA_URL,
      httpClient,
      reason: 'Approved',
    });
    writeFileSync(join(outDir, `${name}.pdf`), signed);
    manifest += `${name}.pdf\t${format}\t${indication}\n`;
  }

  // The signed demos: a services agreement with a visible B-B signature, and a certificate
  // sealed at B-LT. Each reaches the level it claims; B-B alone cannot complete a chain check
  // offline, so INDETERMINATE is right for the agreement.
  writeFileSync(join(outDir, 'demo-signed-agreement.pdf'), await buildSignedAgreement(pki));
  manifest += 'demo-signed-agreement.pdf\tPAdES-BASELINE-B\tINDETERMINATE\n';
  writeFileSync(join(outDir, 'demo-sealed-certificate.pdf'), await buildSealedCertificate(pki));
  manifest += 'demo-sealed-certificate.pdf\tPAdES-BASELINE-LT\tTOTAL_PASSED\n';

  writeFileSync(join(outDir, 'test-ca.pem'), ca.certPem);
  writeFileSync(join(outDir, 'expected.tsv'), manifest);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
