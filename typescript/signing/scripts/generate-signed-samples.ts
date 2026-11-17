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
import type { HttpClient } from '../src/http';
import {
  aiaOcsp,
  basicConstraintsCa,
  crlDistributionPoint,
  generateKeyPair,
  issueCertificate,
  TestOcspResponder,
  TestTsa,
  type TestIdentity,
} from '../tests/helpers/pki';
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

const OCSP_URL = 'http://ocsp.test.invalid/ocsp';
const CRL_URL = 'http://crl.test.invalid/ca.crl';
const TSA_URL = 'http://tsa.test.invalid/tsr';

/**
 * PAdES levels, signed against a throwaway PKI built here: a CA, an OCSP
 * responder and an RFC 3161 authority, all in-process.
 *
 * These are the samples the EU DSS gate checks. It asserts the level each file
 * actually reaches, which is the claim the product makes and the one a buyer's
 * validator will test.
 */
async function writePadesSamples(): Promise<void> {
  const ca = await issueCertificate({
    subject: 'BonniePDF Test CA',
    serial: 1,
    subjectKeys: await generateKeyPair(),
    extensions: [basicConstraintsCa()],
  });
  const signer = await issueCertificate({
    subject: 'BonniePDF Test Signer',
    serial: 2,
    subjectKeys: await generateKeyPair(),
    issuer: ca,
    extensions: [aiaOcsp(OCSP_URL), crlDistributionPoint(CRL_URL)],
  });
  // A real TSA certificate publishes revocation information like any other;
  // without it a long-term signature cannot reach the LT level.
  const tsaIdentity: TestIdentity = await issueCertificate({
    subject: 'BonniePDF Test TSA',
    serial: 3,
    subjectKeys: await generateKeyPair(),
    issuer: ca,
    extensions: [aiaOcsp(OCSP_URL)],
  });

  const tsa = new TestTsa(tsaIdentity);
  const ocsp = new TestOcspResponder(ca);

  const httpClient: HttpClient = async request => {
    if (request.url === TSA_URL) return { status: 200, body: await tsa.respond(request.body!) };
    if (request.url === OCSP_URL) return { status: 200, body: await ocsp.respond(request.body!) };
    return { status: 404, body: new Uint8Array(0) };
  };

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

  writeFileSync(join(outDir, 'test-ca.pem'), ca.certPem);
  writeFileSync(join(outDir, 'expected.tsv'), manifest);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
