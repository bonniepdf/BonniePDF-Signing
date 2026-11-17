/**
 * Generate a set of signed sample PDFs for external validation with `pdfsig`
 * (Poppler). The same sample set is produced by the .NET port's SampleGen, so
 * both libraries are validated by the identical external gate.
 *
 * Usage:  tsx signing/scripts/generate-signed-samples.ts [outDir]
 */
import { Document, TextBlock, StandardFonts } from '../../core/src/index';
import { signPdf } from '../src/signPdf';
import { SigningAlgorithm } from '../src/SigningAlgorithm';
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
  console.log(`Wrote 5 signed samples to ${outDir}/`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
