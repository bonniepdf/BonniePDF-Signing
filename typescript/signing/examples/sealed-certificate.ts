/**
 * Demo: a completion certificate sealed for long-term verification (PAdES B-LT).
 *
 * A certificate like this is kept for years: a fire-safety record, a calibration
 * certificate, a deed. A plain signature checks out only while the signer's
 * certificate is still valid and the authority's answers are still online. A
 * B-LT signature carries both with it: a trusted timestamp proving when it was
 * signed, and the certificate chain and revocation evidence, stored in the
 * document's Document Security Store. The seal verifies offline, long after the
 * signer's certificate has expired.
 *
 * Run (Node 20+), from the signing package:
 *   tsx examples/sealed-certificate.ts [out.pdf]
 *
 * This is a commercial-add-on demo, kept out of the public `@bonniepdf/examples`
 * registry for the same reasons as `signed-agreement.ts`. The signer, the
 * time-stamp authority and the OCSP responder come from a throwaway authority
 * (see `support/demo-pki.ts`) so the demo runs offline; in production you pass
 * a real certificate and the URL of a real time-stamp authority.
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Document,
  TextElementBase,
  Container,
  VerticalStack,
  HorizontalStack,
  Table,
  pageTemplate,
  TextBlock,
  Heading,
  StandardFonts,
  ColorPalette,
  settings,
  type ColorInput,
  type IElement,
} from '@bonniepdf/core';
import { signPdf } from '../src/signPdf';
import { createDemoPki, TSA_URL, type DemoPki } from './support/demo-pki';

const INK = ColorPalette.slate[700];
const MUTED = ColorPalette.slate[600];
const HEADING = ColorPalette.slate[800];
const ACCENT = ColorPalette.emerald[700];
const RULE = ColorPalette.slate[200];

/** The name the seal box carries in the layout snapshot. */
const SEAL_SLOT = 'seal';

const CERTIFICATE = {
  number: 'FSC-2026-004417',
  premises: ['Unit 7, Exemplar Business Park', 'Sample City', 'SC4 2PL'],
  responsible: 'Beispiel Logistics Ltd',
  inspector: 'Jordan Inspector',
  company: 'Sample Inspections Ltd',
  inspected: new Date(Date.UTC(2026, 9, 14)),
  validMonths: 12,
  location: 'Sample City, UK',
};

const CHECKS: Array<{ area: string; item: string; result: 'Pass' | 'Advisory' }> = [
  { area: 'Escape routes', item: 'Routes clear and signed, final exits open', result: 'Pass' },
  { area: 'Detection', item: 'Fire alarm tested at every call point', result: 'Pass' },
  { area: 'Lighting', item: 'Emergency lighting runs for its full duration', result: 'Pass' },
  { area: 'Extinguishers', item: 'Serviced in the last 12 months and mounted correctly', result: 'Pass' },
  { area: 'Compartments', item: 'Fire doors close fully and seals are intact', result: 'Advisory' },
  { area: 'Storage', item: 'Combustibles kept clear of heat sources', result: 'Pass' },
  { area: 'Training', item: 'Staff fire-marshal training is in date', result: 'Pass' },
  { area: 'Records', item: 'Weekly alarm tests logged', result: 'Pass' },
];

/** Builds the certificate and returns the unsealed PDF with the position of the seal box. */
export async function buildCertificate(): Promise<{
  pdf: Uint8Array;
  page: number;
  rect: [number, number, number, number];
}> {
  const doc = createCertificate();

  // The snapshot is observational: asking for it does not change the document.
  const exported = await doc.generateSvgDocumentAsync({ captureLayout: true });
  const seal = findNode(exported.snapshot!.root, SEAL_SLOT);
  if (!seal || seal.rects.length === 0) throw new Error(`The layout has no "${SEAL_SLOT}" box`);
  const box = seal.rects[0];
  const pageHeight = exported.snapshot!.pages[box.page].height;

  return {
    pdf: await doc.generateBytesAsync(),
    page: box.page,
    // The snapshot measures down from the top of the page; PDF measures up from the bottom.
    rect: [box.x, pageHeight - box.y - box.height, box.width, box.height],
  };
}

/** Builds the certificate and seals it with a visible PAdES B-LT signature. */
export async function buildSealedCertificate(pki: DemoPki): Promise<Uint8Array> {
  const { pdf, page, rect } = await buildCertificate();
  const signer = await pki.issueSigner(CERTIFICATE.company);
  const signingTime = new Date();
  return signPdf(pdf, {
    certificatePem: signer.certPem,
    privateKeyPem: signer.keyPem,
    certificateChainPem: [pki.ca.certPem],
    padesLevel: 'b-lt',
    // The trusted timestamp, and where the revocation evidence for the chain is fetched.
    timestampUrl: TSA_URL,
    httpClient: pki.httpClient,
    name: CERTIFICATE.company,
    reason: 'Certificate sealed for long-term verification',
    location: CERTIFICATE.location,
    contactInfo: 'records@sample-inspections.example',
    signingTime,
    appearance: {
      page,
      rect,
      text: [
        `Sealed by ${CERTIFICATE.company}`,
        'PAdES B-LT: trusted timestamp and',
        'validation data are embedded, so this seal',
        'verifies offline, years from now.',
        `Sealed: ${signingTime.toISOString().slice(0, 19).replace('T', ' ')} UTC`,
      ],
      fontSize: 8,
    },
  });
}

function createCertificate(): Document {
  const passes = CHECKS.filter(c => c.result === 'Pass').length;
  const advisories = CHECKS.length - passes;
  const validUntil = new Date(
    Date.UTC(
      CERTIFICATE.inspected.getUTCFullYear(),
      CERTIFICATE.inspected.getUTCMonth() + CERTIFICATE.validMonths,
      CERTIFICATE.inspected.getUTCDate()
    )
  );

  const doc = new Document({
    settings: {
      pageSize: 'a4',
      margin: 46,
      language: 'en-GB',
      defaultTextStyle: { fontFamily: 'Helvetica', fontSize: 9.5, color: INK },
      footerTemplate: pageTemplate({
        default: band(
          `Certificate ${CERTIFICATE.number} · sample, not a real certificate`,
          `Page ${TextElementBase.CurrentPageToken} of ${TextElementBase.TotalPagesToken}`
        ),
      }),
    },
    metadata: {
      title: `Fire safety certificate ${CERTIFICATE.number}`,
      author: CERTIFICATE.company,
      subject: 'A fire safety inspection certificate sealed with a PAdES B-LT signature (sample document).',
      keywords: 'certificate, inspection, fire safety, digital signature, pades, long-term validation',
    },
  });

  doc.add(new Container({ backgroundColor: ACCENT, height: 4, margin: { bottom: 14 } }));
  doc.add(cell('CERTIFICATE OF COMPLETION', { bold: true, size: 8.5, color: ACCENT, mb: 4 }));
  doc.add(h1('Fire safety inspection'));
  doc.add(cell(`Certificate ${CERTIFICATE.number}`, { color: MUTED, mb: 14 }));

  doc.add(
    weightedRow(
      [
        party('Premises', CERTIFICATE.premises),
        party('Responsible person', [CERTIFICATE.responsible]),
        party('Inspected by', [CERTIFICATE.inspector, CERTIFICATE.company]),
      ],
      { spacing: 20, mb: 6 }
    )
  );
  doc.add(
    weightedRow(
      [
        tile(gbDate(CERTIFICATE.inspected), 'Inspected'),
        tile(gbDate(validUntil), 'Valid until'),
        tile(`${passes} of ${CHECKS.length}`, 'Checks passed'),
        tile(String(advisories), 'Advisory notes', advisories > 0 ? ColorPalette.amber[700] : ACCENT),
      ],
      { spacing: 10, mb: 6 }
    )
  );

  doc.add(h2('What was checked'));
  const table = new Table({
    columns: [1.6, 4.4, 1.1],
    cellPadding: 6,
    border: { width: 0.5, color: RULE },
    headerBackgroundColor: ACCENT,
    headerTextColor: '#ffffff',
  });
  table.addHeader(th('Area'), th('Check'), th('Result'));
  for (const c of CHECKS) {
    table.addRow(
      td(c.area, { bold: true }),
      td(c.item),
      td(c.result, { bold: true, color: c.result === 'Pass' ? ACCENT : ColorPalette.amber[700] })
    );
  }
  doc.add(table);

  doc.add(
    cell(
      'Advisory: the door to the loading bay closes but its lower seal is worn. It is safe today and should be replaced at the next service.',
      { size: 9, color: MUTED, mt: 8, mb: 4 }
    )
  );

  doc.add(h2('Sealed for long-term verification'));
  doc.add(
    cell(
      'This certificate carries a digital seal. Changing it after it was sealed breaks the seal, and a viewer will say so. ' +
        'The seal includes a trusted timestamp and the evidence needed to check it, so it can be verified years from now without contacting anyone.',
      { size: 9, color: MUTED, mb: 8 }
    )
  );

  // The box the seal will cover. It is named so the layout can report where it landed.
  const box = new Container({ backgroundColor: ColorPalette.slate[50], height: 92 });
  box.captureName = SEAL_SLOT;
  doc.add(
    weightedRow(
      [
        new VerticalStack({
          children: [cell('SEAL', { bold: true, size: 6.5, color: MUTED, mb: 4 }), box],
        }),
        new VerticalStack({
          children: [
            cell('HOW TO CHECK IT', { bold: true, size: 6.5, color: MUTED, mb: 4 }),
            cell(
              '1. Open the certificate in a PDF viewer.\n2. Open the signature panel.\n3. The seal should read as valid, with the time it was made and the long-term validation data present.',
              { size: 9 }
            ),
          ],
        }),
      ],
      { spacing: 22, mb: 8 }
    )
  );

  return doc;
}

// Local helpers and sample types used by this document.

interface LayoutNodeLike {
  name?: string;
  rects: Array<{ page: number; x: number; y: number; width: number; height: number }>;
  children: LayoutNodeLike[];
}

function findNode(node: LayoutNodeLike, name: string): LayoutNodeLike | undefined {
  if (node.name === name) return node;
  for (const child of node.children) {
    const found = findNode(child, name);
    if (found) return found;
  }
  return undefined;
}

interface TextOpts {
  size?: number;
  bold?: boolean;
  color?: ColorInput;
  align?: 'left' | 'right' | 'center' | 'justify';
  mt?: number;
  mb?: number;
}

function cell(text: string, o: TextOpts = {}): TextBlock {
  return new TextBlock(text, {
    fontName: o.bold ? StandardFonts.HelveticaBold : StandardFonts.Helvetica,
    fontSize: o.size ?? 9,
    color: o.color ?? INK,
    alignment: o.align ?? 'left',
    margin: { top: o.mt ?? 0, bottom: o.mb ?? 0 },
  });
}

function th(text: string): TextBlock {
  return cell(text, { bold: true, size: 8.5, color: '#ffffff' });
}

function td(text: string, o: TextOpts = {}): TextBlock {
  return cell(text, { size: 8.5, ...o });
}

function h1(text: string): Heading {
  return new Heading(text, {
    level: 1,
    fontName: StandardFonts.HelveticaBold,
    fontSize: 21,
    color: HEADING,
    margin: { bottom: 4 },
  });
}

function h2(text: string): Heading {
  return new Heading(text, {
    level: 2,
    fontName: StandardFonts.HelveticaBold,
    fontSize: 13,
    color: ACCENT,
    margin: { top: 16, bottom: 8 },
  });
}

function party(label: string, lines: string[]): VerticalStack {
  return new VerticalStack({
    children: [
      cell(label.toUpperCase(), { bold: true, size: 7, color: MUTED, mb: 3 }),
      cell(lines.join('\n'), { size: 9 }),
    ],
  });
}

function weightedRow(items: IElement[], o: { spacing?: number; mb?: number } = {}): HorizontalStack {
  const row = new HorizontalStack({
    widthDistribution: 'weighted',
    spacing: o.spacing ?? 14,
    margin: { bottom: o.mb ?? 14 },
  });
  for (const item of items) row.add(item, 1);
  return row;
}

function tile(value: string, label: string, accent: ColorInput = ACCENT): Container {
  return new Container({
    backgroundColor: ColorPalette.slate[50],
    border: { width: 0.75, color: RULE },
    cornerRadius: 6,
    padding: [11, 10],
    child: new VerticalStack({
      children: [cell(value, { bold: true, size: 14, color: accent, mb: 2 }), cell(label, { size: 8, color: MUTED })],
    }),
  });
}

function band(left: string, right: string): HorizontalStack {
  const row = new HorizontalStack({ widthDistribution: 'weighted' });
  row.add(cell(left, { size: 7.5, color: MUTED }), 2.5);
  row.add(cell(right, { size: 7.5, color: MUTED, align: 'right' }), 2);
  return row;
}

function gbDate(d: Date): string {
  return new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(
    d
  );
}

async function main(): Promise<void> {
  // Running a demo is not production use, so `evaluation` is the honest declaration.
  settings.license = 'evaluation';
  const outPath = process.argv[2] ?? 'sealed-certificate.pdf';
  const pki = await createDemoPki();
  const sealed = await buildSealedCertificate(pki);
  writeFileSync(outPath, sealed);
  writeFileSync(outPath.replace(/\.pdf$/, '') + '-ca.pem', pki.ca.certPem);
  console.log(`Sealed certificate written to ${outPath} (${sealed.length} bytes).`);
  console.log('Check it with: pdfsig ' + outPath);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
