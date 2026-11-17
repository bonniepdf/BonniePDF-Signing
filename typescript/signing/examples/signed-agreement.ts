/**
 * Demo: a services agreement signed with a visible PAdES signature.
 *
 * The document is built with BonniePDF as usual. Its signature block reserves a
 * box and names it; the layout snapshot reports where that box landed, and the
 * signature is placed exactly over it. Nothing is hard-coded to a page position,
 * so the agreement can grow or shrink and the signature still lands in its box.
 *
 * Run (Node 20+), from the signing package:
 *   tsx examples/signed-agreement.ts [out.pdf]
 *
 * This is a commercial-add-on demo. It is not part of the public
 * `@bonniepdf/examples` registry: that catalogue is core-only, its examples
 * return a `Document`, and signed output is not deterministic. The signer here
 * comes from a throwaway authority (see `support/demo-pki.ts`); in production
 * you pass a certificate issued by a real one.
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
import { createDemoPki, type DemoPki } from './support/demo-pki';

const INK = ColorPalette.slate[700];
const MUTED = ColorPalette.slate[600];
const HEADING = ColorPalette.slate[800];
const ACCENT = ColorPalette.indigo[700];
const RULE = ColorPalette.slate[200];

/** The name the signature box carries in the layout snapshot. */
const SIGNATURE_SLOT = 'supplier-signature';

const AGREEMENT = {
  reference: 'MSA-2026-0418',
  supplier: 'Sample Analytics Ltd',
  supplierAddress: ['4 Example Square', 'Sample City', 'SC2 5DE'],
  customer: 'Beispiel Retail Group plc',
  customerAddress: ['90 Musterweg', 'Sample Town', 'ST7 1AA'],
  effective: new Date(Date.UTC(2026, 10, 1)),
  months: 12,
  /** Pence per month. */
  fee: 840_000,
  paymentDays: 30,
  noticeDays: 60,
  signer: 'Alex Supplier',
  location: 'London, UK',
};

const CLAUSES: Array<{ title: string; items: string[] }> = [
  {
    title: 'The services',
    items: [
      `${AGREEMENT.supplier} will provide the analytics service described in the order form to ${AGREEMENT.customer} for the term of this agreement.`,
      'The supplier will keep the service available at least 99.5% of the time in each calendar month, and credit the customer where it falls short.',
    ],
  },
  {
    title: 'Fees and payment',
    items: [
      `The customer pays ${money(AGREEMENT.fee)} a month. Each invoice is due within ${AGREEMENT.paymentDays} days of its date.`,
      'Fees are fixed for the first term. Any increase for a renewal term is notified in writing at least 90 days before it starts.',
    ],
  },
  {
    title: 'Data and confidentiality',
    items: [
      "Each party keeps the other's confidential information secret and uses it only to perform this agreement.",
      "The supplier processes personal data only on the customer's written instructions and deletes it within 30 days of the end of the agreement.",
    ],
  },
  {
    title: 'Term and ending the agreement',
    items: [
      `This agreement starts on ${gbDate(AGREEMENT.effective)} and runs for ${AGREEMENT.months} months, then renews yearly unless either party gives ${AGREEMENT.noticeDays} days' written notice.`,
      'Either party may end it at once if the other commits a serious breach it does not put right within 30 days of being told.',
    ],
  },
];

/** Builds the agreement and returns the unsigned PDF with the position of the signature box. */
export async function buildAgreement(): Promise<{
  pdf: Uint8Array;
  page: number;
  rect: [number, number, number, number];
}> {
  const doc = createAgreement();

  // The snapshot is observational: asking for it does not change the document.
  const exported = await doc.generateSvgDocumentAsync({ captureLayout: true });
  const slot = findNode(exported.snapshot!.root, SIGNATURE_SLOT);
  if (!slot || slot.rects.length === 0) throw new Error(`The layout has no "${SIGNATURE_SLOT}" box`);
  const box = slot.rects[0];
  const pageHeight = exported.snapshot!.pages[box.page].height;

  return {
    pdf: await doc.generateBytesAsync(),
    page: box.page,
    // The snapshot measures down from the top of the page; PDF measures up from the bottom.
    rect: [box.x, pageHeight - box.y - box.height, box.width, box.height],
  };
}

/** Builds the agreement and signs it with a visible PAdES baseline-B signature. */
export async function buildSignedAgreement(pki: DemoPki): Promise<Uint8Array> {
  const { pdf, page, rect } = await buildAgreement();
  const signer = await pki.issueSigner(AGREEMENT.signer);
  const signingTime = new Date();
  return signPdf(pdf, {
    certificatePem: signer.certPem,
    privateKeyPem: signer.keyPem,
    certificateChainPem: [pki.ca.certPem],
    padesLevel: 'b-b',
    name: AGREEMENT.signer,
    reason: 'I agree to these terms',
    location: AGREEMENT.location,
    contactInfo: 'contracts@sample-analytics.example',
    signingTime,
    appearance: {
      page,
      rect,
      text: [
        `Digitally signed by ${AGREEMENT.signer}`,
        `for ${AGREEMENT.supplier}`,
        'Reason: I agree to these terms',
        `Location: ${AGREEMENT.location}`,
        `Date: ${signingTime.toISOString().slice(0, 19).replace('T', ' ')} UTC`,
      ],
      fontSize: 8,
    },
  });
}

function createAgreement(): Document {
  const doc = new Document({
    settings: {
      pageSize: 'a4',
      margin: 46,
      language: 'en-GB',
      defaultTextStyle: { fontFamily: 'Helvetica', fontSize: 9.5, color: INK },
      footerTemplate: pageTemplate({
        default: band(
          `Services agreement ${AGREEMENT.reference} · digitally signed · sample, not legal advice`,
          `Page ${TextElementBase.CurrentPageToken} of ${TextElementBase.TotalPagesToken}`
        ),
      }),
    },
    metadata: {
      title: `Services agreement ${AGREEMENT.reference}`,
      author: AGREEMENT.supplier,
      subject: 'A services agreement with a visible PAdES digital signature (sample document, not legal advice).',
      keywords: 'agreement, contract, digital signature, pades',
    },
  });

  doc.add(
    new Container({
      backgroundColor: ACCENT,
      height: 4,
      margin: { bottom: 14 },
    })
  );
  doc.add(cell('SERVICES AGREEMENT', { bold: true, size: 8.5, color: ACCENT, mb: 4 }));
  doc.add(h1(`Agreement ${AGREEMENT.reference}`));
  doc.add(
    cell(`Effective ${gbDate(AGREEMENT.effective)} · ${AGREEMENT.months}-month initial term`, { color: MUTED, mb: 14 })
  );

  doc.add(
    weightedRow(
      [
        party('Supplier', [AGREEMENT.supplier, ...AGREEMENT.supplierAddress]),
        party('Customer', [AGREEMENT.customer, ...AGREEMENT.customerAddress]),
      ],
      { spacing: 20, mb: 6 }
    )
  );
  doc.add(
    weightedRow(
      [
        tile(`${money(AGREEMENT.fee)}`, 'Fee per month'),
        tile(money(AGREEMENT.fee * AGREEMENT.months), 'Initial term total'),
        tile(`${AGREEMENT.paymentDays} days`, 'Payment terms'),
        tile(`${AGREEMENT.noticeDays} days`, 'Notice to end'),
      ],
      { spacing: 10, mb: 6 }
    )
  );

  doc.add(h2('Agreed terms'));
  CLAUSES.forEach((clause, c) => {
    doc.add(clauseHeading(c + 1, clause.title));
    clause.items.forEach((text, i) => doc.add(subClause(`${c + 1}.${i + 1}`, text)));
  });

  doc.add(h2('Signatures'));
  doc.add(
    cell('The supplier has signed digitally in the box below. The customer signs on receipt.', {
      size: 9,
      color: MUTED,
      mb: 8,
    })
  );

  // The box the signature will cover. It is named so the layout can report where it landed.
  const box = new Container({
    backgroundColor: ColorPalette.slate[50],
    height: 78,
  });
  box.captureName = SIGNATURE_SLOT;
  doc.add(
    weightedRow(
      [
        new VerticalStack({
          children: [
            cell('SUPPLIER · SIGNED DIGITALLY', {
              bold: true,
              size: 6.5,
              color: MUTED,
              mb: 4,
            }),
            box,
          ],
        }),
        new VerticalStack({
          children: [
            cell('CUSTOMER', { bold: true, size: 6.5, color: MUTED, mb: 4 }),
            new Container({ height: 62 }),
            new Container({
              backgroundColor: RULE,
              height: 0.75,
              margin: { bottom: 5 },
            }),
            cell('Name, position and date', { size: 8, color: MUTED }),
          ],
        }),
      ],
      { spacing: 22, mb: 8 }
    )
  );

  const terms = new Table({
    columns: [2, 5],
    cellPadding: 6,
    border: { width: 0.5, color: RULE },
    headerBackgroundColor: ACCENT,
    headerTextColor: '#ffffff',
  });
  terms.addHeader(th('If you change this document'), th('What happens'));
  terms.addRow(
    td('Anything after it was signed', { bold: true }),
    td('The signature no longer matches and a viewer reports it as broken.')
  );
  terms.addRow(
    td('Opening it in a viewer', { bold: true }),
    td("The signature is checked against the signer's certificate and the time it was made.")
  );
  doc.add(terms);

  return doc;
}

// Local helpers and sample types used by this document.

interface LayoutNodeLike {
  name?: string;
  rects: Array<{
    page: number;
    x: number;
    y: number;
    width: number;
    height: number;
  }>;
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

/** Pence as pounds: £1,234.56. */
function money(pence: number): string {
  const whole = String(Math.floor(pence / 100)).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `£${whole}.${String(pence % 100).padStart(2, '0')}`;
}

function clauseHeading(number: number, title: string): Heading {
  return new Heading(`${number}. ${title}`, {
    level: 3,
    fontName: StandardFonts.HelveticaBold,
    fontSize: 10.5,
    color: HEADING,
    margin: { top: 8, bottom: 4 },
  });
}

/** A numbered sub-clause: the number hangs in its own column so wrapped lines align with the text. */
function subClause(number: string, text: string): HorizontalStack {
  const row = new HorizontalStack({
    widthDistribution: 'weighted',
    spacing: 6,
    margin: { bottom: 4 },
  });
  row.add(cell(number, { size: 9, color: MUTED }), 0.5);
  row.add(cell(text, { size: 9 }), 9);
  return row;
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

function tile(value: string, label: string): Container {
  return new Container({
    backgroundColor: ColorPalette.slate[50],
    border: { width: 0.75, color: RULE },
    cornerRadius: 6,
    padding: [11, 10],
    child: new VerticalStack({
      children: [cell(value, { bold: true, size: 14, color: ACCENT, mb: 2 }), cell(label, { size: 8, color: MUTED })],
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
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(d);
}

async function main(): Promise<void> {
  // Running a demo is not production use, so `evaluation` is the honest declaration.
  settings.license = 'evaluation';
  const outPath = process.argv[2] ?? 'signed-agreement.pdf';
  const pki = await createDemoPki('Alex Supplier');
  const signed = await buildSignedAgreement(pki);
  writeFileSync(outPath, signed);
  writeFileSync(outPath.replace(/\.pdf$/, '') + '-ca.pem', pki.ca.certPem);
  console.log(`Signed agreement written to ${outPath} (${signed.length} bytes).`);
  console.log('Check it with: pdfsig ' + outPath);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
