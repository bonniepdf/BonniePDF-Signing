/**
 * Builds the content stream for a **visible** signature appearance — the
 * graphics drawn inside the signature widget's `/Rect`. Kept deliberately
 * small: an optional border plus left-aligned text lines in standard-14
 * Helvetica (no font embedding needed for a non-PDF/A appearance).
 */

/** Specification for a visible signature appearance. */
export interface SignatureAppearance {
  /** 0-based page index to place the widget on (default 0). */
  page?: number;
  /** Widget rectangle in PDF points: `[x, y, width, height]`. */
  rect: [number, number, number, number];
  /**
   * Text lines to render. If omitted, `signPdf` derives sensible defaults
   * from the signer name / reason / location / signing time.
   */
  text?: string[];
  /** Font size in points (default 8). */
  fontSize?: number;
  /** Draw a thin border around the widget (default true). */
  border?: boolean;
}

/** Escape a string for a PDF literal `( ... )` string. */
function escape(text: string): string {
  return text
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/[\r\n]+/g, ' ');
}

/**
 * Build the appearance content stream for a widget of the given size.
 * Origin is the widget's bottom-left; text is laid out top-down with a small
 * inset and line spacing of 1.2 × font size.
 */
export function buildAppearanceStream(
  width: number,
  height: number,
  lines: string[],
  fontSize: number,
  border: boolean
): string {
  const parts: string[] = [];
  if (border) {
    // 0.5pt mid-grey rectangle just inside the bounding box.
    parts.push(
      'q',
      '0.5 0.5 0.5 RG',
      '0.5 w',
      `0.5 0.5 ${(width - 1).toFixed(2)} ${(height - 1).toFixed(2)} re`,
      'S',
      'Q'
    );
  }
  if (lines.length > 0) {
    const leading = fontSize * 1.2;
    const inset = 2;
    const startY = height - inset - fontSize;
    parts.push('BT', `/Helv ${fontSize} Tf`, `${leading.toFixed(2)} TL`, '0 g', `${inset} ${startY.toFixed(2)} Td`);
    lines.forEach((line, i) => {
      if (i === 0) parts.push(`(${escape(line)}) Tj`);
      else parts.push('T*', `(${escape(line)}) Tj`);
    });
    parts.push('ET');
  }
  return parts.join('\n');
}
