using System.Collections.Generic;

namespace BonniePDF.Signing;

/// <summary>
/// Specification for a <b>visible</b> signature appearance - the graphics drawn
/// inside the signature widget's rectangle. Mirrors the TypeScript
/// <c>SignatureAppearance</c>.
/// </summary>
public sealed class SignatureAppearance
{
    /// <summary>0-based page index to place the widget on (default 0).</summary>
    public int Page { get; set; }

    /// <summary>Widget rectangle in PDF points: <c>[x, y, width, height]</c>.</summary>
    public double[] Rect { get; set; }

    /// <summary>
    /// Text lines to render. If null, sensible defaults are derived from the
    /// signer name / reason / location / signing time.
    /// </summary>
    public IReadOnlyList<string> Text { get; set; }

    /// <summary>Font size in points (default 8).</summary>
    public double FontSize { get; set; } = 8;

    /// <summary>Draw a thin border around the widget (default true).</summary>
    public bool Border { get; set; } = true;
}
