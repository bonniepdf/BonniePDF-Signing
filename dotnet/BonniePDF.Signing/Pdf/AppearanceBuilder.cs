using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace BonniePDF.Signing.Pdf;

/// <summary>
/// Builds the content stream for a visible signature appearance: an optional
/// border plus left-aligned text lines in standard-14 Helvetica (no embedding).
/// Port of the TypeScript <c>appearance.ts</c>.
/// </summary>
internal static class AppearanceBuilder
{
    private static string Escape(string text) =>
        text.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)").Replace("\r", " ").Replace("\n", " ");

    private static string F(double value) => value.ToString("0.##", CultureInfo.InvariantCulture);

    /// <summary>
    /// Build the appearance content stream for a widget of the given size.
    /// Origin is the widget's bottom-left; text is laid out top-down with a
    /// small inset and 1.2x line spacing.
    /// </summary>
    public static string BuildStream(double width, double height, IReadOnlyList<string> lines, double fontSize, bool border)
    {
        var parts = new List<string>();
        if (border)
        {
            parts.Add("q");
            parts.Add("0.5 0.5 0.5 RG");
            parts.Add("0.5 w");
            parts.Add($"0.5 0.5 {F(width - 1)} {F(height - 1)} re");
            parts.Add("S");
            parts.Add("Q");
        }

        if (lines is { Count: > 0 })
        {
            double leading = fontSize * 1.2;
            const double inset = 2;
            double startY = height - inset - fontSize;
            parts.Add("BT");
            parts.Add($"/Helv {F(fontSize)} Tf");
            parts.Add($"{F(leading)} TL");
            parts.Add("0 g");
            parts.Add($"{F(inset)} {F(startY)} Td");
            for (int i = 0; i < lines.Count; i++)
            {
                if (i == 0)
                {
                    parts.Add($"({Escape(lines[i])}) Tj");
                }
                else
                {
                    parts.Add("T*");
                    parts.Add($"({Escape(lines[i])}) Tj");
                }
            }
            parts.Add("ET");
        }

        return string.Join("\n", parts);
    }
}
