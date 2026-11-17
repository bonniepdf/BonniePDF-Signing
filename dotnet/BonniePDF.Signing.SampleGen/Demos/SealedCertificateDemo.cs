#nullable disable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using BonniePDF;

namespace BonniePDF.Signing.SampleGen.Demos;

/// <summary>
/// A completion certificate sealed for long-term verification (PAdES B-LT).
///
/// A certificate like this is kept for years: a fire-safety record, a calibration
/// certificate, a deed. A plain signature checks out only while the signer's
/// certificate is still valid and the authority's answers are still online. A
/// B-LT signature carries both with it: a trusted timestamp proving when it was
/// signed, and the certificate chain and revocation evidence, stored in the
/// document's Document Security Store. The seal verifies offline, long after the
/// signer's certificate has expired.
///
/// The signer, the time-stamp authority and the OCSP responder come from a
/// throwaway authority (see <see cref="DemoPki"/>) so the demo runs offline; in
/// production you pass a real certificate and the URL of a real time-stamp
/// authority.
/// </summary>
internal static class SealedCertificateDemo
{
    /// <summary>The name the seal box carries in the layout snapshot.</summary>
    private const string SealSlot = "seal";

    private const string Number = "FSC-2026-004417";
    private const string Responsible = "Beispiel Logistics Ltd";
    private const string Inspector = "Jordan Inspector";
    private const string Company = "Sample Inspections Ltd";
    private const int ValidMonths = 12;
    private const string Location = "Sample City, UK";

    private static readonly string[] Premises = { "Unit 7, Exemplar Business Park", "Sample City", "SC4 2PL" };
    private static readonly DateTime Inspected = new DateTime(2026, 10, 14);

    private sealed record Check(string Area, string Item, bool Pass);

    private static readonly Check[] Checks =
    {
        new Check("Escape routes", "Routes clear and signed, final exits open", true),
        new Check("Detection", "Fire alarm tested at every call point", true),
        new Check("Lighting", "Emergency lighting runs for its full duration", true),
        new Check("Extinguishers", "Serviced in the last 12 months and mounted correctly", true),
        new Check("Compartments", "Fire doors close fully and seals are intact", false),
        new Check("Storage", "Combustibles kept clear of heat sources", true),
        new Check("Training", "Staff fire-marshal training is in date", true),
        new Check("Records", "Weekly alarm tests logged", true),
    };

    /// <summary>Builds the certificate and returns the unsealed PDF with the position of the seal box.</summary>
    public static (byte[] Pdf, int Page, double[] Rect) BuildCertificate()
    {
        using BonniePDF.Document doc = CreateCertificate();

        // The snapshot is observational: asking for it does not change the document.
        SvgDocumentExport exported = doc.GenerateSvgDocument(new SvgPageExportOptions { CaptureLayout = true });
        LayoutNode seal = FindNode(exported.Snapshot.Root, SealSlot)
            ?? throw new InvalidOperationException($"The layout has no \"{SealSlot}\" box");
        LayoutRect box = seal.Rects[0];
        double pageHeight = exported.Snapshot.Pages[box.Page].Height;

        // The snapshot measures down from the top of the page; PDF measures up from the bottom.
        return (doc.GenerateBytes(), box.Page, new double[] { box.X, pageHeight - box.Y - box.Height, box.Width, box.Height });
    }

    /// <summary>Builds the certificate and seals it with a visible PAdES B-LT signature.</summary>
    public static async Task<byte[]> BuildSealedAsync(DemoPki pki)
    {
        (byte[] pdf, int page, double[] rect) = BuildCertificate();
        TestSupport.TestPki.Identity signer = pki.IssueSigner(Company);
        DateTimeOffset signingTime = DateTimeOffset.UtcNow;
        return await PdfSigner.SignAsync(pdf, new SignatureSettings
        {
            CertificatePem = signer.CertPem,
            PrivateKeyPem = signer.KeyPem,
            CertificateChainPem = new[] { pki.Ca.CertPem },
            PadesLevel = PadesLevel.BLT,

            // The trusted timestamp, and where the revocation evidence for the chain is fetched.
            TimestampUrl = DemoPki.TsaUrl,
            HttpClient = pki.Transport,
            Name = Company,
            Reason = "Certificate sealed for long-term verification",
            Location = Location,
            ContactInfo = "records@sample-inspections.example",
            SigningTime = signingTime,
            Appearance = new SignatureAppearance
            {
                Page = page,
                Rect = rect,
                Text = new[]
                {
                    $"Sealed by {Company}",
                    "PAdES B-LT: trusted timestamp and",
                    "validation data are embedded, so this seal",
                    "verifies offline, years from now.",
                    $"Sealed: {signingTime.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} UTC",
                },
                FontSize = 8,
            },
        }).ConfigureAwait(false);
    }

    private static BonniePDF.Document CreateCertificate()
    {
        int passes = Checks.Count(c => c.Pass);
        int advisories = Checks.Length - passes;
        DateTime validUntil = Inspected.AddMonths(ValidMonths);

        var doc = new BonniePDF.Document(new DocumentSettings { PageSize = PdfSize.A4, Margin = 46 });
        doc.Settings.Language = "en-GB";
        doc.Settings.DefaultTextStyle = new TextStyle().WithFamily("Helvetica").WithSize(9.5f).WithColor(Ink);
        doc.Settings.FooterTemplate = pageNumber => Band(
            $"Certificate {Number} · sample, not a real certificate",
            $"Page {pageNumber} of {TextElementBase.TotalPagesToken}");

        doc.Metadata.Title = $"Fire safety certificate {Number}";
        doc.Metadata.Author = Company;
        doc.Metadata.Subject = "A fire safety inspection certificate sealed with a PAdES B-LT signature (sample document).";
        doc.Metadata.Keywords = "certificate, inspection, fire safety, digital signature, pades, long-term validation";

        doc.Add(new Container { BackgroundColor = Accent, Height = 4, Margin = new Thickness(0, 0, 0, 14) });
        doc.Add(Cell("CERTIFICATE OF COMPLETION", size: 8.5f, bold: true, color: Accent, marginBottom: 4f));
        doc.Add(H1("Fire safety inspection"));
        doc.Add(Cell($"Certificate {Number}", color: Muted, marginBottom: 14f));

        doc.Add(WeightedRow(
            new IElement[]
            {
                Party("Premises", Premises),
                Party("Responsible person", new[] { Responsible }),
                Party("Inspected by", new[] { Inspector, Company }),
            },
            spacing: 20f,
            marginBottom: 6f));
        doc.Add(WeightedRow(
            new IElement[]
            {
                Tile(GbDate(Inspected), "Inspected"),
                Tile(GbDate(validUntil), "Valid until"),
                Tile($"{passes} of {Checks.Length}", "Checks passed"),
                Tile(advisories.ToString(CultureInfo.InvariantCulture), "Advisory notes", advisories > 0 ? ColorPalette.Amber[700] : Accent),
            },
            spacing: 10f,
            marginBottom: 6f));

        doc.Add(H2("What was checked"));
        Table table = new Table(1.6f, 4.4f, 1.1f)
        {
            CellPadding = 6,
            Border = new Border(0.5f),
            BorderColors = new BorderColors(Rule),
            HeaderBackgroundColor = Accent,
            HeaderTextColor = Color.White,
        };
        table.AddHeader(Th("Area"), Th("Check"), Th("Result"));
        foreach (Check c in Checks)
        {
            table.AddRow(
                Td(c.Area, bold: true),
                Td(c.Item),
                Td(c.Pass ? "Pass" : "Advisory", bold: true, color: c.Pass ? Accent : ColorPalette.Amber[700]));
        }

        doc.Add(table);

        doc.Add(Cell(
            "Advisory: the door to the loading bay closes but its lower seal is worn. It is safe today and should be replaced at the next service.",
            size: 9f,
            color: Muted,
            marginTop: 8f,
            marginBottom: 4f));

        doc.Add(H2("Sealed for long-term verification"));
        doc.Add(Cell(
            "This certificate carries a digital seal. Changing it after it was sealed breaks the seal, and a viewer will say so. "
            + "The seal includes a trusted timestamp and the evidence needed to check it, so it can be verified years from now without contacting anyone.",
            size: 9f,
            color: Muted,
            marginBottom: 8f));

        // The box the seal will cover. It is named so the layout can report where it landed.
        Container box = new Container { BackgroundColor = ColorPalette.Slate[50], Height = 92 };
        box.CaptureName = SealSlot;
        VerticalStack left = new VerticalStack();
        left.Add(Cell("SEAL", size: 6.5f, bold: true, color: Muted, marginBottom: 4f));
        left.Add(box);
        VerticalStack right = new VerticalStack();
        right.Add(Cell("HOW TO CHECK IT", size: 6.5f, bold: true, color: Muted, marginBottom: 4f));
        right.Add(Cell(
            "1. Open the certificate in a PDF viewer.\n2. Open the signature panel.\n3. The seal should read as valid, with the time it was made and the long-term validation data present.",
            size: 9f));
        doc.Add(WeightedRow(new IElement[] { left, right }, spacing: 22f, marginBottom: 8f));

        return doc;
    }

    // Local helpers and sample data for this document.

    private static LayoutNode FindNode(LayoutNode node, string name)
    {
        if (string.Equals(node.Name, name, StringComparison.Ordinal)) return node;
        foreach (LayoutNode child in node.Children)
        {
            LayoutNode found = FindNode(child, name);
            if (found != null) return found;
        }

        return null;
    }

    private static readonly Color Ink = ColorPalette.Slate[700];
    private static readonly Color Muted = ColorPalette.Slate[600];
    private static readonly Color Heading = ColorPalette.Slate[800];
    private static readonly Color Accent = ColorPalette.Emerald[700];
    private static readonly Color Rule = ColorPalette.Slate[200];

    private static TextBlock Cell(string text, float size = 9f, bool bold = false, Color? color = null, TextAlignment align = TextAlignment.Left, float marginTop = 0f, float marginBottom = 0f) => new TextBlock
    {
        Text = text,
        FontName = bold ? StandardFonts.HelveticaBold : StandardFonts.Helvetica,
        FontSize = size,
        Color = color ?? Ink,
        Alignment = align,
        Margin = new Thickness(0, marginTop, 0, marginBottom),
    };

    private static TextBlock Th(string text) => Cell(text, size: 8.5f, bold: true, color: Color.White);

    private static TextBlock Td(string text, bool bold = false, Color? color = null) => Cell(text, size: 8.5f, bold: bold, color: color);

    private static Heading H1(string text) => new Heading(text)
    {
        Level = 1,
        FontName = StandardFonts.HelveticaBold,
        FontSize = 21,
        Color = Heading,
        Margin = new Thickness(0, 0, 0, 4),
    };

    private static Heading H2(string text) => new Heading(text)
    {
        Level = 2,
        FontName = StandardFonts.HelveticaBold,
        FontSize = 13,
        Color = Accent,
        Margin = new Thickness(0, 16, 0, 8),
    };

    private static VerticalStack Party(string label, string[] lines)
    {
        VerticalStack stack = new VerticalStack();
        stack.Add(Cell(label.ToUpperInvariant(), size: 7f, bold: true, color: Muted, marginBottom: 3f));
        stack.Add(Cell(string.Join('\n', lines), size: 9f));
        return stack;
    }

    private static HorizontalStack WeightedRow(IEnumerable<IElement> items, float spacing = 14f, float marginBottom = 14f)
    {
        HorizontalStack row = new HorizontalStack
        {
            WidthDistribution = WidthDistribution.Weighted,
            Spacing = spacing,
            Margin = new Thickness(0, 0, 0, marginBottom),
        };
        foreach (IElement item in items)
        {
            row.Add(item, 1);
        }

        return row;
    }

    private static Container Tile(string value, string label, Color? accent = null)
    {
        VerticalStack body = new VerticalStack();
        body.Add(Cell(value, size: 14f, bold: true, color: accent ?? Accent, marginBottom: 2f));
        body.Add(Cell(label, size: 8f, color: Muted));
        return new Container
        {
            BackgroundColor = ColorPalette.Slate[50],
            Border = new Border(0.75f),
            BorderColors = new BorderColors(Rule),
            CornerRadius = 6,
            Padding = new Thickness(11, 10),
            Child = body,
        };
    }

    private static HorizontalStack Band(string left, string right)
    {
        HorizontalStack row = new HorizontalStack { WidthDistribution = WidthDistribution.Weighted };
        row.Add(Cell(left, size: 7.5f, color: Muted), 2.5f);
        row.Add(Cell(right, size: 7.5f, color: Muted, align: TextAlignment.Right), 2);
        return row;
    }

    private static string GbDate(DateTime date) => date.ToString("dd MMM yyyy", CultureInfo.GetCultureInfo("en-GB"));
}
