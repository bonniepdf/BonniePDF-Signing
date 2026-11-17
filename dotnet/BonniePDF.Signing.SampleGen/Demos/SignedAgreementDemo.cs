#nullable disable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using BonniePDF;

namespace BonniePDF.Signing.SampleGen.Demos;

/// <summary>
/// A services agreement signed with a visible PAdES signature.
///
/// The document is built with BonniePDF as usual. Its signature block reserves a
/// box and names it; the layout snapshot reports where that box landed, and the
/// signature is placed exactly over it. Nothing is hard-coded to a page position,
/// so the agreement can grow or shrink and the signature still lands in its box.
///
/// Run through <c>dotnet run --project BonniePDF.Signing.SampleGen -- outDir</c>.
/// The signer comes from a throwaway authority (see <see cref="DemoPki"/>); in
/// production you pass a certificate issued by a real one.
/// </summary>
internal static class SignedAgreementDemo
{
    /// <summary>The name the signature box carries in the layout snapshot.</summary>
    private const string SignatureSlot = "supplier-signature";

    private const string Reference = "MSA-2026-0418";
    private const string Supplier = "Sample Analytics Ltd";
    private const string Customer = "Beispiel Retail Group plc";
    private const int Months = 12;

    /// <summary>Pence per month.</summary>
    private const int Fee = 840_000;

    private const int PaymentDays = 30;
    private const int NoticeDays = 60;
    private const string SignerName = "Alex Supplier";
    private const string Location = "London, UK";

    private static readonly string[] SupplierAddress = { "4 Example Square", "Sample City", "SC2 5DE" };
    private static readonly string[] CustomerAddress = { "90 Musterweg", "Sample Town", "ST7 1AA" };
    private static readonly DateTime Effective = new DateTime(2026, 11, 1);

    private sealed record Clause(string Title, string[] Items);

    /// <summary>Builds the agreement and returns the unsigned PDF with the position of the signature box.</summary>
    public static (byte[] Pdf, int Page, double[] Rect) BuildAgreement()
    {
        using BonniePDF.Document doc = CreateAgreement();

        // The snapshot is observational: asking for it does not change the document.
        SvgDocumentExport exported = doc.GenerateSvgDocument(new SvgPageExportOptions { CaptureLayout = true });
        LayoutNode slot = FindNode(exported.Snapshot.Root, SignatureSlot)
            ?? throw new InvalidOperationException($"The layout has no \"{SignatureSlot}\" box");
        LayoutRect box = slot.Rects[0];
        double pageHeight = exported.Snapshot.Pages[box.Page].Height;

        // The snapshot measures down from the top of the page; PDF measures up from the bottom.
        return (doc.GenerateBytes(), box.Page, new double[] { box.X, pageHeight - box.Y - box.Height, box.Width, box.Height });
    }

    /// <summary>Builds the agreement and signs it with a visible PAdES baseline-B signature.</summary>
    public static byte[] BuildSigned(DemoPki pki)
    {
        (byte[] pdf, int page, double[] rect) = BuildAgreement();
        TestSupport.TestPki.Identity signer = pki.IssueSigner(SignerName);
        DateTimeOffset signingTime = DateTimeOffset.UtcNow;
        return PdfSigner.Sign(pdf, new SignatureSettings
        {
            CertificatePem = signer.CertPem,
            PrivateKeyPem = signer.KeyPem,
            CertificateChainPem = new[] { pki.Ca.CertPem },
            PadesLevel = PadesLevel.BB,
            Name = SignerName,
            Reason = "I agree to these terms",
            Location = Location,
            ContactInfo = "contracts@sample-analytics.example",
            SigningTime = signingTime,
            Appearance = new SignatureAppearance
            {
                Page = page,
                Rect = rect,
                Text = new[]
                {
                    $"Digitally signed by {SignerName}",
                    $"for {Supplier}",
                    "Reason: I agree to these terms",
                    $"Location: {Location}",
                    $"Date: {signingTime.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} UTC",
                },
                FontSize = 8,
            },
        });
    }

    private static Clause[] Clauses() => new[]
    {
        new Clause("The services", new[]
        {
            $"{Supplier} will provide the analytics service described in the order form to {Customer} for the term of this agreement.",
            "The supplier will keep the service available at least 99.5% of the time in each calendar month, and credit the customer where it falls short.",
        }),
        new Clause("Fees and payment", new[]
        {
            $"The customer pays {Money(Fee)} a month. Each invoice is due within {PaymentDays} days of its date.",
            "Fees are fixed for the first term. Any increase for a renewal term is notified in writing at least 90 days before it starts.",
        }),
        new Clause("Data and confidentiality", new[]
        {
            "Each party keeps the other's confidential information secret and uses it only to perform this agreement.",
            "The supplier processes personal data only on the customer's written instructions and deletes it within 30 days of the end of the agreement.",
        }),
        new Clause("Term and ending the agreement", new[]
        {
            $"This agreement starts on {GbDate(Effective)} and runs for {Months} months, then renews yearly unless either party gives {NoticeDays} days' written notice.",
            "Either party may end it at once if the other commits a serious breach it does not put right within 30 days of being told.",
        }),
    };

    private static BonniePDF.Document CreateAgreement()
    {
        var doc = new BonniePDF.Document(new DocumentSettings { PageSize = PdfSize.A4, Margin = 46 });
        doc.Settings.Language = "en-GB";
        doc.Settings.DefaultTextStyle = new TextStyle().WithFamily("Helvetica").WithSize(9.5f).WithColor(Ink);
        doc.Settings.FooterTemplate = pageNumber => Band(
            $"Services agreement {Reference} · digitally signed · sample, not legal advice",
            $"Page {pageNumber} of {TextElementBase.TotalPagesToken}");

        doc.Metadata.Title = $"Services agreement {Reference}";
        doc.Metadata.Author = Supplier;
        doc.Metadata.Subject = "A services agreement with a visible PAdES digital signature (sample document, not legal advice).";
        doc.Metadata.Keywords = "agreement, contract, digital signature, pades";

        doc.Add(new Container { BackgroundColor = Accent, Height = 4, Margin = new Thickness(0, 0, 0, 14) });
        doc.Add(Cell("SERVICES AGREEMENT", size: 8.5f, bold: true, color: Accent, marginBottom: 4f));
        doc.Add(H1($"Agreement {Reference}"));
        doc.Add(Cell($"Effective {GbDate(Effective)} · {Months}-month initial term", color: Muted, marginBottom: 14f));

        doc.Add(WeightedRow(
            new IElement[]
            {
                Party("Supplier", Prepend(Supplier, SupplierAddress)),
                Party("Customer", Prepend(Customer, CustomerAddress)),
            },
            spacing: 20f,
            marginBottom: 6f));
        doc.Add(WeightedRow(
            new IElement[]
            {
                Tile(Money(Fee), "Fee per month"),
                Tile(Money(Fee * Months), "Initial term total"),
                Tile($"{PaymentDays} days", "Payment terms"),
                Tile($"{NoticeDays} days", "Notice to end"),
            },
            spacing: 10f,
            marginBottom: 6f));

        doc.Add(H2("Agreed terms"));
        Clause[] clauses = Clauses();
        for (int c = 0; c < clauses.Length; c++)
        {
            doc.Add(ClauseHeading(c + 1, clauses[c].Title));
            for (int i = 0; i < clauses[c].Items.Length; i++)
            {
                doc.Add(SubClause($"{c + 1}.{i + 1}", clauses[c].Items[i]));
            }
        }

        doc.Add(H2("Signatures"));
        doc.Add(Cell("The supplier has signed digitally in the box below. The customer signs on receipt.", size: 9f, color: Muted, marginBottom: 8f));

        // The box the signature will cover. It is named so the layout can report where it landed.
        Container box = new Container { BackgroundColor = ColorPalette.Slate[50], Height = 78 };
        box.CaptureName = SignatureSlot;
        VerticalStack left = new VerticalStack();
        left.Add(Cell("SUPPLIER · SIGNED DIGITALLY", size: 6.5f, bold: true, color: Muted, marginBottom: 4f));
        left.Add(box);
        VerticalStack right = new VerticalStack();
        right.Add(Cell("CUSTOMER", size: 6.5f, bold: true, color: Muted, marginBottom: 4f));
        right.Add(new Container { Height = 62 });
        right.Add(new Container { BackgroundColor = Rule, Height = 0.75f, Margin = new Thickness(0, 0, 0, 5) });
        right.Add(Cell("Name, position and date", size: 8f, color: Muted));
        doc.Add(WeightedRow(new IElement[] { left, right }, spacing: 22f, marginBottom: 8f));

        Table terms = new Table(2f, 5f)
        {
            CellPadding = 6,
            Border = new Border(0.5f),
            BorderColors = new BorderColors(Rule),
            HeaderBackgroundColor = Accent,
            HeaderTextColor = Color.White,
        };
        terms.AddHeader(Th("If you change this document"), Th("What happens"));
        terms.AddRow(Td("Anything after it was signed", bold: true), Td("The signature no longer matches and a viewer reports it as broken."));
        terms.AddRow(Td("Opening it in a viewer", bold: true), Td("The signature is checked against the signer's certificate and the time it was made."));
        doc.Add(terms);

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

    private static string[] Prepend(string first, string[] rest)
    {
        var all = new string[rest.Length + 1];
        all[0] = first;
        Array.Copy(rest, 0, all, 1, rest.Length);
        return all;
    }

    /// <summary>Pence as pounds: £1,234.56.</summary>
    private static string Money(int pence)
    {
        string whole = (pence / 100).ToString("N0", CultureInfo.InvariantCulture);
        string rest = (pence % 100).ToString("D2", CultureInfo.InvariantCulture);
        return $"£{whole}.{rest}";
    }

    private static Heading ClauseHeading(int number, string title) => new Heading($"{number}. {title}")
    {
        Level = 3,
        FontName = StandardFonts.HelveticaBold,
        FontSize = 10.5f,
        Color = Heading,
        Margin = new Thickness(0, 8, 0, 4),
    };

    /// <summary>A numbered sub-clause: the number hangs in its own column so wrapped lines align with the text.</summary>
    private static HorizontalStack SubClause(string number, string text)
    {
        HorizontalStack row = new HorizontalStack
        {
            WidthDistribution = WidthDistribution.Weighted,
            Spacing = 6,
            Margin = new Thickness(0, 0, 0, 4),
        };
        row.Add(Cell(number, size: 9f, color: Muted), 0.5f);
        row.Add(Cell(text, size: 9f), 9f);
        return row;
    }

    private static readonly Color Ink = ColorPalette.Slate[700];
    private static readonly Color Muted = ColorPalette.Slate[600];
    private static readonly Color Heading = ColorPalette.Slate[800];
    private static readonly Color Accent = ColorPalette.Indigo[700];
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

    private static TextBlock Td(string text, bool bold = false) => Cell(text, size: 8.5f, bold: bold);

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

    private static Container Tile(string value, string label)
    {
        VerticalStack body = new VerticalStack();
        body.Add(Cell(value, size: 14f, bold: true, color: Accent, marginBottom: 2f));
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
