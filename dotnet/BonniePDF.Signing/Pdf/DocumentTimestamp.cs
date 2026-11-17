using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Http;
using BonniePDF.Signing.Timestamp;

namespace BonniePDF.Signing.Pdf;

/// <summary>
/// Document timestamps: the revision that turns a PAdES B-LT signature into
/// B-LTA.
/// </summary>
/// <remarks>
/// A signature timestamp proves when the <i>signature</i> was made. A document
/// timestamp proves when the <i>whole file, validation material included</i>,
/// looked the way it does - which is what lets the evidence in the Document
/// Security Store be trusted later, and what a fresh timestamp renews before the
/// previous one's algorithms age out.
/// <para>
/// Structurally it is a signature dictionary with no CMS signature in it: the
/// /Contents holds an RFC 3161 TimeStampToken directly, under
/// /SubFilter /ETSI.RFC3161 (ETSI EN 319 142-1 §5.4.3, ISO 32000-2 §12.8.5).
/// </para>
/// </remarks>
internal static class DocumentTimestamp
{
    /// <summary>
    /// Append a document timestamp revision covering everything written so far.
    /// </summary>
    /// <remarks>
    /// The imprint is taken over the document's whole byte range excluding only
    /// the /Contents placeholder, exactly as for a signature - so the token
    /// attests to the original document, every earlier signature, and the DSS in
    /// one go.
    /// </remarks>
    public static async Task<byte[]> AppendAsync(
        byte[] document,
        string timestampUrl,
        HashAlgorithmName hashName,
        SigningHttpClient httpClient,
        int page,
        CancellationToken ct)
    {
        PdfIncrementalUpdate.PdfInfo info = PdfIncrementalUpdate.ParsePdf(document, page);

        int nextId = info.Size;
        int timestampId = ++nextId;
        int widgetId = ++nextId;
        int acroFormId = ++nextId;

        // Carry forward the fields an earlier signature revision registered, so
        // the timestamp is added to the form rather than replacing what is there.
        int? existingAcroFormId = PdfIncrementalUpdate.ReadOptionalRef(info.CatalogBody, "/AcroForm");
        List<string> fields = existingAcroFormId is null
            ? []
            : PdfIncrementalUpdate.ReadRefArray(
                PdfIncrementalUpdate.ReadObjectBody(document, existingAcroFormId.Value), "/Fields");
        fields.Add($"{widgetId} 0 R");

        var objects = new List<PdfIncrementalUpdate.RevisionObject>
        {
            new()
            {
                Id = timestampId,
                Body = string.Join("\n",
                    "<<",
                    "  /Type /DocTimeStamp",
                    "  /Filter /Adobe.PPKLite",
                    "  /SubFilter /ETSI.RFC3161",
                    $"  /ByteRange {PdfIncrementalUpdate.ByteRangePlaceholder}",
                    $"  /Contents <{new string('0', PdfIncrementalUpdate.SignatureHexLength)}>",
                    ">>"),
            },
            new()
            {
                Id = widgetId,
                Body = "<<\n  /Type /Annot\n  /Subtype /Widget\n  /FT /Sig\n  /Rect [0 0 0 0]\n" +
                       $"  /V {timestampId} 0 R\n  /T (Timestamp{fields.Count})\n  /F 132\n" +
                       $"  /P {info.TargetPageId} 0 R\n>>",
            },
            new()
            {
                Id = acroFormId,
                Body = $"<<\n  /Fields [{string.Join(" ", fields)}]\n  /SigFlags 3\n>>",
            },
            new()
            {
                Id = info.RootId,
                Body = "<<" + CatalogWithAcroForm(info.CatalogBody, acroFormId) + ">>",
            },
            new()
            {
                Id = info.TargetPageId,
                Body = "<<" + PdfIncrementalUpdate.InjectAnnot(info.TargetPageBody, widgetId) + ">>",
            },
        };

        byte[] withPlaceholders = PdfIncrementalUpdate.AppendRevision(
            document,
            objects,
            new PdfIncrementalUpdate.RevisionTrailer
            {
                RootId = info.RootId,
                NewSize = nextId + 1,
                PrevStartxref = info.PrevStartxref,
                IdArray = info.IdArray,
            });

        PdfIncrementalUpdate.ByteRangeResult range = PdfIncrementalUpdate.PatchByteRange(withPlaceholders);
        byte[] token = await Rfc3161Client
            .GetTokenForDataAsync(range.Signed, hashName, timestampUrl, httpClient, ct)
            .ConfigureAwait(false);

        PdfIncrementalUpdate.InjectContents(withPlaceholders, range.ContentsStart, range.ContentsEnd, token);
        return withPlaceholders;
    }

    /// <summary>Point the catalog at the new AcroForm, replacing any earlier reference.</summary>
    private static string CatalogWithAcroForm(string catalogBody, int acroFormId)
    {
        string body = Regex.Replace(catalogBody, @"\s*/AcroForm\s+\d+\s+0\s+R", string.Empty);
        return $"\n  /AcroForm {acroFormId} 0 R\n" + body.TrimStart('\n');
    }
}
