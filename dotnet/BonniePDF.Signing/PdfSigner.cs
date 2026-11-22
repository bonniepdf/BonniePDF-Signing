using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Cms;
using BonniePDF.Signing.Pdf;
using BonniePDF.Signing.Validation;

namespace BonniePDF.Signing;

/// <summary>
/// Signs a BonniePDF-generated PDF by appending a signature revision (a minimal
/// incremental update). Supports invisible and visible signatures, the PAdES
/// baseline profiles B-B, B-T, B-LT and B-LTA, RFC 3161 timestamps, and the
/// long-term validation material and document timestamps the archival levels
/// carry.
///
/// The signer operates on the finished <c>byte[]</c> output of
/// <c>Document.GenerateBytes()</c> / <c>GenerateBytesAsync()</c>; it has no
/// dependency on the core library and does not modify it.
/// </summary>
public static class PdfSigner
{
    /// <summary>
    /// Sign synchronously. Throws if a timestamp is configured (timestamping
    /// needs network I/O - use <see cref="SignAsync"/> for PAdES B-T and above).
    /// </summary>
    public static byte[] Sign(byte[] pdfBytes, SignatureSettings settings)
    {
        if (settings == null) throw new ArgumentNullException(nameof(settings));
        if (settings.WantsTimestamp)
        {
            throw new InvalidOperationException("Timestamping requires SignAsync (network I/O).");
        }
        return SignCoreAsync(pdfBytes, settings, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <summary>Sign asynchronously. Required when an RFC 3161 timestamp is configured.</summary>
    public static Task<byte[]> SignAsync(byte[] pdfBytes, SignatureSettings settings, CancellationToken cancellationToken = default)
    {
        if (settings == null) throw new ArgumentNullException(nameof(settings));
        return SignCoreAsync(pdfBytes, settings, cancellationToken);
    }

    private static async Task<byte[]> SignCoreAsync(byte[] pdfBytes, SignatureSettings settings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (pdfBytes == null || pdfBytes.Length == 0) throw new ArgumentException("pdfBytes is empty", nameof(pdfBytes));
        settings.Validate();

        using X509Certificate2 cert = CertificateLoader.Load(settings);
        List<X509Certificate2> chain = CertificateLoader.LoadChain(settings);
        try
        {
            DateTimeOffset signingTime = settings.SigningTime ?? DateTimeOffset.UtcNow;
            string subFilter = settings.IsPades ? "ETSI.CAdES.detached" : "adbe.pkcs7.detached";

            // Visible appearance (optional).
            PdfIncrementalUpdate.VisibleSignature visible = null;
            if (settings.Appearance != null)
            {
                double[] rect = settings.Appearance.Rect
                    ?? throw new ArgumentException("Appearance.Rect is required for a visible signature.");
                IReadOnlyList<string> lines = settings.Appearance.Text ?? DefaultAppearanceLines(settings, signingTime);
                string content = AppearanceBuilder.BuildStream(rect[2], rect[3], lines, settings.Appearance.FontSize, settings.Appearance.Border);
                visible = new PdfIncrementalUpdate.VisibleSignature { Rect = rect, ContentStream = content };
            }

            // 1. Append the signature revision with placeholders.
            PdfIncrementalUpdate.PdfInfo info = PdfIncrementalUpdate.ParsePdf(pdfBytes, settings.Appearance?.Page ?? 0);
            byte[] withPlaceholders = PdfIncrementalUpdate.BuildIncrementalUpdate(
                pdfBytes, info,
                new PdfIncrementalUpdate.SignatureDictMeta
                {
                    Reason = settings.Reason,
                    Location = settings.Location,
                    ContactInfo = settings.ContactInfo,
                    Name = settings.Name,
                    SigningTime = signingTime,
                    SubFilter = subFilter,
                },
                visible);

            // 2. Patch /ByteRange and extract the signed spans.
            PdfIncrementalUpdate.ByteRangeResult br = PdfIncrementalUpdate.PatchByteRange(withPlaceholders);

            // 3. Build the detached CMS envelope (with optional timestamp).
            CmsBuilder.CmsResult cms = await CmsBuilder.BuildAsync(br.Signed, cert, chain, settings, signingTime, ct).ConfigureAwait(false);

            // 4. Inject the CMS into /Contents.
            PdfIncrementalUpdate.InjectContents(withPlaceholders, br.ContentsStart, br.ContentsEnd, cms.Cms);

            if (!settings.IsLongTerm) return withPlaceholders;

            // 5. B-LT: append the validation material as a Document Security
            // Store, in its own revision so the signature's byte range is
            // untouched and stays valid.
            var chainDer = new List<byte[]>(chain.Count);
            foreach (X509Certificate2 c in chain) chainDer.Add(c.RawData);

            ValidationMaterial material = await ValidationMaterialCollector.CollectAsync(
                cert.RawData, chainDer, settings.HttpClient, settings.ValidationMaterial,
                settings.FetchRevocation, cms.TimestampToken, ct).ConfigureAwait(false);
            settings.OnValidationMaterial?.Invoke(material);

            // The /VRI key names the signature by the value of its /Contents
            // string - the decoded bytes, zero padding included - which is
            // exactly the span just written.
            byte[] contents = Convert.FromHexString(Encoding.Latin1.GetString(
                withPlaceholders, br.ContentsStart + 1, br.ContentsEnd - br.ContentsStart - 2));

            byte[] result = DssBuilder.Append(
                withPlaceholders, material, contents, signingTime,
                PdfIncrementalUpdate.NeedsEsicExtension(pdfBytes));

            if (settings.PadesLevel != PadesLevel.BLTA) return result;

            // 6. B-LTA: a document timestamp over everything above, DSS included.
            return await DocumentTimestamp.AppendAsync(
                result,
                settings.DocumentTimestampUrl ?? settings.TimestampUrl,
                SigningAlgorithmInfo.HashName(settings.Algorithm),
                settings.HttpClient,
                settings.Appearance?.Page ?? 0,
                ct).ConfigureAwait(false);
        }
        finally
        {
            foreach (X509Certificate2 c in chain) c.Dispose();
        }
    }

    private static IReadOnlyList<string> DefaultAppearanceLines(SignatureSettings settings, DateTimeOffset signingTime)
    {
        var lines = new List<string> { $"Digitally signed by {settings.Name ?? "BonniePDF"}" };
        if (!string.IsNullOrEmpty(settings.Reason)) lines.Add($"Reason: {settings.Reason}");
        if (!string.IsNullOrEmpty(settings.Location)) lines.Add($"Location: {settings.Location}");
        lines.Add("Date: " + PdfIncrementalUpdate.PdfDate(signingTime).Replace("D:", string.Empty));
        return lines;
    }
}

/// <summary>Convenience extension methods mirroring the fluent style.</summary>
public static class PdfSignerExtensions
{
    /// <summary>Sign PDF bytes synchronously (no timestamp).</summary>
    public static byte[] SignPdf(this byte[] pdfBytes, SignatureSettings settings) => PdfSigner.Sign(pdfBytes, settings);

    /// <summary>Sign PDF bytes asynchronously.</summary>
    public static Task<byte[]> SignPdfAsync(this byte[] pdfBytes, SignatureSettings settings, CancellationToken cancellationToken = default) =>
        PdfSigner.SignAsync(pdfBytes, settings, cancellationToken);
}
