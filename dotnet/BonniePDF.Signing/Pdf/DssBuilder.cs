using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BonniePDF.Signing.Validation;

namespace BonniePDF.Signing.Pdf;

/// <summary>
/// The Document Security Store: where a PAdES B-LT signature keeps the evidence
/// that makes it verifiable long after the certificates involved have expired.
/// </summary>
/// <remarks>
/// Structurally it is a dictionary hung off the catalog, holding three arrays of
/// streams - certificates, OCSP responses, CRLs - plus an optional
/// per-signature index (/VRI) that says which of them belong to which signature.
/// It is written as its own incremental revision, appended after the signature
/// it describes, so the signature's own byte range is untouched and stays valid.
/// <para>See ETSI EN 319 142-1 §5.4 and ISO 32000-2 §12.8.4.3.</para>
/// </remarks>
internal static class DssBuilder
{
    /// <summary>
    /// The /VRI key for a signature: the uppercase base-16 SHA-1 of the bytes of
    /// its /Contents entry (ETSI EN 319 142-1 §5.4.2).
    /// </summary>
    /// <remarks>
    /// The hash covers the /Contents octet string as written, padding included -
    /// that string is what the key names, and a validator recomputes it from the
    /// file in front of it rather than from the CMS it parsed out.
    /// </remarks>
    public static string VriKey(byte[] signatureContents) =>
        Convert.ToHexString(SHA1.HashData(signatureContents));

    /// <summary>Append the DSS revision to an already-signed document.</summary>
    public static byte[] Append(
        byte[] signed,
        ValidationMaterial material,
        byte[] signatureContents,
        DateTimeOffset time,
        bool declareEsicExtension)
    {
        PdfIncrementalUpdate.PdfInfo info = PdfIncrementalUpdate.ParsePdf(signed);

        int nextId = info.Size;
        var objects = new List<PdfIncrementalUpdate.RevisionObject>();

        List<string> StreamRefs(IReadOnlyList<byte[]> blobs)
        {
            var refs = new List<string>(blobs.Count);
            foreach (byte[] blob in blobs)
            {
                int id = ++nextId;
                objects.Add(new PdfIncrementalUpdate.RevisionObject
                {
                    Id = id,
                    Body = $"<< /Length {blob.Length.ToString(CultureInfo.InvariantCulture)} >>\n" +
                           $"stream\n{PdfIncrementalUpdate.Latin1Decode(blob)}\nendstream",
                });
                refs.Add($"{id} 0 R");
            }
            return refs;
        }

        List<string> certRefs = StreamRefs(material.Certificates);
        List<string> ocspRefs = StreamRefs(material.OcspResponses);
        List<string> crlRefs = StreamRefs(material.Crls);

        var entries = new List<string>();
        if (certRefs.Count > 0) entries.Add($"/Certs [{string.Join(" ", certRefs)}]");
        if (ocspRefs.Count > 0) entries.Add($"/OCSPs [{string.Join(" ", ocspRefs)}]");
        if (crlRefs.Count > 0) entries.Add($"/CRLs [{string.Join(" ", crlRefs)}]");

        if (signatureContents is not null)
        {
            int vriId = ++nextId;
            var vriEntry = new List<string>();
            if (certRefs.Count > 0) vriEntry.Add($"/Cert [{string.Join(" ", certRefs)}]");
            if (ocspRefs.Count > 0) vriEntry.Add($"/OCSP [{string.Join(" ", ocspRefs)}]");
            if (crlRefs.Count > 0) vriEntry.Add($"/CRL [{string.Join(" ", crlRefs)}]");
            vriEntry.Add($"/TU ({PdfIncrementalUpdate.PdfDate(time)})");

            objects.Add(new PdfIncrementalUpdate.RevisionObject
            {
                Id = vriId,
                Body = $"<< /{VriKey(signatureContents)} << {string.Join(" ", vriEntry)} >> >>",
            });
            entries.Add($"/VRI {vriId} 0 R");
        }

        int dssId = ++nextId;
        objects.Add(new PdfIncrementalUpdate.RevisionObject
        {
            Id = dssId,
            Body = $"<< {string.Join(" ", entries)} >>",
        });

        objects.Add(new PdfIncrementalUpdate.RevisionObject
        {
            Id = info.RootId,
            Body = "<<" + CatalogWithDss(info.CatalogBody, dssId, declareEsicExtension) + ">>",
        });

        return PdfIncrementalUpdate.AppendRevision(signed, objects, new PdfIncrementalUpdate.RevisionTrailer
        {
            RootId = info.RootId,
            NewSize = nextId + 1,
            PrevStartxref = info.PrevStartxref,
            IdArray = info.IdArray,
        });
    }

    /// <summary>
    /// Rewrite the catalog body with /DSS (and, where asked, /Extensions).
    /// </summary>
    /// <remarks>
    /// An existing /DSS is replaced rather than merged: this package writes the
    /// whole store in one go, and a second pass that appended to a store it did
    /// not write could leave a validator with two disagreeing indexes.
    /// </remarks>
    private static string CatalogWithDss(string catalogBody, int dssId, bool declareEsic)
    {
        string body = Regex.Replace(catalogBody, @"\s*/DSS\s+\d+\s+0\s+R", string.Empty);
        var added = new StringBuilder($"  /DSS {dssId} 0 R\n");

        if (declareEsic && !Regex.IsMatch(body, @"/Extensions\s*<<"))
        {
            // ETSI EN 319 142-1 §5.1: PAdES structures in a pre-2.0 file are
            // declared through the ESIC developer extension.
            added.Append("  /Extensions << /ESIC << /BaseVersion /1.7 /ExtensionLevel 1 >> >>\n");
        }

        return "\n" + added + body.TrimStart('\n');
    }
}
