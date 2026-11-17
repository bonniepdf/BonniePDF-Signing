using System;
using System.Collections.Generic;
using System.Text;

namespace BonniePDF.Signing.Asn1;

/// <summary>
/// The slice of X.509 extension parsing needed to find a certificate's
/// revocation information: where its OCSP responder lives, where its CRL is
/// published, and the issuer key hash an OCSP request has to carry.
/// </summary>
/// <remarks>
/// A reader of well-formed DER, not a validating parser - it deliberately does
/// no expiry, chain, or signature checking. Anything it cannot make sense of it
/// reports as absent rather than throwing, because a certificate without
/// revocation pointers is a normal thing to meet, not an error.
/// <para>
/// Hand-parsed rather than delegated to the platform's extension types, so that
/// the two implementations provably agree on what they read out of a given
/// certificate - the same choice the RFC 3161 client here already makes.
/// </para>
/// </remarks>
internal static class CertificateExtensions
{
    public const string AuthorityInfoAccessOid = "1.3.6.1.5.5.7.1.1";
    public const string CrlDistributionPointsOid = "2.5.29.31";
    public const string AccessMethodOcspOid = "1.3.6.1.5.5.7.48.1";
    public const string AccessMethodCaIssuersOid = "1.3.6.1.5.5.7.48.2";

    private const byte ContextConstructed0 = 0xa0;
    private const byte ContextConstructed3 = 0xa3;
    private const byte UniformResourceIdentifier = 0x86;

    /// <summary>TBSCertificate fields, and the index of the first after the optional [0] version.</summary>
    private static (List<Der.Node> Fields, int First) TbsFields(byte[] certDer)
    {
        Der.Node cert = Der.Read(certDer, 0);
        Der.Node tbs = Der.Children(certDer, cert)[0];
        List<Der.Node> fields = Der.Children(certDer, tbs);
        return (fields, fields.Count > 0 && fields[0].Tag == ContextConstructed0 ? 1 : 0);
    }

    /// <summary>Extensions as a map from OID to the extnValue OCTET STRING content.</summary>
    public static Dictionary<string, byte[]> Read(byte[] certDer)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        List<Der.Node> fields;
        try
        {
            (fields, _) = TbsFields(certDer);
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentOutOfRangeException or InvalidOperationException)
        {
            return result;
        }

        Der.Node? wrapper = null;
        foreach (Der.Node field in fields)
        {
            if (field.Tag == ContextConstructed3) wrapper = field;
        }
        if (wrapper is null) return result;

        List<Der.Node> outer = Der.Children(certDer, wrapper.Value);
        if (outer.Count == 0) return result;

        foreach (Der.Node extension in Der.Children(certDer, outer[0]))
        {
            List<Der.Node> parts = Der.Children(certDer, extension);
            if (parts.Count == 0 || parts[0].Tag != 0x06) continue;
            Der.Node value = parts[^1];
            if (value.Tag != 0x04) continue;
            result[Der.OidString(certDer, parts[0])] = Der.Content(certDer, value);
        }
        return result;
    }

    /// <summary>OCSP responder URLs from the AIA extension, in certificate order.</summary>
    public static List<string> OcspUrls(byte[] certDer) => AccessUrls(certDer, AccessMethodOcspOid);

    /// <summary>caIssuers URLs from the AIA extension - where to fetch the issuer certificate.</summary>
    public static List<string> CaIssuerUrls(byte[] certDer) => AccessUrls(certDer, AccessMethodCaIssuersOid);

    private static List<string> AccessUrls(byte[] certDer, string method)
    {
        var urls = new List<string>();
        if (!Read(certDer).TryGetValue(AuthorityInfoAccessOid, out byte[] value)) return urls;

        try
        {
            Der.Node sequence = Der.Read(value, 0);
            foreach (Der.Node description in Der.Children(value, sequence))
            {
                List<Der.Node> parts = Der.Children(value, description);
                if (parts.Count < 2 || parts[0].Tag != 0x06) continue;
                if (!string.Equals(Der.OidString(value, parts[0]), method, StringComparison.Ordinal)) continue;
                if (parts[1].Tag == UniformResourceIdentifier)
                {
                    urls.Add(Encoding.ASCII.GetString(Der.Content(value, parts[1])));
                }
            }
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return [];
        }
        return urls;
    }

    /// <summary>CRL distribution-point URLs, in certificate order.</summary>
    public static List<string> CrlUrls(byte[] certDer)
    {
        var urls = new List<string>();
        if (!Read(certDer).TryGetValue(CrlDistributionPointsOid, out byte[] value)) return urls;

        try
        {
            CollectUris(value, Der.Read(value, 0), urls);
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return [];
        }

        return urls.FindAll(u => u.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || u.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Collect every uniformResourceIdentifier ([6] IA5String) in a DER subtree.</summary>
    /// <remarks>
    /// Recursive because GeneralNames nest several levels deep inside a
    /// DistributionPoint and the exact depth varies between issuers.
    /// </remarks>
    private static void CollectUris(byte[] bytes, Der.Node parent, List<string> into)
    {
        foreach (Der.Node node in Der.Children(bytes, parent))
        {
            if (node.Tag == UniformResourceIdentifier)
            {
                into.Add(Encoding.ASCII.GetString(Der.Content(bytes, node)));
            }
            else if ((node.Tag & 0x20) != 0)
            {
                CollectUris(bytes, node, into);
            }
        }
    }

    /// <summary>The DER subject Name of a certificate, as a full TLV.</summary>
    public static byte[] ExtractSubject(byte[] certDer)
    {
        (List<Der.Node> fields, int first) = TbsFields(certDer);
        Der.Node subject = fields[first + 4];
        if (subject.Tag != 0x30) throw new InvalidOperationException("certificate: missing subject");
        return Der.NodeBytes(certDer, subject);
    }

    /// <summary>
    /// The raw public-key bits of a certificate's SubjectPublicKeyInfo - the BIT
    /// STRING content with its "unused bits" prefix byte removed.
    /// </summary>
    /// <remarks>
    /// This is what an OCSP CertID.issuerKeyHash is computed over (RFC 6960
    /// §4.1.1): the key itself, not the algorithm identifier wrapped around it.
    /// </remarks>
    public static byte[] ExtractPublicKeyBits(byte[] certDer)
    {
        (List<Der.Node> fields, int first) = TbsFields(certDer);
        Der.Node spki = fields[first + 5];
        if (spki.Tag != 0x30) throw new InvalidOperationException("certificate: missing subjectPublicKeyInfo");

        foreach (Der.Node part in Der.Children(certDer, spki))
        {
            if (part.Tag != 0x03) continue;
            // Skip the leading "unused bits" count, always 0 for a public key.
            var outp = new byte[part.ContentEnd - part.ContentStart - 1];
            Buffer.BlockCopy(certDer, part.ContentStart + 1, outp, 0, outp.Length);
            return outp;
        }
        throw new InvalidOperationException("certificate: subjectPublicKeyInfo has no key");
    }

    /// <summary>The DER issuer Name of a certificate, as a full TLV.</summary>
    public static byte[] ExtractIssuerName(byte[] certDer)
    {
        (List<Der.Node> fields, int first) = TbsFields(certDer);
        Der.Node issuer = fields[first + 2];
        if (issuer.Tag != 0x30) throw new InvalidOperationException("certificate: missing issuer");
        return Der.NodeBytes(certDer, issuer);
    }

    /// <summary>The DER serialNumber INTEGER of a certificate, as a full TLV.</summary>
    public static byte[] ExtractSerialNumber(byte[] certDer)
    {
        (List<Der.Node> fields, int first) = TbsFields(certDer);
        Der.Node serial = fields[first];
        if (serial.Tag != 0x02) throw new InvalidOperationException("certificate: missing serialNumber");
        return Der.NodeBytes(certDer, serial);
    }
}
