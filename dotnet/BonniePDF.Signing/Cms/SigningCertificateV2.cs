using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BonniePDF.Signing.Cms;

/// <summary>
/// Builds the ESS <c>signing-certificate-v2</c> signed attribute (RFC 5035)
/// required by the CAdES / PAdES baseline to bind the signature to a specific
/// signer certificate.
///
/// <code>
/// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
/// ESSCertIDv2 ::= SEQUENCE { hashAlgorithm [DEFAULT sha256], certHash OCTET STRING, ... }
/// </code>
/// The certHash is the SHA-256 digest of the DER certificate; since SHA-256 is
/// the DEFAULT hashAlgorithm it is omitted (DER omits defaults). All lengths are
/// well under 128, so short-form DER lengths suffice and the structure is built
/// by hand (no <c>System.Formats.Asn1</c> dependency).
/// </summary>
internal static class SigningCertificateV2
{
    public const string Oid = "1.2.840.113549.1.9.16.2.47";

    public static AsnEncodedData Build(X509Certificate2 cert)
    {
        byte[] certHash = SHA256.HashData(cert.RawData); // 32 bytes
        byte[] octet = Tlv(0x04, certHash);              // certHash OCTET STRING
        byte[] essCertId = Tlv(0x30, octet);             // ESSCertIDv2 SEQUENCE
        byte[] seqOf = Tlv(0x30, essCertId);             // SEQUENCE OF ESSCertIDv2
        byte[] signingCert = Tlv(0x30, seqOf);           // SigningCertificateV2 SEQUENCE
        return new AsnEncodedData(new Oid(Oid), signingCert);
    }

    /// <summary>Short-form DER tag-length-value (values are always &lt; 128 bytes here).</summary>
    private static byte[] Tlv(byte tag, byte[] value)
    {
        if (value.Length >= 0x80) throw new InvalidOperationException("unexpected long-form length");
        var result = new byte[2 + value.Length];
        result[0] = tag;
        result[1] = (byte)value.Length;
        Buffer.BlockCopy(value, 0, result, 2, value.Length);
        return result;
    }
}
