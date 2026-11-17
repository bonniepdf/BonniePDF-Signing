using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Timestamp;

namespace BonniePDF.Signing.Cms;

/// <summary>
/// Builds the detached CMS <c>SignedData</c> envelope embedded in the PDF
/// <c>/Contents</c>, using the platform <see cref="SignedCms"/>. Adds the
/// signed attributes (signing-time, and for PAdES the ESS
/// signing-certificate-v2) and, when requested, an RFC 3161 signature
/// timestamp as an unsigned attribute (PAdES B-T).
/// </summary>
internal static class CmsBuilder
{
    private const string DataContentTypeOid = "1.2.840.113549.1.7.1";

    public static async Task<byte[]> BuildAsync(
        byte[] signedContent, X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain,
        SignatureSettings settings, CancellationToken ct)
    {
        var contentInfo = new ContentInfo(new Oid(DataContentTypeOid), signedContent);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert)
        {
            DigestAlgorithm = new Oid(SigningAlgorithmInfo.DigestOid(settings.Algorithm)),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };

        // Signed attributes. SignedCms adds contentType + messageDigest itself.
        DateTime signingTime = (settings.SigningTime ?? DateTimeOffset.UtcNow).UtcDateTime;
        signer.SignedAttributes.Add(new Pkcs9SigningTime(signingTime));
        if (settings.IsPades) signer.SignedAttributes.Add(SigningCertificateV2.Build(cert));

        foreach (X509Certificate2 c in chain) signer.Certificates.Add(c);

        var cms = new SignedCms(contentInfo, detached: true);
        cms.ComputeSignature(signer, silent: true);

        if (settings.WantsTimestamp)
        {
            HashAlgorithmName hashName = SigningAlgorithmInfo.HashName(settings.Algorithm);
            byte[] signatureValue = cms.SignerInfos[0].GetSignature();
            byte[] token = await Rfc3161Client.GetTokenAsync(signatureValue, hashName, settings, ct).ConfigureAwait(false);
            cms.SignerInfos[0].AddUnsignedAttribute(new AsnEncodedData(new Oid(Rfc3161Client.SignatureTimeStampOid), token));
        }

        return cms.Encode();
    }
}
