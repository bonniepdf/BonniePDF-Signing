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

    /// <summary>The finished envelope, plus the timestamp token embedded in it.</summary>
    /// <remarks>
    /// The token is handed back because a long-term signature has to carry
    /// validation material for the timestamp authority as well as for the
    /// signer (ETSI EN 319 142-1 §5.5) - and the TSA's certificates arrive
    /// inside the token, not from the caller.
    /// </remarks>
    public sealed class CmsResult
    {
        public byte[] Cms { get; init; }

        /// <summary>The RFC 3161 token, or null when no timestamp was requested.</summary>
        public byte[] TimestampToken { get; init; }
    }

    /// <param name="signedContent">The signed byte range of the document.</param>
    /// <param name="cert">The signer certificate, with its private key.</param>
    /// <param name="chain">Further certificates to carry in the envelope.</param>
    /// <param name="settings">Algorithm, PAdES level and timestamp settings.</param>
    /// <param name="signingTime">
    /// The signing time the caller has already written into the signature
    /// dictionary's <c>/M</c>. Passed in rather than read from the clock here,
    /// so the CMS signing-time attribute cannot disagree with it.
    /// </param>
    /// <param name="ct">Cancels the timestamp request.</param>
    public static async Task<CmsResult> BuildAsync(
        byte[] signedContent, X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain,
        SignatureSettings settings, DateTimeOffset signingTime, CancellationToken ct)
    {
        var contentInfo = new ContentInfo(new Oid(DataContentTypeOid), signedContent);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert)
        {
            DigestAlgorithm = new Oid(SigningAlgorithmInfo.DigestOid(settings.Algorithm)),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };

        // Signed attributes. SignedCms adds contentType + messageDigest itself.
        //
        // signing-time is deliberately conditional. A legacy Adobe signature
        // carries it, and Acrobat reads it. PAdES does not: ETSI EN 319 142-1
        // lists the CMS signing-time attribute as "shall not be present",
        // because the signing time of a PAdES signature is the /M entry of the
        // signature dictionary. Emitting both leaves two claims that can
        // disagree, and a validator downgrades the signature out of the
        // baseline profile for it.
        if (!settings.IsPades)
        {
            signer.SignedAttributes.Add(new Pkcs9SigningTime(signingTime.UtcDateTime));
        }
        else
        {
            signer.SignedAttributes.Add(SigningCertificateV2.Build(cert));
        }

        foreach (X509Certificate2 c in chain) signer.Certificates.Add(c);

        var cms = new SignedCms(contentInfo, detached: true);
        cms.ComputeSignature(signer, silent: true);

        if (settings.WantsTimestamp)
        {
            HashAlgorithmName hashName = SigningAlgorithmInfo.HashName(settings.Algorithm);
            byte[] signatureValue = cms.SignerInfos[0].GetSignature();
            byte[] token = await Rfc3161Client.GetTokenAsync(signatureValue, hashName, settings, ct).ConfigureAwait(false);
            cms.SignerInfos[0].AddUnsignedAttribute(new AsnEncodedData(new Oid(Rfc3161Client.SignatureTimeStampOid), token));
            return new CmsResult { Cms = cms.Encode(), TimestampToken = token };
        }

        return new CmsResult { Cms = cms.Encode() };
    }
}
