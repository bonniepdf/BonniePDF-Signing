using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Asn1;
using BonniePDF.Signing.Http;
using BonniePDF.Signing.Ocsp;

namespace BonniePDF.Signing.Validation;

/// <summary>
/// Gathering the validation material a PAdES B-LT signature carries: the
/// certificate chain, and revocation evidence for it.
/// </summary>
/// <remarks>
/// The point of long-term validation is that the document answers the question
/// on its own. A validator opening it in ten years should not need the issuing
/// CA to still be running an OCSP responder, or the certificate to still be
/// within its validity period - everything needed to conclude "this was good
/// when it was signed" travels inside the file.
/// <para>
/// Collection is best-effort by design. A responder that is down, a distribution
/// point that has moved, a certificate that publishes neither - none of these
/// should abort a signature that is otherwise perfectly valid. Each failure is
/// recorded and reported instead, so the caller can decide whether the material
/// gathered is enough for their policy.
/// </para>
/// </remarks>
internal static class ValidationMaterialCollector
{
    /// <summary>
    /// Collect the validation material for a certificate chain.
    /// </summary>
    /// <remarks>
    /// Walks leaf-to-root: for each certificate that has an issuer available,
    /// asks that certificate's OCSP responder, and falls back to its CRL
    /// distribution point when no responder is listed or the responder cannot be
    /// reached. The root is not checked - nothing revokes a trust anchor.
    /// </remarks>
    public static async Task<ValidationMaterial> CollectAsync(
        byte[] certDer,
        IReadOnlyList<byte[]> chainDer,
        SigningHttpClient httpClient,
        SuppliedValidationMaterial supplied,
        bool fetchRevocation,
        CancellationToken ct)
        => await CollectAsync(certDer, chainDer, httpClient, supplied, fetchRevocation, null, ct)
            .ConfigureAwait(false);

    /// <inheritdoc cref="CollectAsync(byte[], IReadOnlyList{byte[]}, SigningHttpClient, SuppliedValidationMaterial, bool, CancellationToken)"/>
    /// <param name="timestampToken">
    /// The RFC 3161 token embedded in the signature, if any. Its certificates
    /// are added to the material and their revocation is collected too: a
    /// long-term signature has to let a validator check the timestamp as well as
    /// the signature, and without the authority's own evidence the document
    /// falls short of the LT level even though everything else is present.
    /// </param>
    public static async Task<ValidationMaterial> CollectAsync(
        byte[] certDer,
        IReadOnlyList<byte[]> chainDer,
        SigningHttpClient httpClient,
        SuppliedValidationMaterial supplied,
        bool fetchRevocation,
        byte[] timestampToken,
        CancellationToken ct)
    {
        var material = new ValidationMaterial();
        material.Certificates.Add(certDer);
        material.Certificates.AddRange(chainDer);
        if (supplied?.Certificates is not null) material.Certificates.AddRange(supplied.Certificates);
        if (supplied?.OcspResponses is not null) material.OcspResponses.AddRange(supplied.OcspResponses);
        if (supplied?.Crls is not null) material.Crls.AddRange(supplied.Crls);

        if (!fetchRevocation) return material;

        var chain = new List<byte[]> { certDer };
        chain.AddRange(chainDer);

        for (int i = 0; i < chain.Count; i++)
        {
            if (i + 1 >= chain.Count)
            {
                // The last certificate in the chain is the trust anchor. Nothing
                // revokes a trust anchor - a validator decides whether to trust
                // it, and there is no issuer above it to ask - so it is not
                // evidence we can or should gather. Stopping here is what keeps
                // Problems meaningful: a root with no AIA is normal, not a
                // shortfall worth reporting.
                break;
            }
            await CollectForAsync(chain[i], chain[i + 1], material, httpClient, i, ct).ConfigureAwait(false);
        }

        await CollectForTimestampAsync(timestampToken, chain, material, httpClient, ct).ConfigureAwait(false);

        return material;
    }

    /// <summary>
    /// Add the timestamp authority's certificates and collect revocation for
    /// them, so a validator can check the timestamp from inside the document.
    /// </summary>
    /// <remarks>
    /// The authority's certificates travel inside the token, so they are read
    /// from there rather than supplied by the caller. Their issuer is looked for
    /// among the certificates already gathered - in practice the same CA - and
    /// where it cannot be found the certificate is still embedded, because a
    /// validator that has the certificate and no revocation for it is better off
    /// than one missing both.
    /// </remarks>
    private static async Task CollectForTimestampAsync(
        byte[] timestampToken, IReadOnlyList<byte[]> known, ValidationMaterial material,
        SigningHttpClient httpClient, CancellationToken ct)
    {
        if (timestampToken is null || timestampToken.Length == 0) return;

        // A token we cannot read and a token carrying no certificates are the
        // same thing to a caller - in both cases the authority's own evidence is
        // missing - so they report identically, as the TypeScript port does.
        var tsaCerts = new List<byte[]>();
        try
        {
            var cms = new SignedCms();
            cms.Decode(timestampToken);
            foreach (X509Certificate2 c in cms.Certificates) tsaCerts.Add(c.RawData);
        }
        catch (CryptographicException)
        {
            tsaCerts.Clear();
        }

        if (tsaCerts.Count == 0)
        {
            material.Problems.Add("timestamp token: carries no certificates for the authority");
            return;
        }

        for (int i = 0; i < tsaCerts.Count; i++)
        {
            byte[] tsaCert = tsaCerts[i];
            if (!Contains(material.Certificates, tsaCert)) material.Certificates.Add(tsaCert);

            byte[] issuer = FindIssuer(tsaCert, known) ?? FindIssuer(tsaCert, tsaCerts);
            if (issuer is null || Equal(issuer, tsaCert))
            {
                // Self-signed, or an issuer we do not hold: nothing to ask about.
                continue;
            }
            await CollectForAsync(tsaCert, issuer, material, httpClient, -(i + 1), ct).ConfigureAwait(false);
        }
    }

    /// <summary>The certificate in <paramref name="pool"/> that issued <paramref name="cert"/>.</summary>
    private static byte[] FindIssuer(byte[] cert, IReadOnlyList<byte[]> pool)
    {
        byte[] issuerName;
        try
        {
            issuerName = Asn1.CertificateExtensions.ExtractIssuerName(cert);
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        foreach (byte[] candidate in pool)
        {
            try
            {
                if (Equal(Asn1.CertificateExtensions.ExtractSubject(candidate), issuerName)) return candidate;
            }
            catch (InvalidOperationException)
            {
                // Not a certificate we can read; skip it.
            }
        }
        return null;
    }

    private static bool Contains(IReadOnlyList<byte[]> list, byte[] value)
    {
        foreach (byte[] item in list)
        {
            if (Equal(item, value)) return true;
        }
        return false;
    }

    private static bool Equal(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    private static async Task CollectForAsync(
        byte[] subject, byte[] issuer, ValidationMaterial material,
        SigningHttpClient httpClient, int index, CancellationToken ct)
    {
        List<string> responders = CertificateExtensions.OcspUrls(subject);
        foreach (string url in responders)
        {
            try
            {
                material.OcspResponses.Add(
                    await OcspClient.RequestAsync(url, subject, issuer, httpClient, ct).ConfigureAwait(false));
                return;
            }
            catch (Exception e) when (IsCollectionFailure(e, ct))
            {
                material.Problems.Add($"certificate {index}: OCSP at {url} failed - {e.Message}");
            }
        }

        await CollectCrlAsync(subject, material, httpClient, index, responders.Count > 0, ct).ConfigureAwait(false);
    }

    private static async Task CollectCrlAsync(
        byte[] subject, ValidationMaterial material, SigningHttpClient httpClient,
        int index, bool afterOcspFailure, CancellationToken ct)
    {
        List<string> urls = CertificateExtensions.CrlUrls(subject);
        if (urls.Count == 0)
        {
            if (!afterOcspFailure)
            {
                material.Problems.Add(
                    $"certificate {index}: publishes no OCSP responder and no CRL distribution point");
            }
            return;
        }

        foreach (string url in urls)
        {
            try
            {
                material.Crls.Add(await CrlClient.FetchAsync(url, httpClient, ct).ConfigureAwait(false));
                return;
            }
            catch (Exception e) when (IsCollectionFailure(e, ct))
            {
                material.Problems.Add($"certificate {index}: CRL at {url} failed - {e.Message}");
            }
        }
    }

    /// <summary>
    /// Fetch the issuer certificate a certificate's AIA caIssuers entry points at.
    /// </summary>
    /// <remarks>
    /// Offered separately rather than folded into collection: completing a chain
    /// the caller did not supply changes which certificates the document vouches
    /// for, and that should be an explicit act.
    /// </remarks>
    public static async Task<byte[]> FetchIssuerCertificateAsync(
        byte[] certDer, SigningHttpClient httpClient, CancellationToken ct)
    {
        foreach (string url in CertificateExtensions.CaIssuerUrls(certDer))
        {
            try
            {
                byte[] body = await SigningHttp.FetchAsync(
                    httpClient,
                    new SigningHttpRequest { Url = url, Method = HttpMethod.Get, Accept = "application/pkix-cert" },
                    "issuer certificate download",
                    ct).ConfigureAwait(false);
                if (body.Length > 0 && body[0] == 0x30) return body;
            }
            catch (Exception e) when (IsCollectionFailure(e, ct))
            {
                // Try the next URL; a partial failure here tells the caller nothing useful.
            }
        }
        return null;
    }

    /// <summary>
    /// Failures that mean "this evidence could not be gathered".
    /// </summary>
    /// <remarks>
    /// Deliberately narrow. A cancellation is a failure to collect only when the
    /// caller did not ask for it: <see cref="HttpClient"/> reports its own
    /// timeout as a <see cref="TaskCanceledException"/>, and a responder that
    /// never answers is exactly the kind of failure collection records rather
    /// than throws. When <paramref name="ct"/> has been cancelled it is the caller
    /// asking us to stop, and swallowing that would let signing carry on after a
    /// cancellation.
    /// </remarks>
    private static bool IsCollectionFailure(Exception e, CancellationToken ct)
    {
        if (e is OperationCanceledException) return !ct.IsCancellationRequested;
        return e is HttpRequestException or CryptographicException or InvalidOperationException or FormatException;
    }
}
