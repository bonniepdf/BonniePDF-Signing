#nullable disable
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Http;
using BonniePDF.Signing.TestSupport;

namespace BonniePDF.Signing.SampleGen.Demos;

/// <summary>
/// A throwaway public-key infrastructure for the signed demos: a certificate
/// authority, signers, an OCSP responder and an RFC 3161 time-stamp authority,
/// all built in-process and discarded when the run ends.
///
/// The package never ships a private key, so the demos make their own. Nothing
/// here is how you sign in production: there you hold a certificate issued by a
/// real authority (PEM or PKCS#12) and point <c>TimestampUrl</c> at a real
/// time-stamp authority. The demos use this so they run anywhere, offline, and
/// so a validator that trusts only the printed CA certificate can check them.
/// </summary>
internal sealed class DemoPki : IDisposable
{
    public const string OcspUrl = "http://ocsp.test.invalid/ocsp";
    public const string CrlUrl = "http://crl.test.invalid/ca.crl";
    public const string TsaUrl = "http://tsa.test.invalid/tsr";

    private readonly TestPki.Identity _tsaIdentity;
    private readonly TestPki.TestTsa _tsa;
    private readonly TestPki.TestOcspResponder _ocsp;
    private readonly List<TestPki.Identity> _issued = new List<TestPki.Identity>();

    public DemoPki()
    {
        Ca = TestPki.IssueCa("BonniePDF Test CA");

        // RFC 3161 section 2.3 requires the critical id-kp-timeStamping extended key usage.
        // The AIA matters just as much: without revocation information for the
        // authority's own certificate a long-term signature cannot reach LT.
        var timeStamping = new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") }, critical: true);
        _tsaIdentity = TestPki.Issue("BonniePDF Test TSA", Ca, timeStamping, TestPki.AiaOcsp(OcspUrl));
        _tsa = new TestPki.TestTsa(_tsaIdentity);
        _ocsp = new TestPki.TestOcspResponder(Ca);
    }

    /// <summary>The certificate authority. Trust this certificate to validate the demos.</summary>
    public TestPki.Identity Ca { get; }

    /// <summary>Issues a signer certificate from the authority, with OCSP and CRL locations.</summary>
    public TestPki.Identity IssueSigner(string commonName)
    {
        TestPki.Identity signer = TestPki.Issue(
            commonName, Ca, TestPki.AiaOcsp(OcspUrl), TestPki.CrlDistributionPoint(CrlUrl));
        _issued.Add(signer);
        return signer;
    }

    /// <summary>Answers the OCSP and time-stamp URLs above in-process, so signing needs no network.</summary>
    public Task<SigningHttpResponse> Transport(SigningHttpRequest request, CancellationToken ct)
    {
        if (string.Equals(request.Url, TsaUrl, StringComparison.Ordinal))
            return Task.FromResult(new SigningHttpResponse { Status = 200, Body = _tsa.Respond(request.Body) });
        if (string.Equals(request.Url, OcspUrl, StringComparison.Ordinal))
            return Task.FromResult(new SigningHttpResponse { Status = 200, Body = _ocsp.Respond(request.Body) });
        return Task.FromResult(new SigningHttpResponse { Status = 404, Body = new byte[0] });
    }

    public void Dispose()
    {
        foreach (TestPki.Identity signer in _issued) signer.Dispose();
        _tsaIdentity.Dispose();
        Ca.Dispose();
    }
}
