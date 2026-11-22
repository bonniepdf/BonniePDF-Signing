using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF;
using BonniePDF.Signing;
using BonniePDF.Signing.Asn1;
using BonniePDF.Signing.Http;
using BonniePDF.Signing.Ocsp;
using BonniePDF.Signing.Pdf;
using BonniePDF.Signing.Validation;
using BonniePDF.Signing.TestSupport;
using Xunit;

namespace BonniePDF.Signing.Tests;

/// <summary>
/// PAdES long-term levels - B-LT (validation material in a Document Security
/// Store) and B-LTA (a document timestamp over the whole file, DSS included).
///
/// Everything here runs against the throwaway PKI in TestPki: a real CA, a real
/// OCSP responder and a real RFC 3161 authority, all generated in-process. No
/// network, and no committed key material.
///
/// Mirrors typescript/signing/tests/ltv.test.ts.
/// </summary>
public sealed class LtvTests : IDisposable
{
    private const string OcspUrl = "http://ocsp.test.invalid/ocsp";
    private const string CrlUrl = "http://crl.test.invalid/ca.crl";
    private const string TsaUrl = "http://tsa.test.invalid/tsr";

    private readonly TestPki.Identity _ca;
    private readonly TestPki.Identity _signer;
    private readonly TestPki.Identity _tsaIdentity;
    private readonly TestPki.TestTsa _tsa;
    private readonly TestPki.TestOcspResponder _ocsp;

    /// <summary>A stand-in CRL: any DER SEQUENCE will do, since the DSS stores it verbatim.</summary>
    private readonly byte[] _crlDer = Der.Sequence(Der.Sequence(Der.IntegerSmall(1)));

    public LtvTests()
    {
        _ca = TestPki.IssueCa("BonniePDF Test CA");
        _signer = TestPki.Issue(
            "BonniePDF Test Signer", _ca, TestPki.AiaOcsp(OcspUrl), TestPki.CrlDistributionPoint(CrlUrl));
        // A real TSA certificate publishes revocation information like any
        // other; without it a long-term signature cannot reach the LT level.
        _tsaIdentity = TestPki.Issue("BonniePDF Test TSA", _ca, TestPki.AiaOcsp(OcspUrl));
        _tsa = new TestPki.TestTsa(_tsaIdentity);
        _ocsp = new TestPki.TestOcspResponder(_ca);
    }

    public void Dispose()
    {
        _ca.Dispose();
        _signer.Dispose();
        _tsaIdentity.Dispose();
    }

    /// <summary>Routes the three protocols to the in-process authorities.</summary>
    private SigningHttpClient TestHttpClient(bool ocspFails = false, bool crlFails = false) =>
        (request, ct) =>
        {
            if (string.Equals(request.Url, TsaUrl, StringComparison.Ordinal))
            {
                return Task.FromResult(new SigningHttpResponse { Status = 200, Body = _tsa.Respond(request.Body) });
            }
            if (string.Equals(request.Url, OcspUrl, StringComparison.Ordinal))
            {
                return Task.FromResult(ocspFails
                    ? new SigningHttpResponse { Status = 503, Body = [] }
                    : new SigningHttpResponse { Status = 200, Body = _ocsp.Respond(request.Body) });
            }
            if (string.Equals(request.Url, CrlUrl, StringComparison.Ordinal))
            {
                return Task.FromResult(crlFails
                    ? new SigningHttpResponse { Status = 404, Body = [] }
                    : new SigningHttpResponse { Status = 200, Body = _crlDer });
            }
            return Task.FromResult(new SigningHttpResponse { Status = 404, Body = [] });
        };

    private static byte[] MakePdf()
    {
        var doc = new BonniePDF.Document();
        doc.Add(new TextBlock { Text = "Long-term validation test document.", FontSize = 12 });
        return doc.GenerateBytes();
    }

    private Task<byte[]> SignAsync(PadesLevel level, Action<SignatureSettings> configure = null)
    {
        var settings = new SignatureSettings
        {
            Algorithm = SigningAlgorithm.Sha256Rsa,
            CertificatePem = _signer.CertPem,
            PrivateKeyPem = _signer.KeyPem,
            CertificateChainPem = [_ca.CertPem],
            PadesLevel = level,
            TimestampUrl = TsaUrl,
            HttpClient = TestHttpClient(),
        };
        configure?.Invoke(settings);
        return PdfSigner.SignAsync(MakePdf(), settings);
    }

    /// <summary>The catalog dictionary body of the document's latest revision.</summary>
    private static string CatalogBody(byte[] bytes)
    {
        string text = PdfIncrementalUpdate.Latin1Decode(bytes);
        string trailer = text[text.LastIndexOf("trailer", StringComparison.Ordinal)..];
        int rootId = int.Parse(
            Regex.Match(trailer, @"/Root\s+(\d+)\s+0\s+R").Groups[1].Value, CultureInfo.InvariantCulture);
        return PdfIncrementalUpdate.ReadObjectBody(bytes, rootId);
    }

    /// <summary>The first <c>/ByteRange [a b c d]</c> at or after <paramref name="from"/>.</summary>
    private static int[] ByteRangeAfter(byte[] bytes, int from)
    {
        int index = PdfIncrementalUpdate.IndexOfAscii(bytes, "/ByteRange [", from);
        string text = PdfIncrementalUpdate.Latin1Decode(bytes[index..Math.Min(index + 80, bytes.Length)]);
        return Regex.Matches(text, @"\d+").Take(4)
            .Select(m => int.Parse(m.Value, CultureInfo.InvariantCulture)).ToArray();
    }

    // --- Certificate extensions drive collection ---

    [Fact]
    public void Extensions_ReadTheOcspResponderOutOfTheAiaExtension() =>
        Assert.Equal([OcspUrl], CertificateExtensions.OcspUrls(_signer.CertDer));

    [Fact]
    public void Extensions_ReadTheCrlDistributionPoint() =>
        Assert.Equal([CrlUrl], CertificateExtensions.CrlUrls(_signer.CertDer));

    [Fact]
    public void Extensions_ReportNoPointersForACertificateThatDeclaresNone()
    {
        Assert.Empty(CertificateExtensions.OcspUrls(_ca.CertDer));
        Assert.Empty(CertificateExtensions.CrlUrls(_ca.CertDer));
    }

    // --- OCSP ---

    [Fact]
    public void Ocsp_NamesTheIssuerByKeyHash()
    {
        byte[] request = OcspClient.BuildRequest(_signer.CertDer, _ca.CertDer);
        Der.Node root = Der.Read(request, 0);
        Der.Node tbs = Der.Children(request, root)[0];
        Der.Node list = Der.Children(request, tbs)[0];
        Der.Node first = Der.Children(request, list)[0];
        Der.Node certId = Der.Children(request, first)[0];
        List<Der.Node> parts = Der.Children(request, certId);

        byte[] expected = SHA1.HashData(CertificateExtensions.ExtractPublicKeyBits(_ca.CertDer));
        Assert.Equal(expected, Der.Content(request, parts[2]));
    }

    [Fact]
    public void Ocsp_AcceptsASuccessfulResponseAndReturnsItVerbatim()
    {
        byte[] response = _ocsp.Respond(OcspClient.BuildRequest(_signer.CertDer, _ca.CertDer));
        Assert.Equal(response, OcspClient.CheckResponse(response));
    }

    [Fact]
    public void Ocsp_RejectsAResponseTheResponderRefused()
    {
        byte[] refused = Der.Sequence(Der.Enumerated(6)); // unauthorized
        CryptographicException error = Assert.Throws<CryptographicException>(() => OcspClient.CheckResponse(refused));
        Assert.Contains("unauthorized", error.Message, StringComparison.Ordinal);
    }

    // --- CRL ---

    [Fact]
    public void Crl_PassesDerThroughUnchanged() => Assert.Equal(_crlDer, CrlClient.Normalize(_crlDer));

    [Fact]
    public void Crl_ConvertsAPemArmouredResponseToDer()
    {
        string pem = new(System.Security.Cryptography.PemEncoding.Write("X509 CRL", _crlDer));
        Assert.Equal(_crlDer, CrlClient.Normalize(Encoding.ASCII.GetBytes(pem)));
    }

    [Fact]
    public void Crl_RefusesAResponseThatIsNeither() =>
        Assert.Throws<CryptographicException>(() => CrlClient.Normalize([1, 2, 3]));

    // --- Collection ---

    [Fact]
    public async Task Collection_GathersTheChainAndAnOcspResponse()
    {
        int before = _ocsp.Requests;
        ValidationMaterial material = await ValidationMaterialCollector.CollectAsync(
            _signer.CertDer, [_ca.CertDer], TestHttpClient(), null, true, CancellationToken.None);

        Assert.Equal(2, material.Certificates.Count);
        Assert.Single(material.OcspResponses);
        Assert.Equal(before + 1, _ocsp.Requests);
    }

    [Fact]
    public async Task Collection_FallsBackToTheCrlWhenTheResponderIsUnreachable()
    {
        ValidationMaterial material = await ValidationMaterialCollector.CollectAsync(
            _signer.CertDer, [_ca.CertDer], TestHttpClient(ocspFails: true), null, true, CancellationToken.None);

        Assert.Empty(material.OcspResponses);
        Assert.Single(material.Crls);
        Assert.Contains(material.Problems, p => p.Contains("OCSP", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Collection_RecordsAProblemRatherThanThrowingWhenNothingIsReachable()
    {
        ValidationMaterial material = await ValidationMaterialCollector.CollectAsync(
            _signer.CertDer, [_ca.CertDer], TestHttpClient(ocspFails: true, crlFails: true),
            null, true, CancellationToken.None);

        Assert.Empty(material.OcspResponses);
        Assert.Empty(material.Crls);
        Assert.True(material.Problems.Count >= 2);
    }

    [Fact]
    public async Task Collection_RecordsAResponderTimeoutAsAProblem()
    {
        // HttpClient reports its own timeout as a TaskCanceledException. A
        // responder that never answers is a gap in the evidence, not a reason to
        // abandon the signature.
        SigningHttpClient timesOut = (_, _) =>
            throw new TaskCanceledException("timed out", new TimeoutException());

        ValidationMaterial material = await ValidationMaterialCollector.CollectAsync(
            _signer.CertDer, [_ca.CertDer], timesOut, null, true, CancellationToken.None);

        Assert.Empty(material.OcspResponses);
        Assert.Empty(material.Crls);
        Assert.True(material.Problems.Count >= 2);
    }

    [Fact]
    public async Task Collection_StillStopsWhenTheCallerCancels()
    {
        using var cts = new CancellationTokenSource();
        SigningHttpClient cancels = (_, ct) =>
        {
            cts.Cancel();
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new SigningHttpResponse());
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ValidationMaterialCollector.CollectAsync(
            _signer.CertDer, [_ca.CertDer], cancels, null, true, cts.Token));
    }

    [Fact]
    public async Task Collection_FetchesNothingWhenRevocationCollectionIsOff()
    {
        int before = _ocsp.Requests;
        ValidationMaterial material = await ValidationMaterialCollector.CollectAsync(
            _signer.CertDer, [_ca.CertDer], TestHttpClient(),
            new SuppliedValidationMaterial { Crls = [_crlDer] }, false, CancellationToken.None);

        Assert.Equal(before, _ocsp.Requests);
        Assert.Single(material.Crls);
        Assert.Empty(material.Problems);
    }

    [Fact]
    public async Task Collection_AlwaysIncludesWhatTheCallerSupplied()
    {
        byte[] extra = Der.Sequence(Der.IntegerSmall(7));
        ValidationMaterial material = await ValidationMaterialCollector.CollectAsync(
            _signer.CertDer, [_ca.CertDer], TestHttpClient(),
            new SuppliedValidationMaterial { Certificates = [extra] }, true, CancellationToken.None);

        Assert.Equal(3, material.Certificates.Count);
    }

    // --- B-LT ---

    [Fact]
    public async Task Blt_KeepsThePadesSubfilter()
    {
        byte[] signed = await SignAsync(PadesLevel.BLT);
        Assert.Contains("/SubFilter /ETSI.CAdES.detached",
            PdfIncrementalUpdate.Latin1Decode(signed), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Blt_AddsADssToTheCatalog()
    {
        byte[] signed = await SignAsync(PadesLevel.BLT);
        Assert.Matches(@"/DSS\s+\d+\s+0\s+R", CatalogBody(signed));
    }

    [Fact]
    public async Task Blt_StoresTheChainTheOcspResponseAndAVriIndex()
    {
        byte[] signed = await SignAsync(PadesLevel.BLT);
        int dssId = PdfIncrementalUpdate.ReadOptionalRef(CatalogBody(signed), "/DSS")!.Value;
        string dss = PdfIncrementalUpdate.ReadObjectBody(signed, dssId);

        Assert.Matches(@"/Certs\s*\[", dss);
        Assert.Matches(@"/OCSPs\s*\[", dss);
        Assert.Matches(@"/VRI\s+\d+\s+0\s+R", dss);
    }

    [Fact]
    public async Task Blt_KeysTheVriEntryByTheSha1OfTheDecodedSignatureContents()
    {
        byte[] signed = await SignAsync(PadesLevel.BLT);

        // A hex string's value is the bytes its digits denote, padding included,
        // and that is what a validator hashes to find the entry - not the digits.
        int tag = PdfIncrementalUpdate.IndexOfAscii(signed, "/Contents <");
        int open = PdfIncrementalUpdate.IndexOfAscii(signed, "<", tag);
        int close = PdfIncrementalUpdate.IndexOfAscii(signed, ">", open);
        byte[] value = Convert.FromHexString(Encoding.Latin1.GetString(signed[(open + 1)..close]));
        string expected = Convert.ToHexString(SHA1.HashData(value));

        int dssId = PdfIncrementalUpdate.ReadOptionalRef(CatalogBody(signed), "/DSS")!.Value;
        int vriId = PdfIncrementalUpdate.ReadOptionalRef(
            PdfIncrementalUpdate.ReadObjectBody(signed, dssId), "/VRI")!.Value;

        Assert.Contains("/" + expected,
            PdfIncrementalUpdate.ReadObjectBody(signed, vriId), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Blt_DeclaresTheEsicExtensionForAPre20Document()
    {
        byte[] signed = await SignAsync(PadesLevel.BLT);
        Assert.True(double.Parse(
            PdfIncrementalUpdate.PdfHeaderVersion(signed), CultureInfo.InvariantCulture) < 2);
        Assert.Contains("/ESIC", CatalogBody(signed), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Blt_AppendsTheDssAsANewRevisionLeavingTheSignedRangeIntact()
    {
        // The signature covers everything that existed when it was made. If the
        // DSS had been merged into that revision rather than appended after it,
        // the covered range would no longer end on the %%EOF that closed it -
        // and the signature would no longer verify.
        byte[] signed = await SignAsync(PadesLevel.BLT);
        int[] range = ByteRangeAfter(signed, 0);
        int end = range[2] + range[3];

        Assert.True(end < signed.Length);
        Assert.Equal("%%EOF", PdfIncrementalUpdate.Latin1Decode(signed[(end - 5)..end]));
        Assert.True(range[1] > 0);
    }

    [Fact]
    public async Task Blt_ReportsWhatItCollectedThroughTheCallback()
    {
        var seen = new List<ValidationMaterial>();
        await SignAsync(PadesLevel.BLT, s => s.OnValidationMaterial = seen.Add);

        ValidationMaterial material = Assert.Single(seen);
        // The root is a trust anchor, so its lack of an AIA extension is not a
        // shortfall: a clean run reports nothing.
        Assert.Empty(material.Problems);
    }

    [Fact]
    public async Task Blt_EmbedsOnlyWhatWasSuppliedWhenFetchingIsOff()
    {
        byte[] signed = await SignAsync(PadesLevel.BLT, s =>
        {
            s.FetchRevocation = false;
            s.ValidationMaterial = new SuppliedValidationMaterial { Crls = [_crlDer] };
        });

        int dssId = PdfIncrementalUpdate.ReadOptionalRef(CatalogBody(signed), "/DSS")!.Value;
        string dss = PdfIncrementalUpdate.ReadObjectBody(signed, dssId);
        Assert.Matches(@"/CRLs\s*\[", dss);
        Assert.DoesNotMatch(@"/OCSPs\s*\[", dss);
    }

    // --- The timestamp authority is covered too ---

    [Fact]
    public async Task Blt_EmbedsTheTimestampAuthoritysCertificate()
    {
        byte[] signed = await SignAsync(PadesLevel.BLT);
        int dssId = PdfIncrementalUpdate.ReadOptionalRef(CatalogBody(signed), "/DSS")!.Value;
        string dss = PdfIncrementalUpdate.ReadObjectBody(signed, dssId);

        // Signer + CA + the TSA's own certificate, plus the VRI reference.
        Assert.True(Regex.Matches(dss, @"\d+\s+0\s+R").Count >= 4);
    }

    [Fact]
    public async Task Blt_CollectsRevocationForTheTimestampAuthority()
    {
        // Two OCSP responses: one for the signer, one for the TSA. Without the
        // second, a validator cannot check the timestamp from inside the
        // document and the signature falls short of the LT level.
        var seen = new List<ValidationMaterial>();
        await SignAsync(PadesLevel.BLT, s => s.OnValidationMaterial = seen.Add);

        ValidationMaterial material = Assert.Single(seen);
        Assert.Equal(2, material.OcspResponses.Count);
        Assert.Empty(material.Problems);
    }

    [Fact]
    public async Task Collection_ReportsAProblemWhenTheTokenCarriesNoCertificates()
    {
        ValidationMaterial material = await ValidationMaterialCollector.CollectAsync(
            _signer.CertDer, [_ca.CertDer], TestHttpClient(), null, true,
            Der.Sequence(Der.Oid("1.2.840.113549.1.7.2")), CancellationToken.None);

        Assert.Contains(material.Problems, p => p.Contains("no certificates", StringComparison.Ordinal));
    }

    // --- PAdES forbids the CMS signing-time attribute ---

    [Theory]
    [InlineData(PadesLevel.BB)]
    [InlineData(PadesLevel.BT)]
    public async Task Pades_OmitsTheCmsSigningTimeAttribute(PadesLevel level)
    {
        // ETSI EN 319 142-1: the signing time of a PAdES signature is the /M
        // entry of the signature dictionary, and the CMS attribute "shall not be
        // present". Emitting both leaves two claims that can disagree, and the
        // EU DSS validator downgrades the signature out of the baseline profile.
        byte[] signed = await PdfSigner.SignAsync(MakePdf(), new SignatureSettings
        {
            CertificatePem = _signer.CertPem,
            PrivateKeyPem = _signer.KeyPem,
            PadesLevel = level,
            TimestampUrl = level == PadesLevel.BB ? null : TsaUrl,
            HttpClient = TestHttpClient(),
        });

        Assert.False(HasSigningTimeAttribute(signed));
    }

    [Fact]
    public void Legacy_KeepsTheCmsSigningTimeAttribute()
    {
        byte[] signed = PdfSigner.Sign(MakePdf(), new SignatureSettings
        {
            CertificatePem = _signer.CertPem,
            PrivateKeyPem = _signer.KeyPem,
        });

        Assert.True(HasSigningTimeAttribute(signed));
    }

    /// <summary>Is the PKCS#9 signing-time attribute present in the first signature?</summary>
    private static bool HasSigningTimeAttribute(byte[] signed)
    {
        int tag = PdfIncrementalUpdate.IndexOfAscii(signed, "/Contents <");
        int open = PdfIncrementalUpdate.IndexOfAscii(signed, "<", tag);
        int close = PdfIncrementalUpdate.IndexOfAscii(signed, ">", open);
        string hex = PdfIncrementalUpdate.Latin1Decode(signed[(open + 1)..close]);
        byte[] all = Convert.FromHexString(hex[..(hex.Length - (hex.Length % 2))]);

        var cms = new System.Security.Cryptography.Pkcs.SignedCms();
        cms.Decode(all[..Der.Read(all, 0).End]);

        const string signingTimeOid = "1.2.840.113549.1.9.5";
        foreach (CryptographicAttributeObject attribute in cms.SignerInfos[0].SignedAttributes)
        {
            if (string.Equals(attribute.Oid?.Value, signingTimeOid, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    // --- B-LTA ---

    [Fact]
    public async Task Blta_AppendsADocumentTimestamp()
    {
        byte[] signed = await SignAsync(PadesLevel.BLTA);
        string text = PdfIncrementalUpdate.Latin1Decode(signed);

        Assert.Contains("/Type /DocTimeStamp", text, StringComparison.Ordinal);
        Assert.Contains("/SubFilter /ETSI.RFC3161", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Blta_StillCarriesTheDssUnderneath()
    {
        byte[] signed = await SignAsync(PadesLevel.BLTA);
        Assert.Matches(@"/DSS\s+\d+\s+0\s+R", CatalogBody(signed));
    }

    [Fact]
    public async Task Blta_KeepsTheSignatureFieldAndAddsTheTimestampField()
    {
        byte[] signed = await SignAsync(PadesLevel.BLTA);
        int acroFormId = PdfIncrementalUpdate.ReadOptionalRef(CatalogBody(signed), "/AcroForm")!.Value;
        string acroForm = PdfIncrementalUpdate.ReadObjectBody(signed, acroFormId);

        Assert.Equal(2, Regex.Matches(acroForm, @"\d+\s+0\s+R").Count);
    }

    [Fact]
    public async Task Blta_TimestampsTheWholeFileNotJustTheSignature()
    {
        // The TSA records every imprint it is asked to stamp. The last one must
        // be the digest of this document's byte range - which is what makes the
        // DSS beneath it trustworthy.
        byte[] signed = await SignAsync(PadesLevel.BLTA);
        int[] range = ByteRangeAfter(signed, PdfIncrementalUpdate.IndexOfAscii(signed, "/Type /DocTimeStamp"));

        var covered = new byte[range[1] + range[3]];
        Buffer.BlockCopy(signed, range[0], covered, 0, range[1]);
        Buffer.BlockCopy(signed, range[2], covered, range[1], range[3]);

        Assert.Equal(SHA256.HashData(covered), _tsa.Imprints[^1]);
    }

    [Fact]
    public async Task Blta_PutsARealRfc3161TokenInTheTimestampContents()
    {
        byte[] signed = await SignAsync(PadesLevel.BLTA);
        int tsIndex = PdfIncrementalUpdate.IndexOfAscii(signed, "/Type /DocTimeStamp");
        int open = PdfIncrementalUpdate.IndexOfAscii(signed, "/Contents <", tsIndex);
        int start = PdfIncrementalUpdate.IndexOfAscii(signed, "<", open);
        int end = PdfIncrementalUpdate.IndexOfAscii(signed, ">", start);

        string hex = PdfIncrementalUpdate.Latin1Decode(signed[(start + 1)..end]);
        byte[] token = Convert.FromHexString(hex[..(hex.Length - (hex.Length % 2))]);

        Der.Node root = Der.Read(token, 0);
        Assert.Equal(0x30, root.Tag);
        Assert.Contains(
            Convert.ToHexString(Der.Oid(TestPki.TstInfoOid)),
            Convert.ToHexString(token[..root.End]),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Blta_UsesASeparateAuthorityWhenOneIsConfigured()
    {
        int separateCalls = 0;
        const string separateUrl = "http://archive-tsa.test.invalid/tsr";
        SigningHttpClient inner = TestHttpClient();

        Task<SigningHttpResponse> Client(SigningHttpRequest request, CancellationToken ct)
        {
            if (string.Equals(request.Url, separateUrl, StringComparison.Ordinal))
            {
                separateCalls++;
                return Task.FromResult(new SigningHttpResponse { Status = 200, Body = _tsa.Respond(request.Body) });
            }
            return inner(request, ct);
        }

        await PdfSigner.SignAsync(MakePdf(), new SignatureSettings
        {
            CertificatePem = _signer.CertPem,
            PrivateKeyPem = _signer.KeyPem,
            CertificateChainPem = [_ca.CertPem],
            PadesLevel = PadesLevel.BLTA,
            TimestampUrl = TsaUrl,
            DocumentTimestampUrl = separateUrl,
            HttpClient = Client,
        });

        Assert.Equal(1, separateCalls);
    }

    // --- Level validation ---

    [Theory]
    [InlineData(PadesLevel.BT)]
    [InlineData(PadesLevel.BLT)]
    [InlineData(PadesLevel.BLTA)]
    public async Task Levels_RejectedWithoutATimestampAuthority(PadesLevel level)
    {
        ArgumentException error = await Assert.ThrowsAsync<ArgumentException>(() =>
            PdfSigner.SignAsync(MakePdf(), new SignatureSettings
            {
                CertificatePem = _signer.CertPem,
                PrivateKeyPem = _signer.KeyPem,
                PadesLevel = level,
            }));

        Assert.Contains("TimestampUrl", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NeedsEsicExtension_TrueForAPdfWithNoVersionHeader() =>
        Assert.True(PdfIncrementalUpdate.NeedsEsicExtension([1, 2, 3]));

    [Fact]
    public async Task SignAsync_PropagatesPreCancelledToken()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PdfSigner.SignAsync(MakePdf(), new SignatureSettings
            {
                CertificatePem = _signer.CertPem,
                PrivateKeyPem = _signer.KeyPem,
                PadesLevel = PadesLevel.BB,
            }, cts.Token));
    }

    [Fact]
    public async Task Blt_ExtractsTsaCertificatesEvenWhenFetchRevocationIsFalse()
    {
        int before = _ocsp.Requests;
        ValidationMaterial? captured = null;
        await PdfSigner.SignAsync(MakePdf(), new SignatureSettings
        {
            CertificatePem = _signer.CertPem,
            PrivateKeyPem = _signer.KeyPem,
            CertificateChainPem = [_ca.CertPem],
            PadesLevel = PadesLevel.BLT,
            TimestampUrl = TsaUrl,
            HttpClient = TestHttpClient(),
            FetchRevocation = false,
            OnValidationMaterial = m => captured = m,
        });

        Assert.Equal(before, _ocsp.Requests);
        Assert.NotNull(captured);
        Assert.Contains(captured!.Certificates, c => c.SequenceEqual(_tsaIdentity.CertDer));
    }

    [Fact]
    public void SignatureOptions_SupportsFullBuilderParityAndValidatesPadesLevel()
    {
        Assert.Throws<ArgumentException>(() =>
            new SignatureOptions()
                .WithCertificate(_signer.CertPem)
                .WithPrivateKey(_signer.KeyPem)
                .UsingPades(PadesLevel.BT)
                .Build());

        DateTimeOffset when = new(2026, 1, 15, 9, 30, 0, TimeSpan.Zero);
        SignatureSettings built = new SignatureOptions()
            .WithPem(_signer.CertPem, _signer.KeyPem)
            .WithSigningTime(when)
            .UsingPades(PadesLevel.BLTA)
            .WithTimestamp(TsaUrl, TestHttpClient())
            .WithDocumentTimestamp(TsaUrl)
            .WithFetchRevocation(false)
            .WithValidationMaterial(new SuppliedValidationMaterial { Crls = [_crlDer] })
            .Build();

        Assert.Equal(when, built.SigningTime);
        Assert.False(built.FetchRevocation);
        Assert.Equal(TsaUrl, built.DocumentTimestampUrl);
    }
}
