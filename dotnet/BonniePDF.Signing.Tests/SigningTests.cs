using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using BonniePDF;
using BonniePDF.Signing;
using BonniePDF.Signing.Http;
using Xunit;

namespace BonniePDF.Signing.Tests;

public class SigningTests
{
    private const string SigningCertV2Oid = "1.2.840.113549.1.9.16.2.47";

    private static byte[] MakePdf()
    {
        using var doc = new Document();
        doc.Add(new TextBlock("Document to be signed."));
        return doc.GenerateBytes();
    }

    private static string Latin1(byte[] bytes) => Encoding.Latin1.GetString(bytes);

    /// <summary>Reconstruct the signed byte range and the detached CMS, then verify.</summary>
    private static void AssertSignatureVerifies(byte[] signed)
    {
        string text = Latin1(signed);
        var m = Regex.Match(text, @"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)");
        Assert.True(m.Success, "ByteRange present");
        int s1 = int.Parse(m.Groups[1].Value), l1 = int.Parse(m.Groups[2].Value);
        int s2 = int.Parse(m.Groups[3].Value), l2 = int.Parse(m.Groups[4].Value);
        Assert.Equal(0, s1);
        Assert.Equal(signed.Length, s2 + l2);

        var content = new byte[l1 + l2];
        Buffer.BlockCopy(signed, s1, content, 0, l1);
        Buffer.BlockCopy(signed, s2, content, l1, l2);

        byte[] cms = ReadContents(signed);
        var signedCms = new SignedCms(new ContentInfo(content), detached: true);
        signedCms.Decode(cms);
        // Verify the cryptographic signature only (self-signed cert: skip chain trust).
        signedCms.CheckSignature(verifySignatureOnly: true);
    }

    private static byte[] ReadContents(byte[] bytes)
    {
        string text = Latin1(bytes);
        int tag = text.IndexOf("/Contents <", StringComparison.Ordinal);
        int open = text.IndexOf('<', tag);
        int close = text.IndexOf('>', open);
        string hex = text.Substring(open + 1, close - open - 1);
        var all = Convert.FromHexString(hex);
        // Slice to the exact DER length so trailing zero padding is excluded.
        int total = DerTotalLength(all);
        var der = new byte[total];
        Buffer.BlockCopy(all, 0, der, 0, total);
        return der;
    }

    private static int DerTotalLength(byte[] der)
    {
        int pos = 1;
        int length = der[pos++];
        int header;
        if ((length & 0x80) != 0)
        {
            int n = length & 0x7f;
            length = 0;
            for (int i = 0; i < n; i++) length = (length << 8) | der[pos++];
            header = 2 + n;
        }
        else
        {
            header = 2;
        }
        return header + length;
    }

    [Fact]
    public void Sign_Invisible_Rsa_Verifies()
    {
        var (certPem, keyPem) = TestCerts.Rsa();
        byte[] signed = PdfSigner.Sign(MakePdf(), new SignatureSettings
        {
            CertificatePem = certPem,
            PrivateKeyPem = keyPem,
            Reason = "Approved",
        });

        string text = Latin1(signed);
        Assert.Contains("/Type /Sig", text);
        Assert.Contains("/SubFilter /adbe.pkcs7.detached", text);
        Assert.Contains("/AcroForm", text);
        Assert.Contains("/SigFlags 3", text);
        Assert.Contains("(Approved)", text);
        AssertSignatureVerifies(signed);
    }

    [Fact]
    public void Sign_Ecdsa_Verifies()
    {
        var (certPem, keyPem) = TestCerts.Ecdsa();
        byte[] signed = PdfSigner.Sign(MakePdf(), new SignatureSettings
        {
            Algorithm = SigningAlgorithm.Sha256Ecdsa,
            CertificatePem = certPem,
            PrivateKeyPem = keyPem,
        });
        AssertSignatureVerifies(signed);
    }

    [Fact]
    public void Sign_FromPkcs12_Verifies()
    {
        var (certPem, keyPem) = TestCerts.Rsa();
        byte[] pfx = TestCerts.Pkcs12(certPem, keyPem, "pw");
        byte[] signed = PdfSigner.Sign(MakePdf(), new SignatureSettings
        {
            Pkcs12 = pfx,
            Pkcs12Password = "pw",
        });
        AssertSignatureVerifies(signed);
    }

    [Fact]
    public void Sign_AppendsRatherThanRewrites()
    {
        var (certPem, keyPem) = TestCerts.Rsa();
        byte[] original = MakePdf();
        byte[] signed = PdfSigner.Sign(original, new SignatureSettings { CertificatePem = certPem, PrivateKeyPem = keyPem });
        Assert.True(signed.Length > original.Length);
        for (int i = 0; i < original.Length; i++) Assert.Equal(original[i], signed[i]);
        Assert.Equal(2, Regex.Matches(Latin1(signed), "%%EOF").Count);
        Assert.Contains("/Prev", Latin1(signed));
    }

    [Fact]
    public void PadesBB_UsesCadesSubfilterAndSigningCertV2()
    {
        var (certPem, keyPem) = TestCerts.Rsa();
        byte[] signed = PdfSigner.Sign(MakePdf(), new SignatureSettings
        {
            CertificatePem = certPem,
            PrivateKeyPem = keyPem,
            PadesLevel = PadesLevel.BB,
        });

        Assert.Contains("/SubFilter /ETSI.CAdES.detached", Latin1(signed));

        byte[] cms = ReadContents(signed);
        var signedCms = new SignedCms();
        signedCms.Decode(cms);
        bool hasSigningCertV2 = false;
        foreach (CryptographicAttributeObject attr in signedCms.SignerInfos[0].SignedAttributes)
        {
            if (attr.Oid.Value == SigningCertV2Oid) hasSigningCertV2 = true;
        }
        Assert.True(hasSigningCertV2, "signing-certificate-v2 present");
    }

    [Fact]
    public void VisibleSignature_HasRectAndAppearance()
    {
        var (certPem, keyPem) = TestCerts.Rsa();
        byte[] signed = PdfSigner.Sign(MakePdf(), new SignatureSettings
        {
            CertificatePem = certPem,
            PrivateKeyPem = keyPem,
            Appearance = new SignatureAppearance
            {
                Rect = new double[] { 72, 72, 200, 60 },
                Text = new[] { "Signed by Test", "BonniePDF" },
            },
        });

        string text = Latin1(signed);
        // [x, y, width, height] = [72, 72, 200, 60] is the box from (72, 72) to (272, 132).
        Assert.Contains("/Rect [72 72 272 132]", text);
        Assert.Contains("/BBox [0 0 200 60]", text);
        Assert.DoesNotContain("/Rect [0 0 0 0]", text);
        Assert.Contains("/AP << /N", text);
        Assert.Contains("/Subtype /Form", text);
        Assert.Contains("/BaseFont /Helvetica", text);
        Assert.Contains("(Signed by Test) Tj", text);
        AssertSignatureVerifies(signed);
    }

    [Fact]
    public void Sign_Throws_WhenTimestampConfiguredOnSyncPath()
    {
        var (certPem, keyPem) = TestCerts.Rsa();
        Assert.Throws<InvalidOperationException>(() => PdfSigner.Sign(MakePdf(), new SignatureSettings
        {
            CertificatePem = certPem,
            PrivateKeyPem = keyPem,
            PadesLevel = PadesLevel.BT,
            TimestampUrl = "https://tsa.example/tsr",
        }));
    }

    [Fact]
    public async Task SignAsync_PadesBT_InvokesTimestampTransportWithDerRequest()
    {
        var (certPem, keyPem) = TestCerts.Rsa();
        bool called = false;
        byte[]? capturedRequest = null;

        Task<SigningHttpResponse> Transport(SigningHttpRequest request, System.Threading.CancellationToken ct)
        {
            called = true;
            capturedRequest = request.Body;
            // Return bytes that are not a valid TimeStampResp so token extraction
            // throws - we only need to assert the request path ran and produced a
            // DER request.
            return Task.FromResult(new SigningHttpResponse { Status = 200, Body = [0x30, 0x00] });
        }

        await Assert.ThrowsAnyAsync<Exception>(() => PdfSigner.SignAsync(MakePdf(), new SignatureSettings
        {
            CertificatePem = certPem,
            PrivateKeyPem = keyPem,
            PadesLevel = PadesLevel.BT,
            TimestampUrl = "https://tsa.example/tsr",
            HttpClient = Transport,
        }));

        Assert.True(called, "timestamp transport invoked");
        Assert.NotNull(capturedRequest);
        Assert.Equal(0x30, capturedRequest![0]); // DER SEQUENCE (TimeStampReq)
    }

    [Fact]
    public void Build_Throws_WhenNoCertificate()
    {
        Assert.Throws<ArgumentException>(() => new SignatureOptions().WithReason("x").Build());
    }
}
