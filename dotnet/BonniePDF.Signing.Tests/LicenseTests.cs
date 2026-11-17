using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BonniePDF.Signing;
using Xunit;

namespace BonniePDF.Signing.Tests;

public class LicenseTests
{
    private const string Prefix = "BPDF1";

    /// <summary>Ephemeral P-256 keypair: returns a minting function + the public SPKI (base64).</summary>
    private static (Func<LicenseClaims, string> Mint, string PublicSpki) MakeMinter()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string publicSpki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        string Mint(LicenseClaims claims)
        {
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(claims);
            string payloadB64 = Base64Url(payload);
            byte[] signingInput = Encoding.UTF8.GetBytes($"{Prefix}.{payloadB64}");
            byte[] sig = ecdsa.SignData(signingInput, HashAlgorithmName.SHA256);
            return $"{Prefix}.{payloadB64}.{Base64Url(sig)}";
        }

        return (Mint, publicSpki);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static string Today() => DateTimeOffset.UtcNow.ToString("yyyy-MM-dd");
    private static string PlusDays(int n) => DateTimeOffset.UtcNow.AddDays(n).ToString("yyyy-MM-dd");

    [Fact]
    public void Accepts_CurrentKey_SignedByMatchingPrivateKey()
    {
        var (mint, pub) = MakeMinter();
        string token = mint(new LicenseClaims { Sub = "acme-corp", Edition = "enterprise", Iat = Today(), Exp = PlusDays(365) });
        LicenseVerification result = License.Verify(token, publicKeySpki: pub);
        Assert.True(result.Ok);
        Assert.Equal(LicenseStatus.Valid, result.Status);
        Assert.Equal("acme-corp", result.Claims.Sub);
        Assert.Equal("enterprise", result.Claims.Edition);
    }

    [Fact]
    public void Rejects_ForgedKey_FromDifferentPrivateKey()
    {
        var (_, realPub) = MakeMinter();
        var (attackerMint, _) = MakeMinter();
        string token = attackerMint(new LicenseClaims { Sub = "free-loader", Edition = "enterprise" });
        LicenseVerification result = License.Verify(token, publicKeySpki: realPub);
        Assert.False(result.Ok);
        Assert.Equal(LicenseStatus.Invalid, result.Status);
    }

    [Fact]
    public void Reports_Grace_WhenExpiredWithinWindow()
    {
        var (mint, pub) = MakeMinter();
        string token = mint(new LicenseClaims { Sub = "acme", Edition = "enterprise", Exp = PlusDays(-5) });
        LicenseVerification result = License.Verify(token, graceDays: 30, publicKeySpki: pub);
        Assert.True(result.Ok);
        Assert.Equal(LicenseStatus.Grace, result.Status);
    }

    [Fact]
    public void Reports_Expired_BeyondGraceWindow()
    {
        var (mint, pub) = MakeMinter();
        string token = mint(new LicenseClaims { Sub = "acme", Edition = "enterprise", Exp = PlusDays(-90) });
        LicenseVerification result = License.Verify(token, graceDays: 30, publicKeySpki: pub);
        Assert.False(result.Ok);
        Assert.Equal(LicenseStatus.Expired, result.Status);
    }

    [Fact]
    public void Treats_AbsentKey_AsUnlicensed()
    {
        Assert.Equal(LicenseStatus.Unlicensed, License.Verify(null).Status);
        Assert.Equal(LicenseStatus.Unlicensed, License.Verify("").Status);
    }

    [Fact]
    public void Treats_MalformedKey_AsInvalid()
    {
        Assert.Equal(LicenseStatus.Invalid, License.Verify("not-a-real-key").Status);
        Assert.Equal(LicenseStatus.Invalid, License.Verify("BPDF1.onlytwo").Status);
    }

    [Fact]
    public void Resolve_PrefersExplicit_OverGlobalKey()
    {
        License.Key = "global-key";
        try
        {
            Assert.Equal("explicit", License.Resolve("explicit"));
            Assert.Equal("global-key", License.Resolve(null));
        }
        finally
        {
            License.Key = null;
        }
    }

    [Fact]
    public void Enforce_AllowsEvaluationMode_ByDefault()
    {
        License.ResetWarning();
        LicenseVerification result = License.Enforce(null, requireLicense: false);
        Assert.Equal(LicenseStatus.Unlicensed, result.Status);
        Assert.False(result.Ok);
    }

    [Fact]
    public void Enforce_Throws_WhenLicenseRequiredButAbsent()
    {
        Assert.Throws<InvalidOperationException>(() => License.Enforce(null, requireLicense: true));
    }

    [Fact]
    public void Enforce_Throws_OnPresentButInvalidKey()
    {
        Assert.Throws<InvalidOperationException>(() => License.Enforce("BPDF1.garbage.sig", requireLicense: false));
    }

    [Fact]
    public void Signing_WorksInEvaluationMode_WithNoKey()
    {
        License.ResetWarning();
        var (certPem, keyPem) = TestCerts.Rsa();
        var doc = new Document();
        doc.Add(new BonniePDF.Elements.Text.TextBlock("Eval-mode signing."));
        byte[] signed = PdfSigner.Sign(doc.ToByteArray(), new SignatureSettings
        {
            CertificatePem = certPem,
            PrivateKeyPem = keyPem,
        });
        Assert.True(signed.Length > 0);
    }
}
