using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BonniePDF;
using BonniePDF.Elements.Text;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing;
using BonniePDF.Signing.Http;
using BonniePDF.Signing.TestSupport;

// Generates the same set of signed sample PDFs as the TypeScript
// generate-signed-samples.ts, for external validation with `pdfsig` (Poppler).
// Both libraries are then validated by the identical pdfsig-validate.sh gate.
//
// Usage:  dotnet run --project BonniePDF.Signing.SampleGen -- [outDir]

const string OcspUrl = "http://ocsp.test.invalid/ocsp";
const string CrlUrl = "http://crl.test.invalid/ca.crl";
const string TsaUrl = "http://tsa.test.invalid/tsr";

string outDir = args.Length > 0 ? args[0] : "signed-samples";
Directory.CreateDirectory(outDir);

(string Cert, string Key) rsa = MakeRsa();
(string Cert, string Key) ec = MakeEc();

File.WriteAllBytes(Path.Combine(outDir, "invisible-rsa.pdf"), PdfSigner.Sign(MakePdf(), new SignatureSettings
{
    CertificatePem = rsa.Cert,
    PrivateKeyPem = rsa.Key,
    Reason = "Approved",
}));

File.WriteAllBytes(Path.Combine(outDir, "visible-rsa.pdf"), PdfSigner.Sign(MakePdf(), new SignatureSettings
{
    CertificatePem = rsa.Cert,
    PrivateKeyPem = rsa.Key,
    Appearance = new SignatureAppearance
    {
        Rect = new double[] { 72, 72, 220, 64 },
        Text = new[] { "Signed by BonniePDF", "External validation" },
    },
}));

File.WriteAllBytes(Path.Combine(outDir, "pades-bb-rsa.pdf"), PdfSigner.Sign(MakePdf(), new SignatureSettings
{
    CertificatePem = rsa.Cert,
    PrivateKeyPem = rsa.Key,
    PadesLevel = PadesLevel.BB,
    Reason = "Approved",
}));

File.WriteAllBytes(Path.Combine(outDir, "invisible-ecdsa.pdf"), PdfSigner.Sign(MakePdf(), new SignatureSettings
{
    Algorithm = SigningAlgorithm.Sha256Ecdsa,
    CertificatePem = ec.Cert,
    PrivateKeyPem = ec.Key,
}));

// PAdES levels, signed against a throwaway PKI built here: a CA, an OCSP
// responder and an RFC 3161 authority, all in-process. These are the samples the
// EU DSS gate checks - it asserts the level each file actually reaches, which is
// the claim the product makes and the one a buyer's validator will test.
await WritePadesSamplesAsync(outDir);

Console.WriteLine($"Wrote signed samples to {outDir}/");

static async Task WritePadesSamplesAsync(string outDir)
{
    using TestPki.Identity ca = TestPki.IssueCa("BonniePDF Test CA");
    using TestPki.Identity signer = TestPki.Issue("BonniePDF Test Signer", ca,
        TestPki.AiaOcsp(OcspUrl), TestPki.CrlDistributionPoint(CrlUrl));

    // RFC 3161 §2.3 requires the critical id-kp-timeStamping extended key usage.
    // The AIA matters just as much: without revocation information for the
    // authority's own certificate a long-term signature cannot reach LT.
    var timeStamping = new X509EnhancedKeyUsageExtension(
        new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") }, critical: true);
    using TestPki.Identity tsaIdentity = TestPki.Issue("BonniePDF Test TSA", ca,
        timeStamping, TestPki.AiaOcsp(OcspUrl));

    var tsa = new TestPki.TestTsa(tsaIdentity);
    var ocsp = new TestPki.TestOcspResponder(ca);

    Task<SigningHttpResponse> Transport(SigningHttpRequest request, CancellationToken ct)
    {
        if (string.Equals(request.Url, TsaUrl, StringComparison.Ordinal))
            return Task.FromResult(new SigningHttpResponse { Status = 200, Body = tsa.Respond(request.Body) });
        if (string.Equals(request.Url, OcspUrl, StringComparison.Ordinal))
            return Task.FromResult(new SigningHttpResponse { Status = 200, Body = ocsp.Respond(request.Body) });
        return Task.FromResult(new SigningHttpResponse { Status = 404, Body = new byte[0] });
    }

    // filename, level, the format DSS must report, and the indication it must
    // reach. B and T carry no revocation material, so an offline validator
    // cannot complete the chain check - INDETERMINATE there is the correct
    // result for those levels, not a defect.
    (string Name, PadesLevel Level, string Format, string Indication)[] samples =
    {
        ("pades-bb", PadesLevel.BB, "PAdES-BASELINE-B", "INDETERMINATE"),
        ("pades-bt", PadesLevel.BT, "PAdES-BASELINE-T", "INDETERMINATE"),
        ("pades-blt", PadesLevel.BLT, "PAdES-BASELINE-LT", "TOTAL_PASSED"),
        ("pades-blta", PadesLevel.BLTA, "PAdES-BASELINE-LTA", "TOTAL_PASSED"),
    };

    var manifest = new System.Text.StringBuilder();
    foreach ((string name, PadesLevel level, string format, string indication) in samples)
    {
        byte[] signed = await PdfSigner.SignAsync(MakePdf(), new SignatureSettings
        {
            CertificatePem = signer.CertPem,
            PrivateKeyPem = signer.KeyPem,
            CertificateChainPem = new[] { ca.CertPem },
            PadesLevel = level,
            TimestampUrl = level == PadesLevel.BB ? null : TsaUrl,
            HttpClient = Transport,
            Reason = "Approved",
        }).ConfigureAwait(false);

        File.WriteAllBytes(Path.Combine(outDir, name + ".pdf"), signed);
        manifest.Append(name).Append(".pdf\t").Append(format).Append('\t').Append(indication).Append('\n');
    }

    File.WriteAllText(Path.Combine(outDir, "test-ca.pem"), ca.CertPem);
    File.WriteAllText(Path.Combine(outDir, "expected.tsv"), manifest.ToString());
}

static byte[] MakePdf()
{
    var doc = new Document();
    doc.Add(new TextBlock("External validation sample."));
    return doc.ToByteArray();
}

static (string Cert, string Key) MakeRsa()
{
    using RSA rsa = RSA.Create(2048);
    var req = new CertificateRequest("CN=BonniePDF Sample RSA, O=BonniePDF, C=GB", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    return (new string(PemEncoding.Write("CERTIFICATE", cert.RawData)), new string(PemEncoding.Write("PRIVATE KEY", rsa.ExportPkcs8PrivateKey())));
}

static (string Cert, string Key) MakeEc()
{
    using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var req = new CertificateRequest("CN=BonniePDF Sample EC, O=BonniePDF, C=GB", ec, HashAlgorithmName.SHA256);
    using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    return (new string(PemEncoding.Write("CERTIFICATE", cert.RawData)), new string(PemEncoding.Write("PRIVATE KEY", ec.ExportPkcs8PrivateKey())));
}
