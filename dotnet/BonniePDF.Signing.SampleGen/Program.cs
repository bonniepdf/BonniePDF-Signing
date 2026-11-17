using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BonniePDF;
using BonniePDF.Elements.Text;
using BonniePDF.Signing;

// Generates the same set of signed sample PDFs as the TypeScript
// generate-signed-samples.ts, for external validation with `pdfsig` (Poppler).
// Both libraries are then validated by the identical pdfsig-validate.sh gate.
//
// Usage:  dotnet run --project BonniePDF.Signing.SampleGen -- [outDir]

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

Console.WriteLine($"Wrote 4 signed samples to {outDir}/");

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
