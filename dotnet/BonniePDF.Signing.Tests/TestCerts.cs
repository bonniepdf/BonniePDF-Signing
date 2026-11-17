using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BonniePDF.Signing.Tests;

/// <summary>
/// Mints throwaway self-signed certificates in-process (no openssl / fixtures)
/// and exposes them as PEM, mirroring how the TS suite uses fixture certs.
/// </summary>
internal static class TestCerts
{
    public static (string CertPem, string KeyPem) Rsa(int keySize = 2048)
    {
        using RSA rsa = RSA.Create(keySize);
        var req = new CertificateRequest("CN=BonniePDF Test Signer, O=BonniePDF, C=GB", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        return (ExportCertPem(cert), ExportRsaKeyPem(rsa));
    }

    public static (string CertPem, string KeyPem) Ecdsa(ECCurve? curve = null)
    {
        using ECDsa ec = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=BonniePDF EC Signer, O=BonniePDF, C=GB", ec, HashAlgorithmName.SHA256);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        return (ExportCertPem(cert), ExportEcKeyPem(ec));
    }

    public static byte[] Pkcs12(string certPem, string keyPem, string password)
    {
        using X509Certificate2 cert = X509Certificate2.CreateFromPem(certPem, keyPem);
        return cert.Export(X509ContentType.Pkcs12, password);
    }

    private static string ExportCertPem(X509Certificate2 cert) =>
        new string(PemEncoding.Write("CERTIFICATE", cert.RawData));

    private static string ExportRsaKeyPem(RSA rsa) =>
        new string(PemEncoding.Write("PRIVATE KEY", rsa.ExportPkcs8PrivateKey()));

    private static string ExportEcKeyPem(ECDsa ec) =>
        new string(PemEncoding.Write("PRIVATE KEY", ec.ExportPkcs8PrivateKey()));
}
