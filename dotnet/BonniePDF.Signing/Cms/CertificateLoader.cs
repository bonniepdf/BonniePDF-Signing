using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace BonniePDF.Signing.Cms;

/// <summary>Loads the signer certificate (+ key) from PEM or PKCS#12 input.</summary>
internal static class CertificateLoader
{
    public static X509Certificate2 Load(SignatureSettings settings)
    {
        if (settings.Pkcs12 is { Length: > 0 })
        {
            return new X509Certificate2(settings.Pkcs12, settings.Pkcs12Password, X509KeyStorageFlags.Exportable);
        }

        // PEM cert + key. CreateFromPem associates an ephemeral key; round-trip
        // through PKCS#12 so the private key is usable for signing on every
        // platform (notably Windows, where ephemeral keys can't sign in CMS).
        using var fromPem = X509Certificate2.CreateFromPem(settings.CertificatePem, settings.PrivateKeyPem);
        return new X509Certificate2(fromPem.Export(X509ContentType.Pkcs12), (string)null, X509KeyStorageFlags.Exportable);
    }

    public static List<X509Certificate2> LoadChain(SignatureSettings settings)
    {
        var chain = new List<X509Certificate2>();
        if (settings.CertificateChainPem != null)
        {
            foreach (string pem in settings.CertificateChainPem)
            {
                if (!string.IsNullOrWhiteSpace(pem)) chain.Add(X509Certificate2.CreateFromPem(pem));
            }
        }
        return chain;
    }
}
