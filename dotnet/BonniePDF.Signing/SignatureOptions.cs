using System;

namespace BonniePDF.Signing;

/// <summary>
/// Fluent builder for <see cref="SignatureSettings"/>, mirroring the core
/// library's <c>EncryptionOptions</c> and the TypeScript <c>SignatureOptions</c>.
/// </summary>
public sealed class SignatureOptions
{
    private readonly SignatureSettings _settings = new();

    /// <summary>Sets the PEM-encoded certificate and PKCS#8 private key.</summary>
    public SignatureOptions WithPem(string certificatePem, string privateKeyPem)
    {
        _settings.CertificatePem = certificatePem;
        _settings.PrivateKeyPem = privateKeyPem;
        return this;
    }

    /// <summary>Sets a PKCS#12 (<c>.pfx</c>) container and its password.</summary>
    public SignatureOptions WithPkcs12(byte[] pkcs12, string password)
    {
        _settings.Pkcs12 = pkcs12;
        _settings.Pkcs12Password = password;
        return this;
    }

    /// <summary>Sets the optional intermediate certificate chain (PEM).</summary>
    public SignatureOptions WithChain(string[] certificateChainPem)
    {
        _settings.CertificateChainPem = certificateChainPem;
        return this;
    }

    /// <summary>Sets the optional signing reason.</summary>
    public SignatureOptions WithReason(string reason)
    {
        _settings.Reason = reason;
        return this;
    }

    /// <summary>Sets the optional signing location.</summary>
    public SignatureOptions WithLocation(string location)
    {
        _settings.Location = location;
        return this;
    }

    /// <summary>Sets the optional contact info.</summary>
    public SignatureOptions WithContactInfo(string contactInfo)
    {
        _settings.ContactInfo = contactInfo;
        return this;
    }

    /// <summary>Sets the optional signer name.</summary>
    public SignatureOptions WithName(string name)
    {
        _settings.Name = name;
        return this;
    }

    /// <summary>Selects the signing algorithm (default <see cref="SigningAlgorithm.Sha256Rsa"/>).</summary>
    public SignatureOptions UsingAlgorithm(SigningAlgorithm algorithm)
    {
        _settings.Algorithm = algorithm;
        return this;
    }

    /// <summary>Selects the PAdES baseline level.</summary>
    public SignatureOptions UsingPades(PadesLevel level)
    {
        _settings.PadesLevel = level;
        return this;
    }

    /// <summary>Enables an RFC 3161 timestamp; implies PAdES B-T unless a level was set.</summary>
    public SignatureOptions WithTimestamp(string timestampUrl)
    {
        _settings.TimestampUrl = timestampUrl;
        if (_settings.PadesLevel is PadesLevel.None or PadesLevel.BB)
        {
            _settings.PadesLevel = PadesLevel.BT;
        }
        return this;
    }

    /// <summary>Makes the signature <b>visible</b> with the given appearance.</summary>
    public SignatureOptions WithVisibleSignature(SignatureAppearance appearance)
    {
        _settings.Appearance = appearance;
        return this;
    }

    /// <summary>
    /// Sets the commercial licence key (the <c>BPDF1.…</c> token). Optional - if
    /// not set here, it is read from <see cref="License.Key"/>,
    /// <c>BONNIEPDF_LICENSE_KEY</c>, or <c>bonniepdf.license</c>.
    /// </summary>
    public SignatureOptions WithLicense(string license)
    {
        _settings.License = license;
        return this;
    }

    /// <summary>Require a valid licence (no evaluation-mode fallback).</summary>
    public SignatureOptions RequireLicense(bool require = true)
    {
        _settings.RequireLicense = require;
        return this;
    }

    /// <summary>Builds the <see cref="SignatureSettings"/>. Throws if cert/key are missing.</summary>
    public SignatureSettings Build()
    {
        _settings.Validate();
        return _settings;
    }
}
