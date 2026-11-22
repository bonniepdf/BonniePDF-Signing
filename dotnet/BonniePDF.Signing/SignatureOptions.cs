using System;
using BonniePDF.Signing.Http;
using BonniePDF.Signing.Validation;

namespace BonniePDF.Signing;

/// <summary>
/// Fluent builder for <see cref="SignatureSettings"/>, mirroring the core
/// library's <c>EncryptionOptions</c> and the TypeScript <c>SignatureOptions</c>.
/// </summary>
public sealed class SignatureOptions
{
    private readonly SignatureSettings _settings = new();

    /// <summary>Sets the PEM-encoded X.509 signer certificate.</summary>
    public SignatureOptions WithCertificate(string certificatePem)
    {
        _settings.CertificatePem = certificatePem;
        return this;
    }

    /// <summary>Sets the PEM-encoded PKCS#8 private key.</summary>
    public SignatureOptions WithPrivateKey(string privateKeyPem)
    {
        _settings.PrivateKeyPem = privateKeyPem;
        return this;
    }

    /// <summary>Sets the PEM-encoded certificate and PKCS#8 private key.</summary>
    public SignatureOptions WithPem(string certificatePem, string privateKeyPem)
    {
        _settings.CertificatePem = certificatePem;
        _settings.PrivateKeyPem = privateKeyPem;
        return this;
    }

    /// <summary>Sets a PKCS#12 (<c>.pfx</c>) container and its password.</summary>
    public SignatureOptions WithPkcs12(byte[] pkcs12, string password = "")
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

    /// <summary>Sets an explicit signing time (defaults to now).</summary>
    public SignatureOptions WithSigningTime(DateTimeOffset signingTime)
    {
        _settings.SigningTime = signingTime;
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
    public SignatureOptions WithTimestamp(string timestampUrl, SigningHttpClient httpClient = null)
    {
        _settings.TimestampUrl = timestampUrl;
        if (httpClient is not null) _settings.HttpClient = httpClient;
        if (_settings.PadesLevel is PadesLevel.None or PadesLevel.BB)
        {
            _settings.PadesLevel = PadesLevel.BT;
        }
        return this;
    }

    /// <summary>Sets a separate TSA endpoint for the PAdES B-LTA document timestamp.</summary>
    public SignatureOptions WithDocumentTimestamp(string documentTimestampUrl)
    {
        _settings.DocumentTimestampUrl = documentTimestampUrl;
        return this;
    }

    /// <summary>Sets the HTTP transport used for timestamping, OCSP, and CRL requests.</summary>
    public SignatureOptions WithHttpClient(SigningHttpClient httpClient)
    {
        _settings.HttpClient = httpClient;
        return this;
    }

    /// <summary>Sets caller-supplied validation material to embed for PAdES B-LT and B-LTA.</summary>
    public SignatureOptions WithValidationMaterial(SuppliedValidationMaterial validationMaterial)
    {
        _settings.ValidationMaterial = validationMaterial;
        return this;
    }

    /// <summary>Controls whether revocation evidence (OCSP/CRL) is fetched over the network.</summary>
    public SignatureOptions WithFetchRevocation(bool fetchRevocation)
    {
        _settings.FetchRevocation = fetchRevocation;
        return this;
    }

    /// <summary>Sets the per-call callback receiving the validation material embedded in the DSS.</summary>
    public SignatureOptions WithOnValidationMaterial(Action<ValidationMaterial> onValidationMaterial)
    {
        _settings.OnValidationMaterial = onValidationMaterial;
        return this;
    }

    /// <summary>Makes the signature <b>visible</b> with the given appearance.</summary>
    public SignatureOptions WithVisibleSignature(SignatureAppearance appearance)
    {
        _settings.Appearance = appearance;
        return this;
    }

    /// <summary>Builds the <see cref="SignatureSettings"/>. Throws if required inputs are missing.</summary>
    public SignatureSettings Build()
    {
        _settings.Validate();
        return _settings;
    }
}
