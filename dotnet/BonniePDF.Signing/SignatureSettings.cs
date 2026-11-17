using System;
using System.Threading;
using System.Threading.Tasks;
// Alias the enum so it can be referenced inside SignatureSettings, whose
// `PadesLevel` property otherwise shadows the type name.
using Level = BonniePDF.Signing.PadesLevel;

namespace BonniePDF.Signing;

/// <summary>
/// PAdES baseline level (ETSI EN 319 142):
/// <list type="bullet">
/// <item><c>None</c> - legacy Adobe signature (<c>adbe.pkcs7.detached</c>), the default.</item>
/// <item><c>BB</c> - PAdES baseline (<c>ETSI.CAdES.detached</c> + signing-certificate-v2).</item>
/// <item><c>BT</c> - <c>BB</c> plus an RFC 3161 signature timestamp (requires <see cref="SignatureSettings.TimestampUrl"/>).</item>
/// </list>
/// </summary>
public enum PadesLevel
{
    None,
    BB,
    BT,
}

/// <summary>
/// Configuration for a BonniePDF digital signature. Provide either a
/// PEM-encoded certificate + PKCS#8 key, or a PKCS#12 (<c>.pfx</c>) blob +
/// password. Everything else is optional metadata.
/// </summary>
public sealed class SignatureSettings
{
    /// <summary>Signing algorithm. Default <see cref="SigningAlgorithm.Sha256Rsa"/>.</summary>
    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.Sha256Rsa;

    /// <summary>X.509 signer certificate, PEM-encoded. Used with <see cref="PrivateKeyPem"/>.</summary>
    public string CertificatePem { get; set; }

    /// <summary>PKCS#8 private key, PEM-encoded. Used with <see cref="CertificatePem"/>.</summary>
    public string PrivateKeyPem { get; set; }

    /// <summary>PKCS#12 (<c>.pfx</c>/<c>.p12</c>) container holding cert + key.</summary>
    public byte[] Pkcs12 { get; set; }

    /// <summary>Password for <see cref="Pkcs12"/>.</summary>
    public string Pkcs12Password { get; set; }

    /// <summary>Optional intermediate certificate chain (PEM), leaf-to-root.</summary>
    public string[] CertificateChainPem { get; set; }

    /// <summary>Optional reason, e.g. "Approved".</summary>
    public string Reason { get; set; }

    /// <summary>Optional location, e.g. "London, UK".</summary>
    public string Location { get; set; }

    /// <summary>Optional contact info (email or phone).</summary>
    public string ContactInfo { get; set; }

    /// <summary>Optional signer name, written to the <c>/Name</c> entry.</summary>
    public string Name { get; set; }

    /// <summary>Signing time. Defaults to the current time at signing.</summary>
    public DateTimeOffset? SigningTime { get; set; }

    /// <summary>PAdES baseline level (default <see cref="PadesLevel.None"/>).</summary>
    public PadesLevel PadesLevel { get; set; } = Level.None;

    /// <summary>
    /// RFC 3161 Time-Stamp Authority URL. When set, a signature timestamp is
    /// embedded. Required for <see cref="PadesLevel.BT"/>.
    /// </summary>
    public string TimestampUrl { get; set; }

    /// <summary>
    /// Optional HTTP transport for timestamping: given the TSA URL and the DER
    /// request bytes, returns the DER response bytes. Defaults to a shared
    /// <see cref="System.Net.Http.HttpClient"/>.
    /// </summary>
    public Func<string, byte[], CancellationToken, Task<byte[]>> HttpClient { get; set; }

    /// <summary>When set, produces a <b>visible</b> signature with this appearance.</summary>
    public SignatureAppearance Appearance { get; set; }

    /// <summary>
    /// Commercial licence key (the <c>BPDF1.…</c> token). Optional: if omitted,
    /// the key is resolved from <see cref="License.Key"/>, the
    /// <c>BONNIEPDF_LICENSE_KEY</c> env var, or a <c>bonniepdf.license</c> file.
    /// With no key found, signing runs in evaluation mode (a one-time warning).
    /// A present-but-invalid key is always an error. See <c>LICENSING.md</c>.
    /// </summary>
    public string License { get; set; }

    /// <summary>
    /// Require a valid licence: when <c>true</c> (or env
    /// <c>BONNIEPDF_LICENSE_REQUIRE=1</c>), signing without a key throws instead
    /// of falling back to evaluation mode.
    /// </summary>
    public bool RequireLicense { get; set; }

    internal bool IsPades => PadesLevel != Level.None;
    internal bool WantsTimestamp => !string.IsNullOrEmpty(TimestampUrl);

    internal void Validate()
    {
        bool hasPem = !string.IsNullOrEmpty(CertificatePem) && !string.IsNullOrEmpty(PrivateKeyPem);
        bool hasPfx = Pkcs12 is { Length: > 0 };
        if (!hasPem && !hasPfx)
        {
            throw new ArgumentException(
                "Provide either CertificatePem + PrivateKeyPem, or a Pkcs12 blob.");
        }
        if (PadesLevel == Level.BT && string.IsNullOrEmpty(TimestampUrl))
        {
            throw new ArgumentException("PadesLevel.BT requires a TimestampUrl.");
        }
    }
}
