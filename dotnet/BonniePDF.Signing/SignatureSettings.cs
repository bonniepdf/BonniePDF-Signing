using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Http;
using BonniePDF.Signing.Validation;
// Alias the enum so it can be referenced inside SignatureSettings, whose
// `PadesLevel` property otherwise shadows the type name.
using Level = BonniePDF.Signing.PadesLevel;

namespace BonniePDF.Signing;

/// <summary>
/// PAdES baseline level (ETSI EN 319 142-1). Each level is a superset of the one
/// before it.
/// </summary>
/// <remarks>
/// Levels above <see cref="BT"/> are about surviving time, not about stronger
/// cryptography. Pick <see cref="BLT"/> when the document must be checkable
/// after the signer's certificate expires, and <see cref="BLTA"/> when it must
/// outlive the algorithms themselves - archival retention, long-dated contracts,
/// regulated record-keeping.
/// </remarks>
public enum PadesLevel
{
    /// <summary>Legacy Adobe signature (<c>adbe.pkcs7.detached</c>), the default.</summary>
    None,

    /// <summary>PAdES baseline (<c>ETSI.CAdES.detached</c> + signing-certificate-v2).</summary>
    BB,

    /// <summary>
    /// <see cref="BB"/> plus an RFC 3161 signature timestamp, proving <i>when</i>
    /// the signature was made. Requires <see cref="SignatureSettings.TimestampUrl"/>.
    /// </summary>
    BT,

    /// <summary>
    /// <see cref="BT"/> plus the certificate chain and revocation evidence,
    /// stored in the document's Document Security Store so the signature still
    /// verifies once the certificates have expired or the responders are gone.
    /// </summary>
    BLT,

    /// <summary>
    /// <see cref="BLT"/> plus a document timestamp over the whole file, DSS
    /// included. This is the level that can be <i>renewed</i>: a fresh document
    /// timestamp applied before the previous one's algorithms weaken extends the
    /// life of the evidence indefinitely.
    /// </summary>
    BLTA,
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
    /// Optional HTTP transport for every network call this package makes -
    /// timestamping, OCSP, and CRL retrieval. Defaults to a shared
    /// <see cref="System.Net.Http.HttpClient"/>.
    /// </summary>
    /// <remarks>
    /// Supply your own to proxy, cache, retry, or audit the requests made on
    /// your behalf, or to reach authorities that are only available from inside
    /// your network.
    /// </remarks>
    public SigningHttpClient HttpClient { get; set; }

    /// <summary>
    /// Validation material to embed, for <see cref="PadesLevel.BLT"/> and
    /// <see cref="PadesLevel.BLTA"/>.
    /// </summary>
    /// <remarks>
    /// Anything supplied here is always embedded. By default the signer also
    /// tries to fetch what the certificates point at - see
    /// <see cref="FetchRevocation"/> to turn that off and rely on this alone.
    /// </remarks>
    public SuppliedValidationMaterial ValidationMaterial { get; set; }

    /// <summary>
    /// Whether to fetch revocation evidence (OCSP, then CRL) for the chain when
    /// building a <see cref="PadesLevel.BLT"/> or <see cref="PadesLevel.BLTA"/>
    /// signature. Default <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// Set it to <see langword="false"/> for an offline or air-gapped signer, or
    /// where your own PKI tooling already produced the evidence and passed it in
    /// <see cref="ValidationMaterial"/>. Collection is best-effort either way:
    /// what could not be gathered is reported, never thrown.
    /// </remarks>
    public bool FetchRevocation { get; set; } = true;

    /// <summary>
    /// Called with the material actually embedded, once a <see cref="PadesLevel.BLT"/>
    /// or <see cref="PadesLevel.BLTA"/> signature has gathered it.
    /// </summary>
    /// <remarks>
    /// Collection is best-effort - a responder that is down does not fail a
    /// signature - so this is how a caller learns that the document carries less
    /// evidence than it asked for. A callback rather than a return value or a
    /// static record, so that two documents signed concurrently in the same
    /// process cannot read each other's.
    /// </remarks>
    public Action<ValidationMaterial> OnValidationMaterial { get; set; }

    /// <summary>
    /// TSA endpoint for the <see cref="PadesLevel.BLTA"/> document timestamp.
    /// Defaults to <see cref="TimestampUrl"/>.
    /// </summary>
    /// <remarks>
    /// Worth setting separately when the archival timestamp should come from a
    /// different authority than the signature timestamp - a common requirement
    /// where the two have different retention guarantees.
    /// </remarks>
    public string DocumentTimestampUrl { get; set; }

    /// <summary>When set, produces a <b>visible</b> signature with this appearance.</summary>
    public SignatureAppearance Appearance { get; set; }

    internal bool IsPades => PadesLevel != Level.None;

    internal bool WantsTimestamp => !string.IsNullOrEmpty(TimestampUrl);

    /// <summary>True for the levels that carry validation material in a DSS.</summary>
    internal bool IsLongTerm => PadesLevel is Level.BLT or Level.BLTA;

    /// <summary>True for the levels that embed an RFC 3161 signature timestamp.</summary>
    internal bool NeedsTimestampAuthority => PadesLevel is Level.BT or Level.BLT or Level.BLTA;

    internal void Validate()
    {
        bool hasPem = !string.IsNullOrEmpty(CertificatePem) && !string.IsNullOrEmpty(PrivateKeyPem);
        bool hasPfx = Pkcs12 is { Length: > 0 };
        if (!hasPem && !hasPfx)
        {
            throw new ArgumentException(
                "Provide either CertificatePem + PrivateKeyPem, or a Pkcs12 blob.");
        }
        if (NeedsTimestampAuthority && string.IsNullOrEmpty(TimestampUrl))
        {
            throw new ArgumentException($"PadesLevel.{PadesLevel} requires a TimestampUrl.");
        }
        if (PadesLevel == Level.BLTA && string.IsNullOrEmpty(TimestampUrl) && string.IsNullOrEmpty(DocumentTimestampUrl))
        {
            throw new ArgumentException("PadesLevel.BLTA requires a TimestampUrl or DocumentTimestampUrl.");
        }
    }
}
