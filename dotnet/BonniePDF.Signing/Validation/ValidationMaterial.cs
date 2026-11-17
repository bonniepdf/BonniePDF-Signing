using System.Collections.Generic;

namespace BonniePDF.Signing.Validation;

/// <summary>The DER blobs a Document Security Store holds.</summary>
public sealed class ValidationMaterial
{
    /// <summary>Certificates: the signer, its issuers, and any responder certificates.</summary>
    public List<byte[]> Certificates { get; } = [];

    /// <summary>DER OCSPResponse blobs, exactly as the responders returned them.</summary>
    public List<byte[]> OcspResponses { get; } = [];

    /// <summary>DER CertificateList (CRL) blobs.</summary>
    public List<byte[]> Crls { get; } = [];

    /// <summary>
    /// What could not be collected, one human-readable line each.
    /// </summary>
    /// <remarks>
    /// Empty on a clean run. A non-empty list does not mean the signature is
    /// invalid - it means the document carries less evidence than it might,
    /// which is a policy question rather than a signing error.
    /// </remarks>
    public List<string> Problems { get; } = [];
}

/// <summary>Material the caller already holds, merged with (or instead of) what gets fetched.</summary>
public sealed class SuppliedValidationMaterial
{
    /// <summary>Extra certificates to embed.</summary>
    public IReadOnlyList<byte[]> Certificates { get; set; }

    /// <summary>DER OCSPResponse blobs the caller obtained elsewhere.</summary>
    public IReadOnlyList<byte[]> OcspResponses { get; set; }

    /// <summary>DER CRL blobs the caller obtained elsewhere.</summary>
    public IReadOnlyList<byte[]> Crls { get; set; }
}
