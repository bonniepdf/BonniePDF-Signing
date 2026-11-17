using System;
using System.Security.Cryptography;

namespace BonniePDF.Signing;

/// <summary>
/// Supported signing algorithms. The names mirror the TypeScript
/// <c>@bonniepdf/signing</c> <c>SigningAlgorithm</c> enum.
/// </summary>
public enum SigningAlgorithm
{
    Sha256Rsa,
    Sha384Rsa,
    Sha512Rsa,
    Sha256Ecdsa,
    Sha384Ecdsa,
}

/// <summary>Resolves the hash and key type for a <see cref="SigningAlgorithm"/>.</summary>
internal static class SigningAlgorithmInfo
{
    public static HashAlgorithmName HashName(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.Sha256Rsa or SigningAlgorithm.Sha256Ecdsa => HashAlgorithmName.SHA256,
        SigningAlgorithm.Sha384Rsa or SigningAlgorithm.Sha384Ecdsa => HashAlgorithmName.SHA384,
        SigningAlgorithm.Sha512Rsa => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    /// <summary>Digest algorithm OID, for the CMS <c>digestAlgorithm</c> identifier.</summary>
    public static string DigestOid(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.Sha256Rsa or SigningAlgorithm.Sha256Ecdsa => "2.16.840.1.101.3.4.2.1",
        SigningAlgorithm.Sha384Rsa or SigningAlgorithm.Sha384Ecdsa => "2.16.840.1.101.3.4.2.2",
        SigningAlgorithm.Sha512Rsa => "2.16.840.1.101.3.4.2.3",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };
}
