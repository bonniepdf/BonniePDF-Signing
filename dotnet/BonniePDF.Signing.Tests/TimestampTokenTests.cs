using System;
using System.Security.Cryptography;
using BonniePDF.Signing.Asn1;
using BonniePDF.Signing.TestSupport;
using BonniePDF.Signing.Timestamp;
using Xunit;

namespace BonniePDF.Signing.Tests;

/// <summary>
/// RFC 3161 section 2.4.2: a token is accepted only if it answers the request
/// that was sent - same hash algorithm and imprint, and the nonce echoed back.
/// </summary>
/// <remarks>Mirrors the checkTimeStampToken cases in pades.test.ts.</remarks>
public sealed class TimestampTokenTests : IDisposable
{
    private static readonly byte[] Imprint = Filled(7);
    private static readonly byte[] Nonce = [0x80, 1, 2, 3];

    private readonly TestPki.Identity _ca = TestPki.IssueCa("BonniePDF Test CA");
    private readonly TestPki.Identity _tsaIdentity;
    private readonly TestPki.TestTsa _tsa;

    public TimestampTokenTests()
    {
        _tsaIdentity = TestPki.Issue("BonniePDF Test TSA", _ca);
        _tsa = new TestPki.TestTsa(_tsaIdentity);
    }

    public void Dispose()
    {
        _ca.Dispose();
        _tsaIdentity.Dispose();
    }

    private static byte[] Filled(byte value)
    {
        var bytes = new byte[32];
        Array.Fill(bytes, value);
        return bytes;
    }

    private byte[] TokenFor(byte[] request) => Rfc3161Client.ExtractToken(_tsa.Respond(request));

    [Fact]
    public void AcceptsATokenThatAnswersTheRequest()
    {
        byte[] token = TokenFor(Rfc3161Client.BuildRequest(Imprint, HashAlgorithmName.SHA256, Nonce));
        Rfc3161Client.CheckToken(token, HashAlgorithmName.SHA256, Imprint, Nonce);
    }

    [Fact]
    public void RejectsATokenForADifferentImprint()
    {
        byte[] token = TokenFor(Rfc3161Client.BuildRequest(Filled(8), HashAlgorithmName.SHA256, Nonce));
        var e = Assert.Throws<CryptographicException>(
            () => Rfc3161Client.CheckToken(token, HashAlgorithmName.SHA256, Imprint, Nonce));
        Assert.Contains("imprint", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsATokenForADifferentHashAlgorithm()
    {
        byte[] token = TokenFor(Rfc3161Client.BuildRequest(Imprint, HashAlgorithmName.SHA384, Nonce));
        var e = Assert.Throws<CryptographicException>(
            () => Rfc3161Client.CheckToken(token, HashAlgorithmName.SHA256, Imprint, Nonce));
        Assert.Contains("hash algorithm", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsATokenThatEchoesADifferentNonceAsAReplayedResponseWould()
    {
        byte[] token = TokenFor(Rfc3161Client.BuildRequest(Imprint, HashAlgorithmName.SHA256, [9, 9]));
        var e = Assert.Throws<CryptographicException>(
            () => Rfc3161Client.CheckToken(token, HashAlgorithmName.SHA256, Imprint, Nonce));
        Assert.Contains("different nonce", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsATokenThatCarriesNoNonce()
    {
        byte[] withoutNonce = Der.Sequence(
            Der.IntegerSmall(1),
            Der.Sequence(Der.Sequence(Der.Oid("2.16.840.1.101.3.4.2.1"), Der.Null()), Der.OctetString(Imprint)));
        byte[] token = TokenFor(withoutNonce);
        var e = Assert.Throws<CryptographicException>(
            () => Rfc3161Client.CheckToken(token, HashAlgorithmName.SHA256, Imprint, Nonce));
        Assert.Contains("no nonce", e.Message, StringComparison.Ordinal);
    }
}
