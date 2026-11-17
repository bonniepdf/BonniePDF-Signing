using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Asn1;
using BonniePDF.Signing.Http;

namespace BonniePDF.Signing.Timestamp;

/// <summary>
/// RFC 3161 timestamping. Builds a request over the signature value, posts it to
/// the TSA, and returns the DER <c>TimeStampToken</c> to embed as the CMS
/// signature-timestamp unsigned attribute (PAdES B-T).
///
/// The request/response DER is hand-built (mirroring the TypeScript port) so the
/// package depends only on the BCL hashing + HTTP primitives.
/// </summary>
internal static class Rfc3161Client
{
    /// <summary>CMS unsigned-attribute OID for the signature timestamp.</summary>
    public const string SignatureTimeStampOid = "1.2.840.113549.1.9.16.2.14";

    private static string HashOid(HashAlgorithmName hashName)
    {
        if (hashName == HashAlgorithmName.SHA256) return "2.16.840.1.101.3.4.2.1";
        if (hashName == HashAlgorithmName.SHA384) return "2.16.840.1.101.3.4.2.2";
        if (hashName == HashAlgorithmName.SHA512) return "2.16.840.1.101.3.4.2.3";
        throw new ArgumentOutOfRangeException(nameof(hashName));
    }

    private static byte[] Hash(byte[] data, HashAlgorithmName hashName)
    {
        if (hashName == HashAlgorithmName.SHA256) return SHA256.HashData(data);
        if (hashName == HashAlgorithmName.SHA384) return SHA384.HashData(data);
        if (hashName == HashAlgorithmName.SHA512) return SHA512.HashData(data);
        throw new ArgumentOutOfRangeException(nameof(hashName));
    }

    /// <summary>
    /// TimeStampReq ::= SEQUENCE {
    ///   version INTEGER (1),
    ///   messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING },
    ///   nonce INTEGER, certReq BOOLEAN }
    /// </summary>
    internal static byte[] BuildRequest(byte[] imprint, HashAlgorithmName hashName, byte[] nonce)
    {
        byte[] messageImprint = Der.Sequence(
            Der.Sequence(Der.Oid(HashOid(hashName)), Der.Null()),
            Der.OctetString(imprint));
        return Der.Sequence(
            Der.IntegerSmall(1),
            messageImprint,
            Der.IntegerFromBytes(nonce), // nonce: CheckToken requires it echoed back
            Der.Boolean(true)); // certReq TRUE (include TSA cert in the token)
    }

    /// <summary>
    /// Extract the TimeStampToken (a CMS ContentInfo) from a DER TimeStampResp:
    /// SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }, status 0/1 == granted.
    /// </summary>
    internal static byte[] ExtractToken(byte[] response)
    {
        Der.Node root = Der.Read(response, 0);
        System.Collections.Generic.List<Der.Node> children = Der.Children(response, root);
        Der.Node statusNode = Der.Children(response, children[0])[0];
        byte status = response[statusNode.ContentStart];
        if (status != 0 && status != 1) throw new CryptographicException($"TSA rejected the request (PKIStatus {status})");
        if (children.Count < 2) throw new CryptographicException("TSA response contained no timeStampToken");
        Der.Node token = children[1];
        var outp = new byte[token.End - token.Start];
        Buffer.BlockCopy(response, token.Start, outp, 0, outp.Length);
        return outp;
    }

    /// <summary>
    /// Check that a TimeStampToken answers the request that was sent (RFC 3161
    /// §2.4.2): its TSTInfo must carry the requested hash algorithm and imprint,
    /// and echo the request's nonce. Throws otherwise.
    /// </summary>
    /// <remarks>
    /// Without this a token for different data - from a misrouted request, a
    /// misbehaving authority, or a replayed response - would be embedded
    /// silently and only fail when someone came to validate the signature. The
    /// nonce is what makes a replayed response detectable; sending one without
    /// checking it protects nothing.
    /// <para>
    /// This checks the token's content, not its signature: whether to trust the
    /// authority is the validator's decision, made against its own trust anchors.
    /// </para>
    /// </remarks>
    internal static void CheckToken(byte[] token, HashAlgorithmName hashName, byte[] imprint, byte[] nonce)
    {
        List<Der.Node> fields;
        try
        {
            // ContentInfo > [0] > SignedData > encapContentInfo > [0] > OCTET STRING > TSTInfo
            Der.Node signedData = Der.Children(token, Der.Children(token, Der.Read(token, 0))[1])[0];
            Der.Node eContent = Der.Children(token, Der.Children(token, Der.Children(token, signedData)[2])[1])[0];
            fields = Der.Children(token, Der.Read(token, eContent.ContentStart));
        }
        catch (Exception e) when (e is ArgumentOutOfRangeException or IndexOutOfRangeException or InvalidOperationException)
        {
            throw Mismatch("its TSTInfo cannot be read");
        }

        // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime,
        //   accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL, ... }
        List<Der.Node> messageImprint = Der.Children(token, fields[2]);
        Der.Node algorithmOid = Der.Children(token, messageImprint[0])[0];
        if (!Der.NodeBytes(token, algorithmOid).AsSpan().SequenceEqual(Der.Oid(HashOid(hashName))))
            throw Mismatch("different hash algorithm");
        if (!Der.Content(token, messageImprint[1]).AsSpan().SequenceEqual(imprint))
            throw Mismatch("different message imprint");

        Der.Node? echoed = null;
        for (int i = 5; i < fields.Count; i++)
        {
            if (fields[i].Tag == 0x02) { echoed = fields[i]; break; }
        }
        if (echoed is not { } nonceNode) throw Mismatch("no nonce");
        if (!IntegerMagnitude(Der.Content(token, nonceNode)).SequenceEqual(IntegerMagnitude(nonce)))
            throw Mismatch("different nonce");
    }

    /// <summary>A non-negative big-endian integer with its leading zero bytes removed.</summary>
    private static ReadOnlySpan<byte> IntegerMagnitude(byte[] bytes)
    {
        int start = 0;
        while (start < bytes.Length && bytes[start] == 0) start++;
        return bytes.AsSpan(start);
    }

    private static CryptographicException Mismatch(string why) =>
        new($"timestamp token does not answer this request: {why}");

    public static Task<byte[]> GetTokenAsync(
        byte[] signatureValue, HashAlgorithmName hashName, SignatureSettings settings, CancellationToken ct) =>
        GetTokenForDataAsync(signatureValue, hashName, settings.TimestampUrl, settings.HttpClient, ct);

    /// <summary>
    /// Request a timestamp over arbitrary data: the signature value for a
    /// signature timestamp, or the whole covered byte range for a document
    /// timestamp.
    /// </summary>
    public static async Task<byte[]> GetTokenForDataAsync(
        byte[] data, HashAlgorithmName hashName, string url, SigningHttpClient httpClient, CancellationToken ct)
    {
        byte[] imprint = Hash(data, hashName);
        var nonce = new byte[16];
        RandomNumberGenerator.Fill(nonce);
        byte[] request = BuildRequest(imprint, hashName, nonce);

        byte[] response = await SigningHttp.FetchAsync(
            httpClient,
            new SigningHttpRequest
            {
                Url = url,
                Method = HttpMethod.Post,
                Body = request,
                ContentType = "application/timestamp-query",
                Accept = "application/timestamp-reply",
            },
            "timestamp request",
            ct).ConfigureAwait(false);

        byte[] token = ExtractToken(response);
        CheckToken(token, hashName, imprint, nonce);
        return token;
    }
}
