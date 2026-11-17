using System;
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
            Der.IntegerFromBytes(nonce),
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

        return ExtractToken(response);
    }
}
