using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Asn1;
using BonniePDF.Signing.Http;

namespace BonniePDF.Signing.Ocsp;

/// <summary>
/// OCSP (RFC 6960): ask a responder whether a certificate is still valid, and
/// keep the signed answer.
/// </summary>
/// <remarks>
/// For long-term validation the answer itself is the point. A PAdES B-LT
/// signature embeds the responder's DER OCSPResponse in the document's Document
/// Security Store, so a validator years from now can establish that the
/// certificate was good at signing time without asking anyone.
/// <para>
/// This builds the request and checks that the response was granted; it does not
/// verify the responder's signature or interpret the certificate status. That is
/// the validator's job, and doing it here would mean deciding on the spot
/// whether to refuse to sign - a policy call that belongs to the caller.
/// </para>
/// </remarks>
internal static class OcspClient
{
    /// <summary>
    /// SHA-1, still the mandated digest for an OCSP CertID (RFC 6960 §4.1.1).
    /// It identifies a certificate; it signs nothing.
    /// </summary>
    private const string Sha1Oid = "1.3.14.3.2.26";

    private const string BasicResponseOid = "1.3.6.1.5.5.7.48.1.1";

    private static readonly Dictionary<int, string> ResponseStatus = new()
    {
        [0] = "successful",
        [1] = "malformedRequest",
        [2] = "internalError",
        [3] = "tryLater",
        [5] = "sigRequired",
        [6] = "unauthorized",
    };

    /// <summary>
    /// Build the CertID that names the certificate being asked about.
    /// </summary>
    /// <remarks>
    /// CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash OCTET STRING,
    /// issuerKeyHash OCTET STRING, serialNumber }.
    /// </remarks>
    public static byte[] BuildCertId(byte[] certDer, byte[] issuerDer)
    {
        byte[] serialNumber = CertificateExtensions.ExtractSerialNumber(certDer);
        byte[] issuerNameHash = SHA1.HashData(CertificateExtensions.ExtractSubject(issuerDer));
        byte[] issuerKeyHash = SHA1.HashData(CertificateExtensions.ExtractPublicKeyBits(issuerDer));

        return Der.Sequence(
            Der.Sequence(Der.Oid(Sha1Oid), Der.Null()),
            Der.OctetString(issuerNameHash),
            Der.OctetString(issuerKeyHash),
            serialNumber);
    }

    /// <summary>
    /// Build a DER OCSPRequest for one certificate.
    /// </summary>
    /// <remarks>
    /// The request is unsigned, which is the norm: responders answer anonymously
    /// and a signed request would only leak who is asking.
    /// </remarks>
    public static byte[] BuildRequest(byte[] certDer, byte[] issuerDer)
    {
        byte[] certId = BuildCertId(certDer, issuerDer);
        byte[] request = Der.Sequence(certId);
        return Der.Sequence(Der.Sequence(Der.Sequence(request)));
    }

    /// <summary>
    /// Check an OCSPResponse's top-level status and hand back the DER unchanged.
    /// </summary>
    /// <remarks>
    /// The bytes are stored verbatim in the DSS, so this deliberately re-encodes
    /// nothing: a responder's exact signed octets are what a validator needs.
    /// </remarks>
    public static byte[] CheckResponse(byte[] response)
    {
        Der.Node root = Der.Read(response, 0);
        List<Der.Node> children = Der.Children(response, root);
        if (children.Count == 0) throw new CryptographicException("OCSP response is empty");

        byte status = response[children[0].ContentStart];
        if (status != 0)
        {
            string name = ResponseStatus.TryGetValue(status, out string s) ? s : $"status {status}";
            throw new CryptographicException($"OCSP responder returned {name}");
        }

        if (children.Count < 2) throw new CryptographicException("OCSP response carried no responseBytes");

        List<Der.Node> bytesChildren = Der.Children(response, children[1]);
        if (bytesChildren.Count == 0) throw new CryptographicException("OCSP responseBytes is empty");

        List<Der.Node> parts = Der.Children(response, bytesChildren[0]);
        if (parts.Count > 0 && !string.Equals(Der.OidString(response, parts[0]), BasicResponseOid, StringComparison.Ordinal))
        {
            throw new CryptographicException("OCSP response is not a BasicOCSPResponse");
        }
        return response;
    }

    /// <summary>Ask <paramref name="url"/> about a certificate, returning the DER response.</summary>
    public static async Task<byte[]> RequestAsync(
        string url, byte[] certDer, byte[] issuerDer, SigningHttpClient httpClient, CancellationToken ct)
    {
        byte[] request = BuildRequest(certDer, issuerDer);
        byte[] body = await SigningHttp.FetchAsync(
            httpClient,
            new SigningHttpRequest
            {
                Url = url,
                Method = HttpMethod.Post,
                Body = request,
                ContentType = "application/ocsp-request",
                Accept = "application/ocsp-response",
            },
            "OCSP request",
            ct).ConfigureAwait(false);

        return CheckResponse(body);
    }
}
