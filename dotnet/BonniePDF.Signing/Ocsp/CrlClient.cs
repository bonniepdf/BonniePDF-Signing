using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Http;

namespace BonniePDF.Signing.Ocsp;

/// <summary>
/// Certificate revocation lists: fetch the list a certificate points at, so a
/// PAdES B-LT signature can carry it.
/// </summary>
/// <remarks>
/// A CRL is the fallback where a certificate offers no OCSP responder, and some
/// validation policies want both. As with OCSP, the bytes are stored verbatim
/// and interpreted by the validator, not here.
/// </remarks>
internal static class CrlClient
{
    /// <summary>Fetch one CRL and return it as DER, accepting a PEM-armoured response.</summary>
    public static async Task<byte[]> FetchAsync(string url, SigningHttpClient httpClient, CancellationToken ct)
    {
        byte[] body = await SigningHttp.FetchAsync(
            httpClient,
            new SigningHttpRequest { Url = url, Method = HttpMethod.Get, Accept = "application/pkix-crl" },
            "CRL download",
            ct).ConfigureAwait(false);

        return Normalize(body);
    }

    /// <summary>
    /// Accept either DER or PEM.
    /// </summary>
    /// <remarks>
    /// Distribution points are usually configured to serve DER, but a
    /// misconfigured one serving PEM is common enough - and silently embedding
    /// base64 text where a validator expects DER fails much later and much less
    /// clearly than converting it here.
    /// </remarks>
    public static byte[] Normalize(byte[] body)
    {
        if (body.Length > 0 && body[0] == 0x30) return body; // DER SEQUENCE

        string head = Encoding.ASCII.GetString(body, 0, Math.Min(body.Length, 64));
        if (head.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            string text = Encoding.ASCII.GetString(body);
            int start = text.IndexOf("-----BEGIN", StringComparison.Ordinal);
            int firstLineEnd = text.IndexOf('\n', start);
            int end = text.IndexOf("-----END", StringComparison.Ordinal);
            if (firstLineEnd > 0 && end > firstLineEnd)
            {
                string base64 = text[(firstLineEnd + 1)..end].Replace("\r", string.Empty, StringComparison.Ordinal)
                    .Replace("\n", string.Empty, StringComparison.Ordinal);
                return Convert.FromBase64String(base64);
            }
        }
        throw new CryptographicException("CRL download returned neither DER nor PEM");
    }
}
