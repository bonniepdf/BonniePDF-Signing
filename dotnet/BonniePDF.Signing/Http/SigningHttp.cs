using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace BonniePDF.Signing.Http;

/// <summary>One outbound request. <see cref="Body"/> is null for a GET.</summary>
public sealed class SigningHttpRequest
{
    public string Url { get; init; }

    public HttpMethod Method { get; init; } = HttpMethod.Post;

    public byte[] Body { get; init; }

    /// <summary>Content type for the request body. Null for a GET.</summary>
    public string ContentType { get; init; }

    /// <summary>Media type the caller will accept back.</summary>
    public string Accept { get; init; }
}

/// <summary>The response, as raw bytes - none of these protocols return text.</summary>
public sealed class SigningHttpResponse
{
    public int Status { get; init; }

    public byte[] Body { get; init; }
}

/// <summary>
/// The HTTP transport the package uses for every network call it makes: RFC 3161
/// timestamping, OCSP, and CRL retrieval.
/// </summary>
/// <remarks>
/// Network I/O goes through one pluggable delegate so the package depends on
/// nothing but the BCL, and so a caller can proxy, cache, retry, or audit every
/// request it makes on their behalf.
/// </remarks>
public delegate Task<SigningHttpResponse> SigningHttpClient(SigningHttpRequest request, CancellationToken cancellationToken);

/// <summary>The default transport and the small helpers built on it.</summary>
public static class SigningHttp
{
    private static readonly HttpClient Shared = new();

    /// <summary>Default transport, built on a shared <see cref="HttpClient"/>.</summary>
    public static async Task<SigningHttpResponse> DefaultAsync(SigningHttpRequest request, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(request.Method, request.Url);
        if (request.Body is not null)
        {
            message.Content = new ByteArrayContent(request.Body);
            if (!string.IsNullOrEmpty(request.ContentType))
            {
                message.Content.Headers.ContentType = new MediaTypeHeaderValue(request.ContentType);
            }
        }
        if (!string.IsNullOrEmpty(request.Accept))
        {
            message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(request.Accept));
        }

        using HttpResponseMessage response = await Shared.SendAsync(message, ct).ConfigureAwait(false);
        byte[] body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        return new SigningHttpResponse { Status = (int)response.StatusCode, Body = body };
    }

    /// <summary>Runs a request and throws on any non-2xx status, naming <paramref name="what"/>.</summary>
    public static async Task<byte[]> FetchAsync(
        SigningHttpClient client, SigningHttpRequest request, string what, CancellationToken ct)
    {
        SigningHttpResponse response = await (client ?? DefaultAsync)(request, ct).ConfigureAwait(false);
        if (response.Status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"{what}: HTTP {response.Status} from {request.Url}");
        }
        return response.Body;
    }
}
