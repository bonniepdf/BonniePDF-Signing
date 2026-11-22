/**
 * The HTTP transport the package uses for every network call it makes: RFC 3161
 * timestamping, OCSP, and CRL retrieval.
 *
 * Network I/O goes through one pluggable function so the package stays
 * platform-neutral and zero-dependency. The default uses the global `fetch`
 * (Node 18+, browsers, Bun, Deno).
 *
 * **In a browser you will usually need to supply your own.** Timestamp
 * authorities, OCSP responders and CRL distribution points rarely send CORS
 * headers, so requests from page context are blocked; route them through a
 * same-origin proxy and pass it as `settings.httpClient`.
 */

/** One outbound request. `body` is absent for `GET`. */
export interface HttpRequest {
  readonly url: string;
  readonly method: 'GET' | 'POST';
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: Uint8Array;
  readonly signal?: AbortSignal;
}

/** The response, as raw bytes - none of these protocols return text. */
export interface HttpResponse {
  readonly status: number;
  readonly body: Uint8Array;
}

/** Performs one request. Supply your own to proxy, cache, retry, or audit. */
export type HttpClient = (request: HttpRequest) => Promise<HttpResponse>;

/** Default transport, built on the global `fetch`. */
export const defaultHttpClient: HttpClient = async request => {
  if (typeof fetch !== 'function') {
    throw new Error('no global fetch available; supply settings.httpClient');
  }
  const response = await fetch(request.url, {
    method: request.method,
    headers: { ...request.headers },
    body: request.body ? (request.body as BufferSource) : undefined,
    signal: request.signal,
  });
  return { status: response.status, body: new Uint8Array(await response.arrayBuffer()) };
};

/** Runs a request and throws on any non-2xx status, naming `what` in the error. */
export async function fetchBytes(client: HttpClient, request: HttpRequest, what: string): Promise<Uint8Array> {
  request.signal?.throwIfAborted();
  const { status, body } = await client(request);
  if (status < 200 || status >= 300) throw new Error(`${what}: HTTP ${status} from ${request.url}`);
  return body;
}
