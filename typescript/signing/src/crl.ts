/**
 * Certificate revocation lists: fetch the list a certificate points at, so a
 * PAdES B-LT signature can carry it.
 *
 * A CRL is the fallback where a certificate offers no OCSP responder, and some
 * validation policies want both. As with OCSP, the bytes are stored verbatim and
 * interpreted by the validator, not here.
 */
import { pemToDer } from './pem';
import { HttpClient, fetchBytes } from './http';

/** Fetch one CRL and return it as DER, accepting a PEM-armoured response. */
export async function fetchCrl(url: string, httpClient: HttpClient): Promise<Uint8Array> {
  const body = await fetchBytes(
    httpClient,
    { url, method: 'GET', headers: { Accept: 'application/pkix-crl' } },
    'CRL download'
  );
  return normalizeCrl(body);
}

/**
 * Accept either DER or PEM.
 *
 * Distribution points are usually configured to serve DER, but a
 * misconfigured one serving PEM is common enough - and silently embedding
 * base64 text where a validator expects DER fails much later and much less
 * clearly than converting it here.
 */
export function normalizeCrl(body: Uint8Array): Uint8Array {
  if (body.length > 0 && body[0] === 0x30) return body; // DER SEQUENCE

  let text = '';
  for (const byte of body.subarray(0, Math.min(body.length, 64))) text += String.fromCharCode(byte);
  if (text.includes('-----BEGIN')) {
    let full = '';
    for (const byte of body) full += String.fromCharCode(byte);
    return pemToDer(full);
  }
  throw new Error('CRL download returned neither DER nor PEM');
}
