/**
 * Gathering the validation material a PAdES B-LT signature carries: the
 * certificate chain, and revocation evidence for it.
 *
 * The point of long-term validation is that the document answers the question on
 * its own. A validator opening it in ten years should not need the issuing CA to
 * still be running an OCSP responder, or the certificate to still be within its
 * validity period - everything needed to conclude "this was good when it was
 * signed" travels inside the file.
 *
 * Collection is best-effort by design. A responder that is down, a distribution
 * point that has moved, a certificate that publishes neither - none of these
 * should abort a signature that is otherwise perfectly valid. Each failure is
 * recorded and reported instead, so the caller can decide whether the material
 * gathered is enough for their policy.
 */
import { caIssuerUrls, crlUrls, extractIssuerName, extractSubject, ocspUrls } from './asn1/extensions';
import { certificatesFromCms } from './cms';
import { fetchCrl } from './crl';
import { HttpClient, fetchBytes } from './http';
import { requestOcsp } from './ocsp';

/** The DER blobs a Document Security Store holds. */
export interface ValidationMaterial {
  /** Certificates: the signer, its issuers, and any responder certificates. */
  certificates: Uint8Array[];
  /** DER `OCSPResponse` blobs, exactly as the responders returned them. */
  ocspResponses: Uint8Array[];
  /** DER `CertificateList` (CRL) blobs. */
  crls: Uint8Array[];
  /**
   * What could not be collected, one human-readable line each.
   *
   * Empty on a clean run. A non-empty list does not mean the signature is
   * invalid - it means the document carries less evidence than it might, which
   * is a policy question rather than a signing error.
   */
  problems: string[];
}

/** Caller-supplied material, merged with (or instead of) what gets fetched. */
export interface SuppliedValidationMaterial {
  certificates?: Uint8Array[];
  ocspResponses?: Uint8Array[];
  crls?: Uint8Array[];
}

/** How hard to work at collecting revocation evidence. */
export interface CollectOptions {
  /** The signer certificate, DER. */
  certDer: Uint8Array;
  /** Intermediates and root, leaf-to-root, DER. */
  chainDer: readonly Uint8Array[];
  /** Transport for OCSP and CRL requests. */
  httpClient: HttpClient;
  /** Material the caller already holds; always included, never re-fetched. */
  supplied?: SuppliedValidationMaterial;
  /**
   * When false, nothing is fetched and only {@link supplied} is used. The honest
   * choice for an air-gapped signer, or where the caller's own PKI tooling has
   * already produced the evidence.
   */
  fetchRevocation?: boolean;
  /**
   * The RFC 3161 token embedded in the signature, if any.
   *
   * Its certificates are added to the material and their revocation is collected
   * too: a long-term signature has to let a validator check the timestamp as
   * well as the signature, and without the authority's own evidence the document
   * falls short of the LT level even though everything else is present.
   */
  timestampToken?: Uint8Array;
  /** Optional cancellation signal forwarded to OCSP and CRL fetches. */
  signal?: AbortSignal;
}

/**
 * Collect the validation material for a certificate chain.
 *
 * Walks leaf-to-root: for each certificate that has an issuer available, asks
 * that certificate's OCSP responder, and falls back to its CRL distribution
 * point when no responder is listed or the responder cannot be reached. The root
 * is not checked - nothing revokes a trust anchor.
 */
export async function collectValidationMaterial(options: CollectOptions): Promise<ValidationMaterial> {
  options.signal?.throwIfAborted();
  const material: ValidationMaterial = {
    certificates: [options.certDer, ...options.chainDer, ...(options.supplied?.certificates ?? [])],
    ocspResponses: [...(options.supplied?.ocspResponses ?? [])],
    crls: [...(options.supplied?.crls ?? [])],
    problems: [],
  };

  const fetchRevocation = options.fetchRevocation !== false;
  const chain = [options.certDer, ...options.chainDer];
  if (fetchRevocation) {
    for (let i = 0; i < chain.length; i++) {
      const issuer = chain[i + 1];
      if (!issuer) {
        // The last certificate in the chain is the trust anchor. Nothing revokes
        // a trust anchor - a validator decides whether to trust it, and there is
        // no issuer above it to ask - so it is not evidence we can or should
        // gather. Stopping here is what keeps `problems` meaningful: a root with
        // no AIA is normal, not a shortfall worth reporting.
        break;
      }
      await collectFor(chain[i], issuer, material, options.httpClient, i, options.signal);
    }
  }

  await collectForTimestamp(options.timestampToken, chain, material, options.httpClient, fetchRevocation, options.signal);

  return material;
}

/**
 * Add the timestamp authority's certificates and collect revocation for them,
 * so a validator can check the timestamp from inside the document.
 *
 * The authority's certificates travel inside the token, so they are read from
 * there rather than supplied by the caller. Their issuer is looked for among the
 * certificates already gathered - in practice the same CA - and where it cannot
 * be found the certificate is still embedded, because a validator that has the
 * certificate and no revocation for it is better off than one missing both.
 */
async function collectForTimestamp(
  timestampToken: Uint8Array | undefined,
  known: readonly Uint8Array[],
  material: ValidationMaterial,
  httpClient: HttpClient,
  fetchRevocation: boolean,
  signal?: AbortSignal
): Promise<void> {
  if (!timestampToken || timestampToken.length === 0) return;

  const tsaCerts = certificatesFromCms(timestampToken);
  if (tsaCerts.length === 0) {
    material.problems.push('timestamp token: carries no certificates for the authority');
    return;
  }

  for (let i = 0; i < tsaCerts.length; i++) {
    const cert = tsaCerts[i];
    if (!material.certificates.some(held => equalBytes(held, cert))) material.certificates.push(cert);

    if (!fetchRevocation) continue;
    const issuer = findIssuer(cert, known) ?? findIssuer(cert, tsaCerts);
    // Self-signed, or an issuer we do not hold: nothing to ask about.
    if (!issuer || equalBytes(issuer, cert)) continue;
    await collectFor(cert, issuer, material, httpClient, -(i + 1), signal);
  }
}

/** The certificate in `pool` that issued `cert`, by subject/issuer name match. */
function findIssuer(cert: Uint8Array, pool: readonly Uint8Array[]): Uint8Array | undefined {
  let issuerName: Uint8Array;
  try {
    issuerName = extractIssuerName(cert);
  } catch {
    return undefined;
  }
  return pool.find(candidate => {
    try {
      return equalBytes(extractSubject(candidate), issuerName);
    } catch {
      return false;
    }
  });
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

async function collectFor(
  subject: Uint8Array,
  issuer: Uint8Array,
  material: ValidationMaterial,
  httpClient: HttpClient,
  index: number,
  signal?: AbortSignal
): Promise<void> {
  const responders = ocspUrls(subject);
  for (const url of responders) {
    try {
      material.ocspResponses.push(await requestOcsp(url, subject, issuer, httpClient, signal));
      return;
    } catch (error) {
      if (signal?.aborted) throw error;
      material.problems.push(`certificate ${index}: OCSP at ${url} failed - ${message(error)}`);
    }
  }
  await collectCrlOnly(subject, material, httpClient, index, responders.length > 0, signal);
}

async function collectCrlOnly(
  subject: Uint8Array,
  material: ValidationMaterial,
  httpClient: HttpClient,
  index: number,
  afterOcspFailure = false,
  signal?: AbortSignal
): Promise<void> {
  const urls = crlUrls(subject);
  if (urls.length === 0) {
    if (!afterOcspFailure) {
      material.problems.push(`certificate ${index}: publishes no OCSP responder and no CRL distribution point`);
    }
    return;
  }
  for (const url of urls) {
    try {
      material.crls.push(await fetchCrl(url, httpClient, signal));
      return;
    } catch (error) {
      if (signal?.aborted) throw error;
      material.problems.push(`certificate ${index}: CRL at ${url} failed - ${message(error)}`);
    }
  }
}

/**
 * Fetch the issuer certificate a certificate's AIA `caIssuers` entry points at.
 *
 * Offered separately rather than folded into collection: completing a chain the
 * caller did not supply changes which certificates the document vouches for, and
 * that should be an explicit act.
 */
export async function fetchIssuerCertificate(
  certDer: Uint8Array,
  httpClient: HttpClient,
  signal?: AbortSignal
): Promise<Uint8Array | undefined> {
  signal?.throwIfAborted();
  for (const url of caIssuerUrls(certDer)) {
    try {
      const body = await fetchBytes(
        httpClient,
        { url, method: 'GET', headers: { Accept: 'application/pkix-cert' }, signal },
        'issuer certificate download'
      );
      if (body.length > 0 && body[0] === 0x30) return body;
    } catch (error) {
      if (signal?.aborted) throw error;
      // Try the next URL; the caller learns nothing useful from a partial failure here.
    }
  }
  return undefined;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
