/**
 * A throwaway public-key infrastructure for the signed demos: a certificate
 * authority, a signer, an OCSP responder and an RFC 3161 time-stamp authority,
 * all built in-process and discarded when the run ends.
 *
 * The package never ships a private key, so the demos make their own. Nothing
 * here is how you sign in production: there you hold a certificate issued by a
 * real authority (PEM, or a PKCS#12 file) and point `timestampUrl` at a real
 * time-stamp authority. The demos use this so they run anywhere, offline, and
 * so a validator that trusts only the printed CA certificate can check them.
 */
import {
  aiaOcsp,
  basicConstraintsCa,
  crlDistributionPoint,
  generateKeyPair,
  issueCertificate,
  timeStampingKeyUsage,
  TestOcspResponder,
  TestTsa,
  type TestIdentity,
} from '../../tests/helpers/pki';
import type { HttpClient } from '../../src/http';

export const OCSP_URL = 'http://ocsp.test.invalid/ocsp';
export const CRL_URL = 'http://crl.test.invalid/ca.crl';
export const TSA_URL = 'http://tsa.test.invalid/tsr';

export interface DemoPki {
  /** The certificate authority. Trust this certificate to validate the demos. */
  ca: TestIdentity;
  /** Answers the OCSP and time-stamp URLs above in-process, so signing needs no network. */
  httpClient: HttpClient;
  /** Issues a signer certificate from the authority, with OCSP and CRL locations. */
  issueSigner(commonName: string): Promise<TestIdentity>;
}

/** Build a fresh authority, responder and time-stamp authority. */
export async function createDemoPki(): Promise<DemoPki> {
  const ca = await issueCertificate({
    subject: 'BonniePDF Test CA',
    serial: 1,
    subjectKeys: await generateKeyPair(),
    extensions: [basicConstraintsCa()],
  });
  // A real time-stamp authority publishes revocation information like any other
  // certificate; without it a long-term signature cannot reach the LT level.
  const tsaIdentity = await issueCertificate({
    subject: 'BonniePDF Test TSA',
    serial: 3,
    subjectKeys: await generateKeyPair(),
    issuer: ca,
    extensions: [timeStampingKeyUsage(), aiaOcsp(OCSP_URL)],
  });
  const tsa = new TestTsa(tsaIdentity);
  const ocsp = new TestOcspResponder(ca);

  const httpClient: HttpClient = async request => {
    if (request.url === TSA_URL) return { status: 200, body: await tsa.respond(request.body!) };
    if (request.url === OCSP_URL) return { status: 200, body: await ocsp.respond(request.body!) };
    return { status: 404, body: new Uint8Array(0) };
  };

  let nextSerial = 10;
  return {
    ca,
    httpClient,
    async issueSigner(commonName: string): Promise<TestIdentity> {
      return issueCertificate({
        subject: commonName,
        serial: nextSerial++,
        subjectKeys: await generateKeyPair(),
        issuer: ca,
        extensions: [aiaOcsp(OCSP_URL), crlDistributionPoint(CRL_URL)],
      });
    },
  };
}
