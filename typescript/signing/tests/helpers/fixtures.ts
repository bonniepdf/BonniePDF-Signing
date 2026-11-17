/**
 * The signer identities the signing tests use, generated at test time.
 *
 * Nothing here is committed: each run makes a fresh RSA and EC key, a
 * self-signed certificate for each, and three PKCS#12 containers - a modern
 * PBES2/AES one for each key, and a legacy 3DES one the reader must refuse with
 * a clear error. The containers are real PKCS#12 (RFC 7292), with a valid MAC,
 * so `openssl pkcs12 -info` reads them as it would a file from any other tool.
 *
 * The containers are built with `node:crypto` because Web Crypto has no 3DES
 * and no PKCS#12 key derivation. Tests run on Node, so that is fine here; the
 * package itself stays on Web Crypto.
 */
import { createCipheriv, createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import * as der from '../../src/asn1/der';
import { basicConstraintsCa, commonName, generateKeyPair, issueCertificate, toPem } from './pki';

/** The password every generated container uses. */
export const PFX_PASSWORD = 'pfxpw';

export interface SigningFixtures {
  certRsa: string;
  keyRsa: string;
  certEc: string;
  keyEc: string;
  /** RSA key and certificate in a PBES2 (PBKDF2 + AES-256-CBC) container. */
  pfxRsa: Uint8Array;
  /** EC key and certificate in a PBES2 container. */
  pfxEc: Uint8Array;
  /** RSA key and certificate in a legacy pbeWithSHAAnd3-KeyTripleDES-CBC container. */
  pfxLegacy: Uint8Array;
}

let cached: Promise<SigningFixtures> | undefined;

/** The fixtures for this test file, generated once on first use. */
export function signingFixtures(): Promise<SigningFixtures> {
  return (cached ??= build());
}

async function build(): Promise<SigningFixtures> {
  const rsa = await issueCertificate({
    subject: 'BonniePDF Test Signer',
    serial: 1,
    subjectKeys: await generateKeyPair(),
    extensions: [basicConstraintsCa()],
  });
  const ec = await issueEcCertificate('BonniePDF EC Signer', 2);

  return {
    certRsa: rsa.certPem,
    keyRsa: rsa.keyPem,
    certEc: ec.certPem,
    keyEc: ec.keyPem,
    pfxRsa: buildPfx(rsa.certDer, rsa.keys.pkcs8, 'pbes2'),
    pfxEc: buildPfx(ec.certDer, ec.pkcs8, 'pbes2'),
    pfxLegacy: buildPfx(rsa.certDer, rsa.keys.pkcs8, 'legacy'),
  };
}

// ─────────────────────────── EC certificate ────────────────────────────

const OID_EC_PUBLIC_KEY_SIGNATURE = '1.2.840.10045.4.3.2'; // ecdsa-with-SHA256

/** A self-signed P-256 certificate, signed with ECDSA over SHA-256. */
async function issueEcCertificate(
  subject: string,
  serial: number
): Promise<{ certDer: Uint8Array; certPem: string; keyPem: string; pkcs8: Uint8Array }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));

  const algorithm = der.sequence(der.oid(OID_EC_PUBLIC_KEY_SIGNATURE));
  const name = commonName(subject);
  const tbs = der.sequence(
    der.contextConstructed(0, der.integer(2)),
    der.integer(serial),
    algorithm,
    name,
    der.sequence(der.utcTime(new Date(Date.now() - 86_400_000)), der.utcTime(new Date(Date.now() + 365 * 86_400_000))),
    name,
    spki,
    der.tlv(0xa3, der.sequence(basicConstraintsCa()))
  );

  // Web Crypto returns r || s; X.509 wants SEQUENCE { INTEGER r, INTEGER s }.
  const raw = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, tbs as BufferSource)
  );
  const signature = der.sequence(der.integerFromBytes(raw.subarray(0, 32)), der.integerFromBytes(raw.subarray(32)));
  const certDer = der.sequence(tbs, algorithm, der.bitString(signature));

  return { certDer, certPem: toPem('CERTIFICATE', certDer), keyPem: toPem('PRIVATE KEY', pkcs8), pkcs8 };
}

// ───────────────────────────── PKCS#12 ─────────────────────────────────

const OID = {
  data: '1.2.840.113549.1.7.1',
  encryptedData: '1.2.840.113549.1.7.6',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  certBag: '1.2.840.113549.1.12.10.1.3',
  x509Certificate: '1.2.840.113549.1.9.22.1',
  pbes2: '1.2.840.113549.1.5.13',
  pbkdf2: '1.2.840.113549.1.5.12',
  hmacWithSha256: '1.2.840.113549.2.9',
  aes256Cbc: '2.16.840.1.101.3.4.1.42',
  pbeWithSha1And3DesCbc: '1.2.840.113549.1.12.1.3',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
} as const;

const ITERATIONS = 2048;

type Scheme = 'pbes2' | 'legacy';

/** A password-integrity PFX holding one certificate and its encrypted key. */
function buildPfx(certDer: Uint8Array, pkcs8: Uint8Array, scheme: Scheme): Uint8Array {
  const certBag = der.sequence(
    der.oid(OID.certBag),
    der.contextConstructed(0, der.sequence(der.oid(OID.x509Certificate), der.contextConstructed(0, der.octetString(certDer))))
  );
  const certSafe = encrypt(der.sequence(certBag), scheme);
  const certInfo = der.sequence(
    der.oid(OID.encryptedData),
    der.contextConstructed(
      0,
      der.sequence(der.integer(0), der.sequence(der.oid(OID.data), certSafe.algorithm, der.tlv(0x80, certSafe.ciphertext)))
    )
  );

  const keyCipher = encrypt(pkcs8, scheme);
  const keyBag = der.sequence(
    der.oid(OID.pkcs8ShroudedKeyBag),
    der.contextConstructed(0, der.sequence(keyCipher.algorithm, der.octetString(keyCipher.ciphertext)))
  );
  const keyInfo = der.sequence(der.oid(OID.data), der.contextConstructed(0, der.octetString(der.sequence(keyBag))));

  const authSafe = der.sequence(certInfo, keyInfo);

  // The MAC covers the AuthenticatedSafe, keyed by the PKCS#12 KDF (purpose 3).
  const hash = scheme === 'pbes2' ? 'sha256' : 'sha1';
  const macSalt = randomBytes(8);
  const macKey = pkcs12Kdf(hash, bmpPassword(PFX_PASSWORD), macSalt, 3, ITERATIONS, hash === 'sha256' ? 32 : 20);
  const mac = createHmac(hash, macKey).update(authSafe).digest();
  const macData = der.sequence(
    der.sequence(der.sequence(der.oid(hash === 'sha256' ? OID.sha256 : OID.sha1), der.nullValue()), der.octetString(mac)),
    der.octetString(macSalt),
    der.integer(ITERATIONS)
  );

  return der.sequence(
    der.integer(3),
    der.sequence(der.oid(OID.data), der.contextConstructed(0, der.octetString(authSafe))),
    macData
  );
}

/** Encrypt under PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC) or legacy PKCS#12 3DES. */
function encrypt(plain: Uint8Array, scheme: Scheme): { algorithm: Uint8Array; ciphertext: Uint8Array } {
  const salt = randomBytes(8);
  if (scheme === 'pbes2') {
    const iv = randomBytes(16);
    const key = pbkdf2Sync(PFX_PASSWORD, salt, ITERATIONS, 32, 'sha256');
    const cipher = createCipheriv('aes-256-cbc', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    const kdf = der.sequence(
      der.oid(OID.pbkdf2),
      der.sequence(der.octetString(salt), der.integer(ITERATIONS), der.sequence(der.oid(OID.hmacWithSha256), der.nullValue()))
    );
    const algorithm = der.sequence(
      der.oid(OID.pbes2),
      der.sequence(kdf, der.sequence(der.oid(OID.aes256Cbc), der.octetString(iv)))
    );
    return { algorithm, ciphertext };
  }
  const password = bmpPassword(PFX_PASSWORD);
  const key = pkcs12Kdf('sha1', password, salt, 1, ITERATIONS, 24);
  const iv = pkcs12Kdf('sha1', password, salt, 2, ITERATIONS, 8);
  const cipher = createCipheriv('des-ede3-cbc', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const algorithm = der.sequence(
    der.oid(OID.pbeWithSha1And3DesCbc),
    der.sequence(der.octetString(salt), der.integer(ITERATIONS))
  );
  return { algorithm, ciphertext };
}

/** The password as a NUL-terminated BMPString (UTF-16BE), as the PKCS#12 KDF wants it. */
function bmpPassword(password: string): Buffer {
  const out = Buffer.alloc((password.length + 1) * 2);
  for (let i = 0; i < password.length; i++) out.writeUInt16BE(password.charCodeAt(i), i * 2);
  return out;
}

/** RFC 7292 appendix B.2: the PKCS#12 key-derivation function. */
function pkcs12Kdf(
  hash: 'sha1' | 'sha256',
  password: Uint8Array,
  salt: Uint8Array,
  id: number,
  iterations: number,
  length: number
): Buffer {
  const u = hash === 'sha256' ? 32 : 20;
  const v = 64;
  const repeat = (source: Uint8Array): Buffer => {
    const out = Buffer.alloc(source.length === 0 ? 0 : v * Math.ceil(source.length / v));
    for (let i = 0; i < out.length; i++) out[i] = source[i % source.length];
    return out;
  };
  const diversifier = Buffer.alloc(v, id);
  const input = Buffer.concat([repeat(salt), repeat(password)]);
  const blocks: Buffer[] = [];
  for (let produced = 0; produced < length; produced += u) {
    let a = createHash(hash).update(diversifier).update(input).digest();
    for (let i = 1; i < iterations; i++) a = createHash(hash).update(a).digest();
    blocks.push(a);
    // I_j = (I_j + B + 1) mod 2^(v*8), for every v-byte block of the input.
    const b = Buffer.alloc(v);
    for (let i = 0; i < v; i++) b[i] = a[i % u];
    for (let j = 0; j < input.length; j += v) {
      let carry = 1;
      for (let k = v - 1; k >= 0; k--) {
        const sum = input[j + k] + b[k] + carry;
        input[j + k] = sum & 0xff;
        carry = sum >> 8;
      }
    }
  }
  return Buffer.concat(blocks).subarray(0, length);
}
