/**
 * Minimal PKCS#12 (.pfx / .p12) reader: extracts the signer certificate (X.509
 * DER) and private key (PKCS#8 DER) so they can feed the same signing path as
 * PEM input.
 *
 * Supports the **modern PBES2** form (PBKDF2 + AES-CBC, HMAC-SHA family) that
 * OpenSSL 3, .NET, and current tooling produce by default. Legacy PKCS#12 PBE
 * (3DES / RC2 with the SHA-1 PKCS#12 KDF) is **not** supported - Web Crypto has
 * no 3DES/RC2 - and yields a clear error asking the caller to re-export with
 * AES (`-keypbe AES-256-CBC -certpbe AES-256-CBC`) or supply PEM instead.
 *
 * All crypto runs on the Web Crypto API, so this stays platform-neutral.
 */
import * as der from './asn1/der';

const OID = {
  data: '1.2.840.113549.1.7.1',
  encryptedData: '1.2.840.113549.1.7.6',
  keyBag: '1.2.840.113549.1.12.10.1.1',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  certBag: '1.2.840.113549.1.12.10.1.3',
  pbes2: '1.2.840.113549.1.5.13',
  pbkdf2: '1.2.840.113549.1.5.12',
  hmacSha1: '1.2.840.113549.2.7',
  hmacSha256: '1.2.840.113549.2.9',
  hmacSha384: '1.2.840.113549.2.10',
  hmacSha512: '1.2.840.113549.2.11',
  aes128Cbc: '2.16.840.1.101.3.4.1.2',
  aes192Cbc: '2.16.840.1.101.3.4.1.22',
  aes256Cbc: '2.16.840.1.101.3.4.1.42',
} as const;

const AES_KEY_LEN: Record<string, number> = {
  [OID.aes128Cbc]: 16,
  [OID.aes192Cbc]: 24,
  [OID.aes256Cbc]: 32,
};

const PRF_HASH: Record<string, string> = {
  [OID.hmacSha1]: 'SHA-1',
  [OID.hmacSha256]: 'SHA-256',
  [OID.hmacSha384]: 'SHA-384',
  [OID.hmacSha512]: 'SHA-512',
};

/** Decode an OBJECT IDENTIFIER node's content to a dotted-decimal string. */
function oidString(bytes: Uint8Array, node: der.DerNode): string {
  const c = bytes.subarray(node.contentStart, node.contentEnd);
  const out: number[] = [Math.floor(c[0] / 40), c[0] % 40];
  let value = 0;
  for (let i = 1; i < c.length; i++) {
    value = value * 128 + (c[i] & 0x7f);
    if (!(c[i] & 0x80)) {
      out.push(value);
      value = 0;
    }
  }
  return out.join('.');
}

function content(bytes: Uint8Array, node: der.DerNode): Uint8Array {
  return bytes.slice(node.contentStart, node.contentEnd);
}

function intValue(bytes: Uint8Array, node: der.DerNode): number {
  let v = 0;
  for (let i = node.contentStart; i < node.contentEnd; i++) v = v * 256 + bytes[i];
  return v;
}

/** Parsed PBES2 parameters. */
interface Pbes2 {
  salt: Uint8Array;
  iterations: number;
  keyLen: number;
  prfHash: string;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * Parse a PBES2 `AlgorithmIdentifier` + ciphertext into the bits needed to run
 * PBKDF2 + AES-CBC. Throws a helpful error for non-PBES2 (legacy) schemes.
 */
function parsePbes2(bytes: Uint8Array, algId: der.DerNode, ciphertext: Uint8Array): Pbes2 {
  const algChildren = der.readChildren(bytes, algId.contentStart, algId.contentEnd);
  const schemeOid = oidString(bytes, algChildren[0]);
  if (schemeOid !== OID.pbes2) {
    throw new Error(
      'unsupported PKCS#12 encryption (legacy PKCS#12 PBE / non-AES). Re-export the ' +
        '.pfx with AES (openssl ... -keypbe AES-256-CBC -certpbe AES-256-CBC), or use PEM input.'
    );
  }
  const params = algChildren[1]; // PBES2-params SEQUENCE { kdf, encryptionScheme }
  const [kdf, enc] = der.readChildren(bytes, params.contentStart, params.contentEnd);

  // keyDerivationFunc: SEQUENCE { OID pbkdf2, PBKDF2-params }
  const kdfChildren = der.readChildren(bytes, kdf.contentStart, kdf.contentEnd);
  if (oidString(bytes, kdfChildren[0]) !== OID.pbkdf2) {
    throw new Error('unsupported PKCS#12 key-derivation function (expected PBKDF2)');
  }
  const pbkdfParams = der.readChildren(bytes, kdfChildren[1].contentStart, kdfChildren[1].contentEnd);
  const salt = content(bytes, pbkdfParams[0]);
  const iterations = intValue(bytes, pbkdfParams[1]);
  // Optional keyLength INTEGER, then optional prf AlgorithmIdentifier (default SHA-1).
  let keyLen = 0;
  let prfHash = 'SHA-1';
  for (let i = 2; i < pbkdfParams.length; i++) {
    const n = pbkdfParams[i];
    if (n.tag === der.Tag.INTEGER) keyLen = intValue(bytes, n);
    else if (n.tag === der.Tag.SEQUENCE) {
      const prfOid = oidString(bytes, der.readChildren(bytes, n.contentStart, n.contentEnd)[0]);
      prfHash = PRF_HASH[prfOid] ?? 'SHA-1';
    }
  }

  // encryptionScheme: SEQUENCE { OID aesXXX-cbc, OCTET STRING iv }
  const encChildren = der.readChildren(bytes, enc.contentStart, enc.contentEnd);
  const encOid = oidString(bytes, encChildren[0]);
  const aesLen = AES_KEY_LEN[encOid];
  if (!aesLen) {
    throw new Error('unsupported PKCS#12 cipher (expected AES-CBC). Re-export with AES or use PEM.');
  }
  if (!keyLen) keyLen = aesLen;
  const iv = content(bytes, encChildren[1]);

  return { salt, iterations, keyLen, prfHash, iv, ciphertext };
}

/** Password bytes as UTF-8 (PBES2) and as PKCS#12 BMPString (UTF-16BE + NUL). */
function passwordVariants(password: string): Uint8Array[] {
  const utf8 = new TextEncoder().encode(password);
  const bmp = new Uint8Array((password.length + 1) * 2); // UTF-16BE, NUL-terminated
  for (let i = 0; i < password.length; i++) {
    const code = password.charCodeAt(i);
    bmp[i * 2] = (code >> 8) & 0xff;
    bmp[i * 2 + 1] = code & 0xff;
  }
  return [utf8, bmp];
}

/** Run PBKDF2 + AES-CBC decrypt, trying both password encodings. */
async function decryptPbes2(p: Pbes2, password: string): Promise<Uint8Array> {
  let lastErr: unknown;
  for (const pw of passwordVariants(password)) {
    try {
      const baseKey = await crypto.subtle.importKey('raw', pw as BufferSource, 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: p.salt as BufferSource, iterations: p.iterations, hash: p.prfHash },
        baseKey,
        p.keyLen * 8
      );
      const aesKey = await crypto.subtle.importKey('raw', bits, { name: 'AES-CBC' }, false, ['decrypt']);
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: p.iv as BufferSource },
        aesKey,
        p.ciphertext as BufferSource
      );
      return new Uint8Array(plain);
    } catch (err) {
      lastErr = err; // wrong password encoding -> bad padding; try the next
    }
  }
  throw new Error(`PKCS#12 decryption failed (wrong password?): ${String(lastErr)}`);
}

/** Result of parsing a PKCS#12 container. */
export interface Pkcs12Contents {
  /** DER bytes of the X.509 signer certificate. */
  certDer: Uint8Array;
  /** DER bytes of the PKCS#8 private key. */
  keyPkcs8Der: Uint8Array;
}

/** Collected, possibly-encrypted SafeBags from one ContentInfo. */
async function readSafeBags(
  bytes: Uint8Array,
  contentInfo: der.DerNode,
  password: string,
  out: { cert?: Uint8Array; key?: Uint8Array }
): Promise<void> {
  const [oidNode, taggedContent] = der.readChildren(bytes, contentInfo.contentStart, contentInfo.contentEnd);
  const type = oidString(bytes, oidNode);

  let safeBagsDer: Uint8Array;
  if (type === OID.data) {
    // [0] EXPLICIT OCTET STRING -> SEQUENCE OF SafeBag
    const octet = der.readChildren(bytes, taggedContent.contentStart, taggedContent.contentEnd)[0];
    safeBagsDer = content(bytes, octet);
  } else if (type === OID.encryptedData) {
    // [0] EXPLICIT EncryptedData { version, EncryptedContentInfo { type, algId, [0] IMPLICIT OCTET STRING } }
    const encData = der.readChildren(bytes, taggedContent.contentStart, taggedContent.contentEnd)[0];
    const eci = der.readChildren(bytes, encData.contentStart, encData.contentEnd)[1];
    const eciChildren = der.readChildren(bytes, eci.contentStart, eci.contentEnd);
    const algId = eciChildren[1];
    const encryptedContent = content(bytes, eciChildren[2]); // [0] IMPLICIT OCTET STRING content
    safeBagsDer = await decryptPbes2(parsePbes2(bytes, algId, encryptedContent), password);
  } else {
    return; // unknown ContentInfo type; skip
  }

  const root = der.readNode(safeBagsDer, 0); // SEQUENCE OF SafeBag
  for (const bag of der.readChildren(safeBagsDer, root.contentStart, root.contentEnd)) {
    const bagChildren = der.readChildren(safeBagsDer, bag.contentStart, bag.contentEnd);
    const bagId = oidString(safeBagsDer, bagChildren[0]);
    const bagValue = bagChildren[1]; // [0] EXPLICIT

    if (bagId === OID.certBag && !out.cert) {
      // CertBag { certId OID, certValue [0] EXPLICIT OCTET STRING }
      const certBag = der.readChildren(safeBagsDer, bagValue.contentStart, bagValue.contentEnd)[0];
      const certBagChildren = der.readChildren(safeBagsDer, certBag.contentStart, certBag.contentEnd);
      const certOctetTagged = certBagChildren[1]; // [0] EXPLICIT
      const certOctet = der.readChildren(safeBagsDer, certOctetTagged.contentStart, certOctetTagged.contentEnd)[0];
      out.cert = content(safeBagsDer, certOctet);
    } else if (bagId === OID.keyBag && !out.key) {
      // Plain PrivateKeyInfo (PKCS#8)
      const pk = der.readChildren(safeBagsDer, bagValue.contentStart, bagValue.contentEnd)[0];
      out.key = der.nodeBytes(safeBagsDer, pk);
    } else if (bagId === OID.pkcs8ShroudedKeyBag && !out.key) {
      // EncryptedPrivateKeyInfo { algId (PBES2), OCTET STRING encryptedData }
      const epki = der.readChildren(safeBagsDer, bagValue.contentStart, bagValue.contentEnd)[0];
      const [algId, ctOctet] = der.readChildren(safeBagsDer, epki.contentStart, epki.contentEnd);
      out.key = await decryptPbes2(parsePbes2(safeBagsDer, algId, content(safeBagsDer, ctOctet)), password);
    }
  }
}

/**
 * Parse a PKCS#12 container and return the signer certificate (DER) and private
 * key (PKCS#8 DER).
 */
export async function parsePkcs12(pfx: Uint8Array, password: string): Promise<Pkcs12Contents> {
  const pfxRoot = der.readNode(pfx, 0); // PFX SEQUENCE
  const pfxChildren = der.readChildren(pfx, pfxRoot.contentStart, pfxRoot.contentEnd);
  // pfxChildren: [version, authSafe ContentInfo, macData?]
  const authSafeCi = pfxChildren[1];
  const [authOid, authTagged] = der.readChildren(pfx, authSafeCi.contentStart, authSafeCi.contentEnd);
  if (oidString(pfx, authOid) !== OID.data) throw new Error('not a password-integrity PKCS#12 file');

  // [0] EXPLICIT OCTET STRING -> AuthenticatedSafe (SEQUENCE OF ContentInfo)
  const authOctet = der.readChildren(pfx, authTagged.contentStart, authTagged.contentEnd)[0];
  const authSafe = content(pfx, authOctet);
  const authRoot = der.readNode(authSafe, 0);

  const found: { cert?: Uint8Array; key?: Uint8Array } = {};
  for (const ci of der.readChildren(authSafe, authRoot.contentStart, authRoot.contentEnd)) {
    await readSafeBags(authSafe, ci, password, found);
  }

  if (!found.cert) throw new Error('no certificate found in PKCS#12 file');
  if (!found.key) throw new Error('no private key found in PKCS#12 file');
  return { certDer: found.cert, keyPkcs8Der: found.key };
}
