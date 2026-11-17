/**
 * Test-only CMS verifier. Parses a `SignedData` envelope produced by the
 * package and verifies the signer's signature over the signed attributes
 * against the embedded certificate, using Web Crypto. This is the
 * cross-validation that stands in for `pdfsig` in CI.
 */
import * as der from '../../src/asn1/der';
import { extractSubjectPublicKeyInfo } from '../../src/asn1/x509';
import { pemToDer } from '../../src/pem';
import { indexOfAscii } from '../../src/pdf';

const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

function oidString(bytes: Uint8Array, node: der.DerNode): string {
  const content = bytes.subarray(node.contentStart, node.contentEnd);
  const out: number[] = [Math.floor(content[0] / 40), content[0] % 40];
  let value = 0;
  for (let i = 1; i < content.length; i++) {
    value = value * 128 + (content[i] & 0x7f);
    if (!(content[i] & 0x80)) {
      out.push(value);
      value = 0;
    }
  }
  return out.join('.');
}

export interface ParsedCms {
  contentTypeOid: string;
  signedAttrsSet: Uint8Array; // re-tagged SET OF for verification
  signature: Uint8Array;
  messageDigest: Uint8Array;
}

export function parseCms(cms: Uint8Array): ParsedCms {
  const root = der.readNode(cms, 0);
  const ci = der.readChildren(cms, root.contentStart, root.contentEnd);
  const contentTypeOid = oidString(cms, ci[0]);

  const explicit = ci[1]; // [0] EXPLICIT SignedData
  const sd = der.readChildren(cms, explicit.contentStart, explicit.contentEnd)[0];
  const sdChildren = der.readChildren(cms, sd.contentStart, sd.contentEnd);
  // SignedData has two SETs: digestAlgorithms (first) and signerInfos (last).
  const sets = sdChildren.filter(n => n.tag === 0x31);
  const signerInfos = sets[sets.length - 1];
  const signerInfo = der.readChildren(cms, signerInfos.contentStart, signerInfos.contentEnd)[0];
  const si = der.readChildren(cms, signerInfo.contentStart, signerInfo.contentEnd);

  const signedAttrsNode = si.find(n => n.tag === 0xa0)!; // [0] IMPLICIT
  const signatureNode = si.filter(n => n.tag === 0x04).pop()!; // signature OCTET STRING
  const signature = cms.slice(signatureNode.contentStart, signatureNode.contentEnd);

  // Re-tag the implicit [0] as an explicit SET OF (0x31) for verification.
  const attrsContent = cms.subarray(signedAttrsNode.contentStart, signedAttrsNode.contentEnd);
  const signedAttrsSet = der.tlv(0x31, attrsContent);

  // Find the messageDigest attribute value.
  let messageDigest = new Uint8Array(0);
  for (const attr of der.readChildren(cms, signedAttrsNode.contentStart, signedAttrsNode.contentEnd)) {
    const parts = der.readChildren(cms, attr.contentStart, attr.contentEnd);
    if (oidString(cms, parts[0]) === OID_MESSAGE_DIGEST) {
      const valueSet = parts[1];
      const value = der.readChildren(cms, valueSet.contentStart, valueSet.contentEnd)[0];
      messageDigest = cms.slice(value.contentStart, value.contentEnd);
    }
  }

  return { contentTypeOid, signedAttrsSet, signature, messageDigest };
}

/** DER ECDSA-Sig-Value -> raw IEEE-P1363 r||s for Web Crypto verify. */
function ecdsaDerToP1363(sig: Uint8Array, size: number): Uint8Array {
  const seq = der.readNode(sig, 0);
  const [r, s] = der.readChildren(sig, seq.contentStart, seq.contentEnd);
  const out = new Uint8Array(size * 2);
  const put = (node: der.DerNode, offset: number) => {
    let bytes = sig.subarray(node.contentStart, node.contentEnd);
    if (bytes.length > size) bytes = bytes.subarray(bytes.length - size); // strip sign byte
    out.set(bytes, offset + (size - bytes.length));
  };
  put(r, 0);
  put(s, size);
  return out;
}

/** Verify the CMS signature against the certificate. */
export async function verifyCms(
  cms: Uint8Array,
  certPem: string,
  alg: { hashName: string; keyType: 'rsa' | 'ec'; curveSize?: number }
): Promise<boolean> {
  const parsed = parseCms(cms);
  const spki = extractSubjectPublicKeyInfo(pemToDer(certPem));

  if (alg.keyType === 'rsa') {
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: alg.hashName }, false, [
      'verify',
    ]);
    return crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, parsed.signature, parsed.signedAttrsSet);
  }

  const namedCurve = alg.hashName === 'SHA-384' ? 'P-384' : 'P-256';
  const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve }, false, ['verify']);
  const raw = ecdsaDerToP1363(parsed.signature, alg.curveSize ?? 32);
  return crypto.subtle.verify({ name: 'ECDSA', hash: alg.hashName }, key, raw, parsed.signedAttrsSet);
}


/**
 * The DER CMS envelope out of a signed PDF's first `/Contents` entry, with the
 * zero padding after it trimmed off.
 */
export function readContents(bytes: Uint8Array): Uint8Array {
  const tag = indexOfAscii(bytes, '/Contents <');
  const open = indexOfAscii(bytes, '<', tag);
  const close = indexOfAscii(bytes, '>', open);

  let hex = '';
  for (let i = open + 1; i < close; i++) hex += String.fromCharCode(bytes[i]);
  const all = new Uint8Array(hex.length / 2);
  for (let i = 0; i < all.length; i++) all[i] = parseInt(hex.substr(i * 2, 2), 16);

  return all.slice(0, der.readNode(all, 0).end);
}

/** Does the SignerInfo's signed or unsigned attributes contain the given OID? */
export function signedAttrsContainOid(cms: Uint8Array, oidDotted: string): boolean {
  const root = der.readNode(cms, 0);
  const ci = der.readChildren(cms, root.contentStart, root.contentEnd);
  const sd = der.readChildren(cms, ci[1].contentStart, ci[1].contentEnd)[0];
  const sdc = der.readChildren(cms, sd.contentStart, sd.contentEnd);
  const signerInfos = sdc.filter(n => n.tag === 0x31).pop()!;
  const si = der.readChildren(cms, signerInfos.contentStart, signerInfos.contentEnd)[0];
  const fields = der.readChildren(cms, si.contentStart, si.contentEnd);
  const wanted = der.oid(oidDotted);

  for (const tag of [0xa0, 0xa1]) {
    const attrsNode = fields.find(n => n.tag === tag);
    if (!attrsNode) continue;
    for (const attr of der.readChildren(cms, attrsNode.contentStart, attrsNode.contentEnd)) {
      const typeOid = der.readChildren(cms, attr.contentStart, attr.contentEnd)[0];
      const bytes = cms.slice(typeOid.start, typeOid.end);
      if (bytes.length === wanted.length && bytes.every((b, i) => b === wanted[i])) return true;
    }
  }
  return false;
}
