import { Oids } from './asn1/oids';

/**
 * Supported signing algorithms. The names mirror `BonniePDF.Signing`'s
 * .NET `SigningAlgorithm` enum (`Sha256Rsa`, `Sha256Ecdsa`, ...).
 */
export enum SigningAlgorithm {
  Sha256Rsa = 'Sha256Rsa',
  Sha384Rsa = 'Sha384Rsa',
  Sha512Rsa = 'Sha512Rsa',
  Sha256Ecdsa = 'Sha256Ecdsa',
  Sha384Ecdsa = 'Sha384Ecdsa',
}

/** Resolved crypto parameters for a {@link SigningAlgorithm}. */
export interface AlgorithmParams {
  /** Web Crypto digest name, e.g. `'SHA-256'`. */
  readonly hashName: 'SHA-256' | 'SHA-384' | 'SHA-512';
  /** `'rsa'` or `'ec'` - selects the SignerInfo signatureAlgorithm OID. */
  readonly keyType: 'rsa' | 'ec';
  /** Parameters for `crypto.subtle.importKey('pkcs8', ...)`. */
  readonly importParams: RsaHashedImportParams | EcKeyImportParams;
  /** Parameters for `crypto.subtle.sign(...)`. */
  readonly signParams: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  /** OID of the digest algorithm (for `digestAlgorithms` / SignerInfo). */
  readonly digestOid: string;
  /** OID of the signature algorithm (for SignerInfo `signatureAlgorithm`). */
  readonly signatureOid: string;
}

const SHA256: AlgorithmParams['hashName'] = 'SHA-256';
const SHA384: AlgorithmParams['hashName'] = 'SHA-384';
const SHA512: AlgorithmParams['hashName'] = 'SHA-512';

const PARAMS: Record<SigningAlgorithm, AlgorithmParams> = {
  [SigningAlgorithm.Sha256Rsa]: {
    hashName: SHA256,
    keyType: 'rsa',
    importParams: { name: 'RSASSA-PKCS1-v1_5', hash: SHA256 },
    signParams: { name: 'RSASSA-PKCS1-v1_5' },
    digestOid: Oids.sha256,
    signatureOid: Oids.rsaEncryption,
  },
  [SigningAlgorithm.Sha384Rsa]: {
    hashName: SHA384,
    keyType: 'rsa',
    importParams: { name: 'RSASSA-PKCS1-v1_5', hash: SHA384 },
    signParams: { name: 'RSASSA-PKCS1-v1_5' },
    digestOid: Oids.sha384,
    signatureOid: Oids.rsaEncryption,
  },
  [SigningAlgorithm.Sha512Rsa]: {
    hashName: SHA512,
    keyType: 'rsa',
    importParams: { name: 'RSASSA-PKCS1-v1_5', hash: SHA512 },
    signParams: { name: 'RSASSA-PKCS1-v1_5' },
    digestOid: Oids.sha512,
    signatureOid: Oids.rsaEncryption,
  },
  [SigningAlgorithm.Sha256Ecdsa]: {
    hashName: SHA256,
    keyType: 'ec',
    importParams: { name: 'ECDSA', namedCurve: 'P-256' },
    signParams: { name: 'ECDSA', hash: SHA256 },
    digestOid: Oids.sha256,
    signatureOid: Oids.ecdsaWithSha256,
  },
  [SigningAlgorithm.Sha384Ecdsa]: {
    hashName: SHA384,
    keyType: 'ec',
    importParams: { name: 'ECDSA', namedCurve: 'P-384' },
    signParams: { name: 'ECDSA', hash: SHA384 },
    digestOid: Oids.sha384,
    signatureOid: Oids.ecdsaWithSha384,
  },
};

/** Resolve the crypto parameters for a signing algorithm. */
export function getAlgorithmParams(algorithm: SigningAlgorithm): AlgorithmParams {
  const params = PARAMS[algorithm];
  if (!params) throw new Error(`unsupported signing algorithm: ${algorithm}`);
  return params;
}
