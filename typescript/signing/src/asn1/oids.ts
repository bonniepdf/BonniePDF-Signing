/**
 * Object Identifier constants needed to build a CMS `SignedData` envelope
 * (RFC 5652) and to describe digest / signature algorithms.
 */
export const Oids = {
  // PKCS#7 / CMS content types (RFC 5652 §4)
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',

  // CMS signed-attribute types (RFC 5652 §11)
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',

  // ESS signing-certificate-v2 signed attribute (RFC 5035) - required by
  // CAdES / PAdES baseline (ETSI EN 319 122 / 319 142) to bind the signature
  // to a specific signer certificate.
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',

  // RFC 3161 signature-timestamp unsigned attribute (CAdES/PAdES B-T).
  signatureTimeStampToken: '1.2.840.113549.1.9.16.2.14',

  // Digest algorithms (NIST)
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',

  // RSA signature algorithm (PKCS#1) - rsaEncryption, used as the
  // signatureAlgorithm identifier for RSASSA-PKCS1-v1_5 in CMS SignerInfo.
  rsaEncryption: '1.2.840.113549.1.1.1',

  // ECDSA signature algorithms (X9.62 / RFC 5758)
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  ecdsaWithSha384: '1.2.840.10045.4.3.3',
} as const;
