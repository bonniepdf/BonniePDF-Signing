import { SignatureSettings, normalizeSettings } from './SignatureSettings';
import { SigningAlgorithm } from './SigningAlgorithm';

/**
 * Fluent builder for {@link SignatureSettings}, mirroring core's
 * `EncryptionOptions`. All setters return `this` for chaining; call
 * {@link build} to produce the settings object passed to `signPdf`.
 */
export class SignatureOptions {
  private readonly settings: Partial<SignatureSettings> = {};

  /** Sets the PEM-encoded X.509 signer certificate. */
  withCertificate(certificatePem: string): this {
    this.settings.certificatePem = certificatePem;
    return this;
  }

  /** Sets the PEM-encoded PKCS#8 private key. */
  withPrivateKey(privateKeyPem: string): this {
    this.settings.privateKeyPem = privateKeyPem;
    return this;
  }

  /** Sets the PEM-encoded certificate and PKCS#8 private key together. */
  withPem(certificatePem: string, privateKeyPem: string): this {
    this.settings.certificatePem = certificatePem;
    this.settings.privateKeyPem = privateKeyPem;
    return this;
  }

  /**
   * Sets a PKCS#12 (`.pfx`/`.p12`) container + password as an alternative to
   * separate PEM cert and key. Modern PBES2 (AES) containers only.
   */
  withPkcs12(pkcs12: Uint8Array, password = ''): this {
    this.settings.pkcs12 = pkcs12;
    this.settings.pkcs12Password = password;
    return this;
  }

  /** Sets the optional intermediate certificate chain (PEM). */
  withChain(certificateChainPem: string[]): this {
    this.settings.certificateChainPem = certificateChainPem;
    return this;
  }

  /** Sets the optional signing reason. */
  withReason(reason: string): this {
    this.settings.reason = reason;
    return this;
  }

  /** Sets the optional signing location. */
  withLocation(location: string): this {
    this.settings.location = location;
    return this;
  }

  /** Sets the optional contact info. */
  withContactInfo(contactInfo: string): this {
    this.settings.contactInfo = contactInfo;
    return this;
  }

  /** Sets the optional signer name. */
  withName(name: string): this {
    this.settings.name = name;
    return this;
  }

  /** Sets an explicit signing time (defaults to now). */
  withSigningTime(signingTime: Date): this {
    this.settings.signingTime = signingTime;
    return this;
  }

  /** Selects the signing algorithm (default {@link SigningAlgorithm.Sha256Rsa}). */
  usingAlgorithm(algorithm: SigningAlgorithm): this {
    this.settings.algorithm = algorithm;
    return this;
  }

  /**
   * Selects the PAdES baseline level (`'b-b'`, `'b-t'`, `'b-lt'`, or `'b-lta'`).
   * `'b-t'` and above also require {@link withTimestamp}.
   */
  usingPades(level: NonNullable<SignatureSettings['padesLevel']>): this {
    this.settings.padesLevel = level;
    return this;
  }

  /**
   * Enables an RFC 3161 timestamp from the given TSA. Implies PAdES B-T unless a
   * different level was already chosen.
   */
  withTimestamp(timestampUrl: string, httpClient?: SignatureSettings['httpClient']): this {
    this.settings.timestampUrl = timestampUrl;
    if (httpClient) this.settings.httpClient = httpClient;
    if (!this.settings.padesLevel || this.settings.padesLevel === 'none' || this.settings.padesLevel === 'b-b') {
      this.settings.padesLevel = 'b-t';
    }
    return this;
  }

  /** Sets a separate TSA endpoint for the PAdES B-LTA document timestamp. */
  withDocumentTimestamp(documentTimestampUrl: string): this {
    this.settings.documentTimestampUrl = documentTimestampUrl;
    return this;
  }

  /** Sets the HTTP transport used for timestamping, OCSP, and CRL requests. */
  withHttpClient(httpClient: NonNullable<SignatureSettings['httpClient']>): this {
    this.settings.httpClient = httpClient;
    return this;
  }

  /** Sets caller-supplied validation material to embed for PAdES B-LT and B-LTA. */
  withValidationMaterial(validationMaterial: NonNullable<SignatureSettings['validationMaterial']>): this {
    this.settings.validationMaterial = validationMaterial;
    return this;
  }

  /** Controls whether revocation evidence (OCSP/CRL) is fetched over the network. */
  withFetchRevocation(fetchRevocation: boolean): this {
    this.settings.fetchRevocation = fetchRevocation;
    return this;
  }

  /** Sets the per-call callback receiving the validation material embedded in the DSS. */
  withOnValidationMaterial(onValidationMaterial: NonNullable<SignatureSettings['onValidationMaterial']>): this {
    this.settings.onValidationMaterial = onValidationMaterial;
    return this;
  }

  /** Makes the signature **visible** with the given appearance. */
  withVisibleSignature(appearance: NonNullable<SignatureSettings['appearance']>): this {
    this.settings.appearance = appearance;
    return this;
  }

  /** Builds the {@link SignatureSettings}. Throws if required inputs are missing. */
  build(): SignatureSettings {
    return normalizeSettings({
      algorithm: SigningAlgorithm.Sha256Rsa,
      ...this.settings,
    } as SignatureSettings);
  }
}
