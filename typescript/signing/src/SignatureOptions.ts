import { SignatureSettings } from './SignatureSettings';
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
   * Selects the PAdES baseline level (`'b-b'` or `'b-t'`). `'b-t'` also needs
   * {@link withTimestamp}.
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
    if (!this.settings.padesLevel || this.settings.padesLevel === 'b-b') this.settings.padesLevel = 'b-t';
    return this;
  }

  /** Makes the signature **visible** with the given appearance. */
  withVisibleSignature(appearance: NonNullable<SignatureSettings['appearance']>): this {
    this.settings.appearance = appearance;
    return this;
  }

  /**
   * Sets the commercial licence key (the `BPDF1.…` token). Optional — if not
   * set here, it is read from `BONNIEPDF_LICENSE_KEY` or `bonniepdf.license`.
   */
  withLicense(license: string): this {
    this.settings.license = license;
    return this;
  }

  /** Require a valid licence (no evaluation-mode fallback). */
  requireLicense(require = true): this {
    this.settings.requireLicense = require;
    return this;
  }

  /** Builds the {@link SignatureSettings}. Throws if cert/key are missing. */
  build(): SignatureSettings {
    const hasPfx = this.settings.pkcs12 instanceof Uint8Array && this.settings.pkcs12.length > 0;
    if (!hasPfx) {
      if (!this.settings.certificatePem) {
        throw new Error('certificate is required: call withCertificate() or withPkcs12()');
      }
      if (!this.settings.privateKeyPem) {
        throw new Error('private key is required: call withPrivateKey() or withPkcs12()');
      }
    }
    return {
      algorithm: SigningAlgorithm.Sha256Rsa,
      ...this.settings,
    } as SignatureSettings;
  }
}
