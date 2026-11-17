# @bonniepdf/signing

Digital signatures for [BonniePDF](https://bonniepdf.dev).

Embeds a PKCS#7 / CMS digital signature into a PDF produced by
`@bonniepdf/core` — **invisible or visible**, with **PAdES** baseline profiles
(`b-b` / `b-t`) and **RFC 3161** timestamps. RSA and ECDSA are supported. There
are **zero runtime dependencies** - every cryptographic operation runs on the
[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
(`crypto.subtle`), so the same code runs in the browser, Node.js 18+, Bun, Deno,
and serverless runtimes.

> **Included with every paid licence.** Signing is **not** part of the
> Community-licensed `@bonniepdf/core`. Production use requires a signing
> licence under the [BonniePDF Commercial License Agreement](https://www.bonniepdf.dev/legal/commercial-license),
> which covers signing at no extra cost. A paid licence covers
> both runtimes for the named legal entities, with unlimited developers and
> signing operations. There is no licence key, activation, or telemetry: the
> package behaves identically whether or not you hold a licence, and
> compliance is contractual rather than enforced in code. See
> **[LICENSING.md](LICENSING.md)** for the entitlement model.

## Scope

This package **signs BonniePDF-generated output**. It is not a general-purpose
"sign any PDF" tool: BonniePDF is a generator, not a parser, so the signer only
understands the classic cross-reference structure that `@bonniepdf/core` emits.
Pointing it at arbitrary third-party PDFs (cross-reference streams, object
streams, already-encrypted or already-signed files) is out of scope.

Signing is applied as a **minimal incremental update** appended to the finished
bytes - the original document is left byte-for-byte intact, and a new revision
adds the signature field, an `/AcroForm`, and a fresh cross-reference section.

## Usage

```ts
import { Document } from '@bonniepdf/core';
import { signPdf, SignatureSettings, SigningAlgorithm } from '@bonniepdf/signing';

// 1. Generate a PDF with BonniePDF as usual.
const doc = new Document();
// ... add content ...
const pdfBytes = await doc.generateBytesAsync();

// 2. Sign it.
const signed = await signPdf(pdfBytes, {
  algorithm: SigningAlgorithm.Sha256Rsa,
  certificatePem: certPem, // X.509 certificate (PEM)
  privateKeyPem: keyPem, // PKCS#8 private key (PEM)
  certificateChainPem: [intermediatePem], // optional
  reason: 'Approved',
  location: 'London, UK',
  contactInfo: 'signer@example.com',
});
```

Or with the fluent builder:

```ts
import { signPdf, SignatureOptions, SigningAlgorithm } from '@bonniepdf/signing';

const signed = await signPdf(
  pdfBytes,
  new SignatureOptions()
    .withCertificate(certPem)
    .withPrivateKey(keyPem)
    .withChain([intermediatePem])
    .withReason('Approved')
    .withLocation('London, UK')
    .usingAlgorithm(SigningAlgorithm.Sha256Rsa)
    .build()
);
```

A runnable end-to-end example lives in
[`examples/sign-document.ts`](examples/sign-document.ts):

```sh
tsx examples/sign-document.ts <cert.pem> <key-pkcs8.pem> [out.pdf]
```

## Algorithms

| `SigningAlgorithm`    | Key type | Web Crypto                      |
| --------------------- | -------- | ------------------------------- |
| `Sha256Rsa` (default) | RSA      | `RSASSA-PKCS1-v1_5` + `SHA-256` |
| `Sha384Rsa`           | RSA      | `RSASSA-PKCS1-v1_5` + `SHA-384` |
| `Sha512Rsa`           | RSA      | `RSASSA-PKCS1-v1_5` + `SHA-512` |
| `Sha256Ecdsa`         | EC P-256 | `ECDSA` + `SHA-256`             |
| `Sha384Ecdsa`         | EC P-384 | `ECDSA` + `SHA-384`             |

## PAdES profiles & timestamps

Select a PAdES baseline level with `padesLevel`. `b-b`/`b-t` switch the
subfilter to `ETSI.CAdES.detached` and add the ESS `signing-certificate-v2`
attribute; `b-t` additionally embeds an **RFC 3161** signature timestamp.

```ts
const signed = await signPdf(pdfBytes, {
  certificatePem,
  privateKeyPem,
  padesLevel: 'b-t',
  timestampUrl: 'https://freetsa.org/tsr', // RFC 3161 TSA
  // httpClient,  // optional transport; needed in browsers (TSAs rarely send CORS)
});
```

Timestamping needs network access. The default transport uses the global
`fetch`; in a browser, supply `httpClient` pointing at a same-origin proxy
because most TSAs do not send CORS headers.

## Visible signatures

Pass an `appearance` (or the builder's `withVisibleSignature`) to draw an
on-page widget instead of an invisible one:

```ts
const signed = await signPdf(pdfBytes, {
  certificatePem,
  privateKeyPem,
  appearance: {
    page: 0, // 0-based page index
    rect: [72, 72, 220, 64], // [x, y, width, height] in points
    text: ['Signed by Jane Doe', 'Acme Ltd'], // optional; derived if omitted
  },
});
```

## Certificate input

Provide credentials either as PEM (`certificatePem` + `privateKeyPem`) or as a
PKCS#12 container:

```ts
const signed = await signPdf(pdfBytes, {
  pkcs12: pfxBytes, // Uint8Array of a .pfx / .p12 file
  pkcs12Password: 'secret',
  reason: 'Approved',
});
// …or the fluent builder: new SignatureOptions().withPkcs12(pfxBytes, 'secret')
```

Only the **modern PBES2** form (PBKDF2 + AES-CBC — the OpenSSL 3 and .NET
default) is supported; legacy 3DES/RC2 containers throw a clear error (Web
Crypto has no 3DES/RC2). Re-export such files with AES
(`openssl pkcs12 -export -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 …`)
or supply PEM instead.

## Limitations

- **No LTV / PAdES-LTA.** B-B and B-T are supported; long-term validation
  (embedded OCSP/CRL in a DSS) and document timestamps are not yet implemented.
- **No certificate validation.** The certificate is embedded as supplied;
  expiry / chain / revocation checking is the PDF reader's responsibility.
- **PKCS#12: modern PBES2 (AES) only** — see [Certificate input](#certificate-input).
- **Single signature.** One signature per call.
- **Visible appearance is text-only.** Image appearances are not yet supported.

See the internal PDF-signing roadmap for the planned LTV / multiple-signature work.

The package embeds certificates and signature material supplied by the user. It
does not validate identity, certificate trust, or legal effect, and does not by
itself create a qualified electronic signature.
