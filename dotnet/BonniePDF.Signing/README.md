# BonniePDF.Signing

Digital signatures for [BonniePDF](https://bonniepdf.dev).

Adds a PKCS#7 / CMS digital signature to a PDF produced by BonniePDF -
**invisible or visible**, with **PAdES** baseline profiles (B-B / B-T) and
**RFC 3161** timestamps. RSA and ECDSA are supported. There are **no
third-party dependencies**: all cryptography uses the .NET platform
(`System.Security.Cryptography.Pkcs`, `Rfc3161TimestampRequest`).

This is the .NET counterpart of the npm package `@bonniepdf/signing`; the two
ports produce the same signature structures.

> **Commercial add-on.** Signing is a paid module and is **not** part of the
> free `BonniePDF` core. It ships under the BonniePDF Commercial License and
> requires a paid licence key (Professional, Enterprise, or the standalone
> Signing licence). Set it via `License.Key`, `SignatureSettings.License`, the
> `BONNIEPDF_LICENSE_KEY` env var, or a `bonniepdf.license` file — verification
> is fully offline. See **[LICENSING.md](LICENSING.md)** for the step-by-step
> guide (both using a key and, for the vendor, issuing them).

## Scope

This package **signs BonniePDF-generated output**. It is not a general-purpose
"sign any PDF" tool: BonniePDF is a generator, not a parser, so the signer only
understands the classic cross-reference structure BonniePDF emits. The
signature is applied as a **minimal incremental update** appended to the
finished bytes - the original document is left byte-for-byte intact.

## Usage

```csharp
using BonniePDF;
using BonniePDF.Elements.Text;
using BonniePDF.Signing;

// 1. Generate a PDF with BonniePDF as usual.
var doc = new Document();
doc.Add(new TextBlock("Service Agreement"));
byte[] pdfBytes = doc.ToByteArray();

// 2. Sign it (PEM cert + key, or a PKCS#12 .pfx).
byte[] signed = PdfSigner.Sign(pdfBytes, new SignatureSettings
{
    CertificatePem = certPem,
    PrivateKeyPem  = keyPem,
    Reason         = "Approved",
    Location       = "London, UK",
});
```

Or with the fluent builder / a `.pfx`:

```csharp
byte[] signed = PdfSigner.Sign(pdfBytes, new SignatureOptions()
    .WithPkcs12(File.ReadAllBytes("signer.pfx"), "password")
    .WithReason("Approved")
    .UsingAlgorithm(SigningAlgorithm.Sha256Rsa)
    .Build());
```

## PAdES profiles & timestamps

```csharp
byte[] signed = await PdfSigner.SignAsync(pdfBytes, new SignatureSettings
{
    CertificatePem = certPem,
    PrivateKeyPem  = keyPem,
    PadesLevel     = PadesLevel.BT,                 // B-B or B-T
    TimestampUrl   = "https://freetsa.org/tsr",     // RFC 3161 TSA
});
```

`PadesLevel.BB`/`BT` emit `/SubFilter /ETSI.CAdES.detached` and the ESS
signing-certificate-v2 attribute; `BT` also embeds an RFC 3161 timestamp.
Timestamping needs network access, so it requires `SignAsync`; `Sign` (sync)
throws if a timestamp is configured.

## Visible signatures

```csharp
byte[] signed = PdfSigner.Sign(pdfBytes, new SignatureSettings
{
    CertificatePem = certPem,
    PrivateKeyPem  = keyPem,
    Appearance = new SignatureAppearance
    {
        Page = 0,
        Rect = new double[] { 72, 72, 220, 64 }, // [x, y, width, height]
        Text = new[] { "Signed by Jane Doe", "Acme Ltd" },
    },
});
```

## Algorithms

`Sha256Rsa` (default) · `Sha384Rsa` · `Sha512Rsa` · `Sha256Ecdsa` · `Sha384Ecdsa`.

## Limitations

- **No LTV / PAdES-LTA.** B-B and B-T are supported; long-term validation
  (DSS with OCSP/CRL) and document timestamps are not yet implemented.
- **No certificate validation.** The certificate is embedded as supplied;
  expiry / chain / revocation checking is the PDF reader's responsibility.
- **Single signature** per call.
- **Visible appearance is text-only** (image appearances pending).
