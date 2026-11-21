# BonniePDF.Signing

[Documentation](https://www.bonniepdf.dev/features/dotnet/signing) · [Release notes](https://www.bonniepdf.dev/docs/dotnet/whats-new) · [BonniePDF on NuGet](https://www.nuget.org/packages/BonniePDF) · [TypeScript package](https://www.npmjs.com/package/@bonniepdf/signing) · [Pricing & Licensing](https://www.bonniepdf.dev/pricing)

Digital signatures for [BonniePDF](https://www.bonniepdf.dev).

Adds a PKCS#7 / CMS digital signature to a PDF produced by BonniePDF -
**invisible or visible**, with **PAdES** baseline profiles (`B-B` through `B-LTA`) and
**RFC 3161** timestamps. RSA and ECDSA are supported. There are **no
third-party dependencies**: all cryptography uses the .NET platform
(`System.Security.Cryptography.Pkcs`, `Rfc3161TimestampRequest`).

This is the .NET counterpart of the npm package `@bonniepdf/signing`; the two
ports produce the same signature structures.

> **Included with every paid licence.** Signing is **not** covered by the
> Community License that the `BonniePDF` core uses, whatever the size of your
> organisation. Evaluation is free and unlimited in time; production use
> requires a paid Professional or Enterprise licence under the
> [BonniePDF Commercial License Agreement](https://www.bonniepdf.dev/legal/commercial-license),
> which includes signing at no extra cost — it is not sold separately. A paid
> licence covers both runtimes for the legal entities named in the Order, with
> unlimited developers and signing operations. There is no licence key, activation, or telemetry: the
> package behaves identically whether or not you hold a licence, and
> compliance is contractual rather than enforced in code. See
> **[LICENSING.md](https://github.com/bonniepdf/BonniePDF-Signing/blob/master/dotnet/BonniePDF.Signing/LICENSING.md)** for the entitlement model.

## Scope

This package **signs BonniePDF-generated output**. It is not a general-purpose
"sign any PDF" tool: BonniePDF is a generator, not a parser, so the signer only
understands the classic cross-reference structure BonniePDF emits. The
signature is applied as a **minimal incremental update** appended to the
finished bytes - the original document is left byte-for-byte intact.

## Usage

```csharp
using BonniePDF;
using BonniePDF.Signing;

// 1. Generate a PDF with BonniePDF as usual.
using var doc = new Document();
doc.Add(new TextBlock("Service Agreement"));
byte[] pdfBytes = doc.GenerateBytes();

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

## Scope and notes

- **PAdES B-B through B-LTA:** Supports baseline signatures (`BB`), signature timestamps (`BT`), embedded validation material in a Document Security Store (`BLT`), and archive document timestamps (`BLTA`).
- **No certificate trust judgement:** The certificate and validation material are embedded as supplied; chain trust and legal effect are determined by the relying party and PDF reader.
- **Single signature per call:** Each `Sign` / `SignAsync` call appends one incremental signature revision.
- **Text signature appearance:** Visible signature widgets render structured text lines.

The package embeds certificates and signature material supplied by the user. It does not validate identity, certificate trust, or legal effect, and does not by itself create a qualified electronic signature.
