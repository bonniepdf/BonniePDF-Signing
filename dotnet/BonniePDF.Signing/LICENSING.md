# BonniePDF.Signing licensing

`BonniePDF.Signing` is separately licensed but is **included with every paid
core licence** at no additional fee. Production use always requires a paid core
licence; it is never permitted under Community terms.

The governing terms are in [LICENSE](LICENSE). The standard core commercial
terms incorporated by that agreement are in
[COMMERCIAL-LICENSE.txt](COMMERCIAL-LICENSE.txt). Current pricing is at
[bonniepdf.dev/license](https://www.bonniepdf.dev/license/).

## No licence keys

There is no licence key, activation, entitlement check, or telemetry in this
package. Nothing to paste, nothing to configure, nothing to renew in code, and
no code path that behaves differently depending on whether you have paid.

This matches the core library, whose licence states plainly that no licence key,
activation, or telemetry is required. Signing is held to the same standard: the
package you install is the whole package, and it works identically for everyone.

Your obligation is contractual, not technical. Signing a PDF in production
requires a paid Solo, Professional, or Enterprise licence. We rely on you to
hold one — the same way the rest of BonniePDF works.

```csharp
using BonniePDF.Signing;

byte[] signed = PdfSigner.Sign(pdfBytes, new SignatureSettings
{
    Pkcs12 = pfxBytes,
    Pkcs12Password = "secret",
});
```

## Entitlement model

- A signing entitlement arises automatically from a paid Solo, Professional, or
  Enterprise core Order and covers both the .NET and TypeScript/JavaScript
  signing packages. Signing is not sold separately.
- Solo signing coverage applies to its one named Solo User and business.
- Professional signing coverage applies to the one legal entity in the Order.
- Enterprise signing coverage applies to the named entity and only the Covered
  Affiliates identified in the Order.
- Solo is limited to one named developer. Other standard entitlements have no
  developer-seat, server, deployment, document, or signature fees.
- Production rights to versions delivered during an active updates term are
  perpetual. Renewal is optional for future versions and support.

## Evaluation

Evaluate for as long as you need. There is no time limit, no feature gate, and
no watermark — evaluation and production builds are byte-for-byte the same.
The line is what you do with the output: signing documents in production is
Production Use and requires a paid licence, whatever the size of the business
or the volume of documents.

## Signature effect

The package embeds the certificate and cryptographic material supplied by the
customer. It does not by itself create a qualified or legally valid electronic
signature. Trust and legal effect depend on certificate issuance, identity
proofing, private-key custody, timestamping, validation policy, the receiving
PDF software, and applicable law.
