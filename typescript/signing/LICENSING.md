# @bonniepdf/signing licensing

`@bonniepdf/signing` is part of the BonniePDF Software licensed under the BonniePDF
Commercial License Agreement, and is **included with every paid licence** at no
additional fee. It is not sold separately. It is **not** covered by the
BonniePDF Community License, which licenses the core library only, so
production use always requires a paid licence — even where the core library
itself is used free under Community terms.

[LICENSE](LICENSE) is the Signing Package Notice, which grants free evaluation.
Your full rights are in the Commercial License Agreement in
[COMMERCIAL-LICENSE.txt](COMMERCIAL-LICENSE.txt), which controls if the two
differ. Current pricing is at
[bonniepdf.dev/license](https://www.bonniepdf.dev/license/).

## No licence keys

There is no licence key, activation, entitlement check, or telemetry in this
package. Nothing to paste, nothing to configure, nothing to renew in code, and
no code path that behaves differently depending on whether you have paid.

This matches the core library, whose licence states plainly that no licence key,
activation, or telemetry is required. Signing is held to the same standard: the
package you install is the whole package, and it works identically for everyone.

Your obligation is contractual, not technical. Signing a PDF in production
requires a paid Professional or Enterprise licence. We rely on you to
hold one — the same way the rest of BonniePDF works.

```ts
import { signPdf } from '@bonniepdf/signing'

const signed = await signPdf(pdfBytes, {
  pkcs12: pfxBytes,
  pkcs12Password: 'secret',
})
```

## Entitlement model

- A signing entitlement arises automatically from a paid Professional or
  Enterprise Order and covers both the TypeScript/JavaScript and .NET
  signing packages. Signing is not sold separately.
- Professional signing coverage applies to the one legal entity in the Order.
- Enterprise signing coverage applies to the named entity and only the Covered
  Affiliates identified in the Order.
- Paid licences include unlimited developers and have no server, deployment,
  document, or signature fees.
- Production rights to versions delivered during an active Updates Term
  (twelve months unless the Order says otherwise) are perpetual. Renewal is
  optional, and needed only for later versions and support.

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
