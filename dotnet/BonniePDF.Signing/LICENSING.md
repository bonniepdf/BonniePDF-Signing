# BonniePDF.Signing licensing and keys

`BonniePDF.Signing` is separately licensed but is **included with every paid
core licence** at no additional fee. Production use always requires a paid core
licence; it is never permitted under Community terms.

The governing terms are in [LICENSE](LICENSE). The standard core commercial
terms incorporated by that agreement are in
[COMMERCIAL-LICENSE.txt](COMMERCIAL-LICENSE.txt). Current pricing is at
[bonniepdf.dev/license](https://www.bonniepdf.dev/license/).

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
- Paid production keys are therefore non-expiring. The `exp` claim is reserved
  for evaluation or another expressly time-limited Order.

## Customer setup

Licence verification is offline. Provide the `BPDF1...` key in this precedence
order: `SignatureSettings.License`, the global `License.Key`,
`BONNIEPDF_LICENSE_KEY`, or `BONNIEPDF_LICENSE_FILE` (falling back to
`bonniepdf.license`).

```csharp
using BonniePDF.Signing;

License.Key = Environment.GetEnvironmentVariable("BONNIEPDF_LICENSE_KEY");

byte[] signed = PdfSigner.Sign(pdfBytes, new SignatureSettings
{
    Pkcs12 = pfxBytes,
    Pkcs12Password = "secret",
    RequireLicense = true,
});
```

Without a key, the package runs in evaluation mode and emits a warning. That
technical fallback grants no Production Use right. Set `RequireLicense = true`
or `BONNIEPDF_LICENSE_REQUIRE=1` so a missing production key fails fast.

| Status | Behaviour |
| --- | --- |
| Valid, non-expiring production key | Signs silently |
| No key | Evaluation warning; throws if a licence is required |
| Time-limited evaluation key within its 30-day grace period | Signs with a warning |
| Expired beyond grace, forged, malformed, or revoked key | Throws |

## Key claims and issuance

Keys contain a customer identifier, licence/order identifier, legal
organisation, edition, optional features, issue date, and informational
`updatesThrough` date. Paid production keys omit `exp`; it is used only for an
evaluation or expressly time-limited entitlement.

The production private key must remain outside source control, CI logs, build
artifacts, ordinary synced folders, and customer systems. The matching public
key is embedded identically in this package and `@bonniepdf/signing`.

From the TypeScript signing directory, generate and install the production
keypair once:

```bash
tsx scripts/rotate-license-key.ts --out /secure/vendor-license-key.pem
```

Then mint a normal non-expiring production key:

```bash
tsx scripts/mint-license.ts \
  --key /secure/vendor-license-key.pem \
  --customer acme-corp \
  --license-id ord_123 \
  --organisation "Acme Corp" \
  --edition professional \
  --features pades \
  --updates-through 2027-08-20
```

The minting script rejects `--exp` for paid production editions. Record the
Order, legal entity, issued key, covered runtimes, licence version, updates
term, and any replacement or revocation in the customer licence record.

## Signature effect

The package embeds the certificate and cryptographic material supplied by the
customer. It does not by itself create a qualified or legally valid electronic
signature. Trust and legal effect depend on certificate issuance, identity
proofing, private-key custody, timestamping, validation policy, the receiving
PDF software, and applicable law.
