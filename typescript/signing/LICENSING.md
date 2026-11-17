# @bonniepdf/signing licensing and keys

`@bonniepdf/signing` is separately licensed but is **included with every paid
core licence** at no additional fee. Production use always requires a paid core
licence; it is never permitted under Community terms.

The governing terms are in [LICENSE](LICENSE). The standard core commercial
terms incorporated by that agreement are in
[COMMERCIAL-LICENSE.txt](COMMERCIAL-LICENSE.txt). Current pricing is at
[bonniepdf.dev/license](https://www.bonniepdf.dev/license/).

## Entitlement model

- A signing entitlement arises automatically from a paid Solo, Professional, or
  Enterprise core Order and covers both the TypeScript/JavaScript and .NET
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

Licence verification is offline: no activation server, phone-home, telemetry,
or network connection is required. Provide the `BPDF1...` key in one of these
ways, in precedence order:

1. `settings.license` in code;
2. `BONNIEPDF_LICENSE_KEY` in Node, Bun, or Deno; or
3. `BONNIEPDF_LICENSE_FILE`, falling back to `bonniepdf.license` in the working
   directory.

Browser applications must pass the key explicitly, normally by injecting it at
build time.

```ts
import { signPdf } from '@bonniepdf/signing'

const signed = await signPdf(pdfBytes, {
  license: process.env.BONNIEPDF_LICENSE_KEY,
  pkcs12: pfxBytes,
  pkcs12Password: 'secret',
  requireLicense: true,
})
```

Without a key, the package runs in evaluation mode and emits a warning. That
technical fallback grants no Production Use right. Set `requireLicense: true`
or `BONNIEPDF_LICENSE_REQUIRE=1` so a missing production key fails fast.

| Status | Behaviour |
| --- | --- |
| Valid, non-expiring production key | Signs silently |
| No key | Evaluation warning; throws if a licence is required |
| Time-limited evaluation key within its 30-day grace period | Signs with a warning |
| Expired beyond grace, forged, malformed, or revoked key | Throws |

## What a key contains

| Claim | Meaning |
| --- | --- |
| `sub` | Stable customer identifier used for attribution and revocation |
| `licenseId` | Order or licence record identifier |
| `organisation` | Human-readable licensed legal entity |
| `edition` | `solo`, `signing`, `professional`, `enterprise`, or `evaluation` |
| `features` | Optional product flags |
| `iat` | Issue date |
| `updatesThrough` | Informational last date for included new releases |
| `exp` | Evaluation/time-limited expiry; omitted from paid perpetual keys |

## Vendor key issuance

The production private key must be held outside source control, CI logs, build
artifacts, ordinary synced folders, and customer systems. The matching public
key is embedded in both signing implementations.

Generate and install a keypair once:

```bash
tsx scripts/rotate-license-key.ts --out /secure/vendor-license-key.pem
```

The script updates both embedded public keys and performs a mint/verify
self-test. Commit only the public keys. The package publish guard refuses to
publish while the placeholder remains.

Mint a normal non-expiring production key:

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

Do not pass `--exp` for a paid production entitlement. The script rejects that
combination. An evaluation key may use `--edition evaluation --exp YYYY-MM-DD`.

Record the Order, legal entity, issued key, covered runtimes, licence version,
updates term, and any replacement or revocation in the customer licence record.
Because revocation is offline, a revoked customer identifier takes effect only
in releases that contain the updated revocation list.

## Signature effect

The package embeds the certificate and cryptographic material supplied by the
customer. It does not by itself create a qualified or legally valid electronic
signature. Trust and legal effect depend on certificate issuance, identity
proofing, private-key custody, timestamping, validation policy, the receiving
PDF software, and applicable law.
