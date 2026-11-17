# BonniePDF Signing

Commercial digital-signature add-ons for BonniePDF.

This repository contains both signing ports:

- `typescript/signing` - `@bonniepdf/signing`
- `dotnet/BonniePDF.Signing` - `BonniePDF.Signing`

The signing libraries are intentionally separate from the Community-licensed
core packages.
They add invisible and visible CMS/PAdES signatures, RFC 3161 timestamps, and
PKCS#12 input. There is no licence key or entitlement check in the code: the
packages behave identically for everyone, and production use is governed by the
BonniePDF Commercial License Agreement rather than enforced in software.

## TypeScript

The TypeScript package is a member of a pnpm workspace alongside
`@bonniepdf/core`, as `BonniePDF-Signing/typescript/signing`. From the workspace
root:

```powershell
pnpm --filter @bonniepdf/signing typecheck
pnpm --filter @bonniepdf/signing test
pnpm --filter @bonniepdf/signing build
```

It depends on `@bonniepdf/core` from the same local workspace.

## .NET

The .NET signing project is decoupled from BonniePDF core. Tests and sample
generation reference the local core project only to generate PDFs to sign:

```powershell
dotnet test .\dotnet\BonniePDF.Signing.Tests\BonniePDF.Signing.Tests.csproj
dotnet pack .\dotnet\BonniePDF.Signing\BonniePDF.Signing.csproj -c Release
```

## Demos

Two signed documents show the signatures on documents people would actually sign. Both are built with BonniePDF and signed
with the package, in both languages, and both are checked by the same external gates as the rest of the sample set.

| Demo | Signature | What it shows |
| --- | --- | --- |
| Services agreement | Visible, PAdES B-B | The signature box is reserved in the layout and named; the layout snapshot reports where it landed, and the signature is placed exactly over it. Nothing is hard-coded to a page position. |
| Fire safety certificate | Visible, PAdES B-LT | A trusted timestamp and the validation data are embedded, so the seal verifies offline, long after the signer's certificate has expired. |

```powershell
# TypeScript (from typescript/signing)
tsx examples/signed-agreement.ts agreement.pdf
tsx examples/sealed-certificate.ts certificate.pdf

# .NET: writes both, with the rest of the sample set
dotnet run --project dotnet/BonniePDF.Signing.SampleGen -- signed-samples
```

The demos sign with a throwaway authority built in the process, so they run anywhere and offline: the package never ships a
private key. In production you pass a certificate issued by a real authority (PEM or PKCS#12) and the address of a real
time-stamp authority. The signed output is not deterministic, so these are not part of the core examples catalogue.

## Licensing

The signing packages are part of the BonniePDF Software licensed under the
BonniePDF Commercial License Agreement. They are **not** covered by the
BonniePDF Community License, which licenses the core library only.

- **Evaluation is free** — development, testing, security review, proof of
  concept, and non-production staging, for as long as you need and with no
  reduction in functionality.
- **Production signing is always paid**, whatever the size of the organisation.
  Signing is included with every paid Professional or Enterprise licence at no
  additional fee and is not sold separately. It covers both runtimes for the
  legal entities identified in the Order, with unlimited developers and signing
  operations.
- **Rights to covered versions are perpetual.** Website licences include an
  annual updates-and-support subscription that renews automatically unless
  cancelled; it is needed only for later versions and support, and cancelling it
  never disables a covered version.

Compliance is contractual, not technical. There are no keys to issue,
rotate, or revoke, and no vendor key material to protect.

See [LICENSE](LICENSE) for the Signing Package Notice,
[COMMERCIAL-LICENSE.txt](COMMERCIAL-LICENSE.txt) for the Commercial License
Agreement that governs production use, and each package's `LICENSING.md` for
the entitlement model.
