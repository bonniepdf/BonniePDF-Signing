# BonniePDF Signing

Commercial digital-signature add-ons for BonniePDF.

This folder is the local home for both signing ports imported from
a working branch:

- `typescript/signing` - `@bonniepdf/signing`
- `dotnet/BonniePDF.Signing` - `BonniePDF.Signing`

The signing libraries are intentionally separate from the Community-licensed
core packages.
They add invisible and visible CMS/PAdES signatures, RFC 3161 timestamps, and
PKCS#12 input. There is no licence key or entitlement check in the code: the
packages behave identically for everyone, and production use is governed by the
BonniePDF Commercial License Agreement rather than enforced in software.

## TypeScript

The TypeScript package is included in the parent `C:\GITHUB\bonniepdf`
workspace as `BonniePDF-Signing/typescript/signing`, so from the workspace root:

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

## Licensing

Production signing is always paid. One standard signing entitlement covers both
runtimes for the legal entities identified in the Order, with unlimited
developers and signing operations. Rights to covered signing versions are
perpetual; annual renewal is optional for future versions and support.

Compliance is contractual, not technical. There are no keys to issue,
rotate, or revoke, and no vendor key material to protect.

See [LICENSE](LICENSE) for the Signing Package Notice,
[COMMERCIAL-LICENSE.txt](COMMERCIAL-LICENSE.txt) for incorporated standard
commercial terms, and each package's `LICENSING.md` for the entitlement
model.
