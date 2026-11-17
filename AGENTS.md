# BonniePDF Signing — agent guide

Commercial digital-signature add-ons for BonniePDF, in **both** runtimes: `@bonniepdf/signing` (TypeScript) and `BonniePDF.Signing` (.NET, `net8.0`). They add invisible and visible CMS/PAdES signatures, RFC 3161 timestamps, and PKCS#12 input.

> **This repository is public.** Keep this file, the README, and code comments useful to an outside contributor who has cloned only this repo.

## Deliberately separate from core

Signing is **not** part of the Community-licensed core packages, and must not drift into them. Keep the dependency direction one-way: signing depends on `@bonniepdf/core` / `BonniePDF`, never the reverse.

## No licence enforcement in code — on purpose

There is **no licence key, no entitlement check, and no vendor key material** anywhere in these packages. They behave identically for everyone. Production use is governed by the **BonniePDF Commercial License Agreement**, which defines these packages as part of the Software — contractually, not technically. [`LICENSE`](LICENSE) is the short Signing Package Notice: it grants free evaluation and points at that agreement, because it has to bind people who download the package without an Order.

**Do not add** a key check, activation call, telemetry ping, trial timer, or watermark. There are no keys to issue, rotate, or revoke, and that is the design — not an omission to correct.

## The parity principle applies here too

Two co-equal implementations of the same behaviour. A signature produced by one runtime and one produced by the other must be equivalent for the same logical input and key material; the surface is idiomatic per language (PascalCase/overloads in C#, camelCase/options objects in TypeScript). Classify any difference as **platform-mandated** (allowed), **idiomatic-surface** (allowed — same behaviour, different spelling), or **behavioural divergence** (the only real defect) before "fixing" it. Never transliterate one language's spelling into the other to force a match.

## Layout

```
typescript/signing/     @bonniepdf/signing — src/, tests/, examples/, scripts/
dotnet/
  BonniePDF.Signing/          Asn1/  Cms/  Pdf/  Timestamp/
  BonniePDF.Signing.Tests/
  BonniePDF.Signing.SampleGen/
  scripts/
```

## Commands

The TypeScript package depends on `@bonniepdf/core`. In the BonniePDF development workspace it resolves through a pnpm workspace link:

```bash
pnpm --filter @bonniepdf/signing typecheck
pnpm --filter @bonniepdf/signing test
pnpm --filter @bonniepdf/signing build
```

The .NET side builds with `dotnet` from this folder:

```bash
dotnet test ./dotnet/BonniePDF.Signing.Tests/BonniePDF.Signing.Tests.csproj
dotnet pack ./dotnet/BonniePDF.Signing/BonniePDF.Signing.csproj -c Release
```

The .NET project is decoupled from core: tests and sample generation reference the local core project **only to produce PDFs to sign**.

## Cryptographic hygiene

- **Never commit key material**, test certificates with real private keys, or PKCS#12 passphrases. Generate test keys at test time.
- **Never weaken a verification path to make a test pass.** A signature that verifies against a relaxed check is worse than a failing test.
- Timestamp behaviour depends on a live RFC 3161 authority; tests that need one must be explicitly opt-in, not silently skipped into a false pass.
- ASN.1/CMS byte layout is exact. When changing `Asn1/` or `Cms/`, verify against a real validator (Adobe Acrobat, veraPDF), not just a round-trip through our own parser.
