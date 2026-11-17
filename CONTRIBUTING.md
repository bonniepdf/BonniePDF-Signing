# Contributing to the BonniePDF signing add-ons

Thanks for your interest. This file covers two things: the legal basis on which
contributions are accepted, and the practical steps for getting a change in.

## Before you open a pull request

Open an issue first for anything beyond a typo or an obvious bug fix. BonniePDF
is a specification-driven project, and a change that looks small locally can
have consequences for output conformance or for the other language
implementation. Agreeing the approach in an issue saves rework.

## Licensing of contributions

This repository is published under the **BonniePDF Signing Add-On License
Agreement 1.0** (see [LICENSE](LICENSE)). Production use is governed
contractually rather than by any check in code — there is deliberately no
licence key, activation call, or telemetry in these packages, and a contribution
must not add one.

By submitting a contribution you confirm that:

1. You wrote the contribution yourself, or you have the right to submit it under
   the terms below — including any clearance you need from an employer or client.
2. You grant CodeFocus Limited a perpetual, worldwide, non-exclusive,
   royalty-free, irrevocable licence to use, reproduce, modify, prepare
   derivative works of, publicly display, sublicense, and distribute your
   contribution and such derivative works, **including as part of commercially
   licensed distributions of BonniePDF under different licence terms**.
3. You understand that you retain copyright in your contribution, and that this
   grant does not transfer ownership of it.
4. Your contribution is provided without warranty of any kind.

This is what allows a contribution to ship in both the source-available and the
paid distributions of BonniePDF. Without it, an accepted change could not be
included in the commercial product.

## Signing off your commits

We use the [Developer Certificate of Origin](https://developercertificate.org/)
rather than a separate contributor licence agreement. Add a sign-off line to
each commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds it for you. Use your real name and an email address you
can be reached at. A pull request whose commits are not signed off cannot be
merged.

## Security issues

Do not open a public issue or pull request for a suspected vulnerability. See
[SECURITY.md](SECURITY.md).

## Building and testing

```bash
pnpm --filter @bonniepdf/signing typecheck
pnpm --filter @bonniepdf/signing test
dotnet test ./dotnet/BonniePDF.Signing.Tests/BonniePDF.Signing.Tests.csproj
```


## Cryptographic hygiene

These rules are not negotiable in review:

- **Never commit key material**, test certificates with real private keys, or
  PKCS#12 passphrases. Generate test keys at test time.
- **Never weaken a verification path to make a test pass.** A signature that
  verifies against a relaxed check is worse than a failing test.
- Timestamp behaviour depends on a live RFC 3161 authority. Tests needing one
  must be explicitly opt-in, never silently skipped into a false pass.
- ASN.1 and CMS byte layout is exact. When changing `Asn1/` or `Cms/`, verify
  against a real validator, not just a round-trip through our own parser.

## Parity is the contract

A signature produced by either runtime must be equivalent for the same logical
input and key material. The surface is idiomatic per language; the behaviour is
not allowed to diverge.

## Code of conduct

Be civil and assume good faith. Discussion stays on the technical merits of the
change. CodeFocus Limited may decline or revert a contribution, or restrict
participation, at its discretion.

## Questions

Open an issue, or email support@bonniepdf.dev.
