## What does this PR do?

<!-- One or two sentences describing the change. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Refactor / internal improvement
- [ ] Documentation / tooling

## Checklist

- [ ] `pnpm --filter @bonniepdf/signing typecheck` passes
- [ ] `pnpm --filter @bonniepdf/signing test` passes
- [ ] `dotnet test ./dotnet/BonniePDF.Signing.Tests/BonniePDF.Signing.Tests.csproj` passes
- [ ] The TypeScript and .NET packages both carry the change and produce equivalent signatures for the same input and key material
- [ ] No key material, real certificates or PKCS#12 passphrases are committed
- [ ] No verification check is relaxed to make a test pass
- [ ] Changes to `Asn1/` or `Cms/` were checked against an external validator
- [ ] Public API changes are reflected in the README or docs
- [ ] Every commit is signed off (`git commit -s`), as described in [CONTRIBUTING.md](../CONTRIBUTING.md)
