# BonniePDF.Signing — Licensing, the Dummies Guide

`BonniePDF.Signing` is a **commercial add-on**. The core (`BonniePDF`) is free;
signing requires a paid licence key. This guide explains, in plain terms, **how
licence keys work, how to use one, and (for us, the vendor) how to make them.**
No prior crypto knowledge needed.

Two audiences:

1. **You are a customer** who bought a licence → read [Part 1](#part-1-im-a-customer).
2. **You are the vendor** (the BonniePDF team) issuing keys → read
   [Part 2](#part-2-im-the-vendor-issuing-keys).

---

## The 30-second version

- A **licence key** is a short text string like `BPDF1.eyJzdWI....MEUCIQ...`.
- You give it to the library **once**: in code, an environment variable, or a
  file. Whichever is easiest.
- The library checks it **offline** — no internet, no licence server, no
  phone-home. Works on an air-gapped build agent.
- Without a key, signing runs in **evaluation mode** (with a warning). A paid
  licence is required for production use.

```csharp
using BonniePDF.Signing;

// Global, set once at startup:
License.Key = "BPDF1.eyJzdWI...";

byte[] signed = PdfSigner.Sign(pdfBytes, new SignatureSettings
{
    Pkcs12 = pfxBytes,
    Pkcs12Password = "secret",
});
```

That's it. The rest is detail.

---

## Part 1: "I'm a customer"

### What is a licence key?

A signed token. Like a concert ticket with a hologram: anyone can *read* what's
on it (your company name, edition, expiry), but only the issuer can *make a
valid one*, because forging the hologram needs a secret only the issuer holds.
The library checks the hologram (a cryptographic signature) locally — it never
contacts a server.

The key encodes:

| Field      | Meaning                            | Example      |
| ---------- | ---------------------------------- | ------------ |
| `sub`      | Your customer id                   | `acme-corp`  |
| `edition`  | What you bought                    | `enterprise` |
| `seats`    | Seat count (informational)         | `25`         |
| `features` | Features unlocked                  | `["pades"]`  |
| `iat`      | Issue date                         | `2026-06-26` |
| `exp`      | Expiry (absent = perpetual)        | `2027-06-26` |

### How do I give the library my key?

Four sources, checked **in this order** (first match wins):

**Option A — Per call, in code:**

```csharp
PdfSigner.Sign(pdfBytes, new SignatureSettings
{
    License = "BPDF1.eyJzdWI...",
    Pkcs12 = pfxBytes,
    Pkcs12Password = "secret",
});
```

or with the fluent builder:

```csharp
var settings = new SignatureOptions()
    .WithLicense("BPDF1.eyJzdWI...")
    .WithPkcs12(pfxBytes, "secret")
    .Build();
```

**Option B — The global key (set once at startup):**

```csharp
License.Key = "BPDF1.eyJzdWI...";
```

**Option C — Environment variable (best for servers / CI):**

```bash
export BONNIEPDF_LICENSE_KEY="BPDF1.eyJzdWI..."
```

**Option D — A licence file (best for desktop / air-gapped):** put the key in
`bonniepdf.license` in the working directory, or point at any path with
`BONNIEPDF_LICENSE_FILE=/etc/bonniepdf/license.key`.

### What happens if my key is missing, wrong, or expired?

| Situation                        | What the library does                            |
| -------------------------------- | ------------------------------------------------ |
| Valid, current key               | Signs silently. 🎉                                |
| **No key at all**                | Signs in **evaluation mode** + one-time warning   |
| Expired, within 30-day grace     | Signs + warning to renew                          |
| Expired beyond grace             | **Throws** — get a renewal                         |
| Garbled / forged key             | **Throws** — a present key must be valid            |
| Revoked key                      | **Throws**                                        |

The rule of thumb: **a key you *provide* must be valid.** Providing *no* key is
the only way to get the lenient evaluation fallback. To make even missing keys
hard-fail (e.g. catching a mis-deployed production build):

```csharp
new SignatureSettings { /* … */ RequireLicense = true };
// or globally:  set env BONNIEPDF_LICENSE_REQUIRE=1
```

### Checking a key yourself

```csharp
LicenseVerification result = License.Verify(License.Key);
Console.WriteLine(result.Status);      // Valid | Grace | Expired | Invalid | Revoked | Unlicensed
Console.WriteLine(result.Claims?.Sub); // acme-corp
```

### Troubleshooting

- **"licence signature does not verify"** — corrupted key, usually a copy-paste
  that dropped characters or wrapped a line. Re-paste it as one line.
- **"malformed licence key"** — it isn't a `BPDF1.…` token; check you pasted the
  whole thing.
- **"licence expired"** — renew, or rely on the 30-day grace meanwhile.
- **Evaluation-mode warning in production** — your key isn't being found. Check
  `BONNIEPDF_LICENSE_KEY`, the file path, or that `License.Key` is set before the
  first `Sign` call.

---

## Part 2: "I'm the vendor, issuing keys"

You hold a **private key** that never leaves your machine. The package ships the
matching **public key** (baked into `License.PublicKeySpki`). To issue a licence
you sign a small JSON claim with the private key and get a `BPDF1.…` string,
which you email to the customer. The library verifies it offline against the
embedded public key. **No runtime server.**

### One-time setup

```bash
# private key — KEEP SECRET, never commit
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out vendor-license-key.pem

# public key (SPKI, base64, one line) — paste into License.PublicKeySpki
openssl pkey -in vendor-license-key.pem -pubout -outform DER | base64 -w0
```

Paste that base64 line into `License.PublicKeySpki` in
[`License.cs`](License.cs) — and the identical value into the TypeScript port's
`LICENSE_PUBLIC_KEY_SPKI` — then publish. The repo ships a **placeholder** public
key whose private half was discarded, so nobody can mint against the published
build until you swap in your own.

> **Why ECDSA P-256, not Ed25519?** P-256 is natively supported by both the .NET
> BCL *and* the browser/Node Web Crypto API, so one token format verifies in both
> ports with zero dependencies. Ed25519 isn't in the .NET 8 base library.

### Minting a key

The TypeScript port ships a ready CLI (`scripts/mint-license.ts`). In .NET,
minting is a few lines — sign the claim JSON with your private key:

```csharp
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

static string Mint(string privateKeyPem, object claims)
{
    string Base64Url(byte[] b) =>
        Convert.ToBase64String(b).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    using var ecdsa = ECDsa.Create();
    ecdsa.ImportFromPem(privateKeyPem);

    string payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(claims));
    byte[] input = Encoding.UTF8.GetBytes($"BPDF1.{payload}");
    byte[] sig = ecdsa.SignData(input, HashAlgorithmName.SHA256); // IEEE P1363
    return $"BPDF1.{payload}.{Base64Url(sig)}";
}

// usage:
string key = Mint(File.ReadAllText("vendor-license-key.pem"), new
{
    sub = "acme-corp",
    edition = "enterprise",
    seats = 25,
    features = new[] { "pades", "ltv" },
    iat = "2026-06-26",
    exp = "2027-06-26",
});
```

Email the resulting `BPDF1.…` string to the customer. Record
`customer → key → expiry` somewhere (a spreadsheet is fine to start).

### Do I need a licence server, database, or billing webhook?

**No — not to start.** Keypair + the few lines above + paste-into-email is the
whole thing. Automate later (billing-webhook auto-mint, a customer portal,
renewal jobs) only when manual minting becomes annoying. None of it is needed to
ship or to take money.

### Revoking a leaked key

Verification is offline, so revocation is **release-time**:

1. Add the customer's `sub` to `License.RevokedCustomers` (and the TypeScript
   `REVOKED_CUSTOMERS`).
2. Ship a new release.

The leaked key keeps working on already-pinned old versions but dies on upgrade.
Each key embeds the customer id, so a leak is **attributable**.

### What this mechanism does and doesn't do

- ✅ **Stops forgery** — no private key, no valid token. (Unlike an honour-system
  enum, which is defeated by typing a different value.)
- ✅ **Zero friction & offline** — declare once, no network, air-gap-friendly.
- ✅ **Attributable & revocable** — leaked keys name a customer, killed on the
  next release.
- ❌ **Not copy-proof** — source-available, so the check can be patched out. That
  is a *legal* breach (and a worse one, being deliberate circumvention), not an
  arms race we try to win technically.
- ❌ **Not the real gate for high-assurance signing** — eIDAS/QES signatures are
  gated by the **certificate and its trust chain** from a qualified provider,
  which is outside our code and uncopyable by design.

### How verification works (for the curious)

A key is `BPDF1.<payload>.<signature>`:

- `payload` is base64url JSON (the claims table above).
- `signature` is ECDSA P-256 / SHA-256 over the UTF-8 bytes of `BPDF1.<payload>`,
  base64url-encoded, in raw IEEE-P1363 (`r‖s`) form — the .NET BCL and Web Crypto
  default.

`License.Verify` recomputes the signing input, verifies against the embedded
public key, checks the revocation list, then checks `exp` against the grace
window. All local, no I/O.

---

## FAQ

**Does signing call home?** No — verification is fully offline. (An optional RFC
3161 *timestamp* contacts a timestamp authority, but that's a separate signing
feature, unrelated to licensing.)

**One key across many servers?** Yes — not node-locked; seats are informational.

**Key expires mid-deploy?** 30-day grace keeps signing working (with a warning)
so a renewal hiccup never bricks production.

**Is the free core affected?** No — `BonniePDF` has no licence check; only
`BonniePDF.Signing` does.
