# BonniePDF Signing — Licensing, the Dummies Guide

`@bonniepdf/signing` is a **commercial add-on**. The core (`@bonniepdf/core`) is
free; signing requires a paid licence key. This guide explains, in plain terms,
**how licence keys work, how to use one, and (for us, the vendor) how to make
them.** No prior crypto knowledge needed.

There are two audiences here:

1. **You are a customer** who bought a licence and just wants signing to work →
   read [Part 1](#part-1-im-a-customer).
2. **You are the vendor** (the BonniePDF team) who needs to issue keys →
   read [Part 2](#part-2-im-the-vendor-issuing-keys).

---

## The 30-second version

- A **licence key** is a short text string that looks like
  `BPDF1.eyJzdWI....MEUCIQ...`.
- You give it to the library **once**. Three ways: in code, an environment
  variable, or a file. Pick whichever is easiest.
- The library checks the key **offline** — no internet, no licence server, no
  phone-home. It works on an air-gapped build server.
- Without a key, signing still runs in **evaluation mode** (with a warning).
  A paid licence is required for production use.

```ts
import { signPdf } from '@bonniepdf/signing';

const signed = await signPdf(pdfBytes, {
  license: 'BPDF1.eyJzdWI...', // ← your key
  pkcs12: pfxBytes,
  pkcs12Password: 'secret',
});
```

That's it. The rest of this document is detail.

---

## Part 1: "I'm a customer"

### What is a licence key?

It's a signed token. Think of it like a concert ticket with a hologram: anyone
can _read_ what's on it (your company name, the edition, the expiry date), but
only the issuer can _make a valid one_, because forging the hologram requires a
secret only the issuer has. The library checks the "hologram" (a cryptographic
signature) locally. It never contacts a server.

The key encodes:

| Field      | Meaning                          | Example      |
| ---------- | -------------------------------- | ------------ |
| `sub`      | Your customer id                 | `acme-corp`  |
| `edition`  | What you bought                  | `enterprise` |
| `seats`    | Seat count (informational)       | `25`         |
| `features` | Features unlocked                | `["pades"]`  |
| `iat`      | Issue date                       | `2026-06-26` |
| `exp`      | Expiry date (absent = perpetual) | `2027-06-26` |

### How do I give the library my key?

Three options, checked **in this order** (first match wins):

**Option A — In code (most explicit).**

```ts
await signPdf(pdfBytes, {
  license: 'BPDF1.eyJzdWI...',
  pkcs12: pfxBytes,
  pkcs12Password: 'secret',
});
```

or with the fluent builder:

```ts
import { SignatureOptions } from '@bonniepdf/signing';

const settings = new SignatureOptions().withLicense('BPDF1.eyJzdWI...').withPkcs12(pfxBytes, 'secret').build();
```

**Option B — Environment variable (best for servers / CI).** Keeps the key out
of your source code.

```bash
export BONNIEPDF_LICENSE_KEY="BPDF1.eyJzdWI..."
```

```ts
await signPdf(pdfBytes, { pkcs12: pfxBytes, pkcs12Password: 'secret' });
// no `license` field needed — it's read from the env var
```

**Option C — A licence file (best for desktop / air-gapped).** Put the key in a
file named `bonniepdf.license` in your working directory:

```
BPDF1.eyJzdWI...
```

Or point at any path with `BONNIEPDF_LICENSE_FILE=/etc/bonniepdf/license.key`.

> **Browser note.** File and environment lookups only run under Node, Bun, and
> Deno. In the browser there is no filesystem, so pass the key **in code**
> (`license: …`), typically injected at build time from your bundler's env.

### What happens if my key is missing, wrong, or expired?

| Situation                        | What the library does                           |
| -------------------------------- | ----------------------------------------------- |
| Valid, current key               | Signs silently. 🎉                              |
| **No key at all**                | Signs in **evaluation mode** + one-time warning |
| Expired, but within 30-day grace | Signs + warning to renew                        |
| Expired beyond grace             | **Throws** — get a renewal                      |
| Garbled / forged key             | **Throws** — a present key must be valid        |
| Revoked key                      | **Throws**                                      |

The rule of thumb: **a key you _provide_ must be valid.** Providing _no_ key is
the only way to get the lenient evaluation fallback. If you want even missing
keys to hard-fail (e.g. to catch a mis-deployed production build), set:

```ts
await signPdf(pdfBytes, { /* … */, requireLicense: true });
// or globally:
process.env.BONNIEPDF_LICENSE_REQUIRE = '1';
```

### Checking a key yourself

You can inspect a key without signing anything:

```ts
import { verifyLicense } from '@bonniepdf/signing';

const result = await verifyLicense(process.env.BONNIEPDF_LICENSE_KEY);
console.log(result.status); // 'valid' | 'grace' | 'expired' | 'invalid' | 'revoked' | 'unlicensed'
console.log(result.claims); // { sub, edition, exp, … }
```

### Troubleshooting

- **"licence signature does not verify"** — the key is corrupted (often a copy-
  paste that dropped characters or added a line break). Re-copy it as one line.
- **"malformed licence key"** — it isn't a `BPDF1.…` token. Check you pasted the
  whole thing.
- **"licence expired"** — renew, or rely on the 30-day grace while you do.
- **Warning about evaluation mode in production** — your key isn't being found.
  Confirm the env var name (`BONNIEPDF_LICENSE_KEY`) or the file path.

---

## Part 2: "I'm the vendor, issuing keys"

This section is for the BonniePDF team. Customers don't need it.

### The big picture

You hold a **private key**. It never leaves your laptop / billing server. The
package ships the matching **public key** (baked into `src/license.ts`). To
issue a licence you run a tiny script that signs a small JSON claim with your
private key and prints a `BPDF1.…` string. You email that string to the
customer. The library verifies it against the embedded public key. **No server
is involved at runtime.**

```
   you (private key)                     customer's app (public key, embedded)
 ┌───────────────────┐   email the key   ┌───────────────────────────────────┐
 │  mint-license.ts  │ ────────────────► │  signPdf() → verifyLicense() → ✅   │
 └───────────────────┘                   └───────────────────────────────────┘
```

### One-time setup

Generate your keypair **once** and keep the private half secret forever. There
are two ways: the **one-shot script (recommended)** or by hand.

**One-shot (recommended).** From the `signing/` directory:

```bash
tsx scripts/rotate-license-key.ts --out /secure/vendor-license-key.pem
```

This generates the keypair, **patches the public key into both ports**
(`src/license.ts` and the .NET `License.PublicKeySpki`), writes the private key
to `--out` (mode 600), and runs a mint→verify self-test so you know it works
before you commit. Add `--dry-run` to preview. Then: vault the private key,
commit **only** the two patched source files, and `node scripts/check-license-key.mjs`
should now pass.

**By hand.** If you prefer to do it manually:

```bash
# private key — KEEP THIS SECRET, never commit it
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out vendor-license-key.pem

# public key (SPKI, base64, one line) — paste into src/license.ts
openssl pkey -in vendor-license-key.pem -pubout -outform DER | base64 -w0
```

Paste that base64 line into `LICENSE_PUBLIC_KEY_SPKI` in
[`src/license.ts`](src/license.ts) — and the **identical** value into
`License.PublicKeySpki` in the .NET port — then publish. The repo currently ships
a **placeholder** public key whose private half was deliberately discarded, so
nobody can mint keys against the published build until you swap in your own. A
pre-publish guard (`prepublishOnly` on npm, a CI step on NuGet) **refuses to
publish while the placeholder is still in place.**

> **Why ECDSA P-256 and not Ed25519?** P-256 is natively supported by both the
> browser/Node Web Crypto API _and_ the .NET BCL, so one token format verifies
> everywhere with zero dependencies. Ed25519 isn't in the .NET 8 base library.

### Minting a key for a customer

```bash
tsx scripts/mint-license.ts \
  --key ./vendor-license-key.pem \
  --customer acme-corp \
  --edition enterprise \
  --seats 25 \
  --features pades,ltv \
  --exp 2027-06-26
```

It prints the `BPDF1.…` key. Email it to the customer. Done. Record the
`customer → key → expiry` somewhere (a spreadsheet is fine to start) — that's
your renewal reminder and your revocation list source.

For a perpetual key, omit `--exp`. For a renewal, just mint a new one with a
later `--exp` and send it; the customer swaps the string.

### Do I need a licence server, database, or billing webhook?

**No — not to start.** The minimum viable setup is:

1. The keypair (one `openssl` command, once).
2. The mint script (already in this repo).
3. Paste-the-output-into-an-email.

Automate later, only when manual minting becomes annoying:

- **Auto-mint** from a Stripe/billing webhook → call `mintLicense()` and email
  the result. This is the _eventually_ version, not a launch requirement.
- **Customer portal** to re-download keys → email works fine until you have
  real volume.
- **Renewal jobs** → a calendar reminder works until you have dozens.

None of that is needed to ship or to take money.

### Revoking a leaked key

Because verification is offline, revocation happens at **release time**, not at
runtime:

1. Add the customer's `sub` to `REVOKED_CUSTOMERS` in `src/license.ts` (and the
   .NET `License.RevokedCustomers`).
2. Cut a new release.

The leaked key keeps working on **already-pinned** old versions but dies on
upgrade — which is acceptable, because the same upgrade carries the security and
feature fixes customers want. Each issued key embeds the customer id, so a leak
is **attributable**.

### What this mechanism does and doesn't do

- ✅ **Stops forgery.** Without your private key, nobody can mint a key that
  verifies. The honour-system enum it replaces could be defeated by typing a
  different value; this can't.
- ✅ **Zero friction & offline.** Declare it
  once, no network, works air-gapped.
- ✅ **Attributable & revocable.** Leaked keys name a customer and can be killed
  on the next release.
- ❌ **Not copy-proof.** The package is source-available, so a determined user
  can patch out the check in their own `node_modules`. That's fine — it's a
  _legal_ breach (and, because it's deliberate circumvention of a technical
  measure, a worse legal position than picking the wrong enum), not something we
  try to win with an anti-tamper arms race.
- ❌ **Not the real gate for high-assurance signing.** Legally-meaningful
  (eIDAS/QES) signatures are gated by the **certificate and its trust chain**,
  which the customer gets from a qualified provider — that's outside our code and
  uncopyable by design.

### How verification works (for the curious)

A key is three dot-separated parts: `BPDF1.<payload>.<signature>`.

- `payload` is base64url-encoded JSON (the claims table above).
- `signature` is ECDSA P-256 / SHA-256 over the UTF-8 bytes of
  `BPDF1.<payload>`, base64url-encoded, in raw IEEE-P1363 (`r‖s`) form — the
  format both Web Crypto and the .NET BCL use by default.

`verifyLicense()` recomputes the signing input, verifies the signature against
the embedded public key, checks the revocation list, then checks `exp` against
the grace window. All local, all synchronous-feeling, no I/O.

---

## FAQ

**Does signing call home / need internet?** No. Verification is fully offline.
(Adding an _RFC 3161 timestamp_ to a signature does contact a timestamp
authority, but that's a separate, optional signing feature — nothing to do with
licensing.)

**Can I use one key across many servers?** Yes. The key isn't node-locked; seat
counts are informational. Honour-system on seats, cryptographic on authenticity.

**What if my key expires mid-deploy?** You get a 30-day grace window (signing
keeps working, with a warning) so a renewal hiccup never bricks production.

**Is the free core affected?** No. `@bonniepdf/core` has no licence check. Only
`@bonniepdf/signing` does.
