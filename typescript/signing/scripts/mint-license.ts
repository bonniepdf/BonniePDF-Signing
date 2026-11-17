/**
 * Vendor-side licence minting. NOT part of the published package — this is the
 * "licence server", run by hand (or from a billing webhook) when you sell.
 * It needs your **private** key, which must never be committed or shipped.
 *
 * Usage:
 *   tsx scripts/mint-license.ts \
 *     --key ./vendor-license-key.pem \
 *     --customer acme-corp \
 *     --license-id ord_123 \
 *     --organisation "Acme Corp" \
 *     --edition enterprise \
 *     [--features pades,ltv] [--updates-through 2027-08-20]
 *
 * Paid production keys are perpetual and MUST omit `--exp`. `--exp` is
 * accepted only with `--edition evaluation` for a time-limited evaluation key.
 *
 * Prints the licence key string to stdout. Email it to the customer; they paste
 * it into `settings.license`, the `BONNIEPDF_LICENSE_KEY` env var, or a
 * `bonniepdf.license` file. Verification happens offline against the public key
 * embedded in `src/license.ts` (which must be the public half of `--key`).
 */
import { readFileSync } from 'fs';
import { pemToDer, bytesToBase64 } from '../src/pem';
import type { LicenseClaims, LicenseEdition } from '../src/license';

const PREFIX = 'BPDF1';

function bytesToB64url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Mint and sign a licence key from a PEM-encoded EC P-256 private key.
 * Shared with the test suite, which mints against an ephemeral keypair.
 */
export async function mintLicense(privateKeyPem: string, claims: LicenseClaims): Promise<string> {
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToDer(privateKeyPem) as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const payloadB64 = bytesToB64url(new TextEncoder().encode(JSON.stringify(claims)));
  const signingInput = new TextEncoder().encode(`${PREFIX}.${payloadB64}`);
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, signingInput as BufferSource)
  );
  return `${PREFIX}.${payloadB64}.${bytesToB64url(signature)}`;
}

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    if (!flag.startsWith('--')) throw new Error(`expected a --flag, got "${flag}"`);
    out[flag.slice(2)] = argv[i + 1];
  }
  return out;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const keyPath = args.key;
  const customer = args.customer;
  const edition = (args.edition ?? 'signing') as LicenseEdition;
  if (!keyPath || !customer) {
    throw new Error(
      'required: --key <private-key.pem> --customer <id> [--license-id] [--organisation] ' +
        '[--edition solo|signing|professional|enterprise|evaluation] [--features] [--updates-through] [--exp for evaluation only]'
    );
  }
  if (!['evaluation', 'solo', 'signing', 'professional', 'enterprise'].includes(edition)) {
    throw new Error(`invalid --edition "${edition}"`);
  }
  if (args.exp && edition !== 'evaluation') {
    throw new Error('paid production keys are perpetual: --exp is allowed only with --edition evaluation');
  }

  const claims: LicenseClaims = {
    sub: customer,
    edition,
    iat: new Date().toISOString().slice(0, 10),
  };
  if (args['license-id']) claims.licenseId = args['license-id'];
  if (args.organisation) claims.organisation = args.organisation;
  if (args.features) claims.features = args.features.split(',').map(f => f.trim());
  if (args['updates-through']) claims.updatesThrough = args['updates-through'];
  if (args.exp) claims.exp = args.exp;

  const token = await mintLicense(readFileSync(keyPath, 'utf8'), claims);
  process.stdout.write(token + '\n');
}

// Run as a CLI only when invoked directly (not when imported by tests).
const isMain = typeof process !== 'undefined' && process.argv[1]?.endsWith('mint-license.ts');
if (isMain) {
  main().catch((err: unknown) => {
    process.stderr.write(`mint-license: ${(err as Error).message}\n`);
    process.exit(1);
  });
}
