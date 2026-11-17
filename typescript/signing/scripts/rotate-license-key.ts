/**
 * Phase 1 — licence-key cutover (vendor-side, run by hand, once).
 *
 * Generates the real vendor EC P-256 licence keypair, writes the PRIVATE key to
 * a file you must vault (never commit), and patches the embedded PUBLIC key into
 * BOTH ports so they verify customer keys against your real key instead of the
 * shipped placeholder. Finishes with a mint→verify round-trip so you know the
 * keypair works before you commit.
 *
 * Run from the `signing/` directory:
 *
 *   tsx scripts/rotate-license-key.ts                 # do it (writes the key + patches both ports)
 *   tsx scripts/rotate-license-key.ts --dry-run       # show what would change, write nothing
 *   tsx scripts/rotate-license-key.ts --out /secure/vendor-license-key.pem
 *   tsx scripts/rotate-license-key.ts --net-license ../../dotnet/BonniePDF.Signing/License.cs
 *
 * After it succeeds: vault the printed private key, commit the two patched
 * source files (NOT the key), then proceed to Phase 4 (first release).
 */
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { derToPem, bytesToBase64 } from '../src/pem';
import { mintLicense } from './mint-license';
import { verifyLicense } from '../src/license';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const signingPackageRoot = resolve(scriptDir, '..'); // <signing-repo>/typescript/signing

interface Args {
  out: string;
  tsLicense: string;
  netLicense: string;
  dryRun: boolean;
  force: boolean;
}

function parseArgs(argv: string[]): Args {
  const map: Record<string, string> = {};
  const flags = new Set<string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run' || a === '--force') {
      flags.add(a.slice(2));
    } else if (a.startsWith('--')) {
      map[a.slice(2)] = argv[++i];
    }
  }
  return {
    out: map.out ?? resolve(process.cwd(), 'vendor-license-key.pem'),
    tsLicense: map['ts-license'] ?? resolve(scriptDir, '..', 'src', 'license.ts'),
    netLicense: map['net-license'] ?? resolve(signingPackageRoot, '..', '..', 'dotnet', 'BonniePDF.Signing', 'License.cs'),
    dryRun: flags.has('dry-run'),
    force: flags.has('force'),
  };
}

/** Replace the SPKI string literal that follows `marker` (TS `'…'` or C# `"…"`). */
function patchSpki(source: string, marker: RegExp, label: string): string {
  if (!marker.test(source)) {
    throw new Error(`could not find the public-key literal (${label}); has the file structure changed?`);
  }
  return source.replace(marker, (_m, prefix: string, quote: string) => `${prefix}${quote}__NEWKEY__${quote}`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  // 1. Generate the keypair.
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const privatePem = derToPem(pkcs8, 'PRIVATE KEY');
  const publicSpkiB64 = bytesToBase64(spki);

  // 2. Round-trip: mint a token with the new private key, verify with the new public key.
  const probe = await mintLicense(privatePem, { sub: '__rotation-self-test__', edition: 'enterprise' });
  const check = await verifyLicense(probe, { publicKeySpki: publicSpkiB64 });
  if (check.status !== 'valid') {
    throw new Error(`self-test failed: freshly minted key verified as "${check.status}" — aborting, nothing written`);
  }

  // 3. Patch both ports (in memory first, so a failure leaves nothing half-done).
  const tsMarker = /(LICENSE_PUBLIC_KEY_SPKI\s*=\s*)(')[A-Za-z0-9+/=]+\2/;
  const netMarker = /(PublicKeySpki\s*=\s*)(")[A-Za-z0-9+/=]+\2/;

  const tsSource = readFileSync(args.tsLicense, 'utf8');
  const netSource = readFileSync(args.netLicense, 'utf8');
  const tsPatched = patchSpki(tsSource, tsMarker, 'TS LICENSE_PUBLIC_KEY_SPKI').replace('__NEWKEY__', publicSpkiB64);
  const netPatched = patchSpki(netSource, netMarker, 'NET License.PublicKeySpki').replace('__NEWKEY__', publicSpkiB64);

  // 4. Guard the private-key file.
  if (existsSync(args.out) && !args.force && !args.dryRun) {
    throw new Error(`refusing to overwrite existing ${args.out} (pass --force if you really mean to)`);
  }

  if (args.dryRun) {
    console.log('DRY RUN — nothing written.\n');
    console.log(`Would write private key  -> ${args.out}`);
    console.log(`Would patch TS  license  -> ${args.tsLicense}`);
    console.log(`Would patch NET license  -> ${args.netLicense}`);
    console.log(`\nNew public key (SPKI b64):\n${publicSpkiB64}`);
    return;
  }

  // 5. Write everything.
  writeFileSync(args.out, privatePem, { mode: 0o600 });
  writeFileSync(args.tsLicense, tsPatched);
  writeFileSync(args.netLicense, netPatched);

  console.log('✓ Licence key rotated. Self-test (mint→verify) passed.\n');
  console.log(`  Private key written : ${args.out}  (chmod 600)`);
  console.log(`  TS  license patched : ${args.tsLicense}`);
  console.log(`  NET license patched : ${args.netLicense}`);
  console.log(`\n  New public key (SPKI b64):\n  ${publicSpkiB64}\n`);
  console.log('NEXT STEPS:');
  console.log('  1. VAULT the private key (secret manager); delete the local copy once stored.');
  console.log('     It can mint licences for every customer — treat it like a signing root.');
  console.log('  2. Commit ONLY the two patched source files. NEVER commit the private key.');
  console.log('  3. Verify both publish guards now pass (placeholder gone):');
  console.log('       node scripts/check-license-key.mjs');
  console.log('  4. Mint a real customer key with scripts/mint-license.ts and proceed to Phase 4.');
}

main().catch((err: unknown) => {
  process.stderr.write(`rotate-license-key: ${(err as Error).message}\n`);
  process.exit(1);
});
