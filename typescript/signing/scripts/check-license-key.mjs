/**
 * Pre-publish guard: refuse to publish while the licence public key is still the
 * committed PLACEHOLDER. Publishing with the placeholder would ship an
 * unenforceable licence (its private half was discarded), so the whole gate
 * would be theatre.
 *
 * Wired to `prepublishOnly`, so it runs on `npm/pnpm publish` (including
 * `changeset publish`) but never on local build/test. Replace
 * LICENSE_PUBLIC_KEY_SPKI in src/license.ts with your real vendor public key
 * (see LICENSING.md) to pass.
 */
import { readFileSync } from 'node:fs';

// A distinctive prefix of the placeholder SPKI in src/license.ts.
const PLACEHOLDER_PREFIX = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdurRtkqh1iLxsOoCJ1yNFV8';

const source = readFileSync(new URL('../src/license.ts', import.meta.url), 'utf8');

if (source.includes(PLACEHOLDER_PREFIX)) {
  console.error(
    '\n✖ Refusing to publish @bonniepdf/signing: src/license.ts still embeds the\n' +
      '  PLACEHOLDER licence public key. A real key must be in place first.\n\n' +
      '  Replace LICENSE_PUBLIC_KEY_SPKI with your vendor public key (keep the\n' +
      '  private half offline) and update License.PublicKeySpki in the .NET port to\n' +
      '  the identical value. See LICENSING.md § "One-time setup".\n'
  );
  process.exit(1);
}

console.log('✓ licence public key is not the placeholder — safe to publish');
