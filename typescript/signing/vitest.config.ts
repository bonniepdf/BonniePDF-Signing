import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'url';

export default defineConfig({
  resolve: {
    alias: {
      // Run the e2e test against core's TypeScript source (vitest-compatible,
      // as core's own suite does) so no prior `pnpm build` of core is needed.
      // Core lives in the sibling BonniePDF-TypeScript repo, not under
      // BonniePDF-Signing/typescript/ - keep this path in step if either moves.
      '@bonniepdf/core': fileURLToPath(
        new URL('../../../BonniePDF-TypeScript/core/src/index.ts', import.meta.url)
      ),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
});
