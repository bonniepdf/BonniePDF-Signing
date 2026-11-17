import { defineConfig } from 'tsup';
import { builtinModules } from 'module';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
  },
  format: ['esm', 'cjs'],
  platform: 'neutral',
  target: 'es2022',
  external: [...builtinModules, ...builtinModules.map(m => `node:${m}`)],
  shims: true,
  dts: false,
  splitting: true,
  treeshake: true,
  clean: true,
  outDir: 'dist',
});
