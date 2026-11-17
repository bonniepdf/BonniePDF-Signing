/**
 * Rewrites extensionless relative specifiers in the emitted declaration files
 * (`.d.ts`) to explicit `.js` paths.
 *
 * The sources use `moduleResolution: "bundler"` and omit extensions, and
 * `tsc --emitDeclarationOnly` copies those specifiers verbatim. TypeScript
 * consumers on `moduleResolution: "node16"` or `"nodenext"` cannot follow
 * them and then see no exports at all. A directory specifier resolves to its
 * `index.js`; specifiers with an extension, and bare package names, are left
 * alone.
 *
 *   node scripts/fix-dts-extensions.mjs dist
 */
import { readdirSync, statSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";

const distDir = resolve(process.argv[2] ?? "dist");
const SPEC = /(from\s*|import\s*|import\(\s*|export\s*\*\s*from\s*)(['"])(\.\.?\/[^'"]*?)\2/g;

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".d.ts")) out.push(p);
  }
  return out;
}

let files = 0;
let rewritten = 0;
for (const file of walk(distDir)) {
  const src = readFileSync(file, "utf8");
  const next = src.replace(SPEC, (whole, head, quote, spec) => {
    if (/\.[cm]?js$/.test(spec)) return whole;
    const base = resolve(dirname(file), spec);
    let fixed = null;
    if (existsSync(`${base}.d.ts`)) fixed = `${spec}.js`;
    else if (existsSync(join(base, "index.d.ts"))) fixed = `${spec.replace(/\/$/, "")}/index.js`;
    if (!fixed) return whole;
    rewritten++;
    return `${head}${quote}${fixed}${quote}`;
  });
  if (next !== src) {
    writeFileSync(file, next);
    files++;
  }
}
console.log(`[fix-dts-extensions] ${rewritten} specifiers in ${files} files`);
