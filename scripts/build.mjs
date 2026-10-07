// Bundles everything into ONE self-contained, offline HTML file: dist/certforge.html
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { build } from 'esbuild';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const r = (...p) => path.join(root, ...p);

// optional white-label: BRAND=path/to/brand.json node scripts/build.mjs
let brandPlugin = [];
let brand = (await import(r('src/brand.js'))).default;
if (process.env.BRAND) {
  brand = { ...brand, ...JSON.parse(fs.readFileSync(process.env.BRAND, 'utf8')) };
  const src = `export default ${JSON.stringify(brand)};`;
  brandPlugin = [{ name: 'brand', setup(b) { b.onLoad({ filter: /brand\.js$/ }, () => ({ contents: src, loader: 'js' })); } }];
}

const js = await build({
  entryPoints: [r('src/main.js')], bundle: true, minify: true, format: 'iife', target: ['chrome100', 'firefox100', 'safari15'],
  write: false, legalComments: 'none', plugins: brandPlugin, define: { 'process.env.NODE_ENV': '"production"' },
  platform: 'browser',
});
let code = js.outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
const css = fs.readFileSync(r('src/styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\s*\n\s*/g, '\n');
const html = fs.readFileSync(r('src/index.html'), 'utf8')
  .replace(/__NAME__/g, brand.name).replace(/__TAGLINE__/g, brand.tagline)
  .replace('/*__CSS__*/', () => css).replace('/*__JS__*/', () => code);

fs.mkdirSync(r('dist'), { recursive: true });
const out = r('dist', 'certforge.html');
fs.writeFileSync(out, html);
const sha = crypto.createHash('sha256').update(html).digest('hex');
fs.writeFileSync(out + '.sha256', `${sha}  certforge.html\n`);
console.log(`built dist/certforge.html — ${(html.length / 1024).toFixed(0)} KB — sha256 ${sha}`);
