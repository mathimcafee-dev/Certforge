// Browser end-to-end test: opens dist/certforge.html from disk in Chromium, drives the real UI,
// checks that no network request is ever made, and verifies downloaded files with keytool/OpenSSL.
// Needs: playwright (npm i -D playwright, or set PLAYWRIGHT_CHROMIUM=/path/to/chrome), openssl, keytool.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const html = 'file://' + path.join(root, 'dist/certforge.html');
const shots = process.env.SHOTS ? path.resolve(process.env.SHOTS) : null;
const D = fs.mkdtempSync(path.join(os.tmpdir(), 'cfb-'));
const env = { ...process.env, JAVA_TOOL_OPTIONS: '' };
const sh = (c) => execSync(c, { cwd: D, env, stdio: ['ignore', 'pipe', 'pipe'] }).toString();

sh(`openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 3650 -subj "/O=Acme Root/CN=Acme Root CA" 2>/dev/null`);
sh(`openssl req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/O=Acme/CN=Acme Issuing CA" 2>/dev/null`);
fs.writeFileSync(path.join(D, 'ca.ext'), 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
sh(`openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 1800 -extfile ca.ext 2>/dev/null`);
fs.writeFileSync(path.join(D, 'leaf.ext'), 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:acmebank.in,DNS:www.acmebank.in\ncertificatePolicies=2.23.140.1.2.1\n');
sh(`openssl req -newkey rsa:2048 -nodes -keyout private.key -out acmebank.csr -subj "/CN=www.acmebank.in" 2>/dev/null`);
sh(`openssl x509 -req -in acmebank.csr -CA int.crt -CAkey int.key -CAcreateserial -out www_acmebank_in.crt -days 187 -extfile leaf.ext 2>/dev/null`);
sh('cp int.crt www_acmebank_in.ca-bundle');
sh('zip -q acmebank_in_ssl.zip www_acmebank_in.crt private.key www_acmebank_in.ca-bundle acmebank.csr');
sh(`openssl req -newkey rsa:2048 -nodes -keyout old_server.key -out o.csr -subj "/CN=old" 2>/dev/null`);
sh('openssl pkcs12 -export -in www_acmebank_in.crt -inkey private.key -certfile int.crt -passout pass:secret123 -out server.pfx');

const executablePath = process.env.PLAYWRIGHT_CHROMIUM || undefined;
const browser = await chromium.launch({ executablePath });
const results = [];
const ok = (name) => { results.push(name); console.log('  ✓', name); };

async function page(opts = {}) {
  const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1440, height: 1000 }, deviceScaleFactor: shots ? 2 : 1, ...opts });
  const p = await ctx.newPage();
  p.net = []; p.errors = [];
  p.on('request', (r) => { const u = r.url(); if (!/^(file|blob|data):/.test(u)) p.net.push(u); });
  p.on('pageerror', (e) => p.errors.push(e.message));
  await p.goto(html);
  return p;
}
const shot = async (p, name, full = true) => { if (shots) { fs.mkdirSync(shots, { recursive: true }); await p.screenshot({ path: path.join(shots, name + '.png'), fullPage: full }); } };
const upload = async (p, files) => {
  const [chooser] = await Promise.all([p.waitForEvent('filechooser'), p.locator('[data-act="choose"]').first().click()]);
  await chooser.setFiles(files.map((f) => path.join(D, f)));
  await p.waitForFunction(() => document.querySelector('.busy')?.hidden !== false);
  await p.waitForTimeout(150);
};

console.log('Browser tests');
// 1. empty state, light + dark
let p = await page();
assert.match(await p.textContent('h1'), /Every certificate format/);
await shot(p, '1-empty', false);
ok('empty state renders');
const pd = await page({ colorScheme: 'dark' });
await shot(pd, '1b-empty-dark', false); await pd.close();

// 2. CA zip → ready, CSR set aside, Tomcat pack
await upload(p, ['acmebank_in_ssl.zip']);
assert.match(await p.textContent('#h-insp'), /www\.acmebank\.in/);
assert.match(await p.textContent('.work'), /acmebank\.csr/);
assert.match(await p.textContent('.work'), /Matches/);
ok('CA zip unpacked, key matched, CSR set aside');
await p.click('[data-act="server"][data-id="tomcat"]');
await p.click('[data-act="gen"]');
const pw = await p.inputValue('#out-pw');
assert.ok(pw.length >= 14);
await shot(p, '2-ready');
const [dl] = await Promise.all([p.waitForEvent('download'), p.click('.dlbox [data-act="dl-pack"]')]);
const zipPath = path.join(D, dl.suggestedFilename()); await dl.saveAs(zipPath);
sh(`rm -rf pack && mkdir pack && cd pack && unzip -q ${zipPath}`);
const jks = fs.readdirSync(path.join(D, 'pack')).find((f) => f.endsWith('.jks'));
const list = sh(`keytool -list -v -storetype JKS -keystore pack/${jks} -storepass '${pw}'`);
assert.match(list, /Alias name: tomcat/); assert.match(list, /Certificate chain length: 2/);
assert.match(fs.readFileSync(path.join(D, 'pack', 'README-tomcat.txt'), 'utf8'), /certificateKeyAlias="tomcat"/);
await p.waitForSelector('.drawer');
await shot(p, '3-tomcat-pack', false);
ok('Tomcat pack downloaded; keytool opens the JKS with the generated password');
await p.click('.df [data-act="close"]');

// 3. individual format download: modern PFX
await p.click('[data-act="server"][data-id="iis"]');
const [dl2] = await Promise.all([p.waitForEvent('download'), p.click('[data-act="dl-one"][data-id="pfx"]')]);
const pfxPath = path.join(D, 'single.pfx'); await dl2.saveAs(pfxPath);
sh(`openssl pkcs12 -in single.pfx -passin 'pass:${pw}' -nodes -out single.pem`);
assert.equal(sh('openssl pkey -in single.pem -pubout'), sh('openssl x509 -in www_acmebank_in.crt -pubkey -noout'));
ok('single PFX download opens in OpenSSL with the right key');

// dark theme of the ready state
await p.click('[data-act="theme"]'); await p.click('[data-act="theme"]');
await p.click('[data-act="server"][data-id="tomcat"]');
await shot(p, '5-ready-dark');
await p.click('[data-act="theme"]');
assert.equal(p.net.length, 0, 'no network requests: ' + p.net.join(', '));
ok('zero network requests during the whole flow');
assert.deepEqual(p.errors, []);
await p.close();

// 4. issues: wrong key, missing intermediate
p = await page();
await upload(p, ['www_acmebank_in.crt', 'old_server.key']);
assert.match(await p.textContent('.banner'), /doesn’t belong/);
assert.match(await p.textContent('.chainlink.missing'), /Intermediate missing/);
await p.click('[data-act="server"][data-id="tomcat"]');
assert.equal(await p.isDisabled('.dlbox [data-act="dl-pack"]'), true);
await shot(p, '4-issues');
ok('wrong key and missing intermediate are shown, pack download paused');
// fix it by adding the right key + bundle
await upload(p, ['private.key', 'int.crt']);
assert.equal(await p.locator('.banner').count(), 0);
ok('adding the right key and bundle clears the problems');
await p.close();

// 5. locked PFX: wrong then right password
p = await page();
await upload(p, ['server.pfx']);
await p.fill('input[id^="pw-"]', 'nope'); await p.click('.unlock button');
await p.waitForSelector('.slot .err');
assert.match(await p.textContent('.slot .err'), /Wrong PFX password/);
await p.fill('input[id^="pw-"]', 'secret123'); await p.click('.unlock button');
await p.waitForSelector('#h-insp');
assert.match(await p.textContent('.work'), /Matches/);
ok('PFX unlock: wrong password message, then opens');
// copy-as-text drawer
await p.click('[data-act="text"]');
assert.match(await p.textContent('.drawer'), /BEGIN PRIVATE KEY/);
ok('copy-as-text drawer shows PEM blocks');
await p.close();

// 6. paste flow
p = await page();
await p.click('[data-act="paste"]');
await p.fill('#pastearea', fs.readFileSync(path.join(D, 'www_acmebank_in.crt'), 'utf8') + fs.readFileSync(path.join(D, 'private.key'), 'utf8'));
await p.click('[data-act="paste-add"]');
await p.waitForSelector('#h-insp');
ok('pasted text is classified');
await p.click('[data-act="clear"]');
assert.match(await p.textContent('h1'), /Every certificate format/);
ok('Clear removes everything');
await p.close();

// 7. phone
p = await page({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
await upload(p, ['acmebank_in_ssl.zip']);
const sw = await p.evaluate(() => document.documentElement.scrollWidth);
assert.ok(sw <= 390, 'no horizontal scroll on a phone, got ' + sw);
await shot(p, '6-mobile');
ok('phone layout has no horizontal scroll');
await p.close();

await browser.close();
console.log(`\n${results.length} browser checks passed`);
