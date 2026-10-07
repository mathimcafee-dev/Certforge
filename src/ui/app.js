// CertForge UI. Plain DOM, one state object, full re-render on discrete actions; typing never re-renders.
import { ingestFile, ingestText, unlock } from '../lib/ingest.js';
import { buildModel } from '../lib/model.js';
import { runChecks } from '../lib/checks.js';
import { makeContext, FORMATS, PACKS, formatById, packById, buildPack } from '../lib/outputs.js';
import { writeZip } from '../lib/zip.js';
import { lifetime } from '../lib/cert.js';
import { toU8, pem } from '../lib/util.js';
import { keyPemPkcs8 } from '../lib/keys.js';
import { I } from './icons.js';
import BRAND from '../brand.js';

const IDLE_SECONDS = 600;
const fresh = () => ({
  pieces: [], locked: [], lockErr: {}, added: new Set(), model: null, report: null,
  server: null, sel: new Set(), more: false, password: '', alias: '', aliasTouched: false, includeRoot: false,
  drawer: null, packFiles: null, paste: false, override: false,
});
let S = fresh();
let busy = 0, theme = 'auto', idleAt = Date.now(), toastTimer = 0, dragDepth = 0;
const root = () => document.getElementById('app');

/* ---------------- helpers ---------------- */
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtDate = (d) => d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
const hasData = () => S.pieces.length > 0 || S.locked.length > 0;
const short = (fp) => fp ? fp.slice(0, 11) + ':…:' + fp.slice(-5) : '';

function ctx() {
  return makeContext(S.model, { password: S.password, alias: S.alias, includeRoot: S.includeRoot });
}
function canKey() { return !!(S.model && S.model.key && S.model.keyMatch); }
function fmtAvailable(f) {
  if (!S.model || !S.model.leaf) return { ok: false, why: 'Add a certificate first' };
  if (f.key && !canKey()) return { ok: false, why: S.model.key ? 'Needs the matching private key' : 'Needs your private key' };
  if (f.id === 'cabundle' && !S.model.intermediates.length) return { ok: false, why: 'No intermediates to bundle' };
  if (f.id === 'truststore' && !S.model.intermediates.length && !S.model.root) return { ok: false, why: 'No CA certificates' };
  if (f.available && !f.available({ key: canKey() ? S.model.key : null })) return { ok: false, why: 'Not available for this key type' };
  return { ok: true };
}
function needsPassword() {
  if (S.server && packById(S.server).pw) return true;
  return [...S.sel].some((id) => formatById(id).pw);
}
function needsAlias() { return S.server === 'tomcat' || S.sel.has('jks') || S.sel.has('pfx') || S.sel.has('pfx-legacy'); }
function pwState() {
  const p = S.password;
  if (!p) return { ok: false, msg: 'Set a password to protect the keystore', cls: '' };
  if (p.length < 6) return { ok: false, msg: 'At least 6 characters — Java’s keytool won’t accept less', cls: 'bad' };
  if (/[^\x20-\x7e]/.test(p)) return { ok: true, msg: 'Heads-up: Java and older Windows can misread non-English characters in PFX passwords', cls: 'warn' };
  return { ok: true, msg: 'Copy it now — it isn’t stored anywhere', cls: '' };
}
function strength(p) {
  if (!p) return ['', ''];
  let score = 0;
  if (p.length >= 10) score++; if (p.length >= 14) score++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) score++; if (/\d/.test(p)) score++; if (/[^A-Za-z0-9]/.test(p)) score++;
  return score >= 4 ? ['Strong', 'var(--ok)'] : score >= 2 ? ['Fair', 'var(--warn)'] : ['Weak', 'var(--bad)'];
}
function genPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=?@';
  const a = new Uint32Array(18); crypto.getRandomValues(a);
  let p = ''; for (const x of a) p += chars[x % chars.length];
  return p;
}
function save(name, data, binary) {
  const bytes = data instanceof Uint8Array ? data : binary ? toU8(data) : new TextEncoder().encode(data);
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
function toast(msg) {
  clearTimeout(toastTimer);
  let t = document.querySelector('.toast');
  if (!t) { t = document.createElement('div'); t.className = 'toast'; t.setAttribute('role', 'status'); document.body.appendChild(t); }
  t.textContent = msg;
  toastTimer = setTimeout(() => t.remove(), 3200);
}
async function copyText(text, btn) {
  const done = () => { if (btn) { const o = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => (btn.textContent = o), 1200); } };
  try { await navigator.clipboard.writeText(text); done(); }
  catch {
    const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); done(); } catch { toast('Copy failed — select the text and copy it manually.'); } ta.remove();
  }
}
function setBusy(d) { busy += d; const b = document.querySelector('.busy'); if (b) b.hidden = busy <= 0; }

/* ---------------- intake ---------------- */
async function addFiles(fileList) {
  setBusy(1);
  try {
    for (const f of fileList) {
      try {
        const u8 = new Uint8Array(await f.arrayBuffer());
        accept(await ingestFile(f.name, u8));
      } catch (e) { accept([{ type: 'note', source: f.name, level: 'warn', text: e.message || 'Could not read this file.' }]); }
    }
    await recompute();
  } finally { setBusy(-1); render(); }
}
async function addText(text, source = 'Pasted text') {
  if (!text || !text.trim()) return;
  setBusy(1);
  try { accept(await ingestText(text, source)); await recompute(); }
  catch (e) { accept([{ type: 'note', source, level: 'warn', text: e.message }]); }
  finally { setBusy(-1); S.paste = false; render(); }
}
function accept(pieces) {
  for (const p of pieces) (p.type === 'locked' ? S.locked : S.pieces).push(p);
}
async function doUnlock(id) {
  const piece = S.locked.find((l) => l.id === id); if (!piece) return;
  const pw = document.getElementById('pw-' + id)?.value ?? '';
  const kpw = document.getElementById('kpw-' + id)?.value;
  setBusy(1);
  try {
    const out = await unlock(piece, pw, kpw || undefined);
    S.locked = S.locked.filter((l) => l !== piece);
    delete S.lockErr[id];
    accept(out);
    await recompute();
  } catch (e) {
    S.lockErr[id] = { msg: e.message, code: e.code };
  } finally { setBusy(-1); render(); if (S.lockErr[id]) document.getElementById((S.lockErr[id].code === 'KEY_PASSWORD' ? 'kpw-' : 'pw-') + id)?.focus(); }
}
async function recompute() {
  if (!S.pieces.some((p) => p.type === 'cert' || p.type === 'key')) { S.model = null; S.report = null; return; }
  S.model = await buildModel(S.pieces, { added: S.added });
  S.report = S.model.leaf ? runChecks(S.model) : null;
  if (!S.aliasTouched) S.alias = defaultAlias();
  // drop selections that are no longer possible
  for (const id of [...S.sel]) if (!fmtAvailable(formatById(id)).ok) S.sel.delete(id);
}
function defaultAlias() {
  if (!S.model || !S.model.leaf) return '';
  if (S.server && packById(S.server).alias) return packById(S.server).alias;
  return (S.model.key?.friendlyName || (S.model.leaf.subject.CN || 'certificate').replace(/^\*\./, 'wildcard.')).toLowerCase();
}
function clearAll(idle) {
  S = fresh();
  idleAt = Date.now();
  render();
  window.scrollTo(0, 0);
  if (idle) toast('Cleared after 10 idle minutes — nothing was kept.');
}

/* ---------------- outputs ---------------- */
function guard() {
  if (S.report && S.report.blocking && !S.override && !(onlyKeyProblem())) { toast('Fix the issues in the Inspector first.'); return false; }
  if (needsPassword() && !pwState().ok) { toast(pwState().msg); document.getElementById('out-pw')?.focus(); return false; }
  return true;
}
function onlyKeyProblem() { return S.report && S.report.checks.filter((c) => c.status === 'bad').every((c) => c.id === 'key'); }
function zipOf(files) { return writeZip(files.map((f) => ({ name: f.name, data: f.binary ? toU8(f.data) : f.data }))); }
function downloadPack() {
  if (!guard()) return;
  try {
    const c = ctx();
    const files = buildPack(S.server, c);
    save(`${c.base}-${S.server}.zip`, zipOf(files));
    S.packFiles = files.map((f) => ({ name: f.name, note: f.note }));
    S.drawer = 'pack'; render();
  } catch (e) { toast(e.message); }
}
function downloadSelected() {
  if (!guard()) return;
  try {
    const c = ctx();
    const ids = FORMATS.map((f) => f.id).filter((id) => S.sel.has(id));
    if (!ids.length) { toast('Switch on at least one format.'); return; }
    const files = ids.map((id) => formatById(id).build(c));
    if (files.length === 1) save(files[0].name, files[0].data, files[0].binary);
    else save(`${c.base}-certforge.zip`, zipOf(files));
    toast(files.length === 1 ? `Downloaded ${files[0].name}` : `Downloaded ${files.length} files as a zip`);
  } catch (e) { toast(e.message); }
}
function downloadOne(id) {
  const f = formatById(id);
  if (f.pw && !pwState().ok) { if (!S.sel.has(id)) { S.sel.add(id); render(); } toast(pwState().msg); document.getElementById('out-pw')?.focus(); return; }
  if (!guard()) return;
  try { const o = f.build(ctx()); save(o.name, o.data, o.binary); toast(`Downloaded ${o.name}`); } catch (e) { toast(e.message); }
}

/* ---------------- rendering ---------------- */
function render() {
  const el = root(); if (!el) return;
  const focus = document.activeElement?.id, selStart = document.activeElement?.selectionStart;
  el.innerHTML = topbar() + `<div class="busy" ${busy > 0 ? '' : 'hidden'}></div>` + (hasData() ? workbench() : empty()) + drawer();
  if (focus) { const f = document.getElementById(focus); if (f) { f.focus(); try { if (selStart != null) f.setSelectionRange(selStart, selStart); } catch {} } }
  tick();
}

function step() {
  if (!hasData()) return 0;
  if (!S.model || !S.model.leaf || S.locked.length || (S.report && S.report.blocking)) return 1;
  return 2;
}
function topbar() {
  const st = step(), names = ['Add files', 'Check', 'Convert'];
  const themeIcon = theme === 'dark' ? I.moon : theme === 'light' ? I.sun : I.auto;
  return `<header class="bar">
    <div class="logo"><i>${I.chain}</i>${esc(BRAND.name)}<small>${esc(BRAND.tagline)}</small></div>
    <nav class="steps" aria-label="Progress">${names.map((n, i) => `<span class="${i < st ? 'done' : i === st ? 'on' : ''}"><b>${i < st ? '✓' : i + 1}</b>${n}</span>`).join('')}</nav>
    <div class="grow"></div>
    ${hasData() ? `<div class="timer" title="Everything is wiped after 10 idle minutes">${I.clock}<span id="timer">Clears in 10:00</span></div>` : ''}
    <div class="shield" title="A Content-Security-Policy in this file blocks all network access"><b></b>Offline<span class="long">· <span id="netcount">0</span> network requests</span></div>
    <button class="iconbtn" data-act="theme" title="Theme: ${theme}" aria-label="Switch theme (now ${theme})">${themeIcon}</button>
    ${hasData() ? `<button class="btn" data-act="clear" title="Remove every file and password from this tab">Clear<span class="sr"> everything</span></button>` : ''}
  </header>${hasData() ? `<div class="mstep" aria-hidden="true"><i class="on"></i><i class="${st >= 1 ? 'on' : ''}"></i><i class="${st >= 2 ? 'on' : ''}"></i></div>` : ''}`;
}

function empty() {
  return `<main class="empty-wrap">
    <h1>Every certificate format, <span>in one drop.</span></h1>
    <p class="lede">Add your certificate, private key and CA bundle — in any format. ${esc(BRAND.name)} sorts them, checks they belong together, and gives you PFX, JKS, PEM and a ready-to-paste config for your server.</p>
    <div class="bigdrop" data-act="choose" role="button" tabindex="0" aria-label="Choose files to add, or drop them here">
      <div class="plus">${I.plus}</div>
      <h2>Drop anything here</h2>
      <p>The zip from your CA, loose files, or an existing PFX / JKS — we’ll work out what each one is.</p>
      <div class="types">${['.crt', '.cer', '.pem', '.key', '.ca-bundle', '.p7b', '.der', '.pfx', '.p12', '.jks', '.zip'].map((t) => `<i>${t}</i>`).join('')}</div>
      <div class="paste">or <button class="link" data-act="paste">paste text</button> · or <span class="link">choose files</span></div>
    </div>
    ${S.paste ? pasteBox() : ''}
    <div class="ghosts">
      <div class="slot empty"><div class="lab">Certificate</div><div class="fn plain">Waiting for your .crt / .pem</div></div>
      <div class="slot empty"><div class="lab">Private key</div><div class="fn plain">The key you made with your CSR</div></div>
      <div class="slot empty"><div class="lab">CA bundle</div><div class="fn plain">Intermediates — we can fill these in</div></div>
    </div>
    <div class="trust">
      <div><span class="ti">${I.noWifi}</span><div><b>Works offline</b>A security policy in this file blocks every network request.</div></div>
      <div><span class="ti">${I.lock}</span><div><b>Nothing is saved</b>Files and passwords live only in this tab, and clear after 10 idle minutes.</div></div>
      <div><span class="ti">${I.bolt}</span><div><b>Checked before converting</b>Key match, chain order and expiry — before anything downloads.</div></div>
    </div>
  </main>${BRAND.footer ? `<div class="foot">${esc(BRAND.footer)}</div>` : ''}`;
}
function pasteBox() {
  return `<div class="pastebox"><label class="sr" for="pastearea">Paste certificates or keys</label>
    <textarea id="pastearea" placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----" spellcheck="false"></textarea>
    <div class="row"><button class="btn sm" data-act="paste-cancel">Cancel</button><button class="btn primary sm" data-act="paste-add">Add</button></div></div>`;
}

function workbench() {
  return `<main class="work">${intake()}${inspector()}${output()}</main>`;
}

/* intake panel */
function intake() {
  const m = S.model, zips = S.pieces.filter((p) => p.type === 'zip');
  const certSlot = (() => {
    if (!m || !m.leaf) return `<div class="slot empty"><div class="lab">Certificate</div><div class="fn plain">Waiting for your certificate</div></div>`;
    const l = m.leaf;
    return `<div class="slot"><div class="lab">Certificate<span style="color:var(--ok)">✓</span></div><div class="fn">${I.file}${esc(l.source)}</div>
      <div class="sub"><span class="chip">${l.selfSigned ? 'Self-signed' : 'Leaf'}</span><span class="chip">${esc(l.pub.label)}</span>${l.validation ? `<span class="chip">${l.validation}</span>` : ''}</div></div>`;
  })();
  const keySlot = (() => {
    if (!m || !m.key) return `<div class="slot empty"><div class="lab">Private key</div><div class="fn plain">${m && m.leaf ? 'Add the key you created with your CSR — needed for PFX, JKS and server packs' : 'The key you made with your CSR'}</div></div>`;
    const k = m.key, bad = m.keyMatch === false;
    return `<div class="slot ${bad ? 'bad' : ''}"><div class="lab">Private key<span style="color:var(--${bad ? 'bad' : 'ok'})">${bad ? '✕' : '✓'}</span></div><div class="fn">${I.file}${esc(k.source)}</div>
      <div class="sub"><span class="chip">${esc(k.label)}</span><span class="chip">${k.wasEncrypted ? 'Unlocked' : 'Unencrypted'}</span>${bad ? '<span class="chip bad">Doesn’t match certificate</span>' : m.keyMatch ? '<span class="chip ok">Matches</span>' : ''}</div></div>`;
  })();
  const bundleSlot = (() => {
    if (!m || !m.leaf) return `<div class="slot empty"><div class="lab">CA bundle</div><div class="fn plain">Intermediates — we can fill these in</div></div>`;
    const user = m.intermediates.filter((c) => !c.fromLibrary), lib = m.intermediates.filter((c) => c.fromLibrary);
    const srcs = [...new Set(user.map((c) => c.source))];
    const warn = !!m.missing && m.missing.kind !== 'root' && !m.leaf.selfSigned;
    if (!user.length && !lib.length) return `<div class="slot ${warn ? 'warn' : 'empty'}"><div class="lab">CA bundle${warn ? '<span style="color:var(--warn)">!</span>' : ''}</div><div class="fn plain">${warn ? 'Intermediate missing — see the Inspector' : m.rootKnown === 'trusted' ? 'Not needed — issued straight from a trusted root' : 'None added'}</div>${warn ? '<div class="sub"><span class="chip warn">Intermediate missing</span></div>' : ''}</div>`;
    return `<div class="slot ${warn ? 'warn' : ''}"><div class="lab">CA bundle<span style="color:var(--${warn ? 'warn' : 'ok'})">${warn ? '!' : '✓'}</span></div>
      <div class="fn">${I.file}${esc(srcs.length ? srcs.join(', ') : 'Built-in library')}</div>
      <div class="sub"><span class="chip">${m.intermediates.length} certificate${m.intermediates.length === 1 ? '' : 's'}</span>${lib.length ? '<span class="chip acc">From library</span>' : ''}${warn ? '<span class="chip warn">Intermediate missing</span>' : `<span class="chip ok">${m.reordered ? 'Put in order' : 'Ordered'}</span>`}</div></div>`;
  })();
  const locked = S.locked.map((l) => {
    const err = S.lockErr[l.id];
    const keyPw = err && err.code === 'KEY_PASSWORD';
    return `<div class="slot locked"><div class="lab">${esc(l.label)}<span style="color:var(--accent)">${I.lock}</span></div><div class="fn">${I.file}${esc(l.source)}</div>
      <form class="unlock" data-unlock="${l.id}" autocomplete="off"><label class="sr" for="pw-${l.id}">Password for ${esc(l.source)}</label>
        <input class="input" type="password" id="pw-${l.id}" placeholder="${l.kind === 'jks' ? 'Keystore password' : 'Password'}" spellcheck="false">
        ${keyPw ? `<input class="input" type="password" id="kpw-${l.id}" placeholder="Key password" spellcheck="false">` : ''}
        <button class="btn primary sm" type="submit">Unlock</button></form>
      ${err ? `<div class="err" role="alert">${esc(err.msg)}</div>` : `<div class="note" style="margin-top:8px">Password-protected. ${l.kind === 'pfx' ? 'Leave empty if it has none.' : ''}</div>`}</div>`;
  }).join('');
  const notes = S.pieces.filter((p) => p.type === 'note').map((n) =>
    `<div class="note ${n.level === 'warn' ? 'warn' : ''}">${I.file}<div><b>${esc(n.source)}</b> ${esc(n.text)}</div></div>`).join('');
  const extras = m ? [
    m.extraCerts.length ? `<div class="note warn">${I.file}<div><b>${m.extraCerts.length} extra certificate${m.extraCerts.length > 1 ? 's' : ''}</b> not part of this chain: ${esc(m.extraCerts.map((c) => c.subject.short).join(', '))}</div></div>` : '',
    m.extraKeys.length ? `<div class="note warn">${I.file}<div><b>${m.extraKeys.length} extra private key${m.extraKeys.length > 1 ? 's' : ''}</b> that don’t match this certificate — set aside.</div></div>` : '',
  ].join('') : '';
  return `<section class="panel" aria-labelledby="h-files"><div class="ph"><em>01</em><h2 id="h-files">Your files</h2><span class="r">${[m?.leaf, m?.key, m && (m.intermediates.length || m.rootKnown === 'trusted')].filter(Boolean).length} of 3</span></div><div class="pb">
    <div class="dropmini" data-act="choose" role="button" tabindex="0" aria-label="Add more files">${I.zip}<div><strong>Drop more files</strong> or <button class="link" data-act="paste">paste text</button> · .crt .key .pem .p7b .pfx .jks .zip</div></div>
    ${S.paste ? pasteBox() : ''}
    ${zips.map((z) => `<div class="src">Unpacked from <code>${esc(z.source)}</code></div>`).join('')}
    ${locked}${certSlot}${keySlot}${bundleSlot}${extras}${notes}
  </div></section>`;
}

/* inspector panel */
function ring(ok, total, color) {
  const c = 2 * Math.PI * 19, p = total ? ok / total : 0;
  return `<svg class="ring" viewBox="0 0 46 46" aria-hidden="true"><circle cx="23" cy="23" r="19" fill="none" stroke="${color}" stroke-opacity=".18" stroke-width="5"/><circle cx="23" cy="23" r="19" fill="none" stroke="${color}" stroke-width="5" stroke-linecap="round" stroke-dasharray="${c * p} ${c}" transform="rotate(-90 23 23)"/><text x="23" y="27.5" text-anchor="middle" font-size="12" font-weight="800" fill="${color}" font-family="system-ui,sans-serif">${ok}/${total}</text></svg>`;
}
const joint = `<div class="joint">${I.joint}</div>`;
function inspector() {
  const m = S.model;
  if (!m || !m.leaf) {
    const msg = S.locked.length ? 'Unlock your file on the left to see what’s inside.' : m && m.key ? 'We have your private key. Now add the certificate it belongs to.' : 'Add a certificate to see its details and checks.';
    return `<section class="panel"><div class="hero"><div><div class="sect" style="margin:0 0 6px">02 · Inspector</div><h1>Waiting for a certificate</h1><p style="color:var(--ink-3);margin:6px 0 16px">${msg}</p></div></div></section>`;
  }
  const l = m.leaf, r = S.report;
  const bad = r.checks.filter((c) => c.status === 'bad').length, warn = r.checks.filter((c) => c.status === 'warn').length;
  const scoreCls = bad ? 'bad' : warn ? 'warn' : '';
  const color = bad ? 'var(--bad)' : warn ? 'var(--warn)' : 'var(--ok)';
  const scoreText = bad ? [`${bad} issue${bad > 1 ? 's' : ''} to fix`, onlyKeyProblem() ? 'Key files paused until fixed' : 'Download is paused until fixed']
    : warn ? [`Ready, ${warn} warning${warn > 1 ? 's' : ''}`, 'Read them before you deploy'] : ['Ready to deploy', `All ${r.score.total} checks passed`];
  const title = l.subject.CN || l.sans[0] || l.subject.short;
  const sans = l.sans.slice(0, 4).map((s) => `<span class="chip acc">${esc(s)}</span>`).join('') + (l.sans.length > 4 ? `<span class="chip acc">+${l.sans.length - 4} more</span>` : '');
  const issuerOrg = l.issuer.O || l.issuer.short;
  const banner = m.keyMatch === false ? `<div class="banner" role="alert"><span class="x">${I.x}</span><div><h3>This private key doesn’t belong to this certificate</h3>
      <p>Most often the certificate was issued from a different CSR, or it was reissued with a new key. Find the key created with the CSR you sent to the CA.</p>
      <div class="fps"><span>Certificate key</span>SHA-256 ${esc(short(l.pubFp))}<span>Your key file</span>SHA-256 ${esc(short(m.key.pubFp))}</div></div></div>` : '';
  // chain
  const link = (c, i, cls, role) => `<div class="chainlink ${cls}"><div class="t"><span class="n">${i}</span><span class="nm">${esc(c.subject.CN || c.subject.short)}</span><span class="role">${role}</span></div>
    <div class="m">Issued by <b>${esc(c.issuer.CN || c.issuer.short)}</b> · valid until <b>${fmtDate(c.notAfter)}</b>${c.fromLibrary ? ' · <span class="chip acc">Added from library</span>' : ''}</div>
    <div class="fp" title="SHA-256 fingerprint">SHA-256 ${esc(c.sha256)}</div></div>`;
  let n = 1, parts = [link(l, n++, 'leaf', 'Your certificate')];
  for (const c of m.intermediates) parts.push(link(c, n++, '', 'Intermediate'));
  if (m.missing && m.missing.kind === 'root') {
    parts.push(`<div class="chainlink ghost"><div class="t"><span class="n">${n++}</span><span class="nm">${esc(m.missing.issuerName)}</span><span class="role">Root · not supplied</span></div><div class="m">Not a public root. Fine for an internal CA — <button class="link" data-act="choose">add the root</button> if you want it in a truststore.</div></div>`);
  } else if (m.missing && !l.selfSigned) {
    const lib = m.missing.library;
    parts.push(`<div class="chainlink missing"><div class="t"><span class="n">${n++}</span><span class="nm">Intermediate missing</span><span class="role">Not in your files</span></div>
      <div class="m">Your certificate was issued by <b>${esc(m.missing.issuerName)}</b>.${lib ? '' : ' It isn’t in the built-in library — ask your CA for the CA bundle.'}</div>
      <div class="acts">${lib ? `<button class="btn primary sm" data-act="add-lib" data-sha="${esc(lib.sha256)}">Add from built-in library</button>` : ''}<button class="btn sm" data-act="choose">Upload it</button></div></div>`);
  }
  if (m.root) parts.push(`<div class="chainlink ghost"><div class="t"><span class="n">${n++}</span><span class="nm">${esc(m.root.subject.short)}</span><span class="role">Root</span></div><div class="m">${m.rootKnown === 'trusted' ? 'Already trusted by browsers and Java — ' : 'Private root — '}${S.includeRoot ? 'included in your files' : 'left out of server files on purpose'}</div></div>`);
  else if (m.rootKnown === 'trusted') parts.push(`<div class="chainlink ghost"><div class="t"><span class="n">${n++}</span><span class="nm">${esc(m.rootName)}</span><span class="role">Root</span></div><div class="m">Already trusted by browsers and Java — left out of server files on purpose</div></div>`);
  const chain = parts.join(joint);
  const ic = { ok: I.check, bad: I.x, warn: I.bang };
  const checks = r.checks.map((c) => `<li class="${c.status === 'bad' ? 'bad' : ''}"><span class="ic ${c.status}">${ic[c.status]}</span><div>${esc(c.title)}${c.detail ? `<small>${esc(c.detail)}</small>` : ''}</div></li>`).join('');
  const lt = lifetime(l);
  const tcls = lt.left < 0 ? 'bad' : lt.left <= 30 ? 'warn' : '';
  const clock = `<div class="clock"><div class="top"><span style="color:var(--ink-2)">Renewal clock</span><b>${lt.left < 0 ? 'Expired' : `${lt.left} day${lt.left === 1 ? '' : 's'} left`}</b></div>
    <div class="track" role="img" aria-label="${Math.round(lt.pct * 100)}% of the certificate lifetime used"><i class="${tcls}" style="width:${Math.max(2, lt.pct * 100)}%"></i></div>
    <div class="ticks"><span>Issued ${fmtDate(l.notBefore)}</span><span>Expires ${fmtDate(l.notAfter)}</span></div>
    <div class="nudge">This certificate lasts ${lt.total} days. Public certificate lifetimes are shrinking toward 47 days.${BRAND.automationUrl ? ` <a class="link" href="${esc(BRAND.automationUrl)}" target="_blank" rel="noopener noreferrer">${esc(BRAND.automationLabel)} →</a>` : ''}</div></div>`;
  return `<section class="panel" aria-labelledby="h-insp"><div class="hero"><div style="min-width:0"><div class="sect" style="margin:0 0 6px">02 · Inspector</div><h1 id="h-insp">${esc(title)}</h1>
      <div class="sans">${sans}${l.validation ? `<span class="chip">${l.validation} · ${esc(issuerOrg)}</span>` : `<span class="chip">${esc(issuerOrg)}</span>`}<span class="chip" title="Serial ${esc(l.serial)}">Serial ${esc(l.serial.slice(0, 8))}…</span></div></div>
      <div class="score ${scoreCls}">${ring(r.score.ok, r.score.total, color)}<div><b>${scoreText[0]}</b><span>${scoreText[1]}</span></div></div></div>
    ${banner}
    <div class="cols"><div><div class="sect">Certificate chain</div>${chain}</div><div><div class="sect">Readiness checks</div><ul class="checks">${checks}</ul></div>${clock}</div></section>`;
}

/* output panel */
function output() {
  const m = S.model, ready = !!(m && m.leaf);
  const pack = S.server ? packById(S.server) : null;
  const servers = PACKS.map((p) => `<button class="srv" data-act="server" data-id="${p.id}" aria-pressed="${S.server === p.id}" ${ready ? '' : 'disabled'}><div class="g">${p.glyph}</div>${p.name}</button>`).join('');
  const tile = (f) => {
    const av = fmtAvailable(f), on = S.sel.has(f.id) && av.ok;
    return `<div class="fmt ${on ? 'on' : ''} ${av.ok ? '' : 'off'}"><span class="ext">.${f.ext}</span><div class="d"><b>${esc(f.title)}</b><span>${esc(av.ok ? f.desc : av.why)}</span></div>
      ${av.ok ? `<button class="dl" data-act="dl-one" data-id="${f.id}" title="Download ${esc(f.title)} on its own" aria-label="Download ${esc(f.title)}">${I.dl}</button>` : ''}
      <button class="tog" role="switch" aria-checked="${on}" aria-label="Include ${esc(f.title)}" data-act="toggle" data-id="${f.id}" ${av.ok ? '' : 'disabled'}></button></div>`;
  };
  let formats = '';
  if (pack) {
    const rec = pack.rec.map(formatById), others = FORMATS.filter((f) => !pack.rec.includes(f.id));
    formats = `<div class="need"><b>${pack.name} needs</b> ${esc(pack.needs)}.</div>${rec.map(tile).join('')}
      <button class="more" data-act="more" aria-expanded="${S.more}"><span>${S.more ? 'Hide other formats' : `${others.length} other formats`}</span><span class="stack">${S.more ? '' : (() => { const ex = [...new Set(others.map((f) => f.ext.toUpperCase()))]; return ex.slice(0, 5).map((e) => `<i>${e}</i>`).join('') + (ex.length > 5 ? `<i>+${ex.length - 5}</i>` : ''); })()}</span></button>
      ${S.more ? others.map(tile).join('') : ''}`;
  } else if (ready) {
    formats = `<div class="need">Pick your server above for exactly what it needs, or choose formats yourself:</div>${FORMATS.map(tile).join('')}`;
  }
  const pwNeeded = ready && needsPassword();
  const ps = pwState(), [sl, sc] = strength(S.password);
  const anyPwFmt = [...S.sel].some((id) => ['jks', 'truststore'].includes(id)) || S.server === 'tomcat';
  const pwField = pwNeeded ? `<div class="field"><label for="out-pw">${anyPwFmt ? 'Keystore password' : 'File password'}</label><div class="f"><div class="inwrap">
      <input class="input" id="out-pw" type="password" value="${esc(S.password)}" autocomplete="new-password" spellcheck="false" aria-describedby="pw-help">
      <span class="strength" id="pw-strength" style="color:${sc}">${sl}</span><button class="eye" data-act="eye" type="button" aria-label="Show password">Show</button></div>
      <button class="btn" data-act="gen" title="Generate a strong password on this device" aria-label="Generate password">${I.dice}</button></div>
      <small id="pw-help" class="${ps.cls}">${esc(ps.msg)}</small></div>` : '';
  const aliasField = ready && canKey() && needsAlias() ? `<div class="field"><label for="out-alias">Alias / friendly name</label><input class="input" id="out-alias" value="${esc(S.alias)}" spellcheck="false"><small>What Java and Windows call this key inside the keystore</small></div>` : '';
  const rootOpt = ready && m.root ? `<label class="opt"><span>Include the root certificate in files</span><button class="tog" role="switch" aria-checked="${S.includeRoot}" data-act="root" aria-label="Include root certificate"></button></label>` : '';
  const blocked = S.report && S.report.blocking && !onlyKeyProblem() && !S.override;
  const packOk = pack && (!pack.files || true) && ready;
  const packNeedsKey = pack && pack.rec.some((id) => formatById(id).key);
  const primary = pack
    ? `<button class="btn primary big" data-act="dl-pack" ${!packOk || blocked || (packNeedsKey && !canKey()) ? 'disabled' : ''}>${I.dl}Download ${pack.name} pack (.zip)</button>`
    : `<button class="btn primary big" data-act="dl-sel" ${!ready || blocked || !S.sel.size ? 'disabled' : ''}>${I.dl}${S.sel.size > 1 ? `Download ${S.sel.size} files (.zip)` : S.sel.size === 1 ? 'Download file' : 'Choose formats to download'}</button>`;
  const why = !ready ? '' : blocked ? `<div class="why">Fix the issues in the Inspector first · <button class="link" data-act="override">Download anyway</button></div>`
    : pack && packNeedsKey && !canKey() ? `<div class="why">${m.key ? 'The private key doesn’t match — add the right key to build this pack.' : 'Add your private key to build this pack.'}</div>` : '';
  return `<section class="panel out" aria-labelledby="h-out"><div class="ph"><em>03</em><h2 id="h-out">Where is this going?</h2></div><div class="pb">
    <div class="servers" role="group" aria-label="Server">${servers}</div>
    ${ready ? formats : '<div class="need">Add your certificate first — then pick a server or choose formats.</div>'}
    ${pwField}${aliasField}${rootOpt}
    ${ready ? `<div class="dlbox">${primary}${why}<div class="sec">${pack ? `<button class="btn" data-act="dl-sel" ${!S.sel.size || blocked ? 'disabled' : ''}>Selected files (.zip)</button>` : ''}<button class="btn" data-act="text">Copy as text</button></div></div>` : ''}
  </div></section>`;
}

/* drawers */
function highlight(code) {
  return esc(code).split('\n').map((line) => {
    if (/^\s*(#|&lt;!--|\/\/)/.test(line)) return `<span class="c">${line}</span>`;
    return line.replace(/(&quot;[^&]*?&quot;)/g, '<span class="s">$1</span>').replace(/(&lt;\/?)([A-Za-z][\w:-]*)/g, '$1<span class="k">$2</span>');
  }).join('\n');
}
function drawer() {
  if (!S.drawer || !S.model || !S.model.leaf) return '';
  if (S.drawer === 'pack') {
    const pack = packById(S.server), c = ctx(), snip = pack.snippet ? pack.snippet(c) : null;
    const files = S.packFiles || [];
    return `<div class="scrim" data-act="close"></div><aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="dr-h">
      <div class="dh"><div class="g">${pack.glyph}</div><div><h2 id="dr-h">${pack.name} pack</h2><p>${files.length} files · downloaded as ${esc(c.base)}-${pack.id}.zip</p></div><span class="chip ok" style="margin-left:auto">Built on this device</span></div>
      <div class="db"><div class="sect">What’s in the zip</div><div class="tree">${files.map((f) => `<div>${I.file}${esc(f.name)}<span>${esc(f.note || '')}</span></div>`).join('')}</div>
      ${snip ? `<div class="lbl"><span>${esc(snip.title)}</span><button class="copybtn" data-act="copy-snip">Copy</button></div><div class="code" id="snip">${highlight(snip.code)}</div>` : ''}
      ${pack.verify ? `<div class="lbl"><span>Check it yourself (optional)</span><button class="copybtn" data-act="copy-verify">Copy</button></div><div class="code" id="verify">${esc(pack.verify(c))}</div>` : ''}
      <div class="lbl"><span>Then</span></div><ol>${pack.steps(c).map((s) => `<li>${esc(s)}</li>`).join('')}</ol></div>
      <div class="df"><button class="btn primary big" style="flex:1" data-act="dl-pack">${I.dl}Download again</button><button class="btn" data-act="close">Close</button></div></aside>`;
  }
  if (S.drawer === 'text') {
    const c = ctx();
    const blocks = [
      ['Certificate', pem('CERTIFICATE', c.chain[0])],
      ...(c.ca.length ? [['CA bundle', c.ca.map((d) => pem('CERTIFICATE', d)).join('')]] : []),
      ['Full chain', c.chain.map((d) => pem('CERTIFICATE', d)).join('')],
      ...(c.key ? [['Private key', keyPemPkcs8(c.key.pkcs8)]] : []),
    ];
    return `<div class="scrim" data-act="close"></div><aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="dr-h">
      <div class="dh"><div class="g">PEM</div><div><h2 id="dr-h">Copy as text</h2><p>For control panels that want you to paste each part</p></div></div>
      <div class="db">${blocks.map(([t, v], i) => `<div class="lbl"><span>${t}</span><button class="copybtn" data-act="copy-block" data-i="${i}">Copy</button></div><div class="code" id="blk-${i}" style="max-height:180px">${esc(v)}</div>`).join('')}</div>
      <div class="df"><button class="btn" data-act="close">Close</button></div></aside>`;
  }
  return '';
}

/* ---------------- events ---------------- */
let fileInput;
function chooseFiles() { fileInput.value = ''; fileInput.click(); }

function onClick(e) {
  const t = e.target.closest('[data-act]'); if (!t) return;
  const act = t.dataset.act;
  switch (act) {
    case 'choose': chooseFiles(); break;
    case 'paste': e.preventDefault(); S.paste = true; render(); document.getElementById('pastearea')?.focus(); break;
    case 'paste-cancel': S.paste = false; render(); break;
    case 'paste-add': addText(document.getElementById('pastearea').value); break;
    case 'clear': clearAll(false); break;
    case 'theme': theme = theme === 'auto' ? 'light' : theme === 'light' ? 'dark' : 'auto'; applyTheme(); render(); break;
    case 'server': {
      const id = t.dataset.id; S.server = S.server === id ? null : id;
      if (S.server) { S.sel = new Set(packById(id).rec.filter((f) => fmtAvailable(formatById(f)).ok)); S.more = false; }
      if (!S.aliasTouched) S.alias = defaultAlias();
      render(); break;
    }
    case 'toggle': { const id = t.dataset.id; S.sel.has(id) ? S.sel.delete(id) : S.sel.add(id); render(); break; }
    case 'more': S.more = !S.more; render(); break;
    case 'root': S.includeRoot = !S.includeRoot; render(); break;
    case 'gen': S.password = genPassword(); render(); { const i = document.getElementById('out-pw'); if (i) { i.type = 'text'; i.focus(); const b = document.querySelector('[data-act="eye"]'); if (b) b.textContent = 'Hide'; } } toast('Strong password generated on this device — copy it now.'); break;
    case 'eye': { const i = document.getElementById('out-pw'); i.type = i.type === 'password' ? 'text' : 'password'; t.textContent = i.type === 'password' ? 'Show' : 'Hide'; break; }
    case 'override': S.override = true; render(); break;
    case 'dl-pack': downloadPack(); break;
    case 'dl-sel': downloadSelected(); break;
    case 'dl-one': downloadOne(t.dataset.id); break;
    case 'text': S.drawer = 'text'; render(); break;
    case 'close': S.drawer = null; render(); break;
    case 'add-lib': S.added.add(t.dataset.sha); setBusy(1); recompute().then(() => { setBusy(-1); render(); toast('Intermediate added from the built-in library.'); }); break;
    case 'copy-snip': copyText(document.getElementById('snip').textContent, t); break;
    case 'copy-verify': copyText(document.getElementById('verify').textContent, t); break;
    case 'copy-block': copyText(document.getElementById('blk-' + t.dataset.i).textContent, t); break;
  }
}
function onInput(e) {
  idleAt = Date.now();
  const t = e.target;
  if (t.id === 'out-pw') {
    const before = needsPassword() && pwState().ok;
    S.password = t.value;
    const ps = pwState(), [sl, sc] = strength(S.password);
    const st = document.getElementById('pw-strength'); if (st) { st.textContent = sl; st.style.color = sc; }
    const h = document.getElementById('pw-help'); if (h) { h.textContent = ps.msg; h.className = ps.cls; }
    if (before !== ps.ok) { /* no re-render needed: buttons validate on click */ }
  } else if (t.id === 'out-alias') { S.alias = t.value; S.aliasTouched = true; }
}
function onSubmit(e) {
  const f = e.target.closest('[data-unlock]'); if (!f) return;
  e.preventDefault(); doUnlock(f.dataset.unlock);
}
function onKey(e) {
  if (e.key === 'Escape' && S.drawer) { S.drawer = null; render(); }
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('[role="button"][data-act="choose"]')) { e.preventDefault(); chooseFiles(); }
}
function onPaste(e) {
  const tag = (e.target.tagName || '').toLowerCase();
  if (tag === 'input' || tag === 'textarea') return;
  const text = e.clipboardData && e.clipboardData.getData('text');
  if (text && /-----BEGIN /.test(text)) { e.preventDefault(); addText(text); }
}

/* drag & drop anywhere */
function onDrag(e) {
  if (!e.dataTransfer || ![...e.dataTransfer.types].includes('Files')) return;
  e.preventDefault();
  if (e.type === 'dragenter') { dragDepth++; showOverlay(true); }
  if (e.type === 'dragleave') { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) showOverlay(false); }
  if (e.type === 'drop') { dragDepth = 0; showOverlay(false); if (e.dataTransfer.files.length) addFiles([...e.dataTransfer.files]); }
}
function showOverlay(on) {
  let o = document.querySelector('.dropzone-overlay');
  document.body.classList.toggle('dragging', on);
  if (on && !o) { o = document.createElement('div'); o.className = 'dropzone-overlay'; o.textContent = 'Drop to add — nothing leaves this computer'; document.body.appendChild(o); }
  if (!on && o) o.remove();
}

/* idle clear + network counter */
function tick() {
  const nc = document.getElementById('netcount');
  if (nc && performance.getEntriesByType) nc.textContent = String(performance.getEntriesByType('resource').length);
  const el = document.getElementById('timer');
  if (!hasData()) return;
  const left = Math.max(0, IDLE_SECONDS - Math.floor((Date.now() - idleAt) / 1000));
  if (el) el.textContent = `Clears in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
  if (left <= 0) clearAll(true);
}
function applyTheme() {
  if (theme === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
}

export function start() {
  fileInput = document.createElement('input');
  fileInput.type = 'file'; fileInput.multiple = true; fileInput.hidden = true;
  fileInput.accept = '.crt,.cer,.pem,.key,.der,.p7b,.p7c,.pfx,.p12,.jks,.keystore,.zip,.ca-bundle,.csr,.txt';
  fileInput.addEventListener('change', () => { if (fileInput.files.length) addFiles([...fileInput.files]); });
  document.body.appendChild(fileInput);
  document.addEventListener('click', onClick);
  document.addEventListener('input', onInput);
  document.addEventListener('submit', onSubmit);
  document.addEventListener('keydown', onKey);
  document.addEventListener('paste', onPaste);
  for (const ev of ['dragenter', 'dragover', 'dragleave', 'drop']) window.addEventListener(ev, onDrag);
  for (const ev of ['pointerdown', 'keydown', 'wheel']) window.addEventListener(ev, () => { idleAt = Date.now(); }, { passive: true });
  setInterval(tick, 1000);
  render();
}

// test hook (used by the browser tests; harmless in production)
export const __state = () => S;
