// Turn anything the user drops or pastes into "pieces": certificates, keys, locked items and notes.
import { asn1, util, A, der as toDer, fromDer, toBin, toU8, CfError } from './util.js';
import { parseCert } from './cert.js';
import { describeKey, wrapRsa, wrapSec1, decryptPkcs8, decryptLegacyPem } from './keys.js';
import { isPkcs12, readPkcs12 } from './pkcs12.js';
import { isJks, isJceks, readJks } from './jks.js';
import { isPkcs7, readPkcs7 } from './pkcs7.js';
import { isZip, readZip } from './zip.js';

const T = asn1.Type;
let seq = 0;
const lockedId = () => 'lk' + (++seq);

const note = (source, text, level = 'info') => ({ type: 'note', source, text, level });

/** @param {string} name @param {Uint8Array} u8 */
export async function ingestFile(name, u8, depth = 0) {
  if (u8.length > 20 * 1024 * 1024) return [note(name, 'Too large to be a certificate file — skipped.', 'warn')];
  if (isZip(u8)) {
    if (depth > 1) return [note(name, 'Zip inside a zip — skipped.', 'warn')];
    let entries;
    try { entries = await readZip(u8); } catch (e) { return [note(name, e.message, 'warn')]; }
    const out = [{ type: 'zip', source: name, count: entries.length }];
    for (const e of entries) {
      if (e.error) out.push(note(e.name, e.error, 'warn'));
      else out.push(...await ingestFile(e.name, e.data, depth + 1));
    }
    return out;
  }
  const bin = toBin(u8);
  if (isJks(bin)) return [{ type: 'locked', id: lockedId(), source: name, kind: 'jks', data: bin, label: 'Java keystore (JKS)' }];
  if (isJceks(bin)) return [note(name, 'This is a JCEKS keystore. Convert it to JKS or PKCS#12 with keytool first.', 'warn')];
  // Text? (PEM, or base64 DER without headers)
  const text = looksText(u8) ? new TextDecoder().decode(u8) : null;
  if (text !== null) {
    if (/-----BEGIN /.test(text)) return ingestText(text, name);
    const compact = text.replace(/\s+/g, '');
    if (/^[A-Za-z0-9+/=]{40,}$/.test(compact)) {
      try { return ingestDer(util.decode64(compact), name); } catch { /* fall through */ }
    }
    if (text.trim() === '') return [note(name, 'This file is empty.', 'warn')];
    return [note(name, 'Not a certificate, key or keystore — skipped.', 'warn')];
  }
  return ingestDer(bin, name);
}

function looksText(u8) {
  const n = Math.min(u8.length, 2048);
  for (let i = 0; i < n; i++) { const c = u8[i]; if (c === 0 || (c < 9) || (c > 13 && c < 32 && c !== 27)) return false; }
  return true;
}

/** Pasted text or a PEM file: may hold many blocks of different kinds. */
export async function ingestText(text, source = 'Pasted text') {
  const out = [];
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
  let m, found = 0;
  while ((m = re.exec(text))) {
    found++;
    const label = m[1].trim();
    let body = m[2], headers = {};
    if (/^\s*[A-Za-z-]+:/m.test(body)) {
      const lines = body.split(/\r?\n/), rest = [];
      for (const l of lines) { const h = /^\s*([A-Za-z-]+):\s*(.*)$/.exec(l); if (h) headers[h[1]] = h[2].trim(); else rest.push(l); }
      body = rest.join('');
    }
    let derBytes;
    try { derBytes = util.decode64(body.replace(/[^A-Za-z0-9+/=]/g, '')); } catch { out.push(note(source, `A ${label} block is damaged.`, 'warn')); continue; }
    const where = blockName(source, found);
    switch (label) {
      case 'CERTIFICATE': case 'X509 CERTIFICATE': case 'TRUSTED CERTIFICATE': {
        const c = parseCert(derBytes, where);
        out.push(c || note(where, 'A certificate block could not be read.', 'warn'));
        break;
      }
      case 'PRIVATE KEY': out.push(await describeKey(derBytes, where)); break;
      case 'RSA PRIVATE KEY': case 'EC PRIVATE KEY': {
        const kind = label.startsWith('RSA') ? 'rsa' : 'sec1';
        if (headers['DEK-Info']) out.push({ type: 'locked', id: lockedId(), source: where, kind: 'legacy-pem', keyKind: kind, data: derBytes, dekInfo: headers['DEK-Info'], label: 'Encrypted private key' });
        else out.push(await describeKey(kind === 'rsa' ? wrapRsa(derBytes) : wrapSec1(derBytes), where));
        break;
      }
      case 'ENCRYPTED PRIVATE KEY': out.push({ type: 'locked', id: lockedId(), source: where, kind: 'pkcs8', data: derBytes, label: 'Encrypted private key' }); break;
      case 'CERTIFICATE REQUEST': case 'NEW CERTIFICATE REQUEST':
        out.push(note(where, 'set aside — that’s your certificate request (CSR), not needed to convert.', 'csr')); break;
      case 'PKCS7': case 'CMS': out.push(...await ingestDer(derBytes, where)); break;
      case 'EC PARAMETERS': break;
      case 'PUBLIC KEY': case 'RSA PUBLIC KEY': out.push(note(where, 'is a public key — you need the private key instead.', 'warn')); break;
      default: out.push(note(where, `“${label}” blocks aren’t used for conversion — skipped.`, 'warn'));
    }
  }
  if (!found) {
    const compact = text.replace(/\s+/g, '');
    if (/^[A-Za-z0-9+/=]{40,}$/.test(compact)) {
      try { return await ingestDer(util.decode64(compact), source); } catch { /* ignore */ }
    }
    out.push(note(source, 'No certificate or key found in this text.', 'warn'));
  }
  return out;
}

function blockName(source, n) { return n > 1 ? `${source} (#${n})` : source; }

async function ingestDer(bin, name) {
  let o;
  try { o = fromDer(bin, false); } catch { return [note(name, 'Not a certificate, key or keystore — skipped.', 'warn')]; }
  if (o.type !== T.SEQUENCE || !Array.isArray(o.value)) return [note(name, 'Not a certificate, key or keystore — skipped.', 'warn')];
  if (isPkcs12(o)) return [{ type: 'locked', id: lockedId(), source: name, kind: 'pfx', data: bin, label: 'PFX / PKCS#12' }];
  if (isPkcs7(o)) {
    const ders = readPkcs7(o);
    if (!ders.length) return [note(name, 'This PKCS#7 file holds no certificates.', 'warn')];
    return ders.map((d, i) => parseCert(d, blockName(name, i + 1)) || note(name, 'A certificate inside could not be read.', 'warn'));
  }
  const v = o.value;
  // Certificate
  if (v.length === 3 && v[0].type === T.SEQUENCE && Array.isArray(v[0].value) && v[0].value.length >= 6) {
    const c = parseCert(bin, name); if (c) return [c];
  }
  // CSR: SEQ{ SEQ{INTEGER, Name, SPKI, [0]}, alg, bits }
  if (v.length === 3 && v[0].type === T.SEQUENCE && Array.isArray(v[0].value) && v[0].value.length === 4 && v[0].value[0].type === T.INTEGER)
    return [note(name, 'set aside — that’s your certificate request (CSR), not needed to convert.', 'csr')];
  // PKCS#8
  if (v.length >= 3 && v[0].type === T.INTEGER && v[1].type === T.SEQUENCE && v[2].type === T.OCTETSTRING) return [await describeKey(bin, name)];
  // EncryptedPrivateKeyInfo
  if (v.length === 2 && v[0].type === T.SEQUENCE && v[1].type === T.OCTETSTRING) return [{ type: 'locked', id: lockedId(), source: name, kind: 'pkcs8', data: bin, label: 'Encrypted private key' }];
  // PKCS#1 RSA
  if (v.length === 9 && v.every((x) => x.type === T.INTEGER)) return [await describeKey(wrapRsa(bin), name)];
  // SEC1 EC
  if (v.length >= 2 && v[0].type === T.INTEGER && v[1].type === T.OCTETSTRING) return [await describeKey(wrapSec1(bin), name)];
  return [note(name, 'Not a certificate, key or keystore — skipped.', 'warn')];
}

/** Unlock a locked piece. Throws CfError with code BAD_PASSWORD / KEY_PASSWORD on failure. */
export async function unlock(piece, password, keyPassword) {
  const src = piece.source;
  if (piece.kind === 'pkcs8') return [await describeKey(decryptPkcs8(piece.data, password), src, { wasEncrypted: true })];
  if (piece.kind === 'legacy-pem') {
    const plain = decryptLegacyPem(piece.data, piece.dekInfo, password);
    return [await describeKey(piece.keyKind === 'rsa' ? wrapRsa(plain) : wrapSec1(plain), src, { wasEncrypted: true })];
  }
  if (piece.kind === 'pfx') {
    const r = readPkcs12(piece.data, password);
    const out = [];
    for (const k of r.keys) out.push(await describeKey(k.pkcs8, src, { friendlyName: k.friendlyName, localKeyId: k.localKeyId }));
    r.certs.forEach((c, i) => { const p = parseCert(c.der, src); if (p) { p.friendlyName = c.friendlyName; p.localKeyId = c.localKeyId; out.push(p); } });
    if (!r.keys.length) out.push(note(src, 'This PFX has no private key — only certificates.', 'warn'));
    return out;
  }
  if (piece.kind === 'jks') {
    const r = readJks(piece.data, password, keyPassword);
    const out = [];
    for (const k of r.keys) out.push(await describeKey(k.pkcs8, src, { friendlyName: k.alias }));
    for (const c of r.certs) { const p = parseCert(c.der, src); if (p) out.push(p); }
    return out;
  }
  throw new CfError('Unknown locked item.', 'ERROR');
}

export { toU8 };
