// Certificate parsing that never re-encodes the certificate itself: `der` is always the original bytes.
import { asn1, util, OID, CURVES, SIG_ALGS, A, der as toDer, fromDer, sha1, sha256, hex, colonHex } from './util.js';

const T = asn1.Type, CTX = asn1.Class.CONTEXT_SPECIFIC;

const DN = {
  '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
  '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'E', '2.5.4.97': 'organizationIdentifier', '0.9.2342.19200300.100.1.25': 'DC',
};

function str(v) {
  let s = v.value;
  if (v.type === T.BMPSTRING) { let t = ''; for (let i = 0; i + 1 < s.length; i += 2) t += String.fromCharCode((s.charCodeAt(i) << 8) | s.charCodeAt(i + 1)); return t; }
  if (v.type === T.UTF8) { try { return util.decodeUtf8(s); } catch { return s; } }
  return typeof s === 'string' ? s : '';
}

export function readName(n) {
  const out = { parts: [] };
  for (const set of n.value) for (const atv of set.value) {
    const oid = asn1.derToOid(atv.value[0].value), k = DN[oid] || oid, s = str(atv.value[1]);
    if (!(k in out)) out[k] = s;
    out.parts.push(`${k}=${s}`);
  }
  out.text = out.parts.join(', ');
  out.short = out.CN || out.O || out.OU || out.text;
  return out;
}

function readTime(t) { return t.type === T.UTCTIME ? asn1.utcTimeToDate(t.value) : asn1.generalizedTimeToDate(t.value); }

/** Parse SubjectPublicKeyInfo into a canonical public key description. */
export function readSpki(spki) {
  const algOid = asn1.derToOid(spki.value[0].value[0].value);
  const param = spki.value[0].value[1];
  const bits = spki.value[1].value; // raw BIT STRING contents incl. unused-bits byte
  const keyBytes = typeof bits === 'string' ? bits.substring(1) : toDer(spki.value[1]).substring(3);
  if (algOid === OID.rsa) {
    const rsa = fromDer(keyBytes, false);
    const n = stripZero(rsa.value[0].value), e = stripZero(rsa.value[1].value);
    return { kind: 'rsa', n, e, bits: bitLen(n), label: `RSA ${bitLen(n)}`, id: `rsa:${hex(n)}:${hex(e)}` };
  }
  if (algOid === OID.ec) {
    const curve = param && param.type === T.OID ? asn1.derToOid(param.value) : '';
    const name = CURVES[curve] || curve;
    return { kind: 'ec', curve, point: keyBytes, label: `EC ${name}`, id: `ec:${curve}:${hex(keyBytes)}` };
  }
  if (algOid === OID.ed25519) return { kind: 'ed25519', point: keyBytes, label: 'Ed25519', id: `ed:${hex(keyBytes)}` };
  if (algOid === OID.dsa) return { kind: 'dsa', label: 'DSA', id: `dsa:${hex(keyBytes)}` };
  return { kind: 'other', label: algOid, id: `${algOid}:${hex(keyBytes)}` };
}

function stripZero(b) { let i = 0; while (i < b.length - 1 && b.charCodeAt(i) === 0) i++; return b.substring(i); }
function bitLen(b) { if (!b.length) return 0; let first = b.charCodeAt(0), n = 0; while (first) { n++; first >>= 1; } return (b.length - 1) * 8 + n; }

/** Canonical SPKI DER for a public key description, so certificate and key fingerprints compare like for like. */
export function spkiDer(pub) {
  if (pub.kind === 'rsa') {
    const rsaPub = toDer(A.seq([A.intBytes(pad(pub.n)), A.intBytes(pad(pub.e))]));
    return toDer(A.seq([A.seq([A.oid(OID.rsa), A.nul()]), A.bits(rsaPub)]));
  }
  if (pub.kind === 'ec') return toDer(A.seq([A.seq([A.oid(OID.ec), A.oid(pub.curve)]), A.bits(pub.point)]));
  if (pub.kind === 'ed25519') return toDer(A.seq([A.seq([A.oid(OID.ed25519)]), A.bits(pub.point)]));
  return '';
}
function pad(b) { return b.charCodeAt(0) & 0x80 ? '\x00' + b : b; }
export function pubFingerprint(pub) { const d = spkiDer(pub); return d ? colonHex(sha256(d)) : ''; }

function extValue(exts, oid) {
  if (!exts) return null;
  for (const e of exts.value) {
    if (asn1.derToOid(e.value[0].value) === oid) {
      const octet = e.value[e.value.length - 1];
      try { return fromDer(octet.value, false); } catch { return null; }
    }
  }
  return null;
}

const POLICY = { '2.23.140.1.2.1': 'DV', '2.23.140.1.2.2': 'OV', '2.23.140.1.1': 'EV', '2.23.140.1.2.3': 'IV' };

export function parseCert(derBytes, source) {
  let o;
  try { o = fromDer(derBytes, false); } catch (e) { return null; }
  if (!o || o.type !== T.SEQUENCE || !Array.isArray(o.value) || o.value.length !== 3) return null;
  const tbsNode = o.value[0];
  if (!Array.isArray(tbsNode.value)) return null;
  const tbs = tbsNode.value;
  let i = tbs[0].tagClass === CTX ? 1 : 0;
  if (tbs.length < i + 6) return null;
  const sigOid = asn1.derToOid(o.value[1].value[0].value);
  const sigBits = o.value[2].value;
  let exts = null;
  for (let k = i + 6; k < tbs.length; k++) if (tbs[k].tagClass === CTX && tbs[k].type === 3) exts = tbs[k].value[0];

  const subject = readName(tbs[i + 4]), issuer = readName(tbs[i + 2]);
  const subjectDer = toDer(tbs[i + 4]), issuerDer = toDer(tbs[i + 2]);
  const pub = readSpki(tbs[i + 5]);

  const sans = [];
  const san = extValue(exts, OID.subjectAltName);
  if (san) for (const g of san.value) {
    if (g.type === 2) sans.push(g.value);
    else if (g.type === 7) sans.push(g.value.length === 4 ? [...g.value].map((c) => c.charCodeAt(0)).join('.') : hex(g.value));
  }
  const bc = extValue(exts, OID.basicConstraints);
  const isCA = !!(bc && bc.value && bc.value[0] && bc.value[0].type === T.BOOLEAN && bc.value[0].value.charCodeAt(0) !== 0);
  let validation = '';
  const pol = extValue(exts, OID.certPolicies);
  if (pol) for (const p of pol.value) { const v = POLICY[asn1.derToOid(p.value[0].value)]; if (v) validation = v; }
  let caIssuersUrl = '';
  const aia = extValue(exts, OID.aia);
  if (aia) for (const ad of aia.value) if (asn1.derToOid(ad.value[0].value) === '1.3.6.1.5.5.7.48.2' && ad.value[1].type === 6) caIssuersUrl = ad.value[1].value;

  const sig = SIG_ALGS[sigOid] || { name: sigOid };
  return {
    type: 'cert',
    source,
    der: derBytes,
    sha1: colonHex(sha1(derBytes)),
    sha256: colonHex(sha256(derBytes)),
    serial: colonHex(tbs[i].value),
    subject, issuer, subjectDer, issuerDer,
    selfSigned: subjectDer === issuerDer,
    notBefore: readTime(tbs[i + 3].value[0]),
    notAfter: readTime(tbs[i + 3].value[1]),
    pub, pubFp: pubFingerprint(pub),
    sans, isCA, validation, caIssuersUrl,
    sigOid, sigAlg: sig,
    tbsDer: toDer(tbsNode),
    signature: typeof sigBits === 'string' ? sigBits.substring(1) : '',
  };
}

/** Lifetime in days, days left from `now`. */
export function lifetime(c, now = Date.now()) {
  const total = Math.round((c.notAfter - c.notBefore) / 864e5);
  const left = Math.floor((c.notAfter - now) / 864e5);
  return { total, left, pct: Math.min(1, Math.max(0, (now - c.notBefore) / (c.notAfter - c.notBefore))) };
}

export { hex };
