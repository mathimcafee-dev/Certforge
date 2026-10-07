// Java KeyStore (JKS) reader and writer. Format and the Sun KeyProtector scheme are implemented directly.
import { asn1, A, der as toDer, fromDer, CfError, sha1, utf16be, randomBytes } from './util.js';

const MAGIC = 0xfeedfeed, JCEKS = 0xcececece;
const KEY_OID = '1.3.6.1.4.1.42.2.17.1.1';

const u2 = (n) => String.fromCharCode((n >>> 8) & 255, n & 255);
const u4 = (n) => String.fromCharCode((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const u8 = (n) => u4(Math.floor(n / 4294967296)) + u4(n >>> 0);
const xor = (a, b) => { let o = ''; for (let i = 0; i < a.length; i++) o += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i)); return o; };

function javaUTF(s) {
  let b = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 1 && c <= 0x7f) b += String.fromCharCode(c);
    else if (c <= 0x7ff) b += String.fromCharCode(0xc0 | (c >> 6), 0x80 | (c & 63));
    else b += String.fromCharCode(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  if (b.length > 65535) throw new CfError('Alias is too long.', 'BAD_ALIAS');
  return u2(b.length) + b;
}
function readJavaUTF(r) {
  const len = r.u2(), b = r.bytes(len);
  let s = '';
  for (let i = 0; i < b.length;) {
    const c = b.charCodeAt(i);
    if (c < 0x80) { s += String.fromCharCode(c); i++; }
    else if ((c & 0xe0) === 0xc0) { s += String.fromCharCode(((c & 31) << 6) | (b.charCodeAt(i + 1) & 63)); i += 2; }
    else { s += String.fromCharCode(((c & 15) << 12) | ((b.charCodeAt(i + 1) & 63) << 6) | (b.charCodeAt(i + 2) & 63)); i += 3; }
  }
  return s;
}

function keystream(pw, salt, len) { let d = salt, s = ''; while (s.length < len) { d = sha1(pw + d); s += d; } return s.substring(0, len); }

export function protectKey(plain, password) {
  const pw = utf16be(password), salt = randomBytes(20);
  const enc = salt + xor(plain, keystream(pw, salt, plain.length)) + sha1(pw + plain);
  return toDer(A.seq([A.seq([A.oid(KEY_OID), A.nul()]), A.octet(enc)]));
}

export function recoverKey(encInfoDer, password) {
  const o = fromDer(encInfoDer, false);
  if (asn1.derToOid(o.value[0].value[0].value) !== KEY_OID) throw new CfError('This keystore protects its key with a scheme CertForge can’t read.', 'UNSUPPORTED');
  const enc = o.value[1].value, pw = utf16be(password);
  const salt = enc.substring(0, 20), body = enc.substring(20, enc.length - 20), check = enc.substring(enc.length - 20);
  const plain = xor(body, keystream(pw, salt, body.length));
  if (sha1(pw + plain) !== check) return null;
  return plain;
}

export function isJks(bytes) { return bytes.length > 4 && bytes.charCodeAt(0) === 0xfe && bytes.charCodeAt(1) === 0xed && bytes.charCodeAt(2) === 0xfe && bytes.charCodeAt(3) === 0xed; }
export function isJceks(bytes) { return bytes.length > 4 && bytes.charCodeAt(0) === 0xce && bytes.charCodeAt(1) === 0xce && bytes.charCodeAt(2) === 0xce && bytes.charCodeAt(3) === 0xce; }

/** Read a JKS. keyPassword defaults to the store password. Returns {keys:[{alias,pkcs8}], certs:[{alias,der,trusted}]} */
export function readJks(bytes, password, keyPassword) {
  const r = reader(bytes);
  if (r.u4() !== MAGIC) throw new CfError('This is not a JKS keystore.', 'BAD_FILE');
  const version = r.u4(), count = r.u4();
  const keys = [], certs = [];
  const readCert = () => { if (version === 2) readJavaUTF(r); const len = r.u4(); return r.bytes(len); };
  for (let i = 0; i < count; i++) {
    const tag = r.u4(), alias = readJavaUTF(r); r.bytes(8);
    if (tag === 1) {
      const enc = r.bytes(r.u4()); const n = r.u4();
      const chain = []; for (let k = 0; k < n; k++) chain.push(readCert());
      keys.push({ alias, enc, chain });
    } else if (tag === 2) {
      certs.push({ alias, der: readCert(), trusted: true });
    } else throw new CfError('This keystore holds an entry type CertForge can’t read (secret keys are JCEKS-only).', 'UNSUPPORTED');
  }
  const dataEnd = r.pos;
  const digest = r.bytes(20);
  if (password !== null && password !== undefined && sha1(utf16be(password) + 'Mighty Aphrodite' + bytes.substring(0, dataEnd)) !== digest)
    throw new CfError('Wrong keystore password.', 'BAD_PASSWORD');
  const outKeys = [];
  for (const k of keys) {
    let plain = recoverKey(k.enc, keyPassword ?? password);
    if (plain === null && keyPassword != null && keyPassword !== password) plain = recoverKey(k.enc, password);
    if (plain === null) throw new CfError(`The key “${k.alias}” has its own password, different from the keystore password.`, 'KEY_PASSWORD');
    outKeys.push({ alias: k.alias, pkcs8: plain });
    k.chain.forEach((d, i) => certs.push({ alias: k.alias, der: d, trusted: false, leafOf: i === 0 ? k.alias : null }));
  }
  return { keys: outKeys, certs };
}

function reader(b) {
  let pos = 0;
  const need = (n) => { if (pos + n > b.length) throw new CfError('This keystore file is cut short or damaged.', 'BAD_FILE'); };
  return {
    get pos() { return pos; },
    u2() { need(2); const v = (b.charCodeAt(pos) << 8) | b.charCodeAt(pos + 1); pos += 2; return v; },
    u4() { need(4); const v = ((b.charCodeAt(pos) << 24) | (b.charCodeAt(pos + 1) << 16) | (b.charCodeAt(pos + 2) << 8) | b.charCodeAt(pos + 3)) >>> 0; pos += 4; return v; },
    bytes(n) { need(n); const v = b.substring(pos, pos + n); pos += n; return v; },
  };
}

/**
 * Write a JKS.
 * @param {object} o { storePassword, keyPassword, entries:[{alias, pkcs8, chain:[der]}], trusted:[{alias, der}] }
 */
export function writeJks({ storePassword, keyPassword, entries = [], trusted = [] }) {
  const now = Date.now(), seen = new Set();
  const alias = (a) => {
    a = String(a || '').trim().toLowerCase();
    if (!a) throw new CfError('Alias cannot be empty.', 'BAD_ALIAS');
    if (seen.has(a)) throw new CfError(`Duplicate alias “${a}”.`, 'BAD_ALIAS');
    seen.add(a); return a;
  };
  let body = u4(MAGIC) + u4(2) + u4(entries.length + trusted.length);
  for (const e of entries) {
    const prot = protectKey(e.pkcs8, keyPassword ?? storePassword);
    body += u4(1) + javaUTF(alias(e.alias)) + u8(now) + u4(prot.length) + prot + u4(e.chain.length);
    for (const d of e.chain) body += javaUTF('X.509') + u4(d.length) + d;
  }
  for (const t of trusted) body += u4(2) + javaUTF(alias(t.alias)) + u8(now) + javaUTF('X.509') + u4(t.der.length) + t.der;
  return body + sha1(utf16be(storePassword) + 'Mighty Aphrodite' + body);
}
