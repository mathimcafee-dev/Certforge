// Private keys: everything is normalized to an unencrypted PKCS#8 PrivateKeyInfo (DER).
import { forge, asn1, pki, util, OID, CURVES, A, der as toDer, fromDer, CfError, utf8, pem } from './util.js';
import { readSpki, pubFingerprint } from './cert.js';

const T = asn1.Type;

/** RSAPrivateKey (PKCS#1) → PKCS#8 */
export function wrapRsa(pkcs1Der) {
  return toDer(A.seq([A.int(0), A.seq([A.oid(OID.rsa), A.nul()]), A.octet(pkcs1Der)]));
}

/** ECPrivateKey (SEC1) → PKCS#8, curve taken from the key's own parameters */
export function wrapSec1(sec1Der, curveHint) {
  const o = fromDer(sec1Der, false);
  let curve = curveHint, rest = [];
  for (const el of o.value) {
    if (el.tagClass === asn1.Class.CONTEXT_SPECIFIC && el.type === 0) curve = asn1.derToOid(el.value[0].value);
    else rest.push(el);
  }
  if (!curve) throw new CfError('This EC key does not say which curve it uses.', 'EC_NO_CURVE');
  // keep version, privateKey, and [1] publicKey; curve moves to the AlgorithmIdentifier
  const inner = toDer(A.seq(rest));
  return toDer(A.seq([A.int(0), A.seq([A.oid(OID.ec), A.oid(curve)]), A.octet(inner)]));
}

/** Describe a PKCS#8 key and work out its public key (async: EC keys without an embedded public key use WebCrypto). */
export async function describeKey(pkcs8, source, extra = {}) {
  let o;
  try { o = fromDer(pkcs8, false); } catch { throw new CfError('This private key is damaged or not a key.', 'BAD_KEY'); }
  const algOid = asn1.derToOid(o.value[1].value[0].value);
  const param = o.value[1].value[1];
  const inner = o.value[2].value;
  let pub;
  if (algOid === OID.rsa) {
    const rsa = fromDer(inner, false);
    const n = rsa.value[1].value, e = rsa.value[2].value;
    pub = readSpki(spkiFor(OID.rsa, null, toDer(A.seq([A.intBytes(n), A.intBytes(e)]))));
  } else if (algOid === OID.ec) {
    const curve = param && param.type === T.OID ? asn1.derToOid(param.value) : '';
    const ecpk = fromDer(inner, false);
    let point = null;
    for (const el of ecpk.value) if (el.tagClass === asn1.Class.CONTEXT_SPECIFIC && el.type === 1) point = el.value[0].value.substring(1);
    if (!point) point = await ecPointFromWebCrypto(pkcs8, curve);
    pub = readSpki(spkiFor(OID.ec, curve, point));
  } else if (algOid === OID.ed25519) {
    const seed = fromDer(inner, false).value;
    const kp = forge.pki.ed25519.generateKeyPair({ seed: util.createBuffer(seed).getBytes() });
    const pt = typeof kp.publicKey === 'string' ? kp.publicKey : util.binary.raw.encode(kp.publicKey);
    pub = readSpki(spkiFor(OID.ed25519, null, pt));
  } else {
    pub = { kind: 'other', label: algOid === OID.dsa ? 'DSA' : algOid, id: 'unknown:' + util.bytesToHex(pkcs8).slice(0, 40) };
  }
  return { type: 'key', source, pkcs8, pub, pubFp: pubFingerprint(pub), label: pub.label, ...extra };
}

function spkiFor(algOid, curve, keyBytes) {
  const alg = algOid === OID.rsa ? A.seq([A.oid(OID.rsa), A.nul()]) : curve ? A.seq([A.oid(algOid), A.oid(curve)]) : A.seq([A.oid(algOid)]);
  return fromDer(toDer(A.seq([alg, A.bits(keyBytes)])), false);
}

async function ecPointFromWebCrypto(pkcs8, curve) {
  const named = CURVES[curve];
  if (!named || !globalThis.crypto?.subtle) throw new CfError('This EC key has no public part and this browser cannot derive it.', 'EC_NO_PUB');
  const u8 = new Uint8Array([...pkcs8].map((c) => c.charCodeAt(0)));
  const k = await crypto.subtle.importKey('pkcs8', u8, { name: 'ECDSA', namedCurve: named }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', k);
  const d = (s) => util.decode64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return '\x04' + d(jwk.x) + d(jwk.y);
}

/** Decrypt an EncryptedPrivateKeyInfo. PBES2 uses the UTF-8 password bytes; PKCS#12 PBE uses BMP (forge handles that). */
export function decryptPkcs8(encDer, password) {
  const obj = fromDer(encDer, false);
  const orig = pki.pbe.getCipherForPBES2;
  pki.pbe.getCipherForPBES2 = function (oid, params, pw) { return orig.call(this, oid, params, utf8(pw)); };
  let info;
  try { info = pki.decryptPrivateKeyInfo(obj, password); }
  catch (e) {
    if (/Unsupported|unknown/i.test(e.message)) throw new CfError('This key uses an encryption scheme CertForge can’t read.', 'UNSUPPORTED', { detail: e.message });
    info = null;
  } finally { pki.pbe.getCipherForPBES2 = orig; }
  if (!info) throw new CfError('Wrong password for this private key.', 'BAD_PASSWORD');
  return toDer(info);
}

/** Traditional OpenSSL encrypted PEM (Proc-Type: 4,ENCRYPTED + DEK-Info). */
export function decryptLegacyPem(body, dekInfo, password) {
  const [algName, ivHex] = dekInfo.split(',').map((s) => s.trim());
  const iv = util.hexToBytes(ivHex);
  const specs = {
    'DES-EDE3-CBC': [24, (k) => forge.des.createDecryptionCipher(k)],
    'DES-CBC': [8, (k) => forge.des.createDecryptionCipher(k)],
    'AES-128-CBC': [16, (k) => forge.aes.createDecryptionCipher(k)],
    'AES-192-CBC': [24, (k) => forge.aes.createDecryptionCipher(k)],
    'AES-256-CBC': [32, (k) => forge.aes.createDecryptionCipher(k)],
  };
  const spec = specs[algName.toUpperCase()];
  if (!spec) throw new CfError(`This key is encrypted with ${algName}, which CertForge can’t read.`, 'UNSUPPORTED');
  // EVP_BytesToKey(MD5, 1 iteration, salt = first 8 bytes of IV)
  const salt = iv.substring(0, 8), pw = utf8(password);
  let key = '', prev = '';
  while (key.length < spec[0]) { const md = forge.md.md5.create(); md.update(prev + pw + salt); prev = md.digest().getBytes(); key += prev; }
  const c = spec[1](key.substring(0, spec[0]));
  c.start(iv); c.update(util.createBuffer(body));
  if (!c.finish()) throw new CfError('Wrong password for this private key.', 'BAD_PASSWORD');
  const out = c.output.getBytes();
  try { fromDer(out, false); } catch { throw new CfError('Wrong password for this private key.', 'BAD_PASSWORD'); }
  return out;
}

/* ---------- key outputs ---------- */

export function keyPemPkcs8(pkcs8) { return pem('PRIVATE KEY', pkcs8); }

export function keyPemEncrypted(pkcs8, password) {
  const obj = fromDer(pkcs8, false);
  const enc = pki.encryptPrivateKeyInfo(obj, utf8(password), { algorithm: 'aes256', prfAlgorithm: 'sha256', count: 2048, saltSize: 16 });
  return pem('ENCRYPTED PRIVATE KEY', toDer(enc));
}

/** Traditional ("BEGIN RSA PRIVATE KEY" / "BEGIN EC PRIVATE KEY"). Returns null for other key types. */
export function keyPemTraditional(pkcs8) {
  const o = fromDer(pkcs8, false);
  const algOid = asn1.derToOid(o.value[1].value[0].value);
  const inner = o.value[2].value;
  if (algOid === OID.rsa) return pem('RSA PRIVATE KEY', inner);
  if (algOid === OID.ec) {
    const curve = asn1.derToOid(o.value[1].value[1].value);
    const ec = fromDer(inner, false);
    const parts = ec.value.filter((el) => !(el.tagClass === asn1.Class.CONTEXT_SPECIFIC && el.type === 0));
    // SEC1 order: version, privateKey, [0] parameters, [1] publicKey
    const params = A.ctx(0, [A.oid(curve)]);
    const out = [parts[0], parts[1], params, ...parts.slice(2)];
    return pem('EC PRIVATE KEY', toDer(A.seq(out)));
  }
  return null;
}
