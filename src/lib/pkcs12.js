// PKCS#12 / PFX reading (via node-forge, keeping original bytes) and writing (our own, any key type).
import { forge, asn1, pki, util, OID, A, der as toDer, fromDer, CfError, utf8, sha1, randomBytes } from './util.js';

/* ---------------- reading ---------------- */

export function isPkcs12(o) {
  try {
    return o.type === asn1.Type.SEQUENCE && o.value.length >= 2 && o.value[0].type === asn1.Type.INTEGER &&
      o.value[0].value === '\x03' && asn1.derToOid(o.value[1].value[0].value) === OID.data;
  } catch { return false; }
}

/** Returns { keys:[{pkcs8, friendlyName, localKeyId}], certs:[{der, friendlyName, localKeyId}] } */
export function readPkcs12(bytes, password) {
  let obj;
  try { obj = asn1.fromDer(bytes, { strict: false }); } catch { throw new CfError('This file is not a valid PFX / P12.', 'BAD_FILE'); }
  const origKey = pki.privateKeyFromAsn1, origCert = pki.certificateFromAsn1, origPbes2 = pki.pbe.getCipherForPBES2;
  const keyDers = [], certDers = [];
  pki.privateKeyFromAsn1 = function (o) { keyDers.push(asn1.toDer(o).getBytes()); throw new Error('captured'); };
  pki.certificateFromAsn1 = function (o) { certDers.push(asn1.toDer(o).getBytes()); throw new Error('captured'); };
  pki.pbe.getCipherForPBES2 = function (oid, params, pw) { return origPbes2.call(this, oid, params, utf8(pw)); };
  let p12;
  const attempt = (pw) => forge.pkcs12.pkcs12FromAsn1(obj, false, pw);
  try {
    try { p12 = attempt(password); }
    catch (e) {
      // Some tools write a password-less PFX with a MAC over a NULL password
      if (password === '' && /mac/i.test(e.message)) { keyDers.length = 0; certDers.length = 0; p12 = attempt(null); } else throw e;
    }
  } catch (e) {
    const m = String(e && e.message || e);
    if (/mac could not be verified|Invalid password|wrong password|decrypt/i.test(m)) throw new CfError('Wrong PFX password.', 'BAD_PASSWORD');
    if (/Unsupported|unknown|OID/i.test(m)) throw new CfError('This PFX uses an encryption scheme CertForge can’t read. Re-save it with: openssl pkcs12 -in old.pfx -nodes | openssl pkcs12 -export -out new.pfx', 'UNSUPPORTED', { detail: m });
    throw new CfError('Could not open this PFX: ' + m, 'BAD_FILE');
  } finally {
    pki.privateKeyFromAsn1 = origKey; pki.certificateFromAsn1 = origCert; pki.pbe.getCipherForPBES2 = origPbes2;
  }
  const attr = (bag, n) => { const a = bag.attributes && bag.attributes[n]; return a && a.length ? a[0] : null; };
  const keys = [], certs = [];
  let ki = 0, ci = 0;
  for (const sc of p12.safeContents) for (const bag of sc.safeBags) {
    const meta = { friendlyName: attr(bag, 'friendlyName'), localKeyId: attr(bag, 'localKeyId') ? util.bytesToHex(attr(bag, 'localKeyId')) : null };
    if (bag.type === pki.oids.keyBag || bag.type === pki.oids.pkcs8ShroudedKeyBag) keys.push({ pkcs8: keyDers[ki++], ...meta });
    else if (bag.type === pki.oids.certBag) certs.push({ der: certDers[ci++], ...meta });
  }
  return { keys, certs };
}

/* ---------------- writing ---------------- */

const ITER = 2048;

function bagAttrs(friendlyName, localKeyId) {
  const attrs = [];
  if (friendlyName) attrs.push(A.seq([A.oid(OID.friendlyName), A.set([A.bmp(friendlyName)])]));
  if (localKeyId) attrs.push(A.seq([A.oid(OID.localKeyId), A.set([A.octet(localKeyId)])]));
  return attrs.length ? [A.set(attrs)] : [];
}

/** Encrypt arbitrary DER content with PBES2-AES-256 (modern) or PKCS#12 3DES (legacy); returns [algId, ciphertext]. */
function pbeEncrypt(contentObj, password, legacy) {
  const enc = legacy
    ? pki.encryptPrivateKeyInfo(contentObj, password, { algorithm: '3des', count: ITER, saltSize: 8 })
    : pki.encryptPrivateKeyInfo(contentObj, utf8(password), { algorithm: 'aes256', prfAlgorithm: 'sha256', count: ITER, saltSize: 16 });
  return [enc.value[0], enc.value[1].value];
}

/**
 * Build a PFX.
 * @param {object} o { pkcs8 (optional), chain: [der...] leaf first, password, legacy, friendlyName }
 */
export function writePkcs12({ pkcs8, chain, password, legacy = false, friendlyName }) {
  const localKeyId = pkcs8 && chain.length ? sha1(chain[0]) : null;
  // certificates, encrypted
  const certBags = chain.map((d, i) => A.seq([
    A.oid(OID.certBag),
    A.ctx(0, [A.seq([A.oid(OID.x509Certificate), A.ctx(0, [A.octet(d)])])]),
    ...(i === 0 ? bagAttrs(friendlyName, localKeyId) : []),
  ]));
  const [certAlg, certCipher] = pbeEncrypt(A.seq(certBags), password, legacy);
  const certInfo = A.seq([A.oid(OID.encryptedData), A.ctx(0, [A.seq([
    A.int(0),
    A.seq([A.oid(OID.data), certAlg, asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, false, certCipher)]),
  ])])]);
  const contents = [certInfo];
  if (pkcs8) {
    const keyObj = fromDer(pkcs8, false);
    const encKey = legacy
      ? pki.encryptPrivateKeyInfo(keyObj, password, { algorithm: '3des', count: ITER, saltSize: 8 })
      : pki.encryptPrivateKeyInfo(keyObj, utf8(password), { algorithm: 'aes256', prfAlgorithm: 'sha256', count: ITER, saltSize: 16 });
    const keyBag = A.seq([A.oid(OID.shroudedKeyBag), A.ctx(0, [encKey]), ...bagAttrs(friendlyName, localKeyId)]);
    contents.push(A.seq([A.oid(OID.data), A.ctx(0, [A.octet(toDer(A.seq([keyBag])))])]));
  }
  const authSafe = toDer(A.seq(contents));

  // MAC over the AuthenticatedSafe
  const md = legacy ? forge.md.sha1.create() : forge.md.sha256.create();
  const macSalt = randomBytes(legacy ? 8 : 16);
  const macKey = pki.pbe.generatePkcs12Key(password, util.createBuffer(macSalt), 3, ITER, md.digestLength, md);
  const hmac = forge.hmac.create();
  hmac.start(legacy ? 'sha1' : 'sha256', macKey);
  hmac.update(authSafe);
  const mac = hmac.digest().getBytes();
  const macData = A.seq([
    A.seq([A.seq([A.oid(legacy ? OID.sha1 : OID.sha256), A.nul()]), A.octet(mac)]),
    A.octet(macSalt),
    A.int(ITER),
  ]);
  return toDer(A.seq([A.int(3), A.seq([A.oid(OID.data), A.ctx(0, [A.octet(authSafe)])]), macData]));
}
