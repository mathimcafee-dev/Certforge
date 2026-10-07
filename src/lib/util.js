// Shared byte helpers. Internally bytes are forge "binary strings" (one char per byte).
import forge from 'node-forge';

export const { asn1, pki, util } = forge;
export { forge };

export const OID = {
  rsa: '1.2.840.113549.1.1.1',
  ec: '1.2.840.10045.2.1',
  ed25519: '1.3.101.112',
  ed448: '1.3.101.113',
  dsa: '1.2.840.10040.4.1',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.3.132.0.34',
  p521: '1.3.132.0.35',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  encryptedData: '1.2.840.113549.1.7.6',
  x509Certificate: '1.2.840.113549.1.9.22.1',
  certBag: '1.2.840.113549.1.12.10.1.3',
  keyBag: '1.2.840.113549.1.12.10.1.1',
  shroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  friendlyName: '1.2.840.113549.1.9.20',
  localKeyId: '1.2.840.113549.1.9.21',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  certPolicies: '2.5.29.32',
  aia: '1.3.6.1.5.5.7.1.1',
};

export const CURVES = { [OID.p256]: 'P-256', [OID.p384]: 'P-384', [OID.p521]: 'P-521' };

export const SIG_ALGS = {
  '1.2.840.113549.1.1.4': { name: 'MD5 with RSA', weak: 'bad' },
  '1.2.840.113549.1.1.5': { name: 'SHA-1 with RSA', weak: 'bad' },
  '1.2.840.113549.1.1.11': { name: 'SHA-256 with RSA', hash: 'SHA-256', kind: 'rsa' },
  '1.2.840.113549.1.1.12': { name: 'SHA-384 with RSA', hash: 'SHA-384', kind: 'rsa' },
  '1.2.840.113549.1.1.13': { name: 'SHA-512 with RSA', hash: 'SHA-512', kind: 'rsa' },
  '1.2.840.113549.1.1.10': { name: 'RSA-PSS', kind: 'pss' },
  '1.2.840.10045.4.1': { name: 'SHA-1 with ECDSA', weak: 'bad' },
  '1.2.840.10045.4.3.2': { name: 'SHA-256 with ECDSA', hash: 'SHA-256', kind: 'ecdsa' },
  '1.2.840.10045.4.3.3': { name: 'SHA-384 with ECDSA', hash: 'SHA-384', kind: 'ecdsa' },
  '1.2.840.10045.4.3.4': { name: 'SHA-512 with ECDSA', hash: 'SHA-512', kind: 'ecdsa' },
  '1.3.101.112': { name: 'Ed25519', kind: 'ed25519' },
};

export class CfError extends Error {
  constructor(message, code, extra) { super(message); this.code = code || 'ERROR'; Object.assign(this, extra || {}); }
}

export function toBin(u8) {
  if (typeof u8 === 'string') return u8;
  let s = '';
  const CH = 0x8000;
  for (let i = 0; i < u8.length; i += CH) s += String.fromCharCode.apply(null, u8.subarray(i, i + CH));
  return s;
}
export function toU8(bin) {
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i) & 255;
  return a;
}
export function sha1(bin) { const md = forge.md.sha1.create(); md.update(bin); return md.digest().getBytes(); }
export function sha256(bin) { const md = forge.md.sha256.create(); md.update(bin); return md.digest().getBytes(); }
export function hex(bin) { return util.bytesToHex(bin); }
export function colonHex(bin) { return hex(bin).toUpperCase().match(/../g).join(':'); }
export function b64(bin) { return util.encode64(bin); }
export function randomBytes(n) {
  const a = new Uint8Array(n);
  globalThis.crypto.getRandomValues(a);
  return toBin(a);
}
export function utf16be(s) { let o = ''; for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); o += String.fromCharCode(c >> 8, c & 255); } return o; }
export function utf8(s) { return util.encodeUtf8(s); }

export function pem(label, der) {
  const body = b64(der).match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

// ASN.1 construction shorthands
const U = asn1.Class.UNIVERSAL, C = asn1.Class.CONTEXT_SPECIFIC, T = asn1.Type;
export const A = {
  seq: (v) => asn1.create(U, T.SEQUENCE, true, v),
  set: (v) => asn1.create(U, T.SET, true, v),
  oid: (o) => asn1.create(U, T.OID, false, asn1.oidToDer(o).getBytes()),
  int: (n) => asn1.create(U, T.INTEGER, false, asn1.integerToDer(n).getBytes()),
  intBytes: (b) => asn1.create(U, T.INTEGER, false, b),
  octet: (b) => asn1.create(U, T.OCTETSTRING, false, b),
  bits: (b) => asn1.create(U, T.BITSTRING, false, '\x00' + b),
  nul: () => asn1.create(U, T.NULL, false, ''),
  bmp: (s) => asn1.create(U, T.BMPSTRING, false, s), // forge encodes BMPSTRING values as UTF-16BE itself
  ctx: (n, v, constructed = true) => asn1.create(C, n, constructed, v),
  raw: (der) => asn1.fromDer(der, { strict: false }),
};
export const der = (o) => asn1.toDer(o).getBytes();
export const fromDer = (b, strict = true) => asn1.fromDer(b, { strict, parseAllBytes: strict, decodeBitStrings: false });

export function safeName(s) {
  return (s || 'certificate').toLowerCase().replace(/^\*\./, 'wildcard.').replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60) || 'certificate';
}
