// Certificates-only PKCS#7 (degenerate SignedData), as used for .p7b / .p7c files.
import { asn1, OID, A, der as toDer, fromDer, pem } from './util.js';

export function isPkcs7(o) {
  try { return o.type === asn1.Type.SEQUENCE && asn1.derToOid(o.value[0].value) === OID.signedData; } catch { return false; }
}

/** Extract certificate DERs (original bytes, re-emitted from the parsed tree) */
export function readPkcs7(o) {
  const sd = o.value[1].value[0];
  const out = [];
  for (const el of sd.value) {
    if (el.tagClass === asn1.Class.CONTEXT_SPECIFIC && el.type === 0 && el.constructed) {
      for (const c of el.value) out.push(toDer(c));
    }
  }
  return out;
}

export function writePkcs7(certDers) {
  const certs = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, certDers.map((d) => fromDer(d, false)));
  const sd = A.seq([A.int(1), A.set([]), A.seq([A.oid(OID.data)]), certs, A.set([])]);
  return toDer(A.seq([A.oid(OID.signedData), A.ctx(0, [sd])]));
}

export function p7bPem(certDers) { return pem('PKCS7', writePkcs7(certDers)); }
