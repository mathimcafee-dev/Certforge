// Signature verification with the browser's own WebCrypto. Returns true / false, or null when it can't tell.
import { asn1, fromDer, toU8 } from './util.js';
import { spkiDer } from './cert.js';

const CURVE = { '1.2.840.10045.3.1.7': ['P-256', 32], '1.3.132.0.34': ['P-384', 48], '1.3.132.0.35': ['P-521', 66] };

export async function verifySignature(child, issuerPub) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle || !child.sigAlg || !child.sigAlg.kind) return null;
  const spki = toU8(spkiDer(issuerPub));
  if (!spki.length) return null;
  const data = toU8(child.tbsDer);
  let sig = child.signature;
  try {
    const kind = child.sigAlg.kind;
    if (kind === 'rsa' && issuerPub.kind === 'rsa') {
      const k = await subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: child.sigAlg.hash }, false, ['verify']);
      return await subtle.verify('RSASSA-PKCS1-v1_5', k, toU8(sig), data);
    }
    if (kind === 'ecdsa' && issuerPub.kind === 'ec') {
      const c = CURVE[issuerPub.curve]; if (!c) return null;
      const k = await subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: c[0] }, false, ['verify']);
      return await subtle.verify({ name: 'ECDSA', hash: child.sigAlg.hash }, k, toU8(derSigToRaw(sig, c[1])), data);
    }
    if (kind === 'ed25519' && issuerPub.kind === 'ed25519') {
      const k = await subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify('Ed25519', k, toU8(sig), data);
    }
  } catch { return null; }
  return null;
}

function derSigToRaw(sig, size) {
  const o = fromDer(sig, false);
  const fix = (b) => { while (b.length > size && b.charCodeAt(0) === 0) b = b.substring(1); while (b.length < size) b = '\x00' + b; return b; };
  return fix(o.value[0].value) + fix(o.value[1].value);
}
