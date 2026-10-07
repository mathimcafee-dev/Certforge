// Readiness checks: plain-English verdicts the UI shows before anything downloads.
import { lifetime } from './cert.js';

const fmt = (d) => d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });

/** @returns {{ checks: {id,status,title,detail}[], blocking: boolean, score: {ok,total} }} */
export function runChecks(m, now = Date.now()) {
  const checks = [];
  const add = (id, status, title, detail = '') => checks.push({ id, status, title, detail });
  if (!m.leaf) return { checks, blocking: true, score: { ok: 0, total: 0 } };
  const leaf = m.leaf;

  // 1. key
  if (!m.key) add('key', 'warn', 'No private key added', 'PFX, JKS and server packs need the key you created with your CSR');
  else if (m.keyMatch) add('key', 'ok', 'Private key matches the certificate');
  else add('key', 'bad', 'Private key doesn’t match the certificate', 'Use the key generated with this certificate’s CSR');

  // 2. chain
  if (m.sigProblems.length) {
    const p = m.sigProblems[0];
    add('chain', 'bad', 'A certificate in the chain doesn’t belong', `${p.child.subject.short} was not signed by ${p.issuer.subject.short}`);
  } else if (m.missing && m.missing.kind === 'root') {
    add('chain', 'warn', 'Root not recognised', `“${m.missing.issuerName}” isn’t a public root — fine for an internal CA; add its root certificate if Java clients must trust it`);
  } else if (m.missing) {
    const n = m.missing.library ? '1 intermediate missing — can be added from the library' : `Missing the certificate for “${m.missing.issuerName}” — ask your CA for its CA bundle`;
    add('chain', 'warn', leaf.selfSigned ? 'Self-signed certificate' : 'Chain incomplete', leaf.selfSigned ? 'Browsers will not trust it' : n);
  } else if (leaf.selfSigned) {
    add('chain', 'warn', 'Self-signed certificate', 'Fine for testing — browsers will show a warning');
  } else if (m.rootKnown === 'untrusted') {
    add('chain', 'warn', 'Chain ends at a private root', `${m.root.subject.short} isn’t a public root — fine for internal use`);
  } else {
    add('chain', 'ok', m.reordered ? 'Chain complete — we put it in order' : 'Chain complete and in order',
      `${m.chain.length === 1 ? 'Leaf' : 'Leaf → ' + (m.intermediates.length === 1 ? 'intermediate' : m.intermediates.length + ' intermediates')}, root trusted`);
  }

  // 3. validity of the leaf
  const lt = lifetime(leaf, now);
  if (leaf.notBefore > now) add('valid', 'warn', `Not valid until ${fmt(leaf.notBefore)}`, 'Check the server clock or wait for the start date');
  else if (lt.left < 0) add('valid', 'bad', `Expired on ${fmt(leaf.notAfter)}`, 'Renew or reissue the certificate before deploying');
  else if (lt.left <= 30) add('valid', 'warn', `Expires ${fmt(leaf.notAfter)}`, `Only ${lt.left} day${lt.left === 1 ? '' : 's'} left — renew soon`);
  else add('valid', 'ok', `Valid until ${fmt(leaf.notAfter)}`, `${lt.left} days left`);

  // 4. intermediates still valid
  const expiredCa = m.intermediates.find((c) => c.notAfter < now);
  if (expiredCa) add('ca-valid', 'bad', 'An intermediate has expired', `${expiredCa.subject.short} expired ${fmt(expiredCa.notAfter)} — get a current CA bundle`);

  // 5. algorithm & key strength
  const weak = m.chain.find((c) => c.sigAlg.weak && !c.selfSigned);
  const small = leaf.pub.kind === 'rsa' && leaf.pub.bits < 2048;
  if (weak) add('algo', 'bad', `${weak.sigAlg.name} signature`, 'Browsers reject SHA-1 and MD5 — reissue the certificate');
  else if (small) add('algo', 'bad', `${leaf.pub.label} key is too small`, 'Use RSA 2048 or larger, or EC P-256');
  else add('algo', 'ok', `${leaf.sigAlg.hash || leaf.sigAlg.name} signature · ${leaf.pub.label}`);

  // 6. names
  if (!leaf.sans.length) add('names', 'warn', 'No Subject Alternative Names', 'Modern browsers ignore the Common Name — reissue with SANs');
  else {
    const shown = leaf.sans.slice(0, 2).join(', ') + (leaf.sans.length > 2 ? ` +${leaf.sans.length - 2} more` : '');
    add('names', 'ok', leaf.sans.length === 1 ? `Covers ${leaf.sans[0]}` : `Covers ${leaf.sans.length} names`, shown);
  }

  // 7. is it a server certificate at all
  if (leaf.isCA) add('leaf', 'warn', 'This is a CA certificate', 'Servers need your own (leaf) certificate, not a CA');
  else if (!leaf.selfSigned) add('leaf', 'ok', 'Not self-signed', m.leaf.validation ? `${m.leaf.validation} certificate` : 'Issued by a certificate authority');

  const ok = checks.filter((c) => c.status === 'ok').length;
  return { checks, blocking: checks.some((c) => c.status === 'bad'), score: { ok, total: checks.length } };
}
