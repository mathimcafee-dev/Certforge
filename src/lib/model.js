// Assemble pieces into one model: the key, the leaf certificate, the ordered chain, and what is missing or extra.
import { util, fromDer } from './util.js';
import { parseCert, readSpki } from './cert.js';
import { verifySignature } from './verify.js';
import LIB from './library-data.js';

let libCache = null;
export function library() {
  if (libCache) return libCache;
  const inter = LIB.intermediates.map((b) => parseCert(util.decode64(b), 'CertForge library')).filter(Boolean);
  const roots = LIB.roots.map((r) => ({ name: r.name, subjectDer: util.decode64(r.subject), pub: readSpki(fromDer(util.decode64(r.spki), false)) }));
  libCache = { date: LIB.date, intermediates: inter, roots };
  return libCache;
}

/**
 * @param {object[]} pieces  output of ingest/unlock (certs, keys, notes, ...)
 * @param {object} opts { added: Set<sha256> of library certs the user added }
 */
export async function buildModel(pieces, opts = {}) {
  const lib = library();
  const added = opts.added || new Set();
  const certs = [], seenC = new Set();
  for (const p of pieces) if (p.type === 'cert' && !seenC.has(p.sha256)) { seenC.add(p.sha256); certs.push(p); }
  for (const c of lib.intermediates) if (added.has(c.sha256) && !seenC.has(c.sha256)) { seenC.add(c.sha256); certs.push({ ...c, fromLibrary: true }); }
  const keys = [], seenK = new Set();
  for (const p of pieces) if (p.type === 'key' && !seenK.has(p.pub.id)) { seenK.add(p.pub.id); keys.push(p); }

  const issuesSomething = (c) => certs.some((o) => o !== c && o.issuerDer === c.subjectDer && !o.selfSigned);
  const leafCandidates = () => {
    let cands = certs.filter((c) => !c.isCA && !c.fromLibrary);
    if (!cands.length) cands = certs.filter((c) => !issuesSomething(c) && !c.fromLibrary);
    return cands.sort((a, b) => b.notAfter - a.notAfter);
  };

  let key = null, leaf = null, keyMatch = null;
  for (const k of keys) {
    const m = certs.filter((c) => c.pub.id === k.pub.id).sort((a, b) => (a.isCA - b.isCA) || (b.notAfter - a.notAfter));
    if (m.length) { key = k; leaf = m[0]; keyMatch = true; break; }
  }
  if (!leaf) {
    leaf = leafCandidates()[0] || null;
    if (keys.length) { key = keys[0]; keyMatch = leaf ? false : null; }
  }

  // chain
  const chain = [];
  let missing = null, rootKnown = null, sigProblems = [];
  if (leaf) {
    chain.push(leaf);
    let cur = leaf;
    while (!cur.selfSigned && chain.length < 12) {
      const cands = certs.filter((c) => c.subjectDer === cur.issuerDer && !chain.includes(c));
      let next = null;
      for (const c of cands) {
        const ok = await verifySignature(cur, c.pub);
        if (ok === true) { next = c; cur.sigOk = true; break; }
        if (ok === null && !next) next = c;
      }
      if (!next && cands.length) { sigProblems.push({ child: cur, issuer: cands[0] }); cur.sigOk = false; }
      if (!next) break;
      chain.push(next); cur = next;
    }
    const last = chain[chain.length - 1];
    if (last.selfSigned) {
      const ok = await verifySignature(last, last.pub);
      last.sigOk = ok;
      rootKnown = lib.roots.find((r) => r.subjectDer === last.subjectDer && r.pub.id === last.pub.id) ? 'trusted' : 'untrusted';
    } else {
      for (const r of lib.roots.filter((x) => x.subjectDer === last.issuerDer)) {
        const ok = await verifySignature(last, r.pub);
        if (ok !== false) { rootKnown = 'trusted'; last.sigOk = ok; break; }
      }
      if (rootKnown !== 'trusted') {
        const fromLib = [];
        for (const c of lib.intermediates) if (c.subjectDer === last.issuerDer && !seenC.has(c.sha256)) {
          if (await verifySignature(last, c.pub) !== false) fromLib.push(c);
        }
        fromLib.sort((a, b) => b.notAfter - a.notAfter);
        missing = { issuerName: last.issuer.short, issuer: last.issuer, after: last, library: fromLib[0] || null, kind: last === leaf || fromLib.length ? 'intermediate' : 'root' };
      }
    }
  }
  // the root goes last and is a "ghost" (not included by default)
  const root = chain.length > 1 && chain[chain.length - 1].selfSigned ? chain[chain.length - 1] : null;
  const intermediates = chain.slice(1).filter((c) => c !== root);

  // order the user supplied vs the correct order
  const supplied = pieces.filter((p) => p.type === 'cert' && chain.some((c) => c.sha256 === p.sha256) && p !== leaf);
  const reordered = supplied.length > 1 && supplied.map((c) => c.sha256).join() !== chain.slice(1).filter((c) => !c.fromLibrary).map((c) => c.sha256).join();

  const inChain = new Set(chain.map((c) => c.sha256));
  const extraCerts = certs.filter((c) => !inChain.has(c.sha256) && !c.fromLibrary);
  const extraKeys = keys.filter((k) => k !== key);

  return {
    key, leaf, keyMatch, chain, intermediates, root, rootKnown, missing, sigProblems, reordered,
    extraCerts, extraKeys, certs, keys,
    rootName: root ? root.subject.short : (rootKnown === 'trusted' && chain.length ? chain[chain.length - 1].issuer.short : null),
    libraryDate: lib.date,
  };
}
