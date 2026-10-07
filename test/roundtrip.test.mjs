// End-to-end round trip: OpenSSL/keytool make inputs → CertForge converts → OpenSSL/keytool must accept every output.
// Run: node --test test/   (needs openssl and a JDK on PATH)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { ingestFile, ingestText, unlock } from '../src/lib/ingest.js';
import { buildModel } from '../src/lib/model.js';
import { runChecks } from '../src/lib/checks.js';
import { makeContext, FORMATS, PACKS, buildPack } from '../src/lib/outputs.js';
import { writeZip } from '../src/lib/zip.js';
import { toU8 } from '../src/lib/util.js';

const D = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-'));
const env = { ...process.env, JAVA_TOOL_OPTIONS: '', LC_ALL: 'C.UTF-8' };
const sh = (cmd) => execSync(cmd, { cwd: D, env, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
const file = (n) => new Uint8Array(fs.readFileSync(path.join(D, n)));
const write = (n, data, binary) => fs.writeFileSync(path.join(D, n), binary ? Buffer.from(data, 'binary') : data);
const pubOfCert = (f) => sh(`openssl x509 -in ${f} -noout -pubkey`).trim();

/* ---------- corpus ---------- */
sh(`openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 3650 -subj "/C=IN/O=CF Test Root/CN=CF Test Root" 2>/dev/null`);
sh(`openssl req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/C=IN/O=CF Test/CN=CF Test Intermediate" 2>/dev/null`);
fs.writeFileSync(path.join(D, 'ca.ext'), 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
sh(`openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 1800 -extfile ca.ext 2>/dev/null`);
fs.writeFileSync(path.join(D, 'leaf.ext'), 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:acme.test,DNS:www.acme.test\n');
const mkLeaf = (name, keyArgs) => {
  sh(`openssl req -new ${keyArgs} -nodes -keyout ${name}.key -out ${name}.csr -subj "/CN=www.acme.test/O=Acme" 2>/dev/null`);
  sh(`openssl x509 -req -in ${name}.csr -CA int.crt -CAkey int.key -CAcreateserial -out ${name}.crt -days 200 -extfile leaf.ext 2>/dev/null`);
};
mkLeaf('rsa', '-newkey rsa:2048');
mkLeaf('ec', '-newkey ec -pkeyopt ec_paramgen_curve:P-256');
mkLeaf('ed', '-newkey ed25519');
sh('cat int.crt root.crt > chain.pem; cat root.crt int.crt > chain-reversed.pem');
sh('openssl pkey -in ec.key -traditional -out ec-sec1.key 2>/dev/null || openssl ec -in ec.key -out ec-sec1.key 2>/dev/null');
sh('openssl rsa -in rsa.key -traditional -out rsa-pkcs1.key 2>/dev/null');
sh('openssl pkcs8 -topk8 -in rsa.key -v2 aes256 -passout pass:keypass1 -out rsa-enc.key');
sh('openssl rsa -in rsa.key -traditional -aes256 -passout pass:keypass1 -out rsa-legacy-enc.key 2>/dev/null');
sh('openssl pkcs12 -export -in rsa.crt -inkey rsa.key -certfile chain.pem -name "Acme Web" -passout pass:pfxpass -out rsa.pfx');
sh('openssl pkcs12 -export -legacy -in ec.crt -inkey ec.key -certfile chain.pem -passout pass:pfxpass -out ec-legacy.pfx 2>/dev/null || openssl pkcs12 -export -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -in ec.crt -inkey ec.key -certfile chain.pem -passout pass:pfxpass -out ec-legacy.pfx');
sh('keytool -importkeystore -srckeystore rsa.pfx -srcstoretype PKCS12 -srcstorepass pfxpass -destkeystore in.jks -deststoretype JKS -deststorepass storepass -noprompt 2>/dev/null');
sh('openssl crl2pkcs7 -nocrl -certfile rsa.crt -certfile int.crt -out chain.p7b');
sh('openssl x509 -in rsa.crt -outform DER -out rsa.der');
sh('openssl req -newkey rsa:2048 -nodes -keyout other.key -out other.csr -subj "/CN=other" 2>/dev/null');

/* ---------- helpers ---------- */
async function ingestAll(names, passwords = {}) {
  let pieces = [];
  for (const n of names) pieces.push(...await ingestFile(n, file(n)));
  const locked = pieces.filter((p) => p.type === 'locked');
  pieces = pieces.filter((p) => p.type !== 'locked');
  for (const l of locked) pieces.push(...await unlock(l, passwords[l.source] ?? passwords['*'], passwords[l.source + ':key']));
  return pieces;
}

function verifyAllOutputs(tag, model) {
  const ctx = makeContext(model, { password: 'Out-pass-1', alias: 'site' });
  const leafPub = pubOfCert(`${tag}.crt`);
  for (const f of FORMATS) {
    if (f.available && !f.available(ctx)) continue;
    const out = f.build(ctx);
    const n = `out-${tag}-${f.id}.${f.ext}`;
    write(n, out.data, out.binary);
    switch (f.id) {
      case 'pfx': case 'pfx-legacy': {
        sh(`openssl pkcs12 -in ${n} -passin pass:Out-pass-1 -nodes ${f.id === 'pfx-legacy' ? '-legacy' : ''} -out ${n}.pem 2>/dev/null || openssl pkcs12 -in ${n} -passin pass:Out-pass-1 -nodes -out ${n}.pem`);
        assert.equal(sh(`openssl pkey -in ${n}.pem -pubout`).trim(), leafPub, `${n}: key matches`);
        assert.equal(sh(`grep -c "BEGIN CERTIFICATE" ${n}.pem`).trim(), '2', `${n}: leaf + intermediate`);
        const jl = sh(`keytool -list -storetype PKCS12 -keystore ${n} -storepass Out-pass-1`);
        assert.match(jl, /PrivateKeyEntry/, `${n}: Java reads it`);
        assert.match(jl, /site/, `${n}: alias`);
        break;
      }
      case 'jks': {
        const l = sh(`keytool -list -v -storetype JKS -keystore ${n} -storepass Out-pass-1`);
        assert.match(l, /Alias name: site/); assert.match(l, /Certificate chain length: 2/);
        sh(`rm -f ${n}.p12; keytool -importkeystore -srckeystore ${n} -srcstoretype JKS -srcstorepass Out-pass-1 -destkeystore ${n}.p12 -deststoretype PKCS12 -deststorepass changeit -noprompt`);
        sh(`openssl pkcs12 -in ${n}.p12 -passin pass:changeit -nodes -out ${n}.pem`);
        assert.equal(sh(`openssl pkey -in ${n}.pem -pubout`).trim(), leafPub, `${n}: key round-trips through Java`);
        break;
      }
      case 'truststore': {
        const l = sh(`keytool -list -storetype JKS -keystore ${n} -storepass Out-pass-1`);
        assert.match(l, /trustedCertEntry/); break;
      }
      case 'fullchain': assert.equal(sh(`openssl x509 -in ${n} -noout -pubkey`).trim(), leafPub); assert.equal(sh(`grep -c BEGIN ${n}`).trim(), '2'); break;
      case 'cert': assert.equal(sh(`openssl x509 -in ${n} -noout -pubkey`).trim(), leafPub); break;
      case 'cabundle': assert.match(sh(`openssl x509 -in ${n} -noout -subject`), /CF Test Intermediate/); break;
      case 'key': case 'key-trad': assert.equal(sh(`openssl pkey -in ${n} -pubout`).trim(), leafPub, `${n}`); break;
      case 'key-enc': assert.equal(sh(`openssl pkey -in ${n} -passin pass:Out-pass-1 -pubout`).trim(), leafPub); break;
      case 'combined': assert.equal(sh(`openssl pkey -in ${n} -pubout`).trim(), leafPub); assert.equal(sh(`openssl x509 -in ${n} -noout -pubkey`).trim(), leafPub); break;
      case 'der': assert.equal(sh(`openssl x509 -inform DER -in ${n} -noout -pubkey`).trim(), leafPub); break;
      case 'p7b': assert.equal(sh(`openssl pkcs7 -in ${n} -print_certs | grep -c "BEGIN CERT"`).trim(), '2'); break;
    }
    // chain verifies against our test root
    if (['fullchain'].includes(f.id)) sh(`openssl verify -CAfile root.crt -untrusted int.crt ${n}`);
  }
  // fingerprints are byte-identical to the originals
  const orig = sh(`openssl x509 -in ${tag}.crt -noout -fingerprint -sha256`).trim();
  assert.equal(sh(`openssl x509 -inform DER -in out-${tag}-der.cer -noout -fingerprint -sha256`).trim(), orig);
  // every pack builds and zips
  for (const p of PACKS) {
    const files = buildPack(p.id, makeContext(model, { password: 'Out-pass-1', alias: p.alias || '' }));
    assert.ok(files.length >= 2, p.id);
    const z = writeZip(files.map((f) => ({ name: f.name, data: f.binary ? toU8(f.data) : f.data })));
    write(`pack-${tag}-${p.id}.zip`, Buffer.from(z), false);
    sh(`unzip -tq pack-${tag}-${p.id}.zip`);
  }
}

/* ---------- tests ---------- */
test('RSA: separate PEM files, chain in the wrong order', async () => {
  const pieces = await ingestAll(['rsa.crt', 'rsa.key', 'chain-reversed.pem']);
  const m = await buildModel(pieces);
  assert.equal(m.keyMatch, true);
  assert.deepEqual(m.chain.map((c) => c.subject.CN), ['www.acme.test', 'CF Test Intermediate', 'CF Test Root']);
  assert.equal(m.reordered, true);
  const { checks } = runChecks(m);
  assert.equal(checks.find((c) => c.id === 'key').status, 'ok');
  verifyAllOutputs('rsa', m);
});

test('EC P-256 with a SEC1 key', async () => {
  const m = await buildModel(await ingestAll(['ec.crt', 'ec-sec1.key', 'chain.pem']));
  assert.equal(m.keyMatch, true); assert.equal(m.leaf.pub.label, 'EC P-256');
  verifyAllOutputs('ec', m);
});

test('Ed25519', async () => {
  const m = await buildModel(await ingestAll(['ed.crt', 'ed.key', 'chain.pem']));
  assert.equal(m.keyMatch, true); assert.equal(m.leaf.pub.label, 'Ed25519');
  const ctx = makeContext(m, { password: 'Out-pass-1', alias: 'ed' });
  const jks = FORMATS.find((f) => f.id === 'jks').build(ctx);
  write('out-ed.jks', jks.data, true);
  assert.match(sh('keytool -list -storetype JKS -keystore out-ed.jks -storepass Out-pass-1'), /PrivateKeyEntry/);
  const pfx = FORMATS.find((f) => f.id === 'pfx').build(ctx);
  write('out-ed.pfx', pfx.data, true);
  sh('openssl pkcs12 -in out-ed.pfx -passin pass:Out-pass-1 -nodes -out out-ed.pem');
  assert.equal(sh('openssl pkey -in out-ed.pem -pubout').trim(), pubOfCert('ed.crt'));
});

test('PKCS#1 key, encrypted PKCS#8 key, and traditional encrypted key', async () => {
  for (const k of ['rsa-pkcs1.key', 'rsa-enc.key', 'rsa-legacy-enc.key']) {
    const m = await buildModel(await ingestAll(['rsa.crt', k, 'chain.pem'], { '*': 'keypass1' }));
    assert.equal(m.keyMatch, true, k);
  }
  await assert.rejects(ingestAll(['rsa-enc.key'], { '*': 'wrong' }), /Wrong password/);
});

test('PFX in (modern and legacy), JKS in, P7B in, DER in', async () => {
  let m = await buildModel(await ingestAll(['rsa.pfx'], { '*': 'pfxpass' }));
  assert.equal(m.keyMatch, true); assert.equal(m.chain.length, 3); assert.equal(m.key.friendlyName, 'Acme Web');
  m = await buildModel(await ingestAll(['ec-legacy.pfx'], { '*': 'pfxpass' }));
  assert.equal(m.keyMatch, true);
  m = await buildModel(await ingestAll(['in.jks'], { '*': 'storepass', 'in.jks:key': 'pfxpass' }));
  assert.equal(m.keyMatch, true); assert.equal(m.chain.length, 3);
  await assert.rejects(ingestAll(['in.jks'], { '*': 'nope' }), /Wrong keystore password/);
  m = await buildModel(await ingestAll(['chain.p7b', 'rsa.key']));
  assert.equal(m.keyMatch, true); assert.equal(m.chain.length, 2);
  m = await buildModel(await ingestAll(['rsa.der']));
  assert.equal(m.leaf.subject.CN, 'www.acme.test'); assert.equal(m.key, null);
});

test('A CA zip with mixed files and a CSR', async () => {
  const z = writeZip(['rsa.crt', 'rsa.key', 'chain.pem', 'rsa.csr'].map((n) => ({ name: n, data: file(n) })));
  const pieces = await ingestFile('acme_ssl.zip', z);
  assert.ok(pieces.some((p) => p.type === 'note' && p.level === 'csr'));
  const m = await buildModel(pieces);
  assert.equal(m.keyMatch, true); assert.equal(m.chain.length, 3);
});

test('Pasted text with everything in one blob', async () => {
  const text = ['rsa.crt', 'int.crt', 'rsa.key'].map((n) => fs.readFileSync(path.join(D, n), 'utf8')).join('\n');
  const m = await buildModel(await ingestText(text));
  assert.equal(m.keyMatch, true); assert.equal(m.chain.length, 2);
});

test('Wrong key and missing intermediate are caught', async () => {
  const m = await buildModel(await ingestAll(['rsa.crt', 'other.key']));
  assert.equal(m.keyMatch, false);
  assert.ok(m.missing);
  const r = runChecks(m);
  assert.equal(r.blocking, true);
  assert.equal(r.checks.find((c) => c.id === 'key').status, 'bad');
  assert.equal(r.checks.find((c) => c.id === 'chain').status, 'warn');
  assert.throws(() => FORMATS.find((f) => f.id === 'pfx').build(makeContext(m, { password: 'x1234567' })), /matching private key/);
});

test('Real public intermediate chains to a Mozilla root from the built-in library', async () => {
  const lib = (await import('../src/lib/model.js')).library();
  const r12 = lib.intermediates.find((c) => c.subject.CN === 'R12');
  assert.ok(r12, 'library has Let’s Encrypt R12');
  const m = await buildModel([r12]);
  assert.equal(m.rootKnown, 'trusted');
  assert.equal(m.rootName, 'ISRG Root X1');
});

test('Non-English output password: OpenSSL reads every file, Java reads JKS', async () => {
  const m = await buildModel(await ingestAll(['rsa.crt', 'rsa.key', 'chain.pem']));
  const pw = 'pässwörd€9';
  const ctx = makeContext(m, { password: pw, alias: 'site' });
  for (const id of ['pfx', 'pfx-legacy', 'jks', 'key-enc']) {
    const f = FORMATS.find((x) => x.id === id), out = f.build(ctx), n = `u-${id}.${f.ext}`;
    write(n, out.data, out.binary);
    if (id === 'jks') assert.match(sh(`keytool -list -storetype JKS -keystore ${n} -storepass '${pw}'`), /PrivateKeyEntry/);
    else if (id === 'key-enc') assert.equal(sh(`openssl pkey -in ${n} -passin 'pass:${pw}' -pubout`).trim(), pubOfCert('rsa.crt'));
    else {
      // Java cannot open PKCS#12 files with non-ASCII passwords (even OpenSSL-made ones); the UI warns about this.
      sh(`openssl pkcs12 -in ${n} -passin 'pass:${pw}' -nodes ${id === 'pfx-legacy' ? '-legacy' : ''} -out ${n}.pem`);
      assert.equal(sh(`openssl pkey -in ${n}.pem -pubout`).trim(), pubOfCert('rsa.crt'));
    }
  }
});
