// Every output format and every server pack. Builders return { name, data, binary } (data: forge binary string or text).
import { pem, b64, safeName, CfError } from './util.js';
import { writePkcs12 } from './pkcs12.js';
import { writeJks } from './jks.js';
import { p7bPem } from './pkcs7.js';
import { keyPemPkcs8, keyPemEncrypted, keyPemTraditional } from './keys.js';

/** Context derived from the model + user options */
export function makeContext(model, { password = '', alias = '', includeRoot = false } = {}) {
  if (!model || !model.leaf) throw new CfError('Add a certificate first.', 'NO_CERT');
  const leaf = model.leaf;
  const chainCerts = [leaf, ...model.intermediates, ...(includeRoot && model.root ? [model.root] : [])];
  const caCerts = chainCerts.slice(1);
  const base = safeName(leaf.subject.CN || leaf.sans[0] || 'certificate');
  const usableKey = model.key && model.keyMatch ? model.key : null;
  return {
    model, leaf, base, password, includeRoot,
    alias: (alias || model.key?.friendlyName || base).toLowerCase(),
    key: usableKey,
    chain: chainCerts.map((c) => c.der),
    ca: caCerts.map((c) => c.der),
    domains: leaf.sans.length ? leaf.sans : [leaf.subject.CN].filter(Boolean),
  };
}

const pemCerts = (ders) => ders.map((d) => pem('CERTIFICATE', d)).join('');
const needKey = (ctx) => { if (!ctx.key) throw new CfError('This format needs the matching private key.', 'NO_KEY'); };
const needPw = (ctx) => { if (!ctx.password) throw new CfError('Set a password for this format.', 'NO_PASSWORD'); };

export const FORMATS = [
  { id: 'pfx', ext: 'pfx', title: 'PFX / PKCS#12', desc: 'Key + cert + chain · AES-256 · Windows Server 2019+, Azure, macOS, Java 9+', key: true, pw: true,
    build: (c, name = `${c.base}.pfx`) => { needKey(c); needPw(c); return { name, binary: true, data: writePkcs12({ pkcs8: c.key.pkcs8, chain: c.chain, password: c.password, friendlyName: c.alias }) }; } },
  { id: 'pfx-legacy', ext: 'pfx', title: 'PFX, legacy encryption', desc: 'Triple-DES · Windows Server 2012–2016, Azure App Service, older appliances', key: true, pw: true,
    build: (c, name = `${c.base}-legacy.pfx`) => { needKey(c); needPw(c); return { name, binary: true, data: writePkcs12({ pkcs8: c.key.pkcs8, chain: c.chain, password: c.password, friendlyName: c.alias, legacy: true }) }; } },
  { id: 'jks', ext: 'jks', title: 'Java KeyStore', desc: 'Key + chain · Tomcat, JBoss, Java 8 and older', key: true, pw: true,
    build: (c, name = `${c.base}.jks`) => { needKey(c); needPw(c); return { name, binary: true, data: writeJks({ storePassword: c.password, entries: [{ alias: c.alias, pkcs8: c.key.pkcs8, chain: c.chain }] }) }; } },
  { id: 'fullchain', ext: 'pem', title: 'Full chain PEM', desc: 'Certificate + intermediates, in order · Nginx, HAProxy', key: false,
    build: (c, name = `${c.base}.fullchain.pem`) => ({ name, data: pemCerts(c.chain) }) },
  { id: 'cert', ext: 'crt', title: 'Certificate PEM', desc: 'Your certificate only · Apache, cPanel, AWS', key: false,
    build: (c, name = `${c.base}.crt`) => ({ name, data: pem('CERTIFICATE', c.chain[0]) }) },
  { id: 'cabundle', ext: 'crt', title: 'CA bundle PEM', desc: 'Intermediates only, in order · Apache chain file, AWS chain field', key: false,
    build: (c, name = `${c.base}.ca-bundle.crt`) => { if (!c.ca.length) throw new CfError('There are no intermediate certificates to bundle.', 'NO_CA'); return { name, data: pemCerts(c.ca) }; } },
  { id: 'key', ext: 'key', title: 'Private key, PKCS#8', desc: 'BEGIN PRIVATE KEY · unencrypted · most servers', key: true,
    build: (c, name = `${c.base}.key`) => { needKey(c); return { name, data: keyPemPkcs8(c.key.pkcs8) }; } },
  { id: 'key-enc', ext: 'key', title: 'Private key, encrypted', desc: 'PKCS#8 · AES-256 · for safe storage and transport', key: true, pw: true,
    build: (c, name = `${c.base}.enc.key`) => { needKey(c); needPw(c); return { name, data: keyPemEncrypted(c.key.pkcs8, c.password) }; } },
  { id: 'key-trad', ext: 'key', title: 'Private key, traditional', desc: 'BEGIN RSA / EC PRIVATE KEY · older Apache and OpenSSL 1.0 tools', key: true,
    available: (c) => !c.key || c.key.pub.kind === 'rsa' || c.key.pub.kind === 'ec',
    build: (c, name = `${c.base}.traditional.key`) => { needKey(c); const t = keyPemTraditional(c.key.pkcs8); if (!t) throw new CfError('This key type has no traditional format.', 'NO_FORMAT'); return { name, data: t }; } },
  { id: 'combined', ext: 'pem', title: 'Combined PEM', desc: 'Key + certificate + chain in one file · HAProxy, Webmin, appliances', key: true,
    build: (c, name = `${c.base}.combined.pem`) => { needKey(c); return { name, data: pemCerts(c.chain) + keyPemPkcs8(c.key.pkcs8) }; } },
  { id: 'der', ext: 'cer', title: 'DER certificate', desc: 'Your certificate, binary · Windows import, Java, IoT devices', key: false,
    build: (c, name = `${c.base}.cer`) => ({ name, binary: true, data: c.chain[0] }) },
  { id: 'p7b', ext: 'p7b', title: 'PKCS#7 bundle', desc: 'Certificate + chain, no key · IIS and Tomcat chain import', key: false,
    build: (c, name = `${c.base}.p7b`) => ({ name, data: p7bPem(c.chain) }) },
  { id: 'truststore', ext: 'jks', title: 'Java truststore', desc: 'CA certificates only · Java clients that must trust this CA', key: false, pw: true,
    build: (c, name = `${c.base}.truststore.jks`) => {
      needPw(c);
      const cas = c.model.root ? [...c.model.intermediates, c.model.root] : c.model.intermediates;
      if (!cas.length) throw new CfError('There are no CA certificates to trust.', 'NO_CA');
      return { name, binary: true, data: writeJks({ storePassword: c.password, trusted: cas.map((x, i) => ({ alias: safeName(x.subject.CN || 'ca' + i).replace(/_/g, '-') + (i ? '' : ''), der: x.der })) }) };
    } },
];
export const formatById = (id) => FORMATS.find((f) => f.id === id);

/* ---------------- server packs ---------------- */

const dots = '••••••••••••';
const readme = (pack, ctx, files, snippet) => [
  `${pack.name} — certificate files for ${ctx.domains.join(', ')}`,
  `Generated by CertForge on ${new Date().toISOString().slice(0, 10)}. Nothing was uploaded anywhere.`,
  '',
  'FILES',
  ...files.map((f) => `  ${f.name.padEnd(32)} ${f.note || ''}`),
  '',
  'STEPS',
  ...pack.steps(ctx).map((s, i) => `  ${i + 1}. ${s}`),
  ...(snippet ? ['', snippet.title.toUpperCase(), '', snippet.code] : []),
  ...(pack.verify ? ['', 'CHECK IT YOURSELF (optional)', '', '  ' + pack.verify(ctx)] : []),
  '',
  ...(pack.pw ? ['The password is not written in any file. Use the one you set in CertForge.', ''] : []),
].join('\n');

export const PACKS = [
  { id: 'nginx', name: 'Nginx', glyph: 'NG', needs: 'a full-chain certificate file and the private key',
    rec: ['fullchain', 'key'], dir: '/etc/nginx/ssl',
    files: (c) => [
      { f: 'fullchain', name: `${c.base}.fullchain.pem`, note: 'Certificate + intermediates' },
      { f: 'key', name: `${c.base}.key`, note: 'Private key (keep it secret)' }],
    snippet: (c) => ({ title: 'Add to your server block', lang: 'nginx', code:
`server {
    listen 443 ssl;
    server_name ${c.domains.join(' ')};

    ssl_certificate     /etc/nginx/ssl/${c.base}.fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/${c.base}.key;
}` }),
    steps: () => ['Copy both files to /etc/nginx/ssl/', 'Add the two ssl_ lines to your server block', 'Test with: sudo nginx -t', 'Reload with: sudo systemctl reload nginx'],
    verify: (c) => `openssl x509 -in /etc/nginx/ssl/${c.base}.fullchain.pem -noout -subject -enddate` },
  { id: 'apache', name: 'Apache', glyph: 'AP', needs: 'the certificate, the CA bundle and the private key',
    rec: ['cert', 'cabundle', 'key'],
    files: (c) => [
      { f: 'cert', name: `${c.base}.crt`, note: 'Your certificate' },
      ...(c.ca.length ? [{ f: 'cabundle', name: `${c.base}.ca-bundle.crt`, note: 'Intermediates (Apache 2.4.7 and older)' }] : []),
      { f: 'fullchain', name: `${c.base}.fullchain.pem`, note: 'Certificate + chain (Apache 2.4.8+)' },
      { f: 'key', name: `${c.base}.key`, note: 'Private key (keep it secret)' }],
    snippet: (c) => ({ title: 'Add inside <VirtualHost *:443>', lang: 'apache', code:
`SSLEngine on
# Apache 2.4.8 and newer
SSLCertificateFile    /etc/ssl/certs/${c.base}.fullchain.pem
SSLCertificateKeyFile /etc/ssl/private/${c.base}.key

# Apache 2.4.7 and older: use these instead
# SSLCertificateFile      /etc/ssl/certs/${c.base}.crt
# SSLCertificateChainFile /etc/ssl/certs/${c.base}.ca-bundle.crt` }),
    steps: () => ['Copy the certificate files to /etc/ssl/certs/ and the key to /etc/ssl/private/', 'Add the lines to your <VirtualHost *:443>', 'Test with: sudo apachectl configtest', 'Reload with: sudo systemctl reload apache2 (or httpd)'],
    verify: (c) => `openssl x509 -in /etc/ssl/certs/${c.base}.fullchain.pem -noout -subject -enddate` },
  { id: 'iis', name: 'IIS', glyph: 'IIS', needs: 'a PFX with your key and chain', pw: true,
    rec: ['pfx', 'pfx-legacy'],
    files: (c) => [
      { f: 'pfx', name: `${c.base}.pfx`, note: 'Windows Server 2019 and newer' },
      { f: 'pfx-legacy', name: `${c.base}-legacy.pfx`, note: 'Windows Server 2016 and older' }],
    snippet: (c) => ({ title: 'Import with PowerShell (as Administrator)', lang: 'powershell', code:
`$pw = Read-Host -AsSecureString "PFX password"
Import-PfxCertificate -FilePath C:\\certs\\${c.base}.pfx \`
  -CertStoreLocation Cert:\\LocalMachine\\My -Password $pw` }),
    steps: () => ['Copy the right PFX to the server (legacy file for Windows Server 2016 and older)', 'IIS Manager → server → Server Certificates → Import, or run the PowerShell below', 'Site → Bindings → https → pick the imported certificate', 'Open the site over https to confirm'],
    verify: (c) => `certutil -dump C:\\certs\\${c.base}.pfx` },
  { id: 'tomcat', name: 'Tomcat', glyph: 'TC', needs: 'a keystore with your key and chain', pw: true, alias: 'tomcat',
    rec: ['jks', 'pfx'],
    files: (c) => [
      { f: 'jks', name: `${c.base}.jks`, note: `Key + chain · alias “${c.alias}”` },
      { f: 'pfx', name: `${c.base}.p12`, note: 'Same, PKCS#12 (Java 9+)' }],
    snippet: (c) => ({ title: 'Paste into conf/server.xml', lang: 'xml', code:
`<!-- HTTPS on 8443, generated by CertForge -->
<Connector port="8443"
  protocol="org.apache.coyote.http11.Http11NioProtocol"
  SSLEnabled="true" maxThreads="150">
  <SSLHostConfig>
    <Certificate certificateKeystoreFile="conf/${c.base}.jks"
      certificateKeystoreType="JKS"
      certificateKeyAlias="${c.alias}"
      certificateKeystorePassword="${dots}" />
  </SSLHostConfig>
</Connector>` }),
    steps: (c) => ['Copy the files to conf/', 'Paste the connector, replacing the password dots', `Restart Tomcat and open https://${c.domains[0] || 'your-site'}:8443`],
    verify: (c) => `keytool -list -v -storetype JKS -keystore conf/${c.base}.jks` },
  { id: 'haproxy', name: 'HAProxy', glyph: 'HA', needs: 'one combined file: certificate, chain and key',
    rec: ['combined'],
    files: (c) => [{ f: 'combined', name: `${c.base}.pem`, note: 'Certificate + chain + key in one file' }],
    snippet: (c) => ({ title: 'In your frontend', lang: 'haproxy', code:
`frontend https-in
    bind :443 ssl crt /etc/haproxy/certs/${c.base}.pem` }),
    steps: () => ['Copy the file to /etc/haproxy/certs/ (chmod 600)', 'Point the bind line at it', 'Check with: haproxy -c -f /etc/haproxy/haproxy.cfg', 'Reload with: sudo systemctl reload haproxy'],
    verify: (c) => `openssl x509 -in /etc/haproxy/certs/${c.base}.pem -noout -subject -enddate` },
  { id: 'k8s', name: 'Kubernetes', glyph: 'K8', needs: 'a TLS Secret with the full chain and key',
    rec: ['fullchain', 'key'],
    files: (c) => [
      { f: 'k8s-secret', name: `${c.base}-tls-secret.yaml`, note: 'Ready-to-apply TLS Secret' },
      { f: 'fullchain', name: 'tls.crt', note: 'Certificate + chain' },
      { f: 'key', name: 'tls.key', note: 'Private key' }],
    snippet: (c) => ({ title: 'Apply the Secret', lang: 'bash', code:
`kubectl apply -f ${c.base}-tls-secret.yaml

# or build it from the two files:
kubectl create secret tls ${c.base.replace(/_/g, '-')}-tls --cert=tls.crt --key=tls.key` }),
    steps: (c) => ['Apply the Secret in the namespace of your Ingress', `Reference it in your Ingress: tls: - secretName: ${c.base.replace(/_/g, '-')}-tls`, 'Check with: kubectl describe secret ' + c.base.replace(/_/g, '-') + '-tls'],
    verify: (c) => `kubectl get secret ${c.base.replace(/_/g, '-')}-tls -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -subject -enddate` },
  { id: 'aws', name: 'AWS', glyph: 'AWS', needs: 'three PEM files for ACM: body, key and chain',
    rec: ['cert', 'key', 'cabundle'],
    files: (c) => [
      { f: 'cert', name: 'certificate.pem', note: 'Certificate body' },
      { f: 'key', name: 'private_key.pem', note: 'Private key (unencrypted, as ACM requires)' },
      ...(c.ca.length ? [{ f: 'cabundle', name: 'certificate_chain.pem', note: 'Certificate chain' }] : [])],
    snippet: (c) => ({ title: 'Import into AWS Certificate Manager', lang: 'bash', code:
`aws acm import-certificate \\
  --certificate fileb://certificate.pem \\
  --private-key fileb://private_key.pem${c.ca.length ? ' \\\n  --certificate-chain fileb://certificate_chain.pem' : ''} \\
  --region us-east-1` }),
    steps: () => ['Pick the AWS region where your load balancer or CloudFront lives (CloudFront needs us-east-1)', 'Run the command, or paste each file into ACM → Import certificate', 'Attach the certificate to your load balancer listener or distribution'] },
  { id: 'azure', name: 'Azure', glyph: 'AZ', needs: 'a PFX — Triple-DES for App Service compatibility', pw: true,
    rec: ['pfx-legacy', 'pfx'],
    files: (c) => [
      { f: 'pfx-legacy', name: `${c.base}.pfx`, note: 'App Service and Key Vault' },
      { f: 'pfx', name: `${c.base}-aes.pfx`, note: 'AES-256, for Key Vault and newer services' }],
    snippet: (c) => ({ title: 'Import into Key Vault', lang: 'bash', code:
`az keyvault certificate import \\
  --vault-name <your-vault> \\
  --name ${c.base.replace(/_/g, '-')} \\
  --file ${c.base}.pfx \\
  --password '<your PFX password>'` }),
    steps: () => ['App Service: TLS/SSL settings → Private Key Certificates → Upload, choose the .pfx', 'Key Vault: run the command below', 'Bind the certificate to your custom domain'] },
  { id: 'cpanel', name: 'cPanel', glyph: 'cP', needs: 'three boxes to paste: certificate, key and CA bundle',
    rec: ['cert', 'key', 'cabundle'],
    files: (c) => [
      { f: 'cert', name: `${c.base}.crt`, note: 'Paste into “Certificate (CRT)”' },
      { f: 'key', name: `${c.base}.key`, note: 'Paste into “Private Key (KEY)”' },
      ...(c.ca.length ? [{ f: 'cabundle', name: `${c.base}.ca-bundle.crt`, note: 'Paste into “Certificate Authority Bundle”' }] : [])],
    snippet: null,
    steps: () => ['cPanel → Security → SSL/TLS → Manage SSL sites', 'Pick the domain', 'Open each file in a text editor and paste it into its box', 'Click Install Certificate'] },
  { id: 'cloudflare', name: 'Cloudflare', glyph: 'CF', needs: 'the full chain and the private key',
    rec: ['fullchain', 'key'],
    files: (c) => [
      { f: 'fullchain', name: `${c.base}.fullchain.pem`, note: 'Paste into “SSL certificate”' },
      { f: 'key', name: `${c.base}.key`, note: 'Paste into “Private key”' }],
    snippet: null,
    steps: () => ['Cloudflare dashboard → your domain → SSL/TLS → Edge Certificates', 'Upload Custom SSL certificate', 'Paste the certificate and key; keep bundle method “Compatible”', 'Save — it goes live across Cloudflare’s network in a few minutes'] },
];
export const packById = (id) => PACKS.find((p) => p.id === id);

function k8sSecret(c) {
  const name = c.base.replace(/_/g, '-') + '-tls';
  const crt = b64(pemCerts(c.chain)), key = b64(keyPemPkcs8(c.key.pkcs8));
  return `apiVersion: v1
kind: Secret
metadata:
  name: ${name}
type: kubernetes.io/tls
data:
  tls.crt: ${crt}
  tls.key: ${key}
`;
}

/** Build every file of a pack. Returns [{name, data, binary, note}] plus README. */
export function buildPack(packId, ctx) {
  const pack = packById(packId);
  const list = pack.files(ctx);
  const files = list.map((f) => {
    if (f.f === 'k8s-secret') { needKey(ctx); return { name: f.name, data: k8sSecret(ctx), note: f.note }; }
    return { ...formatById(f.f).build(ctx, f.name), note: f.note };
  });
  const snippet = pack.snippet ? pack.snippet(ctx) : null;
  files.push({ name: `README-${pack.id}.txt`, data: readme(pack, ctx, list, snippet), note: 'Steps + config' });
  return files;
}
