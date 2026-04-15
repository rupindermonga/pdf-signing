/**
 * Embedded signing HTTP tests — verifies the new session-auth embed-session
 * endpoint, authorization checks, and that /embed/sample serves.
 *
 * Run: node test-embed.js
 */
process.env.SCHEDULER_DISABLED = '1';
process.env.PORT = process.env.PORT || '30994';
process.env.SESSION_SECRET = 'test-secret-embed';

const http = require('http');
const { app } = require('./server');
const { userOps, docOps, signerOps, orgMemberOps, otpOps, db } = require('./database');

let passed = 0, failed = 0;
const failures = [];
function t(name, cond, detail) {
  const ok = !!cond;
  const icon = ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
  console.log(`  [${icon}] ${name}${detail ? ' — ' + detail : ''}`);
  if (ok) passed++; else { failed++; failures.push({ name, detail }); }
}
function section(title) { console.log(`\n\x1b[1m${title}\x1b[0m`); }

function cookieJar() {
  const jar = {};
  return {
    setFromHeaders(h) { const sc = h['set-cookie']; if (!sc) return; for (const raw of sc) { const [p] = raw.split(';'); const [k, v] = p.split('='); jar[k.trim()] = v; } },
    header() { return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '); },
  };
}

function req(port, method, path, body, jar) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({
      hostname: '127.0.0.1', port, path, method,
      headers: {
        'Content-Type': 'application/json', 'Accept': 'application/json',
        ...(jar ? { 'Cookie': jar.header() } : {}),
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      },
    }, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => {
        if (jar) jar.setFromHeaders(res.headers);
        let json = null;
        try { json = JSON.parse(buf); } catch {}
        resolve({ status: res.statusCode, body: json, raw: buf });
      });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

async function main() {
  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log('\x1b[1m  SealForge Embedded Signing Tests\x1b[0m');
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');

  const server = app.listen(process.env.PORT);
  await new Promise(r => server.on('listening', r));
  const port = server.address().port;

  const suffix = Date.now().toString(36);
  const domain = `embedtest-${suffix}.local`;

  // Seed: alice (org admin) + doc + signer
  const alice = userOps.create(`alice@${domain}`, 'Alice');
  const doc = docOps.create(alice.id, 'Embed Doc', 'x.pdf', 'h1', '', 'sequential', alice.org_id);
  const sig = signerOps.addToDocument(doc.id, 'Carl', `carl@${domain}`, 1, 'sign');
  signerOps.updateStatus(sig.id, 'sent');

  // Alice sign-in
  const jar = cookieJar();
  await req(port, 'GET', '/login', null, jar);
  const code = otpOps.create(alice.email);
  await req(port, 'POST', '/api/auth/verify-otp', { email: alice.email, code, name: 'Alice' }, jar);

  section('[1] SESSION-AUTH EMBED SESSION CREATE');

  const okResp = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sig.id}/embed-session`, {
    allowedOrigin: 'http://localhost:9000', ttlSeconds: 1800,
  }, jar);
  t('Returns 200 for valid request', okResp.status === 200, `got ${okResp.status}: ${okResp.raw.slice(0, 200)}`);
  t('Returns embedUrl', typeof okResp.body?.embedUrl === 'string' && okResp.body.embedUrl.includes('/embed/sign/'));
  t('Returns embedToken', typeof okResp.body?.embedToken === 'string' && okResp.body.embedToken.length >= 32);
  t('Returns expiresAt ISO', typeof okResp.body?.expiresAt === 'string' && okResp.body.expiresAt.includes('T'));

  section('[2] VALIDATION');

  const badOrigin = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sig.id}/embed-session`, {
    allowedOrigin: 'not-a-url',
  }, jar);
  t('Rejects malformed allowedOrigin', badOrigin.status === 400);

  const httpPublic = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sig.id}/embed-session`, {
    allowedOrigin: 'http://example.com',
  }, jar);
  t('Rejects http:// for non-localhost origin', httpPublic.status === 400);

  const wrongSigner = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/999999/embed-session`, {
    allowedOrigin: 'http://localhost:9000',
  }, jar);
  t('Returns 404 for unknown signer', wrongSigner.status === 404);

  // Create a signed signer and try to embed-session it
  const sig2 = signerOps.addToDocument(doc.id, 'Dana', `dana@${domain}`, 2, 'sign');
  signerOps.updateStatus(sig2.id, 'signed');
  const alreadySigned = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sig2.id}/embed-session`, {
    allowedOrigin: 'http://localhost:9000',
  }, jar);
  t('Rejects already-signed signer (400)', alreadySigned.status === 400);

  section('[3] AUTHORIZATION');

  // Unauthenticated
  const noAuth = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sig.id}/embed-session`, {
    allowedOrigin: 'http://localhost:9000',
  });
  t('Requires auth', noAuth.status === 401);

  // Different user in different org
  const bob = userOps.create(`bob@otherdomain-${suffix}.local`, 'Bob');
  const bobJar = cookieJar();
  await req(port, 'GET', '/login', null, bobJar);
  const bobCode = otpOps.create(bob.email);
  await req(port, 'POST', '/api/auth/verify-otp', { email: bob.email, code: bobCode, name: 'Bob' }, bobJar);
  const crossOrg = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sig.id}/embed-session`, {
    allowedOrigin: 'http://localhost:9000',
  }, bobJar);
  t('Cross-org user gets 403', crossOrg.status === 403);

  section('[4] SAMPLE PAGE');

  const sampleResp = await req(port, 'GET', '/embed/sample');
  t('/embed/sample returns 200', sampleResp.status === 200);
  t('Sample page contains iframe integration snippet', sampleResp.raw.includes('&lt;iframe') || sampleResp.raw.includes('<iframe'));
  t('Sample page references sf:loaded event', sampleResp.raw.includes('sf:loaded'));

  section('[5] CLEANUP');
  try {
    db.prepare('DELETE FROM embed_sessions WHERE signer_id IN (?, ?)').run(sig.id, sig2.id);
    db.prepare('DELETE FROM signers WHERE document_id = ?').run(doc.id);
    db.prepare('DELETE FROM documents WHERE id = ?').run(doc.id);
    db.prepare('DELETE FROM sessions WHERE user_id IN (?, ?)').run(alice.id, bob.id);
    db.prepare('DELETE FROM otp_codes WHERE email IN (?, ?)').run(alice.email, bob.email);
    db.prepare('DELETE FROM org_members WHERE user_id IN (?, ?)').run(alice.id, bob.id);
    db.prepare('DELETE FROM users WHERE id IN (?, ?)').run(alice.id, bob.id);
    db.prepare('DELETE FROM orgs WHERE id IN (?, ?)').run(alice.org_id, bob.org_id);
    t('Cleanup completed', true);
  } catch (e) { t('Cleanup completed', false, e.message); }

  server.close();

  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log(`\x1b[1m  RESULTS: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m\x1b[1m\x1b[0m`);
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');
  if (failed > 0) {
    console.log('\nFailed tests:');
    failures.forEach(f => console.log('  ✗ ' + f.name + (f.detail ? ' — ' + f.detail : '')));
  }
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error('Test error:', e); process.exit(2); });
