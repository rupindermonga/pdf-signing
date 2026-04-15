/**
 * Analytics depth feature tests: /api/analytics/reports + /api/analytics/signers.csv.
 * Verifies per-template, per-user, reminder-effectiveness, public-form reports
 * and signer-level CSV export.
 *
 * Run: node test-analytics.js
 */
process.env.SCHEDULER_DISABLED = '1';
process.env.PORT = process.env.PORT || '30961';
process.env.SESSION_SECRET = 'test-secret-analytics';

const http = require('http');
const { app } = require('./server');
const { userOps, docOps, signerOps, templateOps, otpOps, db } = require('./database');

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
        let json = null; try { json = JSON.parse(buf); } catch {}
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
  console.log('\x1b[1m  SealForge Analytics Depth Tests\x1b[0m');
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');

  const server = app.listen(process.env.PORT);
  await new Promise(r => server.on('listening', r));
  const port = server.address().port;

  const suffix = Date.now().toString(36);
  const domain = `anatest-${suffix}.local`;

  // Seed: alice + bob in same org + some docs + a template
  const alice = userOps.create(`alice@${domain}`, 'Alice');
  const bob = userOps.create(`bob@${domain}`, 'Bob');

  // Three docs by alice — one completed, one pending, one cancelled
  const doc1 = docOps.create(alice.id, 'Contract A', 'a.pdf', 'h1', '', 'sequential', alice.org_id);
  const doc2 = docOps.create(alice.id, 'Contract A', 'a.pdf', 'h2', '', 'sequential', alice.org_id);
  const doc3 = docOps.create(alice.id, 'Contract A', 'a.pdf', 'h3', '', 'sequential', alice.org_id);
  docOps.updateStatus(doc1.id, 'completed');
  db.prepare("UPDATE documents SET completed_at = datetime('now') WHERE id = ?").run(doc1.id);
  docOps.updateStatus(doc2.id, 'pending');
  docOps.updateStatus(doc3.id, 'cancelled');

  // Two docs by bob
  const doc4 = docOps.create(bob.id, 'Agreement B', 'b.pdf', 'h4', '', 'sequential', alice.org_id);
  docOps.updateStatus(doc4.id, 'completed');
  db.prepare("UPDATE documents SET completed_at = datetime('now') WHERE id = ?").run(doc4.id);

  // Signers with varied reminder counts
  const s1 = signerOps.addToDocument(doc1.id, 'Carl', 'carl@ext.com', 1, 'sign');
  signerOps.updateStatus(s1.id, 'signed');
  db.prepare('UPDATE signers SET reminder_count = 0, signed_at = datetime(\'now\') WHERE id = ?').run(s1.id);

  const s2 = signerOps.addToDocument(doc2.id, 'Dana', 'dana@ext.com', 1, 'sign');
  db.prepare('UPDATE signers SET reminder_count = 2 WHERE id = ?').run(s2.id);

  const s3 = signerOps.addToDocument(doc3.id, 'Erin', 'erin@ext.com', 1, 'sign');
  db.prepare('UPDATE signers SET reminder_count = 3, status = \'declined\', decline_reason = \'Not interested\' WHERE id = ?').run(s3.id);

  // A template in the org with name matching a doc title
  const tpl = templateOps.create(alice.id, {
    name: 'Contract Template A', title: 'Contract A',
    signingMode: 'sequential', signers: [], hasPdf: false,
    pdfHash: null, pdfFilename: null, fields: [], orgId: alice.org_id,
  });
  // Publish it as a public form
  templateOps.publishInOrg(tpl.uuid, alice.org_id);
  db.prepare('UPDATE templates SET public_submissions = 5 WHERE id = ?').run(tpl.id);

  // Alice session
  const jar = cookieJar();
  await req(port, 'GET', '/login', null, jar);
  const code = otpOps.create(alice.email);
  await req(port, 'POST', '/api/auth/verify-otp', { email: alice.email, code, name: 'Alice' }, jar);

  section('[1] /api/analytics/reports — TEMPLATE CONVERSION');

  const rResp = await req(port, 'GET', '/api/analytics/reports?days=365', null, jar);
  t('reports returns 200', rResp.status === 200, `got ${rResp.status}: ${rResp.raw.slice(0, 200)}`);
  t('period_days echoed', rResp.body?.period_days === 365);
  t('scope is org', rResp.body?.scope === 'org');

  const templates = rResp.body?.templates || [];
  t('Returns our Contract Template A', templates.some(x => x.name === 'Contract Template A'));
  const tA = templates.find(x => x.name === 'Contract Template A');
  t('Template spawned count > 0', tA && tA.spawned >= 1);
  t('Template completed count includes the completed doc', tA && tA.completed >= 1);
  t('Template conversion_pct is a number', tA && typeof tA.conversion_pct === 'number');

  section('[2] /api/analytics/reports — PER-USER');

  const users = rResp.body?.users || [];
  t('Users array returned (org-scope)', Array.isArray(users) && users.length >= 2);
  const aliceReport = users.find(u => u.email === alice.email);
  const bobReport = users.find(u => u.email === bob.email);
  t('Alice in user report', !!aliceReport);
  t('Alice sent count matches (3 docs)', aliceReport?.sent === 3, `got ${aliceReport?.sent}`);
  t('Alice completed count matches (1 doc)', aliceReport?.completed === 1);
  t('Bob in user report', !!bobReport);
  t('Bob sent count matches (1 doc)', bobReport?.sent === 1);
  t('Bob completed count matches (1 doc)', bobReport?.completed === 1);
  t('Bob completion_rate_pct is 100', bobReport?.completion_rate_pct === 100);

  section('[3] /api/analytics/reports — REMINDER EFFECTIVENESS');

  const reminders = rResp.body?.reminder_effectiveness || [];
  t('Reminder buckets returned', Array.isArray(reminders) && reminders.length >= 1);
  // Bucket for reminder_count=0 should have the signed signer
  const b0 = reminders.find(r => r.reminder_count === 0);
  t('Bucket 0 has signed signers', b0 && b0.signed >= 1);

  section('[4] /api/analytics/reports — PUBLIC FORMS');

  const forms = rResp.body?.public_forms || [];
  t('Public forms list includes published template', forms.some(f => f.slug && f.name === 'Contract Template A'));
  const f = forms.find(f => f.name === 'Contract Template A');
  t('Form submission count preserved', f?.submissions === 5);

  section('[5] /api/analytics/reports — WEBHOOKS');

  t('webhooks object returned', rResp.body?.webhooks && typeof rResp.body.webhooks === 'object');
  t('webhooks.total is a number', typeof rResp.body?.webhooks?.total === 'number');

  section('[6] /api/analytics/signers.csv');

  const csvResp = await req(port, 'GET', '/api/analytics/signers.csv?days=365', null, jar);
  t('signers.csv returns 200', csvResp.status === 200);
  t('CSV header row present', csvResp.raw.startsWith('doc_uuid,doc_title'));
  t('Includes decline_reason column', csvResp.raw.includes('decline_reason'));
  t('Includes sendback_count column', csvResp.raw.includes('sendback_count'));
  t('Body row for Carl', csvResp.raw.includes('Carl') && csvResp.raw.includes('carl@ext.com'));
  t('Body row includes Erin\'s decline reason', csvResp.raw.includes('Not interested'));

  section('[7] AUTHZ');

  const unauth = await req(port, 'GET', '/api/analytics/reports?days=30');
  t('Requires auth', unauth.status === 401);

  const unauthCsv = await req(port, 'GET', '/api/analytics/signers.csv?days=30');
  t('CSV requires auth', unauthCsv.status === 401);

  // Viewer-role user should be denied (same gate as other analytics endpoints)
  const eve = userOps.create(`eve@${domain}`, 'Eve');
  db.prepare("UPDATE users SET role = 'viewer' WHERE id = ?").run(eve.id);
  const { orgMemberOps } = require('./database');
  orgMemberOps.setRole(alice.org_id, eve.id, 'viewer');
  const eveJar = cookieJar();
  await req(port, 'GET', '/login', null, eveJar);
  const eveCode = otpOps.create(eve.email);
  await req(port, 'POST', '/api/auth/verify-otp', { email: eve.email, code: eveCode, name: 'Eve' }, eveJar);
  const eveReports = await req(port, 'GET', '/api/analytics/reports?days=30', null, eveJar);
  t('Viewer role denied on reports (403)', eveReports.status === 403);

  section('[8] CLEANUP');
  try {
    db.prepare('DELETE FROM signers WHERE document_id IN (?, ?, ?, ?)').run(doc1.id, doc2.id, doc3.id, doc4.id);
    db.prepare('DELETE FROM documents WHERE id IN (?, ?, ?, ?)').run(doc1.id, doc2.id, doc3.id, doc4.id);
    db.prepare('DELETE FROM templates WHERE id = ?').run(tpl.id);
    db.prepare('DELETE FROM sessions WHERE user_id IN (?, ?, ?)').run(alice.id, bob.id, eve.id);
    db.prepare('DELETE FROM otp_codes WHERE email IN (?, ?, ?)').run(alice.email, bob.email, eve.email);
    db.prepare('DELETE FROM org_members WHERE user_id IN (?, ?, ?)').run(alice.id, bob.id, eve.id);
    db.prepare('DELETE FROM users WHERE id IN (?, ?, ?)').run(alice.id, bob.id, eve.id);
    db.prepare('DELETE FROM orgs WHERE id IN (?, ?)').run(alice.org_id, eve.org_id);
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
