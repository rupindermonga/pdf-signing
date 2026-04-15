/**
 * HTTP smoke tests for org workspace routes — spins up server.js on a random port,
 * exercises /api/org, /api/org/members, /api/org/invites, /api/auth/me, /api/org/switch.
 *
 * Run: node test-org-http.js
 */
process.env.SCHEDULER_DISABLED = '1';
process.env.PORT = process.env.PORT || '30991';
process.env.SESSION_SECRET = 'test-secret-for-org-http';

const http = require('http');

const { app } = require('./server');
const { userOps, orgOps, orgMemberOps, orgInviteOps, db, sessionOps } = require('./database');
const expressSession = require('express-session');

let passed = 0, failed = 0;
const failures = [];

function t(name, cond, detail) {
  const ok = !!cond;
  const icon = ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
  console.log(`  [${icon}] ${name}${detail ? ' — ' + detail : ''}`);
  if (ok) passed++; else { failed++; failures.push({ name, detail }); }
}
function section(title) { console.log(`\n\x1b[1m${title}\x1b[0m`); }

// Minimal cookie jar
function cookieJar() {
  const jar = {};
  return {
    setFromHeaders(headers) {
      const sc = headers['set-cookie'];
      if (!sc) return;
      for (const raw of sc) {
        const [pair] = raw.split(';');
        const [k, v] = pair.split('=');
        jar[k.trim()] = v;
      }
    },
    header() { return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '); },
  };
}

function req(port, method, path, body, jar) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({
      hostname: '127.0.0.1', port, path, method,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
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

// Helper: forge a server-side session for a user (skip OTP flow)
// Uses express-session's internal store to inject a valid session cookie.
function forgeSession(user, orgId) {
  return new Promise((resolve) => {
    const mw = app._router.stack.find(l => l.handle && l.handle.name === 'session');
    const store = mw && mw.handle && mw.handle.prototype ? null : null;
    // Simpler: use sessionOps from database.js (legacy session tokens) — but our
    // middleware is express-session, not sessionOps. Instead, we'll seed via a dummy
    // request flow. For this smoke test, we'll call an internal endpoint that sets
    // req.session values. Since that doesn't exist, we short-circuit: use findOrCreate
    // + directly manipulate the store via a fake HTTP call that passes through express-session.
    // The cleanest way: POST /api/auth/verify-otp after seeding an OTP for the user.
    resolve(null);
  });
}

async function main() {
  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log('\x1b[1m  SealForge Org HTTP Tests\x1b[0m');
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');

  const server = app.listen(process.env.PORT);
  await new Promise(r => server.on('listening', r));
  const port = server.address().port;

  const suffix = Date.now().toString(36);
  const domain = `httptest-${suffix}.local`;

  // Direct DB seed: create alice + session
  const alice = userOps.create(`alice@${domain}`, 'Alice');
  const aliceOrg = orgOps.findById(alice.org_id);

  // Seed an OTP and go through the verify-otp flow to establish a session cookie
  const { otpOps } = require('./database');
  const code = otpOps.create(alice.email);

  const jar = cookieJar();

  section('[1] AUTH WITH OTP → SETS session.orgId');

  // First, create a session via a GET so the cookie is issued
  await req(port, 'GET', '/login', null, jar);

  const verifyResp = await req(port, 'POST', '/api/auth/verify-otp', { email: alice.email, code, name: 'Alice' }, jar);
  t('verify-otp returns 200', verifyResp.status === 200, `got ${verifyResp.status}: ${verifyResp.raw.slice(0, 200)}`);
  t('verify-otp redirects to /dashboard', verifyResp.body && verifyResp.body.redirect === '/dashboard');

  const meResp = await req(port, 'GET', '/api/auth/me', null, jar);
  t('auth/me returns org context', meResp.status === 200 && meResp.body.org && meResp.body.org.id === aliceOrg.id, `got ${JSON.stringify(meResp.body && meResp.body.org)}`);
  t('auth/me.org.role is admin', meResp.body?.org?.role === 'admin');
  t('auth/me.workspaces includes current org', Array.isArray(meResp.body?.workspaces) && meResp.body.workspaces.some(w => w.id === aliceOrg.id));

  section('[2] /api/org ROUTES');

  const orgResp = await req(port, 'GET', '/api/org', null, jar);
  t('/api/org returns 200', orgResp.status === 200);
  t('/api/org returns correct name', orgResp.body?.org?.id === aliceOrg.id);
  t('/api/org.role = admin', orgResp.body?.role === 'admin');

  const membersResp = await req(port, 'GET', '/api/org/members', null, jar);
  t('/api/org/members returns alice', membersResp.status === 200 && membersResp.body.members?.some(m => m.id === alice.id));

  // Create an invite
  const inviteResp = await req(port, 'POST', '/api/org/invites', { email: `carol@${domain}`, role: 'member' }, jar);
  t('POST /api/org/invites returns 200', inviteResp.status === 200, `got ${inviteResp.status}: ${inviteResp.raw.slice(0, 200)}`);
  t('Invite has URL', typeof inviteResp.body?.url === 'string' && inviteResp.body.url.includes('/invite/'));

  const invitesListResp = await req(port, 'GET', '/api/org/invites', null, jar);
  t('GET /api/org/invites shows pending invite', invitesListResp.body?.invites?.some(i => i.email === `carol@${domain}`));

  section('[3] INVITE ACCEPTANCE FLOW');

  // Extract invite token from URL
  const inviteUrl = inviteResp.body.url;
  const token = inviteUrl.split('/invite/')[1];

  // Public invite info (no auth)
  const publicInviteResp = await req(port, 'GET', `/api/invite/${token}`);
  t('Public /api/invite/:token works (no auth)', publicInviteResp.status === 200, `got ${publicInviteResp.status}`);
  t('Public invite returns org_name', publicInviteResp.body?.org_name === aliceOrg.name);

  // Log in as carol (different domain so she gets her own primary org) and accept the invite
  const carolDomain = `carol-${suffix}.local`;
  const carolEmail = `carol@${carolDomain}`;
  // Re-issue the invite to the new email (previous one was for carol@${domain})
  // Actually simpler: update inv2a (if any) — just create a brand-new invite for carolEmail
  await req(port, 'DELETE', `/api/org/invites/${inviteResp.body.id || 0}`, null, jar);
  const newInviteResp = await req(port, 'POST', '/api/org/invites', { email: carolEmail, role: 'member' }, jar);
  const newToken = newInviteResp.body.url.split('/invite/')[1];
  const carolOTP = otpOps.create(carolEmail);
  const carolJar = cookieJar();
  await req(port, 'GET', '/login', null, carolJar);
  const carolAuth = await req(port, 'POST', '/api/auth/verify-otp', { email: carolEmail, code: carolOTP, name: 'Carol' }, carolJar);
  t('Carol signs in successfully', carolAuth.status === 200);

  const acceptResp = await req(port, 'POST', `/api/invite/${newToken}/accept`, {}, carolJar);
  t('Carol accepts invite (200)', acceptResp.status === 200, `got ${acceptResp.status}: ${acceptResp.raw.slice(0, 200)}`);
  t('Carol now has alice org in her workspaces', await (async () => {
    const r = await req(port, 'GET', '/api/auth/me', null, carolJar);
    return r.body?.workspaces?.some(w => w.id === aliceOrg.id);
  })());

  section('[4] WORKSPACE SWITCH');

  // Carol's primary org (her own auto-provisioned org) plus alice's = 2 workspaces
  const carolMe = await req(port, 'GET', '/api/auth/me', null, carolJar);
  t('Carol has >= 2 workspaces', carolMe.body?.workspaces?.length >= 2, `got ${carolMe.body?.workspaces?.length}`);

  // Switch to alice's org (the one she just joined)
  const switchResp = await req(port, 'POST', '/api/org/switch', { orgId: aliceOrg.id }, carolJar);
  t('Switch to alice org returns 200', switchResp.status === 200);

  const carolMeAfter = await req(port, 'GET', '/api/auth/me', null, carolJar);
  t('Carol active org is now alice org', carolMeAfter.body?.org?.id === aliceOrg.id);

  // Try to switch to an org Carol isn't part of (eve's)
  const eve = userOps.create(`eve@evil-${suffix}.local`, 'Eve');
  const badSwitch = await req(port, 'POST', '/api/org/switch', { orgId: eve.org_id }, carolJar);
  t('Switch to non-member org returns 403', badSwitch.status === 403);

  section('[5] CROSS-ORG DOCUMENT VISIBILITY');

  // Switch Carol back to alice org, create a doc via alice, Carol should see it
  await req(port, 'POST', '/api/org/switch', { orgId: aliceOrg.id }, carolJar);
  // Alice creates a doc directly via DB (simpler than PDF upload)
  const { docOps } = require('./database');
  const sharedDoc = docOps.create(alice.id, 'Shared Doc', 'x.pdf', 'hash123', '', 'sequential', aliceOrg.id);

  const carolDocs = await req(port, 'GET', '/api/documents', null, carolJar);
  t('Carol sees alice\'s doc in alice workspace', carolDocs.body?.documents?.some(d => d.uuid === sharedDoc.uuid));

  // Switch Carol to her own org, she should NOT see the shared doc
  const carolOrg = orgMemberOps.listOrgsForUser(alice.findByEmail ? carolEmail : userOps.findByEmail(carolEmail).id);
  const carolPrimary = orgMemberOps.listOrgsForUser(userOps.findByEmail(carolEmail).id).find(o => o.id !== aliceOrg.id);
  if (carolPrimary) {
    await req(port, 'POST', '/api/org/switch', { orgId: carolPrimary.id }, carolJar);
    const carolOwnDocs = await req(port, 'GET', '/api/documents', null, carolJar);
    t('In her own org, Carol does NOT see alice\'s doc', !carolOwnDocs.body?.documents?.some(d => d.uuid === sharedDoc.uuid));
  } else {
    t('Carol has separate primary org', false, 'could not find primary org');
  }

  section('[6] NON-ADMIN CANNOT INVITE');

  // Demote Carol in alice org to member, then try to invite
  orgMemberOps.setRole(aliceOrg.id, userOps.findByEmail(carolEmail).id, 'member');
  await req(port, 'POST', '/api/org/switch', { orgId: aliceOrg.id }, carolJar);
  const carolInviteTry = await req(port, 'POST', '/api/org/invites', { email: `intruder@${domain}`, role: 'member' }, carolJar);
  t('Member (non-admin) cannot create invite — 403', carolInviteTry.status === 403);

  section('[7] CLEANUP');

  // Force cleanup
  try {
    const carolUser = userOps.findByEmail(carolEmail);
    db.prepare('DELETE FROM documents WHERE org_id IN (?, ?)').run(aliceOrg.id, eve.org_id);
    db.prepare('DELETE FROM org_invites WHERE org_id = ?').run(aliceOrg.id);
    db.prepare('DELETE FROM org_members WHERE org_id IN (?, ?)').run(aliceOrg.id, eve.org_id);
    if (carolUser) {
      const cOrgs = orgMemberOps.listOrgsForUser(carolUser.id);
      for (const o of cOrgs) db.prepare('DELETE FROM org_members WHERE org_id = ? AND user_id = ?').run(o.id, carolUser.id);
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(carolUser.id);
      db.prepare('DELETE FROM otp_codes WHERE email = ?').run(carolEmail);
      db.prepare('DELETE FROM users WHERE id = ?').run(carolUser.id);
    }
    db.prepare('DELETE FROM sessions WHERE user_id IN (?, ?)').run(alice.id, eve.id);
    db.prepare('DELETE FROM otp_codes WHERE email IN (?, ?)').run(alice.email, eve.email);
    db.prepare('DELETE FROM users WHERE id IN (?, ?)').run(alice.id, eve.id);
    db.prepare('DELETE FROM orgs WHERE id IN (?, ?)').run(aliceOrg.id, eve.org_id);
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

main().catch(e => { console.error('Test harness error:', e); process.exit(2); });
