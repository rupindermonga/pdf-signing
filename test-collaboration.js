/**
 * Collaboration feature tests: comments, substitute-signer, send-back,
 * and that decline reasons surface in doc detail + analytics.
 *
 * Run: node test-collaboration.js
 */
process.env.SCHEDULER_DISABLED = '1';
process.env.PORT = process.env.PORT || '30981';
process.env.SESSION_SECRET = 'test-secret-collab';

const http = require('http');
const { app } = require('./server');
const { userOps, docOps, signerOps, commentOps, otpOps, db } = require('./database');

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
  console.log('\x1b[1m  SealForge Collaboration Tests\x1b[0m');
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');

  const server = app.listen(process.env.PORT);
  await new Promise(r => server.on('listening', r));
  const port = server.address().port;

  const suffix = Date.now().toString(36);
  const domain = `collabtest-${suffix}.local`;

  // Seed: alice (owner) + doc + two signers
  const alice = userOps.create(`alice@${domain}`, 'Alice');
  const doc = docOps.create(alice.id, 'Collab Doc', 'x.pdf', 'h1', '', 'sequential', alice.org_id);
  const sigA = signerOps.addToDocument(doc.id, 'Carl', `carl@${domain}`, 1, 'sign');
  signerOps.updateStatus(sigA.id, 'sent');
  const sigB = signerOps.addToDocument(doc.id, 'Dana', `dana@${domain}`, 2, 'sign');

  // Alice session
  const jar = cookieJar();
  await req(port, 'GET', '/login', null, jar);
  const aCode = otpOps.create(alice.email);
  await req(port, 'POST', '/api/auth/verify-otp', { email: alice.email, code: aCode, name: 'Alice' }, jar);

  section('[1] COMMENTS — OWNER SIDE');

  const postResp = await req(port, 'POST', `/api/documents/${doc.uuid}/comments`, { body: 'Hi Carl, please review before Friday' }, jar);
  t('Owner can post comment (200)', postResp.status === 200, `got ${postResp.status}: ${postResp.raw.slice(0, 200)}`);
  t('Returns new id', typeof postResp.body?.id === 'number');

  const listResp = await req(port, 'GET', `/api/documents/${doc.uuid}/comments`, null, jar);
  t('List returns 1 comment', listResp.body?.comments?.length === 1);
  t('Comment author_type is owner', listResp.body?.comments?.[0]?.author_type === 'owner');
  t('Comment body preserved', listResp.body?.comments?.[0]?.body === 'Hi Carl, please review before Friday');

  const emptyPost = await req(port, 'POST', `/api/documents/${doc.uuid}/comments`, { body: '' }, jar);
  t('Empty comment rejected (400)', emptyPost.status === 400);

  const noAuthPost = await req(port, 'POST', `/api/documents/${doc.uuid}/comments`, { body: 'nope' });
  t('Post requires auth (401)', noAuthPost.status === 401);

  section('[2] COMMENTS — SIGNER SIDE');

  // Signer side needs OTP verification. Use the signer token route.
  const sigJar = cookieJar();
  // Try to post without OTP verification — should be 403
  const noOtpPost = await req(port, 'POST', `/api/sign/${sigA.token}/comments`, { body: 'from Carl' }, sigJar);
  t('Signer post without OTP verify rejected (403)', noOtpPost.status === 403);

  // Get info + send OTP + verify (mirrors the real flow)
  await req(port, 'GET', `/api/sign/${sigA.token}/info`, null, sigJar);
  await req(port, 'POST', `/api/sign/${sigA.token}/send-otp`, {}, sigJar);
  const otpRow = db.prepare('SELECT otp FROM signers WHERE id = ?').get(sigA.id);
  const verifyResp = await req(port, 'POST', `/api/sign/${sigA.token}/verify-otp`, { code: otpRow.otp }, sigJar);
  t('Signer OTP verify returns 200', verifyResp.status === 200, `got ${verifyResp.status}`);

  // Now signer can post
  const sigPost = await req(port, 'POST', `/api/sign/${sigA.token}/comments`, { body: 'I have a question about clause 5' }, sigJar);
  t('Signer can post after OTP verify (200)', sigPost.status === 200, `got ${sigPost.status}: ${sigPost.raw.slice(0, 200)}`);

  const listAfter = await req(port, 'GET', `/api/documents/${doc.uuid}/comments`, null, jar);
  t('Owner sees signer comment (2 total)', listAfter.body?.comments?.length === 2);
  t('Signer comment has author_type=signer', listAfter.body?.comments?.[1]?.author_type === 'signer');

  // Signer can also list comments via their token (no auth needed beyond the token)
  const sigList = await req(port, 'GET', `/api/sign/${sigA.token}/comments`);
  t('Signer can list comments via token', sigList.status === 200 && sigList.body?.comments?.length === 2);

  section('[3] SUBSTITUTE SIGNER');

  // Alice substitutes Dana (pending, signer 2) with Eve
  const subResp = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sigB.id}/substitute`,
    { name: 'Eve', email: `eve@${domain}` }, jar);
  t('Substitute returns 200', subResp.status === 200, `got ${subResp.status}: ${subResp.raw.slice(0, 200)}`);

  const updatedB = signerOps.findById(sigB.id);
  t('Signer name changed', updatedB.name === 'Eve');
  t('Signer email changed', updatedB.email === `eve@${domain}`);
  t('reassigned_from_name captured', updatedB.reassigned_from_name === 'Dana');
  t('substituted_by_owner flag set', updatedB.substituted_by_owner === 1);
  t('Token rotated', updatedB.token !== sigB.token);

  // Cannot substitute a signed signer
  signerOps.updateStatus(sigA.id, 'signed');
  const subSigned = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sigA.id}/substitute`,
    { name: 'Frank', email: `frank@${domain}` }, jar);
  t('Cannot substitute already-signed signer (400)', subSigned.status === 400);
  signerOps.updateStatus(sigA.id, 'sent'); // reset for next test

  // Validation: bad email
  const subBad = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sigB.id}/substitute`,
    { name: 'Nobody', email: 'not-an-email' }, jar);
  t('Rejects malformed email (400)', subBad.status === 400);

  // A substitute posts a system comment
  const commentsAfterSub = await req(port, 'GET', `/api/documents/${doc.uuid}/comments`, null, jar);
  t('System comment logged for substitute', commentsAfterSub.body?.comments?.some(c => c.body.includes('Substituted signer')));

  section('[4] SEND-BACK');

  // Reset sigA to 'sent' (current signer) for send-back
  signerOps.updateStatus(sigA.id, 'sent');
  const sbResp = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sigA.id}/send-back`,
    { message: 'Please update your name field — I misspelled it' }, jar);
  t('Send-back returns 200', sbResp.status === 200, `got ${sbResp.status}: ${sbResp.raw.slice(0, 200)}`);

  const aAfterSb = signerOps.findById(sigA.id);
  t('sendback_count incremented', aAfterSb.sendback_count === 1);
  t('last_sendback_at set', !!aAfterSb.last_sendback_at);

  // Send-back should also post a comment with the message
  const sbComments = await req(port, 'GET', `/api/documents/${doc.uuid}/comments`, null, jar);
  t('Send-back message posted as comment', sbComments.body?.comments?.some(c => c.body.includes('misspelled')));

  // Cannot send-back if signer already signed
  signerOps.updateStatus(sigA.id, 'signed');
  const sbSigned = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sigA.id}/send-back`,
    { message: 'please redo' }, jar);
  t('Cannot send back signed signer (400)', sbSigned.status === 400);
  signerOps.updateStatus(sigA.id, 'sent'); // reset

  // Empty message rejected
  const sbEmpty = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sigA.id}/send-back`,
    { message: '' }, jar);
  t('Empty send-back message rejected (400)', sbEmpty.status === 400);

  section('[5] DECLINE REASON SURFACES IN DOC DETAIL + ANALYTICS');

  // Trigger a decline on sigB (currently status='pending' after substitute). Force to 'sent' so decline works.
  signerOps.updateStatus(sigB.id, 'sent');
  const declineOk = signerOps.decline(sigB.id, 'Need legal review first — too many clauses');
  t('Decline recorded', declineOk === true);

  const detailResp = await req(port, 'GET', `/api/documents/${doc.uuid}`, null, jar);
  const eveRow = detailResp.body?.signers?.find(s => s.id === sigB.id);
  t('Doc detail exposes decline_reason', eveRow?.decline_reason === 'Need legal review first — too many clauses');
  t('Doc detail exposes declined_at', !!eveRow?.declined_at);
  t('Doc detail exposes substituted_by_owner', eveRow?.substituted_by_owner === true);
  t('Doc detail includes commentCount', typeof detailResp.body?.commentCount === 'number' && detailResp.body.commentCount > 0);

  const funnelResp = await req(port, 'GET', '/api/analytics/funnel', null, jar);
  t('Analytics funnel returns decline_reasons array', Array.isArray(funnelResp.body?.decline_reasons));
  t('Decline reason present in analytics', funnelResp.body?.decline_reasons?.some(r => (r.decline_reason || '').includes('legal review')));

  section('[6] MUTATION AUTHZ');

  // Bob in different org should not be able to substitute / send-back / post comments
  const bob = userOps.create(`bob@diff-${suffix}.local`, 'Bob');
  const bJar = cookieJar();
  await req(port, 'GET', '/login', null, bJar);
  const bCode = otpOps.create(bob.email);
  await req(port, 'POST', '/api/auth/verify-otp', { email: bob.email, code: bCode, name: 'Bob' }, bJar);

  const bobComment = await req(port, 'POST', `/api/documents/${doc.uuid}/comments`, { body: 'intrusion' }, bJar);
  t('Cross-org user cannot post comment (403)', bobComment.status === 403);
  const bobSub = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sigA.id}/substitute`,
    { name: 'Hacker', email: `hack@${domain}` }, bJar);
  t('Cross-org user cannot substitute (403)', bobSub.status === 403);
  const bobSendBack = await req(port, 'POST', `/api/documents/${doc.uuid}/signers/${sigA.id}/send-back`,
    { message: 'intrusion' }, bJar);
  t('Cross-org user cannot send back (403)', bobSendBack.status === 403);

  section('[7] CLEANUP');
  try {
    db.prepare('DELETE FROM document_comments WHERE document_id = ?').run(doc.id);
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
