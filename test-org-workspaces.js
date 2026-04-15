/**
 * Org workspaces feature tests — verifies the invite/member/scoping plumbing
 * in database.js (and via userOps.create auto-provision).
 *
 * Run: node test-org-workspaces.js
 *
 * Does NOT require the HTTP server — exercises ops directly, creates a fresh
 * test org + users, and cleans up at the end.
 */
process.env.SCHEDULER_DISABLED = '1';

const {
  db, userOps, docOps, templateOps, webhookOps, apiKeyOps,
  orgOps, orgMemberOps, orgInviteOps,
} = require('./database');

let passed = 0, failed = 0;
const failures = [];

function t(name, cond, detail) {
  const ok = !!cond;
  const icon = ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
  console.log(`  [${icon}] ${name}${detail ? ' — ' + detail : ''}`);
  if (ok) passed++; else { failed++; failures.push({ name, detail }); }
}

function section(title) { console.log(`\n\x1b[1m${title}\x1b[0m`); }

async function main() {
  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log('\x1b[1m  SealForge Org Workspace Tests\x1b[0m');
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');

  // Unique test domain so re-runs don't collide with a prior org
  const testSuffix = Date.now().toString(36);
  const testDomain = `orgtest-${testSuffix}.local`;

  section('[1] ORG CREATION & AUTO-PROVISION');

  const alice = userOps.create(`alice@${testDomain}`, 'Alice');
  t('First user of new domain auto-creates org', !!alice.org_id);
  t('First user is org admin', alice.role === 'admin');

  const aliceOrg = orgOps.findById(alice.org_id);
  t('Org is findable by domain', orgOps.findByDomain(testDomain)?.id === alice.org_id);
  t('Org slug is url-safe', /^[a-z0-9-]+$/.test(aliceOrg.slug));

  const bob = userOps.create(`bob@${testDomain}`, 'Bob');
  t('Second user of same domain joins same org', bob.org_id === alice.org_id);
  t('Second user gets member role (not admin)', bob.role === 'member');

  section('[2] ORG MEMBERS');

  const members = orgMemberOps.listMembers(aliceOrg.id);
  t('listMembers returns both users', members.length === 2, `got ${members.length}`);
  t('Alice is admin', orgMemberOps.getRole(aliceOrg.id, alice.id) === 'admin');
  t('Bob is member', orgMemberOps.getRole(aliceOrg.id, bob.id) === 'member');
  t('countAdmins returns 1', orgMemberOps.countAdmins(aliceOrg.id) === 1);

  // Role change
  orgMemberOps.setRole(aliceOrg.id, bob.id, 'admin');
  t('setRole promotes member to admin', orgMemberOps.getRole(aliceOrg.id, bob.id) === 'admin');
  t('countAdmins reflects change', orgMemberOps.countAdmins(aliceOrg.id) === 2);
  orgMemberOps.setRole(aliceOrg.id, bob.id, 'member');

  // Membership list for a user
  const bobOrgs = orgMemberOps.listOrgsForUser(bob.id);
  t('listOrgsForUser returns current org', bobOrgs.some(o => o.id === aliceOrg.id));

  section('[3] ORG INVITES');

  const inv = orgInviteOps.create(aliceOrg.id, `carol@${testDomain}`, 'member', alice.id);
  t('create returns token', !!inv.token && inv.token.length >= 32);
  t('create returns expiry', !!inv.expires);

  const pending = orgInviteOps.listPending(aliceOrg.id);
  t('listPending shows the invite', pending.some(i => i.email === `carol@${testDomain}`));

  const found = orgInviteOps.findByToken(inv.token);
  t('findByToken returns invite details', found && found.org_id === aliceOrg.id);
  t('findByToken includes org_name', found && found.org_name === aliceOrg.name);

  const accepted = orgInviteOps.markAccepted(inv.id);
  t('markAccepted succeeds first time', accepted === true);
  const acceptedAgain = orgInviteOps.markAccepted(inv.id);
  t('markAccepted is single-use', acceptedAgain === false);

  t('Accepted invite no longer in pending', !orgInviteOps.listPending(aliceOrg.id).some(i => i.id === inv.id));

  // Re-invite should revoke previous pending invite for same email
  const inv2a = orgInviteOps.create(aliceOrg.id, `dave@${testDomain}`, 'member', alice.id);
  const inv2b = orgInviteOps.create(aliceOrg.id, `dave@${testDomain}`, 'admin', alice.id);
  const daveInvites = orgInviteOps.listPending(aliceOrg.id).filter(i => i.email === `dave@${testDomain}`);
  t('Re-invite replaces prior pending invite', daveInvites.length === 1 && daveInvites[0].role === 'admin');

  section('[4] ORG-SCOPED DATA');

  // Documents: create two docs by different users in same org, both should show in listByOrg
  const doc1 = docOps.create(alice.id, 'doc1', 'a.pdf', 'abc123', '', 'sequential', aliceOrg.id);
  const doc2 = docOps.create(bob.id, 'doc2', 'b.pdf', 'def456', '', 'sequential', aliceOrg.id);
  const orgDocs = docOps.listByOrg(aliceOrg.id);
  t('listByOrg returns docs from both members', orgDocs.some(d => d.id === doc1.id) && orgDocs.some(d => d.id === doc2.id));

  // Templates
  const tpl = templateOps.create(alice.id, { name: 'T1', title: 'T1', signingMode: 'sequential', signers: [], hasPdf: false, pdfHash: null, pdfFilename: null, fields: [], orgId: aliceOrg.id });
  const orgTpls = templateOps.listByOrg(aliceOrg.id);
  t('templateOps.listByOrg returns org templates', orgTpls.some(x => x.id === tpl.id));
  const tplFound = templateOps.findByUUIDInOrg(tpl.uuid, aliceOrg.id);
  t('findByUUIDInOrg finds it', tplFound && tplFound.id === tpl.id);

  // Webhooks
  const wh = webhookOps.create(alice.id, 'https://example.com/hook', ['*'], aliceOrg.id);
  const orgHooks = webhookOps.listByOrg(aliceOrg.id);
  t('webhookOps.listByOrg returns org webhook', orgHooks.some(x => x.id === wh.id));

  // API keys
  const key = apiKeyOps.create(alice.id, 'k1', 'rw', aliceOrg.id);
  const orgKeys = apiKeyOps.listByOrg(aliceOrg.id);
  t('apiKeyOps.listByOrg returns org key', orgKeys.some(x => x.id === key.id));

  section('[5] CROSS-ORG ISOLATION');

  // Create a second org via a totally different domain
  const eve = userOps.create(`eve@other-${testSuffix}.local`, 'Eve');
  t('Different-domain user gets different org', eve.org_id !== aliceOrg.id);

  const eveDocs = docOps.listByOrg(eve.org_id);
  t('Eve sees 0 docs from other org (isolation)', eveDocs.every(d => d.org_id === eve.org_id));
  t('Eve cannot find alice\'s template', !templateOps.findByUUIDInOrg(tpl.uuid, eve.org_id));
  t('Eve cannot find alice\'s webhook in listByOrg', !webhookOps.listByOrg(eve.org_id).some(x => x.id === wh.id));
  t('Eve is not a member of alice\'s org', !orgMemberOps.isMember(aliceOrg.id, eve.id));

  section('[6] CLEANUP');

  // Delete in FK-safe order
  db.prepare('DELETE FROM api_keys WHERE org_id IN (?, ?)').run(aliceOrg.id, eve.org_id);
  db.prepare('DELETE FROM webhooks WHERE org_id IN (?, ?)').run(aliceOrg.id, eve.org_id);
  db.prepare('DELETE FROM templates WHERE org_id IN (?, ?)').run(aliceOrg.id, eve.org_id);
  db.prepare('DELETE FROM documents WHERE org_id IN (?, ?)').run(aliceOrg.id, eve.org_id);
  db.prepare('DELETE FROM org_invites WHERE org_id IN (?, ?)').run(aliceOrg.id, eve.org_id);
  db.prepare('DELETE FROM org_members WHERE org_id IN (?, ?)').run(aliceOrg.id, eve.org_id);
  db.prepare('DELETE FROM users WHERE id IN (?, ?, ?)').run(alice.id, bob.id, eve.id);
  db.prepare('DELETE FROM orgs WHERE id IN (?, ?)').run(aliceOrg.id, eve.org_id);
  t('Cleanup completed', true);

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
