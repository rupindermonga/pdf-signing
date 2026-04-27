/**
 * Regression test for the Patch 6 API-v1 org-scoping fix.
 *
 * Before the patch, `/api/v1/documents/:uuid` (and cancel/download/embed)
 * fetched the document by UUID and then filtered by org_id in the handler.
 * A forgotten post-fetch check would have leaked cross-org docs.
 *
 * The fix pushed the scope into the WHERE clause via
 * `docOps.findByUUIDForCaller` and `docOps.findByIdForCaller`. This test
 * exercises those helpers directly at the DB layer — no HTTP server required —
 * so the regression can be caught in CI without the flake surface of a live
 * Express process.
 *
 * Run: node test-idor-scoping.js
 */
require('dotenv').config();
const { docOps, orgOps, userOps, orgMemberOps, db } = require('./database');

let pass = 0, fail = 0;
function t(desc, cond) {
  if (cond) { pass++; console.log(`  ✓ ${desc}`); }
  else      { fail++; console.error(`  ✗ ${desc}`); }
}

// Unique suffix keeps fixtures isolated across runs and from dev data.
const tag = 'idor-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);

// userOps.create auto-provisions an org from the email domain — use distinct
// domains so userA and userB land in different orgs.
const userA = userOps.create(`alice-${tag}@org-a-${tag}.test`, 'Alice');
const userB = userOps.create(`bob-${tag}@org-b-${tag}.test`, 'Bob');

t('userA and userB are in distinct orgs',
  userA.org_id && userB.org_id && userA.org_id !== userB.org_id);

const orgA = userA.org_id;
const orgB = userB.org_id;

// Doc created in each org, owner = that org's user.
const docA = docOps.create(userA.id, `Doc-A-${tag}`, 'a.pdf', 'hashA', '', 'sequential', orgA);
const docB = docOps.create(userB.id, `Doc-B-${tag}`, 'b.pdf', 'hashB', '', 'sequential', orgB);

console.log('\n── findByUUIDForCaller: org scope ──');
t('orgA caller resolves orgA doc',
  !!docOps.findByUUIDForCaller(docA.uuid, { orgId: orgA, userId: userA.id }));
t('orgA caller CANNOT resolve orgB doc (cross-org block)',
  !docOps.findByUUIDForCaller(docB.uuid, { orgId: orgA, userId: userA.id }));
t('orgB caller resolves orgB doc',
  !!docOps.findByUUIDForCaller(docB.uuid, { orgId: orgB, userId: userB.id }));
t('orgB caller CANNOT resolve orgA doc (cross-org block)',
  !docOps.findByUUIDForCaller(docA.uuid, { orgId: orgB, userId: userB.id }));

console.log('\n── findByUUIDForCaller: legacy (no-org) scope ──');
t('legacy userA caller resolves own doc',
  !!docOps.findByUUIDForCaller(docA.uuid, { orgId: null, userId: userA.id }));
t('legacy userA caller CANNOT resolve userB doc',
  !docOps.findByUUIDForCaller(docB.uuid, { orgId: null, userId: userA.id }));

console.log('\n── findByIdForCaller: org scope ──');
const docARow = db.prepare('SELECT id FROM documents WHERE uuid = ?').get(docA.uuid);
const docBRow = db.prepare('SELECT id FROM documents WHERE uuid = ?').get(docB.uuid);
t('orgA caller resolves orgA doc by id',
  !!docOps.findByIdForCaller(docARow.id, { orgId: orgA, userId: userA.id }));
t('orgA caller CANNOT resolve orgB doc by id',
  !docOps.findByIdForCaller(docBRow.id, { orgId: orgA, userId: userA.id }));

console.log('\n── findByIdForCaller: legacy scope ──');
t('legacy userA resolves own doc by id',
  !!docOps.findByIdForCaller(docARow.id, { orgId: null, userId: userA.id }));
t('legacy userA CANNOT resolve userB doc by id',
  !docOps.findByIdForCaller(docBRow.id, { orgId: null, userId: userA.id }));

console.log('\n── Sanity: unscoped helpers still work ──');
t('findByUUID (unscoped) returns doc regardless of caller',
  !!docOps.findByUUID(docA.uuid) && !!docOps.findByUUID(docB.uuid));

// Cleanup: remove fixtures so reruns stay clean.
db.prepare('DELETE FROM documents WHERE id IN (?, ?)').run(docARow.id, docBRow.id);
orgMemberOps.remove(orgA, userA.id);
orgMemberOps.remove(orgB, userB.id);
db.prepare('DELETE FROM users WHERE id IN (?, ?)').run(userA.id, userB.id);
db.prepare('DELETE FROM orgs WHERE id IN (?, ?)').run(orgA, orgB);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
