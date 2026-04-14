/**
 * SealForge feature tests — new field types, scheduler, RFC 3161 TSA.
 *
 * Run: node test-features.js
 *   (or with a live TSA: TSA_URL=https://freetsa.org/tsr node test-features.js)
 *
 * Does NOT require the HTTP server to be running — exercises pure helpers
 * and the SQLite-backed scheduler in-process. A fresh test user is created
 * and all inserted rows are cleaned up at the end.
 */
process.env.SCHEDULER_DISABLED = '1'; // prevent the cron from firing during tests

const crypto = require('crypto');
const { cleanFieldList, validateFieldSubmission, ALLOWED_FIELD_TYPES } = require('./fields');
const { userOps, docOps, signerOps, db } = require('./database');
const tsa = require('./tsa');

let passed = 0, failed = 0;
const failures = [];

function t(name, cond, detail) {
  const ok = !!cond;
  const icon = ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
  console.log(`  [${icon}] ${name}${detail ? ' — ' + detail : ''}`);
  if (ok) passed++; else { failed++; failures.push({ name, detail }); }
}
function eq(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

function section(title) {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
}

// ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log('\x1b[1m  SealForge Feature Tests\x1b[0m');
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');

  // ─── [1] Field cleaning & validation ────────────────────────────
  section('[1] FIELD VALIDATION (dropdown / radio / conditional)');

  // cleanFieldList: strips unknown types, forces allowed ones
  {
    const cleaned = cleanFieldList([
      { type: 'script', page: 1, xPct: 0.1, yPct: 0.1, wPct: 0.1, hPct: 0.05 },
      { type: 'dropdown', page: 1, xPct: 0.2, yPct: 0.2, wPct: 0.2, hPct: 0.04, options: ['A', 'B', 'C'] },
    ]);
    t('Unknown field type falls back to "text"', cleaned[0].type === 'text');
    t('Dropdown type preserved', cleaned[1].type === 'dropdown');
    t('Dropdown options preserved', eq(cleaned[1].options, ['A', 'B', 'C']));
  }

  // cleanFieldList: options sanitation and cap
  {
    const evilOptions = ['<script>', 'OK', 'Nice'.repeat(25)]; // last has 100 chars → capped to 60
    const cleaned = cleanFieldList([{ type: 'dropdown', options: evilOptions }]);
    t('Option HTML tags stripped', !cleaned[0].options[0].includes('<'));
    t('Option length capped at 60 chars', cleaned[0].options[2].length <= 60);
    const twentyFive = Array.from({length: 25}, (_, i) => `opt${i}`);
    const capped = cleanFieldList([{ type: 'dropdown', options: twentyFive }]);
    t('Option count capped at 20', capped[0].options.length === 20);
  }

  // cleanFieldList: empty dropdown gets fallback options so the UI doesn't break
  {
    const cleaned = cleanFieldList([{ type: 'dropdown', options: [] }]);
    t('Empty dropdown gets fallback options', Array.isArray(cleaned[0].options) && cleaned[0].options.length >= 2);
  }

  // cleanFieldList: conditional rule is sanitized and preserved
  {
    const cleaned = cleanFieldList([
      { type: 'text', conditional: { fieldId: 'f1', equals: '<x>Yes' } },
    ]);
    t('Conditional fieldId preserved', cleaned[0].conditional?.fieldId === 'f1');
    t('Conditional equals sanitized (tags removed)', cleaned[0].conditional?.equals === 'xYes');
  }

  // cleanFieldList: radio behaves like dropdown
  {
    const cleaned = cleanFieldList([{ type: 'radio', options: ['Yes', 'No'] }]);
    t('Radio type preserved', cleaned[0].type === 'radio');
    t('Radio options preserved', eq(cleaned[0].options, ['Yes', 'No']));
  }

  // cleanFieldList: forceSignerOrder overrides per-field value (bulk mode)
  {
    const cleaned = cleanFieldList([{ type: 'text', signerOrder: 5 }], { forceSignerOrder: 1 });
    t('forceSignerOrder overrides per-field signerOrder', cleaned[0].signerOrder === 1);
  }

  // validateFieldSubmission: required dropdown empty → error
  {
    const fields = cleanFieldList([{ type: 'dropdown', options: ['A','B'], required: true, signerOrder: 1 }]);
    const err = validateFieldSubmission(fields, 1, {});
    t('Empty required dropdown rejected', typeof err === 'string' && err.includes('required'));
  }

  // validateFieldSubmission: dropdown invalid option → error
  {
    const fields = cleanFieldList([{ type: 'dropdown', options: ['A','B'], required: true, signerOrder: 1 }]);
    const err = validateFieldSubmission(fields, 1, { f1: 'C' });
    t('Dropdown rejects value outside option set', typeof err === 'string' && err.includes('invalid selection'));
  }

  // validateFieldSubmission: dropdown valid option → pass
  {
    const fields = cleanFieldList([{ type: 'dropdown', options: ['A','B'], required: true, signerOrder: 1 }]);
    const err = validateFieldSubmission(fields, 1, { f1: 'A' });
    t('Dropdown accepts valid option', err === null);
  }

  // validateFieldSubmission: radio required empty → error
  {
    const fields = cleanFieldList([{ type: 'radio', options: ['Yes','No'], required: true, signerOrder: 1 }]);
    const err = validateFieldSubmission(fields, 1, {});
    t('Empty required radio rejected', typeof err === 'string');
  }

  // validateFieldSubmission: checkbox required unchecked → error
  {
    const fields = cleanFieldList([{ type: 'checkbox', required: true, signerOrder: 1 }]);
    const err = validateFieldSubmission(fields, 1, {});
    t('Unchecked required checkbox rejected', typeof err === 'string');
    const ok = validateFieldSubmission(fields, 1, { f1: true });
    t('Checked required checkbox accepted', ok === null);
  }

  // validateFieldSubmission: conditional REQUIRED — condition matches → enforced
  {
    const fields = cleanFieldList([
      { type: 'dropdown', options: ['Yes','No'], required: true, signerOrder: 1, label: 'AreYouOk' },
      { type: 'text', required: true, signerOrder: 1, label: 'WhyNot',
        conditional: { fieldId: 'f1', equals: 'No' } },
    ]);
    // User picked "No" → f2 ("WhyNot") is now required and empty → expect error
    const err = validateFieldSubmission(fields, 1, { f1: 'No', f2: '' });
    t('Conditional required enforced when condition MATCHES', typeof err === 'string' && err.includes('WhyNot'));
  }

  // validateFieldSubmission: conditional REQUIRED — condition does NOT match → skipped
  {
    const fields = cleanFieldList([
      { type: 'dropdown', options: ['Yes','No'], required: true, signerOrder: 1 },
      { type: 'text', required: true, signerOrder: 1, label: 'WhyNot',
        conditional: { fieldId: 'f1', equals: 'No' } },
    ]);
    // User picked "Yes" → f2 should be skipped because condition doesn't match
    const err = validateFieldSubmission(fields, 1, { f1: 'Yes', f2: '' });
    t('Conditional required SKIPPED when condition does not match', err === null);
  }

  // validateFieldSubmission: signature field is auto-filled (not by fieldValues) → should not error
  {
    const fields = cleanFieldList([{ type: 'signature', required: true, signerOrder: 1 }]);
    const err = validateFieldSubmission(fields, 1, {});
    t('Signature field skipped in required-value check', err === null);
  }

  // Sanity: ALLOWED_FIELD_TYPES exported and includes both new types
  t('dropdown in ALLOWED_FIELD_TYPES', ALLOWED_FIELD_TYPES.includes('dropdown'));
  t('radio in ALLOWED_FIELD_TYPES', ALLOWED_FIELD_TYPES.includes('radio'));

  // ─── [2] Scheduler: expiration + reminders ──────────────────────
  section('[2] SCHEDULER (auto-expire + auto-remind)');

  // Use a unique test user so we don't pollute real data
  const testEmail = `sched-test-${Date.now()}@sealforge.test`;
  const user = userOps.findOrCreate(testEmail, 'Scheduler Tester');
  const createdDocIds = [];

  // Helper: create a pending doc + signer with specific expiration & reminder cadence
  function makePendingDoc({ expiresAt = null, cadenceDays = 0, lastRemindedMinutesAgo = null } = {}) {
    const doc = docOps.create(user.id, 'Test Doc', 'test.pdf', crypto.randomBytes(16).toString('hex'), '', 'sequential');
    createdDocIds.push(doc.id);
    docOps.updateStatus(doc.id, 'pending');
    if (expiresAt || cadenceDays) docOps.setSchedule(doc.id, expiresAt, cadenceDays);
    const s = signerOps.addToDocument(doc.id, 'Alice', 'alice@test.local', 1, 'sign');
    signerOps.updateStatus(s.id, 'sent');
    if (lastRemindedMinutesAgo != null) {
      const t = new Date(Date.now() - lastRemindedMinutesAgo * 60000).toISOString();
      db.prepare('UPDATE signers SET last_reminded_at = ? WHERE id = ?').run(t, s.id);
    }
    return { doc, signerId: s.id };
  }

  // Load server lazily here so SCHEDULER_DISABLED takes effect first
  const { runScheduler } = require('./server');
  t('runScheduler exported from server.js', typeof runScheduler === 'function');

  // ── Expiration sweep ──
  {
    const pastIso = new Date(Date.now() - 60 * 60 * 1000).toISOString(); // 1h ago
    const { doc: expiredDoc } = makePendingDoc({ expiresAt: pastIso });
    const { doc: futureDoc } = makePendingDoc({
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    });

    await runScheduler();

    const expAfter = docOps.findById(expiredDoc.id);
    const futAfter = docOps.findById(futureDoc.id);
    t('Expired doc auto-cancelled by scheduler', expAfter.status === 'cancelled',
      `status=${expAfter.status}`);
    t('Non-expired doc left alone', futAfter.status === 'pending',
      `status=${futAfter.status}`);
  }

  // ── Reminder sweep: due (last reminded > cadence ago) ──
  {
    const { doc, signerId } = makePendingDoc({
      cadenceDays: 1,               // remind every 1 day
      lastRemindedMinutesAgo: 60 * 48, // last reminder was 2 days ago
    });
    const before = signerOps.findById(signerId);

    await runScheduler();

    const after = signerOps.findById(signerId);
    t('Due reminder bumps signer.reminder_count',
      after.reminder_count > before.reminder_count,
      `${before.reminder_count} → ${after.reminder_count}`);
    t('Due reminder updates signer.last_reminded_at',
      after.last_reminded_at !== before.last_reminded_at);
  }

  // ── Reminder sweep: NOT due (last reminded < cadence ago) ──
  {
    const { doc, signerId } = makePendingDoc({
      cadenceDays: 7,                  // remind every 7 days
      lastRemindedMinutesAgo: 60 * 24, // last reminder was only 1 day ago
    });
    const before = signerOps.findById(signerId);

    await runScheduler();

    const after = signerOps.findById(signerId);
    t('Not-yet-due reminder is a no-op',
      after.reminder_count === before.reminder_count,
      `count stayed at ${after.reminder_count}`);
  }

  // ── Reminder sweep: cadence=0 means disabled ──
  {
    const { doc, signerId } = makePendingDoc({
      cadenceDays: 0,
      lastRemindedMinutesAgo: 60 * 24 * 365, // a year ago
    });
    const before = signerOps.findById(signerId);

    await runScheduler();

    const after = signerOps.findById(signerId);
    t('cadenceDays=0 disables reminders',
      after.reminder_count === before.reminder_count);
  }

  // ── listReminderCandidates: excludes completed/cancelled ──
  {
    const { doc: okDoc } = makePendingDoc({ cadenceDays: 1 });
    const { doc: cancelledDoc } = makePendingDoc({ cadenceDays: 1 });
    docOps.cancel(cancelledDoc.id);
    const candidates = docOps.listReminderCandidates();
    const ids = candidates.map(d => d.id);
    t('listReminderCandidates includes pending+cadence doc', ids.includes(okDoc.id));
    t('listReminderCandidates excludes cancelled docs', !ids.includes(cancelledDoc.id));
  }

  // ─── [3] RFC 3161 Timestamp module ──────────────────────────────
  section('[3] RFC 3161 TSA CLIENT');

  t('tsa.isConfigured reflects TSA_URL presence',
    tsa.isConfigured() === !!process.env.TSA_URL);

  // buildTimestampRequest isn't exported but we exercise requestTimestamp() input validation
  {
    let threw = false;
    try {
      // Not a 32-byte buffer — should reject
      await tsa.requestTimestamp(Buffer.from('short'));
    } catch (e) { threw = /32 bytes/.test(e.message); }
    t('requestTimestamp rejects non-sha256 input', threw);
  }

  {
    let threw = false;
    try {
      // Save & clear TSA_URL to force the "not configured" path
      const orig = process.env.TSA_URL;
      delete process.env.TSA_URL;
      // tsa module snapshots TSA_URL at import time, so we need a fresh instance
      delete require.cache[require.resolve('./tsa')];
      const freshTsa = require('./tsa');
      try { await freshTsa.requestTimestamp(crypto.createHash('sha256').update('x').digest()); }
      catch (e) { threw = /not configured/.test(e.message); }
      // Restore for any subsequent tests
      if (orig) process.env.TSA_URL = orig;
      delete require.cache[require.resolve('./tsa')];
    } catch { /* pass-through */ }
    t('requestTimestamp errors cleanly when TSA_URL unset', threw);
  }

  // Optional live test — only when TSA_URL is set (and network reachable).
  if (process.env.TSA_URL) {
    try {
      const liveTsa = require('./tsa');
      const hash = crypto.createHash('sha256').update('sealforge-test-' + Date.now()).digest();
      const result = await liveTsa.requestTimestamp(hash);
      t('Live TSA returns a timestamp token',
        Buffer.isBuffer(result.token) && result.token.length > 100,
        `${result.token.length} bytes`);
      t('Live TSA token has genTime',
        result.genTime instanceof Date && !isNaN(result.genTime.valueOf()),
        String(result.genTime));
    } catch (e) {
      t(`Live TSA request (TSA_URL=${process.env.TSA_URL})`, false, `network error: ${e.message}`);
    }
  } else {
    console.log('  \x1b[33m(skip)\x1b[0m Set TSA_URL to run the live TSA round-trip test');
  }

  // ─── Cleanup ─────────────────────────────────────────────────────
  for (const id of createdDocIds) {
    try { docOps.delete(id); } catch {}
  }
  try { db.prepare('DELETE FROM users WHERE email = ?').run(testEmail); } catch {}

  // ─── Summary ─────────────────────────────────────────────────────
  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log(`\x1b[1m  RESULTS: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m\x1b[1m\x1b[0m`);
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');

  if (failures.length) {
    console.log('\n\x1b[1mFAILURES:\x1b[0m');
    failures.forEach((f, i) => console.log(`  ${i + 1}. \x1b[31m${f.name}\x1b[0m${f.detail ? ' — ' + f.detail : ''}`));
  }
  console.log('');
  // Ensure the process exits (keep-alive timers/DB handles)
  process.exit(failed ? 1 : 0);
}

main().catch(e => {
  console.error('\n\x1b[31mTest runner crashed:\x1b[0m', e);
  process.exit(2);
});
