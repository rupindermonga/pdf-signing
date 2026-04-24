// Regulatory-compliance helpers: consent capture, data-subject requests (PIPEDA, Quebec Law 25,
// DPDP Act 2023, GDPR). Keep logic separate from signing so auditors can review it on its own.
const crypto = require('crypto');

// Build the consent_events table and the user-deletion queue on first load.
function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS consent_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject_type TEXT NOT NULL,           -- 'user' | 'signer'
      subject_id INTEGER,                   -- user.id or signer.id (nullable for anonymous signers by email only)
      subject_email TEXT NOT NULL,
      consent_kind TEXT NOT NULL,           -- 'esign' | 'privacy' | 'dpdp' | 'pipeda' | 'marketing'
      consent_version TEXT NOT NULL,        -- the policy version the user saw
      granted INTEGER NOT NULL,             -- 1 = granted, 0 = withdrawn/declined
      ip_address TEXT,
      user_agent TEXT,
      lang TEXT,
      proof_hash TEXT,                      -- sha256 of displayed text + timestamp for tamper-evidence
      document_id INTEGER,                  -- optional, when consent happened during a signing
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_consent_email ON consent_events(subject_email, consent_kind);
    CREATE INDEX IF NOT EXISTS idx_consent_doc ON consent_events(document_id);

    CREATE TABLE IF NOT EXISTS dsr_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject_email TEXT NOT NULL,
      request_type TEXT NOT NULL,           -- 'export' | 'delete' | 'correct' | 'withdraw'
      verification_token TEXT UNIQUE NOT NULL,
      verified_at TEXT,
      status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'verified' | 'fulfilled' | 'rejected'
      note TEXT,
      jurisdiction TEXT,                    -- 'CA' | 'QC' | 'IN' | 'EU' | 'US' | 'AU'
      requested_at TEXT DEFAULT (datetime('now')),
      fulfilled_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_dsr_email ON dsr_requests(subject_email);
    CREATE INDEX IF NOT EXISTS idx_dsr_token ON dsr_requests(verification_token);
  `);
}

// Current policy version — bump when the consent wording changes so prior grants can be re-shown.
const CONSENT_VERSION = '2026-04-24';

function recordConsent(db, opts) {
  const { subjectType, subjectId, subjectEmail, consentKind, granted, ip, userAgent, lang, documentId, displayedText } = opts;
  if (!subjectEmail || !consentKind) throw new Error('recordConsent requires subjectEmail and consentKind');
  const proofHash = crypto.createHash('sha256')
    .update(`${consentKind}|${CONSENT_VERSION}|${subjectEmail}|${Date.now()}|${displayedText || ''}`)
    .digest('hex');
  const result = db.prepare(`INSERT INTO consent_events
      (subject_type, subject_id, subject_email, consent_kind, consent_version, granted, ip_address, user_agent, lang, proof_hash, document_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(subjectType || 'signer', subjectId || null, subjectEmail.toLowerCase(), consentKind, CONSENT_VERSION,
         granted ? 1 : 0, ip || null, userAgent || null, lang || 'en', proofHash, documentId || null);
  return { id: result.lastInsertRowid, proofHash, version: CONSENT_VERSION };
}

function getConsents(db, subjectEmail) {
  return db.prepare(`SELECT * FROM consent_events WHERE subject_email = ? ORDER BY created_at DESC`)
    .all(String(subjectEmail).toLowerCase());
}

function hasValidConsent(db, subjectEmail, consentKind) {
  const row = db.prepare(`SELECT * FROM consent_events
      WHERE subject_email = ? AND consent_kind = ? AND granted = 1
      ORDER BY created_at DESC LIMIT 1`)
    .get(String(subjectEmail).toLowerCase(), consentKind);
  if (!row) return false;
  // Check if a later 'withdraw' of same kind occurred
  const withdraw = db.prepare(`SELECT 1 FROM consent_events
      WHERE subject_email = ? AND consent_kind = ? AND granted = 0 AND created_at > ?
      LIMIT 1`).get(String(subjectEmail).toLowerCase(), consentKind, row.created_at);
  return !withdraw;
}

function createDSR(db, opts) {
  const { subjectEmail, requestType, jurisdiction, note } = opts;
  if (!subjectEmail || !requestType) throw new Error('createDSR requires subjectEmail and requestType');
  const allowed = ['export', 'delete', 'correct', 'withdraw'];
  if (!allowed.includes(requestType)) throw new Error('Invalid request_type');
  const verificationToken = crypto.randomBytes(24).toString('hex');
  const result = db.prepare(`INSERT INTO dsr_requests
      (subject_email, request_type, verification_token, jurisdiction, note)
      VALUES (?, ?, ?, ?, ?)`)
    .run(String(subjectEmail).toLowerCase(), requestType, verificationToken, jurisdiction || null, note || null);
  return { id: result.lastInsertRowid, verificationToken };
}

function verifyDSR(db, token) {
  const row = db.prepare(`SELECT * FROM dsr_requests WHERE verification_token = ?`).get(token);
  if (!row) return null;
  if (!row.verified_at) {
    db.prepare(`UPDATE dsr_requests SET verified_at = datetime('now'), status = 'verified' WHERE id = ?`).run(row.id);
    row.verified_at = new Date().toISOString();
    row.status = 'verified';
  }
  return row;
}

// Export: return everything we have keyed by this email — documents owned or signed,
// signer rows, consents, audit events that reference them.
function exportData(db, subjectEmail) {
  const email = String(subjectEmail).toLowerCase();
  const user = db.prepare('SELECT id, email, name, role, created_at, last_login_at FROM users WHERE email = ?').get(email);
  const ownedDocs = user ? db.prepare('SELECT uuid, title, status, created_at, completed_at FROM documents WHERE created_by = ?').all(user.id) : [];
  const signerRows = db.prepare(`SELECT s.id, s.name, s.email, s.role, s.status, s.ip_address, s.location,
      s.signed_at, s.reminder_count, d.uuid as document_uuid, d.title as document_title
      FROM signers s LEFT JOIN documents d ON s.document_id = d.id
      WHERE lower(s.email) = ? ORDER BY s.id DESC`).all(email);
  const consents = getConsents(db, email);
  const dsr = db.prepare('SELECT id, request_type, status, requested_at, fulfilled_at, jurisdiction FROM dsr_requests WHERE subject_email = ?').all(email);
  return {
    generated_at: new Date().toISOString(),
    subject: email,
    user,
    owned_documents: ownedDocs,
    signer_records: signerRows,
    consents,
    dsr_history: dsr,
  };
}

// Delete: pseudonymise signer rows (keep audit trail intact — required for legal record-keeping)
// and purge user row + sessions + API keys + webhooks. Returns a summary count.
function deleteData(db, subjectEmail) {
  const email = String(subjectEmail).toLowerCase();
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  const counts = { sessions: 0, api_keys: 0, webhooks: 0, signers_pseudonymised: 0, otp_codes: 0, consents: 0, user: 0 };
  const run = (sql, ...args) => db.prepare(sql).run(...args).changes;
  if (user) {
    counts.sessions = run('DELETE FROM sessions WHERE user_id = ?', user.id);
    counts.api_keys = run('DELETE FROM api_keys WHERE user_id = ?', user.id);
    counts.webhooks = run('DELETE FROM webhooks WHERE user_id = ?', user.id);
    counts.user = run('DELETE FROM users WHERE id = ?', user.id);
  }
  counts.otp_codes = run('DELETE FROM otp_codes WHERE email = ?', email);
  // Pseudonymise signer records: keep the signed artefacts & timestamps (audit integrity)
  // but replace PII with a one-way hash of the original email.
  const pseudo = 'deleted+' + crypto.createHash('sha256').update(email).digest('hex').slice(0, 12) + '@redacted.local';
  counts.signers_pseudonymised = run(
    "UPDATE signers SET email = ?, name = 'Deleted Subject', phone = NULL, ip_address = NULL, location = NULL, browser_info = NULL, geo_coords = NULL, id_document_path = NULL, id_selfie_path = NULL WHERE lower(email) = ?",
    pseudo, email
  );
  counts.consents = run('UPDATE consent_events SET subject_email = ?, ip_address = NULL, user_agent = NULL WHERE subject_email = ?', pseudo, email);
  db.prepare(`UPDATE dsr_requests SET status = 'fulfilled', fulfilled_at = datetime('now') WHERE subject_email = ? AND request_type = 'delete'`).run(email);
  return counts;
}

module.exports = { initSchema, recordConsent, getConsents, hasValidConsent, createDSR, verifyDSR, exportData, deleteData, CONSENT_VERSION };
