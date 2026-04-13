const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'docseal.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─── Schema ───
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS otp_codes (
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL DEFAULT 'Untitled',
    original_filename TEXT NOT NULL,
    original_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    created_by INTEGER NOT NULL,
    message TEXT DEFAULT '',
    signing_mode TEXT NOT NULL DEFAULT 'sequential',
    fields_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS signers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    sign_order INTEGER NOT NULL DEFAULT 1,
    role TEXT NOT NULL DEFAULT 'sign',
    status TEXT NOT NULL DEFAULT 'pending',
    token TEXT UNIQUE,
    otp TEXT,
    otp_expires TEXT,
    ip_address TEXT,
    location TEXT,
    browser_info TEXT,
    geo_coords TEXT,
    signature_data TEXT,
    field_values_json TEXT NOT NULL DEFAULT '{}',
    signed_at TEXT,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    title TEXT DEFAULT '',
    message TEXT DEFAULT '',
    signing_mode TEXT NOT NULL DEFAULT 'sequential',
    signers_json TEXT NOT NULL DEFAULT '[]',
    has_pdf INTEGER NOT NULL DEFAULT 0,
    pdf_hash TEXT,
    pdf_filename TEXT,
    fields_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'rw',
    last_used_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events_json TEXT NOT NULL DEFAULT '["*"]',
    active INTEGER NOT NULL DEFAULT 1,
    last_status TEXT,
    last_fired_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_apikeys_hash ON api_keys(key_hash);
  CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id);
  CREATE INDEX IF NOT EXISTS idx_templates_user ON templates(user_id);
  CREATE INDEX IF NOT EXISTS idx_documents_uuid ON documents(uuid);
  CREATE INDEX IF NOT EXISTS idx_documents_created_by ON documents(created_by);
  CREATE INDEX IF NOT EXISTS idx_signers_token ON signers(token);
  CREATE INDEX IF NOT EXISTS idx_signers_document_id ON signers(document_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
`);

// ─── Migrations: additive columns for existing installs ───
function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.find(c => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}
ensureColumn('documents', 'signing_mode', "TEXT NOT NULL DEFAULT 'sequential'");
ensureColumn('documents', 'fields_json', "TEXT NOT NULL DEFAULT '[]'");
ensureColumn('documents', 'bulk_group_id', "TEXT");
ensureColumn('signers', 'role', "TEXT NOT NULL DEFAULT 'sign'");
ensureColumn('signers', 'field_values_json', "TEXT NOT NULL DEFAULT '{}'");
ensureColumn('signers', 'payment_amount_cents', "INTEGER NOT NULL DEFAULT 0");
ensureColumn('signers', 'payment_currency', "TEXT NOT NULL DEFAULT 'CAD'");
ensureColumn('signers', 'payment_status', "TEXT NOT NULL DEFAULT 'none'");
ensureColumn('signers', 'payment_session_id', "TEXT");
ensureColumn('signers', 'payment_paid_at', "TEXT");
ensureColumn('documents', 'payment_amount_cents', "INTEGER NOT NULL DEFAULT 0");
ensureColumn('documents', 'payment_currency', "TEXT NOT NULL DEFAULT 'CAD'");
ensureColumn('documents', 'payment_description', "TEXT");
ensureColumn('documents', 'id_verification_required', "INTEGER NOT NULL DEFAULT 0");
ensureColumn('signers', 'id_verification_required', "INTEGER NOT NULL DEFAULT 0");
ensureColumn('signers', 'id_verification_status', "TEXT NOT NULL DEFAULT 'none'");
ensureColumn('signers', 'id_document_path', "TEXT");
ensureColumn('signers', 'id_selfie_path', "TEXT");
ensureColumn('signers', 'id_verified_at', "TEXT");
ensureColumn('signers', 'phone', "TEXT");
ensureColumn('signers', 'notify_method', "TEXT NOT NULL DEFAULT 'email'");

// ─── Helper functions ───
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateOTP() {
  return String(crypto.randomInt(100000, 999999));
}

function generateDocUUID() {
  return 'DS-' + crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{4}/g).join('-');
}

function generateTemplateUUID() {
  return 'TPL-' + crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{4}/g).join('-');
}

// ─── User operations ───
const userOps = {
  findByEmail(email) {
    return db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  },
  create(email, name) {
    const result = db.prepare('INSERT INTO users (email, name) VALUES (?, ?)').run(email.toLowerCase(), name);
    return { id: result.lastInsertRowid, email: email.toLowerCase(), name };
  },
  findOrCreate(email, name = '') {
    let user = this.findByEmail(email);
    if (!user) user = this.create(email, name);
    return user;
  },
  updateName(id, name) {
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, id);
  }
};

// ─── OTP operations ───
const otpOps = {
  create(email) {
    const code = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min
    db.prepare('DELETE FROM otp_codes WHERE email = ?').run(email.toLowerCase());
    db.prepare('INSERT INTO otp_codes (email, code, expires_at) VALUES (?, ?, ?)').run(email.toLowerCase(), code, expires);
    return code;
  },
  verify(email, code) {
    const row = db.prepare("SELECT * FROM otp_codes WHERE email = ? AND used = 0 AND expires_at > datetime('now')").get(email.toLowerCase());
    if (!row) return false;
    // Timing-safe comparison to prevent side-channel attacks
    const codeBuffer = Buffer.from(String(code).padEnd(6, '0'));
    const storedBuffer = Buffer.from(String(row.code).padEnd(6, '0'));
    if (codeBuffer.length !== storedBuffer.length || !crypto.timingSafeEqual(codeBuffer, storedBuffer)) return false;
    db.prepare('UPDATE otp_codes SET used = 1 WHERE email = ? AND code = ?').run(email.toLowerCase(), row.code);
    return true;
  }
};

// ─── Session operations ───
const sessionOps = {
  create(userId) {
    const token = generateToken();
    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 days
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expires);
    return token;
  },
  validate(token) {
    const row = db.prepare("SELECT s.*, u.email, u.name FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > datetime('now')").get(token);
    return row || null;
  },
  destroy(token) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  },
  cleanExpired() {
    db.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run();
  }
};

// ─── Document operations ───
const docOps = {
  create(userId, title, originalFilename, originalHash, message, signingMode = 'sequential') {
    const uuid = generateDocUUID();
    const mode = signingMode === 'parallel' ? 'parallel' : 'sequential';
    const result = db.prepare('INSERT INTO documents (uuid, title, original_filename, original_hash, status, created_by, message, signing_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(uuid, title, originalFilename, originalHash, 'draft', userId, message || '', mode);
    return { id: result.lastInsertRowid, uuid };
  },
  findByUUID(uuid) {
    return db.prepare('SELECT * FROM documents WHERE uuid = ?').get(uuid);
  },
  findById(id) {
    return db.prepare('SELECT * FROM documents WHERE id = ?').get(id);
  },
  listByUser(userId) {
    return db.prepare('SELECT * FROM documents WHERE created_by = ? ORDER BY created_at DESC').all(userId);
  },
  updateStatus(id, status) {
    if (status === 'completed') {
      db.prepare("UPDATE documents SET status = ?, completed_at = datetime('now') WHERE id = ?").run(status, id);
    } else {
      db.prepare('UPDATE documents SET status = ? WHERE id = ?').run(status, id);
    }
  },
  delete(id) {
    db.prepare('DELETE FROM documents WHERE id = ?').run(id);
  },
  cancel(id) {
    db.prepare("UPDATE documents SET status = 'cancelled' WHERE id = ?").run(id);
  },
  setFields(id, fields) {
    db.prepare('UPDATE documents SET fields_json = ? WHERE id = ?').run(JSON.stringify(fields || []), id);
  },
  setBulkGroup(id, groupId) {
    db.prepare('UPDATE documents SET bulk_group_id = ? WHERE id = ?').run(groupId, id);
  },
  listByBulkGroup(userId, groupId) {
    return db.prepare('SELECT * FROM documents WHERE created_by = ? AND bulk_group_id = ? ORDER BY created_at').all(userId, groupId);
  },
  getFields(id) {
    const row = db.prepare('SELECT fields_json FROM documents WHERE id = ?').get(id);
    if (!row) return [];
    try { return JSON.parse(row.fields_json || '[]'); } catch { return []; }
  }
};

// ─── Signer operations ───
const signerOps = {
  addToDocument(documentId, name, email, signOrder, role = 'sign', phone = null, notifyMethod = 'email') {
    const token = generateToken();
    const safeRole = ['sign', 'cc', 'approve'].includes(role) ? role : 'sign';
    const safeMethod = ['email', 'sms', 'both'].includes(notifyMethod) ? notifyMethod : 'email';
    const cleanPhone = phone ? String(phone).replace(/[^\d+]/g, '').slice(0, 20) : null;
    const result = db.prepare('INSERT INTO signers (document_id, name, email, sign_order, role, token, phone, notify_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(documentId, name, email.toLowerCase(), signOrder, safeRole, token, cleanPhone, safeMethod);
    return { id: result.lastInsertRowid, token };
  },
  rotateToken(id) {
    const token = generateToken();
    db.prepare('UPDATE signers SET token = ? WHERE id = ?').run(token, id);
    return token;
  },
  setPayment(id, amountCents, currency) {
    db.prepare('UPDATE signers SET payment_amount_cents = ?, payment_currency = ?, payment_status = ? WHERE id = ?')
      .run(amountCents || 0, currency || 'CAD', amountCents > 0 ? 'pending' : 'none', id);
  },
  setPaymentSession(id, sessionId) {
    db.prepare('UPDATE signers SET payment_session_id = ? WHERE id = ?').run(sessionId, id);
  },
  markPaid(id) {
    db.prepare("UPDATE signers SET payment_status = 'paid', payment_paid_at = datetime('now') WHERE id = ?").run(id);
  },
  setIdRequired(id, required) {
    db.prepare('UPDATE signers SET id_verification_required = ?, id_verification_status = ? WHERE id = ?')
      .run(required ? 1 : 0, required ? 'pending' : 'none', id);
  },
  setIdFiles(id, docPath, selfiePath) {
    db.prepare("UPDATE signers SET id_document_path = ?, id_selfie_path = ?, id_verification_status = 'verified', id_verified_at = datetime('now') WHERE id = ?")
      .run(docPath, selfiePath, id);
  },
  findById(id) {
    return db.prepare(`
      SELECT s.*, d.uuid as doc_uuid, d.title as doc_title, d.original_filename, d.status as doc_status, d.original_hash, d.signing_mode
      FROM signers s JOIN documents d ON s.document_id = d.id WHERE s.id = ?
    `).get(id);
  },
  findByToken(token) {
    return db.prepare(`
      SELECT s.*, d.uuid as doc_uuid, d.title as doc_title, d.original_filename, d.status as doc_status, d.original_hash, d.signing_mode
      FROM signers s JOIN documents d ON s.document_id = d.id
      WHERE s.token = ?
    `).get(token);
  },
  listByDocument(documentId) {
    return db.prepare('SELECT * FROM signers WHERE document_id = ? ORDER BY sign_order').all(documentId);
  },
  updateStatus(id, status) {
    db.prepare('UPDATE signers SET status = ? WHERE id = ?').run(status, id);
  },
  setOTP(id) {
    const otp = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    db.prepare('UPDATE signers SET otp = ?, otp_expires = ? WHERE id = ?').run(otp, expires, id);
    return otp;
  },
  verifyOTP(id, code) {
    const signer = db.prepare("SELECT * FROM signers WHERE id = ? AND otp IS NOT NULL AND otp_expires > datetime('now')").get(id);
    if (!signer) return false;
    const codeBuffer = Buffer.from(String(code).padEnd(6, '0'));
    const storedBuffer = Buffer.from(String(signer.otp).padEnd(6, '0'));
    if (codeBuffer.length !== storedBuffer.length || !crypto.timingSafeEqual(codeBuffer, storedBuffer)) return false;
    db.prepare('UPDATE signers SET otp = NULL, otp_expires = NULL WHERE id = ?').run(id);
    return true;
  },
  markSigned(id, data) {
    // Atomic: only update if status is still 'sent' — prevents race condition double-sign
    const result = db.prepare(`UPDATE signers SET status = 'signed', signature_data = ?, signed_at = datetime('now'),
      ip_address = ?, location = ?, browser_info = ?, geo_coords = ?, field_values_json = ?
      WHERE id = ? AND status = 'sent'`)
      .run(data.signatureData, data.ip, data.location, data.browserInfo, data.geoCoords,
        JSON.stringify(data.fieldValues || {}), id);
    return result.changes === 1;
  },
  getNextPending(documentId) {
    // CC recipients are notified at completion only — skip them in the signing queue
    return db.prepare("SELECT * FROM signers WHERE document_id = ? AND status = 'pending' AND role != 'cc' ORDER BY sign_order LIMIT 1").get(documentId);
  },
  getAllPending(documentId) {
    return db.prepare("SELECT * FROM signers WHERE document_id = ? AND status = 'pending' AND role != 'cc' ORDER BY sign_order").all(documentId);
  },
  allSigned(documentId) {
    // Document is "complete" when all signing/approving signers are signed (CCs don't count)
    const pending = db.prepare("SELECT COUNT(*) as cnt FROM signers WHERE document_id = ? AND status != 'signed' AND role != 'cc'").get(documentId);
    return pending.cnt === 0;
  }
};

// ─── Template operations ───
const templateOps = {
  create(userId, { name, title, message, signingMode, signers, hasPdf, pdfHash, pdfFilename, fields }) {
    const uuid = generateTemplateUUID();
    const mode = signingMode === 'parallel' ? 'parallel' : 'sequential';
    const result = db.prepare(`INSERT INTO templates
      (uuid, user_id, name, title, message, signing_mode, signers_json, has_pdf, pdf_hash, pdf_filename, fields_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(uuid, userId, name, title || '', message || '', mode,
        JSON.stringify(signers || []), hasPdf ? 1 : 0,
        pdfHash || null, pdfFilename || null, JSON.stringify(fields || []));
    return { id: result.lastInsertRowid, uuid };
  },
  listByUser(userId) {
    return db.prepare('SELECT * FROM templates WHERE user_id = ? ORDER BY created_at DESC').all(userId);
  },
  findByUUID(uuid, userId) {
    const row = db.prepare('SELECT * FROM templates WHERE uuid = ? AND user_id = ?').get(uuid, userId);
    if (!row) return null;
    row.signers = JSON.parse(row.signers_json || '[]');
    row.fields = JSON.parse(row.fields_json || '[]');
    return row;
  },
  delete(uuid, userId) {
    return db.prepare('DELETE FROM templates WHERE uuid = ? AND user_id = ?').run(uuid, userId).changes > 0;
  }
};

// ─── API key operations ───
const apiKeyOps = {
  // Returns plaintext key ONCE (only available at creation time).
  create(userId, name, scope = 'rw') {
    const safeScope = ['ro', 'rw'].includes(scope) ? scope : 'rw';
    const raw = crypto.randomBytes(24).toString('hex');
    const plaintext = `ds_live_${raw}`;
    const prefix = plaintext.slice(0, 12);
    const hash = crypto.createHash('sha256').update(plaintext).digest('hex');
    const result = db.prepare('INSERT INTO api_keys (user_id, name, prefix, key_hash, scope) VALUES (?, ?, ?, ?, ?)')
      .run(userId, name, prefix, hash, safeScope);
    return { id: result.lastInsertRowid, plaintext, prefix, scope: safeScope };
  },
  findByPlaintext(plaintext) {
    if (!plaintext || !plaintext.startsWith('ds_live_')) return null;
    const hash = crypto.createHash('sha256').update(plaintext).digest('hex');
    const row = db.prepare(`
      SELECT k.*, u.email, u.name as user_name FROM api_keys k
      JOIN users u ON k.user_id = u.id WHERE k.key_hash = ?
    `).get(hash);
    if (row) {
      db.prepare("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?").run(row.id);
    }
    return row;
  },
  listByUser(userId) {
    return db.prepare('SELECT id, name, prefix, scope, last_used_at, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').all(userId);
  },
  revoke(id, userId) {
    return db.prepare('DELETE FROM api_keys WHERE id = ? AND user_id = ?').run(id, userId).changes > 0;
  }
};

// ─── Webhook operations ───
const webhookOps = {
  create(userId, url, events) {
    const secret = 'whsec_' + crypto.randomBytes(24).toString('hex');
    const evs = Array.isArray(events) && events.length ? events : ['*'];
    const result = db.prepare('INSERT INTO webhooks (user_id, url, secret, events_json) VALUES (?, ?, ?, ?)')
      .run(userId, url, secret, JSON.stringify(evs));
    return { id: result.lastInsertRowid, secret };
  },
  listByUser(userId) {
    return db.prepare('SELECT * FROM webhooks WHERE user_id = ? ORDER BY created_at DESC').all(userId);
  },
  listForEvent(userId, event) {
    const rows = db.prepare('SELECT * FROM webhooks WHERE user_id = ? AND active = 1').all(userId);
    return rows.filter(w => {
      try {
        const evs = JSON.parse(w.events_json);
        return evs.includes('*') || evs.includes(event);
      } catch { return false; }
    });
  },
  toggle(id, userId, active) {
    return db.prepare('UPDATE webhooks SET active = ? WHERE id = ? AND user_id = ?').run(active ? 1 : 0, id, userId).changes > 0;
  },
  delete(id, userId) {
    return db.prepare('DELETE FROM webhooks WHERE id = ? AND user_id = ?').run(id, userId).changes > 0;
  },
  recordFire(id, status) {
    db.prepare("UPDATE webhooks SET last_status = ?, last_fired_at = datetime('now') WHERE id = ?").run(status, id);
  }
};

module.exports = { db, userOps, otpOps, sessionOps, docOps, signerOps, templateOps, apiKeyOps, webhookOps, generateToken };
