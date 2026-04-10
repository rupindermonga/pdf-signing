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
    status TEXT NOT NULL DEFAULT 'pending',
    token TEXT UNIQUE,
    otp TEXT,
    otp_expires TEXT,
    ip_address TEXT,
    location TEXT,
    browser_info TEXT,
    geo_coords TEXT,
    signature_data TEXT,
    signed_at TEXT,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_documents_uuid ON documents(uuid);
  CREATE INDEX IF NOT EXISTS idx_documents_created_by ON documents(created_by);
  CREATE INDEX IF NOT EXISTS idx_signers_token ON signers(token);
  CREATE INDEX IF NOT EXISTS idx_signers_document_id ON signers(document_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
`);

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
  create(userId, title, originalFilename, originalHash, message) {
    const uuid = generateDocUUID();
    const result = db.prepare('INSERT INTO documents (uuid, title, original_filename, original_hash, status, created_by, message) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(uuid, title, originalFilename, originalHash, 'draft', userId, message || '');
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
  }
};

// ─── Signer operations ───
const signerOps = {
  addToDocument(documentId, name, email, signOrder) {
    const token = generateToken();
    const result = db.prepare('INSERT INTO signers (document_id, name, email, sign_order, token) VALUES (?, ?, ?, ?, ?)')
      .run(documentId, name, email.toLowerCase(), signOrder, token);
    return { id: result.lastInsertRowid, token };
  },
  findByToken(token) {
    return db.prepare(`
      SELECT s.*, d.uuid as doc_uuid, d.title as doc_title, d.original_filename, d.status as doc_status, d.original_hash
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
      ip_address = ?, location = ?, browser_info = ?, geo_coords = ? WHERE id = ? AND status = 'sent'`)
      .run(data.signatureData, data.ip, data.location, data.browserInfo, data.geoCoords, id);
    return result.changes === 1; // false if already signed (race condition caught)
  },
  getNextPending(documentId) {
    return db.prepare("SELECT * FROM signers WHERE document_id = ? AND status = 'pending' ORDER BY sign_order LIMIT 1").get(documentId);
  },
  allSigned(documentId) {
    const pending = db.prepare("SELECT COUNT(*) as cnt FROM signers WHERE document_id = ? AND status != 'signed'").get(documentId);
    return pending.cnt === 0;
  }
};

module.exports = { db, userOps, otpOps, sessionOps, docOps, signerOps, generateToken };
