// Multi-document envelopes: a single "signing ceremony" spanning multiple PDFs.
// Competitors (DocuSign, Adobe Sign) call this a "transaction" or "envelope".
// Each envelope owns N documents. Signers sign once per envelope, getting a unified view.
//
// Data model: `envelopes` table + `envelope_id` FK on documents. Status rolls up from children.
function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS envelopes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uuid TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL,
      message TEXT DEFAULT '',
      created_by INTEGER NOT NULL,
      org_id INTEGER,
      status TEXT NOT NULL DEFAULT 'draft',
      signing_mode TEXT NOT NULL DEFAULT 'sequential',
      created_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT,
      expires_at TEXT,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_envelopes_creator ON envelopes(created_by);
    CREATE INDEX IF NOT EXISTS idx_envelopes_org ON envelopes(org_id);
    CREATE INDEX IF NOT EXISTS idx_envelopes_uuid ON envelopes(uuid);
  `);
}

// Add envelope_id + position to documents. Called from database.js after ensureColumn.
function ensureDocColumns(ensureColumn) {
  ensureColumn('documents', 'envelope_id', 'INTEGER');
  ensureColumn('documents', 'envelope_position', 'INTEGER NOT NULL DEFAULT 0');
}

function buildOps(db, { generateDocUUID }) {
  const genEnvelopeUUID = () => 'ENV-' + require('crypto').randomBytes(16).toString('hex').toUpperCase().match(/.{4}/g).join('-');

  return {
    create({ title, message, createdBy, orgId, signingMode, expiresAt }) {
      const uuid = genEnvelopeUUID();
      const mode = signingMode === 'parallel' ? 'parallel' : 'sequential';
      const result = db.prepare(`INSERT INTO envelopes (uuid, title, message, created_by, org_id, signing_mode, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(uuid, title || 'Untitled envelope', message || '', createdBy, orgId || null, mode, expiresAt || null);
      return { id: result.lastInsertRowid, uuid };
    },
    findByUUID(uuid) { return db.prepare('SELECT * FROM envelopes WHERE uuid = ?').get(uuid); },
    findById(id) { return db.prepare('SELECT * FROM envelopes WHERE id = ?').get(id); },
    listByOrg(orgId) { return db.prepare('SELECT * FROM envelopes WHERE org_id = ? ORDER BY created_at DESC').all(orgId); },
    listByUser(userId) { return db.prepare('SELECT * FROM envelopes WHERE created_by = ? ORDER BY created_at DESC').all(userId); },
    addDocument(envelopeId, docId, position) {
      db.prepare('UPDATE documents SET envelope_id = ?, envelope_position = ? WHERE id = ?').run(envelopeId, position || 0, docId);
    },
    listDocuments(envelopeId) {
      return db.prepare('SELECT * FROM documents WHERE envelope_id = ? ORDER BY envelope_position, id').all(envelopeId);
    },
    setStatus(id, status) {
      const completed = status === 'completed' ? ", completed_at = datetime('now')" : '';
      db.prepare(`UPDATE envelopes SET status = ? ${completed} WHERE id = ?`).run(status, id);
    },
    // Roll-up: envelope is 'completed' iff every child document is 'completed'.
    recomputeStatus(id) {
      const docs = db.prepare('SELECT status FROM documents WHERE envelope_id = ?').all(id);
      if (!docs.length) return 'draft';
      if (docs.every(d => d.status === 'completed')) {
        this.setStatus(id, 'completed');
        return 'completed';
      }
      if (docs.some(d => d.status === 'cancelled' || d.status === 'declined')) {
        this.setStatus(id, 'cancelled');
        return 'cancelled';
      }
      if (docs.some(d => d.status === 'sent')) {
        this.setStatus(id, 'sent');
        return 'sent';
      }
      this.setStatus(id, 'draft');
      return 'draft';
    },
    delete(id, userId) {
      // Soft: detach docs first (so they remain accessible), then remove envelope row
      db.prepare('UPDATE documents SET envelope_id = NULL, envelope_position = 0 WHERE envelope_id = ? AND created_by = ?').run(id, userId);
      const r = db.prepare('DELETE FROM envelopes WHERE id = ? AND created_by = ?').run(id, userId);
      return r.changes > 0;
    },
  };
}

module.exports = { initSchema, ensureDocColumns, buildOps };
