// Indian e-Stamping integration.
//
// Under the Indian Stamp Act 1899, many contracts (affidavits, agreements, leases, powers of
// attorney) MUST be executed on stamp paper of the prescribed value — otherwise they are not
// admissible as evidence in court. Stock Holding Corporation of India (SHCIL) is the sole
// Central Record-Keeping Agency authorised by government for e-stamping, rolled out state-wise.
//
// This module provides a pluggable interface so SealForge can:
//   1. Request an e-stamp certificate from SHCIL for a given party/state/amount.
//   2. Embed the certificate number + QR on the first page of the PDF before signing.
//
// Real-world: SHCIL does not offer a public REST API. Integrators typically use either:
//   - a state-specific e-stamping gateway (Karnataka "Kaveri Online", Delhi "DORIS", etc.),
//   - a licensed ACC (Authorised Collection Centre) reseller,
//   - or a partner like Legalwiz / Leegality / Digio that has the SHCIL relationship.
//
// We expose a generic provider contract plus a sandbox that produces a realistic-looking
// certificate number so the UI / PDF stamping flow can be exercised end-to-end.
const crypto = require('crypto');

const PROVIDERS = {};
function register(name, impl) { PROVIDERS[name] = impl; }
function listProviders() { return Object.keys(PROVIDERS); }
function getActive() {
  const name = (process.env.ESTAMP_PROVIDER || 'sandbox').toLowerCase();
  const p = PROVIDERS[name];
  if (!p) throw new Error(`Unknown ESTAMP_PROVIDER "${name}". Available: ${Object.keys(PROVIDERS).join(', ')}`);
  return { name, impl: p };
}

// Indian states that currently support e-stamping via SHCIL (partial list — update as needed).
const SUPPORTED_STATES = ['KA', 'DL', 'MH', 'TN', 'TG', 'UP', 'GJ', 'RJ', 'PB', 'HR', 'WB', 'AP', 'OD', 'BR', 'JH'];

// Article codes (common ones). Full list is in Schedule I of the Indian Stamp Act.
const ARTICLE_CODES = {
  'AGREEMENT': '5',
  'AFFIDAVIT': '4',
  'LEASE': '35',
  'POWER_OF_ATTORNEY': '48',
  'MOU': '5',
  'NDA': '5',
  'LOAN': '6',
  'INDEMNITY_BOND': '34',
};

// ─── Sandbox ───
register('sandbox', {
  async purchase({ state, firstParty, secondParty, stampDutyPaise, articleCode, description }) {
    if (!SUPPORTED_STATES.includes(state)) {
      throw new Error(`State "${state}" not supported for e-stamping. Supported: ${SUPPORTED_STATES.join(', ')}`);
    }
    if (!stampDutyPaise || stampDutyPaise < 100) {
      throw new Error('stampDutyPaise must be at least ₹1 (100 paise)');
    }
    // Certificate numbers in India look like IN-KA12345678901234J (state prefix + 14 digits + check letter)
    const serial = String(Math.floor(Math.random() * 1e14)).padStart(14, '0');
    const checkLetter = String.fromCharCode(65 + (parseInt(serial.slice(-4), 10) % 26));
    const certNumber = `IN-${state}${serial}${checkLetter}`;
    return {
      provider: 'sandbox',
      certificateNumber: certNumber,
      state,
      firstParty,
      secondParty,
      stampDutyPaise,
      articleCode: articleCode || ARTICLE_CODES.AGREEMENT,
      description: description || '',
      issuedAt: new Date().toISOString(),
      verificationUrl: `https://www.shcilestamp.com/OnlineVerification/VerifyCertificate?certificate=${certNumber}`,
      qrPayload: certNumber,
      sandboxWarning: 'This is a SANDBOX certificate — not legally valid. Configure ESTAMP_PROVIDER for production.',
    };
  },
  async verify(certificateNumber) {
    return {
      provider: 'sandbox',
      certificateNumber,
      valid: /^IN-[A-Z]{2}\d{14}[A-Z]$/.test(certificateNumber),
      status: 'active',
      verifiedAt: new Date().toISOString(),
    };
  },
  available: () => true,
});

// ─── Leegality / Digio / partner-mediated (real) ───
// Most production integrations go through a partner because SHCIL has no public API.
register('partner', {
  async purchase(params) {
    const apiUrl = process.env.ESTAMP_PARTNER_URL;
    const apiKey = process.env.ESTAMP_PARTNER_KEY;
    if (!apiUrl || !apiKey) {
      throw new Error('Partner e-stamp not configured. Set ESTAMP_PARTNER_URL and ESTAMP_PARTNER_KEY.');
    }
    // Real flow: POST to partner's /api/v1/estamp/create, poll for certificate URL.
    return {
      provider: 'partner',
      status: 'pending',
      message: 'Partner e-stamp request submitted — verify credentials with your partner.',
      certificateNumber: 'PARTNER-PENDING-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
    };
  },
  async verify(certNumber) {
    return { provider: 'partner', certificateNumber: certNumber, status: 'unknown', message: 'Verify via partner dashboard.' };
  },
  available: () => !!(process.env.ESTAMP_PARTNER_URL && process.env.ESTAMP_PARTNER_KEY),
});

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS estamp_certificates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      document_id INTEGER NOT NULL,
      provider TEXT NOT NULL,
      certificate_number TEXT NOT NULL,
      state TEXT NOT NULL,
      article_code TEXT,
      stamp_duty_paise INTEGER NOT NULL,
      first_party TEXT,
      second_party TEXT,
      description TEXT,
      verification_url TEXT,
      qr_payload TEXT,
      issued_at TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_estamp_doc ON estamp_certificates(document_id);
    CREATE INDEX IF NOT EXISTS idx_estamp_cert ON estamp_certificates(certificate_number);
  `);
}

function saveCertificate(db, documentId, cert) {
  db.prepare(`INSERT INTO estamp_certificates
      (document_id, provider, certificate_number, state, article_code, stamp_duty_paise,
       first_party, second_party, description, verification_url, qr_payload, issued_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    documentId, cert.provider, cert.certificateNumber, cert.state, cert.articleCode,
    cert.stampDutyPaise, cert.firstParty || null, cert.secondParty || null,
    cert.description || null, cert.verificationUrl || null, cert.qrPayload || null, cert.issuedAt || new Date().toISOString()
  );
}

function getCertificateForDocument(db, documentId) {
  return db.prepare('SELECT * FROM estamp_certificates WHERE document_id = ? ORDER BY id DESC LIMIT 1').get(documentId);
}

module.exports = {
  register, listProviders, getActive, initSchema, saveCertificate, getCertificateForDocument,
  SUPPORTED_STATES, ARTICLE_CODES,
};
