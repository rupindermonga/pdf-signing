/**
 * One-shot migration: re-encrypt legacy sha256-derived blobs under the new
 * HKDF-derived keys introduced with the Patch 2 security hardening.
 *
 * Context: prior to the hardening, `ID_VERIF_KEY` and `TOTP_KEY` were derived
 * via a plain sha256 of the root secret. The server now derives via HKDF with
 * a purpose-specific `info` label — but decryption falls back to the legacy
 * scheme so existing on-disk blobs and DB rows keep working.
 *
 * This script reads every encrypted artefact, tries the HKDF key first, and
 * if that fails re-encrypts the plaintext under HKDF. Once every deployment
 * has run this, the legacy branches in server.js can be deleted.
 *
 * Usage:
 *   node rekey-legacy-blobs.js              # dry-run, prints counts only
 *   node rekey-legacy-blobs.js --apply      # performs the rewrite
 *
 * Safety:
 *   - Idempotent: blobs already under HKDF are skipped.
 *   - Atomic per-file: writes to `<path>.tmp` then renames.
 *   - Per-row for TOTP: updates users.totp_secret only after successful
 *     HKDF re-encrypt. If any step fails the row is left as-is.
 *
 * Requires the same env vars the server uses (SESSION_SECRET, ID_VERIF_KEY,
 * TOTP_KEY) — run from the deployment shell so derivation matches.
 */
require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { db } = require('./database');

const APPLY = process.argv.includes('--apply');
const idVerifDir = path.join(__dirname, 'data', 'idverif');

// Key derivation must mirror server.js exactly.
function deriveKeys(rootEnv, label) {
  const root = process.env[rootEnv] || process.env.SESSION_SECRET || 'certadocs-dev-NEVER-USE-IN-PROD';
  const hkdf = Buffer.from(crypto.hkdfSync('sha256',
    Buffer.from(root, 'utf8'),
    Buffer.from(`certadocs-${label}-salt-v1`, 'utf8'),
    Buffer.from(`${label}.aes-256-gcm.v1`, 'utf8'),
    32
  ));
  const legacy = crypto.createHash('sha256').update(root).digest();
  return { hkdf, legacy, sameKey: hkdf.equals(legacy) };
}

function tryDecrypt(key, iv, tag, ct) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

function encryptUnder(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}

// ─── ID-verification blobs (raw files under data/idverif/) ───
function rekeyIdVerif() {
  const keys = deriveKeys('ID_VERIF_KEY', 'idverif');
  const stats = { total: 0, already_hkdf: 0, migrated: 0, failed: 0 };

  if (!fs.existsSync(idVerifDir)) {
    console.log(`[idverif] ${idVerifDir} not found — nothing to do`);
    return stats;
  }

  for (const name of fs.readdirSync(idVerifDir)) {
    if (!name.endsWith('.enc')) continue;
    const full = path.join(idVerifDir, name);
    stats.total++;

    const blob = fs.readFileSync(full);
    if (blob.length < 28) { stats.failed++; console.warn(`[idverif] ${name}: too small, skipping`); continue; }
    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(12, 28);
    const ct = blob.subarray(28);

    // HKDF first — if it works, blob is already migrated.
    try {
      tryDecrypt(keys.hkdf, iv, tag, ct);
      stats.already_hkdf++;
      continue;
    } catch (_) { /* fall through */ }

    // Legacy decrypt. If it also fails, the file is corrupt or encrypted under
    // a different root secret — log and skip rather than destroying data.
    let plaintext;
    try {
      plaintext = tryDecrypt(keys.legacy, iv, tag, ct);
    } catch (e) {
      stats.failed++;
      console.warn(`[idverif] ${name}: failed to decrypt under HKDF or legacy — ${e.message}`);
      continue;
    }

    if (keys.sameKey) {
      // Shouldn't happen: HKDF decrypt would have succeeded. Defensive.
      stats.failed++;
      console.warn(`[idverif] ${name}: keys collide, refusing to re-encrypt`);
      continue;
    }

    const rewritten = encryptUnder(keys.hkdf, plaintext);
    if (APPLY) {
      const tmp = full + '.tmp';
      fs.writeFileSync(tmp, rewritten);
      fs.renameSync(tmp, full);
    }
    stats.migrated++;
    console.log(`[idverif] ${name}: ${APPLY ? 'migrated' : 'would migrate'}`);
  }

  return stats;
}

// ─── TOTP secrets (users.totp_secret, base64 of [iv|tag|ct]) ───
function rekeyTotp() {
  const keys = deriveKeys('TOTP_KEY', 'totp');
  const stats = { total: 0, already_hkdf: 0, migrated: 0, failed: 0 };

  const rows = db.prepare('SELECT id, email, totp_secret FROM users WHERE totp_secret IS NOT NULL').all();
  for (const row of rows) {
    stats.total++;
    let blob;
    try { blob = Buffer.from(row.totp_secret, 'base64'); }
    catch { stats.failed++; console.warn(`[totp] user ${row.id} (${row.email}): invalid base64`); continue; }
    if (blob.length < 28) { stats.failed++; continue; }

    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(12, 28);
    const ct = blob.subarray(28);

    try {
      tryDecrypt(keys.hkdf, iv, tag, ct);
      stats.already_hkdf++;
      continue;
    } catch (_) { /* fall through */ }

    let plaintext;
    try {
      plaintext = tryDecrypt(keys.legacy, iv, tag, ct);
    } catch (e) {
      stats.failed++;
      console.warn(`[totp] user ${row.id} (${row.email}): failed to decrypt under HKDF or legacy — ${e.message}`);
      continue;
    }

    if (keys.sameKey) {
      stats.failed++;
      console.warn(`[totp] user ${row.id}: keys collide, refusing to re-encrypt`);
      continue;
    }

    const rewritten = encryptUnder(keys.hkdf, plaintext).toString('base64');
    if (APPLY) {
      db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(rewritten, row.id);
    }
    stats.migrated++;
    console.log(`[totp] user ${row.id} (${row.email}): ${APPLY ? 'migrated' : 'would migrate'}`);
  }

  return stats;
}

console.log(`rekey-legacy-blobs: ${APPLY ? 'APPLY mode (writes enabled)' : 'DRY RUN (pass --apply to commit)'}`);
console.log('');
const idv = rekeyIdVerif();
const totp = rekeyTotp();
console.log('');
console.log('── Summary ──');
console.log(`ID-verif blobs : ${idv.total} total, ${idv.already_hkdf} already HKDF, ${idv.migrated} migrated, ${idv.failed} failed`);
console.log(`TOTP secrets   : ${totp.total} total, ${totp.already_hkdf} already HKDF, ${totp.migrated} migrated, ${totp.failed} failed`);
if (!APPLY && (idv.migrated || totp.migrated)) {
  console.log('');
  console.log('Re-run with --apply to commit the migration.');
}
process.exit((idv.failed + totp.failed) > 0 ? 1 : 0);
