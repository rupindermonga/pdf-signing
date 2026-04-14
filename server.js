require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const QRCode = require('qrcode');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { SignPdf } = require('@signpdf/signpdf');
const { P12Signer } = require('@signpdf/signer-p12');
const { pdflibAddPlaceholder } = require('@signpdf/placeholder-pdf-lib');
const { PDFDocument } = require('pdf-lib');

const { userOps, otpOps, sessionOps, docOps, signerOps, templateOps, apiKeyOps, webhookOps, eventLogOps, workflowOps, VALID_ROLES } = require('./database');
const email = require('./email');
const { TOTP, Secret } = require('otpauth');
const stripe = require('./stripe');
const sms = require('./sms');
const tsa = require('./tsa');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Trust the N closest proxies in front of us (default: 0 = no proxy; Render = 1).
// Set TRUST_PROXY=1 (or higher) in deployments behind a reverse proxy so that
// req.ip reflects the real client IP and Express sets `secure` on req correctly.
// When 0/unset, Express treats X-Forwarded-For as untrusted and uses socket IP.
const TRUST_PROXY = parseInt(process.env.TRUST_PROXY || '0', 10);
if (TRUST_PROXY > 0) app.set('trust proxy', TRUST_PROXY);

// Unified client-IP helper — honours trust-proxy setting, strips IPv4-mapped
// IPv6 prefix, and normalizes loopback for audit-log readability.
function clientIp(req) {
  // When trust proxy is set, req.ip is the real client; otherwise it's the socket peer.
  const raw = (req.ip || req.socket.remoteAddress || '').toString();
  return raw.replace('::ffff:', '').replace(/^::1$/, '127.0.0.1');
}

// DEV mode must be explicitly enabled — defaults to production-safe behavior
const IS_DEV = process.env.NODE_ENV === 'development';
// OTPs are returned in API responses only in LOCAL dev mode (never on a
// remote BASE_URL). Even if NODE_ENV is accidentally set to "development" on
// a public host, this guard prevents the OTP from leaving the server.
const IS_LOCAL = !process.env.BASE_URL || /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(process.env.BASE_URL);
const ALLOW_DEV_OTP = IS_DEV && IS_LOCAL;
if (IS_DEV && !IS_LOCAL) {
  console.warn('\x1b[33m[sealforge] NODE_ENV=development on a non-local BASE_URL — OTPs will NOT be returned in responses. Set NODE_ENV=production to remove this warning.\x1b[0m');
}
if (!IS_DEV && process.env.NODE_ENV !== 'production') {
  console.warn('\x1b[33m[sealforge] NODE_ENV is not set to "production" — session cookies will be issued without the Secure flag. Set NODE_ENV=production in your deployment.\x1b[0m');
}

// ─── Security headers (nonce-based CSP) ───
app.use((req, res, next) => {
  // Generate per-request nonce for inline scripts/styles
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' https://cdnjs.cloudflare.com https://fonts.googleapis.com blob:`,
    "worker-src blob:",
    `style-src 'self' 'nonce-${nonce}' https://fonts.googleapis.com`,
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "connect-src 'self' https://nominatim.openstreetmap.org https://api.ipify.org https://api.stripe.com data:",
    "frame-src https://checkout.stripe.com",
    "frame-ancestors 'none'",
    "form-action 'self' https://checkout.stripe.com",
    "base-uri 'self'",
    "object-src 'none'",
  ].join('; '));
  next();
});

// ─── Nonce-injecting HTML sender ───
// Replaces res.sendFile for HTML pages — injects nonce into <script> and <style> tags.
function sendHtml(res, filePath) {
  let html = fs.readFileSync(filePath, 'utf-8');
  const nonce = res.locals.cspNonce;
  // Inject nonce into all inline <script> and <style> tags
  html = html.replace(/<script(?=[\s>])/gi, `<script nonce="${nonce}"`);
  html = html.replace(/<style(?=[\s>])/gi, `<style nonce="${nonce}"`);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
}

// ─── Middleware ───
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'sealforge-dev',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  }
}));

// ─── Rate limiting (in-memory, keyed by socket IP — not spoofable) ───
const rateLimits = new Map();
function rateLimit(windowMs, maxReqs) {
  return (req, res, next) => {
    // clientIp() honours TRUST_PROXY: behind a trusted proxy it's the real client IP,
    // otherwise it falls back to the socket peer (so X-Forwarded-For can't be spoofed).
    const ip = clientIp(req);
    const key = ip + ':' + req.path;
    const now = Date.now();
    const entry = rateLimits.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + windowMs; }
    entry.count++;
    rateLimits.set(key, entry);
    if (entry.count > maxReqs) {
      return res.status(429).json({ error: 'Too many requests. Please wait and try again.' });
    }
    next();
  };
}
// Cleanup expired rate limit entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimits) {
    if (now > entry.resetAt) rateLimits.delete(key);
  }
}, 5 * 60 * 1000);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Storage dirs
const storageDir = path.join(__dirname, 'data', 'files');
if (!fs.existsSync(storageDir)) fs.mkdirSync(storageDir, { recursive: true });
const templatesDir = path.join(__dirname, 'data', 'templates');
if (!fs.existsSync(templatesDir)) fs.mkdirSync(templatesDir, { recursive: true });
const idVerifDir = path.join(__dirname, 'data', 'idverif');
if (!fs.existsSync(idVerifDir)) fs.mkdirSync(idVerifDir, { recursive: true });

// ─── ID-verification at-rest encryption (AES-256-GCM) ───
// Key derived from ID_VERIF_KEY env; if unset, derive from SESSION_SECRET (dev fallback).
// Rotating the key invalidates prior files by design — store them off-server if you need portability.
const idVerifKey = crypto.createHash('sha256')
  .update(process.env.ID_VERIF_KEY || process.env.SESSION_SECRET || 'sealforge-dev-idverif')
  .digest();

function encryptIdBlob(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', idVerifKey, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  // On-disk format: [12 byte IV][16 byte auth tag][ciphertext]
  return Buffer.concat([iv, tag, enc]);
}

function decryptIdBlob(blob) {
  if (!blob || blob.length < 28) throw new Error('encrypted blob too small');
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', idVerifKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// P12 Certificate
const certPath = path.join(__dirname, 'cert', 'sealforge.p12');
let p12Buffer = null;
if (fs.existsSync(certPath)) {
  p12Buffer = fs.readFileSync(certPath);
  console.log('P12 certificate loaded');
}

// Multer for PDF uploads
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') return cb(null, true);
    cb(new Error('Only PDF files are allowed'), false);
  },
  limits: { fileSize: 50 * 1024 * 1024 }
});

// Init email
email.init();

// ─── Scheduler: reminders + expiration sweep ───
// Runs hourly by default. Disable by setting SCHEDULER_DISABLED=1 (useful for tests).
function minutesBetween(aISO, nowMs) {
  if (!aISO) return Infinity;
  const t = Date.parse(aISO);
  return isNaN(t) ? Infinity : (nowMs - t) / 60000;
}
async function runScheduler() {
  const now = Date.now();
  // 1) Expire any pending docs past their expires_at.
  try {
    const expired = docOps.listExpired();
    for (const doc of expired) {
      docOps.cancel(doc.id);
      try {
        const owner = require('./database').db.prepare('SELECT email, name FROM users WHERE id = ?').get(doc.created_by);
        if (owner && email.isConfigured()) {
          await email.sendExpiredNotice(owner.email, owner.name || owner.email, doc.title, doc.uuid);
        }
        fireWebhooks(doc.created_by, 'document.expired', {
          document: { uuid: doc.uuid, title: doc.title, expires_at: doc.expires_at },
        });
      } catch (e) { console.warn(`[scheduler] expire-notify failed for ${doc.uuid}:`, e.message); }
      console.log(`[scheduler] auto-cancelled expired doc ${doc.uuid}`);
    }
  } catch (e) { console.error('[scheduler] expiration sweep error:', e.message); }

  // 2) Send reminders for pending signers whose cadence is due.
  try {
    const candidates = docOps.listReminderCandidates();
    for (const doc of candidates) {
      const cadenceDays = doc.reminder_every_days || 0;
      if (cadenceDays <= 0) continue;
      const cadenceMinutes = cadenceDays * 1440;
      const creator = require('./database').db.prepare('SELECT email, name FROM users WHERE id = ?').get(doc.created_by);
      const senderName = creator?.name || creator?.email || 'SealForge';
      // Only remind currently-awaiting signers (sequential: the one holding the ball;
      // parallel: all signers that have been dispatched but haven't signed yet).
      const awaiting = signerOps.getAwaiting(doc.id, doc.signing_mode);
      for (const s of awaiting) {
        const lastMs = s.last_reminded_at
          ? minutesBetween(s.last_reminded_at, now)
          : minutesBetween(s.signed_at || doc.created_at, now);
        if (lastMs < cadenceMinutes) continue;
        try {
          const signUrl = `${BASE_URL}/sign/${s.token}`;
          if (email.isConfigured()) {
            await email.sendReminder(s.email, s.name, senderName, doc.title, signUrl, doc.expires_at);
          }
          if (sms.isConfigured() && (s.notify_method === 'sms' || s.notify_method === 'both') && s.phone) {
            try { await sms.sendSigningLinkSMS(s.phone, s.name, senderName, doc.title, signUrl); } catch {}
          }
          signerOps.markReminded(s.id);
          docOps.markReminded(doc.id);
          console.log(`[scheduler] reminder sent to ${s.email} for ${doc.uuid}`);
        } catch (e) { console.warn(`[scheduler] reminder failed for signer ${s.id}:`, e.message); }
      }
    }
  } catch (e) { console.error('[scheduler] reminder sweep error:', e.message); }

  // 3) Purge old event log entries (Zapier polling, >30 days old)
  try { eventLogOps.purgeOld(30); } catch {}
}

if (process.env.SCHEDULER_DISABLED !== '1') {
  try {
    const cron = require('node-cron');
    // Hourly at :07 to avoid top-of-hour collisions.
    cron.schedule(process.env.SCHEDULER_CRON || '7 * * * *', () => {
      runScheduler().catch(e => console.error('[scheduler] tick error:', e.message));
    });
    // Also run 30s after startup so a freshly-deployed server catches backlog.
    setTimeout(() => runScheduler().catch(() => {}), 30_000);
    console.log('[scheduler] cron scheduled (hourly @ :07)');
  } catch (e) {
    console.warn('[scheduler] node-cron unavailable, falling back to setInterval:', e.message);
    setInterval(() => runScheduler().catch(() => {}), 60 * 60 * 1000);
  }
}
// Manual trigger for tests/ops (authenticated owner only — no-op if nothing to do).
app.post('/api/admin/run-scheduler', requireAuth, rateLimit(60000, 3), async (req, res) => {
  await runScheduler();
  res.json({ ok: true });
});

// Exported for unit tests — see test-features.js.
module.exports = { app, runScheduler };

// ─── Sanitize input (strip HTML tags) ───
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '');
}

// ─── Email format validation ───
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function isValidEmail(s) {
  return typeof s === 'string' && s.length <= 254 && EMAIL_RE.test(s);
}

// Field validation / normalisation helpers live in ./fields.js so they can be
// unit-tested without booting the HTTP server.
const { cleanFieldList, validateFieldSubmission } = require('./fields');

// ─── Auth middleware ───
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (req.headers.accept?.includes('json')) return res.status(401).json({ error: 'Not authenticated' });
  res.redirect('/login');
}

function requireRole(...roles) {
  return (req, res, next) => {
    const userRole = req.session.userRole || (req.apiUser && userOps.findById(req.apiUser.id)?.role) || 'viewer';
    if (roles.includes(userRole)) return next();
    res.status(403).json({ error: 'Insufficient permissions' });
  };
}

// ─── TOTP helpers ───
const totpEncKey = crypto.createHash('sha256')
  .update(process.env.TOTP_KEY || process.env.SESSION_SECRET || 'sealforge-dev-totp')
  .digest();

function encryptTotpSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', totpEncKey, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

function decryptTotpSecret(encoded) {
  const blob = Buffer.from(encoded, 'base64');
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', totpEncKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

// API-key auth: requires Bearer token in Authorization header. Sets req.apiUser.
function requireApiKey(scope = 'rw') {
  return (req, res, next) => {
    const auth = req.headers.authorization || '';
    const m = auth.match(/^Bearer\s+(\S+)$/i);
    if (!m) return res.status(401).json({ error: 'Missing Authorization: Bearer <api_key>' });
    const key = apiKeyOps.findByPlaintext(m[1]);
    if (!key) return res.status(401).json({ error: 'Invalid API key' });
    if (scope === 'rw' && key.scope === 'ro') return res.status(403).json({ error: 'API key is read-only' });
    req.apiUser = { id: key.user_id, email: key.email, name: key.user_name };
    req.apiKey = { id: key.id, scope: key.scope };
    next();
  };
}

// ─── SSRF protection: block private / link-local / loopback IPs (v4 + v6) ───
function isBlockedIP(ip) {
  if (!ip) return true;
  const s = String(ip).toLowerCase();
  // IPv4
  if (/^127\./.test(s)) return true;                                          // loopback
  if (/^10\./.test(s)) return true;                                           // RFC1918
  if (/^192\.168\./.test(s)) return true;                                     // RFC1918
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(s)) return true;                  // RFC1918
  if (/^169\.254\./.test(s)) return true;                                     // link-local (AWS IMDS etc.)
  if (/^0\./.test(s)) return true;                                            // 0.0.0.0/8
  if (/^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./.test(s)) return true;  // CGNAT 100.64/10
  // IPv6
  if (s === '::1' || s === '::') return true;
  if (s.startsWith('fe80:') || s.startsWith('fe90:') || s.startsWith('fea0:') || s.startsWith('feb0:')) return true; // link-local
  if (/^f[cd][0-9a-f]{2}:/.test(s)) return true;                              // unique-local fc00::/7
  if (s.startsWith('::ffff:')) {                                              // IPv4-mapped
    return isBlockedIP(s.slice(7));
  }
  return false;
}

async function resolveAndCheckUrl(urlStr) {
  const url = new URL(urlStr);
  // Webhooks MUST use HTTPS — plain HTTP would leak payloads and HMAC secrets on path.
  if (url.protocol !== 'https:') return { ok: false, reason: 'https_required' };
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host === 'metadata.google.internal') return { ok: false, reason: 'blocked_host' };
  // If the host is already a literal IP, check it directly
  if (/^[\d.]+$/.test(host) || host.includes(':')) {
    return { ok: !isBlockedIP(host), reason: isBlockedIP(host) ? 'blocked_private_ip' : null, url };
  }
  // Resolve via DNS (prevents hostname-smuggling and partial DNS rebinding)
  return new Promise((resolve) => {
    require('dns').lookup(host, { all: true }, (err, addrs) => {
      if (err) return resolve({ ok: false, reason: 'dns_error', url });
      for (const a of addrs) {
        if (isBlockedIP(a.address)) return resolve({ ok: false, reason: 'blocked_private_ip', url });
      }
      resolve({ ok: true, url });
    });
  });
}

// ─── Webhook fire (async, fire-and-forget) ───
async function fireWebhooks(userId, event, payload) {
  // Record event for polling (Zapier/Make)
  try { eventLogOps.record(userId, event, payload); } catch {}
  const hooks = webhookOps.listForEvent(userId, event);
  for (const w of hooks) {
    const ts = Math.floor(Date.now() / 1000);
    const body = JSON.stringify({ event, created_at: new Date().toISOString(), data: payload });
    // Signed payload includes timestamp to mitigate replay (consumers verify ±300s)
    const signedPayload = `${ts}.${body}`;
    const sig = crypto.createHmac('sha256', w.secret).update(signedPayload).digest('hex');
    try {
      const check = await resolveAndCheckUrl(w.url);
      if (!check.ok) {
        webhookOps.recordFire(w.id, check.reason || 'blocked');
        continue;
      }
      const url = check.url;
      // resolveAndCheckUrl has already enforced https://
      const protocol = require('https');
      const opts = {
        method: 'POST',
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'User-Agent': 'SealForge-Webhook/1.0',
          'X-SealForge-Event': event,
          // Stripe-style signature: t=<unix timestamp>, v1=<hmac of `${t}.${body}`>
          // Consumers: reject if |now - t| > 300s, then recompute HMAC and compare.
          'X-SealForge-Signature': `t=${ts}, v1=${sig}`,
        },
        timeout: 8000,
      };
      const req2 = protocol.request(opts, (resp) => {
        webhookOps.recordFire(w.id, String(resp.statusCode));
      });
      req2.on('error', (e) => webhookOps.recordFire(w.id, 'error:' + (e.code || 'unknown')));
      req2.on('timeout', () => { req2.destroy(); webhookOps.recordFire(w.id, 'timeout'); });
      req2.write(body);
      req2.end();
    } catch (e) {
      webhookOps.recordFire(w.id, 'error:' + e.message.slice(0, 30));
    }
  }
}

// ─── Auth Routes ───
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  sendHtml(res, path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/auth/send-otp', rateLimit(60000, 5), async (req, res) => {
  const { email: userEmail } = req.body;
  if (!userEmail) return res.status(400).json({ error: 'Email required' });

  const otp = otpOps.create(userEmail);

  const sent = await email.sendLoginOTP(userEmail, otp);
  if (!sent && ALLOW_DEV_OTP) {
    return res.json({ ok: true, devOtp: otp, message: 'Email not configured (dev mode). Use this code.' });
  }
  if (!sent) {
    return res.status(500).json({ error: 'Email delivery failed. Configure SMTP in .env.' });
  }
  res.json({ ok: true, message: 'Verification code sent to your email.' });
});

app.post('/api/auth/verify-otp', rateLimit(60000, 10), (req, res) => {
  const { email: userEmail, code, name } = req.body;
  if (!userEmail || !code) return res.status(400).json({ error: 'Email and code required' });

  if (!otpOps.verify(userEmail, code)) {
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  const cleanName = sanitize(name || '');
  const user = userOps.findOrCreate(userEmail, cleanName);
  if (cleanName && !user.name) userOps.updateName(user.id, cleanName);

  // If user has TOTP enabled, don't complete login yet
  if (user.totp_enabled) {
    req.session.pendingMfaUserId = user.id;
    return res.json({ ok: true, requireTotp: true });
  }

  // Regenerate session to prevent session fixation
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.userId = user.id;
    req.session.userEmail = user.email;
    req.session.userName = user.name || cleanName;
    req.session.userRole = user.role || 'member';
    res.json({ ok: true, redirect: '/dashboard' });
  });
});

// ─── TOTP verification (second factor) ───
app.post('/api/auth/verify-totp', rateLimit(60000, 10), (req, res) => {
  const { code } = req.body;
  const pendingId = req.session.pendingMfaUserId;
  if (!pendingId) return res.status(400).json({ error: 'No pending MFA session' });
  if (!code) return res.status(400).json({ error: 'Code required' });

  const user = userOps.findById(pendingId);
  if (!user || !user.totp_secret) return res.status(400).json({ error: 'TOTP not configured' });

  const secret = decryptTotpSecret(user.totp_secret);
  const totp = new TOTP({ issuer: 'SealForge', label: user.email, secret: Secret.fromBase32(secret) });
  const delta = totp.validate({ token: String(code), window: 1 });
  if (delta === null) return res.status(400).json({ error: 'Invalid authenticator code' });

  delete req.session.pendingMfaUserId;
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.userId = user.id;
    req.session.userEmail = user.email;
    req.session.userName = user.name;
    req.session.userRole = user.role || 'member';
    res.json({ ok: true, redirect: '/dashboard' });
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// ─── Current user info ───
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ id: req.session.userId, email: req.session.userEmail, name: req.session.userName, role: req.session.userRole || 'member' });
});

// ─── TOTP setup routes ───
app.post('/api/settings/totp/setup', requireAuth, (req, res) => {
  const secret = new Secret();
  const totp = new TOTP({ issuer: 'SealForge', label: req.session.userEmail, secret });
  const encrypted = encryptTotpSecret(secret.base32);
  userOps.setTotpSecret(req.session.userId, encrypted);
  const uri = totp.toString();
  res.json({ ok: true, uri, secret: secret.base32 });
});

app.post('/api/settings/totp/confirm', requireAuth, rateLimit(60000, 10), (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code required' });
  const user = userOps.findById(req.session.userId);
  if (!user || !user.totp_secret) return res.status(400).json({ error: 'Run setup first' });

  const secret = decryptTotpSecret(user.totp_secret);
  const totp = new TOTP({ issuer: 'SealForge', label: user.email, secret: Secret.fromBase32(secret) });
  const delta = totp.validate({ token: String(code), window: 1 });
  if (delta === null) return res.status(400).json({ error: 'Invalid code. Make sure your authenticator is set up correctly.' });

  userOps.enableTotp(req.session.userId);
  res.json({ ok: true });
});

app.post('/api/settings/totp/disable', requireAuth, rateLimit(60000, 5), (req, res) => {
  const { code } = req.body;
  const user = userOps.findById(req.session.userId);
  if (!user || !user.totp_enabled) return res.status(400).json({ error: 'TOTP not enabled' });

  const secret = decryptTotpSecret(user.totp_secret);
  const totp = new TOTP({ issuer: 'SealForge', label: user.email, secret: Secret.fromBase32(secret) });
  const delta = totp.validate({ token: String(code), window: 1 });
  if (delta === null) return res.status(400).json({ error: 'Invalid authenticator code' });

  userOps.disableTotp(req.session.userId);
  res.json({ ok: true });
});

app.get('/api/settings/totp/status', requireAuth, (req, res) => {
  const user = userOps.findById(req.session.userId);
  res.json({ enabled: !!(user && user.totp_enabled) });
});

// ─── Admin: user management ───
app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/admin/users', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ users: userOps.listAll() });
});

app.put('/api/admin/users/:id/role', requireAuth, requireRole('admin'), (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const { role } = req.body;
  if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role. Must be: admin, member, or viewer' });
  // Prevent removing last admin
  if (targetId === req.session.userId && role !== 'admin') {
    if (userOps.countAdmins() <= 1) return res.status(400).json({ error: 'Cannot remove the last admin' });
  }
  userOps.setRole(targetId, role);
  // Update own session if changing own role
  if (targetId === req.session.userId) req.session.userRole = role;
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
  userOps.deleteUser(targetId);
  res.json({ ok: true });
});

// Admin can disable another user's TOTP (recovery)
app.post('/api/admin/users/:id/disable-totp', requireAuth, requireRole('admin'), (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  userOps.disableTotp(targetId);
  res.json({ ok: true });
});

// ─── Dashboard ───
app.get('/dashboard', requireAuth, (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/api/documents', requireAuth, (req, res) => {
  const docs = docOps.listByUser(req.session.userId);
  const enriched = docs.map(doc => {
    const signers = signerOps.listByDocument(doc.id);
    const signed = signers.filter(s => s.status === 'signed').length;
    return { ...doc, signers, signedCount: signed, totalSigners: signers.length };
  });
  res.json({ documents: enriched, user: { email: req.session.userEmail, name: req.session.userName, role: req.session.userRole || 'member' } });
});

// ─── Create Signing Request ───
app.get('/send', requireAuth, requireRole('admin', 'member'), (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'send.html'));
});

app.post('/api/documents/create', requireAuth, requireRole('admin', 'member'), (req, res, next) => {
  upload.single('pdf')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    next();
  });
}, async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'PDF required' });

    // Verify PDF magic bytes (%PDF) - catches forged MIME types
    if (!req.file.buffer || req.file.buffer.length < 5 || req.file.buffer.toString('utf-8', 0, 5) !== '%PDF-') {
      return res.status(400).json({ error: 'Invalid PDF file' });
    }

    const { title, message, signers, signingMode, fields, paymentAmount, paymentCurrency, paymentDescription, requireIdVerification, expiresAt, reminderEveryDays } = req.body;
    const idRequired = requireIdVerification === 'true' || requireIdVerification === true || requireIdVerification === '1';
    const parsedSigners = JSON.parse(signers || '[]');
    const parsedFields = JSON.parse(fields || '[]');
    const amtCents = Math.max(0, Math.round(parseFloat(paymentAmount || '0') * 100) || 0);
    const cur = (paymentCurrency || 'CAD').toUpperCase();
    if (!parsedSigners.length) return res.status(400).json({ error: 'At least one signer required' });

    // Sanitize all user inputs
    const cleanTitle = sanitize(title) || sanitize(req.file.originalname);
    const cleanMessage = sanitize(message);
    const allowedRoles = ['sign', 'cc', 'approve'];
    const allowedMethods = ['email', 'sms', 'both'];
    const cleanSigners = parsedSigners.map(s => ({
      name: sanitize(s.name),
      email: sanitize(s.email).toLowerCase(),
      role: allowedRoles.includes(s.role) ? s.role : 'sign',
      phone: sanitize(s.phone || '').replace(/[^\d+]/g, '').slice(0, 20),
      notifyMethod: allowedMethods.includes(s.notifyMethod) ? s.notifyMethod : 'email',
    }));

    // Validate: every signer needs a name and a well-formed email
    const bad = cleanSigners.find(s => !s.name || !isValidEmail(s.email));
    if (bad) return res.status(400).json({ error: `Invalid signer entry (name and valid email required): ${bad.email || '(missing email)'}` });

    // Must have at least one non-CC signer
    if (!cleanSigners.some(s => s.role !== 'cc')) {
      return res.status(400).json({ error: 'At least one signer must have role Sign or Approve (CC-only is not allowed).' });
    }

    const cleanMode = signingMode === 'parallel' ? 'parallel' : 'sequential';

    // Sanitize original filename
    const cleanFilename = sanitize(req.file.originalname).replace(/[^\w.\-() ]/g, '_');

    // Hash original PDF
    const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

    // Create document record
    const doc = docOps.create(req.session.userId, cleanTitle, cleanFilename, hash, cleanMessage, cleanMode);

    // Save PDF file
    fs.writeFileSync(path.join(storageDir, `${doc.uuid}.pdf`), req.file.buffer);

    // Persist document-level payment defaults
    if (amtCents > 0) {
      require('./database').db.prepare('UPDATE documents SET payment_amount_cents = ?, payment_currency = ?, payment_description = ? WHERE id = ?')
        .run(amtCents, cur, sanitize(paymentDescription || cleanTitle), doc.id);
    }

    // Persist document-level ID requirement
    if (idRequired) {
      require('./database').db.prepare('UPDATE documents SET id_verification_required = 1 WHERE id = ?').run(doc.id);
    }

    // Persist expiration + reminder cadence. expiresAt expected as 'YYYY-MM-DD' or ISO.
    // Parse to ISO UTC end-of-day so a date like '2026-04-20' doesn't expire at midnight local.
    let expIso = null;
    if (expiresAt && typeof expiresAt === 'string') {
      const m = expiresAt.match(/^(\d{4})-(\d{2})-(\d{2})$/);
      if (m) {
        expIso = new Date(Date.UTC(+m[1], +m[2]-1, +m[3], 23, 59, 59)).toISOString();
      } else {
        const t = Date.parse(expiresAt);
        if (!isNaN(t) && t > Date.now()) expIso = new Date(t).toISOString();
      }
    }
    const cadenceDays = Math.max(0, Math.min(30, parseInt(reminderEveryDays, 10) || 0));
    if (expIso || cadenceDays) {
      docOps.setSchedule(doc.id, expIso, cadenceDays);
    }

    // Add signers
    for (let i = 0; i < cleanSigners.length; i++) {
      const s = cleanSigners[i];
      const created = signerOps.addToDocument(doc.id, s.name, s.email, i + 1, s.role, s.phone, s.notifyMethod);
      // Each signing-required signer pays their share
      if (amtCents > 0 && s.role !== 'cc') {
        signerOps.setPayment(created.id, amtCents, cur);
      }
      if (idRequired && s.role !== 'cc') {
        signerOps.setIdRequired(created.id, true);
      }
    }

    // Validate + persist fields (sender-defined)
    const cleanFields = cleanFieldList(parsedFields);
    docOps.setFields(doc.id, cleanFields);

    // Workflow mode: store workflow steps if provided
    let workflowDef = null;
    try { workflowDef = JSON.parse(req.body.workflow || 'null'); } catch {}
    if (Array.isArray(workflowDef) && workflowDef.length) {
      require('./database').db.prepare('UPDATE documents SET workflow_json = ? WHERE id = ?').run(JSON.stringify(workflowDef), doc.id);
      // Create workflow step records
      const signers = signerOps.listByDocument(doc.id);
      const wfSteps = workflowDef.map((step, i) => ({
        step_order: i + 1,
        signer_id: step.signerId ? signers.find(s => s.sign_order === step.signerId)?.id : null,
        action: step.action || 'sign',
        condition_field: step.conditionField || null,
        condition_operator: step.conditionOperator || null,
        condition_value: step.conditionValue || null,
        on_true_step: step.onTrueStep || null,
        on_false_step: step.onFalseStep || null,
      }));
      workflowOps.create(doc.id, wfSteps);
    }

    // Set status to pending and dispatch
    docOps.updateStatus(doc.id, 'pending');
    if (workflowDef) {
      await advanceWorkflow(doc.id);
    } else if (cleanMode === 'parallel') {
      await sendToAllParallel(doc.id);
    } else {
      await sendToNextSigner(doc.id);
    }

    fireWebhooks(req.session.userId, 'document.sent', {
      document: { uuid: doc.uuid, title: cleanTitle, signing_mode: cleanMode },
      signers: cleanSigners,
    });

    res.json({ ok: true, uuid: doc.uuid });
  } catch (err) {
    console.error('Create document error:', err);
    console.error('Document create error:', err);
    res.status(500).json({ error: 'Failed to create document. Please try again.' });
  }
});

// ─── Bulk send ───
app.get('/bulk', requireAuth, requireRole('admin', 'member'), (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'bulk.html'));
});

app.post('/api/documents/bulk-create', requireAuth, requireRole('admin', 'member'), (req, res, next) => {
  upload.single('pdf')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    next();
  });
}, async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'PDF required' });
    if (!req.file.buffer || req.file.buffer.length < 5 || req.file.buffer.toString('utf-8', 0, 5) !== '%PDF-') {
      return res.status(400).json({ error: 'Invalid PDF file' });
    }

    const { title, message, recipients, fields, fieldMapping: fieldMappingStr } = req.body;
    const parsedRecipients = JSON.parse(recipients || '[]');
    const parsedFields = JSON.parse(fields || '[]');
    let fieldMapping = {};
    try { fieldMapping = JSON.parse(fieldMappingStr || '{}'); } catch {}
    if (!parsedRecipients.length) return res.status(400).json({ error: 'At least one recipient required' });
    if (parsedRecipients.length > 500) return res.status(400).json({ error: 'Bulk size limited to 500 recipients per batch' });

    const cleanRecipients = parsedRecipients
      .map(r => {
        const base = { name: sanitize(r.name || ''), email: sanitize(r.email || '').toLowerCase() };
        // Carry over extra CSV columns for field mapping
        for (const key of Object.keys(r)) {
          if (key !== 'name' && key !== 'email') base[key] = sanitize(String(r[key] || ''));
        }
        return base;
      })
      .filter(r => r.name && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(r.email));
    if (!cleanRecipients.length) return res.status(400).json({ error: 'No valid recipients (need name + valid email each)' });

    const cleanFilename = sanitize(req.file.originalname).replace(/[^\w.\-() ]/g, '_');
    const cleanTitle = sanitize(title) || cleanFilename;
    const cleanMessage = sanitize(message);
    const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

    const cleanFields = cleanFieldList(parsedFields, { forceSignerOrder: 1 }); // bulk is always single-signer per copy

    const groupId = 'BULK-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const created = [];

    for (const r of cleanRecipients) {
      const doc = docOps.create(req.session.userId, cleanTitle, cleanFilename, hash, cleanMessage, 'sequential');
      docOps.setBulkGroup(doc.id, groupId);
      // Each recipient gets their own copy of the PDF (saves bytes via hardlink? no, simpler to copy)
      fs.writeFileSync(path.join(storageDir, `${doc.uuid}.pdf`), req.file.buffer);
      const signer = signerOps.addToDocument(doc.id, r.name, r.email, 1, 'sign');
      docOps.setFields(doc.id, cleanFields);
      // Apply field mapping: pre-fill signer field values from CSV columns
      if (Object.keys(fieldMapping).length && cleanFields.length) {
        const prefilled = {};
        for (const [csvCol, fieldId] of Object.entries(fieldMapping)) {
          if (r[csvCol] !== undefined) prefilled[fieldId] = r[csvCol];
        }
        if (Object.keys(prefilled).length) {
          require('./database').db.prepare('UPDATE signers SET field_values_json = ? WHERE id = ?').run(JSON.stringify(prefilled), signer.id);
        }
      }
      docOps.updateStatus(doc.id, 'pending');
      await sendToNextSigner(doc.id);
      created.push({ uuid: doc.uuid, recipient: r.email });
    }

    fireWebhooks(req.session.userId, 'document.sent', {
      bulk_group_id: groupId, count: created.length,
      document: { title: cleanTitle, signing_mode: 'sequential' },
    });

    res.json({ ok: true, bulk_group_id: groupId, count: created.length, documents: created });
  } catch (err) {
    console.error('Bulk send error:', err);
    res.status(500).json({ error: 'Bulk send failed' });
  }
});

// ─── Notify a signer via configured channels ───
async function notifySigner(signer, doc, senderName) {
  const signUrl = `${BASE_URL}/sign/${signer.token}`;
  const method = signer.notify_method || 'email';
  if (method === 'email' || method === 'both') {
    await email.sendSigningRequest(signer.email, signer.name, senderName, doc.title, signUrl, doc.message);
  }
  if ((method === 'sms' || method === 'both') && signer.phone && sms.isConfigured()) {
    await sms.sendSigningLinkSMS(signer.phone, signer.name, senderName, doc.title, signUrl);
  }
  return signUrl;
}

// ─── Send to next pending signer (sequential mode) ───
async function sendToNextSigner(documentId) {
  const next = signerOps.getNextPending(documentId);
  if (!next) return;
  const doc = docOps.findById(documentId);
  const creatorUser = require('./database').db.prepare('SELECT * FROM users WHERE id = ?').get(doc.created_by);
  const senderName = creatorUser?.name || creatorUser?.email || 'Someone';
  signerOps.updateStatus(next.id, 'sent');
  const signUrl = await notifySigner(next, doc, senderName);
  return { signUrl, signer: next };
}

// ─── Send to ALL pending signers (parallel mode) ───
async function sendToAllParallel(documentId) {
  const all = signerOps.getAllPending(documentId);
  if (!all.length) return;
  const doc = docOps.findById(documentId);
  const creatorUser = require('./database').db.prepare('SELECT * FROM users WHERE id = ?').get(doc.created_by);
  const senderName = creatorUser?.name || creatorUser?.email || 'Someone';
  for (const s of all) {
    signerOps.updateStatus(s.id, 'sent');
    await notifySigner(s, doc, senderName);
  }
}

// ─── Workflow Engine ───
// Advances a workflow-mode document to its next step based on conditions.
async function advanceWorkflow(documentId) {
  const doc = docOps.findById(documentId);
  if (!doc || !doc.workflow_json) return sendToNextSigner(documentId); // fallback to sequential

  let workflow;
  try { workflow = JSON.parse(doc.workflow_json); } catch { return sendToNextSigner(documentId); }
  if (!Array.isArray(workflow) || !workflow.length) return sendToNextSigner(documentId);

  // Find the current step (first with status pending)
  const steps = workflowOps.listByDocument(documentId);
  const currentStep = steps.find(s => s.status === 'pending');
  if (!currentStep) return; // all steps done

  const signers = signerOps.listByDocument(documentId);

  if (currentStep.action === 'condition') {
    // Evaluate the condition based on submitted field values
    const allFields = docOps.getFields(documentId);
    let conditionMet = false;

    // Gather all submitted field values from all signed signers
    const allValues = {};
    for (const s of signers.filter(s => s.status === 'signed')) {
      try { Object.assign(allValues, JSON.parse(s.field_values_json || '{}')); } catch {}
    }

    const fieldVal = String(allValues[currentStep.condition_field] || '').toLowerCase();
    const condVal = String(currentStep.condition_value || '').toLowerCase();

    switch (currentStep.condition_operator) {
      case 'equals': conditionMet = fieldVal === condVal; break;
      case 'not_equals': conditionMet = fieldVal !== condVal; break;
      case 'contains': conditionMet = fieldVal.includes(condVal); break;
      case 'gt': conditionMet = parseFloat(fieldVal) > parseFloat(condVal); break;
      case 'lt': conditionMet = parseFloat(fieldVal) < parseFloat(condVal); break;
      default: conditionMet = fieldVal === condVal;
    }

    workflowOps.updateStepStatus(currentStep.id, conditionMet ? 'true' : 'false');

    // Jump to the target step
    const targetOrder = conditionMet ? currentStep.on_true_step : currentStep.on_false_step;
    if (targetOrder) {
      // Skip steps between current and target
      for (const s of steps) {
        if (s.step_order > currentStep.step_order && s.step_order < targetOrder && s.status === 'pending') {
          workflowOps.updateStepStatus(s.id, 'skipped');
          // Also skip the associated signer
          if (s.signer_id) signerOps.updateStatus(s.signer_id, 'signed'); // mark as skipped
        }
      }
    }
    // Recurse to process the next step
    return advanceWorkflow(documentId);
  }

  // It's a signing step — dispatch the signer
  if (currentStep.signer_id) {
    const signer = signers.find(s => s.id === currentStep.signer_id);
    if (signer && signer.status === 'signed') {
      // Already signed, move to next step
      workflowOps.updateStepStatus(currentStep.id, 'completed');
      return advanceWorkflow(documentId);
    }
    if (signer && signer.status === 'pending') {
      workflowOps.updateStepStatus(currentStep.id, 'active');
      const doc2 = docOps.findById(documentId);
      const creator = require('./database').db.prepare('SELECT * FROM users WHERE id = ?').get(doc2.created_by);
      const senderName = creator?.name || creator?.email || 'SealForge';
      signerOps.updateStatus(signer.id, 'sent');
      await notifySigner(signer, doc2, senderName);
    }
  }
}

// ─── Signer Experience ───
app.get('/sign/:token', (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).send('Signing link not found or expired.');
  if (signer.status === 'signed') return res.send('You have already signed this document.');
  if (signer.doc_status === 'completed') return res.send('This document has already been completed.');
  if (signer.doc_status === 'cancelled') return res.send('This signing request was cancelled by the sender.');
  sendHtml(res, path.join(__dirname, 'public', 'sign.html'));
});

app.get('/api/sign/:token/info', (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  // Filter fields: only this signer's fields (by sign_order) — others are hidden
  const allFields = docOps.getFields(signer.document_id);
  const myFields = allFields.filter(f => f.signerOrder === signer.sign_order);
  const otherFields = allFields.filter(f => f.signerOrder !== signer.sign_order)
    .map(f => ({ ...f, type: 'readonly', label: '(other signer)' })); // shown as locked overlays
  // Pre-filled field values from bulk mapping
  let prefilledValues = {};
  try { prefilledValues = JSON.parse(signer.field_values_json || '{}'); } catch {}

  res.json({
    signerName: signer.name,
    signerEmail: signer.email,
    docTitle: signer.doc_title,
    docUUID: signer.doc_uuid,
    status: signer.status,
    role: signer.role,
    fields: myFields,
    readonlyFields: otherFields,
    prefilledValues,
    paymentRequired: signer.payment_amount_cents > 0,
    paymentAmountCents: signer.payment_amount_cents || 0,
    paymentCurrency: signer.payment_currency || 'CAD',
    paymentStatus: signer.payment_status || 'none',
    paymentConfigured: stripe.isConfigured(),
    idVerificationRequired: !!signer.id_verification_required,
    idVerificationStatus: signer.id_verification_status || 'none',
    emailConfigured: email.isConfigured(),
  });
});

// ─── ID verification upload (multipart: id, selfie) ───
app.post('/api/sign/:token/id-verify', rateLimit(60000, 5), (req, res, next) => {
  const idUpload = multer({
    storage: multer.memoryStorage(),
    fileFilter: (req, file, cb) => {
      if (['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype)) return cb(null, true);
      cb(new Error('Only JPG/PNG/WebP images allowed'), false);
    },
    limits: { fileSize: 8 * 1024 * 1024 },
  }).fields([{ name: 'id', maxCount: 1 }, { name: 'selfie', maxCount: 1 }]);
  idUpload(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    next();
  });
}, (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  if (signer.doc_status === 'cancelled') return res.status(410).json({ error: 'Cancelled' });
  if (signer.status !== 'sent') return res.status(403).json({ error: 'Not your turn' });
  if (!signer.id_verification_required) return res.status(400).json({ error: 'ID verification not required' });
  if (!req.session.verifiedSigners?.[req.params.token]) return res.status(403).json({ error: 'Email not verified first' });

  const idFile = req.files?.id?.[0];
  const selfieFile = req.files?.selfie?.[0];
  if (!idFile || !selfieFile) return res.status(400).json({ error: 'Both ID photo and selfie are required' });

  // Verify image magic bytes (basic check)
  function isImage(buf) {
    if (!buf || buf.length < 4) return false;
    const h = buf.slice(0, 4);
    return (h[0] === 0xFF && h[1] === 0xD8) || // JPEG
           (h[0] === 0x89 && h[1] === 0x50) || // PNG
           (buf.slice(0, 4).toString() === 'RIFF'); // WebP
  }
  if (!isImage(idFile.buffer) || !isImage(selfieFile.buffer)) {
    return res.status(400).json({ error: 'Files do not appear to be valid images' });
  }

  const ext = (file) => file.mimetype === 'image/png' ? 'png' : (file.mimetype === 'image/webp' ? 'webp' : 'jpg');
  // Files stored AES-256-GCM encrypted with a `.enc` suffix. The original extension is
  // retained before `.enc` so tooling can still identify the original type after decryption.
  const idPath = path.join(idVerifDir, `${signer.doc_uuid}_${signer.id}_id.${ext(idFile)}.enc`);
  const selfiePath = path.join(idVerifDir, `${signer.doc_uuid}_${signer.id}_selfie.${ext(selfieFile)}.enc`);
  try {
    fs.writeFileSync(idPath, encryptIdBlob(idFile.buffer));
    fs.writeFileSync(selfiePath, encryptIdBlob(selfieFile.buffer));
  } catch (e) {
    console.error('ID file encryption failed:', e.message);
    return res.status(500).json({ error: 'Could not store verification files' });
  }

  signerOps.setIdFiles(signer.id, idPath, selfiePath);
  res.json({ ok: true, status: 'verified' });
});

// ─── Stripe payment for signer ───
app.post('/api/sign/:token/payment-checkout', rateLimit(60000, 5), async (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  if (signer.doc_status === 'cancelled') return res.status(410).json({ error: 'Cancelled' });
  if (signer.status !== 'sent') return res.status(403).json({ error: 'Not your turn' });
  if (signer.payment_amount_cents <= 0) return res.status(400).json({ error: 'No payment required' });
  if (signer.payment_status === 'paid') return res.status(400).json({ error: 'Already paid' });
  if (!stripe.isConfigured()) return res.status(503).json({ error: 'Payments not configured on this server' });

  const doc = docOps.findById(signer.document_id);
  try {
    const session = await stripe.createCheckoutSession({
      amountCents: signer.payment_amount_cents,
      currency: signer.payment_currency,
      description: doc.payment_description || doc.title,
      signerEmail: signer.email,
      successUrl: `${BASE_URL}/sign/${req.params.token}?stripe_session={CHECKOUT_SESSION_ID}`,
      cancelUrl: `${BASE_URL}/sign/${req.params.token}?paid=cancel`,
    });
    signerOps.setPaymentSession(signer.id, session.id);
    res.json({ url: session.url });
  } catch (e) {
    console.error('Stripe checkout error:', e.message);
    res.status(500).json({ error: 'Could not start checkout: ' + e.message });
  }
});

// Verify a returning Stripe session and mark paid
app.post('/api/sign/:token/payment-verify', async (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  if (signer.payment_status === 'paid') return res.json({ ok: true, status: 'paid' });
  if (!signer.payment_session_id) return res.status(400).json({ error: 'No checkout session on file' });
  if (!stripe.isConfigured()) return res.status(503).json({ error: 'Payments not configured' });

  try {
    const session = await stripe.retrieveSession(signer.payment_session_id);
    if (session.payment_status === 'paid') {
      signerOps.markPaid(signer.id);
      return res.json({ ok: true, status: 'paid' });
    }
    return res.json({ ok: false, status: session.payment_status });
  } catch (e) {
    res.status(500).json({ error: 'Could not verify: ' + e.message });
  }
});

app.post('/api/sign/:token/send-otp', rateLimit(60000, 5), async (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  if (signer.doc_status === 'cancelled') return res.status(410).json({ error: 'This signing request was cancelled' });
  if (signer.status !== 'sent') return res.status(403).json({ error: 'It is not your turn to sign yet' });

  const otp = signerOps.setOTP(signer.id);
  // Channel: client may request 'sms' explicitly; otherwise honor the signer's preference
  const reqChannel = req.body && req.body.channel;
  const channel = (reqChannel === 'sms' || (!reqChannel && signer.notify_method === 'sms')) ? 'sms' : 'email';

  let sent = false;
  if (channel === 'sms' && signer.phone && sms.isConfigured()) {
    const r = await sms.sendOTPSMS(signer.phone, otp);
    sent = r.ok;
  } else {
    sent = await email.sendSignerOTP(signer.email, signer.name, otp);
  }

  if (!sent && ALLOW_DEV_OTP) return res.json({ ok: true, devOtp: otp, channel });
  if (!sent) return res.status(500).json({ error: 'Code delivery failed' });
  res.json({ ok: true, channel });
});

app.post('/api/sign/:token/verify-otp', rateLimit(60000, 10), (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  if (signer.doc_status === 'cancelled') return res.status(410).json({ error: 'This signing request was cancelled' });
  if (signer.status !== 'sent') return res.status(403).json({ error: 'It is not your turn to sign yet' });

  if (!signerOps.verifyOTP(signer.id, req.body.code)) {
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  // Mark as verified in session
  if (!req.session.verifiedSigners) req.session.verifiedSigners = {};
  req.session.verifiedSigners[req.params.token] = true;

  res.json({ ok: true });
});

app.get('/api/sign/:token/pdf', (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  if (signer.doc_status === 'cancelled') return res.status(410).json({ error: 'This signing request was cancelled' });
  if (signer.status !== 'sent') return res.status(403).json({ error: 'It is not your turn to sign yet' });

  // Check OTP verified
  if (!req.session.verifiedSigners?.[req.params.token]) {
    return res.status(403).json({ error: 'Email not verified' });
  }

  const filePath = path.join(storageDir, `${signer.doc_uuid}.pdf`);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'PDF not found' });

  res.setHeader('Content-Type', 'application/pdf');
  res.sendFile(filePath);
});

app.post('/api/sign/:token/submit', rateLimit(60000, 10), async (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  if (signer.status === 'signed') return res.status(400).json({ error: 'Already signed' });
  if (signer.doc_status === 'cancelled') return res.status(410).json({ error: 'This signing request was cancelled' });
  if (signer.status !== 'sent') return res.status(403).json({ error: 'It is not your turn to sign yet' });

  if (!req.session.verifiedSigners?.[req.params.token]) {
    return res.status(403).json({ error: 'Email not verified' });
  }

  if (signer.payment_amount_cents > 0 && signer.payment_status !== 'paid') {
    return res.status(402).json({ error: 'Payment required before signing' });
  }
  if (signer.id_verification_required && signer.id_verification_status !== 'verified') {
    return res.status(403).json({ error: 'ID verification required before signing' });
  }

  const { signatureData, location, browserInfo, geoCoords, publicIp, fieldValues } = req.body;
  // Prefer client-reported public IP (from ipify.org), fall back to clientIp()
  // which respects TRUST_PROXY for accurate audit logging behind a reverse proxy.
  const ip = sanitize(publicIp || '') || clientIp(req);

  // Validate field values: only this signer's fields. Supports all field types
  // (including dropdown/radio with allowed-option enforcement) and conditional
  // `required-if` rules — enforcement mirrors what the UI shows.
  const allFields = docOps.getFields(signer.document_id);
  const myFields = allFields.filter(f => f.signerOrder === signer.sign_order);
  const cleanValues = {};
  for (const f of myFields) {
    const raw = fieldValues && Object.prototype.hasOwnProperty.call(fieldValues, f.id) ? fieldValues[f.id] : '';
    if (f.type === 'checkbox') {
      cleanValues[f.id] = raw === true || raw === 'true' || raw === '1';
    } else {
      cleanValues[f.id] = sanitize(String(raw == null ? '' : raw)).slice(0, 500);
    }
  }
  const validationError = validateFieldSubmission(allFields, signer.sign_order, cleanValues);
  if (validationError) return res.status(400).json({ error: validationError });

  const signed = signerOps.markSigned(signer.id, {
    signatureData: sanitize(signatureData || ''),
    ip,
    location: sanitize(location || ''),
    browserInfo: sanitize(browserInfo || ''),
    geoCoords: sanitize(geoCoords || ''),
    fieldValues: cleanValues,
  });
  if (!signed) return res.status(409).json({ error: 'Signature already recorded (concurrent request)' });

  const signerDoc = docOps.findById(signer.document_id);
  fireWebhooks(signerDoc.created_by, 'document.signed_by', {
    document: { uuid: signerDoc.uuid, title: signerDoc.title },
    signer: { name: signer.name, email: signer.email, sign_order: signer.sign_order, role: signer.role },
  });

  // Check if all signers are done
  if (signerOps.allSigned(signer.document_id)) {
    docOps.updateStatus(signer.document_id, 'completed');
    await generateFinalPdf(signer.document_id);
    const doc = docOps.findById(signer.document_id);
    const allSigners = signerOps.listByDocument(signer.document_id);
    const creator = require('./database').db.prepare('SELECT * FROM users WHERE id = ?').get(doc.created_by);
    await email.sendCompletionNotice(creator.email, creator.name, doc.title, doc.uuid);
    for (const s of allSigners) {
      // Includes signers, approvers, and CCs (CCs only get this notice)
      await email.sendCompletionNotice(s.email, s.name, doc.title, doc.uuid);
    }
    fireWebhooks(doc.created_by, 'document.completed', {
      document: { uuid: doc.uuid, title: doc.title, completed_at: doc.completed_at },
      signers: allSigners.map(s => ({ name: s.name, email: s.email, role: s.role, signed_at: s.signed_at })),
    });
    return res.json({ ok: true, completed: true });
  }

  // Advance to next signer: workflow mode → engine; sequential → next; parallel → noop
  const signerDoc2 = docOps.findById(signer.document_id);
  if (signerDoc2.workflow_json) {
    // Mark current workflow step as completed
    const wfSteps = workflowOps.listByDocument(signer.document_id);
    const activeStep = wfSteps.find(s => s.signer_id === signer.id && (s.status === 'active' || s.status === 'pending'));
    if (activeStep) workflowOps.updateStepStatus(activeStep.id, 'completed');
    await advanceWorkflow(signer.document_id);
  } else if (signer.signing_mode !== 'parallel') {
    await sendToNextSigner(signer.document_id);
  }
  res.json({ ok: true, completed: false });
});

// ─── Cancel a document (creator only, while pending) ───
app.post('/api/documents/:uuid/cancel', requireAuth, (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  if (doc.created_by !== req.session.userId) return res.status(403).json({ error: 'Access denied' });
  if (doc.status === 'completed') return res.status(400).json({ error: 'Already completed' });
  if (doc.status === 'cancelled') return res.status(400).json({ error: 'Already cancelled' });
  docOps.cancel(doc.id);
  fireWebhooks(req.session.userId, 'document.cancelled', {
    document: { uuid: doc.uuid, title: doc.title },
  });
  res.json({ ok: true });
});

// ─── Resend signing request to a specific signer (creator only) ───
app.post('/api/documents/:uuid/signers/:signerId/resend', requireAuth, async (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  if (doc.created_by !== req.session.userId) return res.status(403).json({ error: 'Access denied' });
  if (doc.status !== 'pending') return res.status(400).json({ error: 'Document not pending' });

  const signer = signerOps.findById(parseInt(req.params.signerId, 10));
  if (!signer || signer.document_id !== doc.id) return res.status(404).json({ error: 'Signer not found' });
  if (signer.status === 'signed') return res.status(400).json({ error: 'Signer already signed' });
  if (signer.role === 'cc') return res.status(400).json({ error: 'CCs are not sent signing requests' });

  // Sequential mode: only resend to the currently-active signer (status=sent)
  if (doc.signing_mode === 'sequential' && signer.status !== 'sent') {
    return res.status(400).json({ error: 'Not this signer\'s turn yet' });
  }

  // Rotate token (invalidates the old link — fresh secret on resend)
  const newToken = signerOps.rotateToken(signer.id);
  if (signer.status === 'pending') signerOps.updateStatus(signer.id, 'sent');

  const creatorUser = require('./database').db.prepare('SELECT * FROM users WHERE id = ?').get(doc.created_by);
  const signUrl = `${BASE_URL}/sign/${newToken}`;
  await email.sendSigningRequest(
    signer.email, signer.name,
    creatorUser?.name || creatorUser?.email || 'Someone',
    doc.title, signUrl, doc.message
  );
  res.json({ ok: true });
});

// ─── Generate final signed PDF with all signatures ───
async function generateFinalPdf(documentId) {
  const doc = docOps.findById(documentId);
  const signers = signerOps.listByDocument(documentId);
  const originalPath = path.join(storageDir, `${doc.uuid}.pdf`);
  const originalBytes = fs.readFileSync(originalPath);

  const pdfDoc = await PDFDocument.load(originalBytes);
  const { rgb, StandardFonts } = require('pdf-lib');
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontMono = await pdfDoc.embedFont(StandardFonts.Courier);

  const pages = pdfDoc.getPages();

  // ── Draw filled fields on their respective pages ──
  const fields = docOps.getFields(documentId);
  if (fields.length) {
    for (const signer of signers) {
      if (signer.status !== 'signed') continue;
      let signerValues = {};
      try { signerValues = JSON.parse(signer.field_values_json || '{}'); } catch {}
      const myFields = fields.filter(f => f.signerOrder === signer.sign_order);
      for (const f of myFields) {
        const pageIdx = Math.min(pages.length, Math.max(1, f.page)) - 1;
        const page = pages[pageIdx];
        const { width: pageW, height: pageH } = page.getSize();
        // PDF coords: origin bottom-left. Our yPct measured from top.
        const x = f.xPct * pageW;
        const w = f.wPct * pageW;
        const h = f.hPct * pageH;
        const yTop = (1 - f.yPct) * pageH;
        const y = yTop - h;

        const value = signerValues[f.id];

        if (f.type === 'checkbox') {
          page.drawRectangle({ x, y, width: h, height: h, borderColor: rgb(0.2,0.2,0.2), borderWidth: 1 });
          if (value === true || value === 'true') {
            page.drawText('X', { x: x + h * 0.2, y: y + h * 0.15, size: h * 0.7, font: fontBold, color: rgb(0.1,0.23,0.48) });
          }
        } else if (f.type === 'signature' && signer.signature_data && signer.signature_data.startsWith('data:image/png')) {
          try {
            const sigBytes = Buffer.from(signer.signature_data.split(',')[1], 'base64');
            const sigImg = await pdfDoc.embedPng(sigBytes);
            const aspect = sigImg.width / sigImg.height;
            let drawW = w, drawH = w / aspect;
            if (drawH > h) { drawH = h; drawW = h * aspect; }
            page.drawImage(sigImg, { x, y: y + (h - drawH) / 2, width: drawW, height: drawH });
          } catch {}
        } else {
          let displayValue = String(value || '');
          if (f.type === 'date' && !displayValue) displayValue = new Date().toISOString().slice(0, 10);
          if (f.type === 'name' && !displayValue) displayValue = signer.name;
          if (f.type === 'email' && !displayValue) displayValue = signer.email;
          if (f.type === 'initials' && !displayValue) {
            displayValue = (signer.name || '').split(' ').map(p => p[0] || '').join('').toUpperCase().slice(0, 4);
          }
          if (displayValue) {
            const fontSize = Math.min(h * 0.7, 14);
            page.drawText(displayValue, { x: x + 2, y: y + (h - fontSize) / 2 + 1, size: fontSize, font, color: rgb(0.05,0.1,0.25) });
          }
        }
      }
    }
  }

  const lastPage = pages[pages.length - 1];
  const { width: pw } = lastPage.getSize();

  // Add signature stamps to the last page of original content
  let stampY = 60;
  for (const signer of signers) {
    if (signer.status !== 'signed') continue;

    const stampH = 55;
    const stampW = 260;
    const stampX = pw - stampW - 30;

    lastPage.drawRectangle({ x: stampX, y: stampY, width: stampW, height: stampH, color: rgb(1,1,1), borderColor: rgb(0.1,0.23,0.48), borderWidth: 1 });

    const lx = stampX + 6;
    lastPage.drawText('Doc', { x: lx, y: stampY + stampH/2 - 5, size: 13, font: fontBold, color: rgb(0.1,0.23,0.48) });
    lastPage.drawText('Seal', { x: lx + fontBold.widthOfTextAtSize('Doc', 13), y: stampY + stampH/2 - 5, size: 13, font: fontBold, color: rgb(0.18,0.37,0.72) });

    const dx = lx + 46;
    lastPage.drawLine({ start: { x: dx, y: stampY + 4 }, end: { x: dx, y: stampY + stampH - 4 }, thickness: 0.8, color: rgb(0.1,0.23,0.48) });

    const tx = dx + 6;
    let ty = stampY + stampH - 10;
    lastPage.drawText(`Signed by: ${signer.name}`, { x: tx, y: ty, size: 7, font: fontBold, color: rgb(0.1,0.1,0.1) });
    ty -= 10; lastPage.drawText(`Email: ${signer.email}`, { x: tx, y: ty, size: 7, font, color: rgb(0.2,0.2,0.2) });
    ty -= 10; lastPage.drawText(`Date: ${signer.signed_at}`, { x: tx, y: ty, size: 7, font, color: rgb(0.2,0.2,0.2) });
    ty -= 10; lastPage.drawText(`IP: ${signer.ip_address || '-'}`, { x: tx, y: ty, size: 6, font: fontMono, color: rgb(0.4,0.4,0.4) });

    // Draw signature image if present
    if (signer.signature_data && signer.signature_data.startsWith('data:image/png')) {
      try {
        const sigImgBytes = Buffer.from(signer.signature_data.split(',')[1], 'base64');
        const sigImg = await pdfDoc.embedPng(sigImgBytes);
        const aspect = sigImg.width / sigImg.height;
        const sigW = Math.min(stampW - 8, 100);
        const sigH = sigW / aspect;
        lastPage.drawImage(sigImg, { x: stampX + 4, y: stampY + stampH + 2, width: sigW, height: Math.min(sigH, 30) });
      } catch (e) { /* skip if image fails */ }
    }

    stampY += stampH + 40;
  }

  // ── Audit trail page ──
  const ap = pdfDoc.addPage([595, 842]);
  const w = 595, h = 842;
  let y = h - 50;

  ap.drawRectangle({ x: 0, y: h - 80, width: w, height: 80, color: rgb(0.1, 0.23, 0.48) });
  ap.drawText('Seal', { x: 40, y: h - 52, size: 24, font: fontBold, color: rgb(1,1,1) });
  ap.drawText('Forge', { x: 40 + fontBold.widthOfTextAtSize('Seal', 24), y: h - 52, size: 24, font: fontBold, color: rgb(0.5,0.72,1) });
  ap.drawText('Certificate of Signing', { x: 40 + fontBold.widthOfTextAtSize('SealForge', 24) + 20, y: h - 50, size: 16, font, color: rgb(0.85,0.9,1) });

  y = h - 110;

  function section(title, items) {
    ap.drawText(title, { x: 40, y, size: 11, font: fontBold, color: rgb(0.1,0.23,0.48) });
    y -= 4;
    ap.drawLine({ start: { x: 40, y }, end: { x: w - 40, y }, thickness: 1, color: rgb(0.8,0.85,0.9) });
    y -= 14;
    for (const [label, value] of items) {
      ap.drawText(label, { x: 50, y, size: 9, font: fontBold, color: rgb(0.3,0.3,0.3) });
      const mono = label.includes('Hash') || label.includes('ID') || label.includes('IP');
      ap.drawText(String(value || '-'), { x: 190, y, size: mono ? 8 : 9, font: mono ? fontMono : font, color: rgb(0.15,0.15,0.15) });
      y -= 14;
    }
    y -= 6;
  }

  section('DOCUMENT', [
    ['Document ID:', doc.uuid],
    ['Title:', doc.title],
    ['Original File:', doc.original_filename],
    ['Original SHA-256:', doc.original_hash.substring(0, 32)],
    ['', doc.original_hash.substring(32)],
    ['Status:', 'Completed'],
    ['Created:', doc.created_at],
    ['Completed:', doc.completed_at || new Date().toISOString()],
  ]);

  for (const signer of signers) {
    section(`SIGNER ${signer.sign_order}: ${signer.name}`, [
      ['Email:', signer.email],
      ['Status:', signer.status],
      ['Signed At:', signer.signed_at || '-'],
      ['IP Address:', signer.ip_address || '-'],
      ['Location:', signer.location || '-'],
      ['Browser:', signer.browser_info || '-'],
      ['GPS:', signer.geo_coords || '-'],
    ]);
  }

  const tsaLines = [
    ['Verify URL:', 'https://rupindermonga.github.io/pdf-signing/'],
    ['Digital Sig:', 'PKCS#7 X.509 Certificate'],
  ];
  if (tsa.isConfigured()) {
    tsaLines.push(['Timestamp:', 'RFC 3161 (external .tst sidecar — LTV-ready)']);
    tsaLines.push(['TSA:', tsa.TSA_URL]);
  }
  section('VERIFICATION', tsaLines);

  ap.drawLine({ start: { x: 40, y: 55 }, end: { x: w - 40, y: 55 }, thickness: 0.5, color: rgb(0.7,0.7,0.7) });
  ap.drawText('This document was digitally signed using SealForge. Verify at: https://rupindermonga.github.io/pdf-signing/', { x: 40, y: 40, size: 7, font, color: rgb(0.5,0.5,0.5) });

  // Save stamped PDF
  const stampedBytes = await pdfDoc.save({ useObjectStreams: false });

  // PKI sign
  let finalBytes = stampedBytes;
  if (p12Buffer) {
    try {
      const pdfForSign = await PDFDocument.load(stampedBytes);
      pdflibAddPlaceholder({ pdfDoc: pdfForSign, reason: 'All parties signed', name: 'SealForge', location: '' });
      const withPlaceholder = await pdfForSign.save({ useObjectStreams: false });
      const signer = new P12Signer(p12Buffer, { passphrase: process.env.P12_PASSPHRASE || 'sealforge' });
      const signPdf = new SignPdf();
      finalBytes = await signPdf.sign(withPlaceholder, signer);
    } catch (e) {
      console.error('PKI signing failed for final PDF:', e.message);
    }
  }

  // Save final
  const finalPath = path.join(storageDir, `${doc.uuid}_signed.pdf`);
  fs.writeFileSync(finalPath, Buffer.from(finalBytes));

  // ─── RFC 3161 timestamp over the final signed PDF ───
  // Produces an external .tst sidecar file that proves the PDF existed at the
  // TSA-asserted time — enabling LTV even after the P12 cert expires.
  if (tsa.isConfigured()) {
    try {
      const finalHash = crypto.createHash('sha256').update(Buffer.from(finalBytes)).digest();
      const result = await tsa.requestTimestamp(finalHash);
      const tstPath = path.join(storageDir, `${doc.uuid}_signed.pdf.tst`);
      fs.writeFileSync(tstPath, result.token);
      docOps.setTimestamp(doc.id, {
        tsaUrl: result.tsaUrl,
        tokenPath: tstPath,
        hashHex: finalHash.toString('hex'),
        genTimeISO: result.genTime ? result.genTime.toISOString() : null,
      });
      console.log(`[TSA] token stored (${result.token.length} bytes) for ${doc.uuid}, genTime=${result.genTime || 'unknown'}`);
    } catch (e) {
      console.warn(`[TSA] timestamp failed for ${doc.uuid}: ${e.message}`);
      // Non-fatal: the PDF is still signed, just without a TSA token.
    }
  }
}

// ─── Download completed PDF ───
app.get('/api/documents/:uuid/download', requireAuth, (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  if (doc.created_by !== req.session.userId) return res.status(403).json({ error: 'Access denied' });

  const signedPath = path.join(storageDir, `${doc.uuid}_signed.pdf`);
  const originalPath = path.join(storageDir, `${doc.uuid}.pdf`);
  const filePath = fs.existsSync(signedPath) ? signedPath : originalPath;

  // Safe Content-Disposition: encode filename to prevent header injection
  const safeFilename = encodeURIComponent(doc.original_filename).replace(/%20/g, '_');
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="signed_${safeFilename}"`);
  res.sendFile(filePath);
});

// ─── Download RFC 3161 timestamp token (.tst) ───
// Verify externally with: openssl ts -verify -data signed_<uuid>.pdf -in <uuid>_signed.pdf.tst -CAfile <tsa-root.pem>
app.get('/api/documents/:uuid/timestamp', requireAuth, (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  if (doc.created_by !== req.session.userId) return res.status(403).json({ error: 'Access denied' });
  if (!doc.tsa_token_path || !fs.existsSync(doc.tsa_token_path)) {
    return res.status(404).json({ error: 'No timestamp token available for this document' });
  }
  res.setHeader('Content-Type', 'application/timestamp-reply');
  res.setHeader('Content-Disposition', `attachment; filename="${doc.uuid}.tst"`);
  res.sendFile(doc.tsa_token_path);
});

// ─── Document detail ───
app.get('/api/documents/:uuid', requireAuth, (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  if (doc.created_by !== req.session.userId) return res.status(403).json({ error: 'Access denied' });

  const signers = signerOps.listByDocument(doc.id);
  // Strip tokens — only show sign URLs when email is NOT configured (owner needs to share manually)
  const safeSigner = signers.map(s => ({
    id: s.id,
    name: s.name,
    email: s.email,
    sign_order: s.sign_order,
    role: s.role,
    status: s.status,
    signed_at: s.signed_at,
    ip_address: s.ip_address,
    location: s.location,
    browser_info: s.browser_info,
    signUrl: (!email.isConfigured() && (s.status === 'sent' || s.status === 'pending'))
      ? `${BASE_URL}/sign/${s.token}` : undefined,
  }));
  res.json({ document: doc, signers: safeSigner, emailConfigured: email.isConfigured() });
});

// ─── Templates ───
app.get('/templates', requireAuth, (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'templates.html'));
});

app.get('/api/templates', requireAuth, (req, res) => {
  const list = templateOps.listByUser(req.session.userId).map(t => ({
    uuid: t.uuid, name: t.name, title: t.title, message: t.message,
    signing_mode: t.signing_mode, has_pdf: !!t.has_pdf, pdf_filename: t.pdf_filename,
    signers: JSON.parse(t.signers_json || '[]'),
    fields_count: JSON.parse(t.fields_json || '[]').length,
    created_at: t.created_at,
  }));
  res.json({ templates: list });
});

app.get('/api/templates/:uuid', requireAuth, (req, res) => {
  const tpl = templateOps.findByUUID(req.params.uuid, req.session.userId);
  if (!tpl) return res.status(404).json({ error: 'Not found' });
  res.json({
    uuid: tpl.uuid, name: tpl.name, title: tpl.title, message: tpl.message,
    signing_mode: tpl.signing_mode, has_pdf: !!tpl.has_pdf, pdf_filename: tpl.pdf_filename,
    signers: tpl.signers, fields: tpl.fields,
  });
});

app.post('/api/templates', requireAuth, (req, res, next) => {
  upload.single('pdf')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    next();
  });
}, (req, res) => {
  try {
    const { name, title, message, signingMode, signers, fields } = req.body;
    const cleanName = sanitize(name);
    if (!cleanName) return res.status(400).json({ error: 'Template name is required' });

    const parsedSigners = JSON.parse(signers || '[]');
    const allowedRoles = ['sign', 'cc', 'approve'];
    const cleanSigners = parsedSigners.map(s => ({
      name: sanitize(s.name || ''),
      email: sanitize(s.email || '').toLowerCase(),
      role: allowedRoles.includes(s.role) ? s.role : 'sign',
    }));

    let hasPdf = false, pdfHash = null, pdfFilename = null;
    let pdfBuffer = null;
    if (req.file) {
      if (!req.file.buffer || req.file.buffer.length < 5 || req.file.buffer.toString('utf-8', 0, 5) !== '%PDF-') {
        return res.status(400).json({ error: 'Invalid PDF file' });
      }
      hasPdf = true;
      pdfBuffer = req.file.buffer;
      pdfHash = crypto.createHash('sha256').update(pdfBuffer).digest('hex');
      pdfFilename = sanitize(req.file.originalname).replace(/[^\w.\-() ]/g, '_');
    }

    const tpl = templateOps.create(req.session.userId, {
      name: cleanName,
      title: sanitize(title),
      message: sanitize(message),
      signingMode,
      signers: cleanSigners,
      hasPdf,
      pdfHash,
      pdfFilename,
      fields: fields ? cleanFieldList(JSON.parse(fields)) : [],
    });

    if (pdfBuffer) {
      fs.writeFileSync(path.join(templatesDir, `${tpl.uuid}.pdf`), pdfBuffer);
    }

    res.json({ ok: true, uuid: tpl.uuid });
  } catch (err) {
    console.error('Template create error:', err);
    res.status(500).json({ error: 'Failed to save template' });
  }
});

app.delete('/api/templates/:uuid', requireAuth, (req, res) => {
  const tpl = templateOps.findByUUID(req.params.uuid, req.session.userId);
  if (!tpl) return res.status(404).json({ error: 'Not found' });
  templateOps.delete(req.params.uuid, req.session.userId);
  const pdfPath = path.join(templatesDir, `${req.params.uuid}.pdf`);
  if (fs.existsSync(pdfPath)) fs.unlinkSync(pdfPath);
  res.json({ ok: true });
});

// Serve a template PDF (used by send.html when the user picks a template)
app.get('/api/templates/:uuid/pdf', requireAuth, (req, res) => {
  const tpl = templateOps.findByUUID(req.params.uuid, req.session.userId);
  if (!tpl || !tpl.has_pdf) return res.status(404).json({ error: 'No PDF in template' });
  const pdfPath = path.join(templatesDir, `${tpl.uuid}.pdf`);
  if (!fs.existsSync(pdfPath)) return res.status(404).json({ error: 'PDF file missing' });
  res.setHeader('Content-Type', 'application/pdf');
  res.sendFile(pdfPath);
});

// ─── Settings page (API keys + webhooks) ───
app.get('/settings', requireAuth, requireRole('admin'), (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'settings.html'));
});

// API key management (session auth)
app.get('/api/settings/keys', requireAuth, (req, res) => {
  res.json({ keys: apiKeyOps.listByUser(req.session.userId) });
});
app.post('/api/settings/keys', requireAuth, (req, res) => {
  const name = sanitize(req.body.name || '');
  if (!name) return res.status(400).json({ error: 'Name required' });
  const scope = req.body.scope === 'ro' ? 'ro' : 'rw';
  const created = apiKeyOps.create(req.session.userId, name, scope);
  res.json({ ok: true, name, plaintext: created.plaintext, prefix: created.prefix, scope: created.scope });
});
app.delete('/api/settings/keys/:id', requireAuth, (req, res) => {
  const ok = apiKeyOps.revoke(parseInt(req.params.id, 10), req.session.userId);
  res.json({ ok });
});

// Webhook management
app.get('/api/settings/webhooks', requireAuth, (req, res) => {
  const list = webhookOps.listByUser(req.session.userId).map(w => ({
    id: w.id, url: w.url, secret: w.secret,
    events: JSON.parse(w.events_json || '[]'),
    active: !!w.active, last_status: w.last_status, last_fired_at: w.last_fired_at,
    created_at: w.created_at,
  }));
  res.json({ webhooks: list });
});
app.post('/api/settings/webhooks', requireAuth, async (req, res) => {
  const url = (req.body.url || '').trim();
  if (!url || !/^https:\/\//i.test(url)) return res.status(400).json({ error: 'Valid https:// URL required (plain http is not allowed for webhooks)' });
  // Defense-in-depth: reject private / link-local / loopback URLs at creation, not only at fire time
  const check = await resolveAndCheckUrl(url);
  if (!check.ok) return res.status(400).json({ error: `Webhook URL rejected (${check.reason}) — public HTTPS endpoints only` });
  const events = Array.isArray(req.body.events) ? req.body.events : ['*'];
  const allowed = ['*', 'document.sent', 'document.signed_by', 'document.completed', 'document.cancelled'];
  const cleanEvents = events.filter(e => allowed.includes(e));
  if (!cleanEvents.length) return res.status(400).json({ error: 'No valid events' });
  const created = webhookOps.create(req.session.userId, url, cleanEvents);
  res.json({ ok: true, id: created.id, secret: created.secret });
});
app.post('/api/settings/webhooks/:id/toggle', requireAuth, (req, res) => {
  const ok = webhookOps.toggle(parseInt(req.params.id, 10), req.session.userId, !!req.body.active);
  res.json({ ok });
});
app.delete('/api/settings/webhooks/:id', requireAuth, (req, res) => {
  const ok = webhookOps.delete(parseInt(req.params.id, 10), req.session.userId);
  res.json({ ok });
});

// ─── PUBLIC REST API v1 (Bearer token auth) ───
app.get('/api/v1/me', requireApiKey('ro'), (req, res) => {
  res.json({ user: { email: req.apiUser.email, name: req.apiUser.name }, scope: req.apiKey.scope });
});

app.get('/api/v1/documents', requireApiKey('ro'), (req, res) => {
  const docs = docOps.listByUser(req.apiUser.id).map(d => {
    const signers = signerOps.listByDocument(d.id);
    return {
      uuid: d.uuid, title: d.title, status: d.status, signing_mode: d.signing_mode,
      created_at: d.created_at, completed_at: d.completed_at,
      signers: signers.map(s => ({
        name: s.name, email: s.email, sign_order: s.sign_order, role: s.role,
        status: s.status, signed_at: s.signed_at,
      })),
    };
  });
  res.json({ documents: docs });
});

app.get('/api/v1/documents/:uuid', requireApiKey('ro'), (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc || doc.created_by !== req.apiUser.id) return res.status(404).json({ error: 'Not found' });
  const signers = signerOps.listByDocument(doc.id);
  res.json({
    uuid: doc.uuid, title: doc.title, status: doc.status, signing_mode: doc.signing_mode,
    created_at: doc.created_at, completed_at: doc.completed_at,
    fields: docOps.getFields(doc.id),
    signers: signers.map(s => ({
      name: s.name, email: s.email, sign_order: s.sign_order, role: s.role,
      status: s.status, signed_at: s.signed_at, ip_address: s.ip_address,
      sign_url: (s.status === 'sent' || s.status === 'pending') ? `${BASE_URL}/sign/${s.token}` : undefined,
    })),
  });
});

app.post('/api/v1/documents', requireApiKey('rw'), (req, res, next) => {
  upload.single('pdf')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    next();
  });
}, async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'PDF file required (multipart field "pdf")' });
    if (!req.file.buffer || req.file.buffer.length < 5 || req.file.buffer.toString('utf-8', 0, 5) !== '%PDF-') {
      return res.status(400).json({ error: 'Invalid PDF file' });
    }

    const { title, message, signers, signingMode, fields } = req.body;
    let parsedSigners, parsedFields;
    try {
      parsedSigners = typeof signers === 'string' ? JSON.parse(signers) : (signers || []);
      parsedFields = typeof fields === 'string' ? JSON.parse(fields || '[]') : (fields || []);
    } catch { return res.status(400).json({ error: 'signers/fields must be JSON arrays' }); }

    if (!parsedSigners.length) return res.status(400).json({ error: 'At least one signer required' });

    const allowedRoles = ['sign', 'cc', 'approve'];
    const cleanSigners = parsedSigners.map(s => ({
      name: sanitize(s.name || ''),
      email: sanitize(s.email || '').toLowerCase(),
      role: allowedRoles.includes(s.role) ? s.role : 'sign',
    }));
    const bad = cleanSigners.find(s => !s.name || !isValidEmail(s.email));
    if (bad) return res.status(400).json({ error: `Invalid signer entry (name and valid email required): ${bad.email || '(missing email)'}` });
    if (!cleanSigners.some(s => s.role !== 'cc')) {
      return res.status(400).json({ error: 'At least one signer must have role Sign or Approve' });
    }

    const cleanMode = signingMode === 'parallel' ? 'parallel' : 'sequential';
    const cleanFilename = sanitize(req.file.originalname).replace(/[^\w.\-() ]/g, '_');
    const cleanTitle = sanitize(title) || cleanFilename;
    const cleanMessage = sanitize(message);
    const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

    const doc = docOps.create(req.apiUser.id, cleanTitle, cleanFilename, hash, cleanMessage, cleanMode);
    fs.writeFileSync(path.join(storageDir, `${doc.uuid}.pdf`), req.file.buffer);

    for (let i = 0; i < cleanSigners.length; i++) {
      signerOps.addToDocument(doc.id, cleanSigners[i].name, cleanSigners[i].email, i + 1, cleanSigners[i].role);
    }

    // Optional expiration / reminder cadence for API callers
    const apiExpISO = (() => {
      const v = req.body.expires_at || req.body.expiresAt;
      if (!v || typeof v !== 'string') return null;
      const m = v.match(/^(\d{4})-(\d{2})-(\d{2})$/);
      if (m) return new Date(Date.UTC(+m[1], +m[2]-1, +m[3], 23, 59, 59)).toISOString();
      const t = Date.parse(v);
      return (!isNaN(t) && t > Date.now()) ? new Date(t).toISOString() : null;
    })();
    const apiCadence = Math.max(0, Math.min(30, parseInt(req.body.reminder_every_days || req.body.reminderEveryDays, 10) || 0));
    if (apiExpISO || apiCadence) docOps.setSchedule(doc.id, apiExpISO, apiCadence);

    const cleanFields = cleanFieldList(parsedFields);
    docOps.setFields(doc.id, cleanFields);

    docOps.updateStatus(doc.id, 'pending');
    if (cleanMode === 'parallel') await sendToAllParallel(doc.id);
    else await sendToNextSigner(doc.id);

    fireWebhooks(req.apiUser.id, 'document.sent', {
      document: { uuid: doc.uuid, title: cleanTitle, signing_mode: cleanMode },
      signers: cleanSigners,
    });

    res.status(201).json({
      uuid: doc.uuid, title: cleanTitle, status: 'pending', signing_mode: cleanMode,
      view_url: `${BASE_URL}/dashboard`,
    });
  } catch (err) {
    console.error('API v1 create error:', err);
    res.status(500).json({ error: 'Failed to create document' });
  }
});

app.post('/api/v1/documents/:uuid/cancel', requireApiKey('rw'), (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc || doc.created_by !== req.apiUser.id) return res.status(404).json({ error: 'Not found' });
  if (doc.status === 'completed') return res.status(400).json({ error: 'Already completed' });
  if (doc.status === 'cancelled') return res.status(400).json({ error: 'Already cancelled' });
  docOps.cancel(doc.id);
  fireWebhooks(req.apiUser.id, 'document.cancelled', { document: { uuid: doc.uuid, title: doc.title } });
  res.json({ ok: true, status: 'cancelled' });
});

app.get('/api/v1/documents/:uuid/download', requireApiKey('ro'), (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc || doc.created_by !== req.apiUser.id) return res.status(404).json({ error: 'Not found' });
  if (doc.status !== 'completed') return res.status(409).json({ error: 'Document not completed yet' });
  const signedPath = path.join(storageDir, `${doc.uuid}_signed.pdf`);
  const finalPath = fs.existsSync(signedPath) ? signedPath : path.join(storageDir, `${doc.uuid}.pdf`);
  if (!fs.existsSync(finalPath)) return res.status(404).json({ error: 'PDF file missing' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="signed_${doc.uuid}.pdf"`);
  res.sendFile(finalPath);
});

app.get('/api/v1/templates', requireApiKey('ro'), (req, res) => {
  const list = templateOps.listByUser(req.apiUser.id).map(t => ({
    uuid: t.uuid, name: t.name, title: t.title, signing_mode: t.signing_mode,
    has_pdf: !!t.has_pdf, created_at: t.created_at,
  }));
  res.json({ templates: list });
});

// ─── API v1: Webhooks (Zapier/Make compatible) ───
app.get('/api/v1/webhooks', requireApiKey('ro'), (req, res) => {
  const hooks = webhookOps.listByUser(req.apiUser.id).map(w => ({
    id: w.id, url: w.url, events: JSON.parse(w.events_json || '["*"]'),
    active: !!w.active, last_status: w.last_status, last_fired_at: w.last_fired_at, created_at: w.created_at,
  }));
  res.json({ webhooks: hooks });
});

app.post('/api/v1/webhooks', requireApiKey('rw'), async (req, res) => {
  const { url, events } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });
  // SSRF check
  try {
    const ok = await resolveAndCheckUrl(url);
    if (!ok) return res.status(400).json({ error: 'Webhook URL must be HTTPS and not target private networks' });
  } catch (e) { return res.status(400).json({ error: e.message }); }
  const result = webhookOps.create(req.apiUser.id, url, events);
  res.json({ ok: true, id: result.id, secret: result.secret });
});

app.delete('/api/v1/webhooks/:id', requireApiKey('rw'), (req, res) => {
  const deleted = webhookOps.delete(parseInt(req.params.id, 10), req.apiUser.id);
  if (!deleted) return res.status(404).json({ error: 'Webhook not found' });
  res.json({ ok: true });
});

// ─── API v1: Event polling (Zapier REST hook fallback) ───
app.get('/api/v1/events', requireApiKey('ro'), (req, res) => {
  const since = req.query.since || null;
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const events = eventLogOps.listSince(req.apiUser.id, since, limit).map(e => ({
    id: e.id, event: e.event, data: JSON.parse(e.payload_json || '{}'), created_at: e.created_at,
  }));
  res.json({ events });
});

// ─── QR Code (authenticated — guard against abuse & CPU DoS) ───
app.post('/api/qr', requireAuth, rateLimit(60000, 30), async (req, res) => {
  try {
    const { data } = req.body;
    if (typeof data !== 'string' || !data.length) return res.status(400).json({ error: 'No data' });
    if (data.length > 2048) return res.status(413).json({ error: 'QR data too large (max 2048 chars)' });
    const qr = await QRCode.toDataURL(data, { errorCorrectionLevel: 'M', margin: 1, width: 200, color: { dark: '#1a3b7a', light: '#ffffff' } });
    res.json({ qr });
  } catch { res.status(500).json({ error: 'QR failed' }); }
});

// ─── Solo PKI Sign (authenticated — uses server P12 cert) ───
app.post('/api/sign', requireAuth, rateLimit(60000, 20), async (req, res) => {
  try {
    const { pdfBytes } = req.body;
    if (!pdfBytes || !Array.isArray(pdfBytes)) {
      return res.status(400).json({ error: 'No PDF bytes provided' });
    }
    if (!p12Buffer) {
      return res.status(500).json({ error: 'No signing certificate available' });
    }
    const pdfBuffer = Buffer.from(pdfBytes);
    const pdfDoc = await PDFDocument.load(pdfBuffer);
    pdflibAddPlaceholder({
      pdfDoc,
      reason: req.body.reason || 'Document Signing',
      contactInfo: req.body.signer || '',
      name: req.body.signer || 'SealForge Signer',
      location: req.body.location || '',
    });
    const pdfWithPlaceholder = await pdfDoc.save({ useObjectStreams: false });
    const signer = new P12Signer(p12Buffer, { passphrase: process.env.P12_PASSPHRASE || 'sealforge' });
    const signPdf = new SignPdf();
    const signedPdf = await signPdf.sign(pdfWithPlaceholder, signer);
    const hash = crypto.createHash('sha256').update(signedPdf).digest('hex');
    res.json({ signedPdf: Buffer.from(signedPdf).toString('base64'), hash });
  } catch (err) {
    console.error('Solo signing error:', err.message);
    res.status(500).json({ error: 'PDF signing failed' });
  }
});

// ─── IP ───
app.get('/api/ip', (req, res) => {
  res.json({ ip: clientIp(req) });
});

// ─── Verify page ───
app.get('/verify', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'verify.html'));
});

// ─── Compliance page ───
app.get('/compliance', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'compliance.html'));
});

// ─── Solo sign page (authenticated — uses server P12 cert) ───
app.get('/solo', requireAuth, (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'solo.html'));
});

// ─── Kiosk / In-Person Signing ───
app.get('/kiosk/:uuid', (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc || !doc.kiosk_mode) return res.status(404).send('Not found');
  sendHtml(res, path.join(__dirname, 'public', 'kiosk.html'));
});

app.get('/api/kiosk/:uuid/info', (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc || !doc.kiosk_mode) return res.status(404).json({ error: 'Not found' });
  if (doc.status === 'cancelled') return res.status(410).json({ error: 'This request was cancelled' });

  const signers = signerOps.listByDocument(doc.id).filter(s => s.role !== 'cc');
  const current = signers.find(s => s.status !== 'signed');
  const allSigned = signers.every(s => s.status === 'signed');

  res.json({
    docTitle: doc.title,
    status: doc.status,
    totalSigners: signers.length,
    signedCount: signers.filter(s => s.status === 'signed').length,
    allSigned,
    currentSigner: current ? { id: current.id, name: current.name, email: current.email, order: current.sign_order } : null,
    signers: signers.map(s => ({ name: s.name, status: s.status, order: s.sign_order })),
    hasPin: !!doc.kiosk_pin,
    fields: current ? (JSON.parse(doc.fields_json || '[]')).filter(f => f.signerOrder === current.sign_order) : [],
  });
});

app.post('/api/kiosk/:uuid/verify-pin', rateLimit(60000, 10), (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc || !doc.kiosk_mode) return res.status(404).json({ error: 'Not found' });
  if (!doc.kiosk_pin) return res.json({ ok: true });
  const { pin } = req.body;
  if (!pin || pin !== doc.kiosk_pin) return res.status(400).json({ error: 'Invalid PIN' });
  req.session.kioskVerified = req.params.uuid;
  res.json({ ok: true });
});

app.get('/api/kiosk/:uuid/pdf', (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc || !doc.kiosk_mode) return res.status(404).json({ error: 'Not found' });
  const pdfPath = path.join(storageDir, `${doc.uuid}.pdf`);
  if (!fs.existsSync(pdfPath)) return res.status(404).json({ error: 'PDF not found' });
  res.setHeader('Content-Type', 'application/pdf');
  res.sendFile(pdfPath);
});

app.post('/api/kiosk/:uuid/submit', rateLimit(60000, 10), async (req, res) => {
  const doc = docOps.findByUUID(req.params.uuid);
  if (!doc || !doc.kiosk_mode) return res.status(404).json({ error: 'Not found' });
  if (doc.status === 'completed') return res.status(400).json({ error: 'Already completed' });
  if (doc.status === 'cancelled') return res.status(410).json({ error: 'Cancelled' });

  // PIN check if required
  if (doc.kiosk_pin && req.session.kioskVerified !== req.params.uuid) {
    return res.status(403).json({ error: 'PIN verification required' });
  }

  const signers = signerOps.listByDocument(doc.id).filter(s => s.role !== 'cc');
  const current = signers.find(s => s.status !== 'signed');
  if (!current) return res.status(400).json({ error: 'All signers already signed' });

  const { signatureData, fieldValues } = req.body;
  if (!signatureData) return res.status(400).json({ error: 'Signature required' });

  // Validate fields
  const docFields = JSON.parse(doc.fields_json || '[]');
  if (docFields.length) {
    const { validateFieldSubmission } = require('./fields');
    const fieldErr = validateFieldSubmission(docFields, current.sign_order, fieldValues || {});
    if (fieldErr) return res.status(400).json({ error: fieldErr });
  }

  const signed = signerOps.markSigned(current.id, {
    signatureData,
    ip: clientIp(req),
    location: 'In-person (kiosk)',
    browserInfo: req.headers['user-agent'] || 'Kiosk',
    geoCoords: '',
    fieldValues: fieldValues || {},
  });
  if (!signed) return res.status(409).json({ error: 'Already signed' });

  // Check if all done
  if (signerOps.allSigned(doc.id)) {
    docOps.updateStatus(doc.id, 'completed');
    // Generate final PDF (reuse existing logic)
    try { await generateFinalPdf(doc.id); } catch (e) { console.error('Kiosk final PDF error:', e.message); }
    fireWebhooks(doc.created_by, 'document.completed', { document: { uuid: doc.uuid, title: doc.title } });
    return res.json({ ok: true, allSigned: true, nextSigner: null });
  }

  const nextSigner = signers.find(s => s.status !== 'signed' && s.id !== current.id);
  res.json({ ok: true, allSigned: false, nextSigner: nextSigner ? { name: nextSigner.name } : null });
});

// Enable kiosk mode on existing document creation
app.post('/api/documents/create-kiosk', requireAuth, requireRole('admin', 'member'), (req, res, next) => {
  // Flag the request as kiosk — the create handler will pick it up
  req.kioskMode = true;
  next();
}, (req, res, next) => {
  upload.single('pdf')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    next();
  });
}, async (req, res) => {
  try {
    const pdfBuffer = req.file?.buffer;
    if (!pdfBuffer || !pdfBuffer.length) return res.status(400).json({ error: 'No PDF uploaded' });

    const title = sanitize(req.body.title || req.file.originalname || 'Untitled');
    const hash = crypto.createHash('sha256').update(pdfBuffer).digest('hex');
    const doc = docOps.create(req.session.userId, title, req.file.originalname, hash, '', 'sequential');

    // Save PDF
    fs.writeFileSync(path.join(storageDir, `${doc.uuid}.pdf`), pdfBuffer);

    // Parse signers
    let signersList;
    try { signersList = JSON.parse(req.body.signers || '[]'); } catch { return res.status(400).json({ error: 'Invalid signers JSON' }); }
    if (!signersList.length) return res.status(400).json({ error: 'At least one signer required' });

    for (let i = 0; i < signersList.length; i++) {
      const s = signersList[i];
      signerOps.addToDocument(doc.id, sanitize(s.name || `Signer ${i + 1}`), sanitize(s.email || `signer${i + 1}@kiosk.local`), i + 1, 'sign');
    }

    // Enable kiosk mode
    require('./database').db.prepare('UPDATE documents SET kiosk_mode = 1, kiosk_pin = ?, status = ? WHERE id = ?')
      .run(req.body.pin || null, 'pending', doc.id);

    // Fields
    if (req.body.fields) {
      try {
        const fields = cleanFieldList(JSON.parse(req.body.fields));
        docOps.setFields(doc.id, fields);
      } catch {}
    }

    const kioskUrl = `${BASE_URL}/kiosk/${doc.uuid}`;
    res.json({ ok: true, uuid: doc.uuid, kioskUrl });
  } catch (err) {
    console.error('Kiosk create error:', err.message);
    res.status(500).json({ error: 'Failed to create kiosk signing request' });
  }
});

// ─── Root redirect ───
app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.redirect('/login');
});

// Only bind the port when run directly — letting test suites `require()` this
// module without a port collision or an unexpected TCP listener.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`SealForge running at ${BASE_URL}`);
  });
}
