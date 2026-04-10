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

const { userOps, otpOps, sessionOps, docOps, signerOps } = require('./database');
const email = require('./email');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const IS_DEV = process.env.NODE_ENV !== 'production';

// ─── Security headers ───
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' https://nominatim.openstreetmap.org;");
  next();
});

// ─── Middleware ───
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'docseal-dev',
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
    // Use socket address only — X-Forwarded-For is spoofable unless behind a trusted proxy
    const ip = req.socket.remoteAddress || '';
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

// P12 Certificate
const certPath = path.join(__dirname, 'cert', 'docseal.p12');
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

// ─── Sanitize input (strip HTML tags) ───
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '');
}

// ─── Auth middleware ───
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (req.headers.accept?.includes('json')) return res.status(401).json({ error: 'Not authenticated' });
  res.redirect('/login');
}

// ─── Auth Routes ───
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/auth/send-otp', rateLimit(60000, 5), async (req, res) => {
  const { email: userEmail } = req.body;
  if (!userEmail) return res.status(400).json({ error: 'Email required' });

  const otp = otpOps.create(userEmail);

  const sent = await email.sendLoginOTP(userEmail, otp);
  if (!sent && IS_DEV) {
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

  // Regenerate session to prevent session fixation
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.userId = user.id;
    req.session.userEmail = user.email;
    req.session.userName = user.name || cleanName;
    res.json({ ok: true, redirect: '/dashboard' });
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// ─── Dashboard ───
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/api/documents', requireAuth, (req, res) => {
  const docs = docOps.listByUser(req.session.userId);
  const enriched = docs.map(doc => {
    const signers = signerOps.listByDocument(doc.id);
    const signed = signers.filter(s => s.status === 'signed').length;
    return { ...doc, signers, signedCount: signed, totalSigners: signers.length };
  });
  res.json({ documents: enriched, user: { email: req.session.userEmail, name: req.session.userName } });
});

// ─── Create Signing Request ───
app.get('/send', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'send.html'));
});

app.post('/api/documents/create', requireAuth, (req, res, next) => {
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

    const { title, message, signers } = req.body;
    const parsedSigners = JSON.parse(signers || '[]');
    if (!parsedSigners.length) return res.status(400).json({ error: 'At least one signer required' });

    // Sanitize all user inputs
    const cleanTitle = sanitize(title) || sanitize(req.file.originalname);
    const cleanMessage = sanitize(message);
    const cleanSigners = parsedSigners.map(s => ({ name: sanitize(s.name), email: sanitize(s.email).toLowerCase() }));

    // Sanitize original filename
    const cleanFilename = sanitize(req.file.originalname).replace(/[^\w.\-() ]/g, '_');

    // Hash original PDF
    const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

    // Create document record
    const doc = docOps.create(req.session.userId, cleanTitle, cleanFilename, hash, cleanMessage);

    // Save PDF file
    fs.writeFileSync(path.join(storageDir, `${doc.uuid}.pdf`), req.file.buffer);

    // Add signers
    for (let i = 0; i < cleanSigners.length; i++) {
      const s = cleanSigners[i];
      signerOps.addToDocument(doc.id, s.name, s.email, i + 1);
    }

    // Set status to pending and send to first signer
    docOps.updateStatus(doc.id, 'pending');
    await sendToNextSigner(doc.id);

    res.json({ ok: true, uuid: doc.uuid });
  } catch (err) {
    console.error('Create document error:', err);
    console.error('Document create error:', err);
    res.status(500).json({ error: 'Failed to create document. Please try again.' });
  }
});

// ─── Send to next pending signer ───
async function sendToNextSigner(documentId) {
  const next = signerOps.getNextPending(documentId);
  if (!next) return;

  const doc = docOps.findById(documentId);
  const creator = userOps.findByEmail(doc.created_by === 0 ? '' : '');
  // get creator info
  const creatorUser = require('./database').db.prepare('SELECT * FROM users WHERE id = ?').get(doc.created_by);

  signerOps.updateStatus(next.id, 'sent');
  const signUrl = `${BASE_URL}/sign/${next.token}`;

  const sent = await email.sendSigningRequest(
    next.email, next.name,
    creatorUser?.name || creatorUser?.email || 'Someone',
    doc.title, signUrl, doc.message
  );

  // Return the sign URL for dashboard display regardless
  return { signUrl, sent, signer: next };
}

// ─── Signer Experience ───
app.get('/sign/:token', (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).send('Signing link not found or expired.');
  if (signer.status === 'signed') return res.send('You have already signed this document.');
  if (signer.doc_status === 'completed') return res.send('This document has already been completed.');
  res.sendFile(path.join(__dirname, 'public', 'sign.html'));
});

app.get('/api/sign/:token/info', (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  res.json({
    signerName: signer.name,
    signerEmail: signer.email,
    docTitle: signer.doc_title,
    docUUID: signer.doc_uuid,
    status: signer.status,
    emailConfigured: email.isConfigured(),
  });
});

app.post('/api/sign/:token/send-otp', rateLimit(60000, 5), async (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  if (signer.status !== 'sent') return res.status(403).json({ error: 'It is not your turn to sign yet' });

  const otp = signerOps.setOTP(signer.id);
  const sent = await email.sendSignerOTP(signer.email, signer.name, otp);

  if (!sent && IS_DEV) return res.json({ ok: true, devOtp: otp });
  if (!sent) return res.status(500).json({ error: 'Email delivery failed' });
  res.json({ ok: true });
});

app.post('/api/sign/:token/verify-otp', rateLimit(60000, 10), (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
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

app.post('/api/sign/:token/submit', async (req, res) => {
  const signer = signerOps.findByToken(req.params.token);
  if (!signer) return res.status(404).json({ error: 'Not found' });
  if (signer.status === 'signed') return res.status(400).json({ error: 'Already signed' });
  if (signer.status !== 'sent') return res.status(403).json({ error: 'It is not your turn to sign yet' });

  if (!req.session.verifiedSigners?.[req.params.token]) {
    return res.status(403).json({ error: 'Email not verified' });
  }

  const { signatureData, location, browserInfo, geoCoords } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';

  const signed = signerOps.markSigned(signer.id, {
    signatureData: sanitize(signatureData || ''),
    ip: ip.replace('::ffff:', '').replace('::1', '127.0.0.1'),
    location: sanitize(location || ''),
    browserInfo: sanitize(browserInfo || ''),
    geoCoords: sanitize(geoCoords || ''),
  });
  if (!signed) return res.status(409).json({ error: 'Signature already recorded (concurrent request)' });

  // Check if all signers are done
  if (signerOps.allSigned(signer.document_id)) {
    docOps.updateStatus(signer.document_id, 'completed');
    // Generate final signed PDF
    await generateFinalPdf(signer.document_id);
    // Notify all parties
    const doc = docOps.findById(signer.document_id);
    const allSigners = signerOps.listByDocument(signer.document_id);
    const creator = require('./database').db.prepare('SELECT * FROM users WHERE id = ?').get(doc.created_by);
    await email.sendCompletionNotice(creator.email, creator.name, doc.title, doc.uuid);
    for (const s of allSigners) {
      await email.sendCompletionNotice(s.email, s.name, doc.title, doc.uuid);
    }
    return res.json({ ok: true, completed: true });
  }

  // Send to next signer
  await sendToNextSigner(signer.document_id);
  res.json({ ok: true, completed: false });
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
  ap.drawText('Doc', { x: 40, y: h - 52, size: 24, font: fontBold, color: rgb(1,1,1) });
  ap.drawText('Seal', { x: 40 + fontBold.widthOfTextAtSize('Doc', 24), y: h - 52, size: 24, font: fontBold, color: rgb(0.5,0.72,1) });
  ap.drawText('Certificate of Signing', { x: 40 + fontBold.widthOfTextAtSize('DocSeal', 24) + 20, y: h - 50, size: 16, font, color: rgb(0.85,0.9,1) });

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

  section('VERIFICATION', [
    ['Verify URL:', 'https://rupindermonga.github.io/pdf-signing/'],
    ['Digital Sig:', 'PKCS#7 X.509 Certificate'],
  ]);

  ap.drawLine({ start: { x: 40, y: 55 }, end: { x: w - 40, y: 55 }, thickness: 0.5, color: rgb(0.7,0.7,0.7) });
  ap.drawText('This document was digitally signed using DocSeal. Verify at: https://rupindermonga.github.io/pdf-signing/', { x: 40, y: 40, size: 7, font, color: rgb(0.5,0.5,0.5) });

  // Save stamped PDF
  const stampedBytes = await pdfDoc.save({ useObjectStreams: false });

  // PKI sign
  let finalBytes = stampedBytes;
  if (p12Buffer) {
    try {
      const pdfForSign = await PDFDocument.load(stampedBytes);
      pdflibAddPlaceholder({ pdfDoc: pdfForSign, reason: 'All parties signed', name: 'DocSeal', location: '' });
      const withPlaceholder = await pdfForSign.save({ useObjectStreams: false });
      const signer = new P12Signer(p12Buffer, { passphrase: process.env.P12_PASSPHRASE || 'docseal' });
      const signPdf = new SignPdf();
      finalBytes = await signPdf.sign(withPlaceholder, signer);
    } catch (e) {
      console.error('PKI signing failed for final PDF:', e.message);
    }
  }

  // Save final
  fs.writeFileSync(path.join(storageDir, `${doc.uuid}_signed.pdf`), Buffer.from(finalBytes));
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
    status: s.status,
    signed_at: s.signed_at,
    ip_address: s.ip_address,
    location: s.location,
    browser_info: s.browser_info,
    // Only expose sign URL if email is not configured AND signer is currently active
    signUrl: (!email.isConfigured() && (s.status === 'sent' || s.status === 'pending'))
      ? `${BASE_URL}/sign/${s.token}` : undefined,
  }));
  res.json({ document: doc, signers: safeSigner, emailConfigured: email.isConfigured() });
});

// ─── QR Code ───
app.post('/api/qr', requireAuth, async (req, res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error: 'No data' });
    const qr = await QRCode.toDataURL(data, { errorCorrectionLevel: 'M', margin: 1, width: 200, color: { dark: '#1a3b7a', light: '#ffffff' } });
    res.json({ qr });
  } catch { res.status(500).json({ error: 'QR failed' }); }
});

// ─── IP ───
app.get('/api/ip', (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').replace('::ffff:', '').replace('::1', '127.0.0.1');
  res.json({ ip });
});

// ─── Verify page ───
app.get('/verify', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'verify.html'));
});

// ─── Solo sign page (original feature) ───
app.get('/solo', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'solo.html'));
});

// ─── Root redirect ───
app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`DocSeal running at ${BASE_URL}`);
});
