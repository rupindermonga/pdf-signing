const express = require('express');
const multer = require('multer');
const QRCode = require('qrcode');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { SignPdf } = require('@signpdf/signpdf');
const { P12Signer } = require('@signpdf/signer-p12');
const { pdflibAddPlaceholder } = require('@signpdf/placeholder-pdf-lib');
const { PDFDocument } = require('pdf-lib');

const app = express();
const PORT = 3000;

// Allow large JSON bodies (PDF bytes sent from client)
app.use(express.json({ limit: '60mb' }));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Load P12 certificate
const certPath = path.join(__dirname, 'cert', 'docseal.p12');
let p12Buffer = null;
if (fs.existsSync(certPath)) {
  p12Buffer = fs.readFileSync(certPath);
  console.log('P12 certificate loaded from cert/docseal.p12');
} else {
  console.warn('WARNING: No P12 certificate found. Run "node generate-cert.js" first.');
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'));
    }
  },
  limits: { fileSize: 50 * 1024 * 1024 }
});

app.use(express.static(path.join(__dirname, 'public')));

// ─── Upload PDF ───
app.post('/upload', upload.single('pdf'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  res.json({
    filename: req.file.filename,
    originalName: req.file.originalname,
    url: `/uploads/${req.file.filename}`
  });
});

app.get('/uploads/:filename', (req, res) => {
  const filePath = path.join(uploadsDir, req.params.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  res.setHeader('Content-Type', 'application/pdf');
  res.sendFile(filePath);
});

// ─── Get client IP ───
app.get('/api/ip', (req, res) => {
  const ip = req.headers['x-forwarded-for']
    || req.connection.remoteAddress
    || req.socket.remoteAddress
    || '';
  const cleanIp = ip.replace('::ffff:', '').replace('::1', '127.0.0.1');
  res.json({ ip: cleanIp });
});

// ─── Generate QR code ───
app.post('/api/qr', async (req, res) => {
  try {
    const { data } = req.body;
    if (!data) {
      return res.status(400).json({ error: 'No data provided' });
    }
    const qrDataUrl = await QRCode.toDataURL(data, {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 200,
      color: { dark: '#1a3b7a', light: '#ffffff' }
    });
    res.json({ qr: qrDataUrl });
  } catch (err) {
    res.status(500).json({ error: 'QR generation failed' });
  }
});

// ─── PKI Sign PDF ───
app.post('/api/sign', async (req, res) => {
  try {
    const { pdfBytes } = req.body;
    if (!pdfBytes || !Array.isArray(pdfBytes)) {
      return res.status(400).json({ error: 'No PDF bytes provided' });
    }
    if (!p12Buffer) {
      return res.status(500).json({ error: 'No signing certificate available' });
    }

    const pdfBuffer = Buffer.from(pdfBytes);

    // Load PDF with pdf-lib and add signature placeholder
    const pdfDoc = await PDFDocument.load(pdfBuffer);
    pdflibAddPlaceholder({
      pdfDoc,
      reason: req.body.reason || 'Document Signing',
      contactInfo: req.body.signer || '',
      name: req.body.signer || 'DocSeal Signer',
      location: req.body.location || '',
    });
    const pdfWithPlaceholder = await pdfDoc.save({ useObjectStreams: false });

    // Sign with P12 certificate
    const signer = new P12Signer(p12Buffer, { passphrase: 'docseal' });
    const signPdf = new SignPdf();
    const signedPdf = await signPdf.sign(pdfWithPlaceholder, signer);

    // Compute hash of signed PDF
    const hash = crypto.createHash('sha256').update(signedPdf).digest('hex');

    // Return signed PDF as base64 + hash
    res.json({
      signedPdf: Buffer.from(signedPdf).toString('base64'),
      hash,
    });

  } catch (err) {
    console.error('Signing error:', err);
    res.status(500).json({ error: 'PDF signing failed: ' + err.message });
  }
});

// ─── Verify page ───
app.get('/verify', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'verify.html'));
});

// Cleanup old uploads (files older than 1 hour)
setInterval(() => {
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  fs.readdirSync(uploadsDir).forEach(file => {
    const filePath = path.join(uploadsDir, file);
    const stat = fs.statSync(filePath);
    if (stat.mtimeMs < oneHourAgo) {
      fs.unlinkSync(filePath);
    }
  });
}, 30 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`DocSeal PDF Signature app running at http://localhost:${PORT}`);
});
