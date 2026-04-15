const nodemailer = require('nodemailer');

let transporter = null;

// Escape HTML entities for safe email interpolation
function esc(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function init() {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (host && user && pass) {
    transporter = nodemailer.createTransport({
      host,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user, pass },
    });
    console.log(`Email configured: ${user} via ${host}`);
    return true;
  }

  console.log('Email NOT configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS in .env');
  console.log('Signing links will be shown in dashboard instead.');
  return false;
}

function isConfigured() {
  return transporter !== null;
}

const FROM_NAME = process.env.FROM_NAME || 'SealForge';
const FROM_EMAIL = process.env.FROM_EMAIL || process.env.SMTP_USER || 'noreply@finelai.com';

// Build a branded email header. `brand` is optional — falls back to default SealForge styling.
function brandHeader(brand) {
  const color = (brand && brand.color) || '#1a3b7a';
  if (brand && brand.logoUrl) {
    return `<div style="background:${esc(color)};padding:16px 24px;border-radius:8px 8px 0 0;text-align:center;">
      <img src="${esc(brand.logoUrl)}" alt="${esc(brand.fromName || 'Logo')}" style="max-height:40px;max-width:200px;">
    </div>`;
  }
  return `<div style="background:${esc(color)};padding:16px 24px;border-radius:8px 8px 0 0;">
    <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
  </div>`;
}

function brandFooter(brand) {
  if (brand && brand.emailFooter) {
    return `<div style="font-size:11px;color:#888;margin-top:16px;padding-top:12px;border-top:1px solid #eee;">${esc(brand.emailFooter)}</div>`;
  }
  return '';
}

function fromField(brand) {
  const name = (brand && brand.fromName) || FROM_NAME;
  // Strip quotes, CR, LF from name to prevent header injection
  const safeName = String(name).replace(/["\r\n]/g, '').slice(0, 80);
  return `"${safeName}" <${FROM_EMAIL}>`;
}

async function sendLoginOTP(toEmail, otp) {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: 'Your SealForge login verification code',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>Your login verification code is:</p>
          <div style="font-size:32px;font-weight:700;color:#1a3b7a;letter-spacing:4px;text-align:center;padding:16px;background:#f5f7fa;border-radius:8px;margin:16px 0;">${otp}</div>
          <p style="color:#666;font-size:13px;">This code expires in 10 minutes. If you didn't request this, ignore this email.</p>
        </div>
      </div>`,
  });
  return true;
}

async function sendSignerOTP(toEmail, signerName, otp) {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: 'Your SealForge verification code',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>Hi ${esc(signerName)},</p>
          <p>Enter this code to verify your identity before signing:</p>
          <div style="font-size:32px;font-weight:700;color:#1a3b7a;letter-spacing:4px;text-align:center;padding:16px;background:#f5f7fa;border-radius:8px;margin:16px 0;">${otp}</div>
          <p style="color:#666;font-size:13px;">This code expires in 10 minutes.</p>
        </div>
      </div>`,
  });
  return true;
}

async function sendSigningRequest(toEmail, signerName, senderName, docTitle, signUrl, message, brand) {
  if (!transporter) return false;
  const color = (brand && brand.color) || '#1a3b7a';
  await transporter.sendMail({
    from: fromField(brand),
    to: toEmail,
    subject: `${senderName} requested your signature: ${docTitle}`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        ${brandHeader(brand)}
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>Hi ${esc(signerName)},</p>
          <p><strong>${esc(senderName)}</strong> has requested your signature on:</p>
          <div style="background:#f5f7fa;padding:14px;border-radius:8px;margin:16px 0;">
            <div style="font-weight:600;color:${esc(color)};">${esc(docTitle)}</div>
            ${message ? `<div style="color:#666;font-size:13px;margin-top:6px;">"${esc(message)}"</div>` : ''}
          </div>
          <a href="${esc(signUrl)}" style="display:inline-block;background:${esc(color)};color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:600;">Review & Sign</a>
          <p style="color:#666;font-size:13px;margin-top:16px;">You will be asked to verify your email before signing.</p>
          ${brandFooter(brand)}
        </div>
      </div>`,
  });
  return true;
}

async function sendCompletionNotice(toEmail, recipientName, docTitle, docUUID) {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: `Completed: All signatures collected for "${docTitle}"`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>Hi ${esc(recipientName)},</p>
          <div style="background:#e8f5e9;border:1px solid #66bb6a;padding:14px;border-radius:8px;margin:16px 0;color:#2e7d32;">
            <strong>All signatures have been collected</strong> for "${esc(docTitle)}".
          </div>
          <p style="font-size:13px;color:#666;">Document ID: ${docUUID}</p>
          <p style="font-size:13px;color:#666;">Log in to your SealForge dashboard to download the signed document.</p>
        </div>
      </div>`,
  });
  return true;
}

async function sendReminder(toEmail, signerName, senderName, docTitle, signUrl, expiresAt, brand) {
  if (!transporter) return false;
  const expiryLine = expiresAt
    ? `<p style="color:#c62828;font-size:13px;margin:12px 0;"><strong>Note:</strong> This request expires on ${esc(String(expiresAt).slice(0, 10))}.</p>`
    : '';
  await transporter.sendMail({
    from: fromField(brand),
    to: toEmail,
    subject: `Reminder: Please sign "${docTitle}"`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>Hi ${esc(signerName)},</p>
          <p>This is a friendly reminder that <strong>${esc(senderName)}</strong> is still waiting for your signature on:</p>
          <div style="background:#f5f7fa;padding:14px;border-radius:8px;margin:16px 0;">
            <div style="font-weight:600;color:#1a3b7a;">${esc(docTitle)}</div>
          </div>
          <a href="${esc(signUrl)}" style="display:inline-block;background:#1a3b7a;color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:600;">Review & Sign</a>
          ${expiryLine}
        </div>
      </div>`,
  });
  return true;
}

async function sendExpiredNotice(toEmail, ownerName, docTitle, docUUID) {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: `Expired: "${docTitle}" is no longer available for signing`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>Hi ${esc(ownerName)},</p>
          <div style="background:#fff3e0;border:1px solid #ff9800;padding:14px;border-radius:8px;margin:16px 0;color:#6d4c00;">
            The signing request for "<strong>${esc(docTitle)}</strong>" has expired and was automatically cancelled.
          </div>
          <p style="font-size:13px;color:#666;">Document ID: ${docUUID}</p>
          <p style="font-size:13px;color:#666;">You can re-create the request from your SealForge dashboard.</p>
        </div>
      </div>`,
  });
  return true;
}

module.exports = { init, isConfigured, sendLoginOTP, sendSignerOTP, sendSigningRequest, sendCompletionNotice, sendReminder, sendExpiredNotice };
