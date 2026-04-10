const nodemailer = require('nodemailer');

let transporter = null;

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

const FROM_NAME = process.env.FROM_NAME || 'DocSeal';
const FROM_EMAIL = process.env.FROM_EMAIL || process.env.SMTP_USER || 'noreply@docseal.app';

async function sendLoginOTP(toEmail, otp) {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: `Your DocSeal login code: ${otp}`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Doc</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Seal</span>
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
    subject: `Your verification code: ${otp}`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Doc</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Seal</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>Hi ${signerName},</p>
          <p>Enter this code to verify your identity before signing:</p>
          <div style="font-size:32px;font-weight:700;color:#1a3b7a;letter-spacing:4px;text-align:center;padding:16px;background:#f5f7fa;border-radius:8px;margin:16px 0;">${otp}</div>
          <p style="color:#666;font-size:13px;">This code expires in 10 minutes.</p>
        </div>
      </div>`,
  });
  return true;
}

async function sendSigningRequest(toEmail, signerName, senderName, docTitle, signUrl, message) {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: `${senderName} requested your signature: ${docTitle}`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Doc</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Seal</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>Hi ${signerName},</p>
          <p><strong>${senderName}</strong> has requested your signature on:</p>
          <div style="background:#f5f7fa;padding:14px;border-radius:8px;margin:16px 0;">
            <div style="font-weight:600;color:#1a3b7a;">${docTitle}</div>
            ${message ? `<div style="color:#666;font-size:13px;margin-top:6px;">"${message}"</div>` : ''}
          </div>
          <a href="${signUrl}" style="display:inline-block;background:#1a3b7a;color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:600;">Review & Sign</a>
          <p style="color:#666;font-size:13px;margin-top:16px;">You will be asked to verify your email before signing.</p>
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
          <span style="color:#fff;font-size:24px;font-weight:800;">Doc</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Seal</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>Hi ${recipientName},</p>
          <div style="background:#e8f5e9;border:1px solid #66bb6a;padding:14px;border-radius:8px;margin:16px 0;color:#2e7d32;">
            <strong>All signatures have been collected</strong> for "${docTitle}".
          </div>
          <p style="font-size:13px;color:#666;">Document ID: ${docUUID}</p>
          <p style="font-size:13px;color:#666;">Log in to your DocSeal dashboard to download the signed document.</p>
        </div>
      </div>`,
  });
  return true;
}

module.exports = { init, isConfigured, sendLoginOTP, sendSignerOTP, sendSigningRequest, sendCompletionNotice };
