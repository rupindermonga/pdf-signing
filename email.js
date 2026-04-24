const nodemailer = require('nodemailer');
const { t } = require('./i18n-server');

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

// `lang` is an optional 2-letter code ('en' | 'fr' | 'hi'). Defaults to 'en'.
async function sendLoginOTP(toEmail, otp, lang = 'en') {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: t(lang, 'email.login_subject'),
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>${esc(t(lang, 'email.login_body'))}</p>
          <div style="font-size:32px;font-weight:700;color:#1a3b7a;letter-spacing:4px;text-align:center;padding:16px;background:#f5f7fa;border-radius:8px;margin:16px 0;">${otp}</div>
          <p style="color:#666;font-size:13px;">${esc(t(lang, 'email.login_expire'))}</p>
        </div>
      </div>`,
  });
  return true;
}

async function sendSignerOTP(toEmail, signerName, otp, lang = 'en') {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: t(lang, 'email.signer_subject'),
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>${esc(t(lang, 'email.signer_hi', { name: signerName }))}</p>
          <p>${esc(t(lang, 'email.signer_body'))}</p>
          <div style="font-size:32px;font-weight:700;color:#1a3b7a;letter-spacing:4px;text-align:center;padding:16px;background:#f5f7fa;border-radius:8px;margin:16px 0;">${otp}</div>
          <p style="color:#666;font-size:13px;">${esc(t(lang, 'email.signer_expire'))}</p>
        </div>
      </div>`,
  });
  return true;
}

async function sendSigningRequest(toEmail, signerName, senderName, docTitle, signUrl, message, brand, lang = 'en') {
  if (!transporter) return false;
  const color = (brand && brand.color) || '#1a3b7a';
  await transporter.sendMail({
    from: fromField(brand),
    to: toEmail,
    subject: t(lang, 'email.request_subject', { sender: senderName, title: docTitle }),
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        ${brandHeader(brand)}
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>${esc(t(lang, 'email.signer_hi', { name: signerName }))}</p>
          <p>${t(lang, 'email.request_body', { sender: esc(senderName) })}</p>
          <div style="background:#f5f7fa;padding:14px;border-radius:8px;margin:16px 0;">
            <div style="font-weight:600;color:${esc(color)};">${esc(docTitle)}</div>
            ${message ? `<div style="color:#666;font-size:13px;margin-top:6px;">"${esc(message)}"</div>` : ''}
          </div>
          <a href="${esc(signUrl)}" style="display:inline-block;background:${esc(color)};color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:600;">${esc(t(lang, 'email.request_button'))}</a>
          <p style="color:#666;font-size:13px;margin-top:16px;">${esc(t(lang, 'email.request_note'))}</p>
          ${brandFooter(brand)}
        </div>
      </div>`,
  });
  return true;
}

async function sendCompletionNotice(toEmail, recipientName, docTitle, docUUID, lang = 'en') {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: t(lang, 'email.complete_subject', { title: docTitle }),
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>${esc(t(lang, 'email.signer_hi', { name: recipientName }))}</p>
          <div style="background:#e8f5e9;border:1px solid #66bb6a;padding:14px;border-radius:8px;margin:16px 0;color:#2e7d32;">
            <strong>${esc(t(lang, 'email.complete_body', { title: docTitle }))}</strong>
          </div>
          <p style="font-size:13px;color:#666;">Document ID: ${docUUID}</p>
        </div>
      </div>`,
  });
  return true;
}

async function sendReminder(toEmail, signerName, senderName, docTitle, signUrl, expiresAt, brand, lang = 'en') {
  if (!transporter) return false;
  const expiryLine = expiresAt
    ? `<p style="color:#c62828;font-size:13px;margin:12px 0;"><strong>${esc(t(lang, 'email.expiry_note', { date: String(expiresAt).slice(0, 10) }))}</strong></p>`
    : '';
  await transporter.sendMail({
    from: fromField(brand),
    to: toEmail,
    subject: t(lang, 'email.reminder_subject', { title: docTitle }),
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>${esc(t(lang, 'email.signer_hi', { name: signerName }))}</p>
          <p>${t(lang, 'email.reminder_body', { sender: esc(senderName) })}</p>
          <div style="background:#f5f7fa;padding:14px;border-radius:8px;margin:16px 0;">
            <div style="font-weight:600;color:#1a3b7a;">${esc(docTitle)}</div>
          </div>
          <a href="${esc(signUrl)}" style="display:inline-block;background:#1a3b7a;color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:600;">${esc(t(lang, 'email.request_button'))}</a>
          ${expiryLine}
        </div>
      </div>`,
  });
  return true;
}

async function sendExpiredNotice(toEmail, ownerName, docTitle, docUUID, lang = 'en') {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: t(lang, 'email.expired_subject', { title: docTitle }),
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#1a3b7a;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#7eb8ff;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>${esc(t(lang, 'email.signer_hi', { name: ownerName }))}</p>
          <div style="background:#fff3e0;border:1px solid #ff9800;padding:14px;border-radius:8px;margin:16px 0;color:#6d4c00;">
            ${t(lang, 'email.expired_body', { title: esc(docTitle) })}
          </div>
          <p style="font-size:13px;color:#666;">Document ID: ${docUUID}</p>
        </div>
      </div>`,
  });
  return true;
}

async function sendDeclineNotice(toEmail, ownerName, docTitle, signerName, reason, lang = 'en') {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: t(lang, 'email.decline_subject', { signer: signerName, title: docTitle }),
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        <div style="background:#c62828;padding:16px 24px;border-radius:8px 8px 0 0;">
          <span style="color:#fff;font-size:24px;font-weight:800;">Seal</span><span style="color:#ffb3b3;font-size:24px;font-weight:600;">Forge</span>
        </div>
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>${esc(t(lang, 'email.signer_hi', { name: ownerName }))}</p>
          <div style="background:#ffebee;border:1px solid #ef5350;padding:14px;border-radius:8px;margin:16px 0;color:#c62828;">
            ${t(lang, 'email.decline_body', { signer: esc(signerName), title: esc(docTitle) })}
          </div>
          <p style="font-size:13px;color:#555;"><b>${esc(t(lang, 'email.decline_reason'))}</b></p>
          <div style="background:#f5f7fa;padding:12px;border-radius:6px;font-size:13px;color:#333;white-space:pre-wrap;">${esc(reason)}</div>
        </div>
      </div>`,
  });
  return true;
}

async function sendReassignNotice(toEmail, ownerName, docTitle, fromName, toName, toEmailAddr, lang = 'en') {
  if (!transporter) return false;
  await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to: toEmail,
    subject: `Reassigned: ${fromName} forwarded "${docTitle}" to ${toName}`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        ${brandHeader(null)}
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>${esc(t(lang, 'email.signer_hi', { name: ownerName }))}</p>
          <div style="background:#fff3e0;border:1px solid #ff9800;padding:14px;border-radius:8px;margin:16px 0;color:#6d4c00;">
            <strong>${esc(fromName)}</strong> reassigned their signing task on <strong>"${esc(docTitle)}"</strong> to:
            <div style="margin-top:8px;">${esc(toName)} &lt;${esc(toEmailAddr)}&gt;</div>
          </div>
        </div>
      </div>`,
  });
  return true;
}

async function sendInvite(toEmail, opts, brand, lang = 'en') {
  if (!transporter) return false;
  const { orgName, inviterName, role, url } = opts;
  const color = (brand && brand.color) || '#1a3b7a';
  await transporter.sendMail({
    from: fromField(brand),
    to: toEmail,
    subject: t(lang, 'email.invite_subject', { inviter: inviterName, org: orgName }),
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
        ${brandHeader(brand)}
        <div style="padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
          <p>${esc(t(lang, 'email.signer_hi', { name: '' }))}</p>
          <p>${t(lang, 'email.invite_body', { inviter: esc(inviterName), org: esc(orgName), role: esc(role) })}</p>
          <div style="text-align:center;margin:24px 0;">
            <a href="${esc(url)}" style="display:inline-block;background:${esc(color)};color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:600;">${esc(t(lang, 'email.invite_button'))}</a>
          </div>
          <p style="color:#666;font-size:13px;">${esc(t(lang, 'email.invite_note'))}</p>
          ${brandFooter(brand)}
        </div>
      </div>`,
  });
  return true;
}

module.exports = { init, isConfigured, sendLoginOTP, sendSignerOTP, sendSigningRequest, sendCompletionNotice, sendReminder, sendExpiredNotice, sendDeclineNotice, sendReassignNotice, sendInvite };
