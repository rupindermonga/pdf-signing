// Minimal Twilio REST client — no SDK dependency.
// Configured via env: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM (e.g. +15551234567).
const https = require('https');
const { URLSearchParams } = require('url');

const SID = process.env.TWILIO_ACCOUNT_SID || '';
const TOKEN = process.env.TWILIO_AUTH_TOKEN || '';
const FROM = process.env.TWILIO_FROM || '';

function isConfigured() { return !!(SID && TOKEN && FROM); }

function sendSMS(to, body) {
  return new Promise((resolve) => {
    if (!isConfigured()) return resolve({ ok: false, error: 'Twilio not configured' });
    if (!to || !/^\+?\d{7,15}$/.test(to.replace(/\s/g, ''))) {
      return resolve({ ok: false, error: 'Invalid phone' });
    }
    const params = new URLSearchParams({ To: to, From: FROM, Body: body }).toString();
    const auth = Buffer.from(`${SID}:${TOKEN}`).toString('base64');
    const req = https.request({
      hostname: 'api.twilio.com',
      path: `/2010-04-01/Accounts/${SID}/Messages.json`,
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + auth,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(params),
      },
      timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', (d) => data += d);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve({ ok: true });
        else { try { const j = JSON.parse(data); resolve({ ok: false, error: j.message || 'Twilio ' + res.statusCode }); } catch { resolve({ ok: false, error: 'Twilio ' + res.statusCode }); } }
      });
    });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'Twilio timeout' }); });
    req.write(params);
    req.end();
  });
}

async function sendSigningLinkSMS(phone, signerName, senderName, docTitle, signUrl) {
  const body = `${senderName} sent you a document to sign on DocSeal: "${docTitle}". Sign here: ${signUrl}`;
  return sendSMS(phone, body);
}

async function sendOTPSMS(phone, otp) {
  return sendSMS(phone, `Your DocSeal verification code: ${otp} (expires in 10 min). Do not share this code.`);
}

async function sendCompletionSMS(phone, docTitle) {
  return sendSMS(phone, `Your DocSeal document "${docTitle}" has been fully signed by all parties.`);
}

module.exports = { isConfigured, sendSigningLinkSMS, sendOTPSMS, sendCompletionSMS };
