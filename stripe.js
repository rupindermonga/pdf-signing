// Minimal Stripe REST client — no SDK dependency.
// Configured via env:
//   STRIPE_SECRET_KEY     sk_test_... or sk_live_... (required for API calls)
//   STRIPE_WEBHOOK_SECRET whsec_...                  (required for webhook verification)
const https = require('https');
const crypto = require('crypto');
const { URLSearchParams } = require('url');

const SECRET = process.env.STRIPE_SECRET_KEY || '';

function isConfigured() { return !!SECRET; }

function form(obj, prefix) {
  // Encode nested params using Stripe's bracket convention: foo[bar]=baz
  const params = new URLSearchParams();
  function walk(o, prefix) {
    for (const k in o) {
      const v = o[k]; const key = prefix ? `${prefix}[${k}]` : k;
      if (v == null) continue;
      if (typeof v === 'object' && !Array.isArray(v)) walk(v, key);
      else if (Array.isArray(v)) v.forEach((it, i) => {
        if (typeof it === 'object') walk(it, `${key}[${i}]`);
        else params.append(`${key}[${i}]`, String(it));
      });
      else params.append(key, String(v));
    }
  }
  walk(obj);
  return params.toString();
}

function call(path, method, body) {
  return new Promise((resolve, reject) => {
    if (!SECRET) return reject(new Error('STRIPE_SECRET_KEY not configured'));
    const payload = body ? form(body) : '';
    const req = https.request({
      hostname: 'api.stripe.com',
      path,
      method,
      headers: {
        'Authorization': 'Bearer ' + SECRET,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 15000,
    }, (res) => {
      let data = '';
      res.on('data', (d) => data += d);
      res.on('end', () => {
        try {
          const json = data ? JSON.parse(data) : {};
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(json);
          else reject(new Error(json.error?.message || `Stripe ${res.statusCode}`));
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Stripe request timeout')); });
    if (payload) req.write(payload);
    req.end();
  });
}

async function createCheckoutSession({ amountCents, currency, description, signerEmail, successUrl, cancelUrl }) {
  return call('/v1/checkout/sessions', 'POST', {
    mode: 'payment',
    payment_method_types: ['card'],
    customer_email: signerEmail,
    line_items: [{
      price_data: {
        currency: (currency || 'CAD').toLowerCase(),
        product_data: { name: description || 'Document signing payment' },
        unit_amount: amountCents,
      },
      quantity: 1,
    }],
    success_url: successUrl,
    cancel_url: cancelUrl,
  });
}

async function retrieveSession(sessionId) {
  return call('/v1/checkout/sessions/' + encodeURIComponent(sessionId), 'GET');
}

// Verify Stripe webhook signature. Header format: "t=<unix>,v1=<hex>[,v1=<hex>...]"
// REQUIRES the raw request body (Buffer or string) — not the JSON-parsed object.
// Rejects payloads older than `toleranceSeconds` (default 5 min) to block replay.
function verifyWebhookSignature(rawBody, signatureHeader, secret, toleranceSeconds = 300) {
  const webhookSecret = secret || process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret || !signatureHeader) return false;
  const parts = { v1: [] };
  for (const kv of String(signatureHeader).split(',')) {
    const eq = kv.indexOf('=');
    if (eq < 0) continue;
    const k = kv.slice(0, eq).trim();
    const v = kv.slice(eq + 1).trim();
    if (k === 'v1') parts.v1.push(v);
    else if (k === 't') parts.t = v;
  }
  const ts = parseInt(parts.t, 10);
  if (!ts || !parts.v1.length) return false;
  // Replay protection
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > toleranceSeconds) return false;

  const payload = rawBody instanceof Buffer ? rawBody : Buffer.from(String(rawBody), 'utf8');
  const signedPayload = Buffer.concat([Buffer.from(String(ts) + '.', 'utf8'), payload]);
  const expectedHex = crypto.createHmac('sha256', webhookSecret).update(signedPayload).digest('hex');
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  for (const v1 of parts.v1) {
    let candidate;
    try { candidate = Buffer.from(v1, 'hex'); } catch { continue; }
    if (candidate.length !== expectedBuf.length) continue;
    if (crypto.timingSafeEqual(candidate, expectedBuf)) return true;
  }
  return false;
}

module.exports = { isConfigured, createCheckoutSession, retrieveSession, verifyWebhookSignature };
