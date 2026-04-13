// Minimal Stripe REST client — no SDK dependency.
// Configured via env: STRIPE_SECRET_KEY (sk_test_... or sk_live_...).
const https = require('https');
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

module.exports = { isConfigured, createCheckoutSession, retrieveSession };
