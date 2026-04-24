// Minimal Razorpay REST client — no SDK dependency.
// Used for INR / UPI / NetBanking / Cards in the Indian market (Stripe isn't well-suited for
// domestic Indian transactions — Razorpay, Cashfree, PhonePe are the common choices).
//
// Config: RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET (optional).
const https = require('https');
const crypto = require('crypto');

const KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';

function isConfigured() { return !!(KEY_ID && KEY_SECRET); }

function call(path, method, body) {
  return new Promise((resolve, reject) => {
    if (!KEY_ID || !KEY_SECRET) return reject(new Error('Razorpay not configured: set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.'));
    const payload = body ? JSON.stringify(body) : '';
    const auth = Buffer.from(`${KEY_ID}:${KEY_SECRET}`).toString('base64');
    const req = https.request({
      hostname: 'api.razorpay.com',
      path,
      method,
      headers: {
        'Authorization': 'Basic ' + auth,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 15000,
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const json = data ? JSON.parse(data) : {};
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(json);
          else reject(new Error(json.error?.description || json.error?.reason || `Razorpay ${res.statusCode}`));
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Razorpay request timeout')); });
    if (payload) req.write(payload);
    req.end();
  });
}

// Razorpay uses paise (INR) — 100 paise = ₹1
async function createOrder({ amountPaise, currency, receipt, notes }) {
  return call('/v1/orders', 'POST', {
    amount: amountPaise,
    currency: currency || 'INR',
    receipt: receipt || undefined,
    notes: notes || {},
    payment_capture: 1,
  });
}

// Payment links — hosted page, sharable with signer. Simpler than Razorpay Checkout.js.
async function createPaymentLink({ amountPaise, currency, description, customerName, customerEmail, customerPhone, callbackUrl, referenceId, notes }) {
  return call('/v1/payment_links', 'POST', {
    amount: amountPaise,
    currency: currency || 'INR',
    description: description || 'Document signing payment',
    accept_partial: false,
    customer: {
      name: customerName || undefined,
      email: customerEmail || undefined,
      contact: customerPhone || undefined,
    },
    notify: { sms: !!customerPhone, email: !!customerEmail },
    callback_url: callbackUrl,
    callback_method: 'get',
    reference_id: referenceId || undefined,
    notes: notes || {},
  });
}

async function fetchPaymentLink(linkId) {
  return call('/v1/payment_links/' + encodeURIComponent(linkId), 'GET');
}

// Webhook signature verification (set RAZORPAY_WEBHOOK_SECRET in Razorpay dashboard → Webhooks)
function verifyWebhookSignature(bodyRaw, signatureHeader, secret) {
  const webhookSecret = secret || process.env.RAZORPAY_WEBHOOK_SECRET;
  if (!webhookSecret) return false;
  const expected = crypto.createHmac('sha256', webhookSecret).update(bodyRaw).digest('hex');
  if (!signatureHeader || signatureHeader.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(signatureHeader), Buffer.from(expected));
  } catch { return false; }
}

// Verify a client-side payment after Razorpay Checkout returns razorpay_payment_id / razorpay_order_id / razorpay_signature
function verifyCheckoutSignature({ orderId, paymentId, signature }) {
  if (!KEY_SECRET) return false;
  const expected = crypto.createHmac('sha256', KEY_SECRET)
    .update(orderId + '|' + paymentId).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  } catch { return false; }
}

module.exports = { isConfigured, createOrder, createPaymentLink, fetchPaymentLink, verifyWebhookSignature, verifyCheckoutSignature, KEY_ID };
