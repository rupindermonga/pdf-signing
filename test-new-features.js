/**
 * SealForge New Features Dynamic Test Suite
 * Tests: RBAC, MFA/TOTP, Kiosk, Zapier API, CSP Nonce
 * Server must be running on localhost:3000
 */
const http = require('http');

function req(method, path, body, cookie) {
  return new Promise((resolve) => {
    const opts = { hostname: 'localhost', port: 3000, method, path, headers: { 'Content-Type': 'application/json' } };
    if (cookie) opts.headers.Cookie = cookie;
    const r = http.request(opts, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        let json;
        try { json = JSON.parse(data); } catch { json = null; }
        resolve({ status: res.statusCode, headers: res.headers, json, raw: data, cookies: res.headers['set-cookie'] });
      });
    });
    r.on('error', e => resolve({ status: 0, error: e.message }));
    if (body) r.write(JSON.stringify(body));
    r.end();
  });
}

let passed = 0, failed = 0;
const failures = [];
function t(name, cond, detail) {
  const ok = !!cond;
  const icon = ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
  console.log('  [' + icon + '] ' + name + (detail ? ' \u2014 ' + detail : ''));
  if (ok) passed++; else { failed++; failures.push({ name, detail }); }
}

async function main() {
  console.log('\n\x1b[1m\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\x1b[0m');
  console.log('\x1b[1m  SealForge New Features Dynamic Tests\x1b[0m');
  console.log('\x1b[1m\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\x1b[0m');

  // ─── Login to get session ───
  console.log('\n\x1b[1m[1] AUTH + RBAC\x1b[0m');
  const otpResp = await req('POST', '/api/auth/send-otp', { email: 'newfeature-test@sealforge.test' });
  const otp = otpResp.json && otpResp.json.devOtp;
  t('OTP received for test', !!otp);

  const loginResp = await req('POST', '/api/auth/verify-otp', { email: 'newfeature-test@sealforge.test', code: otp, name: 'Feature Tester' });
  const cookie = loginResp.cookies && loginResp.cookies[0] ? loginResp.cookies[0].split(';')[0] : '';
  t('Login successful', loginResp.json && loginResp.json.ok && cookie);

  // ─── /api/auth/me ───
  const meResp = await req('GET', '/api/auth/me', null, cookie);
  t('/api/auth/me returns user info', meResp.json && meResp.json.email === 'newfeature-test@sealforge.test');
  t('Role is assigned', meResp.json && ['admin', 'member'].includes(meResp.json.role), 'role=' + (meResp.json && meResp.json.role));

  // ─── RBAC: Admin routes ───
  console.log('\n\x1b[1m[2] ADMIN PANEL\x1b[0m');
  const usersResp = await req('GET', '/api/admin/users', null, cookie);
  if (usersResp.status === 200) {
    t('Admin users list accessible', Array.isArray(usersResp.json && usersResp.json.users));
    t('Users list contains users', usersResp.json && usersResp.json.users && usersResp.json.users.length > 0, (usersResp.json.users ? usersResp.json.users.length : 0) + ' user(s)');
  } else {
    t('Admin routes require admin role (403 for non-admin)', usersResp.status === 403);
  }

  // ─── RBAC: Unauthenticated admin ───
  const unauthedAdmin = await req('GET', '/api/admin/users');
  t('Admin users list blocked without auth', unauthedAdmin.status === 401 || unauthedAdmin.status === 302);

  // ─── Delete self blocked ───
  if (meResp.json && meResp.json.id) {
    const deleteSelf = await req('DELETE', '/api/admin/users/' + meResp.json.id, null, cookie);
    t('Cannot delete yourself', deleteSelf.status === 400 || deleteSelf.status === 403);
  }

  // ─── TOTP status ───
  console.log('\n\x1b[1m[3] MFA / TOTP\x1b[0m');
  const totpStatus = await req('GET', '/api/settings/totp/status', null, cookie);
  t('TOTP status endpoint works', totpStatus.status === 200);
  t('TOTP initially disabled', totpStatus.json && totpStatus.json.enabled === false);

  // Setup TOTP
  const totpSetup = await req('POST', '/api/settings/totp/setup', {}, cookie);
  t('TOTP setup returns URI', totpSetup.json && totpSetup.json.uri && totpSetup.json.uri.startsWith('otpauth://'));
  t('TOTP setup returns base32 secret', totpSetup.json && typeof totpSetup.json.secret === 'string' && totpSetup.json.secret.length > 10);
  t('TOTP URI contains SealForge issuer', totpSetup.json && totpSetup.json.uri && totpSetup.json.uri.includes('SealForge'));

  // Confirm with wrong code
  const badConfirm = await req('POST', '/api/settings/totp/confirm', { code: '000000' }, cookie);
  t('TOTP confirm rejects wrong code', badConfirm.status === 400);

  // Disable before enable
  const badDisable = await req('POST', '/api/settings/totp/disable', { code: '000000' }, cookie);
  t('TOTP disable fails when not enabled', badDisable.status === 400);

  // Verify TOTP without pending session
  const noPending = await req('POST', '/api/auth/verify-totp', { code: '123456' });
  t('TOTP verify without pending session rejected', noPending.status === 400);

  // ─── Kiosk mode ───
  console.log('\n\x1b[1m[4] KIOSK / IN-PERSON SIGNING\x1b[0m');
  const kioskInfo = await req('GET', '/api/kiosk/FAKE-UUID/info');
  t('Kiosk info 404 for non-existent doc', kioskInfo.status === 404);

  const kioskPdf = await req('GET', '/api/kiosk/FAKE-UUID/pdf');
  t('Kiosk PDF 404 for non-existent doc', kioskPdf.status === 404);

  const kioskSubmit = await req('POST', '/api/kiosk/FAKE-UUID/submit', { signatureData: 'test' });
  t('Kiosk submit 404 for non-existent doc', kioskSubmit.status === 404);

  const kioskPage = await req('GET', '/kiosk/FAKE-UUID');
  t('Kiosk page 404 for non-existent doc', kioskPage.status === 404);

  // ─── Zapier / Event API ───
  console.log('\n\x1b[1m[5] ZAPIER / WEBHOOK API\x1b[0m');
  const noKeyWebhooks = await req('GET', '/api/v1/webhooks');
  t('API v1 webhooks requires Bearer token', noKeyWebhooks.status === 401);

  const noKeyEvents = await req('GET', '/api/v1/events');
  t('API v1 events requires Bearer token', noKeyEvents.status === 401);

  const noKeyWebhookCreate = await req('POST', '/api/v1/webhooks', { url: 'https://example.com/hook' });
  t('API v1 webhook create requires Bearer token', noKeyWebhookCreate.status === 401);

  const noKeyWebhookDelete = await req('DELETE', '/api/v1/webhooks/1');
  t('API v1 webhook delete requires Bearer token', noKeyWebhookDelete.status === 401);

  // ─── CSP Nonce ───
  console.log('\n\x1b[1m[6] CSP NONCE INJECTION\x1b[0m');
  const loginPage = await req('GET', '/login');
  const csp = loginPage.headers['content-security-policy'] || '';
  t('CSP header present', csp.length > 50);
  t('No unsafe-inline in CSP', !csp.includes("'unsafe-inline'"));
  t('CSP has nonce directive', csp.includes('nonce-'));

  const hasNonce = loginPage.raw && loginPage.raw.includes('nonce=');
  t('HTML has nonce attributes injected', hasNonce);

  const cspMatch = csp.match(/nonce-([A-Za-z0-9+/=]+)/);
  const htmlMatch = loginPage.raw ? loginPage.raw.match(/nonce="([A-Za-z0-9+/=]+)"/) : null;
  t('HTML nonce matches CSP nonce', cspMatch && htmlMatch && cspMatch[1] === htmlMatch[1]);

  // Two requests get different nonces
  const loginPage2 = await req('GET', '/login');
  const csp2 = loginPage2.headers['content-security-policy'] || '';
  const cspMatch2 = csp2.match(/nonce-([A-Za-z0-9+/=]+)/);
  t('Different requests get different nonces', cspMatch && cspMatch2 && cspMatch[1] !== cspMatch2[1]);

  // Check all pages get nonces
  const verifyPage = await req('GET', '/verify');
  t('/verify page has nonce', verifyPage.raw && verifyPage.raw.includes('nonce='));
  const compliancePage = await req('GET', '/compliance');
  t('/compliance page has nonce', compliancePage.raw && compliancePage.raw.includes('nonce='));

  // ─── Security: New feature endpoints ───
  console.log('\n\x1b[1m[7] NEW FEATURE SECURITY\x1b[0m');
  const adminPage = await req('GET', '/admin');
  t('/admin blocked without auth', adminPage.status === 302 || adminPage.status === 401 || adminPage.status === 403);

  // Viewer role check (try to create doc as viewer — need to simulate)
  // For now, test that settings requires admin
  const settingsUnauthed = await req('GET', '/settings');
  t('/settings blocked without auth', settingsUnauthed.status === 302 || settingsUnauthed.status === 401);

  // Rate limiting on kiosk PIN
  let pinBlocked = false;
  for (let i = 0; i < 12; i++) {
    const r = await req('POST', '/api/kiosk/FAKE-UUID/verify-pin', { pin: '0000' });
    if (r.status === 429) { pinBlocked = true; break; }
  }
  t('Kiosk PIN rate limited', pinBlocked);

  // Rate limiting on TOTP confirm
  let totpBlocked = false;
  for (let i = 0; i < 12; i++) {
    const r = await req('POST', '/api/settings/totp/confirm', { code: '000000' }, cookie);
    if (r.status === 429) { totpBlocked = true; break; }
  }
  t('TOTP confirm rate limited', totpBlocked);

  // ─── Summary ───
  console.log('\n\x1b[1m\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\x1b[0m');
  console.log('\x1b[1m  RESULTS: \x1b[32m' + passed + ' passed\x1b[0m, \x1b[31m' + failed + ' failed\x1b[0m');
  console.log('\x1b[1m\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\x1b[0m');

  if (failures.length) {
    console.log('\n\x1b[1mFAILURES:\x1b[0m');
    failures.forEach((f, i) => console.log('  ' + (i+1) + '. \x1b[31m' + f.name + '\x1b[0m' + (f.detail ? ' \u2014 ' + f.detail : '')));
  }
  console.log('');
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error('Test crash:', e); process.exit(2); });
