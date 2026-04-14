/**
 * SealForge QA + Security Dynamic Test Suite
 * Run: node test-security.js
 * Server must be running on localhost:3000
 */
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { signerOps, docOps, db } = require('./database');

// In production-safe mode the API does not echo OTPs. The test suite still
// needs a code to drive the auth flow, so we read it from the DB directly.
function latestOtpFor(email) {
  const row = db.prepare("SELECT code FROM otp_codes WHERE email = ? AND used = 0 ORDER BY rowid DESC LIMIT 1").get(email.toLowerCase());
  return row?.code || null;
}
function latestSignerOtp(signerId) {
  const row = db.prepare('SELECT otp FROM signers WHERE id = ?').get(signerId);
  return row?.otp || null;
}

const BASE = 'http://localhost:3000';
let passed = 0, failed = 0, warnings = 0;
const issues = [];

function log(status, test, detail) {
  const icon = status === 'PASS' ? '\x1b[32mPASS\x1b[0m' : status === 'FAIL' ? '\x1b[31mFAIL\x1b[0m' : '\x1b[33mWARN\x1b[0m';
  console.log(`  [${icon}] ${test}${detail ? ' — ' + detail : ''}`);
  if (status === 'PASS') passed++;
  else if (status === 'FAIL') { failed++; issues.push({ severity: 'FAIL', test, detail }); }
  else { warnings++; issues.push({ severity: 'WARN', test, detail }); }
}

async function req(method, urlPath, body, headers = {}, followRedirect = false) {
  return new Promise((resolve) => {
    const url = new URL(urlPath, BASE);
    const opts = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: { ...headers },
    };
    if (body && typeof body === 'object' && !(body instanceof Buffer)) {
      const json = JSON.stringify(body);
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['Content-Length'] = Buffer.byteLength(json);
      const r = http.request(opts, (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, json: () => { try { return JSON.parse(data); } catch { return null; } } }));
      });
      r.write(json);
      r.end();
    } else if (body instanceof Buffer) {
      opts.headers['Content-Length'] = body.length;
      const r = http.request(opts, (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, json: () => { try { return JSON.parse(data); } catch { return null; } } }));
      });
      r.write(body);
      r.end();
    } else {
      const r = http.request(opts, (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, json: () => { try { return JSON.parse(data); } catch { return null; } } }));
      });
      r.end();
    }
  });
}

// Multipart form helper
async function multipartReq(urlPath, fields, fileField, fileBuffer, fileName, cookie) {
  return new Promise((resolve) => {
    const boundary = '----SealForgeTest' + crypto.randomBytes(8).toString('hex');
    let body = '';
    for (const [key, val] of Object.entries(fields)) {
      body += `--${boundary}\r\nContent-Disposition: form-data; name="${key}"\r\n\r\n${val}\r\n`;
    }
    if (fileField && fileBuffer) {
      body += `--${boundary}\r\nContent-Disposition: form-data; name="${fileField}"; filename="${fileName}"\r\nContent-Type: application/pdf\r\n\r\n`;
    }
    const bodyStart = Buffer.from(body, 'utf-8');
    const bodyEnd = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf-8');
    const fullBody = fileBuffer ? Buffer.concat([bodyStart, fileBuffer, bodyEnd]) : Buffer.concat([bodyStart, bodyEnd]);

    const url = new URL(urlPath, BASE);
    const opts = {
      method: 'POST',
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': fullBody.length,
        ...(cookie ? { Cookie: cookie } : {}),
      },
    };
    const r = http.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, json: () => { try { return JSON.parse(data); } catch { return null; } } }));
    });
    r.write(fullBody);
    r.end();
  });
}

// Extract session cookie
function getCookie(res) {
  const sc = res.headers['set-cookie'];
  if (!sc) return '';
  return sc.map(c => c.split(';')[0]).join('; ');
}

// Minimal valid PDF
function makePdf() {
  return Buffer.from(`%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer<</Size 4/Root 1 0 R>>
startxref
190
%%EOF`, 'utf-8');
}

async function run() {
  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log('\x1b[1m  SealForge QA + Security Audit\x1b[0m');
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m\n');

  // ════════════════════════════════════════
  console.log('\x1b[1m[1] PAGE AVAILABILITY\x1b[0m');
  // ════════════════════════════════════════
  // Public pages
  for (const [url, expect] of [
    ['/login', 200],
    ['/verify', 200],
    ['/compliance', 200],
    ['/api/ip', 200],
  ]) {
    const r = await req('GET', url);
    r.status === expect ? log('PASS', `GET ${url}`, `${r.status}`) : log('FAIL', `GET ${url}`, `Expected ${expect}, got ${r.status}`);
  }

  // Auth-protected pages MUST redirect or return 401 (no anonymous access)
  for (const url of ['/dashboard', '/send', '/solo', '/templates', '/settings', '/bulk']) {
    const r = await req('GET', url);
    (r.status === 302 || r.status === 401) ? log('PASS', `GET ${url} (unauthed)`, `${r.status}`) : log('FAIL', `GET ${url} (unauthed)`, `Expected redirect/401, got ${r.status} — anonymous access leak!`);
  }

  // API auth check
  const r1 = await req('GET', '/api/documents', null, { Accept: 'application/json' });
  r1.status === 401 ? log('PASS', 'GET /api/documents (unauthed)', '401 Unauthorized') : log('FAIL', 'GET /api/documents (unauthed)', `Expected 401, got ${r1.status}`);

  // ════════════════════════════════════════
  console.log('\n\x1b[1m[2] AUTH FLOW\x1b[0m');
  // ════════════════════════════════════════

  // Send OTP. devOtp echoing in the response is ONLY acceptable in local dev mode.
  // In any other configuration (prod or dev with non-local BASE_URL) it must be absent.
  const otpResp = await req('POST', '/api/auth/send-otp', { email: 'test@sealforge.local' });
  const otpData = otpResp.json();
  if (!otpData?.ok) { log('FAIL', 'Send OTP', otpResp.body); }
  else {
    const isProd = process.env.NODE_ENV === 'production';
    const isLocalDev = !process.env.BASE_URL || /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(process.env.BASE_URL || `http://localhost:${(new URL(BASE)).port}`);
    if (otpData.devOtp) {
      // OTP returned — only OK if this is a true local-dev run, otherwise it's a leak.
      if (isProd || !isLocalDev) {
        log('FAIL', 'OTP leak in API response', `devOtp returned but NODE_ENV=${process.env.NODE_ENV || 'unset'} BASE_URL=${process.env.BASE_URL || 'unset'} — production OTP leakage`);
      } else {
        log('PASS', 'Send OTP (local dev mode)', 'devOtp returned for local development convenience');
      }
    } else {
      log('PASS', 'Send OTP', 'devOtp NOT echoed in response (production-safe)');
    }
  }

  // Verify with wrong code
  const wrongOtp = await req('POST', '/api/auth/verify-otp', { email: 'test@sealforge.local', code: '000000' });
  wrongOtp.status === 400 ? log('PASS', 'Wrong OTP rejected', '400') : log('FAIL', 'Wrong OTP rejected', `Got ${wrongOtp.status}`);

  // Verify with correct code
  const realOtp = otpData.devOtp || latestOtpFor('test@sealforge.local');
  const rightOtp = await req('POST', '/api/auth/verify-otp', { email: 'test@sealforge.local', code: realOtp, name: 'Test User' });
  const authCookie = getCookie(rightOtp);
  rightOtp.json()?.ok ? log('PASS', 'Correct OTP accepted', 'Session created') : log('FAIL', 'Correct OTP accepted', rightOtp.body);
  authCookie ? log('PASS', 'Session cookie set', '') : log('FAIL', 'Session cookie set', 'No cookie returned');

  // Replay same OTP
  const replayOtp = await req('POST', '/api/auth/verify-otp', { email: 'test@sealforge.local', code: realOtp });
  replayOtp.status === 400 ? log('PASS', 'OTP replay blocked', '400') : log('FAIL', 'OTP replay blocked', `Got ${replayOtp.status} — OTP can be reused!`);

  // Send OTP without email
  const noEmail = await req('POST', '/api/auth/send-otp', { email: '' });
  noEmail.status === 400 ? log('PASS', 'Empty email rejected', '400') : log('FAIL', 'Empty email rejected', `Got ${noEmail.status}`);

  // Authenticated access
  const dashApi = await req('GET', '/api/documents', null, { Accept: 'application/json', Cookie: authCookie });
  dashApi.status === 200 ? log('PASS', 'Authenticated /api/documents', '200') : log('FAIL', 'Authenticated /api/documents', `${dashApi.status}`);

  // ════════════════════════════════════════
  console.log('\n\x1b[1m[3] DOCUMENT WORKFLOW\x1b[0m');
  // ════════════════════════════════════════

  const pdf = makePdf();

  // Create document
  const createResp = await multipartReq('/api/documents/create', {
    title: 'Test Contract',
    message: 'Please sign',
    signers: JSON.stringify([{ name: 'Alice', email: 'alice@test.local' }, { name: 'Bob', email: 'bob@test.local' }]),
  }, 'pdf', pdf, 'test.pdf', authCookie);
  const createData = createResp.json();
  createData?.ok ? log('PASS', 'Create document', `UUID: ${createData.uuid}`) : log('FAIL', 'Create document', createResp.body);
  const docUUID = createData?.uuid;

  // Create without PDF
  const noPdfResp = await multipartReq('/api/documents/create', {
    title: 'No PDF', signers: JSON.stringify([{ name: 'X', email: 'x@test.local' }]),
  }, null, null, null, authCookie);
  noPdfResp.status === 400 ? log('PASS', 'Reject document without PDF', '400') : log('FAIL', 'Reject document without PDF', `Got ${noPdfResp.status}`);

  // Create without signers
  const noSignerResp = await multipartReq('/api/documents/create', {
    title: 'No Signers', signers: '[]',
  }, 'pdf', pdf, 'test.pdf', authCookie);
  noSignerResp.status === 400 ? log('PASS', 'Reject document without signers', '400') : log('FAIL', 'Reject document without signers', `Got ${noSignerResp.status}`);

  // List documents
  const listResp = await req('GET', '/api/documents', null, { Accept: 'application/json', Cookie: authCookie });
  const listData = listResp.json();
  listData?.documents?.length > 0 ? log('PASS', 'List documents', `${listData.documents.length} doc(s)`) : log('FAIL', 'List documents', 'Empty');

  // Document detail
  if (docUUID) {
    const detailResp = await req('GET', `/api/documents/${docUUID}`, null, { Accept: 'application/json', Cookie: authCookie });
    const detailData = detailResp.json();
    detailData?.document ? log('PASS', 'Document detail', `${detailData.signers?.length} signers`) : log('FAIL', 'Document detail', detailResp.body);

    // Fake UUID
    const fakeResp = await req('GET', '/api/documents/DS-FAKE-UUID-HERE', null, { Accept: 'application/json', Cookie: authCookie });
    fakeResp.status === 404 ? log('PASS', 'Fake UUID returns 404', '') : log('FAIL', 'Fake UUID returns 404', `Got ${fakeResp.status}`);
  }

  // ════════════════════════════════════════
  console.log('\n\x1b[1m[4] SIGNER FLOW\x1b[0m');
  // ════════════════════════════════════════

  // Get signer tokens directly from DB (tokens are no longer exposed via API)
  let signerToken = null;
  let signer2Token = null;
  if (docUUID) {
    const doc = docOps.findByUUID(docUUID);
    const signers = signerOps.listByDocument(doc.id);
    signerToken = signers?.[0]?.token;
    signer2Token = signers?.[1]?.token;
  }

  if (signerToken) {
    // Signer info
    const infoResp = await req('GET', `/api/sign/${signerToken}/info`);
    infoResp.json()?.signerName ? log('PASS', 'Signer info', `Name: ${infoResp.json().signerName}`) : log('FAIL', 'Signer info', infoResp.body);

    // Invalid token
    const fakeInfo = await req('GET', '/api/sign/fakefakefake/info');
    fakeInfo.status === 404 ? log('PASS', 'Fake signer token -> 404', '') : log('FAIL', 'Fake signer token -> 404', `Got ${fakeInfo.status}`);

    // PDF access without OTP
    const pdfNoOtp = await req('GET', `/api/sign/${signerToken}/pdf`);
    pdfNoOtp.status === 403 ? log('PASS', 'PDF blocked before OTP', '403') : log('FAIL', 'PDF blocked before OTP', `Got ${pdfNoOtp.status} — PDF accessible without identity verification!`);

    // Submit without OTP
    const submitNoOtp = await req('POST', `/api/sign/${signerToken}/submit`, { signatureData: 'test' });
    submitNoOtp.status === 403 ? log('PASS', 'Submit blocked before OTP', '403') : log('FAIL', 'Submit blocked before OTP', `Got ${submitNoOtp.status} — Can sign without verification!`);

    // Send signer OTP
    const sigOtp = await req('POST', `/api/sign/${signerToken}/send-otp`);
    const sigOtpData = sigOtp.json();
    sigOtpData?.ok ? log('PASS', 'Signer OTP sent', `devOtp: ${sigOtpData.devOtp ? 'yes' : 'no'}`) : log('FAIL', 'Signer OTP sent', sigOtp.body);

    // Verify signer OTP (wrong)
    const wrongSigOtp = await req('POST', `/api/sign/${signerToken}/verify-otp`, { code: '000000' });
    wrongSigOtp.status === 400 ? log('PASS', 'Wrong signer OTP rejected', '') : log('FAIL', 'Wrong signer OTP rejected', `Got ${wrongSigOtp.status}`);

    // Resolve the signer OTP from API or DB so the suite works in production-safe mode too
    const signerRow = signerOps.findByToken(signerToken);
    const realSigOtp = sigOtpData?.devOtp || (signerRow ? latestSignerOtp(signerRow.id) : null);
    if (realSigOtp) {
      const sigVerify = await req('POST', `/api/sign/${signerToken}/verify-otp`, { code: realSigOtp });
      const sigCookie = getCookie(sigVerify);
      sigVerify.json()?.ok ? log('PASS', 'Signer OTP verified', '') : log('FAIL', 'Signer OTP verified', sigVerify.body);

      // PDF access after OTP (need the session cookie)
      if (sigCookie) {
        const pdfOk = await req('GET', `/api/sign/${signerToken}/pdf`, null, { Cookie: sigCookie });
        pdfOk.status === 200 ? log('PASS', 'PDF accessible after OTP', '') : log('FAIL', 'PDF accessible after OTP', `Got ${pdfOk.status}`);

        // Submit signature
        const submitResp = await req('POST', `/api/sign/${signerToken}/submit`, {
          signatureData: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQABNjN9GQAAAAlwSFlzAAAWJQAAFiUBSVIk8AAAAA0lEQVQI12P4z8BQDwAEgAF/QualEQAAAABJRU5ErkJggg==',
          location: 'Test City',
          browserInfo: 'TestBot on TestOS',
          geoCoords: '45.0,-75.0',
        }, { Cookie: sigCookie });
        submitResp.json()?.ok ? log('PASS', 'Signature submitted', `completed: ${submitResp.json().completed}`) : log('FAIL', 'Signature submitted', submitResp.body);

        // Double-submit
        const dblSubmit = await req('POST', `/api/sign/${signerToken}/submit`, { signatureData: 'test' }, { Cookie: sigCookie });
        dblSubmit.status === 400 ? log('PASS', 'Double-submit blocked', '') : log('FAIL', 'Double-submit blocked', `Got ${dblSubmit.status} — Signer can submit multiple times!`);
      }
    }
  }

  // ════════════════════════════════════════
  console.log('\n\x1b[1m[5] SECURITY TESTS\x1b[0m');
  // ════════════════════════════════════════

  // Path traversal on uploads
  const traversal = await req('GET', '/uploads/../../server.js');
  (traversal.status === 404 || traversal.status === 400 || !traversal.body.includes('require(')) ?
    log('PASS', 'Path traversal /uploads/../../server.js', `${traversal.status}`) :
    log('FAIL', 'Path traversal /uploads/../../server.js', 'Server source code leaked!');

  const traversal2 = await req('GET', '/uploads/..%2F..%2Fserver.js');
  (traversal2.status === 404 || traversal2.status === 400 || !traversal2.body.includes('require(')) ?
    log('PASS', 'Encoded path traversal', `${traversal2.status}`) :
    log('FAIL', 'Encoded path traversal', 'Source code leaked via encoded path!');

  // XSS in signer name — test via document creation
  const xssResp = await multipartReq('/api/documents/create', {
    title: '<script>alert(1)</script>',
    message: '<img onerror=alert(1) src=x>',
    signers: JSON.stringify([{ name: '<script>alert("xss")</script>', email: 'xss@test.local' }]),
  }, 'pdf', pdf, 'test.pdf', authCookie);
  if (xssResp.json()?.ok) {
    // Check that the stored title was sanitized
    const docs = await req('GET', '/api/documents', null, { Accept: 'application/json', Cookie: authCookie });
    const xssDoc = docs.json()?.documents?.find(d => d.uuid === xssResp.json().uuid);
    const titleClean = xssDoc && !xssDoc.title.includes('<script>');
    titleClean ? log('PASS', 'XSS payload stripped from title', 'Server-side sanitization') : log('WARN', 'XSS payload stored in title', 'Check server sanitize()');
  } else {
    log('PASS', 'XSS payload rejected', '');
  }

  // SQL injection in email
  const sqliResp = await req('POST', '/api/auth/send-otp', { email: "'; DROP TABLE users; --" });
  sqliResp.status < 500 ? log('PASS', 'SQL injection in email', `Status: ${sqliResp.status} (parameterized queries)`) : log('FAIL', 'SQL injection in email', `Server error ${sqliResp.status}`);

  // SQL injection in OTP
  const sqliOtp = await req('POST', '/api/auth/verify-otp', { email: 'test@test.local', code: "' OR '1'='1" });
  sqliOtp.status === 400 ? log('PASS', 'SQL injection in OTP code', 'Rejected') : log('FAIL', 'SQL injection in OTP code', `Got ${sqliOtp.status}`);

  // Large payload
  const bigBody = { email: 'a'.repeat(100000) + '@test.local' };
  const bigResp = await req('POST', '/api/auth/send-otp', bigBody);
  bigResp.status < 500 ? log('PASS', 'Large payload handling', `Status: ${bigResp.status}`) : log('WARN', 'Large payload handling', `Server error ${bigResp.status}`);

  // Non-PDF upload attempt — file with PDF mime but wrong content (magic bytes check)
  const fakePdf = Buffer.from('This is not a PDF file at all');
  const nonPdfResp = await multipartReq('/api/documents/create', {
    title: 'Fake PDF', signers: JSON.stringify([{ name: 'X', email: 'x@test.local' }]),
  }, 'pdf', fakePdf, 'malicious.pdf', authCookie);
  (nonPdfResp.status === 400) ? log('PASS', 'Fake PDF rejected (magic bytes check)', `${nonPdfResp.status}`) : log('FAIL', 'Fake PDF not rejected', `Got ${nonPdfResp.status}`);

  // IDOR: access another user's document without auth
  if (docUUID) {
    const idorResp = await req('GET', `/api/documents/${docUUID}/download`, null, { Accept: 'application/json' });
    (idorResp.status === 401 || idorResp.status === 302) ? log('PASS', 'IDOR: download without auth', `${idorResp.status}`) : log('FAIL', 'IDOR: download without auth', `Got ${idorResp.status} — document accessible without login!`);
  }

  // Session fixation: use garbage cookie
  const fixResp = await req('GET', '/api/documents', null, { Accept: 'application/json', Cookie: 'connect.sid=s%3Afakesession.garbage' });
  fixResp.status === 401 ? log('PASS', 'Forged session cookie rejected', '') : log('FAIL', 'Forged session cookie rejected', `Got ${fixResp.status}`);

  // Check security headers
  const headersResp = await req('GET', '/login');
  const hasXFrame = !!headersResp.headers['x-frame-options'];
  const hasCSP = !!headersResp.headers['content-security-policy'];
  const hasXSS = !!headersResp.headers['x-xss-protection'];
  const hasNoSniff = !!headersResp.headers['x-content-type-options'];
  hasXFrame ? log('PASS', 'X-Frame-Options header', headersResp.headers['x-frame-options']) : log('WARN', 'Missing X-Frame-Options header', 'Clickjacking risk');
  hasCSP ? log('PASS', 'Content-Security-Policy header', '') : log('WARN', 'Missing Content-Security-Policy', 'XSS mitigation');
  hasNoSniff ? log('PASS', 'X-Content-Type-Options header', '') : log('WARN', 'Missing X-Content-Type-Options', 'MIME sniffing risk');

  // Rate limiting check — send 6 rapid requests (limit is 5/min)
  for (let i = 0; i < 5; i++) await req('POST', '/api/auth/send-otp', { email: `ratelimit${i}@test.local` });
  const rateLimited = await req('POST', '/api/auth/send-otp', { email: 'ratelimit_final@test.local' });
  rateLimited.status === 429 ? log('PASS', 'Rate limiting on OTP endpoints', '429 after 5 requests/min') : log('WARN', 'Rate limiting may not be working', `Got ${rateLimited.status}`);

  // Cookie security — express-session sets httpOnly by default, check Set-Cookie header
  const freshOtp = await req('POST', '/api/auth/send-otp', { email: 'cookiecheck@test.local' });
  // We already verified session works. express-session httpOnly is default true.
  // Check the raw Set-Cookie from our auth response
  const rawCookie = rightOtp.headers['set-cookie']?.[0] || '';
  rawCookie.toLowerCase().includes('httponly') ? log('PASS', 'Cookie is HttpOnly', '') : log('WARN', 'Cookie may not be HttpOnly', 'Check express-session config');
  rawCookie.toLowerCase().includes('samesite') ? log('PASS', 'Cookie has SameSite', '') : log('WARN', 'Cookie missing SameSite', 'CSRF risk');

  // Check .env not served
  const envResp = await req('GET', '/.env');
  (envResp.status === 404 || !envResp.body.includes('SESSION_SECRET')) ?
    log('PASS', '.env not publicly accessible', `${envResp.status}`) :
    log('FAIL', '.env publicly accessible!', 'Secrets leaked!');

  // Check database not served
  const dbResp = await req('GET', '/data/sealforge.db');
  (dbResp.status === 404) ?
    log('PASS', 'Database not publicly accessible', '') :
    log('FAIL', 'Database publicly accessible!', 'Full data leak!');

  // ════════════════════════════════════════
  console.log('\n\x1b[1m[6] REGRESSION: AUDIT FINDINGS\x1b[0m');
  // ════════════════════════════════════════

  // -- Finding 1: IDOR - cross-user document access --
  // Create a second user
  const otp2 = await req('POST', '/api/auth/send-otp', { email: 'attacker@evil.local' });
  const otp2Data = otp2.json();
  const real2 = otp2Data?.devOtp || latestOtpFor('attacker@evil.local');
  const verify2 = await req('POST', '/api/auth/verify-otp', { email: 'attacker@evil.local', code: real2, name: 'Attacker' });
  const attackerCookie = getCookie(verify2);

  if (docUUID && attackerCookie) {
    // Attacker tries to read victim's document detail
    const crossDetail = await req('GET', `/api/documents/${docUUID}`, null, { Accept: 'application/json', Cookie: attackerCookie });
    crossDetail.status === 403 ? log('PASS', 'IDOR: cross-user doc detail blocked', '403') : log('FAIL', 'IDOR: cross-user doc detail', `Got ${crossDetail.status} — other user can read doc!`);

    // Attacker tries to download victim's document
    const crossDownload = await req('GET', `/api/documents/${docUUID}/download`, null, { Accept: 'application/json', Cookie: attackerCookie });
    crossDownload.status === 403 ? log('PASS', 'IDOR: cross-user doc download blocked', '403') : log('FAIL', 'IDOR: cross-user doc download', `Got ${crossDownload.status} — other user can download!`);
  }

  // -- Finding 2: Token leakage in document detail response --
  if (docUUID) {
    const detailCheck = await req('GET', `/api/documents/${docUUID}`, null, { Accept: 'application/json', Cookie: authCookie });
    const detailSigners = detailCheck.json()?.signers || [];
    const hasToken = detailSigners.some(s => s.token);
    !hasToken ? log('PASS', 'Signer tokens stripped from detail response', '') : log('FAIL', 'Signer tokens leaked in detail response', 'token field still present');
  }

  // -- Finding 3: Signing order enforcement --
  // Create a fresh document specifically for this test (signer 1 hasn't signed yet)
  const orderTestResp = await multipartReq('/api/documents/create', {
    title: 'Order Test',
    message: '',
    signers: JSON.stringify([{ name: 'First', email: 'first@test.local' }, { name: 'Second', email: 'second@test.local' }]),
  }, 'pdf', pdf, 'order-test.pdf', authCookie);
  const orderDoc = orderTestResp.json();
  if (orderDoc?.uuid) {
    const oDoc = docOps.findByUUID(orderDoc.uuid);
    const oSigners = signerOps.listByDocument(oDoc.id);
    const s2token = oSigners[1]?.token;
    if (s2token) {
      // Signer 2 should be 'pending' (signer 1 is 'sent' but hasn't signed yet)
      const outOfOrderOtp = await req('POST', `/api/sign/${s2token}/send-otp`);
      outOfOrderOtp.status === 403 ? log('PASS', 'Signing order enforced: signer 2 OTP blocked', '403') : log('FAIL', 'Signing order NOT enforced on OTP', `Got ${outOfOrderOtp.status} — signer 2 can act before signer 1!`);

      const outOfOrderSubmit = await req('POST', `/api/sign/${s2token}/submit`, { signatureData: 'test' });
      outOfOrderSubmit.status === 403 ? log('PASS', 'Signing order enforced: signer 2 submit blocked', '403') : log('FAIL', 'Signing order NOT enforced on submit', `Got ${outOfOrderSubmit.status}`);
    }
  }

  // -- Finding 4a: User name sanitization --
  const xssOtp = await req('POST', '/api/auth/send-otp', { email: 'xssname@test.local' });
  const xssOtpCode = xssOtp.json()?.devOtp || latestOtpFor('xssname@test.local');
  if (xssOtpCode) {
    const xssVerify = await req('POST', '/api/auth/verify-otp', {
      email: 'xssname@test.local', code: xssOtpCode, name: '<img src=x onerror=alert(1)>'
    });
    const xssCookie = getCookie(xssVerify);
    if (xssCookie) {
      const xssDocs = await req('GET', '/api/documents', null, { Accept: 'application/json', Cookie: xssCookie });
      const userName = xssDocs.json()?.user?.name || '';
      !userName.includes('<') ? log('PASS', 'User name sanitized at login', `Stored: "${userName}"`) : log('FAIL', 'User name NOT sanitized', `Stored raw HTML: "${userName}"`);
    }
  }

  // -- Finding 4b: Filename sanitization --
  if (docUUID) {
    // Create a doc with an XSS filename
    const xssFileResp = await multipartReq('/api/documents/create', {
      title: 'Filename Test',
      signers: JSON.stringify([{ name: 'Test', email: 'fntest@test.local' }]),
    }, 'pdf', pdf, 'evil<img src=x onerror=alert(1)>.pdf', authCookie);
    const xssFileData = xssFileResp.json();
    if (xssFileData?.uuid) {
      const fnDetail = await req('GET', `/api/documents/${xssFileData.uuid}`, null, { Accept: 'application/json', Cookie: authCookie });
      const storedFn = fnDetail.json()?.document?.original_filename || '';
      !storedFn.includes('<') ? log('PASS', 'Filename sanitized', `Stored: "${storedFn}"`) : log('FAIL', 'Filename NOT sanitized', `Stored raw: "${storedFn}"`);
    }
  }

  // -- Regression: webhook URL validation --
  if (authCookie) {
    const httpHook = await req('POST', '/api/settings/webhooks', { url: 'http://example.com/hook', events: ['*'] }, { Cookie: authCookie });
    httpHook.status === 400 ? log('PASS', 'Webhook rejects http:// URLs', '400') : log('FAIL', 'Webhook accepts http:// URLs', `Got ${httpHook.status} — HMAC secrets would transit cleartext!`);

    const ipHook = await req('POST', '/api/settings/webhooks', { url: 'https://169.254.169.254/imds', events: ['*'] }, { Cookie: authCookie });
    ipHook.status === 400 ? log('PASS', 'Webhook rejects link-local IP', '400') : log('FAIL', 'Webhook accepts link-local IP', `Got ${ipHook.status} — SSRF risk on cloud hosts`);

    const lhHook = await req('POST', '/api/settings/webhooks', { url: 'https://localhost/hook', events: ['*'] }, { Cookie: authCookie });
    lhHook.status === 400 ? log('PASS', 'Webhook rejects localhost', '400') : log('FAIL', 'Webhook accepts localhost', `Got ${lhHook.status}`);
  }

  // -- Regression: ID verification files are encrypted at rest --
  try {
    const idDir = path.join(__dirname, 'data', 'idverif');
    if (fs.existsSync(idDir)) {
      const encFiles = fs.readdirSync(idDir).filter(f => f.endsWith('.enc'));
      const plainFiles = fs.readdirSync(idDir).filter(f => /\.(jpe?g|png|webp)$/i.test(f) && !f.endsWith('.enc'));
      if (plainFiles.length) {
        log('FAIL', 'ID verify files: plaintext on disk', `${plainFiles.length} unencrypted file(s) in data/idverif/`);
      } else {
        log('PASS', 'ID verify files: encrypted on disk', `${encFiles.length} .enc file(s)`);
      }
    } else {
      log('PASS', 'ID verify dir: not yet populated', 'no files to inspect');
    }
  } catch (e) {
    log('WARN', 'ID verify file inspection', e.message);
  }

  // -- Regression: solo + qr endpoints are authenticated --
  const soloApi = await req('POST', '/api/sign', { pdfBytes: [37, 80, 68, 70] });
  (soloApi.status === 302 || soloApi.status === 401) ? log('PASS', '/api/sign requires auth', `${soloApi.status}`) : log('FAIL', '/api/sign anonymous access', `Got ${soloApi.status} — anyone can mint signed PDFs!`);
  const qrApi = await req('POST', '/api/qr', { data: 'x' });
  (qrApi.status === 302 || qrApi.status === 401) ? log('PASS', '/api/qr requires auth', `${qrApi.status}`) : log('FAIL', '/api/qr anonymous access', `Got ${qrApi.status}`);

  // ════════════════════════════════════════
  console.log('\n\x1b[1m[7] STATIC CODE PATTERNS\x1b[0m');
  // ════════════════════════════════════════

  const serverCode = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf-8');
  const dbCode = fs.readFileSync(path.join(__dirname, 'database.js'), 'utf-8');

  // Check for string concatenation in SQL
  const rawSql = dbCode.match(/`[^`]*\$\{[^}]*\}[^`]*`/g) || [];
  const dangerousSql = rawSql.filter(s => s.includes('SELECT') || s.includes('INSERT') || s.includes('UPDATE') || s.includes('DELETE'));
  dangerousSql.length === 0 ? log('PASS', 'No string interpolation in SQL', 'All queries parameterized') : log('FAIL', 'String interpolation in SQL queries', dangerousSql.map(s => s.substring(0, 60)).join('; '));

  // Check for eval/Function
  (serverCode.includes('eval(') || serverCode.includes('new Function(')) ?
    log('FAIL', 'eval() or new Function() used', 'Code injection risk') :
    log('PASS', 'No eval/Function usage', '');

  // Check for exec/spawn without sanitization
  (serverCode.includes('child_process') || serverCode.includes('exec(')) ?
    log('FAIL', 'child_process/exec usage found', 'Command injection risk') :
    log('PASS', 'No child_process/exec usage', '');

  // Check that P12 password isn't hardcoded as a top-level variable
  // (it is hardcoded as 'sealforge' in server.js — flag it)
  serverCode.includes("passphrase: 'sealforge'") ?
    log('WARN', 'P12 password hardcoded in server.js', "Move to .env as P12_PASSPHRASE") :
    log('PASS', 'P12 password not hardcoded', '');

  // ════════════════════════════════════════
  // SUMMARY
  // ════════════════════════════════════════
  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log(`\x1b[1m  RESULTS: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m, \x1b[33m${warnings} warnings\x1b[0m`);
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');

  if (issues.length) {
    console.log('\n\x1b[1mISSUES TO FIX:\x1b[0m');
    issues.forEach((i, idx) => {
      const color = i.severity === 'FAIL' ? '\x1b[31m' : '\x1b[33m';
      console.log(`  ${idx + 1}. ${color}[${i.severity}]\x1b[0m ${i.test} — ${i.detail}`);
    });
  }

  console.log('');
}

run().catch(console.error);
