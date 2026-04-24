// Identity-verification provider interface.
//
// The existing SealForge ID flow already captures a government-ID photo + a selfie (server.js).
// This module wraps that capture in a pluggable *verification* step: does the selfie match
// the ID? Is it a real live face (liveness)? Is the document genuine?
//
// Providers: persona, jumio, onfido, and a local "mock" provider for dev/sandbox that performs
// a deterministic pass/fail based on a flag in the filename. Canadian title insurers typically
// accept Persona, Jumio, or Onfido output.
//
// Configure via env: IDV_PROVIDER=mock|persona|jumio|onfido + provider-specific keys.
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');

const PROVIDERS = {};

function register(name, impl) { PROVIDERS[name] = impl; }
function listProviders() { return Object.keys(PROVIDERS); }
function getActive() {
  const name = (process.env.IDV_PROVIDER || 'mock').toLowerCase();
  const p = PROVIDERS[name];
  if (!p) throw new Error(`Unknown IDV_PROVIDER "${name}". Available: ${Object.keys(PROVIDERS).join(', ')}`);
  return { name, impl: p };
}

// ─── Mock provider (dev/sandbox) ───
// Passes verification unless either filename contains 'fail' — lets testers simulate both paths.
register('mock', {
  async verify({ idPath, selfiePath, signerName, signerEmail }) {
    const anyFail = /fail/i.test(idPath || '') || /fail/i.test(selfiePath || '');
    const idExists = idPath && fs.existsSync(idPath);
    const selfieExists = selfiePath && fs.existsSync(selfiePath);
    if (!idExists || !selfieExists) {
      return { provider: 'mock', status: 'rejected', reason: 'Missing ID or selfie file', confidence: 0 };
    }
    if (anyFail) {
      return { provider: 'mock', status: 'rejected', reason: 'Simulated failure (filename contains "fail")', confidence: 0.1 };
    }
    return {
      provider: 'mock',
      status: 'approved',
      confidence: 0.98,
      documentType: 'passport',
      livenessPassed: true,
      faceMatchScore: 0.96,
      checks: { document_authenticity: 'passed', selfie_liveness: 'passed', face_match: 'passed' },
      reference: 'MOCK-' + crypto.randomBytes(8).toString('hex'),
      verifiedAt: new Date().toISOString(),
    };
  },
  available: () => true,
});

// ─── Persona provider (real) ───
// Config: IDV_PROVIDER=persona  PERSONA_API_KEY=persona_live_...
// Persona API: https://docs.withpersona.com/api-reference
register('persona', {
  async verify({ idPath, selfiePath, signerName, signerEmail }) {
    const apiKey = process.env.PERSONA_API_KEY;
    if (!apiKey) throw new Error('PERSONA_API_KEY not set');
    // Real flow: upload documents via multipart to /api/v1/documents, create an inquiry,
    // poll status, return final decision. Stubbed here to show the response shape.
    return {
      provider: 'persona',
      status: 'pending',
      reference: 'persona-' + crypto.randomBytes(6).toString('hex'),
      message: 'Persona integration configured but verification upload not wired. See persona-docs.',
    };
  },
  available: () => !!process.env.PERSONA_API_KEY,
});

// ─── Jumio provider (real) ───
register('jumio', {
  async verify({ idPath, selfiePath, signerName, signerEmail }) {
    const apiToken = process.env.JUMIO_API_TOKEN;
    const apiSecret = process.env.JUMIO_API_SECRET;
    if (!apiToken || !apiSecret) throw new Error('JUMIO_API_TOKEN / JUMIO_API_SECRET not set');
    return {
      provider: 'jumio',
      status: 'pending',
      reference: 'jumio-' + crypto.randomBytes(6).toString('hex'),
      message: 'Jumio configured but NetVerify upload not wired.',
    };
  },
  available: () => !!(process.env.JUMIO_API_TOKEN && process.env.JUMIO_API_SECRET),
});

// ─── Onfido provider (real) ───
register('onfido', {
  async verify({ idPath, selfiePath, signerName, signerEmail }) {
    const apiToken = process.env.ONFIDO_API_TOKEN;
    if (!apiToken) throw new Error('ONFIDO_API_TOKEN not set');
    return {
      provider: 'onfido',
      status: 'pending',
      reference: 'onfido-' + crypto.randomBytes(6).toString('hex'),
      message: 'Onfido configured but checks API not wired.',
    };
  },
  available: () => !!process.env.ONFIDO_API_TOKEN,
});

// ─── Interac Verification Service (Canada-specific, banking-grade) ───
// Used by Canadian banks and many title insurers. Requires a commercial contract with Interac.
register('interac', {
  async verify({ idPath, selfiePath, signerName, signerEmail }) {
    if (!process.env.INTERAC_API_URL || !process.env.INTERAC_CLIENT_ID) {
      throw new Error('Interac Verification Service not configured. Set INTERAC_API_URL, INTERAC_CLIENT_ID, INTERAC_CLIENT_SECRET.');
    }
    return {
      provider: 'interac',
      status: 'pending',
      reference: 'interac-' + crypto.randomBytes(6).toString('hex'),
      message: 'Interac Verification Service configured but inquiry endpoint not wired.',
    };
  },
  available: () => !!(process.env.INTERAC_API_URL && process.env.INTERAC_CLIENT_ID && process.env.INTERAC_CLIENT_SECRET),
});

module.exports = { register, listProviders, getActive };
