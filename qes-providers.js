// eIDAS Qualified Electronic Signature (QES) provider interface.
//
// eIDAS Regulation (EU No 910/2014, updated by eIDAS 2 in 2024) defines three tiers:
//   SES  — simple electronic signature (what most e-sign apps provide by default)
//   AES  — advanced (uniquely identifies signer, under sole control, detects tampering)
//   QES  — qualified: AES + a qualified certificate from a Qualified Trust Service Provider (QTSP)
//          listed on the EU Trust List, executed on a Qualified Signature Creation Device (QSCD).
//
// QES is the only tier that is automatically considered legally equivalent to a handwritten
// signature across the EU. Many contracts (real estate, many employment) require it.
//
// This module provides a pluggable interface so CertaDocs can embed a QES into the PAdES-LTV
// signed PDF produced by @signpdf/signpdf. Real integration requires a commercial contract
// with one of the QTSPs below (see EU Trust List).
//
// Supported stubs:
//   - infocert (Italy, strong presence in real estate)
//   - namirial (Italy, reseller-friendly API)
//   - dtrust   (Germany, Bundesdruckerei)
//   - swisssign (Switzerland / EU-listed)
//   - signicat (Nordics / pan-EU aggregator)
//
// Config: QES_PROVIDER=infocert|namirial|... + provider-specific keys.
const crypto = require('crypto');
const https = require('https');

const PROVIDERS = {};
function register(name, impl) { PROVIDERS[name] = impl; }
function listProviders() { return Object.keys(PROVIDERS); }
function getActive() {
  const name = (process.env.QES_PROVIDER || '').toLowerCase();
  if (!name) throw new Error('QES_PROVIDER not set. Supported: ' + Object.keys(PROVIDERS).join(', '));
  const p = PROVIDERS[name];
  if (!p) throw new Error(`Unknown QES_PROVIDER "${name}". Available: ${Object.keys(PROVIDERS).join(', ')}`);
  return { name, impl: p };
}

function configuredProviders() {
  return Object.entries(PROVIDERS).filter(([, p]) => p.available()).map(([k]) => k);
}

// ─── InfoCert (IT) ───
register('infocert', {
  async identify({ signerName, signerEmail, signerCountry, signerDob, idPath, videoPath }) {
    if (!process.env.INFOCERT_API_KEY) throw new Error('INFOCERT_API_KEY not set');
    return { provider: 'infocert', status: 'pending', inquiryId: 'ic-' + crypto.randomBytes(6).toString('hex'), message: 'InfoCert identity session created (stub).' };
  },
  async sign({ docHash, signerIdentity, tsaUrl }) {
    if (!process.env.INFOCERT_API_KEY) throw new Error('INFOCERT_API_KEY not set');
    return {
      provider: 'infocert',
      signatureFormat: 'PAdES-LTV',
      signatureToken: 'infocert-signed-' + crypto.randomBytes(8).toString('hex'),
      qualifiedCertificate: { issuer: 'InfoCert QTSP', valid: true },
      tsaUrl: tsaUrl || 'http://time.certum.pl',
      signedAt: new Date().toISOString(),
      message: 'Stub response — wire to InfoCert GoSign API.',
    };
  },
  available: () => !!process.env.INFOCERT_API_KEY,
});

// ─── Namirial (IT) ───
register('namirial', {
  async identify(opts) {
    if (!process.env.NAMIRIAL_API_KEY) throw new Error('NAMIRIAL_API_KEY not set');
    return { provider: 'namirial', status: 'pending', inquiryId: 'nmr-' + crypto.randomBytes(6).toString('hex') };
  },
  async sign({ docHash, signerIdentity, tsaUrl }) {
    if (!process.env.NAMIRIAL_API_KEY) throw new Error('NAMIRIAL_API_KEY not set');
    return {
      provider: 'namirial',
      signatureFormat: 'PAdES-LTV',
      signatureToken: 'namirial-signed-' + crypto.randomBytes(8).toString('hex'),
      qualifiedCertificate: { issuer: 'Namirial CA', valid: true },
      tsaUrl: tsaUrl || 'http://timestamp.namirialtsp.com',
      signedAt: new Date().toISOString(),
    };
  },
  available: () => !!process.env.NAMIRIAL_API_KEY,
});

// ─── D-Trust (Bundesdruckerei, DE) ───
register('dtrust', {
  async identify(opts) {
    if (!process.env.DTRUST_API_KEY) throw new Error('DTRUST_API_KEY not set');
    return { provider: 'dtrust', status: 'pending', inquiryId: 'dt-' + crypto.randomBytes(6).toString('hex') };
  },
  async sign(opts) {
    if (!process.env.DTRUST_API_KEY) throw new Error('DTRUST_API_KEY not set');
    return {
      provider: 'dtrust',
      signatureFormat: 'PAdES-LTV',
      signatureToken: 'dtrust-signed-' + crypto.randomBytes(8).toString('hex'),
      qualifiedCertificate: { issuer: 'D-Trust CA', valid: true },
      signedAt: new Date().toISOString(),
    };
  },
  available: () => !!process.env.DTRUST_API_KEY,
});

// ─── Signicat (Nordic / pan-EU) ───
register('signicat', {
  async identify(opts) {
    if (!process.env.SIGNICAT_API_KEY) throw new Error('SIGNICAT_API_KEY not set');
    return { provider: 'signicat', status: 'pending', inquiryId: 'sc-' + crypto.randomBytes(6).toString('hex') };
  },
  async sign(opts) {
    if (!process.env.SIGNICAT_API_KEY) throw new Error('SIGNICAT_API_KEY not set');
    return {
      provider: 'signicat',
      signatureFormat: 'PAdES-LTV',
      signatureToken: 'signicat-signed-' + crypto.randomBytes(8).toString('hex'),
      qualifiedCertificate: { issuer: 'Signicat Trust Services', valid: true },
      signedAt: new Date().toISOString(),
    };
  },
  available: () => !!process.env.SIGNICAT_API_KEY,
});

// ─── SwissSign ───
register('swisssign', {
  async identify(opts) {
    if (!process.env.SWISSSIGN_API_KEY) throw new Error('SWISSSIGN_API_KEY not set');
    return { provider: 'swisssign', status: 'pending', inquiryId: 'ss-' + crypto.randomBytes(6).toString('hex') };
  },
  async sign(opts) {
    if (!process.env.SWISSSIGN_API_KEY) throw new Error('SWISSSIGN_API_KEY not set');
    return {
      provider: 'swisssign',
      signatureFormat: 'PAdES-LTV',
      signatureToken: 'swisssign-signed-' + crypto.randomBytes(8).toString('hex'),
      qualifiedCertificate: { issuer: 'SwissSign Certification Authority', valid: true },
      signedAt: new Date().toISOString(),
    };
  },
  available: () => !!process.env.SWISSSIGN_API_KEY,
});

module.exports = { register, listProviders, getActive, configuredProviders };
