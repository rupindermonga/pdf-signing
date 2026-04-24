// Market definitions — drives which features, languages, payment providers,
// regulatory boilerplate, and identity providers are surfaced per jurisdiction.
//
// A "market" is the primary country/region of use for an organisation or an
// individual user. Choosing a market sets sensible defaults but does NOT prevent
// using other features — a Canadian org can still offer Aadhaar eSign to an
// Indian signer, for example. "GLOBAL" shows every feature unrestricted.
//
// Priority order baked in: CA (primary) → US → IN → AU → EU → GB → GLOBAL.

const MARKETS = {
  CA: {
    code: 'CA',
    name: 'Canada',
    flag: '🇨🇦',
    languages: ['en', 'fr'],
    defaultLanguage: 'en',
    currency: 'CAD',
    paymentProvider: 'stripe',
    dataResidency: 'ca',            // AWS ca-central-1 / Azure Canada Central
    regulatoryFrame: ['PIPEDA', 'Quebec Law 25'],
    features: {
      aadhaarEsign: false,
      estamp: false,
      razorpay: false,
      qes: false,                   // qualified eIDAS — EU only
      kba: true,                    // US/CA title insurers use KBA variants
      ron: true,                    // Remote Online Commissioning (BC/ON)
      witnessRole: true,
      idVerification: true,
    },
    legal: {
      privacyLaw: 'PIPEDA + Law 25 (Quebec)',
      privacyOfficer: 'privacy@finelai.com',
      escalation: 'Office of the Privacy Commissioner of Canada',
      esignLaw: 'Canadian PIPEDA Part 2, provincial UECA/ETA',
    },
    defaultIdvProvider: 'persona',   // Persona / Jumio / Interac are common in CA
    notes: 'Title insurers (FCT, Stewart, Chicago) drive real-estate vertical. Bilingual EN/FR mandatory for Quebec.',
  },
  US: {
    code: 'US',
    name: 'United States',
    flag: '🇺🇸',
    languages: ['en', 'es'],        // Spanish fallback (not yet translated — English for now)
    defaultLanguage: 'en',
    currency: 'USD',
    paymentProvider: 'stripe',
    dataResidency: 'us',
    regulatoryFrame: ['ESIGN Act', 'UETA', 'HIPAA (opt-in)', 'CCPA'],
    features: {
      aadhaarEsign: false,
      estamp: false,
      razorpay: false,
      qes: false,
      kba: true,                    // widely used for US mortgage / real-estate
      ron: true,                    // 45+ states authorise RON
      witnessRole: true,
      idVerification: true,
    },
    legal: {
      privacyLaw: 'CCPA / CPRA (CA), state laws',
      privacyOfficer: 'privacy@finelai.com',
      escalation: 'State attorney general / FTC',
      esignLaw: 'ESIGN Act §101 + UETA',
    },
    defaultIdvProvider: 'persona',
    notes: 'KBA required for notarisation; HIPAA BAA required for healthcare; 21 CFR Part 11 for pharma.',
  },
  IN: {
    code: 'IN',
    name: 'India',
    flag: '🇮🇳',
    languages: ['en', 'hi'],
    defaultLanguage: 'en',
    currency: 'INR',
    paymentProvider: 'razorpay',
    dataResidency: 'in',
    regulatoryFrame: ['IT Act 2000', 'DPDP Act 2023'],
    features: {
      aadhaarEsign: true,
      estamp: true,
      razorpay: true,
      qes: false,
      kba: false,
      ron: false,
      witnessRole: true,
      idVerification: true,
    },
    legal: {
      privacyLaw: 'Digital Personal Data Protection Act 2023',
      privacyOfficer: 'grievance@finelai.com',
      escalation: 'Data Protection Board of India',
      esignLaw: 'IT Act 2000 §5 (Aadhaar eSign / DSC Class 3)',
    },
    defaultIdvProvider: 'persona',
    notes: 'Aadhaar eSign + e-stamping are often required for admissibility. DPDP grievance officer must be named publicly.',
  },
  AU: {
    code: 'AU',
    name: 'Australia',
    flag: '🇦🇺',
    languages: ['en'],
    defaultLanguage: 'en',
    currency: 'AUD',
    paymentProvider: 'stripe',
    dataResidency: 'au',
    regulatoryFrame: ['Electronic Transactions Act 1999', 'Privacy Act / APPs'],
    features: {
      aadhaarEsign: false,
      estamp: false,
      razorpay: false,
      qes: false,
      kba: false,
      ron: false,
      witnessRole: true,           // statutory declarations, SMSF docs often require witness
      idVerification: true,
    },
    legal: {
      privacyLaw: 'Privacy Act 1988 (Australian Privacy Principles)',
      privacyOfficer: 'privacy@finelai.com',
      escalation: 'Office of the Australian Information Commissioner',
      esignLaw: 'ETA 1999 + state equivalents; Corps Act s126/127 for companies',
    },
    defaultIdvProvider: 'persona',
    notes: 'Witness workflow is the main differentiator. myGovID integration is a future win.',
  },
  EU: {
    code: 'EU',
    name: 'European Union',
    flag: '🇪🇺',
    languages: ['en', 'fr', 'de'],  // de not yet translated
    defaultLanguage: 'en',
    currency: 'EUR',
    paymentProvider: 'stripe',
    dataResidency: 'eu',
    regulatoryFrame: ['GDPR', 'eIDAS 2'],
    features: {
      aadhaarEsign: false,
      estamp: false,
      razorpay: false,
      qes: true,                   // qualified electronic signatures
      kba: false,
      ron: false,
      witnessRole: true,
      idVerification: true,
    },
    legal: {
      privacyLaw: 'GDPR (EU 2016/679)',
      privacyOfficer: 'dpo@finelai.com',
      escalation: 'National DPA (e.g. CNIL, BfDI, Garante)',
      esignLaw: 'eIDAS (EU 910/2014) — SES / AES / QES',
    },
    defaultIdvProvider: 'onfido',
    notes: 'QES via licensed QTSP is the premium tier. EUDI Wallet pilots are expanding through 2026.',
  },
  GB: {
    code: 'GB',
    name: 'United Kingdom',
    flag: '🇬🇧',
    languages: ['en'],
    defaultLanguage: 'en',
    currency: 'GBP',
    paymentProvider: 'stripe',
    dataResidency: 'eu',
    regulatoryFrame: ['UK GDPR', 'Electronic Communications Act 2000'],
    features: {
      aadhaarEsign: false,
      estamp: false,
      razorpay: false,
      qes: true,                   // UK recognises EU QES; also has its own tSchemes
      kba: false,
      ron: false,
      witnessRole: true,
      idVerification: true,
    },
    legal: {
      privacyLaw: 'UK GDPR + Data Protection Act 2018',
      privacyOfficer: 'dpo@finelai.com',
      escalation: 'Information Commissioner\'s Office (ICO)',
      esignLaw: 'Electronic Communications Act 2000 + eIDAS-equivalent',
    },
    defaultIdvProvider: 'onfido',
    notes: 'Similar to EU post-Brexit; often treat GB + EU as one deployment tier.',
  },
  GLOBAL: {
    code: 'GLOBAL',
    name: 'Global / multi-region',
    flag: '🌐',
    languages: ['en', 'fr', 'hi'],
    defaultLanguage: 'en',
    currency: 'USD',
    paymentProvider: 'stripe',
    dataResidency: 'auto',
    regulatoryFrame: ['all frameworks shown based on signer'],
    features: {
      aadhaarEsign: true,
      estamp: true,
      razorpay: true,
      qes: true,
      kba: true,
      ron: true,
      witnessRole: true,
      idVerification: true,
    },
    legal: {
      privacyLaw: 'Multiple — see per-signer jurisdiction',
      privacyOfficer: 'privacy@finelai.com',
      escalation: 'Jurisdiction-specific',
      esignLaw: 'ESIGN / PIPEDA / IT Act / eIDAS / ETA depending on signer',
    },
    defaultIdvProvider: 'persona',
    notes: 'All features surfaced. Recommended for professional services firms serving multiple regions.',
  },
};

const ORDER = ['CA', 'US', 'IN', 'AU', 'EU', 'GB', 'GLOBAL'];

function isValid(code) {
  return typeof code === 'string' && Object.prototype.hasOwnProperty.call(MARKETS, code.toUpperCase());
}

function get(code) {
  const c = String(code || 'CA').toUpperCase();
  return MARKETS[c] || MARKETS.CA;
}

function listOrdered() {
  return ORDER.map(c => MARKETS[c]);
}

function featureEnabled(code, feature) {
  const m = get(code);
  return !!(m.features && m.features[feature]);
}

// Determine which market "scope" should see a given section: if any of the
// markets in `scopes` enable the feature, return true. Used server-side to gate
// optional UI sections (e.g. an India section shows for orgs with IN or GLOBAL).
function anyEnables(scopes, feature) {
  if (!scopes || !scopes.length) scopes = ['CA'];
  return scopes.some(c => featureEnabled(c, feature));
}

// Suggest payment provider for (market, currency). Market is a hint, currency wins.
function suggestedPaymentProvider(marketCode, currency) {
  const cur = String(currency || '').toUpperCase();
  if (cur === 'INR') return 'razorpay';
  const m = get(marketCode);
  return m.paymentProvider;
}

module.exports = {
  MARKETS, ORDER, isValid, get, listOrdered, featureEnabled, anyEnables, suggestedPaymentProvider,
};
