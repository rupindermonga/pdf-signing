// ─── Field validation / normalisation ───
// Supported types: signature, initials, name, email, date, text, checkbox,
// plus dropdown and radio. Each field may carry a `conditional` rule
// { fieldId, equals } — when present, `required` only applies if the
// referenced field's value equals `equals`.
//
// Pure helpers (no I/O) so they can be unit-tested without a running server.

function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'\\]/g, '');
}

const ALLOWED_FIELD_TYPES = [
  'text', 'date', 'checkbox', 'initials', 'signature',
  'name', 'email', 'dropdown', 'radio', 'attachment',
];

// Validate a regex pattern is safe-ish: cap length, reject catastrophic backtracking indicators.
function cleanRegex(pattern) {
  if (typeof pattern !== 'string' || !pattern) return null;
  if (pattern.length > 100) return null;
  // Reject patterns with nested quantifiers that cause ReDoS (simple heuristic)
  if (/(\(\?:?[^)]*[+*][^)]*\)[+*])|(\([^)]*\+\)[+*])|(\w[+*]\w[+*])/.test(pattern)) return null;
  try { new RegExp(pattern); return pattern; } catch { return null; }
}

function cleanFieldList(parsedFields, { forceSignerOrder = null } = {}) {
  return (Array.isArray(parsedFields) ? parsedFields : []).map((f, idx) => {
    const type = ALLOWED_FIELD_TYPES.includes(f.type) ? f.type : 'text';
    let options = [];
    if ((type === 'dropdown' || type === 'radio') && Array.isArray(f.options)) {
      options = f.options
        .map(o => (typeof o === 'string' ? o : String(o?.value ?? o?.label ?? '')))
        .map(o => sanitize(o).slice(0, 60))
        .filter(o => o.length > 0)
        .slice(0, 20);
      if (!options.length) options = ['Option 1', 'Option 2'];
    }
    let conditional = null;
    if (f.conditional && typeof f.conditional === 'object' && f.conditional.fieldId) {
      conditional = {
        fieldId: sanitize(String(f.conditional.fieldId)).slice(0, 32),
        equals: sanitize(String(f.conditional.equals ?? '')).slice(0, 120),
      };
    }
    // Validation rules: regex pattern, numeric range, length range
    const validation = {};
    if (f.validation && typeof f.validation === 'object') {
      const pattern = cleanRegex(f.validation.pattern);
      if (pattern) validation.pattern = pattern;
      if (f.validation.message) validation.message = sanitize(String(f.validation.message)).slice(0, 120);
      if (f.validation.minLength != null) validation.minLength = Math.max(0, Math.min(1000, parseInt(f.validation.minLength, 10) || 0));
      if (f.validation.maxLength != null) validation.maxLength = Math.max(1, Math.min(1000, parseInt(f.validation.maxLength, 10) || 500));
      if (f.validation.minValue != null && !isNaN(Number(f.validation.minValue))) validation.minValue = Number(f.validation.minValue);
      if (f.validation.maxValue != null && !isNaN(Number(f.validation.maxValue))) validation.maxValue = Number(f.validation.maxValue);
    }
    // Preset: mask (currency, zip, ssn, phone) — pre-configured regex with friendly message
    const PRESET_PATTERNS = {
      currency: { pattern: '^\\$?\\d+(\\.\\d{1,2})?$', message: 'Enter an amount like 12.34' },
      zip: { pattern: '^\\d{5}(-\\d{4})?$', message: 'Enter a ZIP code (e.g., 90210 or 90210-1234)' },
      ssn: { pattern: '^\\d{3}-\\d{2}-\\d{4}$', message: 'Enter SSN as 123-45-6789' },
      phone: { pattern: '^\\+?[\\d\\s()-]{7,20}$', message: 'Enter a valid phone number' },
      numeric: { pattern: '^-?\\d+(\\.\\d+)?$', message: 'Enter a number' },
    };
    if (f.mask && PRESET_PATTERNS[f.mask]) {
      validation.pattern = PRESET_PATTERNS[f.mask].pattern;
      if (!validation.message) validation.message = PRESET_PATTERNS[f.mask].message;
    }
    // Locked: sender-filled, signer cannot change (default value comes from sender at create time)
    const locked = f.locked === true;
    const defaultValue = f.defaultValue != null ? sanitize(String(f.defaultValue)).slice(0, 500) : null;
    // Calculated: formula like "sum:f1,f2" (only + supported for safety)
    const calc = f.calc && typeof f.calc === 'object' && f.calc.op === 'sum' && Array.isArray(f.calc.fields)
      ? { op: 'sum', fields: f.calc.fields.slice(0, 10).map(id => sanitize(String(id)).slice(0, 32)) }
      : null;

    return {
      id: 'f' + (idx + 1),
      type,
      page: Math.max(1, parseInt(f.page, 10) || 1),
      xPct: Math.min(1, Math.max(0, Number(f.xPct) || 0)),
      yPct: Math.min(1, Math.max(0, Number(f.yPct) || 0)),
      wPct: Math.min(1, Math.max(0.01, Number(f.wPct) || 0.15)),
      hPct: Math.min(1, Math.max(0.01, Number(f.hPct) || 0.04)),
      signerOrder: forceSignerOrder != null ? forceSignerOrder : Math.max(1, parseInt(f.signerOrder, 10) || 1),
      required: f.required !== false,
      label: sanitize(f.label || ''),
      ...(options.length ? { options } : {}),
      ...(conditional ? { conditional } : {}),
      ...(Object.keys(validation).length ? { validation } : {}),
      ...(locked ? { locked: true } : {}),
      ...(defaultValue != null ? { defaultValue } : {}),
      ...(calc ? { calc } : {}),
      ...(f.mask ? { mask: String(f.mask).slice(0, 20) } : {}),
    };
  });
}

// Server-side field enforcement. Returns null on success, or an error string.
// Validates: required, conditional, dropdown/radio options, regex pattern,
// min/max length, min/max numeric value, locked (default value), calculated.
function validateFieldSubmission(allFields, signerOrder, submittedValues) {
  const myFields = allFields.filter(f => f.signerOrder === signerOrder);
  for (const f of myFields) {
    if (f.type === 'signature') continue;
    if (f.type === 'attachment') continue; // separate upload endpoint
    // If locked, value must equal defaultValue (signer cannot modify)
    if (f.locked) {
      const v = submittedValues[f.id];
      const expected = f.defaultValue != null ? String(f.defaultValue) : '';
      if (String(v == null ? '' : v) !== expected) {
        return `Field "${f.label || f.type}" is locked and cannot be modified`;
      }
      continue;
    }
    // Conditional: skip required enforcement if condition doesn't match
    const conditionActive = !f.conditional || !f.conditional.fieldId ||
      String(submittedValues[f.conditional.fieldId] == null ? '' : submittedValues[f.conditional.fieldId]) === String(f.conditional.equals);

    const v = submittedValues[f.id];
    const isEmpty = v == null || (f.type === 'checkbox' ? (v !== true && v !== 'true') : String(v).trim() === '');

    if (f.required && conditionActive && isEmpty) {
      return `Field "${f.label || f.type}" is required`;
    }
    if (isEmpty) continue; // nothing more to validate for optional empty fields

    // Dropdown/radio: must be one of the allowed options
    if ((f.type === 'dropdown' || f.type === 'radio') && Array.isArray(f.options)) {
      if (!f.options.includes(String(v))) return `Field "${f.label || f.type}" has an invalid selection`;
    }

    // Regex pattern validation
    if (f.validation && f.validation.pattern) {
      try {
        const re = new RegExp(f.validation.pattern);
        if (!re.test(String(v))) return f.validation.message || `Field "${f.label || f.type}" format is invalid`;
      } catch { /* ignore malformed pattern */ }
    }
    // Length validation
    if (f.validation && f.validation.minLength != null && String(v).length < f.validation.minLength) {
      return `Field "${f.label || f.type}" must be at least ${f.validation.minLength} characters`;
    }
    if (f.validation && f.validation.maxLength != null && String(v).length > f.validation.maxLength) {
      return `Field "${f.label || f.type}" must be at most ${f.validation.maxLength} characters`;
    }
    // Numeric range
    if (f.validation && (f.validation.minValue != null || f.validation.maxValue != null)) {
      const num = parseFloat(String(v).replace(/[^0-9.-]/g, ''));
      if (isNaN(num)) return `Field "${f.label || f.type}" must be a number`;
      if (f.validation.minValue != null && num < f.validation.minValue) return `Field "${f.label || f.type}" must be ≥ ${f.validation.minValue}`;
      if (f.validation.maxValue != null && num > f.validation.maxValue) return `Field "${f.label || f.type}" must be ≤ ${f.validation.maxValue}`;
    }
  }
  return null;
}

// Compute calculated fields from submitted values. Supports simple sum of numeric fields.
// Returns the enriched value map.
function applyCalculatedFields(allFields, signerOrder, submittedValues) {
  const out = { ...submittedValues };
  const myFields = allFields.filter(f => f.signerOrder === signerOrder && f.calc);
  for (const f of myFields) {
    if (f.calc.op === 'sum') {
      let sum = 0;
      for (const ref of f.calc.fields) {
        const raw = out[ref];
        const num = parseFloat(String(raw == null ? '' : raw).replace(/[^0-9.-]/g, ''));
        if (!isNaN(num)) sum += num;
      }
      out[f.id] = Number(sum.toFixed(2));
    }
  }
  return out;
}

module.exports = { ALLOWED_FIELD_TYPES, cleanFieldList, validateFieldSubmission, applyCalculatedFields, sanitize };
