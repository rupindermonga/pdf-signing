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
  'name', 'email', 'dropdown', 'radio',
];

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
    };
  });
}

// Server-side required-field enforcement. Returns null on success, or an error string.
function validateFieldSubmission(allFields, signerOrder, submittedValues) {
  const myFields = allFields.filter(f => f.signerOrder === signerOrder);
  for (const f of myFields) {
    if (!f.required) continue;
    if (f.type === 'signature') continue;
    if (f.conditional && f.conditional.fieldId) {
      const refVal = submittedValues[f.conditional.fieldId];
      const refStr = refVal == null ? '' : String(refVal);
      if (refStr !== String(f.conditional.equals)) continue;
    }
    const v = submittedValues[f.id];
    if (f.type === 'checkbox') {
      if (v !== true && v !== 'true') return `Field "${f.label || f.type}" is required`;
      continue;
    }
    if (v == null || String(v).trim() === '') return `Field "${f.label || f.type}" is required`;
    if ((f.type === 'dropdown' || f.type === 'radio') && Array.isArray(f.options)) {
      if (!f.options.includes(String(v))) return `Field "${f.label || f.type}" has an invalid selection`;
    }
  }
  return null;
}

module.exports = { ALLOWED_FIELD_TYPES, cleanFieldList, validateFieldSubmission, sanitize };
