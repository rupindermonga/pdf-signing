/**
 * Form builder feature tests — new formula ops (multiply/divide/round/abs/negate/if)
 * and visibleIf conditional visibility.
 *
 * Run: node test-form-builder.js
 */
const { cleanFieldList, validateFieldSubmission, applyCalculatedFields, evaluateVisibility, FORMULA_OPS } = require('./fields');

let passed = 0, failed = 0;
const failures = [];
function t(name, cond, detail) {
  const ok = !!cond;
  const icon = ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
  console.log(`  [${icon}] ${name}${detail ? ' — ' + detail : ''}`);
  if (ok) passed++; else { failed++; failures.push({ name, detail }); }
}
function section(title) { console.log(`\n\x1b[1m${title}\x1b[0m`); }

async function main() {
  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log('\x1b[1m  SealForge Form Builder Tests\x1b[0m');
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');

  section('[1] EXTENDED FORMULA OPS ACCEPTED');
  const ops = ['multiply', 'divide', 'round', 'abs', 'negate', 'if'];
  for (const op of ops) {
    t(`FORMULA_OPS includes ${op}`, FORMULA_OPS.includes(op));
  }

  // Base fields: two numeric inputs
  const baseFields = [
    { id: 'a', type: 'text', page: 1, xPct: 0, yPct: 0, wPct: 0.1, hPct: 0.05, signerOrder: 1, label: 'A', required: false },
    { id: 'b', type: 'text', page: 1, xPct: 0, yPct: 0, wPct: 0.1, hPct: 0.05, signerOrder: 1, label: 'B', required: false },
  ];

  section('[2] MULTIPLY / DIVIDE');

  // Build fields with calc and run applyCalculatedFields
  const multiplyFields = cleanFieldList([
    ...baseFields,
    { type: 'formula', label: 'prod', signerOrder: 1, calc: { op: 'multiply', fields: ['f1', 'f2'] } },
  ]);
  const rMultiply = applyCalculatedFields(multiplyFields, 1, { f1: '4', f2: '5' });
  t('multiply: 4 * 5 = 20', rMultiply[multiplyFields[2].id] === 20, `got ${rMultiply[multiplyFields[2].id]}`);

  const divideFields = cleanFieldList([
    ...baseFields,
    { type: 'formula', label: 'div', signerOrder: 1, calc: { op: 'divide', fields: ['f1', 'f2'] } },
  ]);
  t('divide: 10 / 4 = 2.5', applyCalculatedFields(divideFields, 1, { f1: '10', f2: '4' })[divideFields[2].id] === 2.5);
  t('divide by 0 = 0 (no NaN/Infinity)', applyCalculatedFields(divideFields, 1, { f1: '10', f2: '0' })[divideFields[2].id] === 0);

  section('[3] ROUND / ABS / NEGATE');

  const roundFields = cleanFieldList([
    ...baseFields,
    { type: 'formula', label: 'r', signerOrder: 1, calc: { op: 'round', fields: ['f1'], decimals: 1 } },
  ]);
  t('round 3.14159 to 1dp = 3.1', applyCalculatedFields(roundFields, 1, { f1: '3.14159' })[roundFields[2].id] === 3.1);

  const roundZero = cleanFieldList([
    ...baseFields,
    { type: 'formula', label: 'r0', signerOrder: 1, calc: { op: 'round', fields: ['f1'] } },
  ]);
  t('round 3.7 default=0dp → 4', applyCalculatedFields(roundZero, 1, { f1: '3.7' })[roundZero[2].id] === 4);

  const absFields = cleanFieldList([
    ...baseFields,
    { type: 'formula', label: 'a', signerOrder: 1, calc: { op: 'abs', fields: ['f1'] } },
  ]);
  t('abs(-7) = 7', applyCalculatedFields(absFields, 1, { f1: '-7' })[absFields[2].id] === 7);

  const negFields = cleanFieldList([
    ...baseFields,
    { type: 'formula', label: 'n', signerOrder: 1, calc: { op: 'negate', fields: ['f1'] } },
  ]);
  t('negate(5) = -5', applyCalculatedFields(negFields, 1, { f1: '5' })[negFields[2].id] === -5);

  section('[4] IF OP');

  const ifFields = cleanFieldList([
    { type: 'text', label: 'status', signerOrder: 1, required: false },
    { type: 'text', label: 'hi', signerOrder: 1, required: false },
    { type: 'text', label: 'lo', signerOrder: 1, required: false },
    { type: 'formula', label: 'pick', signerOrder: 1, calc: { op: 'if', condField: 'f1', equals: 'high', thenField: 'f2', elseField: 'f3', fields: [] } },
  ]);
  const vals1 = applyCalculatedFields(ifFields, 1, { f1: 'high', f2: 'Big Amount', f3: 'Small Amount' });
  t('if op picks thenField when equals match', vals1[ifFields[3].id] === 'Big Amount', `got ${vals1[ifFields[3].id]}`);
  const vals2 = applyCalculatedFields(ifFields, 1, { f1: 'low', f2: 'Big Amount', f3: 'Small Amount' });
  t('if op picks elseField when no match', vals2[ifFields[3].id] === 'Small Amount');

  section('[5] VISIBILITY RULES');

  t('equals op', evaluateVisibility({ fieldId: 'x', equals: 'yes' }, { x: 'yes' }) === true);
  t('equals op false', evaluateVisibility({ fieldId: 'x', equals: 'yes' }, { x: 'no' }) === false);
  t('notEquals op', evaluateVisibility({ fieldId: 'x', equals: 'yes', operator: 'notEquals' }, { x: 'no' }) === true);
  t('contains op', evaluateVisibility({ fieldId: 'x', equals: 'bar', operator: 'contains' }, { x: 'foobar' }) === true);
  t('notContains op', evaluateVisibility({ fieldId: 'x', equals: 'bar', operator: 'notContains' }, { x: 'foo' }) === true);
  t('notEmpty op', evaluateVisibility({ fieldId: 'x', operator: 'notEmpty' }, { x: 'hello' }) === true);
  t('notEmpty false on empty', evaluateVisibility({ fieldId: 'x', operator: 'notEmpty' }, { x: '' }) === false);
  t('empty op', evaluateVisibility({ fieldId: 'x', operator: 'empty' }, { x: '' }) === true);
  t('gt op', evaluateVisibility({ fieldId: 'x', equals: '5', operator: 'gt' }, { x: '10' }) === true);
  t('lt op', evaluateVisibility({ fieldId: 'x', equals: '5', operator: 'lt' }, { x: '3' }) === true);
  // Unknown operator is coerced to the safe default ('equals'), not silently "always true".
  t('unknown op falls back to equals', evaluateVisibility({ fieldId: 'x', equals: 'yes', operator: 'bogus' }, { x: 'yes' }) === true);
  t('unknown op falls back to equals (false path)', evaluateVisibility({ fieldId: 'x', equals: 'yes', operator: 'bogus' }, { x: 'no' }) === false);
  t('missing fieldId returns true', evaluateVisibility({}, {}) === true);

  section('[6] visibleIf IN cleanFieldList');

  const cleaned = cleanFieldList([
    { type: 'text', label: 'trigger', signerOrder: 1 },
    { type: 'text', label: 'extra', signerOrder: 1, visibleIf: { fieldId: 'f1', equals: 'yes', operator: 'equals' } },
  ]);
  t('visibleIf preserved on clean', cleaned[1].visibleIf && cleaned[1].visibleIf.fieldId === 'f1');
  t('operator preserved', cleaned[1].visibleIf.operator === 'equals');
  t('equals preserved', cleaned[1].visibleIf.equals === 'yes');

  // Bad operator falls back to default (stripped from object)
  const cleanedBad = cleanFieldList([
    { type: 'text', label: 'extra', signerOrder: 1, visibleIf: { fieldId: 'f1', equals: 'yes', operator: 'DROP_TABLE' } },
  ]);
  t('Invalid operator is stripped', cleanedBad[0].visibleIf.operator === undefined);

  // Malformed visibleIf (missing fieldId) is dropped
  const cleanedMalformed = cleanFieldList([
    { type: 'text', label: 'extra', signerOrder: 1, visibleIf: { equals: 'yes' } },
  ]);
  t('Malformed visibleIf (no fieldId) is dropped', cleanedMalformed[0].visibleIf == null);

  section('[7] VALIDATION SKIPS HIDDEN-BY-visibleIf FIELDS');

  const fields = cleanFieldList([
    { type: 'dropdown', label: 'type', signerOrder: 1, options: ['refund', 'exchange'], required: true },
    { type: 'text', label: 'refund reason', signerOrder: 1, required: true,
      visibleIf: { fieldId: 'f1', equals: 'refund' } },
  ]);

  // When type is 'exchange', the refund-reason field is hidden and required is waived
  const err1 = validateFieldSubmission(fields, 1, { f1: 'exchange' });
  t('Hidden-by-visibleIf required field is not enforced', err1 === null, `err: ${err1}`);

  // When type is 'refund', refund-reason becomes required
  const err2 = validateFieldSubmission(fields, 1, { f1: 'refund' });
  t('Visible-by-visibleIf required field IS enforced', err2 !== null && err2.includes('required'));

  // With both filled out, validation passes
  const err3 = validateFieldSubmission(fields, 1, { f1: 'refund', f2: 'did not fit' });
  t('Both filled → valid', err3 === null);

  section('[8] FORMULAS IGNORE HIDDEN FIELDS (no poison)');

  // A hidden (by visibleIf) field that's referenced in a formula shouldn't
  // silently inject a stale value. Verify by clearing + evaluating.
  const mixed = cleanFieldList([
    { type: 'dropdown', label: 'mode', signerOrder: 1, options: ['a', 'b'] },
    { type: 'text', label: 'qty', signerOrder: 1, visibleIf: { fieldId: 'f1', equals: 'a' } },
    { type: 'text', label: 'fallback', signerOrder: 1 },
    { type: 'formula', label: 'pick', signerOrder: 1, calc: { op: 'if', condField: 'f1', equals: 'a', thenField: 'f2', elseField: 'f3', fields: [] } },
  ]);
  // In mode 'b', f2 is hidden → fieldValues should have empty f2 (signer UI clears it)
  const pickResult = applyCalculatedFields(mixed, 1, { f1: 'b', f2: '', f3: 'fallback-text' });
  t('if picks else when hidden input empty', pickResult[mixed[3].id] === 'fallback-text');

  console.log('\n\x1b[1m══════════════════════════════════════════\x1b[0m');
  console.log(`\x1b[1m  RESULTS: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m\x1b[1m\x1b[0m`);
  console.log('\x1b[1m══════════════════════════════════════════\x1b[0m');
  if (failed > 0) {
    console.log('\nFailed tests:');
    failures.forEach(f => console.log('  ✗ ' + f.name + (f.detail ? ' — ' + f.detail : '')));
  }
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error('Test error:', e); process.exit(2); });
