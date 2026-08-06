const test = require('node:test');
const assert = require('node:assert');
const { cwesFromRaw, CWE_RE } = require('./cwe');

test('cwesFromRaw extracts Primary and Secondary weakness ids', () => {
  const raw = {
    weaknesses: [
      { type: 'Primary', description: [{ lang: 'en', value: 'CWE-79' }] },
      { type: 'Secondary', description: [{ lang: 'en', value: 'CWE-89' }] },
    ],
  };
  assert.deepStrictEqual(cwesFromRaw(raw), ['CWE-79', 'CWE-89']);
});

test('cwesFromRaw excludes CWE-noinfo', () => {
  const raw = { weaknesses: [{ type: 'Primary', description: [{ lang: 'en', value: 'CWE-noinfo' }] }] };
  assert.deepStrictEqual(cwesFromRaw(raw), []);
});

test('cwesFromRaw only reads English descriptions', () => {
  const raw = {
    weaknesses: [{ type: 'Primary', description: [
      { lang: 'es', value: 'CWE-79' },
      { lang: 'en', value: 'CWE-89' },
    ] }],
  };
  assert.deepStrictEqual(cwesFromRaw(raw), ['CWE-89']);
});

test('cwesFromRaw de-duplicates a repeated id across weakness entries', () => {
  const raw = {
    weaknesses: [
      { type: 'Primary', description: [{ lang: 'en', value: 'CWE-79' }] },
      { type: 'Secondary', description: [{ lang: 'en', value: 'CWE-79' }] },
    ],
  };
  assert.deepStrictEqual(cwesFromRaw(raw), ['CWE-79']);
});

test('cwesFromRaw returns [] for absent or malformed structures', () => {
  for (const bad of [null, undefined, {}, { weaknesses: null }, { weaknesses: [{}] }, { weaknesses: [{ description: [{}] }] }]) {
    assert.deepStrictEqual(cwesFromRaw(bad), []);
  }
});

test('CWE_RE matches only a bare CWE-<digits> shape', () => {
  assert.ok(CWE_RE.test('CWE-79'));
  assert.ok(!CWE_RE.test('CWE-noinfo'));
  assert.ok(!CWE_RE.test('cwe-79'));
  assert.ok(!CWE_RE.test('CWE-79 (improper input validation)'));
});
