const test = require('node:test');
const assert = require('node:assert/strict');
const { detectFields } = require('./field_detect');

test('detects fields from MSRC-shaped record', () => {
  const rec = { DocumentTitle: 'x', vendorProject: 'Microsoft', severity: 'Critical' };
  const out = detectFields(rec);
  assert.equal(out.vendorField, 'vendorProject');
  assert.equal(out.severityField, 'severity');
  assert.equal(out.cveField, null);
  assert.equal(out.cvssField, null);
});

test('detects fields from Red-Hat-shaped record', () => {
  const rec = { CVE: 'CVE-2026-1234', cvss3_score: '7.5', severity: 'important' };
  const out = detectFields(rec);
  assert.equal(out.cveField, 'CVE');
  assert.equal(out.cvssField, 'cvss3_score');
  assert.equal(out.severityField, 'severity');
});

test('detects fields from CIRCL-shaped record with different casing', () => {
  const rec = { CveId: 'CVE-2026-9999', CvssScore: 9.1 };
  const out = detectFields(rec);
  assert.equal(out.cveField, 'CveId');
  assert.equal(out.cvssField, 'CvssScore');
});

test('returns nulls when no candidate keys present', () => {
  const rec = { Foo: 'breach', Description: 'x' };
  const out = detectFields(rec);
  assert.deepEqual(out, { cveField: null, cvssField: null, severityField: null, vendorField: null, titleField: null, idField: null });
});

test('handles non-object input safely', () => {
  const empty = { cveField: null, cvssField: null, severityField: null, vendorField: null, titleField: null, idField: null };
  assert.deepEqual(detectFields(null), empty);
  assert.deepEqual(detectFields(undefined), empty);
});

test('detects title and id fields', () => {
  const rec = { id: 'CVE-2026-1', title: 'x' };
  const out = detectFields(rec);
  assert.equal(out.titleField, 'title');
  assert.equal(out.idField, 'id');
});

test('candidate priority order: first match in list wins', () => {
  const rec = { cvss: 5, cvssScore: 9 };
  const out = detectFields(rec);
  assert.equal(out.cvssField, 'cvss');
});
