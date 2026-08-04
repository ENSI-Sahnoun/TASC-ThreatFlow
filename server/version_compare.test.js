const test = require('node:test');
const assert = require('node:assert');
const { compareVersions, affectedStatus } = require('./version_compare');

// --- compareVersions ---

test('Windows four-part builds: less than', () => {
  assert.strictEqual(compareVersions('10.0.26100.8300', '10.0.26100.8875'), -1);
});

test('Windows four-part builds: equal', () => {
  assert.strictEqual(compareVersions('10.0.26100.8875', '10.0.26100.8875'), 0);
});

test('Windows four-part builds: greater than', () => {
  assert.strictEqual(compareVersions('10.0.26100.9001', '10.0.26100.8875'), 1);
});

test('segment-count mismatch: 2.0 equals 2.0.0 (shorter padded with zero)', () => {
  assert.strictEqual(compareVersions('2.0', '2.0.0'), 0);
});

test('segment-count mismatch: 7.4 is less than 7.4.5', () => {
  assert.strictEqual(compareVersions('7.4', '7.4.5'), -1);
});

test('numeric, not lexical: 7.4.10 is greater than 7.4.9', () => {
  // A string comparison gets this backwards ('10' < '9' lexically) — the classic
  // version-compare bug, and the one most likely to tell someone they are patched.
  assert.strictEqual(compareVersions('7.4.10', '7.4.9'), 1);
});

test('leading zeros: 1.02 equals 1.2', () => {
  assert.strictEqual(compareVersions('1.02', '1.2'), 0);
});

test('every uncomparable shape returns null, individually', () => {
  const other = '1.0.0';
  for (const bad of ['1.0.0-rc1', '1:2.4.1', '2.4.1-3.el9', 'v7.4.5', '2024.1a', '', null]) {
    assert.strictEqual(compareVersions(bad, other), null, `expected null for ${JSON.stringify(bad)}`);
    assert.strictEqual(compareVersions(other, bad), null, `expected null for ${JSON.stringify(bad)} as second arg`);
  }
});

test('compareVersions(null, null) is null, not 0 — absence is not equality', () => {
  assert.strictEqual(compareVersions(null, null), null);
});

// --- affectedStatus ---

const NO_BOUNDS = { startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: null, pinned: null };

test('affectedStatus: inside a "before X" range is affected', () => {
  assert.strictEqual(affectedStatus('7.4.0', { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'affected');
});

test('affectedStatus: outside a "before X" range is not_covered', () => {
  assert.strictEqual(affectedStatus('7.5.0', { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'not_covered');
});

test('affectedStatus: exactly at the excluded boundary is not_covered (endExcluding is exclusive)', () => {
  assert.strictEqual(affectedStatus('7.4.5', { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'not_covered');
});

test('affectedStatus: inside "X through Y" (inclusive both ends) is affected', () => {
  assert.strictEqual(
    affectedStatus('1.2.0', { ...NO_BOUNDS, startIncluding: '1.0.0', endIncluding: '1.5.0' }), 'affected');
});

test('affectedStatus: at the inclusive upper bound of "X through Y" is affected', () => {
  assert.strictEqual(
    affectedStatus('1.5.0', { ...NO_BOUNDS, startIncluding: '1.0.0', endIncluding: '1.5.0' }), 'affected');
});

test('affectedStatus: below the lower bound of "X through Y" is not_covered', () => {
  assert.strictEqual(
    affectedStatus('0.9.0', { ...NO_BOUNDS, startIncluding: '1.0.0', endIncluding: '1.5.0' }), 'not_covered');
});

test('affectedStatus: a pin that matches is affected', () => {
  assert.strictEqual(affectedStatus('4.2.1', { ...NO_BOUNDS, pinned: '4.2.1' }), 'affected');
});

test('affectedStatus: a pin that differs is unknown, never not_covered', () => {
  assert.strictEqual(affectedStatus('4.2.2', { ...NO_BOUNDS, pinned: '4.2.1' }), 'unknown');
});

test('affectedStatus: an entry with no usable bound at all is unknown', () => {
  assert.strictEqual(affectedStatus('4.2.2', { ...NO_BOUNDS }), 'unknown');
});

test('affectedStatus: no installed version is unknown even against a bounded entry', () => {
  assert.strictEqual(affectedStatus(null, { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'unknown');
});

test('affectedStatus: no entry at all is unknown', () => {
  assert.strictEqual(affectedStatus('7.4.0', null), 'unknown');
});

test('affectedStatus: an uncomparable installed version against a bounded entry is unknown, not not_covered', () => {
  assert.strictEqual(affectedStatus('v7.0', { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'unknown');
});

// The property this module exists to guarantee: a null anywhere in the comparison chain can
// never produce not_covered. Exhaustive over every bound-field combination that involves a
// comparison at all (pin is checked separately below since it uses string equality, not
// compareVersions).
test('property: no bound-comparison combination returns not_covered when a comparison is null', () => {
  const uncomparable = 'v1.0';
  const boundKeys = ['startIncluding', 'startExcluding', 'endIncluding', 'endExcluding'];
  for (const key of boundKeys) {
    const entry = { ...NO_BOUNDS, [key]: uncomparable };
    const result = affectedStatus('1.0.0', entry);
    assert.notStrictEqual(result, 'not_covered', `${key}=${uncomparable} must not yield not_covered`);
  }
});
