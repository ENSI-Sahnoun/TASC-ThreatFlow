const { test } = require('node:test');
const assert = require('node:assert');
const { tierWeight, computeConfidence } = require('./confidence');

test('tierWeight ranks source classes, defaults to the floor', () => {
  assert.strictEqual(tierWeight('Government / CERT Advisory'), 0.95);
  assert.strictEqual(tierWeight('Vendor Advisory'), 0.9);
  assert.strictEqual(tierWeight('Cybersecurity News'), 0.6);
  assert.strictEqual(tierWeight('OSINT'), 0.5);
  assert.strictEqual(tierWeight('Unknown Category'), 0.5);
  assert.strictEqual(tierWeight(null), 0.5);
  // Data Breaches is a first-class taxonomy bucket (Task 5) with curated sources (HIBP) — it
  // must not collapse to the same floor weight as an unrecognized category.
  assert.strictEqual(tierWeight('Data Breaches'), 0.9);
});

test('computeConfidence adds corroboration and caps at 0.99', () => {
  assert.strictEqual(computeConfidence('Cybersecurity News', 1), 0.6);
  assert.strictEqual(computeConfidence('Cybersecurity News', 3), 0.7);
  assert.strictEqual(computeConfidence('Government / CERT Advisory', 5), 0.99);
  // a missing or nonsensical corroboration count must not lower the tier weight
  assert.strictEqual(computeConfidence('Vendor Advisory', 0), 0.9);
});
