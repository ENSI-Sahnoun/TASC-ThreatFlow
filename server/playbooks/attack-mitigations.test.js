const test = require('node:test');
const assert = require('node:assert');
const { attackStep } = require('./attack-mitigations');

test('a curated name returns its mitigation entries', () => {
  const result = attackStep('LockBit');
  assert.ok(Array.isArray(result));
  assert.ok(result.length > 0);
  for (const m of result) {
    assert.ok(typeof m.id === 'string' && m.id.length > 0);
    assert.ok(typeof m.name === 'string' && m.name.length > 0);
    assert.match(m.url, /^https:\/\/attack\.mitre\.org\/mitigations\//);
  }
});

test('an unmatched name returns null', () => {
  assert.strictEqual(attackStep('NotARealGroup'), null);
});

test('no partial or fuzzy match', () => {
  assert.strictEqual(attackStep('APT2'), null);
  assert.strictEqual(attackStep('lockbit'), null);
});

test('null or empty name returns null', () => {
  assert.strictEqual(attackStep(null), null);
  assert.strictEqual(attackStep(''), null);
});
