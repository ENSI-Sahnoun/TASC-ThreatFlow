const test = require('node:test');
const assert = require('node:assert');
const { DOMAINS, isDomain } = require('./domains');
const { domainsForCategory } = require('./normalize');

test('16 domains defined with slug+label', () => {
  assert.strictEqual(DOMAINS.length, 16);
  for (const d of DOMAINS) { assert.ok(d.slug && d.label); }
});

test('isDomain validates slugs', () => {
  assert.ok(isDomain('ransomware'));
  assert.ok(!isDomain('not-a-domain'));
});

test('domainsForCategory maps buckets to defaults', () => {
  assert.deepStrictEqual(domainsForCategory('ransomware'), ['ransomware']);
  assert.ok(domainsForCategory('cve').includes('vulnerability'));
});
