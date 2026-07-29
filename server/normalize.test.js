const { test } = require('node:test');
const assert = require('node:assert');
const { categoryBucket, domainsForCategory } = require('./normalize');

test('categoryBucket classifies phishing and data-breach sources', () => {
  assert.strictEqual(categoryBucket('Phishing'), 'phishing');
  assert.strictEqual(categoryBucket('Data Breaches'), 'data-breach');
  assert.strictEqual(categoryBucket('Vulnerability Intelligence'), 'cve');
  assert.strictEqual(categoryBucket('Cybersecurity News'), 'news');
  assert.strictEqual(categoryBucket('Something Unmapped'), 'other');
});

test('domainsForCategory covers the new buckets', () => {
  assert.deepStrictEqual(domainsForCategory('phishing'), ['phishing']);
  assert.deepStrictEqual(domainsForCategory('data-breach'), ['data-breach']);
});
