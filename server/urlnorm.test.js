const test = require('node:test');
const assert = require('node:assert');
const { normalizeUrl } = require('./urlnorm');

test('normalizeUrl strips scheme and trailing slash', () => {
  assert.strictEqual(normalizeUrl('https://example.test'), 'example.test');
  assert.strictEqual(normalizeUrl('http://example.test/'), 'example.test');
  assert.strictEqual(normalizeUrl('HTTPS://Example.test///'), 'Example.test');
});

test('normalizeUrl preserves path and query differences (not a domain-match)', () => {
  assert.strictEqual(normalizeUrl('https://evil.example/a'), 'evil.example/a');
  assert.notStrictEqual(normalizeUrl('https://evil.example/a'), normalizeUrl('https://evil.example/b'));
});

test('normalizeUrl handles empty/nullish input', () => {
  assert.strictEqual(normalizeUrl(''), '');
  assert.strictEqual(normalizeUrl(null), '');
});
