const test = require('node:test');
const assert = require('node:assert');
const textFeed = require('./text_feed');

test('text_feed makes one item per non-comment line', async () => {
  const body = '# comment\nhttps://evil.example/a\nhttps://evil.example/b\n\n';
  const source = { category: 'Phishing', enrichHints: { iocType: 'url' } };
  const ctx = { request: async () => ({ status: 200, headers: {}, body }) };
  const items = await textFeed.fetch(source, ctx);
  assert.strictEqual(items.length, 2);
  assert.strictEqual(items[0].title, 'Phishing page · evil.example');
  assert.deepStrictEqual(items[0].native.iocs, [{ type: 'url', value: 'https://evil.example/a' }]);
});
