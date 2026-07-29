const test = require('node:test');
const assert = require('node:assert');
const mispFeed = require('./misp_feed');

test('misp_feed reads manifest then events, extracting IOC attributes', async () => {
  const manifest = JSON.stringify({ 'uuid-1': { info: 'Phishing campaign', date: '2025-03-03' } });
  const event = JSON.stringify({ Event: { info: 'Phishing campaign', date: '2025-03-03', uuid: 'uuid-1', Attribute: [{ type: 'domain', value: 'bad.test' }, { type: 'md5', value: 'd41d8cd98f00b204e9800998ecf8427e' }] } });
  const ctx = { request: async (url) => ({ status: 200, headers: { 'content-type': 'application/json' }, body: url.endsWith('manifest.json') ? manifest : event }) };
  const source = { category: 'Threat Intelligence', url: 'https://circl/feed-osint/manifest.json' };
  const items = await mispFeed.fetch(source, ctx);
  assert.strictEqual(items.length, 1);
  assert.strictEqual(items[0].title, 'Phishing campaign');
  assert.strictEqual(items[0].native.iocs.length, 2);
});
