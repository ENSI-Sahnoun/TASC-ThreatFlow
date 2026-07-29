const test = require('node:test');
const assert = require('node:assert');
const rss = require('./rss');

const SAMPLE = `<?xml version="1.0"?><rss version="2.0"><channel><title>Feed</title>
<item><title>Bad thing CVE-2024-1234</title><link>https://ex/1</link><guid>g1</guid>
<pubDate>Tue, 01 Jul 2025 10:00:00 GMT</pubDate><description>A summary</description></item>
</channel></rss>`;

test('rss adapter maps items via mapping', async () => {
  const source = { category: 'Cybersecurity News', mapping: { title: 'title', summary: 'contentSnippet', link: 'link', date: 'isoDate', id: 'guid' } };
  const ctx = { request: async () => ({ status: 200, headers: { 'content-type': 'application/rss+xml' }, body: SAMPLE }) };
  const items = await rss.fetch(source, ctx);
  assert.strictEqual(items.length, 1);
  assert.match(items[0].title, /Bad thing/);
  assert.strictEqual(items[0].external_id, 'g1');
  assert.strictEqual(items[0].category, 'news');
});
