const Parser = require('rss-parser');
const { normalizedItem } = require('./shape');
const { categoryBucket } = require('../normalize');

const parser = new Parser({ timeout: 15000 });

// Real feeds sometimes contain a bare "&" that strict XML rejects; escape only ampersands
// not already part of a recognized entity (same fix as the legacy fetcher).
function sanitize(xml) {
  return xml.replace(/&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)/g, '&amp;');
}

async function fetch(source, ctx) {
  const res = await ctx.request(source.url, { timeoutMs: 15000 });
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
  const feed = await parser.parseString(sanitize(res.body));
  const bucket = categoryBucket(source.category);
  const m = source.mapping || {};
  const out = [];
  for (const entry of feed.items || []) {
    const externalId = entry[m.id] || entry.guid || entry.link || entry.title;
    if (!externalId) continue;
    out.push(normalizedItem({
      external_id: externalId,
      title: entry[m.title] || entry.title || '(untitled)',
      summary: entry[m.summary] || entry.contentSnippet || entry.content || entry.summary || null,
      author: entry[m.author] || entry.creator || entry.author || null,
      link: entry[m.link] || entry.link || null,
      published_at: entry[m.date] || entry.isoDate || entry.pubDate || null,
      category: bucket,
      raw: entry,
    }));
  }
  return out;
}
module.exports = { fetch };
