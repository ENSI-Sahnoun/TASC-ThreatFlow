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

  // A summary that's byte-identical across 2+ items in the same fetch carries no
  // per-item signal (e.g. CERT-EU repeats one "what is a Cyber Brief" paragraph on
  // every entry) — drop it so the title, which does vary, isn't drowned out by
  // repeated boilerplate.
  const counts = new Map();
  for (const item of out) if (item.summary) counts.set(item.summary, (counts.get(item.summary) || 0) + 1);
  for (const item of out) if (item.summary && counts.get(item.summary) > 1) item.summary = null;

  return out;
}
module.exports = { fetch };
