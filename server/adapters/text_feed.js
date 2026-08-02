const { normalizedItem } = require('./shape');
const { categoryBucket } = require('../normalize');
const { bulkIocSummary } = require('../present');

async function fetch(source, ctx) {
  const res = await ctx.request(source.url, { timeoutMs: 20000 });
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
  const bucket = categoryBucket(source.category);
  const iocType = source.enrichHints?.iocType || null;
  const lines = res.body.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  return lines.slice(0, 200).map((line) => normalizedItem({
    external_id: line,
    title: line,
    // A text feed is a bare URL list with no date, so firstSeen is genuinely null — the
    // template omits the date clause rather than inventing one.
    summary: bulkIocSummary({ category: bucket, value: line, sourceName: source.name, firstSeen: null }),
    link: /^https?:\/\//.test(line) ? line : null,
    category: bucket,
    raw: { line },
    native: iocType ? { iocs: [{ type: iocType, value: line }] } : {},
  }));
}
module.exports = { fetch };
