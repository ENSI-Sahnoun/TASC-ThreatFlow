// Re-derives presentation fields over rows written before present.js existed. Idempotent —
// running it twice changes nothing the second time. Never destroys data: raw_json still holds
// the untouched upstream record, so every value here can be recomputed at any point.
const { displayTitle, cleanSummary, normalizeLink, extractTitleUrl, bulkIocSummary } = require('./present');

function backfillItem(row) {
  const titleUrl = extractTitleUrl(row.title);
  const title = displayTitle(row.title, { category: row.category }) || '(untitled)';
  const link = normalizeLink(row.link) || titleUrl || null;
  // Bulk indicator feeds (OpenPhish, URLhaus) ship one URL per record with no prose. The
  // adapters template a summary at write time, but writeItem's ON CONFLICT upsert only ever
  // reaches rows a feed is still returning — OpenPhish rotates its URLs, so rows written
  // before the template existed would keep a null summary forever without this.
  // A genuine upstream summary always wins.
  const summary = cleanSummary(row.summary)
    || bulkIocSummary({
      category: row.category,
      value: link,
      sourceName: row.source_name,
      firstSeen: row.published_at,
    });
  if (title === row.title && summary === row.summary && link === row.link) return null;
  return { title, summary, link };
}

async function backfill(store, { dryRun = true, batchSize = 500 } = {}) {
  let offset = 0;
  let scanned = 0;
  let changed = 0;
  const samples = [];

  for (;;) {
    const rows = await store.all(
      `SELECT items.id, items.category, items.title, items.summary, items.link, items.published_at,
              sources.name AS source_name
         FROM items JOIN sources ON sources.id = items.source_id
        ORDER BY items.id LIMIT $1 OFFSET $2`,
      [batchSize, offset]);
    if (!rows.length) break;

    for (const row of rows) {
      scanned += 1;
      const next = backfillItem(row);
      if (!next) continue;
      changed += 1;
      if (samples.length < 10) samples.push({ id: row.id, before: row.title, after: next.title });
      if (!dryRun) {
        await store.run('UPDATE items SET title=$1, summary=$2, link=$3 WHERE id=$4',
          [next.title, next.summary, next.link, row.id]);
      }
    }
    offset += rows.length;
  }

  return { scanned, changed, samples };
}

module.exports = { backfill, backfillItem };

if (require.main === module) {
  const store = require('./db');
  const dryRun = process.argv.includes('--dry-run');
  backfill(store, { dryRun })
    .then((r) => {
      console.log(`${dryRun ? '[dry run] ' : ''}scanned ${r.scanned}, changed ${r.changed}`);
      for (const s of r.samples) console.log(`  #${s.id}\n    - ${s.before}\n    + ${s.after}`);
      return store.close();
    })
    .catch((err) => { console.error(err); process.exit(1); });
}
