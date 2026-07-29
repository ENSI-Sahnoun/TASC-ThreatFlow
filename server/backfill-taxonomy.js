// Re-derives category and severity over rows the write path never touches again.
//
// syncSource only reaches the ON CONFLICT DO UPDATE branch of writeItem for external_ids an
// adapter still returns. Feeds with a rolling window (OpenPhish's active-URL list, an RSS
// source's last-N-posts page) stop returning old external_ids once they age out, so any item
// ingested before a taxonomy/severity fix landed keeps its pre-fix value forever — no future
// sync ever revisits it. This script re-derives both fields from data already on the row
// (the owning source's category label, and whatever raw severity label/blob is stored) using
// the exact same pure functions the live write path uses, so a backfilled value is byte-for-byte
// what a fresh sync would have written. Idempotent — running it twice changes nothing the
// second time. Never destroys data: raw_json still holds the untouched upstream record.
const { categoryBucket } = require('./normalize');
const { canonicalSeverity } = require('./cvss');

function backfillItem(row) {
  const category = categoryBucket(row.source_category);
  const severity = row.severity == null ? null : canonicalSeverity(row.severity);
  if (category === row.category && severity === row.severity) return null;
  return { category, severity };
}

async function backfill(store, { dryRun = true, batchSize = 500 } = {}) {
  let offset = 0;
  let scanned = 0;
  let changed = 0;
  const samples = [];

  for (;;) {
    const rows = await store.all(
      `SELECT items.id, items.category, items.severity, sources.category AS source_category
       FROM items JOIN sources ON sources.id = items.source_id
       ORDER BY items.id LIMIT $1 OFFSET $2`,
      [batchSize, offset]);
    if (!rows.length) break;

    for (const row of rows) {
      scanned += 1;
      const next = backfillItem(row);
      if (!next) continue;
      changed += 1;
      if (samples.length < 10) {
        samples.push({
          id: row.id,
          before: { category: row.category, severity: row.severity },
          after: next,
        });
      }
      if (!dryRun) {
        await store.run('UPDATE items SET category=$1, severity=$2 WHERE id=$3',
          [next.category, next.severity, row.id]);
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
      for (const s of r.samples) {
        console.log(`  #${s.id}\n    - ${JSON.stringify(s.before)}\n    + ${JSON.stringify(s.after)}`);
      }
      return store.close();
    })
    .catch((err) => { console.error(err); process.exit(1); });
}
