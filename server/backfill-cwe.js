// Re-derives item_cwes for every existing item from raw_json already in hand -- no network
// call, no re-fetch. Same idiom as backfill-cvss.js: writeItem's ON CONFLICT upsert only
// reaches rows a source is still actively returning, so this is the only path that repairs the
// existing corpus after a schema/extraction change like this one.
const { cwesFromRaw } = require('./cwe');

function backfillRow(row) {
  let raw;
  try { raw = JSON.parse(row.raw_json); } catch { return []; }
  return cwesFromRaw(raw);
}

async function backfill(store, { dryRun = false, batchSize = 500 } = {}) {
  let offset = 0;
  let scanned = 0;
  let changed = 0;
  let cwesWritten = 0;

  for (;;) {
    const rows = await store.all(
      `SELECT id, raw_json FROM items WHERE raw_json IS NOT NULL ORDER BY id LIMIT $1 OFFSET $2`,
      [batchSize, offset]);
    if (!rows.length) break;

    for (const row of rows) {
      scanned += 1;
      const cwes = backfillRow(row);

      const existing = (await store.all('SELECT cwe_id FROM item_cwes WHERE item_id = $1', [row.id]))
        .map((r) => r.cwe_id).sort();
      const next = [...cwes].sort();
      const same = existing.length === next.length && existing.every((c, i) => c === next[i]);
      if (same) continue;

      changed += 1;
      if (dryRun) continue;

      await store.run('DELETE FROM item_cwes WHERE item_id = $1', [row.id]);
      for (const c of cwes) {
        await store.run('INSERT INTO item_cwes (item_id, cwe_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [row.id, c]);
        cwesWritten += 1;
      }
    }
    offset += rows.length;
  }

  return { scanned, changed, cwesWritten };
}

module.exports = { backfill, backfillRow };

if (require.main === module) {
  const store = require('./db');
  const dryRun = process.argv.includes('--dry-run');
  backfill(store, { dryRun })
    .then((r) => {
      console.log(`${dryRun ? '[dry run] ' : ''}scanned ${r.scanned}, changed ${r.changed}, cwes ${r.cwesWritten}`);
      return store.close();
    })
    .catch((err) => { console.error(err); process.exit(1); });
}
