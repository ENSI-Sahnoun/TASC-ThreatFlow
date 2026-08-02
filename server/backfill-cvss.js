// Re-derives CVSS score/severity/version and CPE rows over items written before the NVD
// metric chain and CPE extraction existed. Idempotent, no network — raw_json holds the
// untouched upstream record, so every value here is recomputable at any time.
//
// writeItem's ON CONFLICT upsert only reaches rows a source is still actively returning, so
// this is the only path that repairs the existing corpus.
//
// Never overwrites a severity or score already present: a vendor-supplied value outranks
// anything re-derived here.
const { metricFromNvd } = require('./cvss');
const { cpesFromRaw } = require('./cpe');

function backfillRow(row) {
  let raw;
  try { raw = JSON.parse(row.raw_json); } catch { return null; }
  if (!raw || typeof raw !== 'object') return null;

  const metric = row.severity == null && row.cvss_score == null ? metricFromNvd(raw.metrics) : null;
  const cpes = cpesFromRaw(raw);
  if (!metric && !cpes.length) return null;

  return {
    severity: metric ? metric.severity : row.severity,
    cvssScore: metric ? metric.score : row.cvss_score,
    cvssVersion: metric ? metric.version : row.cvss_version,
    cpes,
  };
}

async function backfill(store, { dryRun = false, batchSize = 500 } = {}) {
  let offset = 0;
  let scanned = 0;
  let changed = 0;
  let cpesWritten = 0;
  let skipped = 0;

  for (;;) {
    const rows = await store.all(
      `SELECT id, raw_json, severity, cvss_score, cvss_version
         FROM items WHERE raw_json IS NOT NULL ORDER BY id LIMIT $1 OFFSET $2`,
      [batchSize, offset]);
    if (!rows.length) break;

    for (const row of rows) {
      scanned += 1;
      const next = backfillRow(row);
      if (!next) { skipped += 1; continue; }

      const existing = await store.all('SELECT part, vendor, product FROM item_cpes WHERE item_id=$1', [row.id]);
      const sameCpes = existing.length === next.cpes.length
        && next.cpes.every((c) => existing.some((e) => e.part === c.part && e.vendor === c.vendor && e.product === c.product));
      const sameCols = next.severity === row.severity
        && next.cvssScore === row.cvss_score
        && next.cvssVersion === row.cvss_version;
      if (sameCols && sameCpes) continue;

      changed += 1;
      if (dryRun) continue;

      await store.run(
        'UPDATE items SET severity=$1, cvss_score=$2, cvss_version=$3 WHERE id=$4',
        [next.severity, next.cvssScore, next.cvssVersion, row.id]);
      // Delete-then-insert mirrors writeItem's child-row handling, so reruns cannot accumulate.
      await store.run('DELETE FROM item_cpes WHERE item_id=$1', [row.id]);
      for (const c of next.cpes) {
        await store.run(
          'INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
          [row.id, c.part, c.vendor, c.product]);
        cpesWritten += 1;
      }
    }
    offset += rows.length;
  }

  return { scanned, changed, cpesWritten, skipped };
}

module.exports = { backfill, backfillRow };

if (require.main === module) {
  const store = require('./db');
  const dryRun = process.argv.includes('--dry-run');
  backfill(store, { dryRun })
    .then((r) => {
      console.log(`${dryRun ? '[dry run] ' : ''}scanned ${r.scanned}, changed ${r.changed}, cpes ${r.cpesWritten}, skipped ${r.skipped}`);
      return store.close();
    })
    .catch((err) => { console.error(err); process.exit(1); });
}
