// Re-derives items.cvss_vector from raw_json. Idempotent, no network — raw_json preserves the
// untouched upstream record, so the vector is recomputable at any time.
//
// writeItem's ON CONFLICT upsert only reaches rows a source is still actively returning, so
// this is the only path that populates the existing corpus.
//
// Note the inverted default, matching the other backfills in this directory: a bare invocation
// WRITES. Pass --dry-run to preview.
const { parseVector } = require('./cvss');

// v3.1 first, then v3.0. v2 is deliberately absent: cvss.js recognises but does not score it,
// and consequence.js reads v3 metric names (PR, UI, S) that a v2 vector does not carry, so a
// stored v2 string would be a value every consumer has to special-case.
const KEYS = ['cvssMetricV31', 'cvssMetricV30'];

function vectorFromRaw(raw) {
  if (!raw || typeof raw !== 'object' || !raw.metrics) return null;
  for (const key of KEYS) {
    const entries = raw.metrics[key];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      const vector = entry && entry.cvssData && entry.cvssData.vectorString;
      // parseVector is the gate: an unparseable string is never stored, so every value in the
      // column is one consequence.js can actually read.
      if (typeof vector === 'string' && parseVector(vector)) return vector;
    }
  }
  return null;
}

async function backfill(store, { dryRun = false, batchSize = 500 } = {}) {
  let offset = 0;
  let scanned = 0;
  let changed = 0;
  let skipped = 0;

  for (;;) {
    const rows = await store.all(
      `SELECT id, raw_json, cvss_vector FROM items
        WHERE raw_json IS NOT NULL ORDER BY id LIMIT $1 OFFSET $2`,
      [batchSize, offset]);
    if (!rows.length) break;

    for (const row of rows) {
      scanned += 1;
      let raw;
      try { raw = JSON.parse(row.raw_json); } catch { skipped += 1; continue; }
      const vector = vectorFromRaw(raw);
      // Absence over destruction: a row we cannot derive a vector for keeps whatever it has.
      if (!vector || vector === row.cvss_vector) { skipped += 1; continue; }

      changed += 1;
      if (dryRun) continue;
      await store.run('UPDATE items SET cvss_vector = $1 WHERE id = $2', [vector, row.id]);
    }
    // Paging by offset is safe here because the UPDATE does not change the ORDER BY key.
    offset += rows.length;
  }

  return { scanned, changed, skipped };
}

module.exports = { backfill, vectorFromRaw };

if (require.main === module) {
  const store = require('./db');
  const dryRun = process.argv.includes('--dry-run');
  backfill(store, { dryRun })
    .then((r) => { console.log(dryRun ? 'dry run:' : 'wrote:', r); return store.close(); })
    .catch((e) => { console.error(e); process.exit(1); });
}
