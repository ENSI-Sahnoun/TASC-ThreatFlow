const appStore = require('./db');
const { getAdapter } = require('./adapters');
const { enrichItem } = require('./enrich');
const { safeRequest } = require('./safe-request');
const { enrichIps } = require('./shodan_enrich');
const { detectFields } = require('./field_detect');

// Sources emit dates in mixed formats (ISO 8601, RFC-822 `Wed, 20 Jun 2018 ...`,
// `2024-01-01 12:00:00 UTC`). Canonicalize to ISO 8601 so the timestamptz column parses
// them and recency ordering is chronological rather than lexical.
function normalizeDate(v) {
  if (v == null || v === '') return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

// Persist raw source JSON, but never store a mid-token slice: a byte-truncated blob is
// invalid JSON and throws for any consumer that parses it. Replace oversized blobs with
// a valid marker instead.
function serializeRaw(raw) {
  if (raw == null) return null;
  const s = JSON.stringify(raw);
  if (s.length <= 20000) return s;
  return JSON.stringify({ _truncated: true, _original_length: s.length });
}

async function loadKevCveSet(store) {
  const rows = await store.all("SELECT cve_id FROM item_cves JOIN items ON items.id = item_cves.item_id WHERE items.exploitation_status = 'actively_exploited'");
  return new Set(rows.map((r) => r.cve_id));
}

// One row per completed sync. Written at the end rather than as a running/finished pair so a
// crashed process can never leave a dangling 'running' row.
async function recordSync(store, sourceId, startedAt, { status, itemsNew = 0, itemsTotal = 0, error = null }) {
  await store.run(
    `INSERT INTO source_syncs (source_id, started_at, finished_at, status, items_new, items_total, error)
     VALUES ($1,$2,now(),$3,$4,$5,$6)`,
    [sourceId, startedAt, status, itemsNew, itemsTotal, error]);
}

// Writes one item + its enrichment child rows. `t` is a transaction-scoped store.
async function writeItem(t, sourceId, item, enr) {
  const externalId = item.external_id != null ? String(item.external_id) : null;
  const inserted = await t.get(
    `INSERT INTO items (source_id, category, title, summary, author, link, published_at, external_id, raw_json, severity, cvss_score, epss_score, exploitation_status, vendor, region, industry, threat_type, cvss_version)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
     ON CONFLICT (source_id, external_id) DO UPDATE SET
       category=excluded.category, title=excluded.title, summary=excluded.summary, author=excluded.author, link=excluded.link,
       published_at=excluded.published_at, fetched_at=now(), raw_json=excluded.raw_json,
       severity=excluded.severity, cvss_score=excluded.cvss_score, cvss_version=excluded.cvss_version, epss_score=excluded.epss_score,
       exploitation_status=excluded.exploitation_status,
       vendor=excluded.vendor, region=excluded.region, industry=excluded.industry, threat_type=excluded.threat_type
     RETURNING id, (xmax = 0) AS inserted`,
    [
      sourceId,
      item.category,
      String(item.title || '(untitled)'),
      item.summary || null,
      item.author || null,
      item.link || null,
      normalizeDate(item.published_at),
      externalId,
      serializeRaw(item.raw),
      enr.severity,
      enr.cvssScore,
      enr.epssScore,
      enr.exploitationStatus,
      enr.vendor,
      enr.region,
      enr.industry,
      enr.threatType,
      enr.cvssVersion,
    ]
  );
  const itemId = inserted.id;
  const isNew = inserted.inserted === true;

  // Enrichment child rows are idempotent: clear then re-insert for this item.
  for (const tbl of ['item_cves', 'item_iocs', 'item_actors', 'item_malware_families', 'item_domains', 'item_cpes']) {
    await t.run(`DELETE FROM ${tbl} WHERE item_id = $1`, [itemId]);
  }
  for (const c of enr.cves) await t.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [itemId, c]);
  for (const io of enr.iocs) await t.run('INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [itemId, io.type, io.value]);
  for (const a of enr.actors) await t.run('INSERT INTO item_actors (item_id, actor) VALUES ($1, $2) ON CONFLICT DO NOTHING', [itemId, a]);
  for (const f of enr.families) await t.run('INSERT INTO item_malware_families (item_id, family) VALUES ($1, $2) ON CONFLICT DO NOTHING', [itemId, f]);
  for (const d of enr.domains) await t.run('INSERT INTO item_domains (item_id, domain) VALUES ($1, $2) ON CONFLICT DO NOTHING', [itemId, d]);
  for (const c of enr.cpes || []) {
    await t.run('INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
      [itemId, c.part, c.vendor, c.product]);
  }
  return { itemId, isNew };
}

async function syncSource(source, opts = {}) {
  const startedAt = new Date();
  const store = opts.store || opts.db || appStore;
  const request = opts.request || safeRequest;
  const now = opts.now || (() => new Date());
  const kevCveSet = opts.kevCveSet || new Set();
  const configByName = opts.configByName || {};
  const kind = source.kind || source.fetch_kind;

  if (kind === 'unsupported' || !kind) {
    await store.run("UPDATE sources SET last_status='unsupported', last_synced_at=now() WHERE id=$1", [source.id]);
    await recordSync(store, source.id, startedAt, { status: 'unsupported' });
    return { status: 'unsupported', itemsFetched: 0 };
  }
  try {
    const adapter = getAdapter(kind);
    // Rows loaded from the DB carry only the columns in the `sources` table; adapter-facing
    // config (auth, field mapping, recordsPath, enrichHints) lives only in sources.config.js.
    // Without merging it in, adapters silently send unauthenticated requests / drop every
    // mapped field instead of erroring.
    const cfg = configByName[source.name];
    if (cfg) {
      for (const key of ['auth', 'mapping', 'recordsPath', 'enrichHints', 'method']) {
        if (source[key] == null && cfg[key] != null) source[key] = cfg[key];
      }
    }
    // Operator-set field overrides (from the source-edit UI) win over both the
    // registry's enrichHints and the adapter's own auto-detection.
    const overrides = {
      cveField: source.cve_field || undefined,
      cvssField: source.cvss_field || undefined,
      severityField: source.severity_field || undefined,
      vendorField: source.vendor_field || undefined,
    };
    if (Object.values(overrides).some((v) => v !== undefined)) {
      source.enrichHints = { ...(source.enrichHints || {}), ...Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== undefined)) };
    }
    const items = await adapter.fetch(source, { request, now });
    if (kind === 'json_api' && items.length && items[0].raw) {
      try {
        const detected = detectFields(items[0].raw);
        await store.run('UPDATE sources SET detected_mapping_json = $1 WHERE id = $2', [JSON.stringify(detected), source.id]);
      } catch { /* best-effort, never fails the sync */ }
    }
    const configDomains = (configByName[source.name]?.domains) || [];
    const ipsSeen = [];
    let newCount = 0;
    const itemsFetched = await store.tx(async (t) => {
      let n = 0;
      for (const item of items) {
        if (!item || !item.external_id) continue;
        const enr = enrichItem(item, { kevCveSet });
        enr.domains = [...new Set([...enr.domains, ...configDomains])];
        const { isNew } = await writeItem(t, source.id, item, enr);
        if (isNew) newCount += 1;
        for (const io of enr.iocs) if (io.type === 'ip') ipsSeen.push(io.value);
        n += 1;
      }
      return n;
    });
    // Sweep leftover junk rows from old adapter/mapping bugs (fixed since, e.g. Vulnetix
    // pre-f710851) that a fresh sync no longer reproduces and thus never overwrites via
    // the (source_id, external_id) upsert key.
    await store.run("DELETE FROM items WHERE source_id = $1 AND (title = '(untitled)' OR external_id = 'undefined')", [source.id]);
    if (ipsSeen.length) {
      const shodanRow = await store.get("SELECT api_key FROM sources WHERE name = 'Shodan (IP enrichment)'");
      const apiKey = (shodanRow && shodanRow.api_key) || process.env.SHODAN_API_KEY;
      await enrichIps(store, ipsSeen, { request, now, apiKey }).catch(() => {});
    }
    await store.run("UPDATE sources SET last_status='ok', last_synced_at=now() WHERE id=$1", [source.id]);
    await recordSync(store, source.id, startedAt, { status: 'ok', itemsNew: newCount, itemsTotal: itemsFetched });
    return { status: 'ok', itemsFetched };
  } catch (err) {
    const msg = String(err.message || err).slice(0, 300);
    await store.run('UPDATE sources SET last_status=$1, last_synced_at=now() WHERE id=$2', [`error: ${msg}`, source.id]);
    await recordSync(store, source.id, startedAt, { status: `error: ${msg}`, error: msg });
    return { status: `error: ${msg}`, itemsFetched: 0 };
  }
}

module.exports = { syncSource, writeItem, loadKevCveSet, normalizeDate };
