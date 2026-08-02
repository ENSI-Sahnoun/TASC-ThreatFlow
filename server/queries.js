// Read-side SQL for the v4 endpoints. Kept out of index.js so route handlers stay thin and
// the queries are testable against a temp database without an HTTP layer. This module is the
// last stop before raw SQL, so every query-string value reaching it (still a string, '', or
// undefined) is validated here rather than trusted.

const COVERAGE_FIELDS = ['summary', 'link', 'published_at', 'severity', 'cvss_score', 'vendor', 'region', 'industry', 'confidence'];

// A malformed or absent numeric filter must be treated as "no filter", never as NaN (which
// silently drops every NULL-column row past a `col >= NaN` comparison) or as a raw DB error.
function numOrUndefined(v) {
  if (v === undefined || v === null || v === '') return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

// NVD's backlog re-analysis put 10,232 rows older than five years into the corpus. They stay
// in the database and remain searchable; default listings just do not lead with them.
const DEFAULT_MAX_AGE_DAYS = 365;

// published_at IS NULL means "unknown age", not "old" — dropping the 1,410 undated rows would
// repeat the very defect this filter exists to fix. Pass 0 to disable the filter entirely.
function maxAgeClause(maxAgeDays, ph) {
  const raw = maxAgeDays === undefined || maxAgeDays === null || maxAgeDays === ''
    ? DEFAULT_MAX_AGE_DAYS
    : Number(maxAgeDays);
  if (!Number.isFinite(raw) || raw <= 0) return null;
  return `(items.published_at IS NULL OR items.published_at >= now() - (${ph(raw)} || ' days')::interval)`;
}

function clampedInt(v, def, min, max) {
  const n = numOrUndefined(v);
  const int = n === undefined ? def : Math.trunc(n);
  return Math.min(Math.max(int, min), max);
}

async function sourceStats(store, sourceId) {
  const id = Number(sourceId);
  if (!Number.isInteger(id) || id <= 0) return null;
  const source = await store.get(
    `SELECT id, name, category, conn_type, fetch_kind, url, tier, notes, active, auth_required,
            last_synced_at, last_status, (api_key IS NOT NULL) AS has_apikey
       FROM sources WHERE id = $1`, [id]);
  if (!source) return null;

  const counts = await store.get(
    `SELECT (SELECT count(*) FROM items WHERE source_id=$1)::int AS items,
            (SELECT count(DISTINCT cve_id) FROM item_cves ic JOIN items i ON i.id=ic.item_id WHERE i.source_id=$1)::int AS cves,
            (SELECT count(*) FROM item_iocs io JOIN items i ON i.id=io.item_id WHERE i.source_id=$1)::int AS iocs,
            (SELECT count(DISTINCT actor) FROM item_actors a JOIN items i ON i.id=a.item_id WHERE i.source_id=$1)::int AS actors,
            (SELECT count(DISTINCT family) FROM item_malware_families f JOIN items i ON i.id=f.item_id WHERE i.source_id=$1)::int AS families`,
    [id]);

  const timeline = await store.all(
    `SELECT to_char(date_trunc('month', COALESCE(published_at, fetched_at)), 'YYYY-MM') AS bucket, count(*)::int AS count
       FROM items WHERE source_id=$1
      GROUP BY 1 ORDER BY 1`, [id]);

  const byCategory = await store.all(
    'SELECT category, count(*)::int AS count FROM items WHERE source_id=$1 GROUP BY 1 ORDER BY 2 DESC', [id]);

  const byDomain = await store.all(
    `SELECT d.domain, count(*)::int AS count FROM item_domains d JOIN items i ON i.id=d.item_id
      WHERE i.source_id=$1 GROUP BY 1 ORDER BY 2 DESC`, [id]);

  // Severity only ever gets derived for CVE-bearing categories (see enrich.js) — scoping here
  // matches server/stats.js's dashboard-wide bySeverity so a news-only source doesn't read as
  // "100% unknown severity" when severity was never applicable to begin with.
  const bySeverity = await store.all(
    `SELECT COALESCE(severity,'unknown') AS severity, count(*)::int AS count
       FROM items WHERE source_id=$1 AND category IN ('cve','advisory') GROUP BY 1 ORDER BY 2 DESC`, [id]);

  // Percentage of this source's rows that actually carry each field. This is the widget that
  // makes per-source data quality legible.
  const coverageSelect = COVERAGE_FIELDS
    .map((f) => `COALESCE(round(100.0 * count(${f}) / NULLIF(count(*),0))::int, 0) AS ${f}`)
    .join(', ');
  const fieldCoverage = await store.get(`SELECT ${coverageSelect} FROM items WHERE source_id=$1`, [id]);

  const syncHistory = await store.all(
    `SELECT started_at, finished_at, status, items_new, items_total, error
       FROM source_syncs WHERE source_id=$1 ORDER BY started_at DESC LIMIT 50`, [id]);

  return { source, counts, timeline, byCategory, byDomain, bySeverity, fieldCoverage, syncHistory };
}

async function listCves(store, filters = {}) {
  const where = [];
  const params = [];
  const add = (sql, value) => { params.push(value); where.push(sql.replace('$?', `$${params.length}`)); };

  if (filters.q) {
    params.push(`%${filters.q}%`);
    where.push(`(cve_id ILIKE $${params.length} OR description ILIKE $${params.length})`);
  }
  if (filters.severity) add('severity = $?', filters.severity);
  if (filters.kevOnly) where.push('kev_listed = true');
  const minCvss = numOrUndefined(filters.minCvss);
  if (minCvss !== undefined) add('cvss_score >= $?', minCvss);
  const minEpss = numOrUndefined(filters.minEpss);
  if (minEpss !== undefined) add('epss_score >= $?', minEpss);

  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const limit = clampedInt(filters.limit, 50, 1, 200);
  const offset = clampedInt(filters.offset, 0, 0, Number.MAX_SAFE_INTEGER);

  const totalRow = await store.get(`SELECT count(*)::int AS n FROM cve_intel ${clause}`, params);
  const rows = await store.all(
    `SELECT * FROM cve_intel ${clause}
      ORDER BY kev_listed DESC, cvss_score DESC NULLS LAST, last_seen DESC NULLS LAST
      LIMIT ${limit} OFFSET ${offset}`, params);

  return { rows, total: totalRow.n };
}

async function cveDetail(store, cveId) {
  const cve = await store.get('SELECT * FROM cve_intel WHERE cve_id = $1', [cveId]);
  if (!cve) return null;
  const sources = await store.all(
    `SELECT cs.item_id, cs.source_id, cs.cvss_score, cs.severity, s.name AS source_name,
            s.last_status, i.title, i.link, i.published_at
       FROM cve_sources cs
       JOIN sources s ON s.id = cs.source_id
       JOIN items i ON i.id = cs.item_id
      WHERE cs.cve_id = $1
      ORDER BY i.published_at DESC NULLS LAST`, [cveId]);
  const actors = (await store.all(
    `SELECT DISTINCT a.actor FROM item_actors a
      WHERE a.item_id IN (SELECT item_id FROM cve_sources WHERE cve_id=$1)`, [cveId])).map((r) => r.actor);
  const families = (await store.all(
    `SELECT DISTINCT f.family FROM item_malware_families f
      WHERE f.item_id IN (SELECT item_id FROM cve_sources WHERE cve_id=$1)`, [cveId])).map((r) => r.family);
  return { cve, sources, actors, families };
}

async function entityProfile(store, kind, name) {
  if (kind !== 'actor' && kind !== 'family') return null;
  const table = kind === 'actor' ? 'item_actors' : 'item_malware_families';
  const column = kind === 'actor' ? 'actor' : 'family';

  const countRow = await store.get(
    `SELECT count(*)::int AS n FROM ${table} WHERE ${column} = $1`, [name]);
  if (!countRow.n) return null;

  const items = await store.all(
    `SELECT i.id, i.title, i.summary, i.category, i.severity, i.published_at, s.name AS source_name, s.last_status
       FROM ${table} e JOIN items i ON i.id = e.item_id JOIN sources s ON s.id = i.source_id
      WHERE e.${column} = $1 ORDER BY i.published_at DESC NULLS LAST LIMIT 100`, [name]);

  const cves = (await store.all(
    `SELECT DISTINCT c.cve_id FROM item_cves c
      WHERE c.item_id IN (SELECT item_id FROM ${table} WHERE ${column} = $1) ORDER BY 1`, [name])).map((r) => r.cve_id);

  const sources = await store.all(
    `SELECT s.id, s.name, s.last_status, count(*)::int AS count
       FROM ${table} e JOIN items i ON i.id = e.item_id JOIN sources s ON s.id = i.source_id
      WHERE e.${column} = $1 GROUP BY 1,2,3 ORDER BY 4 DESC`, [name]);

  // Cross-link to the other entity kind sharing at least one item — malware families used by an
  // actor, or actors observed using a malware family. Same join pattern cveDetail() already uses
  // for its actors/families lookup.
  const relatedTable = kind === 'actor' ? 'item_malware_families' : 'item_actors';
  const relatedColumn = kind === 'actor' ? 'family' : 'actor';
  const related = (await store.all(
    `SELECT DISTINCT r.${relatedColumn} AS name FROM ${relatedTable} r
      WHERE r.item_id IN (SELECT item_id FROM ${table} WHERE ${column} = $1)`, [name])).map((r) => r.name);

  const timeline = await store.all(
    `SELECT to_char(date_trunc('month', COALESCE(i.published_at, i.fetched_at)), 'YYYY-MM') AS bucket, count(*)::int AS count
       FROM ${table} e JOIN items i ON i.id = e.item_id
      WHERE e.${column} = $1 GROUP BY 1 ORDER BY 1`, [name]);

  return { kind, name, itemCount: countRow.n, items, cves, sources, related, timeline };
}

async function feed(store, { since = null, limit = 50 } = {}) {
  const capped = clampedInt(limit, 50, 1, 200);
  const params = [];
  // 'malware'/'ioc' are raw indicator dumps (ThreatFox/URLhaus/Feodo/DShield — "Cobalt Strike:
  // 1.2.3.4:443", "Attacking IP: x.x.x.x"), not narrative intel. They're still fully browsable
  // via the Intel Explorer, Arsenal, and IOC export — just not what a "Live intel" story stream
  // is for.
  const clauses = [`i.category NOT IN ('malware','ioc')`];
  // An unparseable `since` is treated as absent rather than left to fail as a raw timestamptz
  // cast error at the DB.
  if (since && !Number.isNaN(Date.parse(since))) {
    params.push(since); clauses.push(`cl.last_seen > $${params.length}`);
  }

  return store.all(
    `SELECT cl.id AS cluster_id, cl.title, cl.first_seen, cl.last_seen, cl.source_count,
            i.id AS item_id, i.category, i.summary, i.severity, i.link, i.confidence,
            s.name AS source_name, s.last_status AS source_status, s.fetch_kind AS source_fetch_kind
       FROM clusters cl
       JOIN items i ON i.id = cl.primary_item_id
       JOIN sources s ON s.id = i.source_id
      WHERE ${clauses.join(' AND ')}
      ORDER BY cl.last_seen DESC NULLS LAST
      LIMIT ${capped}`, params);
}

async function search(store, q, limit = 8) {
  const like = `%${q}%`;
  const capped = clampedInt(limit, 8, 1, 25);
  const [items, cves, actors, families, sources] = await Promise.all([
    store.all(`SELECT id, title, category FROM items WHERE title ILIKE $1 ORDER BY published_at DESC NULLS LAST LIMIT ${capped}`, [like]),
    store.all(`SELECT cve_id, severity, cvss_score FROM cve_intel WHERE cve_id ILIKE $1 ORDER BY cvss_score DESC NULLS LAST LIMIT ${capped}`, [like]),
    store.all(`SELECT DISTINCT actor FROM item_actors WHERE actor ILIKE $1 ORDER BY 1 LIMIT ${capped}`, [like]),
    store.all(`SELECT DISTINCT family FROM item_malware_families WHERE family ILIKE $1 ORDER BY 1 LIMIT ${capped}`, [like]),
    store.all(`SELECT id, name, last_status FROM sources WHERE name ILIKE $1 ORDER BY name LIMIT ${capped}`, [like]),
  ]);
  return { items, cves, actors, families, sources };
}

// Mirrors the exact filter set (and WHERE-building style) GET /api/items supports, so
// "Export CSV" / "Copy all IOCs" cover exactly what the explorer's current filters show —
// previously only source_id/category/type were honored here, so most filter combinations
// silently exported far more than what was on screen.
async function iocRows(store, filters = {}) {
  const where = [];
  const params = [];
  const ph = (v) => { params.push(v); return `$${params.length}`; };

  const sourceId = numOrUndefined(filters.source_id);
  if (sourceId !== undefined) where.push(`i.source_id = ${ph(sourceId)}`);
  if (filters.category) where.push(`i.category = ${ph(filters.category)}`);
  if (filters.type) where.push(`io.ioc_type = ${ph(filters.type)}`);

  if (filters.q) {
    const like = `%${filters.q}%`;
    where.push(`(i.title ILIKE ${ph(like)} OR i.summary ILIKE ${ph(like)} OR i.author ILIKE ${ph(like)} OR s.name ILIKE ${ph(like)})`);
  }

  const joinFilters = [
    ['domain', 'item_domains', 'domain'],
    ['actor', 'item_actors', 'actor'],
    ['malware_family', 'item_malware_families', 'family'],
    ['cve', 'item_cves', 'cve_id'],
  ];
  for (const [key, tbl, col] of joinFilters) {
    if (filters[key]) where.push(`i.id IN (SELECT item_id FROM ${tbl} WHERE ${col} = ${ph(filters[key])})`);
  }

  // Mirrors GET /api/items' 'unknown' handling: that bucket is COALESCE(severity,'unknown'),
  // covering both the literal string and NULL rows — a plain equality would only match the
  // former and export fewer IOCs than the explorer showed for the same filter.
  if (filters.severity) {
    where.push(filters.severity === 'unknown'
      ? `(i.severity IS NULL OR i.severity = ${ph(filters.severity)})`
      : `i.severity = ${ph(filters.severity)}`);
  }
  for (const col of ['exploitation_status', 'vendor', 'region', 'industry']) {
    if (filters[col]) where.push(`i.${col} = ${ph(filters[col])}`);
  }

  // confidence is nullable and often unset; NULL >= x is never true, so tolerate NULL the same
  // way /api/items does rather than silently dropping every un-scored row.
  const minConfidence = numOrUndefined(filters.min_confidence);
  if (minConfidence !== undefined) where.push(`(i.confidence IS NULL OR i.confidence >= ${ph(minConfidence)})`);

  // Mirrors GET /api/items' cluster-dedup exclusion: a cluster's non-primary members are
  // duplicates of the same story from other sources, invisible in the explorer's table (they
  // collapse behind the "N sources" badge). Without this, the export/copy-all count would
  // include IOCs belonging to rows the table never shows, inflating the reported total beyond
  // what's actually visible.
  where.push(`i.id NOT IN (
    SELECT ci.item_id FROM cluster_items ci JOIN clusters cl ON cl.id = ci.cluster_id
    WHERE cl.primary_item_id <> ci.item_id
  )`);

  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  return store.all(
    `SELECT io.ioc_type AS type, io.ioc_value AS value, i.id AS "itemId",
            s.name AS "sourceName", i.published_at AS "firstSeen"
       FROM item_iocs io
       JOIN items i ON i.id = io.item_id
       JOIN sources s ON s.id = i.source_id
       ${clause}
      ORDER BY i.published_at DESC NULLS LAST
      LIMIT 5000`, params);
}

// Autocomplete source for the onboarding survey's tech-stack step. Reads item_cpes (2,706
// distinct vendors) rather than items.vendor, which is populated on under 1% of rows and holds
// 34 values — a survey built on the latter would offer almost nothing to pick.
//
// `kind` selects a column name, so it is resolved through a whitelist rather than interpolated:
// an unknown value falls back to 'vendor' instead of reaching SQL.
async function cpeFacets(store, { q = '', kind = 'vendor', limit } = {}) {
  const col = kind === 'product' ? 'product' : 'vendor';
  const lim = clampedInt(limit, 50, 1, 200);
  const params = [lim];
  let where = '';
  const term = typeof q === 'string' ? q.trim() : '';
  if (term) {
    params.push(`%${term.toLowerCase()}%`);
    where = `WHERE ${col} LIKE $${params.length}`;
  }
  return store.all(
    `SELECT ${col} AS value, count(*)::int AS refs
       FROM item_cpes ${where}
      GROUP BY 1 ORDER BY refs DESC, value ASC LIMIT $1`, params);
}

module.exports = { sourceStats, listCves, cveDetail, entityProfile, feed, search, iocRows, cpeFacets, COVERAGE_FIELDS, DEFAULT_MAX_AGE_DAYS, maxAgeClause };
