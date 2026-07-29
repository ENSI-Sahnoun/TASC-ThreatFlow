// Additive, read-only dashboard aggregations. Severity is guaranteed canonical at ingest time,
// so no read-time coercion happens there. Malware-family values are NOT cleaned at ingest —
// they come straight from upstream feeds as free text (arch strings, raw IPs), so top-malware
// still filters that noise here.
const { DOMAINS } = require('./domains');

const FAMILY_STOP = new Set(['elf', 'mips', 'arm', '32-bit', '64-bit', 'x86', 'x64', 'win32', 'win64', 'pe', 'apk']);
const DOMAIN_LABEL = new Map(DOMAINS.map((d) => [d.slug, d.label]));

async function dashboardStats(store) {
  const total = (await store.get('SELECT COUNT(*)::int AS c FROM items')).c;

  const byCategory = (await store.all(
    'SELECT category, COUNT(*)::int AS count FROM items GROUP BY category ORDER BY count DESC'));

  const byDomainRaw = await store.all(
    'SELECT domain, COUNT(*)::int AS count FROM item_domains GROUP BY domain ORDER BY count DESC');
  const byDomain = byDomainRaw.map((r) => ({ ...r, label: DOMAIN_LABEL.get(r.domain) || r.domain }));

  const byExploitation = await store.all(
    "SELECT COALESCE(exploitation_status,'unknown') AS status, COUNT(*)::int AS count " +
    'FROM items GROUP BY 1 ORDER BY count DESC');

  // Severity is only ever derived for CVE-bearing categories (enrich.js needs a CVSS score
  // or vector) — counting the rest as 'unknown' would conflate "not applicable" with "not yet
  // scored" and dwarf the real gap. Same category pair the critical-advisories KPI uses below.
  const bySeverity = await store.all(
    "SELECT COALESCE(severity, 'unknown') AS severity, COUNT(*)::int AS count " +
    "FROM items WHERE category IN ('cve','advisory') GROUP BY 1 ORDER BY count DESC");

  const topActors = await store.all(
    'SELECT actor, COUNT(*)::int AS count FROM item_actors GROUP BY actor ORDER BY count DESC LIMIT 15');

  // Filter IOC noise: families starting with a digit (IP-shaped) or in the arch/format stop-set.
  const malwareRaw = await store.all(
    "SELECT family, COUNT(*)::int AS count FROM item_malware_families " +
    "WHERE family !~ '^[0-9]' GROUP BY family ORDER BY count DESC LIMIT 40");
  const topMalware = malwareRaw
    .filter((r) => !FAMILY_STOP.has(r.family.toLowerCase()))
    .slice(0, 12);

  // Prefer the canonical CVE-category record for drill-down; fall back to the lowest-id
  // item mentioning the CVE (e.g. a news/advisory article) when no 'cve' item exists.
  const topCves = await store.all(
    'SELECT ic.cve_id AS cve, COUNT(*)::int AS count, MAX(i.cvss_score) AS "maxCvss", ' +
    'COALESCE(MIN(i.id) FILTER (WHERE i.category = \'cve\'), MIN(i.id))::int AS "itemId" ' +
    'FROM item_cves ic JOIN items i ON i.id = ic.item_id ' +
    'GROUP BY ic.cve_id ORDER BY count DESC, "maxCvss" DESC NULLS LAST LIMIT 12');

  // Targeted countries: ISO-2 region codes, merged with any ip_intel country codes.
  const regionRows = await store.all(
    "SELECT region AS code, COUNT(*)::int AS count FROM items WHERE region ~ '^[A-Z]{2}$' GROUP BY region");
  const ipRows = await store.all(
    "SELECT country_code AS code, COUNT(*)::int AS count FROM ip_intel " +
    "WHERE country_code ~ '^[A-Za-z]{2}$' GROUP BY country_code");
  const countryMap = new Map();
  for (const r of [...regionRows, ...ipRows]) {
    const code = r.code.toUpperCase();
    countryMap.set(code, (countryMap.get(code) || 0) + r.count);
  }
  const targetedCountries = [...countryMap.entries()]
    .map(([code, count]) => ({ code, count })).sort((a, b) => b.count - a.count);

  const timeline = await store.all(
    "SELECT to_char(date_trunc('month', COALESCE(published_at, fetched_at)), 'YYYY-MM') AS bucket, " +
    'COUNT(*)::int AS count FROM items ' +
    "WHERE COALESCE(published_at, fetched_at) >= now() - interval '12 months' GROUP BY 1 ORDER BY 1");

  const latestReports = await store.all(
    'SELECT items.id, items.title, items.category, sources.name AS source_name, items.published_at ' +
    'FROM items JOIN sources ON sources.id = items.source_id ' +
    "WHERE items.category IN ('news','advisory','osint') " +
    'ORDER BY COALESCE(items.published_at, items.fetched_at) DESC LIMIT 10');

  const topSources = await store.all(
    'SELECT sources.id, sources.name, COUNT(items.id)::int AS item_count ' +
    'FROM sources LEFT JOIN items ON items.source_id = sources.id ' +
    'GROUP BY sources.id ORDER BY item_count DESC LIMIT 5');

  const health = await store.get(
    'SELECT COUNT(*) FILTER (WHERE active)::int AS active_count, ' +
    "COUNT(*) FILTER (WHERE last_status LIKE 'error:%')::int AS error_count, " +
    "COUNT(*) FILTER (WHERE last_status = 'unsupported')::int AS unsupported_count, " +
    'COUNT(*) FILTER (WHERE last_synced_at IS NULL)::int AS never_synced_count, ' +
    'COUNT(*)::int AS total_sources FROM sources');

  const payload = {
    total, generatedAt: new Date().toISOString(),
    byCategory, byDomain, byExploitation, bySeverity,
    topActors, topMalware, topCves, targetedCountries, timeline,
    latestReports, topSources, health,
  };

  const { kpis: kpiTiles, sourceHealth } = await kpis(store);
  return { ...payload, kpis: kpiTiles, sourceHealth };
}

// A KPI tile is a value, its change over the comparison window, and a 14-day series for the
// sparkline. Every tile answers "what changed", which is why the dashboard leads with them.
async function kpiSeries(store, sql, params = []) {
  const rows = await store.all(sql, params);
  return rows.map((r) => Number(r.count));
}

async function kpis(store) {
  const daily = (where) => `
    SELECT to_char(d.day, 'YYYY-MM-DD') AS bucket, count(i.id)::int AS count
      FROM generate_series(now() - interval '13 days', now(), interval '1 day') AS d(day)
      LEFT JOIN items i ON date_trunc('day', COALESCE(i.published_at, i.fetched_at)) = date_trunc('day', d.day) AND ${where}
     GROUP BY 1 ORDER BY 1`;

  const [exploited, iocs, critical, health] = await Promise.all([
    kpiSeries(store, daily("i.exploitation_status = 'actively_exploited'")),
    kpiSeries(store, `
      SELECT to_char(d.day, 'YYYY-MM-DD') AS bucket, count(io.item_id)::int AS count
        FROM generate_series(now() - interval '13 days', now(), interval '1 day') AS d(day)
        LEFT JOIN items i ON date_trunc('day', COALESCE(i.published_at, i.fetched_at)) = date_trunc('day', d.day)
        LEFT JOIN item_iocs io ON io.item_id = i.id
       GROUP BY 1 ORDER BY 1`),
    kpiSeries(store, daily("i.severity = 'critical' AND i.category IN ('advisory','cve')")),
    store.get(`
      SELECT count(*)::int AS total,
             count(*) FILTER (WHERE last_status = 'ok')::int AS ok,
             count(*) FILTER (WHERE last_status LIKE 'error%')::int AS error,
             count(*) FILTER (WHERE last_status = 'unsupported')::int AS unsupported,
             count(*) FILTER (WHERE last_status IS NULL)::int AS "neverSynced"
        FROM sources`),
  ]);

  // delta = last full day vs the day before, so a tile never reads "0" mid-day.
  const tile = (series) => {
    const value = series.reduce((a, b) => a + b, 0);
    const delta = series.length >= 2 ? series[series.length - 1] - series[series.length - 2] : 0;
    return { value, delta, series };
  };

  return {
    kpis: {
      activelyExploited: tile(exploited),
      newIocs24h: tile(iocs),
      criticalAdvisories7d: tile(critical),
      sourcesHealthy: { value: health.ok, delta: 0, series: [] },
    },
    sourceHealth: health,
  };
}

module.exports = { dashboardStats };
