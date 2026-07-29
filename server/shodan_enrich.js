// IP enrichment via Shodan. Not a ThreatFlow "source" — no feed of new items exists on a
// free/oss-plan key (/shodan/host/search returns "Requires membership or higher").
// Instead this attaches exposure context (open ports, known vulns, org/geo) to IP IOCs
// that other sources (URLhaus, ThreatFox, Feodo Tracker) already ingest.
//
// Two tiers, both best-effort:
//   - InternetDB (internetdb.shodan.io): free, unlimited, no key. Primary source for
//     ports/vulns/tags/cpes.
//   - Shodan host lookup (api.shodan.io/shodan/host/<ip>): only attempted if an API key is
//     available — from the "Shodan (IP enrichment)" source row's api_key (settable via the
//     Ingestion page, same as any other key-gated source) or the SHODAN_API_KEY env var as
//     a fallback. Adds org/isp/city/country. Swallowed on any error (missing key, exhausted
//     credits, plan restriction) since it's a bonus field, not required.
//
// Results are cached in ip_intel with a TTL so re-syncing sources doesn't re-hit Shodan
// for IPs seen minutes ago.
//
// Future: when a paid/membership key is available, /shodan/host/search can drive a real
// standalone source (e.g. curated vuln: queries) — keep that as a separate adapter+config
// entry rather than folding it into this enrichment path.

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

async function fetchInternetDb(ip, request) {
  const res = await request(`https://internetdb.shodan.io/${ip}`, { timeoutMs: 10000 });
  if (res.status === 404) return null; // no data for this IP
  if (res.status < 200 || res.status >= 300) throw new Error(`internetdb HTTP ${res.status}`);
  return JSON.parse(res.body);
}

async function fetchShodanHost(ip, request, apiKey) {
  const res = await request(`https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(apiKey)}`, { timeoutMs: 10000 });
  if (res.status < 200 || res.status >= 300) throw new Error(`shodan host HTTP ${res.status}`);
  const body = JSON.parse(res.body);
  if (body.error) throw new Error(body.error);
  return body;
}

async function enrichIp(ip, { request, apiKey }) {
  const record = { ip, ports: [], vulns: [], tags: [], cpes: [], hostnames: [], org: null, isp: null, city: null, country_code: null, source: 'internetdb' };

  const idb = await fetchInternetDb(ip, request).catch(() => null);
  if (idb) {
    record.ports = idb.ports || [];
    record.vulns = idb.vulns || [];
    record.tags = idb.tags || [];
    record.cpes = idb.cpes || [];
    record.hostnames = idb.hostnames || [];
  }

  if (apiKey) {
    const host = await fetchShodanHost(ip, request, apiKey).catch(() => null);
    if (host) {
      record.org = host.org || null;
      record.isp = host.isp || null;
      record.city = host.city || null;
      record.country_code = host.country_code || null;
      record.source = idb ? 'internetdb+shodan' : 'shodan';
    }
  }

  return (idb || record.org) ? record : null;
}

function isFresh(row, now) {
  if (!row) return false;
  // fetched_at comes back from pg as a Date (timestamptz).
  return now - new Date(row.fetched_at).getTime() < CACHE_TTL_MS;
}

// Looks up + caches IP intel for a set of IOC IPs. Best-effort: network/parse errors for
// an individual IP are swallowed so one bad lookup doesn't fail the whole sync.
async function enrichIps(store, ips, { request, now = () => new Date(), apiKey = process.env.SHODAN_API_KEY } = {}) {
  const uniqueIps = [...new Set(ips)];
  if (!uniqueIps.length) return;
  const nowMs = now().getTime();

  for (const ip of uniqueIps) {
    const cached = await store.get('SELECT * FROM ip_intel WHERE ip = $1', [ip]);
    if (isFresh(cached, nowMs)) continue;
    const record = await enrichIp(ip, { request, apiKey }).catch(() => null);
    if (!record) continue;
    await store.run(
      `INSERT INTO ip_intel (ip, ports_json, vulns_json, tags_json, cpes_json, hostnames_json, org, isp, city, country_code, source)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (ip) DO UPDATE SET
         ports_json=excluded.ports_json, vulns_json=excluded.vulns_json, tags_json=excluded.tags_json,
         cpes_json=excluded.cpes_json, hostnames_json=excluded.hostnames_json, org=excluded.org, isp=excluded.isp,
         city=excluded.city, country_code=excluded.country_code, source=excluded.source, fetched_at=now()`,
      [
        ip,
        JSON.stringify(record.ports),
        JSON.stringify(record.vulns),
        JSON.stringify(record.tags),
        JSON.stringify(record.cpes),
        JSON.stringify(record.hostnames),
        record.org,
        record.isp,
        record.city,
        record.country_code,
        record.source,
      ]
    );
  }
}

module.exports = { enrichIps, enrichIp };
