const { normalizedItem } = require('./shape');
const { categoryBucket } = require('../normalize');
const { metricFromNvd, scoreFromVector, severityFromScore } = require('../cvss');
const { cpesFromRaw } = require('../cpe');

const kev = {
  async fetch(source, ctx) {
    const limit = Number(source.requestBody) || 100;
    const res = await ctx.request(source.url, { timeoutMs: 25000, headers: { Accept: 'application/json' } });
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    const vulns = (JSON.parse(res.body).vulnerabilities || []).slice(-limit).reverse();
    return vulns.filter((v) => v.cveID).map((v) => normalizedItem({
      external_id: v.cveID,
      title: v.cveID,
      summary: v.shortDescription || v.vulnerabilityName || null,
      author: v.vendorProject ? `${v.vendorProject} / ${v.product || ''}`.trim() : 'CISA',
      link: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      published_at: v.dateAdded || null,
      category: 'cve',
      raw: v,
      native: { cveIds: [v.cveID], vendor: v.vendorProject || null, exploitation: 'actively_exploited' },
    }));
  },
};

const epss = {
  async fetch(source, ctx) {
    const limit = Number(source.requestBody) || 50;
    const url = `${source.url}?order=!epss&limit=${limit}&envelope=true`;
    const res = await ctx.request(url, { timeoutMs: 20000, headers: { Accept: 'application/json' } });
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    const rows = JSON.parse(res.body).data || [];
    return rows.filter((r) => r.cve).map((row) => {
      const pct = Math.round(Number(row.epss) * 100);
      return normalizedItem({
        external_id: row.cve,
        title: row.cve,
        summary: `Exploitation probability ${pct}% — EPSS ${row.epss} (as of ${row.date}).`,
        author: 'FIRST EPSS',
        link: `https://nvd.nist.gov/vuln/detail/${row.cve}`,
        published_at: row.date || null,
        category: 'cve',
        raw: row,
        native: { cveIds: [row.cve], epssScore: Number(row.epss), exploitation: Number(row.epss) >= 0.5 ? 'likely' : null },
      });
    });
  },
};

const ghsa = {
  // GitHub's public advisory DB — reviewed CVE/GHSA records with a real one-line `summary`
  // field (unlike MSRC's updates index, nothing needs composing here) plus package/ecosystem
  // and CVSS. Unauthenticated calls are rate-limited to 60/hr, so keep per_page modest.
  async fetch(source, ctx) {
    const limit = Math.min(Number(source.requestBody) || 30, 100);
    const res = await ctx.request(`${source.url}?per_page=${limit}`, {
      timeoutMs: 20000, headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'threatflow' },
    });
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    const records = JSON.parse(res.body);
    if (!Array.isArray(records)) throw new Error('expected an array of advisories');
    const bucket = categoryBucket(source.category);
    return records.filter((r) => r.ghsa_id).map((r) => normalizedItem({
      external_id: r.ghsa_id,
      title: r.cve_id || r.ghsa_id,
      summary: r.summary || null,
      author: 'GitHub Advisory Database',
      link: r.html_url || null,
      published_at: r.published_at || null,
      category: bucket,
      raw: r,
      native: {
        cveIds: r.cve_id ? [r.cve_id] : [],
        cvssScore: r.cvss?.score != null ? r.cvss.score : null,
        cvssVector: r.cvss?.vector_string || null,
        severity: r.severity ? String(r.severity).toLowerCase() : null,
        // No `vendor`: vulnerabilities[].package is an ecosystem:package identifier
        // ("go:github.com/kube-logging/logging-operator"), not a vendor name — the
        // "Vendors affected" panel expects real company names (Microsoft, Ivanti, NETGEAR,
        // as NVD/MSRC/Red Hat/KEV report them), and package strings drowned that list out.
      },
    }));
  },
};

// SANS ISC's live top-attacker ranking — no per-record timestamp (it's a current snapshot,
// not a dated history), so published_at is the sync time itself.
const dshield = {
  async fetch(source, ctx) {
    const limit = Number(source.requestBody) || 20;
    const res = await ctx.request(`${source.url}/${limit}?json`, { timeoutMs: 15000 });
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    const rows = JSON.parse(res.body);
    if (!Array.isArray(rows)) throw new Error('expected a JSON array of top attackers');
    const now = (ctx.now ? ctx.now() : new Date()).toISOString();
    const bucket = categoryBucket(source.category);
    return rows.filter((r) => r.source).map((r) => normalizedItem({
      external_id: r.source,
      title: `Attacking IP: ${r.source}`,
      summary: `Rank #${r.rank} — ${r.reports.toLocaleString()} reports across ${r.targets.toLocaleString()} target${r.targets === 1 ? '' : 's'} in the last 24h.`,
      author: 'SANS Internet Storm Center',
      link: `https://isc.sans.edu/ipinfo.html?ip=${r.source}`,
      published_at: now,
      category: bucket,
      raw: r,
      native: { iocs: [{ type: 'ip', value: r.source }] },
    }));
  },
};

// MSRC's /cvrf/v3.0/updates list is a document index, not per-CVE detail — its rows are
// monthly rollup stubs ("March 2017 Security Updates", Severity: null, dated 2017) with no
// description field at all. Real per-CVE data lives behind each stub's CvrfUrl.
//
// A single CVRF document holds ~991 vulnerabilities, so this is capped twice: to the three
// most recent documents, and to MSRC_MAX_ITEMS emitted items. The /updates index is returned
// oldest-first (1999-Sep is element 0), so "most recent" is the tail.
const MSRC_DOC_COUNT = 3;
const MSRC_MAX_ITEMS = 400;

const msrc = {
  async fetch(source, ctx) {
    const res = await ctx.request(source.url, { timeoutMs: 20000, headers: { Accept: 'application/json' } });
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    const index = JSON.parse(res.body).value || [];
    const recent = index
      .filter((r) => r.CvrfUrl)
      .sort((a, b) => new Date(a.InitialReleaseDate || 0) - new Date(b.InitialReleaseDate || 0))
      .slice(-MSRC_DOC_COUNT);

    const maxItems = Number(source.requestBody) || MSRC_MAX_ITEMS;
    const items = [];
    for (const doc of recent) {
      if (items.length >= maxItems) break;
      let vulns;
      try {
        const docRes = await ctx.request(doc.CvrfUrl, { timeoutMs: 30000, headers: { Accept: 'application/json' } });
        if (docRes.status < 200 || docRes.status >= 300) continue;
        vulns = JSON.parse(docRes.body).Vulnerability || [];
      } catch {
        // A document that cannot be fetched or parsed contributes nothing. No stub fallback —
        // the content-free stubs are exactly what this change removes.
        continue;
      }
      for (const v of vulns) {
        if (items.length >= maxItems) break;
        if (!v.CVE) continue;
        // CVSSScoreSets repeats the same score once per affected ProductID; the first entry
        // carries the base score for the vulnerability itself.
        const scoreSet = (v.CVSSScoreSets || [])[0] || null;
        const vector = scoreSet ? scoreSet.Vector : null;
        const score = scoreSet && typeof scoreSet.BaseScore === 'number'
          ? scoreSet.BaseScore
          : scoreFromVector(vector);
        // Notes Type 2 is the CVE description; Type 4 is FAQ boilerplate.
        const description = (v.Notes || []).find((n) => n.Type === 2);
        const revision = (v.RevisionHistory || [])[0];
        const version = vector && /^CVSS:(\d\.\d)/.test(vector) ? vector.match(/^CVSS:(\d\.\d)/)[1] : null;
        items.push(normalizedItem({
          external_id: v.CVE,
          title: v.Title && v.Title.Value ? `${v.CVE} — ${v.Title.Value}` : v.CVE,
          summary: description ? description.Value : null,
          author: 'Microsoft MSRC',
          link: `https://msrc.microsoft.com/update-guide/vulnerability/${v.CVE}`,
          published_at: (revision && revision.Date) || doc.InitialReleaseDate || null,
          category: 'cve',
          raw: v,
          native: {
            cveIds: [v.CVE],
            vendor: 'Microsoft',
            cvssScore: score != null ? score : null,
            cvssVersion: version,
            severity: score != null ? severityFromScore(score, version) : null,
          },
        }));
      }
    }
    return items;
  },
};

// Pass 1 covers newly published CVEs. NVD publishes roughly 40k CVEs/year, so 45 days is
// ~5k records — inside NVD_MAX_PAGES * NVD_RESULTS_PER_PAGE. The previous 120-day window
// would be ~13k and would silently truncate.
const NVD_PUB_WINDOW_DAYS = 45;
// Pass 2 catches meaningful re-scores (a 2025 CVE raised to critical this week) without
// re-importing NVD's 1990s-2000s backlog, which is what a bare lastMod query returns:
// before this change, 2002 contributed 2,156 stored rows and 2017 contributed 19.
const NVD_MOD_WINDOW_DAYS = 14;
const NVD_MOD_MAX_AGE_YEARS = 2;
const NVD_RESULTS_PER_PAGE = 2000;
const NVD_MAX_PAGES = 5;

const nvdCve = {
  async fetch(source, ctx) {
    const fmt = (d) => d.toISOString().replace('Z', '');
    const now = ctx.now ? ctx.now() : new Date();
    const headers = source.api_key ? { apiKey: source.api_key } : {};
    const sleep = ctx.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
    // NVD rate limit is 5 req/30s unauthenticated, 50 req/30s with an apiKey.
    const delayMs = source.api_key ? 700 : 6500;
    const daysAgo = (n) => new Date(now - n * 24 * 60 * 60 * 1000);

    async function collect(startParam, endParam, since) {
      const out = [];
      let startIndex = 0;
      for (let page = 0; page < NVD_MAX_PAGES; page += 1) {
        const url = `${source.url}?${startParam}=${fmt(since)}&${endParam}=${fmt(now)}`
          + `&resultsPerPage=${NVD_RESULTS_PER_PAGE}&startIndex=${startIndex}`;
        const res = await ctx.request(url, { timeoutMs: 20000, headers });
        if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
        const body = JSON.parse(res.body);
        out.push(...(body.vulnerabilities || []));
        const totalResults = body.totalResults || 0;
        startIndex += NVD_RESULTS_PER_PAGE;
        if (startIndex >= totalResults) break;
        await sleep(delayMs);
      }
      return out;
    }

    const published = await collect('pubStartDate', 'pubEndDate', daysAgo(NVD_PUB_WINDOW_DAYS));
    await sleep(delayMs);
    const modified = await collect('lastModStartDate', 'lastModEndDate', daysAgo(NVD_MOD_WINDOW_DAYS));

    const maxAge = new Date(now);
    maxAge.setFullYear(maxAge.getFullYear() - NVD_MOD_MAX_AGE_YEARS);
    const fresh = modified.filter((v) => {
      const p = v.cve && v.cve.published;
      return p && new Date(p) >= maxAge;
    });

    const byId = new Map();
    for (const v of [...published, ...fresh]) {
      if (v.cve && v.cve.id && !byId.has(v.cve.id)) byId.set(v.cve.id, v);
    }

    return [...byId.values()].map((v) => {
      const cve = v.cve;
      const desc = (cve.descriptions || []).find((d) => d.lang === 'en');
      const metric = metricFromNvd(cve.metrics);
      return normalizedItem({
        external_id: cve.id,
        title: cve.id,
        summary: desc ? desc.value : null,
        author: 'NVD',
        link: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        published_at: cve.published || null,
        category: 'cve',
        raw: cve,
        native: {
          cveIds: [cve.id],
          cvssScore: metric ? metric.score : null,
          cvssVersion: metric ? metric.version : null,
          severity: metric ? metric.severity : null,
          cpes: cpesFromRaw(cve),
        },
      });
    });
  },
};

const ransomwareLive = {
  async fetch(source, ctx) {
    const limit = Number(source.requestBody) || 60;
    const headers = { Accept: 'application/json' };
    if (source.api_key) headers['X-API-KEY'] = source.api_key;
    const res = await ctx.request(source.url, { timeoutMs: 20000, headers });
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    const body = JSON.parse(res.body);
    const rows = Array.isArray(body) ? body : body.victims;
    if (!Array.isArray(rows)) throw new Error('expected a JSON array of victims');
    return rows.slice(0, limit).map((v) => {
      const group = v.group_name || v.group;
      const victim = v.post_title || v.victim || v.website;
      if (!victim) return null;
      return normalizedItem({
        external_id: v.id || v.post_url || `${group || '?'}:${victim}`,
        title: `${victim}${group ? ` (${group})` : ''}`,
        summary: [v.activity && `Sector: ${v.activity}`, v.country && `Country: ${v.country}`, v.description].filter(Boolean).join(' — ') || null,
        author: group || 'ransomware.live',
        link: v.permalink || v.post_url || (v.website ? `https://${v.website}` : null),
        published_at: v.published || v.discovered || v.attackdate || null,
        category: 'ransomware',
        raw: v,
        native: { region: v.country || null, industry: v.activity || null, actors: group ? [group] : [] },
      });
    }).filter(Boolean);
  },
};

const feodo = {
  async fetch(source, ctx) {
    const limit = Number(source.requestBody) || 80;
    const res = await ctx.request(source.url, { timeoutMs: 20000, headers: { Accept: 'application/json' } });
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    const rows = JSON.parse(res.body);
    if (!Array.isArray(rows)) throw new Error('expected a JSON array of C2 hosts');
    rows.sort((a, b) => String(b.last_online || b.first_seen || '').localeCompare(String(a.last_online || a.first_seen || '')));
    return rows.slice(0, limit).filter((c) => c.ip_address).map((c) => normalizedItem({
      external_id: `${c.ip_address}:${c.port || ''}`,
      title: `${c.malware || 'Malware'} C2: ${c.ip_address}:${c.port || '?'}`,
      summary: `${c.malware || 'Unknown'} botnet C2 — status ${c.status || 'unknown'}${c.country ? ` (${c.country})` : ''}.`,
      author: c.malware || 'Feodo Tracker',
      link: `https://feodotracker.abuse.ch/browse/host/${c.ip_address}/`,
      published_at: c.first_seen || null,
      category: 'malware',
      raw: c,
      native: { iocs: [{ type: 'ip', value: c.ip_address }], malwareFamilies: c.malware ? [c.malware] : [], region: c.country || null },
    }));
  },
};

const VULNETIX_METRIC_KEYS = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'];

// Picks the highest-version CVSS metric present on a CNA metrics entry — Vulnetix
// records carry whichever versions the upstream source published, not always all four.
function bestVulnetixMetric(metrics) {
  for (const key of VULNETIX_METRIC_KEYS) {
    const found = (metrics || []).find((m) => m && m[key]);
    if (found) return found[key];
  }
  return null;
}

// Builds the pre-normalizedItem field object for one /gcve CVEListV5 record.
function gcveEntry(r) {
  const cveId = r.cveMetadata.cveId;
  const cna = r.containers?.cna || {};
  const desc = (cna.descriptions || []).find((d) => d.lang === 'en') || cna.descriptions?.[0] || null;
  const metric = bestVulnetixMetric(cna.metrics);
  const dataSource = r.containers?.adp?.find((a) => a.x_dataSource)?.x_dataSource;
  // Real CVE records carry no per-record cna.title, so cveId is the right title. Vulnetix's
  // open-source-malware bucket (non-"CVE-" ids like OSM-2026-9268) mints one CNA record per
  // malicious repo with a distinct cna.title and a shared boilerplate description — falling
  // back to cveId there collapses hundreds of distinct repos to an indistinguishable list.
  const title = cna.title || cveId;
  const advisoryLink = cna.references?.find((ref) => ref?.url)?.url;
  return {
    external_id: cveId,
    title,
    summary: desc?.value || null,
    author: dataSource ? dataSource.toUpperCase() : 'Vulnetix',
    link: cveId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cveId}` : advisoryLink || `https://nvd.nist.gov/vuln/detail/${cveId}`,
    published_at: r.cveMetadata.datePublished || null,
    category: 'cve',
    raw: r,
    native: {
      cveIds: [cveId],
      cvssScore: metric?.baseScore != null ? metric.baseScore : null,
      cvssVector: metric?.vectorString || null,
      severity: metric?.baseSeverity ? String(metric.baseSeverity).toLowerCase() : null,
    },
  };
}

// Builds the pre-normalizedItem field object for one /exploits record — a flat shape,
// nothing like CVEListV5 (cveId, title, description, metrics.highestScore/highestSeverity,
// kev.inCisaKev, timeline.datePublished, provenance.source all sit at the top level).
function exploitEntry(e) {
  const cveId = e.cveId;
  return {
    external_id: cveId,
    title: cveId,
    summary: e.description || e.title || null,
    author: e.provenance?.source ? String(e.provenance.source).toUpperCase() : 'Vulnetix',
    link: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    published_at: e.timeline?.datePublished || null,
    category: 'cve',
    raw: e,
    native: {
      cveIds: [cveId],
      cvssScore: e.metrics?.highestScore != null ? e.metrics.highestScore : null,
      severity: e.metrics?.highestSeverity ? String(e.metrics.highestSeverity).toLowerCase() : null,
      exploitation: e.kev?.inCisaKev ? 'actively_exploited' : null,
    },
  };
}

const vulnetix = {
  // Two calls against the same Vulnetix source row, merged by CVE ID before writing:
  //
  // - GET /v1/gcve?start=&end= — the only bulk/date-range endpoint on Vulnetix's VDB API
  //   (confirmed against the live OpenAPI spec at /v1/spec plus a real authenticated call
  //   on 2026-07-29; every other endpoint is a single-identifier lookup, e.g. /vuln/{id},
  //   and can't drive a periodic sync). Returns CVEListV5 records — not the flat
  //   {cveId, cvss:{baseScore,severity}, title} shape this adapter previously assumed,
  //   which never matched any real Vulnetix response and was never exercised in production.
  // - GET /v1/exploits — CVEs with exploit intelligence (Metasploit/ExploitDB/Nuclei/
  //   CrowdSec/KEV), a flat shape unrelated to CVEListV5. Sibling of /gcve, not a filter
  //   on it: a CVE can carry exploit data without falling in today's publish window, so
  //   this is a second source of *items*, not just enrichment for the first.
  //
  // Same source_id + external_id=cveId means a CVE present in both collapses to one row
  // (items' unique key is (source_id, external_id)) — /gcve's fuller CVEListV5 description
  // wins when both cover a CVE, upgraded with /exploits' KEV/exploitation signal.
  // /exploits failing outright doesn't fail the sync: /gcve's CVEs are still real data.
  async fetch(source, ctx) {
    const limit = Number(source.request_body || source.requestBody) || 50;
    const now = ctx.now ? ctx.now() : new Date();
    const fmt = (d) => d.toISOString().slice(0, 10);
    const start = fmt(new Date(now.getTime() - 24 * 60 * 60 * 1000));
    const end = fmt(now);
    const headers = { Accept: 'application/json' };
    if (source.api_key) headers.Authorization = `ApiKey ${source.api_key}`;

    const gcveUrl = `${source.url}?start=${start}&end=${end}&limit=${limit}`;
    const gcveRes = await ctx.request(gcveUrl, { timeoutMs: 20000, headers });
    if (gcveRes.status < 200 || gcveRes.status >= 300) throw new Error(`HTTP ${gcveRes.status}`);
    const gcveRecords = JSON.parse(gcveRes.body).records;

    const byId = new Map();
    for (const r of (Array.isArray(gcveRecords) ? gcveRecords : [])) {
      if (r?.cveMetadata?.cveId) byId.set(r.cveMetadata.cveId, gcveEntry(r));
    }

    try {
      const exploitsUrl = `${source.url.replace(/\/gcve$/, '/exploits')}?limit=25&sort=recent`;
      const expRes = await ctx.request(exploitsUrl, { timeoutMs: 20000, headers });
      if (expRes.status >= 200 && expRes.status < 300) {
        const results = JSON.parse(expRes.body).results;
        for (const e of (Array.isArray(results) ? results : [])) {
          if (!e?.cveId) continue;
          const existing = byId.get(e.cveId);
          if (existing) {
            if (e.kev?.inCisaKev) existing.native.exploitation = 'actively_exploited';
            if (existing.native.cvssScore == null && e.metrics?.highestScore != null) existing.native.cvssScore = e.metrics.highestScore;
            if (!existing.native.severity && e.metrics?.highestSeverity) existing.native.severity = String(e.metrics.highestSeverity).toLowerCase();
          } else {
            byId.set(e.cveId, exploitEntry(e));
          }
        }
      }
    } catch { /* best-effort: /gcve's items are still valid without exploit augmentation */ }

    return [...byId.values()].map(normalizedItem);
  },
};

module.exports = { kev, epss, nvd_cve: nvdCve, ransomware_live: ransomwareLive, feodo, vulnetix, msrc, ghsa, dshield };
