# ThreatFlow API

Base URL: `http://localhost:4173`

Stack: Node 22.x · Express · PostgreSQL 16

CORS allowlist: `CORS_ORIGIN` env var, default `http://localhost:4200` (Angular dev server).

---

## Sources

### `GET /api/sources`
List all sources, ordered by name. Each row is the source's own columns plus `item_count`
(total items from that source, one aggregate `LEFT JOIN`/`COUNT` query) and `has_api_key`
(boolean, **with** underscore — note this is a different spelling from the nested `source`
object returned by `GET /api/sources/:id/stats` below, which uses `has_apikey` with no
underscore; both are real, intentional, and endpoint-specific, not a typo).

### `POST /api/sources`
Create a custom source.

Body: `name` (required), `url` (required, SSRF-checked), `category`, `conn_type`, `fetch_kind`, `notes`, `auth_required`, `api_key`, `request_method`, `request_body`, `api_key_header`.

`201` → created source (public shape). `400` if `name`/`url` missing or URL rejected by SSRF guard.

### `PATCH /api/sources/:id`
Partial update. Any of: `active`, `api_key`, `request_method`, `request_body`, `api_key_header`, `url` (SSRF-checked), `name`, `category`, `notes`, `auth_required`, `cve_field`, `cvss_field`, `severity_field`, `vendor_field`.

`404` if not found. `400` if `url` rejected.

### `DELETE /api/sources/:id`
Deletes source and cascades to all its items + item children (cves/iocs/actors/families/domains). `204` on success, `404` if not found.

### `POST /api/sources/:id/sync`
Sync one source now. Returns sync result. `404` if not found.

### `POST /api/sources/sync-all`
Sync all active sources, 8-way concurrent, then run post-sync consolidation. Returns:
```
{
  results: [{ id, name, status: 'ok'|'unsupported'|'error: <msg>', itemsFetched }],
  consolidation: { cves, clusters, items, pruned } | null,
  consolidationError: string | null
}
```
`consolidation` is `null` only if `consolidationError` is set — a consolidation failure never
discards the per-source `results`, since each source's items are already committed by its own
transaction inside `syncSource`.

---

## Items

### `GET /api/items`
Paginated, filtered item list. Total count in `X-Total-Count` response header (body stays a bare array).

Query params:
- `limit` (default 50, max 200), `offset` (default 0)
- `category`, `source_id`
- `q` — ILIKE search over title/summary/author/source name
- `domain`, `actor`, `malware_family`, `cve` — filter by joined child entity
- `severity`, `exploitation_status`, `vendor`, `region`, `industry` — exact match
- `min_confidence` — NULL-tolerant (rows with no confidence score are kept)

Sorted by `published_at` (fallback `fetched_at`) descending.

Rows carry `cluster_id` (nullable) and `source_count`. A story reported by 2+ sources is one
`clusters` row with one `primary_item_id`; non-primary members are excluded from this list and
from `X-Total-Count` (same join `GET /api/feed` uses) so a clustered story appears once, not once
per source. Fetch the collapsed members with `GET /api/clusters/:id/items`.

### `GET /api/items/:id`
Single item, embedded with everything needed for a detail view:
`cves[]`, `iocs[{type,value}]`, `actors[]`, `families[]`, `domains[]`, `ip_intel{}` (keyed by IP, decoded), `raw` (parsed `raw_json`).

`404` if not found.

### `GET /api/clusters/:id/items`
Every item belonging to cluster `:id` (the primary and every collapsed member), each with
`item_id`, `title`, `published_at`, `source_id`, `source_name`, `source_status`. `404` if the
cluster doesn't exist.

---

## Lookups

### `GET /api/ip-intel/:ip`
Shodan-style enrichment for one IP: `ports`, `vulns`, `tags`, `cpes`, `hostnames`, `org`, `isp`, `city`, `country_code`, `source`, `fetched_at`. `404` if not found.

### `GET /api/domains`
All known domains (threat categories) with live item counts.

### `GET /api/facets`
Distinct filter values for building UI filters: `vendors`, `regions`, `actors`, `families` (each capped at 100).

### `GET /api/preview-check`
Whether a page permits being displayed in an iframe, so the UI can decide *before* creating one. Query param `url` (required).

The browser gives client script no way to answer this: a site refusing to be framed renders the browser's own error document inside the frame and still fires `load`, so from the outside a refusal is indistinguishable from a successful render. This fetches the URL server-side and reads `X-Frame-Options` / CSP `frame-ancestors` (`server/frame-policy.js`), evaluated against the caller's `Origin`.

Returns `{ url, status, frameable, reason?, detail? }`. `reason` is one of `x-frame-options`, `frame-ancestors`, `unreachable`, `http-error`, and is absent when `frameable` is true; `detail` is the header text or error worth showing a user.

`url` must be the `link` of an existing item whose source has `fetch_kind = 'rss'` — the same rule the UI uses to decide whether to offer a preview at all. Anything else is `404 { error: 'not a previewable item link' }`. Without that restriction the endpoint would be a general-purpose fetch proxy, and item links from the phishing/abuse.ch feeds are live malicious URLs the server should not be dereferencing on request. `unreachable` and `http-error` are *inconclusive*, not refusals — bot-filtered sites (Dark Reading, BleepingComputer) answer a server-side fetch with `403` while serving a browser normally. Callers should still attempt the frame on those two and fall back on a load timeout; only `x-frame-options` and `frame-ancestors` are the page actually saying no.

---

## Stats

### `GET /api/stats`
Dashboard payload: `total`, `byCategory`, `recentCves` (10), `recentNews` (10, news/advisory/osint), `health` (source sync health), `topSources` (5), `byDomain`, `byExploitation`.

### `GET /api/stats/dashboard`
Aggregation payload for the Angular widget dashboard. Read-only; cleans known dirty data server-side (malware-family IOC noise stripped, non-label `severity` blobs coerced to `unknown`). Shape:

```
{
  total: number,
  generatedAt: string,                                             // ISO timestamp
  byCategory:   { category: string, count: number }[],
  byDomain:     { domain: string, label: string, count: number }[],// label joined from domains.js
  byExploitation: { status: string, count: number }[],             // NULL bucketed as "unknown"
  bySeverity:   { severity: string, count: number }[],             // non-label values coerced to "unknown"
  topActors:    { actor: string, count: number }[],                // top 15
  topMalware:   { family: string, count: number }[],               // top 12, IOC/arch noise filtered
  topCves:      { cve: string, count: number, maxCvss: number|null, itemId: number }[], // top 12, itemId for drill-down
  targetedCountries: { code: string, count: number }[],            // ISO-2 from items.region + ip_intel, merged
  timeline:     { bucket: string, count: number }[],               // monthly (YYYY-MM), last 12 months
  latestReports:{ id: number, title: string, category: string, source_name: string, published_at: string|null }[], // 10, news/advisory/osint
  topSources:   { id: number, name: string, item_count: number }[],// top 5
  health:       { active_count: number, error_count: number, unsupported_count: number, never_synced_count: number, total_sources: number }
}
```

---

## CVEs

### `GET /api/sources/:id/stats`
Aggregated threat intelligence statistics for one source. Includes item counts, field data-quality coverage, timeline, distribution by category/domain/severity, and sync history.

Query params: none.

`404` if source ID is not found or not an integer.

Response shape:
```
{
  source: {
    id: number,
    name: string,
    category: string,
    conn_type: string,
    fetch_kind: string,
    url: string,
    tier: string,
    notes: string | null,
    active: boolean,
    last_synced_at: string | null,       // ISO timestamp
    last_status: string,                 // "ok", "error: ...", "unsupported", etc.
    has_apikey: boolean,                 // note: no underscore here — GET /api/sources (above) uses has_api_key
    auth_required: string | null         // env var name this source's key comes from, or null if none needed
  },
  counts: {
    items: number,                       // total items from this source
    cves: number,                        // distinct CVE IDs
    iocs: number,                        // distinct IOCs (IP, domain, email, hash)
    actors: number,                      // distinct threat actor names
    families: number                     // distinct malware family names
  },
  timeline: [{ bucket: "YYYY-MM", count: number }, ...],  // monthly, all-time
  byCategory: [{ category: string, count: number }, ...], // sorted by count desc
  byDomain: [{ domain: string, count: number }, ...],     // threat domains (ransomware, vulnerability, etc.)
  bySeverity: [{ severity: string, count: number }, ...], // critical, high, medium, low, none, unknown
  fieldCoverage: {
    summary: number,                     // % of rows with this field (0-100)
    link: number,
    published_at: number,
    severity: number,
    cvss_score: number,
    vendor: number,
    region: number,
    industry: number,
    confidence: number
  },
  syncHistory: [
    {
      started_at: string,                // ISO timestamp
      finished_at: string | null,        // ISO timestamp; null if in-progress
      status: string,                    // "ok", "error: ...", "partial"
      items_new: number,
      items_total: number,
      error: string | null
    },
    ...
  ]                                      // up to 50 most recent syncs
}
```

### `GET /api/cves`
Paginated list of all CVEs with aggregated cross-source data. Total count in `X-Total-Count` response header.

Query params:
- `limit` (default 50, max 200), `offset` (default 0)
- `q` — keyword search in CVE ID and description
- `severity` — filter by severity level: `critical`, `high`, `medium`, `low`, `none`, `unknown`
- `kev` — if `true`, include only KEV (Known Exploited Vulnerabilities) CVEs
- `min_cvss` — minimum CVSS v3 score (0–10)
- `min_epss` — minimum EPSS score (0–1)

Response: array of cve_intel records. Each record includes `cve_id`, `description`, `cvss_score`, `epss_score`, `kev_listed`, `severity`, and aggregated source counts.

### `GET /api/cves/:cveId`
Single CVE with full detail: aggregated data, all reporting sources, and associated threat actors/malware families.

CVE ID is case-insensitive (e.g., `cve-2024-1234` and `CVE-2024-1234` are equivalent).

`404` if CVE not found.

Response shape:
```
{
  cve: {
    cve_id: string,
    description: string,
    cvss_score: number | null,
    epss_score: number | null,
    kev_listed: boolean,
    severity: string | null,
    last_seen: string,                  // ISO timestamp
    source_count: number                // how many sources reported this CVE
  },
  sources: [
    {
      item_id: number,                  // primary item from this source
      source_id: number,
      cvss_score: number | null,
      severity: string | null,
      source_name: string,
      last_status: string,              // source's current sync status
      title: string,                    // item title
      link: string | null,
      published_at: string | null       // ISO timestamp
    },
    ...
  ],
  actors: ["actor1", "actor2", ...],    // distinct threat actor names linked to this CVE
  families: ["family1", "family2", ...] // distinct malware families linked to this CVE
}
```

---

## Entities

### `GET /api/actors/:name`
Profile for a single threat actor: all items attributed to this actor across all sources, associated CVEs, reporting sources, and activity timeline.

Actor name is case-sensitive as stored in the database.

`404` if actor not found.

Response shape:
```
{
  kind: "actor",
  name: string,                         // actor name as stored
  itemCount: number,                    // total items attributed to this actor
  items: [
    {
      id: number,
      title: string,
      summary: string | null,
      category: string,                 // "advisory", "news", "intrusion", etc.
      severity: string | null,
      published_at: string | null,      // ISO timestamp
      source_name: string,
      last_status: string               // source's sync status
    },
    ...
  ],                                    // up to 100 most recent items
  cves: ["CVE-2024-1234", ...],         // distinct CVE IDs associated with this actor
  sources: [
    {
      id: number,
      name: string,
      count: number                     // how many items from this source mention this actor
    },
    ...
  ],
  timeline: [{ bucket: "YYYY-MM", count: number }, ...] // monthly activity
}
```

### `GET /api/malware/:family`
Profile for a single malware family: all items mentioning this family across all sources, associated CVEs, reporting sources, and activity timeline.

Malware family name is case-sensitive as stored in the database.

`404` if malware family not found.

Response shape:
```
{
  kind: "family",
  name: string,                         // malware family name as stored
  itemCount: number,                    // total items mentioning this family
  items: [
    {
      id: number,
      title: string,
      summary: string | null,
      category: string,                 // "advisory", "news", "intrusion", etc.
      severity: string | null,
      published_at: string | null,      // ISO timestamp
      source_name: string,
      last_status: string               // source's sync status
    },
    ...
  ],                                    // up to 100 most recent items
  cves: ["CVE-2024-1234", ...],         // distinct CVE IDs associated with this family
  sources: [
    {
      id: number,
      name: string,
      count: number                     // how many items from this source mention this family
    },
    ...
  ],
  timeline: [{ bucket: "YYYY-MM", count: number }, ...] // monthly activity
}
```

---

## Feed & Discovery

### `GET /api/feed`
Chronological feed of recent threat intelligence items across all sources. Ordered by publication date (newest first).

Query params:
- `since` — ISO 8601 timestamp; return items published after this time
- `limit` — maximum number of items to return (default 50)

Response: array of items with source metadata.

### `GET /api/search`
Cross-entity search: find items, CVEs, actors, malware families, and sources matching a query string.

Query params:
- `q` (required) — search string (minimum 2 characters)
- `limit` — maximum results per entity type (default 8, max 25)

Returns a short summary of results:
```
{
  items: [{ id, title, category }, ...],
  cves: [{ cve_id, severity, cvss_score }, ...],
  actors: ["actor1", ...],              // distinct actor names
  families: ["family1", ...],           // distinct malware family names
  sources: [{ id, name, last_status }, ...]
}
```

If `q` has fewer than 2 characters, returns empty result sets.

---

## Export

### `GET /api/export/iocs`
Export indicators of compromise (IOCs). Includes IP addresses, domains, URLs, file hashes, and
email addresses discovered across all sources.

Query params — the same filter set `GET /api/items` supports, so an export always covers exactly
the explorer's current filters, never more:
- `source_id`, `category`
- `type` — filter by IOC type (ip, domain, email, hash, etc.)
- `q` — ILIKE search over title/summary/author/source name
- `domain`, `actor`, `malware_family`, `cve` — filter by joined child entity
- `severity`, `exploitation_status`, `vendor`, `region`, `industry` — exact match
- `min_confidence` — NULL-tolerant (rows with no confidence score are kept)
- `format=json` — return the same rows as a JSON array instead of CSV (used by "Copy all IOCs";
  avoids re-parsing quoted CSV client-side for values that legitimately contain commas)

Response (default): CSV file with columns: `type`, `value`, `item_id`, `source`, `first_seen`.
All fields are quoted and embedded quotes are escaped per RFC 4180.

---

## Conventions

- IDs are positive integers; non-integer `:id` params return `404` (not a 500).
- All handlers wrapped so rejected promises become `500 { error }` instead of crashing the process.
- `assertSafeUrl` runs on every user-supplied source URL (create + update) — blocks SSRF including bracketed IPv6 literals.
