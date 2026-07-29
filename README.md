# ThreatFlow

Threat-intelligence aggregation platform. It ingests 43 public threat-intel feeds (RSS, JSON APIs,
OSV, MISP, abuse.ch, plain-text IOC lists), normalizes every record into a single schema, enriches
it with CVEs / IOCs / threat actors / malware families, and presents the result as an analyst
dashboard plus a per-source catalog called **Arsenal**.

Two deployables live in this repo:

| Path | What it is | Port |
|---|---|---|
| `server/` | Express 4 REST API + ingestion engine, backed by PostgreSQL 16 | `4173` |
| `frontend-v4/` | Angular 19 SPA (standalone components + signals, ECharts) | `4400` |

---

## Quick start

Prerequisites: **Node 22.x** and **Docker** (for Postgres 16).

```bash
# 1. Start PostgreSQL 16
docker run -d --name threatflow-pg16 \
  -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres -e POSTGRES_DB=threatflow \
  -p 55432:5432 postgres:16

# 2. Backend — applies the schema, seeds the 43 sources, starts the scheduler, listens on :4173
npm install
npm start

# 3. Frontend — in a second terminal
cd frontend-v4
npm install
npm start        # http://localhost:4400
```

The frontend dev server proxies `/api/*` to `http://localhost:4173`
(`frontend-v4/proxy.conf.json`), so no CORS configuration is needed in development.

On first boot the database is empty. Either wait about a minute for the built-in scheduler's first
tick, or force a full pull immediately:

```bash
curl -X POST http://localhost:4173/api/sources/sync-all
```

A full sync takes a few minutes and lands roughly 2,000–3,000 items.

There are no native addons — the app is pure JS on `pg`, so it runs on any Node 22 with no rebuild
step. If your `node`/`npm` come from a broken shell function (a lazy-loaded nvm, for example), call
the binaries by absolute path: `~/.nvm/versions/node/<version>/bin/node server/index.js`.

### Configuration

All backend configuration is environment variables. None are required for local development.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgres://postgres:postgres@127.0.0.1:55432/threatflow` | Postgres connection string |
| `PORT` | `4173` | API listen port |
| `CORS_ORIGIN` | `http://localhost:4200` | Comma-separated browser origin allowlist |
| `SHODAN_API_KEY` | _unset_ | Optional. Upgrades IP enrichment from free InternetDB to full Shodan |
| `RUN_LIVE` | _unset_ | Set to also run the network-touching integration tests |

The API binds to `127.0.0.1` only. There is no authentication layer — the source-management routes
(`POST`/`PATCH`/`DELETE /api/sources`) are unauthenticated by design for a single-user local
deployment, so loopback binding is the only thing keeping them off the network. **Do not expose this
port directly.**

### Key-gated sources

Five sources are wired but inactive until you supply an API key. Set the environment variable, then
flip `active` on the source (via the Arsenal UI or `PATCH /api/sources/:id`):

| Source | Env var |
|---|---|
| AlienVault OTX | `OTX_API_KEY` |
| VulnCheck KEV | `VULNCHECK_API_KEY` |
| PhishTank | `PHISHTANK_API_KEY` |
| abuse.ch MalwareBazaar | `ABUSECH_AUTH_KEY` |
| GreyNoise Community | `GREYNOISE_API_KEY` |

Shodan is deliberately absent from that table. Its search API needs a paid membership tier
(`/shodan/host/search` returns "Requires membership or higher" on free keys), so there is no feed to
wire as a source. It is used for **IP enrichment** instead: `server/shodan_enrich.js` attaches open
ports and known vulns (free InternetDB, no key needed) plus org/ISP/geo (optional, needs a key) to
IP IOCs already ingested from URLhaus, ThreatFox and Feodo Tracker, cached in the `ip_intel` table.
It still appears as a row in the source list ("Shodan (IP enrichment)", inactive, never synced as a
feed) purely so the key can be pasted into the same field used by the other key-gated sources.
InternetDB enrichment runs whether or not a key is set.

---

## Architecture

### Backend

```
server/
  index.js            Express app + every route (reference: docs/API.md)
  store.js            async pg wrapper — all(), get(), run(), tx(). Postgres $1 placeholders.
  db.js               singleton store + idempotent applySchema()
  scheduler.js        background sync: 60s tick for feeds, 24h tick for slow sources
  fetchers.js         syncSource orchestration + bounded-concurrency sync-all (8 at a time)
  adapters/           one module per fetch_kind; every one returns normalizedItem() from shape.js
  normalize.js        deriveFetchKind, categoryBucket, domainsForCategory
  enrich.js           CVE / IOC / actor / family extraction, severity derivation
  shodan_enrich.js    IP enrichment via InternetDB (free) + Shodan (optional key)
  consolidate.js      post-sync pass: cross-source CVE merge, clustering, confidence scoring
  present.js          presentation-field derivation
  queries.js          read-side queries for feed, search, CVE and entity pages
  stats.js            dashboard aggregation
  sources.config.js   the 43 source definitions
  safe-request.js     fetch wrapper; ssrf-guard.js blocks private/reserved targets
```

**Ingestion flow.** `sources.config.js` → `seed.js` writes the `sources` table → `fetchers.syncSource`
picks an adapter by `fetch_kind` → the adapter returns `normalizedItem()` objects → `enrich.js`
extracts entities → rows are upserted into `items` and its child tables → `consolidate.js` runs a
cross-source pass at the end.

**Adapters are the extension point.** To add a feed type: add a `fetch_kind`, add a module in
`server/adapters/`, and register it in `server/adapters/index.js`. Adapters must return
`normalizedItem()` and must never write to the database directly.

**SSRF protection.** Every user-supplied source URL passes `assertSafeUrl` on both create and update;
`ssrf-guard.js` rejects private, loopback, link-local and reserved address ranges.

No ORM: `server/store.js` is a thin async data-access layer over a `pg` Pool. All database access
goes through `await store.all() / get() / run() / tx()`.

### Data model

```
sources ──< items ──┬─< item_cves
                    ├─< item_iocs
                    ├─< item_actors
                    ├─< item_malware_families
                    └─< item_domains

cve_intel    consolidated per-CVE view, rebuilt after each sync
cve_sources  per-source CVE scores, retained so disagreement stays visible
ip_intel     Shodan / InternetDB enrichment, keyed by IP
```

`items` is unique on `(source_id, external_id)`. All child tables cascade on delete from `sources`.
`items.raw_json` preserves the original upstream record, so presentation fields can always be
re-derived without re-syncing.

To reseed from config: drop and recreate the `threatflow` database (or `TRUNCATE sources CASCADE`),
then restart — startup re-applies the schema and reseeds.

### Frontend

`frontend-v4/` is an Angular 19 standalone-component app using signals for state.

| Route | Page |
|---|---|
| `/` | Dashboard — KPI tiles, live lane, exploited lane, geography, breakdowns |
| `/arsenal` · `/arsenal/:id` | Source catalog index and per-source dossier |
| `/intel` · `/intel/:id` | Item explorer with facets, and item detail |
| `/check` | URL / indicator lookup |
| `/cve/:id` · `/actor/:name` · `/malware/:family` | Entity profile pages |

Charts are ECharts (`frontend-v4/src/app/charts/`); the world map uses `world-atlas` TopoJSON.
Design tokens live in `frontend-v4/src/app/core/tokens.css` and drive both light and dark themes
through `core/theme.service.ts`.

---

## API

Full endpoint reference with request and response shapes: **[`docs/API.md`](docs/API.md)**.

- **Sources** — `GET`/`POST /api/sources`, `PATCH`/`DELETE /api/sources/:id`,
  `POST /api/sources/:id/sync`, `POST /api/sources/sync-all`, `GET /api/sources/:id/stats`
- **Items** — `GET /api/items`, `GET /api/items/:id`, `GET /api/clusters/:id/items`
- **Stats** — `GET /api/stats`, `GET /api/stats/dashboard`
- **CVEs** — `GET /api/cves`, `GET /api/cves/:cveId`
- **Entities** — `GET /api/actors/:name`, `GET /api/malware/:family`
- **Discovery** — `GET /api/feed`, `GET /api/search`, `GET /api/facets`, `GET /api/domains`
- **Lookups** — `GET /api/ip-intel/:ip`, `GET /api/preview-check`
- **Export** — `GET /api/export/iocs` (CSV)

Conventions: a non-integer `:id` route param returns `404`, not `500`. Every handler is wrapped so a
rejected promise becomes `500 { error }` rather than crashing the process.

---

## Testing

```bash
npm test                          # backend — node:test, needs the Postgres container running
RUN_LIVE=1 npm test               # also runs server/integration.test.js against live feeds
cd frontend-v4 && npm test        # frontend — tsc --noEmit + vitest
cd frontend-v4 && npm run smoke   # Playwright smoke run against a live dev server
```

Backend tests are `node:test`, colocated as `*.test.js` next to the module they cover. Each test
creates and drops its own isolated database, so they never share state; isolated stores come from
`server/test-helpers.js` — never the `db.js` singleton. Pure logic (parsing, normalizing, scoring)
lives in its own module with its own tests, so adapters and route handlers stay thin.

---

## Known data-quality constraints

These are real limits of the upstream data, not bugs. The UI is built to surface them rather than
paper over them — please keep it that way.

- **`confidence` is derived, not vendor-supplied.** It is written by the post-sync consolidation
  pass (`server/consolidate.js`) using the source-tier × corroboration heuristic in
  `server/confidence.js`. A row inserted between consolidation runs carries `confidence = NULL`
  until the next pass. Never present it as a vendor-provided score.

- **`region` / `industry` are sparse.** Only ransomware.live and `ip_intel` geolocation supply them.
  Do not infer victim geography from an advisory issuer's country — CERT-FR publishing an advisory
  says nothing about France being targeted. Geography visualizations are therefore labelled
  "victim & infrastructure geography" and are sourced only from those two paths.

- **One CVE legitimately produces several `items` rows.** `UNIQUE(source_id, external_id)` dedups
  within a source only, so a CVE covered by NVD, Red Hat, EPSS and KEV yields four rows by design.
  Cross-source consolidation lives in `cve_intel`, rebuilt after each sync, with per-source values
  retained in `cve_sources` so genuine scoring disagreement stays visible instead of being averaged
  away.

- **8 of the 43 sources do not sync.** Five need API keys. BleepingComputer returns 403 (Cloudflare
  bot management fingerprints Node's TLS/JA3 specifically — curl from the same host passes, and
  changing User-Agent or headers does not help; not fixable without a real browser engine). Dragos
  moved its feed from `/blog/feed/` to `/blog.rss`, which is fixed in config, but the new URL
  currently returns `200` with an empty body upstream. And Shodan is an enrichment-key placeholder
  with `fetch_kind = 'unsupported'`. The UI shows this degradation rather than silently rendering 35
  of 43.

- **IPv4 is forced.** `safe-request.js` calls `dns.setDefaultResultOrder('ipv4first')` because Node's
  Happy Eyeballs raced an unreachable AAAA record on hosts with no IPv6 route (Google Project Zero
  failed with `AggregateError`). If the deploy target has working IPv6, confirm whether this should
  be reverted.

- **Rows outside the current sync window are never touched by a live sync.** `writeItem`'s
  `ON CONFLICT` upsert only reaches rows a source is still actively returning. After any schema or
  taxonomy rule change that should apply retroactively, run the two idempotent backfill scripts —
  they re-derive fields for every row using the same pure functions the live write path uses:

  ```bash
  node server/backfill-presentation.js --dry-run   # preview
  node server/backfill-presentation.js             # write
  node server/backfill-taxonomy.js --dry-run
  node server/backfill-taxonomy.js
  ```

  Note the inverted default: a bare invocation **writes**. Pass `--dry-run` explicitly to preview.

---

## Operational notes

- The scheduler starts automatically with `npm start`: a 60-second tick syncs all active feed
  sources and then consolidates, and a 24-hour tick handles the slow `vulnetix` source. Both are
  re-entrancy guarded, so a slow tick cannot stack on itself.
- `POST /api/sources/sync-all` runs the same work on demand with a concurrency cap of 8.
- Query the dev database through the container:

  ```bash
  docker exec -e PGPASSWORD=postgres threatflow-pg16 \
    psql -U postgres -d threatflow -X -c "SELECT count(*) FROM items"
  ```
