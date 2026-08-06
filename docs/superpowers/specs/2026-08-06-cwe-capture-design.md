# CWE capture — the cheap first half of CVE-to-ATT&CK grounding

Design, 2026-08-06. Part 1 of a two-part follow-up flagged in
[`2026-08-06-attack-mitigation-ingestion-design.md`](2026-08-06-attack-mitigation-ingestion-design.md):

> **ATT&CK grounding for the CVE playbook (`playbook.js`).** A real, sourced chain exists (NVD
> publishes CWE per CVE; MITRE publishes an official CWE→CAPEC→ATT&CK-technique mapping) — but
> nothing in this codebase captures CWE today.

Part 2 — CWE→CAPEC→ATT&CK-technique→mitigation, and an actual new CVE playbook step — is
deliberately not designed here. It needs two more external MITRE datasets (CWE database, CAPEC
database) on top of Spec A's STIX ingestion, and its real payoff (how many of the corpus's 7,685
CVSS-bearing items would actually get a step) isn't measured yet. This spec ships the part that's
cheap and useful on its own, and gives Part 2 real CWE data to design against instead of guessing.

## Problem

NVD's CVE API response already carries CWE (weakness type) data in `weaknesses[].description[]`.
The adapter's `raw: cve` already stores the full response into `raw_json` — the data has been
sitting in the DB, unused, since the first sync. Nothing extracts it, nothing displays it, no
column exists.

## Architecture

Same shape as `cpe.js`/`cpesFromRaw` (pure parsing, no I/O):

```
server/
  cwe.js          -- cwesFromRaw(raw): pure extraction from an NVD CVE object
  cwe.test.js
  backfill-cwe.js -- one-off, re-derives item_cwes for every existing item from raw_json
  backfill-cwe.test.js
```

### Extraction

```js
// server/cwe.js
const CWE_RE = /^CWE-\d+$/;

function cwesFromRaw(raw) {
  if (!raw || typeof raw !== 'object') return [];
  const out = new Set();
  for (const w of raw.weaknesses || []) {
    for (const d of w.description || []) {
      if (d.lang === 'en' && typeof d.value === 'string' && CWE_RE.test(d.value)) out.add(d.value);
    }
  }
  return [...out];
}

module.exports = { cwesFromRaw, CWE_RE };
```

NVD's `weaknesses[].type` can be `'Primary'` or `'Secondary'` — both kept. A CVE can genuinely
have more than one contributing weakness type; picking only `Primary` would silently drop real
NVD-sourced data for no stated reason. `CWE-noinfo` (NVD's explicit "not yet assigned" marker) is
excluded by the regex — that's the honest-absence case, same as a `null` `summary` elsewhere in
this codebase, never rendered as a hedge.

### Data model

```sql
CREATE TABLE item_cwes (
  item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  cwe_id  text NOT NULL,
  PRIMARY KEY (item_id, cwe_id)
);
CREATE INDEX idx_item_cwes_cwe_id ON item_cwes(cwe_id);
```

Same shape as `item_cpes`/`item_actors` — a child table, `ON DELETE CASCADE`, indexed on the
lookup column for the eventual Part 2 join.

### Live path

`adapters/bespoke.js`'s `nvdCve.fetch`: add `cwes: cwesFromRaw(cve)` to the `native` object
alongside the existing `cpes: cpesFromRaw(cve)` — same line, same pattern.

`enrich.js`: pass `native.cwes` through to the enrichment output, same as `native.cpes` already is.

`fetchers.js:writeItem` (the loop at line 93-104): add `item_cwes` to the idempotent
delete-then-reinsert table list, and a fifth insert loop:

```js
for (const c of enr.cwes || []) {
  await t.run('INSERT INTO item_cwes (item_id, cwe_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [itemId, c]);
}
```

### Backfill

`backfill-cwe.js`, same idiom as `backfill-cvss.js`: iterate every `category = 'cve'` item's
`raw_json`, run `cwesFromRaw`, write `item_cwes` rows. `--dry-run` to preview, bare invocation
writes. Re-derives from data already in hand — no re-fetch, no network call, matching the
`backfill-presentation.js` precedent CLAUDE.md documents for exactly this situation.

### API / display

`GET /api/items/:id` response gains a `cwes: string[]` field (e.g. `["CWE-79", "CWE-89"]`), read
directly off `item_cwes`. Display only in this spec — no scoring change, no playbook change, no
new UI component required (existing item-detail metadata rendering can list it the same way it
already lists CVE ids).

## Failure modes

| Condition | Behaviour |
|---|---|
| `raw.weaknesses` absent (non-NVD source, or an old raw shape) | `cwesFromRaw` returns `[]`, no rows written — same "nothing to extract" posture as `cpesFromRaw` |
| Only `CWE-noinfo` present | Filtered by `CWE_RE`, item gets zero `item_cwes` rows — honest absence, not a placeholder value |
| Backfill run against an item whose `raw_json` predates NVD adding `weaknesses` to its schema | Same as "absent" — empty array, no error |

## Testing

- `cwe.test.js`: fixture NVD CVE object with Primary+Secondary weaknesses, a `CWE-noinfo` entry,
  a non-English description entry (excluded), dedup of a repeated CWE id across weakness entries.
- `backfill-cwe.test.js`: seeds a few items with varying `raw_json` shapes (real weaknesses, no
  weaknesses key, `CWE-noinfo` only), asserts exactly the right `item_cwes` rows result, and that
  a rerun is idempotent (no duplicate rows, no error on `ON CONFLICT`).
- `adapters/bespoke.test.js`: `nvdCve` fixture assertion extended to check `native.cwes`.
- `api.test.js`: item detail response includes `cwes` for a seeded item that has `item_cwes` rows,
  omits/empty-arrays it for one that doesn't.

## Out of scope

- **CAPEC/ATT&CK technique mapping (Part 2).** Needs its own spec once this ships and real CWE
  distribution across the corpus can be measured — designing the mapping and its playbook step
  now would be guessing at scope rather than measuring it, the same mistake CLAUDE.md's NVD
  window-sizing section warns against ("measured, not estimated").
- **Any change to `playbook.js` or its step catalogue.** This spec only adds data; no new step
  reads `item_cwes` yet.
- **Non-NVD sources.** `weaknesses[]` is NVD's own schema; other CVE-shaped sources (OSV, GHSA)
  are untouched by this spec and simply produce empty `item_cwes` rows, same as today's absence
  of CWE data for those.
