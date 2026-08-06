# Real ATT&CK mitigation ingestion — replacing the hand-curated lookup

Design, 2026-08-06. Extends
[`2026-08-05-category-playbooks-design.md`](2026-08-05-category-playbooks-design.md), which shipped
`data/attack-mitigations.json` as a 20-entry hand-typed file and explicitly scoped out:

> **Full MITRE ATT&CK ingestion.** The curated mitigation map only covers names already in
> ThreatFlow's own actor/family dictionaries (currently 10 + 10). Expanding the dictionaries is a
> separate, unrelated piece of work; this spec only joins against what already exists.

This is that follow-up, for the `attack-mitigation` step only. Growing the actor/family
dictionaries themselves, and adding ATT&CK grounding to the CVE playbook, are separate specs (see
Out of scope).

## Problem

`data/attack-mitigations.json` is hand-typed and frozen at whatever the author knew when they
wrote it. A newly-named ransomware group or malware family gets zero mitigation coverage forever,
not until someone remembers to edit the file and ship a commit. The map is also thin by
construction — 1-2 mitigations per name, picked by judgment rather than derived from anything —
where MITRE's own data would support a ranked, justified list per actor/family.

## Architecture

New backfill script `server/backfill-attack.js`, same idiom as `backfill-cvss.js` /
`backfill-taxonomy.js` / `backfill-presentation.js`: idempotent, one-off, `--dry-run` to preview,
bare invocation writes. Rerun manually whenever `data/threat-actors.json` /
`data/malware-families.json` gains entries, or periodically to pick up ATT&CK's own updates
(MITRE revises the Enterprise matrix roughly twice a year).

```
server/
  backfill-attack.js          -- fetch, match, rank, write attack_mitigations
  backfill-attack.test.js     -- fixture STIX bundle, no live network call
  playbooks/attack-mitigations.js  -- now a pure Map lookup, no fs.readFileSync
```

`data/attack-mitigations.json` is deleted. `playbooks/ransomware.js`, `malware.js`, `ioc.js` keep
their existing shape (pure, no I/O) — they receive the resolved data as an argument instead of a
module reading a file at require time.

### Data source

MITRE's own STIX 2.1 bundle:
`https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
(~30-40MB, fetched once per script run via `safe-request.js`, not on any live request path).
Relevant object types:

- `intrusion-set` — threat actor groups (`name`, `aliases`, external ref `G####`)
- `malware` / `tool` — malware families and tooling (`name`, `x_mitre_aliases`, external ref `S####`)
- `attack-pattern` — techniques (external ref `T####`)
- `course-of-action` — mitigations (`name`, external ref `M####`)
- `relationship` — `uses` (actor/malware → technique) and `mitigates` (mitigation → technique)

Objects with `revoked: true` or `x_mitre_deprecated: true` are skipped entirely — a revoked group
matching by name would attribute mitigations to a STIX object MITRE itself no longer stands behind.

### Matching

For each entry in `data/threat-actors.json` and `data/malware-families.json`, build the candidate
name set: `{name, ...aliases}` (ours) ∪ `{name, ...aliases}` (the matched STIX object's own, once
found). Matching itself is case-insensitive exact string match only, tried across every
non-revoked `intrusion-set`/`malware`/`tool` object's own name+alias set — no fuzzy matching, no
partial/substring match, no invented mitigation for a name that doesn't hit. This is the same
posture the current `attackStep` already documents, just against a much larger candidate pool.

If more than one STIX object matches the same subject (rare — e.g. a name tracked as both a group
and separately as its tooling), their technique sets are unioned before ranking.

### Ranking

For the matched STIX id(s): walk `uses` relationships → the actor's/family's technique set. Walk
`mitigates` relationships from every `course-of-action` → intersect against that technique set,
tallying how many of the subject's techniques each mitigation addresses (`technique_count`). Sort
descending by that count, keep the top 5, write one row per (subject, mitigation).

This produces a real, computed justification — "addresses 9 of this group's techniques" — instead
of an unranked pair someone picked by hand.

### Data model

New table:

```sql
CREATE TABLE attack_mitigations (
  subject_type    text NOT NULL,   -- 'actor' | 'family'
  subject_name    text NOT NULL,   -- our canonical spelling, from threat-actors.json / malware-families.json
  mitigation_id   text NOT NULL,   -- e.g. 'M1053'
  mitigation_name text NOT NULL,
  mitigation_url  text NOT NULL,
  technique_count integer NOT NULL,
  synced_at       timestamptz NOT NULL,
  PRIMARY KEY (subject_type, subject_name, mitigation_id)
);
```

`subject_type` disambiguates names that appear in both dictionaries today (e.g. `LockBit` is both
an actor and, separately, ransomware tooling in `malware-families.json`) — same name, potentially
different STIX object, potentially different technique set.

The backfill script does `DELETE FROM attack_mitigations` + reinsert on every run — same
rebuild-not-merge pattern as `rebuildClusters()`, so a name dropped from the dictionaries or from
ATT&CK itself doesn't leave a stale row behind.

## Call-site changes

- `playbooks/attack-mitigations.js`: `attackStep(name)` → `attackStep(name, subjectType, map)`.
  Drops `fs.readFileSync`; becomes a pure lookup (`map.get(`${subjectType}:${name.toLowerCase()}`)`).
  Still returns `null` for no match, still no fuzzy fallback.
- `relevance.js:recomputeProfile`: one `store.all('SELECT * FROM attack_mitigations')` before the
  item loop (loaded once per recompute pass, not per item — the existing ~1.3s/24k-item budget is
  unaffected by a single extra query). Built into a `Map`, passed into `buildCategoryPlaybook` as
  `facts.attackMitigations`.
- `playbooks/index.js`, `ransomware.js`, `malware.js`, `ioc.js`: thread `attackMitigations` through
  `facts` into each module's mitigation step function.
- Step `detail` wording changes to include the justification, e.g.: *"Recommended ATT&CK
  mitigations for Sandworm (from 47 documented techniques): Network Segmentation (M1030, addresses
  9 techniques), Data Backup (M1053, 7)..."* — top 5 max, comma-joined, same sentence shape as
  today's step just with real counts.
- `source` field changes from `'data/attack-mitigations.json'` to
  `'MITRE ATT&CK (attack_mitigations table, synced <date>)'`.

## Failure modes

| Condition | Behaviour |
|---|---|
| Backfill script's STIX fetch fails (network, rate limit, malformed bundle) | Logs and exits non-zero; `attack_mitigations` table untouched — no partial overwrite, same all-or-nothing posture as `relevance_prose.js` |
| Table never populated (fresh DB, script never run) | Empty `Map` → `attackStep` returns `null` for everything → step absent everywhere, identical to today's "no match" behavior, no crash |
| Actor/family in our dictionary but genuinely untracked by ATT&CK (e.g. a commodity stealer MITRE doesn't document) | Step stays absent — this is real information, not a bug, and stays silent rather than rendered as a hedge |
| Name matches a revoked/deprecated STIX object only | Treated as no match — revoked objects are filtered before matching runs |
| Item recategorized, or dictionary regains an entry after a rerun | Playbook regenerates under the current table state next recompute pass, same as any other profile-driven regen |

## Testing

- `attack-mitigations.test.js`: pure `Map` fixtures in, `attackStep` out — same shape as the
  existing test, no STIX parsing involved.
- `backfill-attack.test.js`: small fixture STIX bundle (a handful of intrusion-sets, malware,
  techniques, `uses`/`mitigates` relationships, including one revoked object) run through
  matching+ranking; asserts `technique_count` ordering, top-5 cap, revoked-object exclusion, and
  the `subject_type` split for a name appearing in both dictionaries. No live network call.
- `ransomware.test.js` / `malware.test.js` / `ioc.test.js`: fixtures updated to pass a `Map`
  instead of depending on the real JSON file.
- `relevance.test.js`: assert the one preload query happens once per recompute call, not per item.

## Out of scope

- **Growing `data/threat-actors.json` / `data/malware-families.json` from the same STIX bundle.**
  Real fix for the same staleness problem, and cheap to add once this ingestion exists — but this
  dictionary also drives `enrich.js`'s live ingest-time matching (populates `item_actors` /
  `item_malware_families` on every synced item, feeds corroboration/confidence scoring). Growing it
  10→100s of names needs its own design pass for match-precision and ingest-time performance, not a
  drive-by expansion here. Separate spec.
- **ATT&CK grounding for the CVE playbook (`playbook.js`).** A real, sourced chain exists (NVD
  publishes CWE per CVE; MITRE publishes an official CWE→CAPEC→ATT&CK-technique mapping) — but
  nothing in this codebase captures CWE today (checked: no `cwe` column, NVD adapter doesn't read
  `weaknesses[]` from the API response). That capture is a prerequisite, not part of this spec.
  Separate spec.
- **Live/scheduled sync.** ATT&CK's Enterprise matrix updates roughly twice a year; wiring this
  into the per-minute `sources.config.js` scheduler like the 43 feeds would be pure waste for data
  that changes this rarely. Manual rerun, like the other backfill scripts.
