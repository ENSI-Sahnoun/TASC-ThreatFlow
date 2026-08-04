# Clickable Provenance + Affected-Version Ranges Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the "why" provenance link in the impact panel keyboard/touch-accessible, and make the playbook's confirm step state the specific affected version range instead of a generic "check whether you run the affected version."

> **Amendment, 2026-08-04.** Each `affected_versions` entry now carries the raw bound fields
> (`startIncluding`/`startExcluding`/`endIncluding`/`endExcluding`/`pinned`) alongside the
> human-readable `text`. `text` is unchanged and remains what the confirm step renders, so Tasks
> 3–6 are untouched; only Task 1's implementation and Task 1/2's `deepStrictEqual` expectations
> change. Reason: a follow-on remediation system has to compare a version the user actually runs
> against the affected range, and decide what to upgrade to. Re-parsing `"before 7.4.5"` with a
> regex would be reconstructing data we discarded one function earlier. Storing the fields now
> costs one object literal; adding them later costs a second migration plus a full
> `consolidate()` re-run.
>
> The bound fields are stored, not yet interpreted. In particular **`endExcluding` is the only
> field that names a fixed version.** `endIncluding: "2.4.1"` says "≤ 2.4.1 is broken" and says
> nothing about what is fixed; no downstream code may infer `2.4.2` from it. That rule is
> enforced where the inference would happen, not here.

**Architecture:** Backend: a new pure `affectedVersionsFrom()` in `server/consolidate.js` reads NVD's `raw_json` CPE match data (already used for `patchUrl`/`advisoryUrl`) and writes a new `cve_intel.affected_versions` JSONB column during the existing `rebuildCveIntel` pass; `relevance.js` threads it through to `playbook.js`'s `confirmStep`. Frontend: `impact-panel.component.ts`'s hover-only `title` tooltip becomes a `<button>` toggling an inline reveal.

**Tech Stack:** Node 22 · Express 4 · PostgreSQL 16 (`node:test`, colocated `*.test.js`, isolated stores via `test-helpers.js`) · Angular 19 standalone components (vitest, no TestBed).

## Global Constraints

- Every derived fact must trace to something a source actually said; an unparseable or absent value is `null`, never a guess (this codebase's rule throughout `consolidate.js`/`consequence.js`/`playbook.js`).
- `affectedVersionsFrom` only ever reads the real NVD row (found via `evidence.find((e) => e.source_name === 'NVD CVE API')`), same restriction `referenceUrlFrom` already has — an incidentally-shared CVE from another source has no CPE configuration to read.
- No new backfill script — `cve_intel` fully rebuilds (`DELETE` + reinsert) on every `consolidate()` pass, which already runs at the end of every sync.
- Reuse `parseCpe` from `server/cpe.js` rather than reimplementing CPE-string parsing, so vendor/product spelling matches `item_cpes` exactly.
- Frontend: no TestBed in this app by design — component behavior is either a pure function in `core/*.ts` with its own `*.spec.ts`, or (for trivial synchronous UI-only state, per `playbook-panel.component.ts` precedent) plain component fields with no dedicated spec file.

---

### Task 1: `versionRangeText` + `affectedVersionsFrom` pure functions

**Files:**
- Modify: `server/consolidate.js:3-5` (add `parseCpe` import), `server/consolidate.js:74` (append new functions after `referenceUrlFrom`, before `rebuildCveIntel`)
- Test: `server/consolidate.test.js` (append new tests at end of file)

**Interfaces:**
- Consumes: `parseCpe(criteria)` from `./cpe.js` — returns `{ part, vendor, product }` (all lowercased) or `null`.
- Produces: `versionRangeText(match)` — takes one `cpeMatch[]` entry object (`{ criteria, versionStartIncluding?, versionStartExcluding?, versionEndIncluding?, versionEndExcluding? }`), returns a string or `null`. `versionBounds(match)` — takes the same entry, returns `{ startIncluding, startExcluding, endIncluding, endExcluding, pinned }` with every field a string or `null`. `affectedVersionsFrom(nvdRow)` — takes a row shaped like `{ raw_json }` (same shape `referenceUrlFrom` takes), returns `Array<{ vendor, product, text, startIncluding, startExcluding, endIncluding, endExcluding, pinned }>`. All three used by Task 2.

- [ ] **Step 1: Write the failing tests**

Append to `server/consolidate.test.js`:

```js
const { versionRangeText, versionBounds, affectedVersionsFrom } = require('./consolidate');

// Spread into an expectation and override only the field under test, so a test reads as "this
// bound and nothing else" rather than five lines of null.
const NO_BOUNDS = { startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: null, pinned: null };

test('versionRangeText: versionEndExcluding only reads as "before X"', () => {
  assert.strictEqual(versionRangeText({ versionEndExcluding: '10.0.26100.8875' }), 'before 10.0.26100.8875');
});

test('versionRangeText: versionEndIncluding only reads as "X and earlier"', () => {
  assert.strictEqual(versionRangeText({ versionEndIncluding: '2.4.1' }), '2.4.1 and earlier');
});

test('versionRangeText: versionStartIncluding only reads as "X and later"', () => {
  assert.strictEqual(versionRangeText({ versionStartIncluding: '3.0.0' }), '3.0.0 and later');
});

test('versionRangeText: versionStartExcluding only reads as "after X"', () => {
  assert.strictEqual(versionRangeText({ versionStartExcluding: '1.0.0' }), 'after 1.0.0');
});

test('versionRangeText: start + inclusive end reads as "X through Y"', () => {
  assert.strictEqual(
    versionRangeText({ versionStartIncluding: '1.0.0', versionEndIncluding: '1.5.0' }),
    '1.0.0 through 1.5.0');
});

test('versionRangeText: start + exclusive end reads as "X up to (not including) Y"', () => {
  assert.strictEqual(
    versionRangeText({ versionStartIncluding: '1.0.0', versionEndExcluding: '2.0.0' }),
    '1.0.0 up to (not including) 2.0.0');
});

test('versionRangeText: no bound fields falls back to the CPE\'s own pinned version segment', () => {
  assert.strictEqual(
    versionRangeText({ criteria: 'cpe:2.3:a:acme:widget:4.2.1:*:*:*:*:*:*:*' }),
    'version 4.2.1');
});

test('versionRangeText: no bounds and a wildcard version yields null', () => {
  assert.strictEqual(versionRangeText({ criteria: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*' }), null);
});

test('versionRangeText: no bounds and no criteria at all yields null', () => {
  assert.strictEqual(versionRangeText({}), null);
});

test('versionBounds: each NVD bound field is carried through verbatim', () => {
  assert.deepStrictEqual(
    versionBounds({ versionStartIncluding: '1.0.0', versionEndExcluding: '2.0.0' }),
    { startIncluding: '1.0.0', startExcluding: null, endIncluding: null, endExcluding: '2.0.0', pinned: null });
});

test('versionBounds: an exact pinned version is reported as pinned, not as a range', () => {
  assert.deepStrictEqual(
    versionBounds({ criteria: 'cpe:2.3:a:acme:widget:4.2.1:*:*:*:*:*:*:*' }),
    { startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: null, pinned: '4.2.1' });
});

test('versionBounds: a wildcard version and no bounds is all-null — nothing is invented', () => {
  assert.deepStrictEqual(
    versionBounds({ criteria: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*' }),
    { startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: null, pinned: null });
});

test('versionBounds: "X and earlier" sets endIncluding and leaves endExcluding null', () => {
  // endExcluding is the only field that names a fixed version. A caller reading this entry must
  // find nothing to upgrade to, because NVD said nothing about one.
  const b = versionBounds({ versionEndIncluding: '2.4.1' });
  assert.strictEqual(b.endIncluding, '2.4.1');
  assert.strictEqual(b.endExcluding, null);
});

test('affectedVersionsFrom: one entry per distinct vendor/product, arch variants deduped', () => {
  const nvdRow = {
    raw_json: JSON.stringify({
      configurations: [{
        nodes: [{
          cpeMatch: [
            { vulnerable: true, criteria: 'cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*', versionEndExcluding: '10.0.26100.8875' },
            { vulnerable: true, criteria: 'cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*', versionEndExcluding: '10.0.26100.8875' },
            { vulnerable: true, criteria: 'cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*', versionEndExcluding: '10.0.19045.7548' },
          ],
        }],
      }],
    }),
  };
  const result = affectedVersionsFrom(nvdRow);
  assert.deepStrictEqual(result, [
    { vendor: 'microsoft', product: 'windows_11_24h2', text: 'before 10.0.26100.8875', ...NO_BOUNDS, endExcluding: '10.0.26100.8875' },
    { vendor: 'microsoft', product: 'windows_10_22h2', text: 'before 10.0.19045.7548', ...NO_BOUNDS, endExcluding: '10.0.19045.7548' },
  ]);
});

test('affectedVersionsFrom: vulnerable:false platform-dependency entries are skipped', () => {
  const nvdRow = {
    raw_json: JSON.stringify({
      configurations: [{
        nodes: [{
          cpeMatch: [
            { vulnerable: false, criteria: 'cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*' },
            { vulnerable: true, criteria: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*', versionEndExcluding: '4.0' },
          ],
        }],
      }],
    }),
  };
  assert.deepStrictEqual(affectedVersionsFrom(nvdRow),
    [{ vendor: 'acme', product: 'widget', text: 'before 4.0', ...NO_BOUNDS, endExcluding: '4.0' }]);
});

test('affectedVersionsFrom: a match with nothing meaningful to say is excluded, not padded with null', () => {
  const nvdRow = {
    raw_json: JSON.stringify({
      configurations: [{ nodes: [{ cpeMatch: [
        { vulnerable: true, criteria: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*' },
      ] }] }],
    }),
  };
  assert.deepStrictEqual(affectedVersionsFrom(nvdRow), []);
});

test('affectedVersionsFrom: no configurations, malformed raw_json, or no row all yield []', () => {
  assert.deepStrictEqual(affectedVersionsFrom({ raw_json: JSON.stringify({}) }), []);
  assert.deepStrictEqual(affectedVersionsFrom({ raw_json: 'not json' }), []);
  assert.deepStrictEqual(affectedVersionsFrom(null), []);
  assert.deepStrictEqual(affectedVersionsFrom({}), []);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/consolidate.test.js`
Expected: FAIL — `versionRangeText`/`affectedVersionsFrom` are not exported (TypeError: `versionRangeText is not a function` or similar).

- [ ] **Step 3: Implement**

In `server/consolidate.js`, change the top imports:

```js
const { clusterItems } = require('./cluster');
const { computeConfidence } = require('./confidence');
const { severityFromScore, canonicalSeverity } = require('./cvss');
const { parseCpe } = require('./cpe');
```

Then, immediately after the existing `referenceUrlFrom` function (currently ending at line 74, right before `async function rebuildCveIntel`), insert:

```js
// Formats one CPE match's version bound into a plain-English fragment. Only vulnerable:true
// matches are ever passed in by affectedVersionsFrom — a "runs on" platform dependency isn't a
// statement about which version of the affected product itself is unsafe.
function versionRangeText(match) {
  const startIncluding = match.versionStartIncluding;
  const startExcluding = match.versionStartExcluding;
  const endIncluding = match.versionEndIncluding;
  const endExcluding = match.versionEndExcluding;
  const start = startIncluding || startExcluding;
  const end = endIncluding || endExcluding;
  if (start && end) {
    return endIncluding ? `${start} through ${end}` : `${start} up to (not including) ${end}`;
  }
  if (end) return endExcluding ? `before ${end}` : `${end} and earlier`;
  if (start) return startExcluding ? `after ${start}` : `${start} and later`;
  // No bound fields — fall back to the CPE's own pinned version segment.
  const version = pinnedVersion(match);
  return version ? `version ${version}` : null;
}

// The CPE's own version segment (5th colon field, cpe : 2.3 : part : vendor : product : version
// : ...), when it isn't the wildcard '*' or the not-applicable '-'.
function pinnedVersion(match) {
  const fields = typeof match.criteria === 'string' ? match.criteria.split(':') : [];
  const version = fields[5];
  return version && version !== '*' && version !== '-' ? version : null;
}

// The same facts as versionRangeText, as fields instead of a sentence. versionRangeText is what a
// reader sees; this is what code compares against a version someone actually runs. Every field is
// null unless NVD supplied it — this function derives nothing.
//
// endExcluding is the only field that names a fixed version. endIncluding says "this and earlier
// is broken" and names no fix; pinned says "exactly this version is broken" and names no fix
// either. Any caller turning one of these into an upgrade target would be inventing it.
function versionBounds(match) {
  return {
    startIncluding: match.versionStartIncluding || null,
    startExcluding: match.versionStartExcluding || null,
    endIncluding: match.versionEndIncluding || null,
    endExcluding: match.versionEndExcluding || null,
    pinned: pinnedVersion(match),
  };
}

// One line of text per distinct (vendor, product) the real NVD row calls vulnerable, in the
// order NVD lists them. Reuses parseCpe so the vendor/product spelling matches item_cpes exactly
// — this is what buildPlaybook/buildConsequence key their lookup on.
function affectedVersionsFrom(nvdRow) {
  if (!nvdRow || !nvdRow.raw_json) return [];
  let raw;
  try { raw = JSON.parse(nvdRow.raw_json); } catch { return []; }
  const out = [];
  const seen = new Set();
  for (const config of raw.configurations || []) {
    for (const node of (config && config.nodes) || []) {
      for (const match of (node && node.cpeMatch) || []) {
        if (!match || match.vulnerable !== true) continue;
        const parsed = parseCpe(match.criteria);
        if (!parsed) continue;
        const key = `${parsed.vendor}:${parsed.product}`;
        if (seen.has(key)) continue;
        const text = versionRangeText(match);
        if (!text) continue;
        seen.add(key);
        out.push({ vendor: parsed.vendor, product: parsed.product, text, ...versionBounds(match) });
      }
    }
  }
  return out;
}
```

Update the `module.exports` line at the end of the file:

```js
module.exports = { consolidate, rebuildCveIntel, rebuildClusters, applyConfidence, pruneSyncHistory, SOURCE_RANK, versionRangeText, versionBounds, affectedVersionsFrom };
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/consolidate.test.js`
Expected: PASS, all tests including the new ones.

- [ ] **Step 5: Commit**

```bash
git add server/consolidate.js server/consolidate.test.js
git commit -m "feat(playbooks): add pure affectedVersionsFrom/versionRangeText version-range extraction"
```

---

### Task 2: `cve_intel.affected_versions` column, wired into `rebuildCveIntel`

**Files:**
- Modify: `server/db.js:330` (new `ALTER TABLE`), `server/consolidate.js` (cveIntel array + insert + select)
- Test: `server/consolidate.test.js` (append)

**Interfaces:**
- Consumes: `affectedVersionsFrom(nvdRow)` from Task 1.
- Produces: `cve_intel.affected_versions` column, readable as `SELECT affected_versions FROM cve_intel WHERE cve_id = $1` → JSON array of `{ vendor, product, text }`, always present (an empty array `[]`, never SQL `NULL`, when there's no parseable NVD version data — the INSERT always supplies a value). Consumed by Task 4 (`relevance.js`).

- [ ] **Step 1: Write the failing test**

Append to `server/consolidate.test.js`:

```js
test('rebuildCveIntel writes affected_versions from the real NVD row\'s CPE matches', async () => {
  await withTestStore(async (store) => {
    const nvd = await mkSource(store, 'NVD CVE API', 'Vulnerability Intelligence');
    const a = await store.get(
      `INSERT INTO items (source_id, category, title, cvss_score, published_at, raw_json)
       VALUES ($1,'cve','CVE-2026-7020',9.8,'2026-07-01T00:00:00Z',$2) RETURNING id`,
      [nvd.id, JSON.stringify({
        configurations: [{ nodes: [{ cpeMatch: [
          { vulnerable: true, criteria: 'cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*', versionEndExcluding: '10.0.26100.8875' },
        ] }] }],
      })]);
    await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [a.id, 'CVE-2026-7020']);

    await rebuildCveIntel(store);
    const row = await store.get('SELECT affected_versions FROM cve_intel WHERE cve_id=$1', ['CVE-2026-7020']);
    assert.deepStrictEqual(row.affected_versions, [
      {
        vendor: 'microsoft', product: 'windows_11_24h2', text: 'before 10.0.26100.8875',
        startIncluding: null, startExcluding: null, endIncluding: null,
        endExcluding: '10.0.26100.8875', pinned: null,
      },
    ]);
  });
});

test('affected_versions is null when the CVE\'s NVD row has no parseable CPE version data', async () => {
  await withTestStore(async (store) => {
    const nvd = await mkSource(store, 'NVD CVE API', 'Vulnerability Intelligence');
    const a = await mkItem(store, nvd.id, { cvss: 5.0 });
    await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [a.id, 'CVE-2026-7021']);

    await rebuildCveIntel(store);
    const row = await store.get('SELECT affected_versions FROM cve_intel WHERE cve_id=$1', ['CVE-2026-7021']);
    assert.deepStrictEqual(row.affected_versions, []);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/consolidate.test.js`
Expected: FAIL — `column "affected_versions" does not exist`.

- [ ] **Step 3: Implement**

In `server/db.js`, immediately after the existing line `ALTER TABLE cve_intel ADD COLUMN IF NOT EXISTS advisory_url TEXT;` (currently line 330), add:

```js
    -- Per-product version ranges lifted from the real NVD row's CPE match data (parseCpe/
    -- affectedVersionsFrom in consolidate.js). [{vendor, product, text, startIncluding,
    -- startExcluding, endIncluding, endExcluding, pinned}] — `text` is the rendered sentence,
    -- the rest are NVD's own bound fields kept comparable for code. Empty array, not null, when
    -- the CVE has no parseable version data — see affectedVersionsFrom's own doc comment.
    ALTER TABLE cve_intel ADD COLUMN IF NOT EXISTS affected_versions JSONB;
```

In `server/consolidate.js`, inside `rebuildCveIntel`, extend the `cveIntel` accumulator object literal to add an `affectedVersions: []` array field (in whatever position matches the existing key ordering — it doesn't need to be adjacent to any particular key).

In the per-CVE `for` loop, right after the existing block that computes `nvdRow`/`patchUrl`/`advisoryUrl` (the block ending `const advisoryUrl = referenceUrlFrom(nvdRow, ADVISORY_TAG);`), add:

```js
    const affectedVersions = affectedVersionsFrom(nvdRow);
```

Find this exact block (the `cveIntel.*.push(...)` calls) and add one line, `cveIntel.affectedVersions.push(...)`, anywhere among the others:

```js
    cveIntel.cveId.push(cveId);
    cveIntel.cvss.push(cvss);
    cveIntel.cvssSource.push(winner ? winner.source_name : null);
    cveIntel.severity.push(severity);
    cveIntel.epss.push(epss ? Number(epss.epss_score) : null);
    cveIntel.kevListed.push(Boolean(exploited));
    cveIntel.kevAddedAt.push(kevRow ? kevRow.published_at : null);
    cveIntel.kevDueDate.push(kevDueDate);
    cveIntel.kevRequiredAction.push(kevRequiredAction);
    cveIntel.kevRansomware.push(kevRansomware);
    cveIntel.patchUrl.push(patchUrl);
    cveIntel.advisoryUrl.push(advisoryUrl);
    cveIntel.affectedVersions.push(JSON.stringify(affectedVersions));
    cveIntel.description.push(description);
    cveIntel.firstSeen.push(times.length ? new Date(times[0]) : null);
    cveIntel.lastSeen.push(times.length ? new Date(times[times.length - 1]) : null);
    cveIntel.sourceCount.push(new Set(evidence.map((e) => e.source_id)).size);
```

(Stored pre-stringified per array element because `unnest($n::jsonb[])` needs a `jsonb[]` array of individually-valid JSON text — each element must itself be a JSON string, not a nested JS array, for the driver to bind it as `jsonb[]`.)

Find this exact block (the batched `INSERT INTO cve_intel` inside `store.tx`, currently `$1`–`$16`):

```js
    if (cveIntel.cveId.length) {
      await t.run(
        `INSERT INTO cve_intel (cve_id, cvss_score, cvss_source, severity, epss_score, kev_listed,
                                kev_added_at, kev_due_date, kev_required_action, kev_ransomware,
                                patch_url, advisory_url, description, first_seen, last_seen, source_count)
         SELECT * FROM unnest($1::text[], $2::float8[], $3::text[], $4::text[], $5::float8[],
                              $6::bool[], $7::timestamptz[], $8::date[], $9::text[], $10::bool[],
                              $11::text[], $12::text[], $13::text[], $14::timestamptz[], $15::timestamptz[], $16::int[])`,
        [cveIntel.cveId, cveIntel.cvss, cveIntel.cvssSource, cveIntel.severity, cveIntel.epss,
         cveIntel.kevListed, cveIntel.kevAddedAt, cveIntel.kevDueDate, cveIntel.kevRequiredAction, cveIntel.kevRansomware,
         cveIntel.patchUrl, cveIntel.advisoryUrl, cveIntel.description, cveIntel.firstSeen, cveIntel.lastSeen, cveIntel.sourceCount]);
```

Replace it with (adds `affected_versions`/`$13::jsonb[]`, renumbers every placeholder after it by one, up to `$17`):

```js
    if (cveIntel.cveId.length) {
      await t.run(
        `INSERT INTO cve_intel (cve_id, cvss_score, cvss_source, severity, epss_score, kev_listed,
                                kev_added_at, kev_due_date, kev_required_action, kev_ransomware,
                                patch_url, advisory_url, affected_versions, description, first_seen, last_seen, source_count)
         SELECT * FROM unnest($1::text[], $2::float8[], $3::text[], $4::text[], $5::float8[],
                              $6::bool[], $7::timestamptz[], $8::date[], $9::text[], $10::bool[],
                              $11::text[], $12::text[], $13::jsonb[], $14::text[], $15::timestamptz[], $16::timestamptz[], $17::int[])`,
        [cveIntel.cveId, cveIntel.cvss, cveIntel.cvssSource, cveIntel.severity, cveIntel.epss,
         cveIntel.kevListed, cveIntel.kevAddedAt, cveIntel.kevDueDate, cveIntel.kevRequiredAction, cveIntel.kevRansomware,
         cveIntel.patchUrl, cveIntel.advisoryUrl, cveIntel.affectedVersions, cveIntel.description, cveIntel.firstSeen, cveIntel.lastSeen, cveIntel.sourceCount]);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/consolidate.test.js`
Expected: PASS, all tests.

Also run the full backend suite to confirm the column addition and renumbered insert didn't break any existing `cve_intel` assertions:
Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add server/db.js server/consolidate.js server/consolidate.test.js
git commit -m "feat(playbooks): add cve_intel.affected_versions, populated by rebuildCveIntel"
```

---

### Task 3: `confirmStep`/`buildPlaybook` accept and use `affectedVersions`

**Files:**
- Modify: `server/playbook.js:22-31` (`confirmStep`), `server/playbook.js:94-117` (`buildPlaybook`)
- Test: `server/playbook.test.js` (append)

**Interfaces:**
- Consumes: nothing new from other tasks — `affectedVersions` is passed in by the caller (Task 4 wires the real value; this task only needs the parameter to exist and behave correctly given any array).
- Produces: `buildPlaybook({ ..., affectedVersions })` — new optional param, default `[]`. `confirmStep`'s `detail` includes the matched version text when present.

- [ ] **Step 1: Write the failing tests**

Append to `server/playbook.test.js`:

```js
// --- confirm: version specificity ---

test('confirm names the specific affected version range when one matches the asset', () => {
  const steps = base({
    affectedVersions: [
      { vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5' },
      { vendor: 'fortinet', product: 'forticlient', text: 'before 7.2.0' }, // different product, must not match
    ],
  });
  assert.match(find(steps, 'confirm').detail, /before 7\.4\.5/);
  assert.match(find(steps, 'confirm').source, /NVD CPE match/);
});

test('confirm stays generic when affectedVersions has no entry for this vendor/product', () => {
  const steps = base({ affectedVersions: [{ vendor: 'microsoft', product: 'windows_11_24h2', text: 'before 10.0.26100.8875' }] });
  assert.doesNotMatch(find(steps, 'confirm').detail, /before/);
  assert.strictEqual(find(steps, 'confirm').source, 'your profile assets');
});

test('confirm stays generic when affectedVersions is omitted entirely', () => {
  const steps = base();
  // roleFor('fortinet', 'fortios') resolves to 'your VPN and firewall' (server/asset_roles.js).
  assert.strictEqual(find(steps, 'confirm').detail, 'Affected: your VPN and firewall');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/playbook.test.js`
Expected: FAIL — the first two new tests fail because `detail` doesn't yet include version text.

- [ ] **Step 3: Implement**

In `server/playbook.js`, replace `confirmStep`:

```js
function confirmStep(vendor, product, affectedVersions) {
  const target = targetPhrase(vendor, product);
  const match = (affectedVersions || []).find((v) => v.vendor === vendor && v.product === product);
  return {
    key: 'confirm',
    title: 'Check whether you run the affected version',
    detail: match ? `Affected: ${target} — ${match.text}` : `Affected: ${target}`,
    source: match ? 'NVD CPE match (version range)' : (vendor && product ? 'your profile assets' : 'this item’s CVE match'),
    link: null,
  };
}
```

Update `buildPlaybook`'s signature and its call to `confirmStep`:

```js
function buildPlaybook({
  vector, exposure = 'unknown', vendor = null, product = null,
  kevListed = false, kevDueDate = null, kevRansomware = false,
  patchUrl = null, advisoryUrl = null, affectedVersions = [],
} = {}) {
  const parsed = vector ? parseVector(vector) : null;
  const metrics = parsed ? parsed.metrics : null;

  const steps = [confirmStep(vendor, product, affectedVersions)];
  // ... rest of function unchanged
```

(Only the `confirmStep(vendor, product)` call site and the destructured params change — every other line in `buildPlaybook` stays exactly as-is.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/playbook.test.js`
Expected: PASS, all tests including the pre-existing ones (they still call `base()`/`buildPlaybook` without `affectedVersions`, which now defaults to `[]`).

- [ ] **Step 5: Commit**

```bash
git add server/playbook.js server/playbook.test.js
git commit -m "feat(playbooks): confirm step states the matched product's affected version range"
```

---

### Task 4: Wire `affected_versions` through `relevance.js`

**Files:**
- Modify: `server/relevance.js:20-124`
- Test: `server/relevance.test.js` (append)

**Interfaces:**
- Consumes: `cve_intel.affected_versions` column (Task 2), `buildPlaybook({ ..., affectedVersions })` (Task 3).
- Produces: `item_playbooks.steps[].detail` includes real version text end-to-end for a matched asset.

- [ ] **Step 1: Write the failing test**

Append to `server/relevance.test.js` (place near the existing `'a low-tier item gets no item_playbooks row'` test, reusing the same `WORST` vector constant and `createProfile`/`PROFILE_INPUT` helpers already imported at the top of that file):

```js
test('the confirm step states the affected version range when cve_intel carries one for the matched product', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
    const i = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, cvss_vector, published_at)
       VALUES ($1,'cve','FortiOS RCE','CVE-2026-30',$2, now() - interval '2 days') RETURNING id`,
      [s.id, WORST]);
    await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [i.id]);
    await store.run("INSERT INTO item_cves (item_id, cve_id) VALUES ($1,'CVE-2026-30')", [i.id]);
    await store.run(
      `INSERT INTO cve_intel (cve_id, severity, kev_listed, affected_versions)
       VALUES ('CVE-2026-30','critical',true,$1)`,
      [JSON.stringify([{ vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5' }])]);
    const p = await createProfile(store, {
      ...PROFILE_INPUT,
      assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
    });

    await recomputeProfile(store, p.id);

    const row = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2 AND profile_version=$3',
      [i.id, p.id, p.profile_version]);
    const confirm = row.steps.find((st) => st.key === 'confirm');
    assert.match(confirm.detail, /before 7\.4\.5/);
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/relevance.test.js`
Expected: FAIL — `confirm.detail` does not contain the version text (still the generic form), since `relevance.js` doesn't read or forward `affected_versions` yet.

- [ ] **Step 3: Implement**

In `server/relevance.js`, in `assembleItems`'s SQL (the lateral join aliased `ci`), add `ci.affected_versions` to the select list:

```js
    SELECT i.id, i.severity, i.cvss_score, i.cvss_version, i.cvss_vector, i.published_at, i.industry,
           COALESCE(d.domains, '{}') AS domains,
           COALESCE(c.cpes, '[]'::jsonb) AS cpes,
           ci.kev_listed, ci.epss_score, ci.severity AS cve_severity, ci.cvss_score AS cve_cvss,
           ci.kev_ransomware, ci.patch_url, ci.advisory_url, ci.affected_versions,
           to_char(ci.kev_due_date, 'YYYY-MM-DD') AS kev_due_date
```

In the `rows.map((r) => ({ ... }))` shape, inside the `cve: ...` object, add `affectedVersions: r.affected_versions || [],` alongside the existing `patchUrl`/`advisoryUrl` fields.

In `recomputeProfile`, inside the `buildPlaybook({...})` call, add:

```js
        affectedVersions: item.cve ? item.cve.affectedVersions : [],
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/relevance.test.js`
Expected: PASS, all tests.

Run full backend suite: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add server/relevance.js server/relevance.test.js
git commit -m "feat(playbooks): thread cve_intel.affected_versions through to the confirm step"
```

---

### Task 5: Clickable "why" in the impact panel

**Files:**
- Modify: `frontend-v4/src/app/ui/impact-panel.component.ts`

**Interfaces:**
- Consumes: `ImpactBlock` shape from `frontend-v4/src/app/core/relevance.ts` (unchanged — `{ label, text, from, missing }`).
- Produces: no new exported interface; purely a template/class change local to this component.

- [ ] **Step 1: Implement the toggle**

Replace the template's `dd` block:

```html
              <dd>
                {{ b.text }}
                <!-- Provenance, so a claim about the reader's own estate can be checked rather
                     than taken on trust. A button, not a title tooltip — hover-only provenance
                     was unreachable by keyboard or touch. -->
                @if (b.from) {
                  <button type="button" class="from" [attr.aria-expanded]="isOpen(b.label)" (click)="toggle(b.label)">why</button>
                }
                @if (b.from && isOpen(b.label)) { <p class="prov">{{ b.from }}</p> }
              </dd>
```

Replace the `.from` style rule and add a `.prov` rule:

```css
    .from {
      font: inherit; font-size: var(--fs-xs); color: var(--ink-2); cursor: pointer;
      background: none; border: none; padding: 0; margin-left: 6px;
      border-bottom: 1px dotted currentColor;
    }
    .from:hover, .from:focus-visible { color: var(--ink); }
    .from:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .prov { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink-2); }
```

(Remove the old `.from { ...cursor: help... }` rule entirely — the button rule above replaces it.)

Add toggle state and methods to the component class, right after the `@Input() relevance` line:

```ts
  private openBlocks = new Set<string>();

  isOpen(label: string): boolean {
    return this.openBlocks.has(label);
  }

  toggle(label: string): void {
    if (this.openBlocks.has(label)) this.openBlocks.delete(label);
    else this.openBlocks.add(label);
  }
```

No signal needed: this is a synchronous click handler inside an `OnPush` component, and Angular runs change detection on the component whenever a DOM event originates from within its own template — the same reasoning that already lets `RelevanceChipComponent`'s plain getters and `explorer.component.ts`'s `toggleCluster` work without signals.

- [ ] **Step 2: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 3: Manual verification in the browser**

Start the backend (`cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node server/index.js`) and the frontend dev server (`cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npm start` — runs `ng serve --port 4400 --proxy-config proxy.conf.json`, i.e. http://localhost:4400). Open an item detail page for an `act_now`/`watch` item with at least one populated impact-block fact (any item with `items.cvss_vector` set, per the earlier backfill run). Click "why" on a fact: the provenance text should appear inline below it immediately, and clicking again should hide it. Tab to the button with the keyboard and press Enter: same behavior. This matches the project's own rule ("For UI or frontend changes ... use the feature in a browser before reporting the task as complete").

- [ ] **Step 4: Commit**

```bash
git add frontend-v4/src/app/ui/impact-panel.component.ts
git commit -m "fix(impact): make the 'why' provenance link a real button, not a hover-only tooltip"
```

---

### Task 6: Data refresh and full verification

**Files:** none (operational task — refreshes derived data in the running dev database and confirms everything end-to-end).

**Interfaces:** none — this task only exercises what Tasks 1–5 already built.

- [ ] **Step 1: Run the full backend suite**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures.

- [ ] **Step 2: Run the full frontend suite**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures.

- [ ] **Step 3: Refresh `cve_intel.affected_versions` in the dev database**

`affected_versions` only exists in rows written after Task 2's schema change. Repopulate it without a full network sync by calling `consolidate()` directly (same technique already used earlier for the initial `cvss_vector` backfill):

`server/db.js` exports the singleton store directly (`module.exports = store`, built from `createStore()` in `server/store.js`), so:

```bash
cd /home/sah/projects
/home/sah/.nvm/versions/node/v22.23.1/bin/node -e "
const store = require('./server/db');
const { consolidate } = require('./server/consolidate');
(async () => {
  console.log(await consolidate(store));
  process.exit(0);
})();
"
```

- [ ] **Step 4: Recompute relevance for every profile**

With the API server running (`/home/sah/.nvm/versions/node/v22.23.1/bin/node server/index.js`), recompute each profile so `item_playbooks` regenerates with the new confirm-step wording:

```bash
docker exec -e PGPASSWORD=postgres threatflow-pg16 psql -U postgres -d threatflow -X -t -c "SELECT id FROM profiles;" \
  | while read -r id; do [ -n "$id" ] && curl -s -X POST "http://localhost:4173/api/profiles/$id/relevance/recompute" && echo; done
```

- [ ] **Step 5: Spot-check one real playbook got a version-qualified confirm step**

```bash
docker exec -e PGPASSWORD=postgres threatflow-pg16 psql -U postgres -d threatflow -X -c "
SELECT ip.item_id, jsonb_pretty(ip.steps::jsonb -> 0)
  FROM item_playbooks ip
  JOIN cve_intel ci ON ci.affected_versions IS NOT NULL AND ci.affected_versions != '[]'
  JOIN item_cves ic ON ic.item_id = ip.item_id AND ic.cve_id = ci.cve_id
 LIMIT 3;"
```

Expected: at least one row (may be zero if no currently-relevant item happens to match a profile's asset vendor/product exactly — if so, this is not a failure of the feature, just a sampling gap; confirm instead via a `psql` query joining `item_cpes`/`profile_assets` to find a real matching pair, or trust Task 4's integration test as the authoritative proof).

- [ ] **Step 6: Manual browser check of both features together**

Reload the item detail page from Task 5's manual check (or navigate to whichever item Step 5 above found). Confirm: (a) the "why" buttons work as verified in Task 5, and (b) the playbook's "Check whether you run the affected version" step now names a specific version range for a matched asset.

- [ ] **Step 7: Final commit** (only if Steps 3–6 required any code fixes; if everything passed as-is, there is nothing to commit here)

```bash
git status
# If clean, nothing to do. If any fix was needed above, commit it with an accurate message
# describing what was actually wrong, following the same commit-message conventions as Tasks 1-5.
```
