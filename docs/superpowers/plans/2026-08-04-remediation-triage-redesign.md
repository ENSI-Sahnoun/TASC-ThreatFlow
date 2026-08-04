# Remediation Triage Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the remediation queue (`/remediate`) and guided page (`/remediate/:itemId`) so 295 threats read as nine actionable rows instead of a flat 295-row wall — grouped by fix, ranked by risk (worst CVSS, KEV overriding score), split three ways once a version is known, filterable, with provenance and a ticket-text export — and extend the guided page's reach diagram to state `AC`/`S` and per-metric `C`/`I`/`A` levels it currently drops. Revises the queue/guided pages Spec B shipped, on Spec A's already-tested pure functions.

**Architecture:** All new decision logic — grouping, risk/reach ordering, the three-way status split, filtering, diagram layout, provenance text, ticket text — is pure functions in `frontend-v4/src/app/core/remediation.ts`, tested without a DOM (vitest, node environment, no TestBed, this app's existing convention). The backend change is a single task: seven fields (`cveId` also, an eighth — see Spec Accuracy Finding 2) added to the existing `LATERAL` join projection on both remediation GET routes, no new join, no new query, no change to `fixTarget`/`remediationFor`/`affectedStatus`/`version_compare.js`. Components stay thin bindings over the pure module, per this app's established split.

**Tech Stack:** Node 22 (`/home/sah/.nvm/versions/node/v22.23.1/bin/node`) · Express 4 · PostgreSQL 16 (`node:test`, colocated `*.test.js`, isolated stores via `test-helpers.js`) · Angular 19 standalone components (vitest, no TestBed).

## Global Constraints

- Existing tokens only (`frontend-v4/src/app/core/tokens.css`). No new palette, no new radius scale. Severity uses the existing `--sev-*` ramp (`--sev-critical: #ff0086`, `--sev-high: #ff4da8`, `--sev-medium: #8a9900`, `--sev-low: #d6ff00`, `--sev-none: #177d86`, `--sev-unknown: #8c70ff`). KEV differentiates by fill weight (filled vs soft), not a new hue — the ramp keeps one meaning.
- Motion: `--ease-out` for anything entering. `prefers-reduced-motion: reduce` renders the finished state with no draw, everywhere motion is added (existing pattern in `reach-diagram.component.ts` and `remediation-queue.component.ts`'s progress bar).
- Severity colour always comes from the route's `severity` string (`server/cvss.js`'s `severityFromScore`, already computed server-side into `cve_intel.severity`) — never re-derived client-side. This is asserted directly in a test, not just implied by code shape.
- The `not_covered` section caveat is load-bearing, verbatim from Spec B: "Not a clean bill of health — confirm against the vendor advisory before treating any of these as closed." Must never read as "you are safe" — asserted directly.
- `fixTarget`/`remediationFor`/`affectedStatus`/`version_compare.js` (Spec A) are not modified anywhere in this plan. Every verdict this page renders already comes from them; this plan changes only what is rendered and ordered.
- `consequence.js`'s wording (`buildImpact`'s verbs) is read, never edited — Part 7's diagram reuses its verb vocabulary (`read`/`change`/`shut down`, `partly` for `:L`) so the two surfaces never drift into different words for the same metric.
- No EPSS surface (2 non-null scores across the whole open set — not usable). No ticket-system integration — clipboard text only, via the existing `tf-copy-button` component. No cross-asset bulk action.
- Use absolute node/npm paths per `CLAUDE.md`: `/home/sah/.nvm/versions/node/v22.23.1/bin/node`, `/home/sah/.nvm/versions/node/v22.23.1/bin/npm`, `/home/sah/.nvm/versions/node/v22.23.1/bin/npx`.
- No `Co-Authored-By` or Claude/Anthropic attribution in any commit (user's global instruction).
- `docs/superpowers/` is listed in `.git/info/exclude` — a plain `git add` on files under it silently does nothing. This plan's own tasks never touch that directory, so no `-f` is needed for them, but be aware of it if asked to commit spec/plan files themselves.
- Test baselines to beat: backend `663 tests / 661 pass / 0 fail / 2 skipped` (`npm test`, confirmed 2026-08-04). Frontend `176 pass` across 12 files (`npx vitest run`, confirmed 2026-08-04). Every task's verification step must report the actual new numbers, not just "passed."
- Restart the API server (`node server/index.js`) after backend changes before any manual/browser verification — a stale server has already produced one false bug report on this branch.

---

## Spec Accuracy Findings

Recorded here per the spec's own instruction, rather than silently reshaping scope. Confirmed against `server/db.js`'s actual schema, `server/consolidate.js`'s actual write path, and `server/index.js`'s actual route bodies before writing any task below.

### 1. `cve_intel` has no `cvss_version` column — Part 8's field list assumes one

`server/db.js`'s `CREATE TABLE cve_intel` (line 237) carries `cve_id, cvss_score, cvss_source, severity, epss_score, kev_listed, kev_added_at, kev_due_date, description, first_seen, last_seen, source_count`. There is no `cvss_version` column and no `ALTER TABLE cve_intel ADD COLUMN ... cvss_version` anywhere in the migration block. `cvss_version` exists only on `items` (`db.js` line 52, `ALTER TABLE items ADD COLUMN IF NOT EXISTS cvss_version TEXT` at line 328) — the *item's own* reported vector, written by `fetchers.js`/`enrich.js`/`backfill-cvss.js` together with that same item's `cvss_score` in one `UPDATE`/`INSERT`.

Worse: `server/consolidate.js` line 217 computes `cve_intel.severity` via `severityFromScore(cvss)` — called with **no version argument at all**, so `cve_intel.severity` is always banded under v3 rules regardless of which version the winning score actually came from. This is a pre-existing behavior this plan's non-goals forbid touching (`version_compare.js`/`affectedStatus` are the only functions explicitly protected, but `consolidate.js`'s severity derivation is adjacent, untested territory outside every task below's scope — flagged here, not fixed here).

**Resolution:** `cvss_score`, `severity`, `kev_listed`, `kev_due_date`, `kev_ransomware`, `source_count` (six of Part 8's seven fields) all come from the already-joined `cve_intel` row (`ci` in the queue route, a fresh single-CVE query in the detail route) — zero new joins, exactly as Part 8 promises. `cvss_version` has no home in `cve_intel`; Task 1 sources it from `items.cvss_version` instead (already in scope on both routes — `i.cvss_version` in the queue route's existing `items i` join, `item.cvss_version` on the detail route's existing `SELECT * FROM items` row) with a code comment noting it describes the *item's own* reported vector, not necessarily the CVE-level winning source `cvss_score`/`severity` were consolidated from. This is the best available field without a schema migration, which Part 8's "purely additive... no new query" framing does not authorize.

### 2. Part 4's filter needs a `cveId` field neither route currently returns — free from the same join

"A filter field (CVE id or version substring)" (Part 4) requires a per-item CVE id, but neither `GET /api/profiles/:id/remediation` nor `GET /api/items/:id/remediation` currently selects one — only `affected_versions`/`patch_url`/`advisory_url` come out of the `cve_intel` join today. It is available for free: the queue route's `LATERAL` join already does `SELECT ci2.*` (line 215 of `server/index.js`), which includes `cve_id` (the table's own primary key) — it is simply never named in the outer `SELECT` list. Task 1 adds `ci.cve_id AS "cveId"` as an eighth additive field, alongside Part 8's named seven, through the exact same already-existing join.

### 3. Part 2's "recording a version splits the actions" is ambiguous once Part 1 has grouped multiple CVEs under one action

Part 1 groups by `fix.value` — two different CVEs can share the same upgrade target (e.g. both closed by "upgrade to 14.8.8") while carrying different `affected_versions` entries (different `startIncluding`/`startExcluding` bounds), so their `affectedStatus` can genuinely differ even inside one action bundle. Part 2's prose ("Recording a version splits the actions... Still affects you / Can't tell / No longer in range") reads as if one action has one status, which is not guaranteed once Part 1 exists.

**Resolution adopted** (documented in code, not a scope change): an action's status is `'affected'` the moment any item in its bundle is `'affected'` — there is still a reason to do the fix — else `'unknown'` if any item is `'unknown'`, else `'not_covered'` only when every item in the bundle already reads `'not_covered'`. Conservative, worst-case-wins precedence, the same posture `version_compare.js` already applies everywhere: never launder a partial abstention into a resolved claim.

### 4. Part 5's "how many independent sources corroborate" is a per-CVE fact, but the "why" control is per action row

`source_count` (Part 8) lives on `cve_intel`, i.e. one value per CVE — but Part 5 puts the "why this action?" control on the action row (Part 1), which can bundle several CVEs, each with its own `source_count`. Resolution: the "why" panel reports the `source_count` of the item that set the action's worst-CVSS ranking — the same item whose score and severity already anchor the row's headline number, so the panel is never explaining a different CVE than the one the numeral describes.

---

## Task 1: Backend — Part 8's additive fields (`cveId`, `cvssScore`, `cvssVersion`, `severity`, `kevListed`, `kevDueDate`, `kevRansomware`, `sourceCount`) on both remediation routes

**Files:**
- Modify: `server/index.js` (both remediation GET route handlers)
- Test: `server/api.test.js` (append)

**Interfaces:**
- Produces: `GET /api/profiles/:id/remediation` — each item in a group's `items[]` gains `cveId: string | null`, `cvssScore: number | null`, `cvssVersion: string | null`, `severity: string | null`, `kevListed: boolean`, `kevDueDate: string | null`, `kevRansomware: boolean`, `sourceCount: number`. `GET /api/items/:id/remediation` — the response gains the same eight fields at the top level (siblings of `remediation`/`asset`/`patchUrl`, same pattern Spec B already established for `patchUrl`).
- Consumes: nothing new — `cveId`/`cvssScore`/`severity`/`kevListed`/`kevDueDate`/`kevRansomware`/`sourceCount` come from the already-joined `cve_intel` row on both routes (Spec Accuracy Finding 2); `cvssVersion` comes from the already-joined `items` row (Spec Accuracy Finding 1).

- [ ] **Step 1: Write the failing tests**

Append to `server/api.test.js` (after the existing remediation tests, which end around line 1088 with `GET /api/items/:id/remediation returns remediation: null when no asset matches the item`):

```js
// --- Remediation triage redesign: Part 8's additive fields ---

test('GET /api/profiles/:id/remediation surfaces cvss/kev/source fields from cve_intel and cvssVersion from the item', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run(
      "UPDATE cve_intel SET cvss_score = 9.8, kev_due_date = '2026-08-17', kev_ransomware = true WHERE cve_id = 'CVE-2026-1'");
    await store.run("UPDATE items SET cvss_version = '3.1' WHERE id = $1", [hitId]);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/profiles/${created.body.id}/remediation`);
    assert.strictEqual(res.status, 200);
    const item = res.body[0].items.find((i) => i.itemId === hitId);
    assert.strictEqual(item.cveId, 'CVE-2026-1');
    assert.strictEqual(item.cvssScore, 9.8);
    assert.strictEqual(item.cvssVersion, '3.1');
    assert.strictEqual(item.severity, 'high'); // seedRelevanceFixture's own default
    assert.strictEqual(item.kevListed, true); // seedRelevanceFixture's own default
    assert.strictEqual(item.kevDueDate, '2026-08-17');
    assert.strictEqual(item.kevRansomware, true);
    assert.strictEqual(item.sourceCount, 1); // seedRelevanceFixture's own default
  } finally { await cleanup(); }
});

test('GET /api/profiles/:id/remediation defaults every additive field sanely when the item has no matching cve_intel row', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);
    // Tier was already assigned by the recompute above (which ran while cve_intel still existed);
    // deleting it now exercises the live LATERAL join finding nothing, independent of scoring.
    await store.run("DELETE FROM cve_intel WHERE cve_id = 'CVE-2026-1'");

    const res = await get(app, `/api/profiles/${created.body.id}/remediation`);
    const item = res.body[0].items.find((i) => i.itemId === hitId);
    assert.strictEqual(item.cveId, null);
    assert.strictEqual(item.cvssScore, null);
    assert.strictEqual(item.severity, null);
    assert.strictEqual(item.kevListed, false);
    assert.strictEqual(item.kevDueDate, null);
    assert.strictEqual(item.kevRansomware, false);
    assert.strictEqual(item.sourceCount, 0);
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation surfaces the same eight additive fields at the top level', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run(
      "UPDATE cve_intel SET cvss_score = 9.8, kev_due_date = '2026-08-17', kev_ransomware = true WHERE cve_id = 'CVE-2026-1'");
    await store.run("UPDATE items SET cvss_version = '3.1' WHERE id = $1", [hitId]);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/items/${hitId}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.cveId, 'CVE-2026-1');
    assert.strictEqual(res.body.cvssScore, 9.8);
    assert.strictEqual(res.body.cvssVersion, '3.1');
    assert.strictEqual(res.body.severity, 'high');
    assert.strictEqual(res.body.kevListed, true);
    assert.strictEqual(res.body.kevDueDate, '2026-08-17');
    assert.strictEqual(res.body.kevRansomware, true);
    assert.strictEqual(res.body.sourceCount, 1);
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation defaults every additive field sanely when there is no matching cve_intel row', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { missId } = await seedRelevanceFixture(store); // missId has no item_cves row at all
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    const res = await get(app, `/api/items/${missId}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.cveId, null);
    assert.strictEqual(res.body.cvssScore, null);
    assert.strictEqual(res.body.severity, null);
    assert.strictEqual(res.body.kevListed, false);
    assert.strictEqual(res.body.kevDueDate, null);
    assert.strictEqual(res.body.kevRansomware, false);
    assert.strictEqual(res.body.sourceCount, 0);
    // cvssVersion is items-sourced (Spec Accuracy Finding 1), not cve_intel-sourced, so it is
    // independently null here too: the news fixture item was seeded with no cvss_version at all.
    assert.strictEqual(res.body.cvssVersion, null);
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: FAIL — `item.cveId`/`res.body.cveId` etc. are all `undefined`, not the asserted values.

- [ ] **Step 3: Implement**

In `server/index.js`, in the `GET /api/profiles/:id/remediation` handler, extend the `SELECT` list. Find:

```js
    const rows = await store.all(`
      SELECT pa.vendor, pa.product, pa.exposure, pa.version, pa.version_state AS "versionState",
             i.id AS "itemId", i.title, ir.tier, ir.score, ir.consequence,
             ci.affected_versions AS "affectedVersions", ci.patch_url AS "patchUrl", ci.advisory_url AS "advisoryUrl",
             ip.steps
        FROM profile_assets pa
```

Replace with:

```js
    const rows = await store.all(`
      SELECT pa.vendor, pa.product, pa.exposure, pa.version, pa.version_state AS "versionState",
             i.id AS "itemId", i.title, i.cvss_version AS "cvssVersion", ir.tier, ir.score, ir.consequence,
             ci.affected_versions AS "affectedVersions", ci.patch_url AS "patchUrl", ci.advisory_url AS "advisoryUrl",
             ci.cve_id AS "cveId", ci.cvss_score AS "cvssScore", ci.severity,
             ci.kev_listed AS "kevListed", ci.kev_due_date AS "kevDueDate", ci.kev_ransomware AS "kevRansomware",
             ci.source_count AS "sourceCount",
             ip.steps
        FROM profile_assets pa
```

Then in the per-item push, find:

```js
      const rem = remediationFor(asset, r.affectedVersions || [], { patchUrl: r.patchUrl, advisoryUrl: r.advisoryUrl }, r.steps || []);
      const dueDate = (r.consequence && r.consequence.urgency && r.consequence.urgency.due) || null;
      groups.get(key).items.push({
        itemId: r.itemId, title: r.title, tier: r.tier, score: r.score, dueDate,
        patchUrl: r.patchUrl || null, ...rem,
      });
```

Replace with:

```js
      const rem = remediationFor(asset, r.affectedVersions || [], { patchUrl: r.patchUrl, advisoryUrl: r.advisoryUrl }, r.steps || []);
      const dueDate = (r.consequence && r.consequence.urgency && r.consequence.urgency.due) || null;
      groups.get(key).items.push({
        itemId: r.itemId, title: r.title, tier: r.tier, score: r.score, dueDate,
        patchUrl: r.patchUrl || null,
        // cveId/cvssScore/severity/kev*/sourceCount all come from the same LATERAL cve_intel
        // join patchUrl already reads (Spec Accuracy Finding 2) — zero new joins. cvssVersion
        // has no home in cve_intel (Spec Accuracy Finding 1) so it reads the item's own column
        // instead; it may not describe the same source cvssScore/severity were consolidated
        // from when this item isn't cve_intel's own tier-winning source for the CVE.
        cveId: r.cveId || null,
        cvssScore: r.cvssScore ?? null,
        cvssVersion: r.cvssVersion || null,
        severity: r.severity || null,
        kevListed: !!r.kevListed,
        kevDueDate: r.kevDueDate || null,
        kevRansomware: !!r.kevRansomware,
        sourceCount: r.sourceCount ?? 0,
        ...rem,
      });
```

In the `GET /api/items/:id/remediation` handler, find the `ci` query:

```js
    const ci = await store.get(
      `SELECT ci.affected_versions AS "affectedVersions", ci.patch_url AS "patchUrl", ci.advisory_url AS "advisoryUrl"
         FROM item_cves ic JOIN cve_intel ci ON ci.cve_id = ic.cve_id WHERE ic.item_id = $1
        ORDER BY ci.kev_listed DESC, ci.cvss_score DESC NULLS LAST LIMIT 1`, [id]);
```

Replace with:

```js
    const ci = await store.get(
      `SELECT ci.cve_id AS "cveId", ci.affected_versions AS "affectedVersions",
              ci.patch_url AS "patchUrl", ci.advisory_url AS "advisoryUrl",
              ci.cvss_score AS "cvssScore", ci.severity,
              ci.kev_listed AS "kevListed", ci.kev_due_date AS "kevDueDate", ci.kev_ransomware AS "kevRansomware",
              ci.source_count AS "sourceCount"
         FROM item_cves ic JOIN cve_intel ci ON ci.cve_id = ic.cve_id WHERE ic.item_id = $1
        ORDER BY ci.kev_listed DESC, ci.cvss_score DESC NULLS LAST LIMIT 1`, [id]);
```

Then find the response object:

```js
    res.json({
      item,
      relevance: rel ? { tier: rel.tier, matches: rel.matches, consequence: rel.consequence } : null,
      playbook: pb ? { steps: pb.steps, done: pbDone } : null,
      remediation,
      asset: asset ? { vendor: asset.vendor, product: asset.product, exposure: asset.exposure } : null,
      patchUrl: (ci && ci.patchUrl) || null,
    });
```

Replace with:

```js
    res.json({
      item,
      relevance: rel ? { tier: rel.tier, matches: rel.matches, consequence: rel.consequence } : null,
      playbook: pb ? { steps: pb.steps, done: pbDone } : null,
      remediation,
      asset: asset ? { vendor: asset.vendor, product: asset.product, exposure: asset.exposure } : null,
      patchUrl: (ci && ci.patchUrl) || null,
      // Same eight additive fields as the queue route, same reasoning (Spec Accuracy Findings
      // 1-2): six from the cve_intel row already fetched above for remediationFor's own
      // cveIntel argument, cvssVersion from the item row's own column instead.
      cveId: (ci && ci.cveId) || null,
      cvssScore: (ci && ci.cvssScore) ?? null,
      cvssVersion: item.cvss_version || null,
      severity: (ci && ci.severity) || null,
      kevListed: !!(ci && ci.kevListed),
      kevDueDate: (ci && ci.kevDueDate) || null,
      kevRansomware: !!(ci && ci.kevRansomware),
      sourceCount: (ci && ci.sourceCount) ?? 0,
    });
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: PASS, all tests including the four new ones.

Run the full backend suite and record the actual numbers:
Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures (baseline was 663 tests / 661 pass / 2 skipped; this task adds 4 tests, so expect 667 tests / 665 pass / 2 skipped).

- [ ] **Step 5: Restart the API and sanity-check by hand**

The dev server races the scheduler's own per-minute sync if left running during a manual sync, but a plain restart to pick up route changes is safe. Stop any running `node server/index.js`, then:

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node server/index.js &`
Then: `curl -s http://localhost:4173/api/profiles/1/remediation | head -c 2000` (adjust the profile id to one that actually exists in the dev DB) and confirm `cveId`/`cvssScore`/`severity`/`kevListed`/`kevDueDate`/`kevRansomware`/`sourceCount`/`cvssVersion` all appear on at least one item.

- [ ] **Step 6: Commit**

```bash
git add server/index.js server/api.test.js
git commit -m "feat(remediation): surface CVSS/KEV/source fields on both remediation routes"
```

---

## Task 2: Frontend types — `models.ts` field additions

**Files:**
- Modify: `frontend-v4/src/app/core/models.ts`

**Interfaces:**
- Consumes: Task 1's response shape.
- Produces: `RemediationQueueItem` and `RemediationDetail` both gain `cveId: string | null`, `cvssScore: number | null`, `cvssVersion: string | null`, `severity: string | null`, `kevListed: boolean`, `kevDueDate: string | null`, `kevRansomware: boolean`, `sourceCount: number`. Consumed by every task from Task 3 onward.

No test file — a pure type addition with no branching logic, same posture as Spec B's own Task 2 (`docs/superpowers/plans/2026-08-04-remediation-experience.md`, "No test file... every later task that actually exercises these types" is the verification). Verified here by `tsc` plus every later task's own tests, which construct `RemediationQueueItem`/`RemediationDetail` literals and would fail to compile against a wrong shape.

- [ ] **Step 1: Add the fields**

In `frontend-v4/src/app/core/models.ts`, find the `RemediationQueueItem` interface:

```ts
// One row in GET /api/profiles/:id/remediation's per-asset items array.
export interface RemediationQueueItem extends RemediationSummary {
  itemId: number;
  title: string;
  tier: 'act_now' | 'watch';
  score: number;
  // CISA KEV due date (YYYY-MM-DD), read off item_relevance.consequence.urgency.due — null for
  // anything not KEV-listed, or not yet (re)scored since the due date was recorded.
  dueDate: string | null;
  // The CVE's vendor patch URL, independent of which fix.kind was chosen (Spec Accuracy
  // Finding 3) — never inside `fix` itself. Only rendered by the UI when fix.kind === 'version'
  // (the spec's "patch link beneath the upgrade instruction, if one exists").
  patchUrl: string | null;
}
```

Replace with:

```ts
// One row in GET /api/profiles/:id/remediation's per-asset items array.
export interface RemediationQueueItem extends RemediationSummary {
  itemId: number;
  title: string;
  tier: 'act_now' | 'watch';
  score: number;
  // CISA KEV due date (YYYY-MM-DD), read off item_relevance.consequence.urgency.due — null for
  // anything not KEV-listed, or not yet (re)scored since the due date was recorded.
  dueDate: string | null;
  // The CVE's vendor patch URL, independent of which fix.kind was chosen (Spec Accuracy
  // Finding 3) — never inside `fix` itself. Only rendered by the UI when fix.kind === 'version'
  // (the spec's "patch link beneath the upgrade instruction, if one exists").
  patchUrl: string | null;
  // The following eight fields are Part 8 of the triage redesign — six read straight
  // off cve_intel (never re-derived client-side, see server/cvss.js's severityFromScore), one
  // (cveId) free from the same LATERAL join, one (cvssVersion) from the item's own column
  // because cve_intel carries no version — see that plan's Spec Accuracy Findings 1-2.
  cveId: string | null;
  cvssScore: number | null;
  cvssVersion: string | null;
  severity: string | null;
  kevListed: boolean;
  kevDueDate: string | null;
  kevRansomware: boolean;
  sourceCount: number;
}
```

Find the `RemediationDetail` interface:

```ts
export interface RemediationDetail {
  item: RemediationItemRow;
  relevance: { tier: string; matches: RelevanceMatch[]; consequence: Consequence | null } | null;
  playbook: Playbook | null;
  remediation: RemediationSummary | null;
  // The profile_assets row remediation was computed against — null when none matched this
  // item's CPEs. Needed to PATCH a version back (server/index.js's route carries no
  // vendor/product on `remediation` itself; entry.vendor/product only exist when
  // affected_versions happened to match too).
  asset: { vendor: string; product: string; exposure: Exposure } | null;
  // The CVE's vendor patch URL — same field and same reasoning as RemediationQueueItem.patchUrl
  // (Spec Accuracy Finding 3): a sibling of `remediation`, shown by the UI only when
  // remediation.fix.kind === 'version'.
  patchUrl: string | null;
}
```

Replace with:

```ts
export interface RemediationDetail {
  item: RemediationItemRow;
  relevance: { tier: string; matches: RelevanceMatch[]; consequence: Consequence | null } | null;
  playbook: Playbook | null;
  remediation: RemediationSummary | null;
  // The profile_assets row remediation was computed against — null when none matched this
  // item's CPEs. Needed to PATCH a version back (server/index.js's route carries no
  // vendor/product on `remediation` itself; entry.vendor/product only exist when
  // affected_versions happened to match too).
  asset: { vendor: string; product: string; exposure: Exposure } | null;
  // The CVE's vendor patch URL — same field and same reasoning as RemediationQueueItem.patchUrl
  // (Spec Accuracy Finding 3): a sibling of `remediation`, shown by the UI only when
  // remediation.fix.kind === 'version'.
  patchUrl: string | null;
  // Same eight fields and same reasoning as RemediationQueueItem (triage redesign, Part 8) —
  // powers the guided page's KEV block.
  cveId: string | null;
  cvssScore: number | null;
  cvssVersion: string | null;
  severity: string | null;
  kevListed: boolean;
  kevDueDate: string | null;
  kevRansomware: boolean;
  sourceCount: number;
}
```

- [ ] **Step 2: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors. (The two existing `item()` fixture builders in `remediation.spec.ts` construct `RemediationQueueItem` literals without these eight fields — that will surface here as a real compile error until Task 3 updates the fixture, which is expected; if `tsc` errors only in `remediation.spec.ts` at this point, that is the correct, temporary state — proceed to Task 3, which fixes it as its own first step.)

- [ ] **Step 3: Commit**

```bash
git add frontend-v4/src/app/core/models.ts
git commit -m "feat(remediation): add CVSS/KEV/source fields to RemediationQueueItem and RemediationDetail"
```

---

## Task 3: `core/remediation.ts` — `groupActions` (Part 1: threats collapse into fix-based action rows)

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (update the shared `item()` fixture, append tests)

**Interfaces:**
- Consumes: `RemediationQueueItem` (Task 2).
- Produces: `RemediationAction` interface, `groupActions(items, now?)`. Consumed by Task 4 (`sortActions`), Task 5 (`splitActionsByStatus`), Task 10 (`actionProvenance`), Task 11 (`buildTicketText`), Task 12 (`RemediationQueueComponent`), Task 15 (`actionCountFor`).

- [ ] **Step 1: Update the shared test fixture, then write the failing tests**

In `frontend-v4/src/app/core/remediation.spec.ts`, find the shared `item()` builder (there are two near-duplicate copies in the file today — one near the top from Spec B's original commit, update **both** if `git grep -n "const item = "` shows two; as of this plan there is one, at the top of the file):

```ts
const item = (over: Partial<RemediationQueueItem> = {}): RemediationQueueItem => ({
  itemId: 1, title: 'T', tier: 'act_now', score: 1,
  status: 'affected', installed: null, versionState: 'unset', entry: null,
  fix: { kind: 'none' }, mitigations: [], dueDate: null, patchUrl: null,
  ...over,
});
```

Replace with:

```ts
const item = (over: Partial<RemediationQueueItem> = {}): RemediationQueueItem => ({
  itemId: 1, title: 'T', tier: 'act_now', score: 1,
  status: 'affected', installed: null, versionState: 'unset', entry: null,
  fix: { kind: 'none' }, mitigations: [], dueDate: null, patchUrl: null,
  cveId: null, cvssScore: null, cvssVersion: null, severity: null,
  kevListed: false, kevDueDate: null, kevRansomware: false, sourceCount: 0,
  ...over,
});
```

Then append to the same file:

```ts
import { groupActions } from './remediation';

describe('groupActions', () => {
  it('collapses version-kind items sharing the same fix.value into one action', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'version', value: '14.8.8' } }),
      item({ itemId: 2, fix: { kind: 'version', value: '14.8.8' } }),
      item({ itemId: 3, fix: { kind: 'version', value: '26.6' } }),
    ];
    const actions = groupActions(items);
    expect(actions.length).toBe(2);
    expect(actions.find((a) => a.fix.kind === 'version' && a.fix.value === '14.8.8')!.count).toBe(2);
  });
  it('collapses every patch-kind item into a single action regardless of differing URLs', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'patch', value: 'https://x/a' } }),
      item({ itemId: 2, fix: { kind: 'patch', value: 'https://x/b' } }),
    ];
    expect(groupActions(items).length).toBe(1);
  });
  it('collapses every advisory-kind item into a single action', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'advisory', value: 'https://x/a' } }),
      item({ itemId: 2, fix: { kind: 'advisory', value: 'https://x/b' } }),
    ];
    expect(groupActions(items).length).toBe(1);
  });
  it('collapses every none-kind item into a single action', () => {
    const items = [item({ itemId: 1, fix: { kind: 'none' } }), item({ itemId: 2, fix: { kind: 'none' } })];
    expect(groupActions(items).length).toBe(1);
  });
  it('never counts one threat in two actions', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'version', value: '14.8.8' } }),
      item({ itemId: 2, fix: { kind: 'patch', value: 'https://x/a' } }),
      item({ itemId: 3, fix: { kind: 'none' } }),
    ];
    const actions = groupActions(items);
    const total = actions.reduce((n, a) => n + a.count, 0);
    expect(total).toBe(items.length);
  });
  it('computes the worst CVSS score and its severity within the bundle', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'version', value: '14.8.8' }, cvssScore: 9.8, severity: 'critical' }),
      item({ itemId: 2, fix: { kind: 'version', value: '14.8.8' }, cvssScore: 7.5, severity: 'high' }),
    ];
    const a = groupActions(items)[0];
    expect(a.worstScore).toBe(9.8);
    expect(a.worstSeverity).toBe('critical');
  });
  it('carries the worst item\'s own cvssVersion alongside the worst score', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'none' }, cvssScore: 9.8, cvssVersion: '3.1' }),
      item({ itemId: 2, fix: { kind: 'none' }, cvssScore: 7.5, cvssVersion: '2.0' }),
    ];
    expect(groupActions(items)[0].worstVersion).toBe('3.1');
  });
  it('tallies the severity distribution across the bundle, unrated items counting as unknown', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'version', value: '14.8.8' }, severity: 'critical' }),
      item({ itemId: 2, fix: { kind: 'version', value: '14.8.8' }, severity: 'critical' }),
      item({ itemId: 3, fix: { kind: 'version', value: '14.8.8' }, severity: 'high' }),
      item({ itemId: 4, fix: { kind: 'version', value: '14.8.8' }, severity: null }),
    ];
    expect(groupActions(items)[0].severityCounts).toEqual({ critical: 2, high: 1, medium: 0, low: 0, none: 0, unknown: 1 });
  });
  it('reports kev: null when nothing in the bundle is KEV-listed', () => {
    expect(groupActions([item({ itemId: 1, fix: { kind: 'none' }, kevListed: false })])[0].kev).toBeNull();
  });
  it('aggregates KEV count, ransomware flag and past-due count across the bundle', () => {
    const now = new Date('2026-08-04T00:00:00Z');
    const items = [
      item({ itemId: 1, fix: { kind: 'none' }, kevListed: true, kevRansomware: true, kevDueDate: '2024-12-03' }),
      item({ itemId: 2, fix: { kind: 'none' }, kevListed: true, kevRansomware: false, kevDueDate: '2027-01-01' }),
      item({ itemId: 3, fix: { kind: 'none' }, kevListed: false }),
    ];
    expect(groupActions(items, now)[0].kev).toEqual({ count: 2, ransomware: true, pastDueCount: 1 });
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `groupActions` not exported, plus the pre-existing `tsc` error from Task 2's Step 2 about the fixture now resolved.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
// ---- Part 1: threats collapse into fix-based action rows ----

export type SeverityBand = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown';

export interface RemediationAction {
  key: string;
  fix: RemediationFix;
  items: RemediationQueueItem[];
  count: number;
  worstScore: number | null;
  worstSeverity: string | null;
  // The worst-scoring item's OWN cvssVersion — for the numeral only, not for picking the
  // severity colour (that already comes from `worstSeverity`, itself server-derived). See the
  // triage redesign plan's Spec Accuracy Finding 1: cve_intel carries no version, so this is the
  // best available pairing, not a guaranteed-consistent one.
  worstVersion: string | null;
  severityCounts: Record<SeverityBand, number>;
  kev: { count: number; ransomware: boolean; pastDueCount: number } | null;
}

// Grouping key is the fix itself (Part 1): kind:'version' groups on fix.value (a distinct
// upgrade target is a distinct action), but patch/advisory/none each collapse to ONE group per
// asset regardless of the specific URL — two patch links are not two decisions, they're one
// ("go read the vendor's links"), and splitting patch/advisory by URL would reproduce the wall
// this whole redesign exists to remove.
function actionKey(fix: RemediationFix): string {
  return fix.kind === 'version' ? `version:${fix.value}` : fix.kind;
}

const EMPTY_SEVERITY_COUNTS: Record<SeverityBand, number> = {
  critical: 0, high: 0, medium: 0, low: 0, none: 0, unknown: 0,
};

function isSeverityBand(value: string | null): value is SeverityBand {
  return value != null && value in EMPTY_SEVERITY_COUNTS;
}

export function groupActions(items: RemediationQueueItem[], now: Date = new Date()): RemediationAction[] {
  const byKey = new Map<string, RemediationQueueItem[]>();
  for (const item of items) {
    const key = actionKey(item.fix);
    const bucket = byKey.get(key);
    if (bucket) bucket.push(item); else byKey.set(key, [item]);
  }

  const actions: RemediationAction[] = [];
  for (const [key, bucketItems] of byKey) {
    const severityCounts = { ...EMPTY_SEVERITY_COUNTS };
    let worst: RemediationQueueItem | null = null;
    let kevCount = 0;
    let kevRansomware = false;
    let kevPastDue = 0;

    for (const item of bucketItems) {
      const band = isSeverityBand(item.severity) ? item.severity : 'unknown';
      severityCounts[band] += 1;

      if (worst === null || (item.cvssScore ?? -1) > (worst.cvssScore ?? -1)) worst = item;

      if (item.kevListed) {
        kevCount += 1;
        if (item.kevRansomware) kevRansomware = true;
        if (isPastDue(item.kevDueDate, now)) kevPastDue += 1;
      }
    }

    actions.push({
      key,
      fix: bucketItems[0].fix,
      items: bucketItems,
      count: bucketItems.length,
      worstScore: worst?.cvssScore ?? null,
      worstSeverity: worst?.severity ?? null,
      worstVersion: worst?.cvssVersion ?? null,
      severityCounts,
      kev: kevCount > 0 ? { count: kevCount, ransomware: kevRansomware, pastDueCount: kevPastDue } : null,
    });
  }
  return actions;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests.

Run the full frontend suite:
Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run`
Expected: PASS, 0 failures (baseline 176 across 12 files; this task adds 10, so expect 186).

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): group queue items into fix-based action rows"
```

---

## Task 4: `core/remediation.ts` — `sortActions` (Part 3: risk ordering with KEV precedence, Part 4's reach mode)

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (append)

**Interfaces:**
- Consumes: `RemediationAction` (Task 3).
- Produces: `RiskReachMode`, `sortActions(actions, mode?)`. Consumed by Task 12 (`RemediationQueueComponent`).

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import { sortActions } from './remediation';
import type { RemediationAction } from './remediation';

describe('sortActions', () => {
  const action = (over: Partial<RemediationAction> = {}): RemediationAction => ({
    key: 'k', fix: { kind: 'none' }, items: [], count: 1,
    worstScore: null, worstSeverity: null, worstVersion: null,
    severityCounts: { critical: 0, high: 0, medium: 0, low: 0, none: 0, unknown: 0 },
    kev: null,
    ...over,
  });

  it('the measured case: a 5-threat CVSS 10.0 action outranks a 111-threat CVSS 9.8 action under risk', () => {
    const noFix = action({ key: 'none', count: 5, worstScore: 10.0 });
    const upgrade = action({ key: 'version:14.8.8', count: 111, worstScore: 9.8 });
    expect(sortActions([upgrade, noFix], 'risk')).toEqual([noFix, upgrade]);
  });
  it('risk mode breaks a score tie on count', () => {
    const a = action({ key: 'a', count: 3, worstScore: 9.0 });
    const b = action({ key: 'b', count: 9, worstScore: 9.0 });
    expect(sortActions([a, b], 'risk')).toEqual([b, a]);
  });
  it('reach mode sorts by count first, worst score breaking ties', () => {
    const small = action({ key: 'small', count: 5, worstScore: 10.0 });
    const big = action({ key: 'big', count: 111, worstScore: 9.8 });
    expect(sortActions([small, big], 'reach')).toEqual([big, small]);
  });
  it('reach mode breaks a count tie on worst score', () => {
    const lower = action({ key: 'lower', count: 4, worstScore: 6.0 });
    const higher = action({ key: 'higher', count: 4, worstScore: 8.0 });
    expect(sortActions([lower, higher], 'reach')).toEqual([higher, lower]);
  });
  it('any KEV action outranks every non-KEV action regardless of score, under risk', () => {
    const critical = action({ key: 'critical', worstScore: 10.0, kev: null });
    const kevLow = action({ key: 'kev', worstScore: 4.0, kev: { count: 1, ransomware: false, pastDueCount: 0 } });
    expect(sortActions([critical, kevLow], 'risk')).toEqual([kevLow, critical]);
  });
  it('any KEV action outranks every non-KEV action regardless of score, under reach too', () => {
    const bigNonKev = action({ key: 'big', count: 100, kev: null });
    const smallKev = action({ key: 'kev', count: 1, kev: { count: 1, ransomware: false, pastDueCount: 0 } });
    expect(sortActions([bigNonKev, smallKev], 'reach')).toEqual([smallKev, bigNonKev]);
  });
  it('among several KEV actions, still orders by the active sort mode', () => {
    const kevA = action({ key: 'a', worstScore: 9.0, kev: { count: 1, ransomware: false, pastDueCount: 0 } });
    const kevB = action({ key: 'b', worstScore: 9.9, kev: { count: 1, ransomware: false, pastDueCount: 0 } });
    expect(sortActions([kevA, kevB], 'risk')).toEqual([kevB, kevA]);
  });
  it('defaults to risk mode when none is given', () => {
    const noFix = action({ key: 'none', count: 5, worstScore: 10.0 });
    const upgrade = action({ key: 'version:14.8.8', count: 111, worstScore: 9.8 });
    expect(sortActions([upgrade, noFix])).toEqual([noFix, upgrade]);
  });
  it('does not mutate the input array', () => {
    const list = [action({ key: 'a', worstScore: 1 }), action({ key: 'b', worstScore: 9 })];
    const copy = [...list];
    sortActions(list, 'risk');
    expect(list).toEqual(copy);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `sortActions` not exported.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
// ---- Part 3 (risk ordering) + Part 4 (the risk <-> reach toggle) ----

export type RiskReachMode = 'risk' | 'reach';

// Part 3's default: worst CVSS in the bundle, descending, count breaking ties. Deliberately
// buries nothing behind volume — "No fix published" (5 threats, one CVSS 10.0) outranks "upgrade
// to 14.8.8" (111 threats, worst 9.8): the unfixable 10.0 is what a reader must not miss, and a
// count-ordered list is exactly what would bury it.
function riskCompare(a: RemediationAction, b: RemediationAction): number {
  const as = a.worstScore ?? -1;
  const bs = b.worstScore ?? -1;
  if (as !== bs) return bs - as;
  return b.count - a.count;
}

// Part 4's toggle: how many threats one action closes, descending, worst score breaking ties.
function reachCompare(a: RemediationAction, b: RemediationAction): number {
  if (a.count !== b.count) return b.count - a.count;
  return (b.worstScore ?? -1) - (a.worstScore ?? -1);
}

// KEV sorts above every non-KEV action regardless of score (Part 3) — "regardless of score"
// reads as unconditional, so this precedence holds in both risk and reach mode: an actively
// exploited action is the thing a reader must not miss no matter which axis they're currently
// sorting by. Among several KEV actions, the active mode still decides their relative order.
export function sortActions(actions: RemediationAction[], mode: RiskReachMode = 'risk'): RemediationAction[] {
  const compare = mode === 'reach' ? reachCompare : riskCompare;
  return [...actions].sort((a, b) => {
    const aKev = a.kev ? 1 : 0;
    const bKev = b.kev ? 1 : 0;
    if (aKev !== bKev) return bKev - aKev;
    return compare(a, b);
  });
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): sort actions by risk (default) or reach, KEV always first"
```

---

## Task 5: `core/remediation.ts` — `actionStatus` and `splitActionsByStatus` (Part 2: the three-way split)

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (append)

**Interfaces:**
- Consumes: `RemediationAction` (Task 3), `groupActions` (Task 3).
- Produces: `ActionStatus`, `actionStatus(action)`, `ActionSections`, `splitActionsByStatus(actions)`, `NOT_COVERED_SECTION_CAVEAT`. Consumed by Task 12 (`RemediationQueueComponent`).

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import { actionStatus, splitActionsByStatus, NOT_COVERED_SECTION_CAVEAT } from './remediation';

describe('actionStatus', () => {
  it('is affected when any item in the bundle is still affected', () => {
    const a = groupActions([
      item({ itemId: 1, fix: { kind: 'version', value: '1.0' }, status: 'not_covered' }),
      item({ itemId: 2, fix: { kind: 'version', value: '1.0' }, status: 'affected' }),
    ])[0];
    expect(actionStatus(a)).toBe('affected');
  });
  it('is unknown when nothing is affected but something is unknown', () => {
    const a = groupActions([
      item({ itemId: 1, fix: { kind: 'version', value: '1.0' }, status: 'not_covered' }),
      item({ itemId: 2, fix: { kind: 'version', value: '1.0' }, status: 'unknown' }),
    ])[0];
    expect(actionStatus(a)).toBe('unknown');
  });
  it('is not_covered only when every item in the bundle already reads not_covered', () => {
    const a = groupActions([
      item({ itemId: 1, fix: { kind: 'version', value: '1.0' }, status: 'not_covered' }),
      item({ itemId: 2, fix: { kind: 'version', value: '1.0' }, status: 'not_covered' }),
    ])[0];
    expect(actionStatus(a)).toBe('not_covered');
  });
});

describe('splitActionsByStatus', () => {
  it('sorts each action into exactly one of the three sections', () => {
    const affectedAction = groupActions([item({ itemId: 1, fix: { kind: 'version', value: '1.0' }, status: 'affected' })])[0];
    const unknownAction = groupActions([item({ itemId: 2, fix: { kind: 'patch', value: 'https://x/a' }, status: 'unknown' })])[0];
    const notCoveredAction = groupActions([item({ itemId: 3, fix: { kind: 'none' }, status: 'not_covered' })])[0];
    const sections = splitActionsByStatus([affectedAction, unknownAction, notCoveredAction]);
    expect(sections.affected).toEqual([affectedAction]);
    expect(sections.unknown).toEqual([unknownAction]);
    expect(sections.notCovered).toEqual([notCoveredAction]);
  });
  it('an action built from an item with no version bound never reaches the not_covered section', () => {
    // affectedStatus (server/version_compare.js) abstains to 'unknown' the moment there is no
    // entry to compare against — this is the queue-side consequence of that abstention: a
    // no-version-bound action must land in the middle section, never the "resolved" one.
    const noBoundAction = groupActions([item({ itemId: 1, fix: { kind: 'advisory', value: 'https://x/a' }, entry: null, status: 'unknown' })])[0];
    const sections = splitActionsByStatus([noBoundAction]);
    expect(sections.notCovered).toEqual([]);
    expect(sections.unknown).toEqual([noBoundAction]);
  });
  it('is all-empty for an empty action list', () => {
    expect(splitActionsByStatus([])).toEqual({ affected: [], unknown: [], notCovered: [] });
  });
});

describe('NOT_COVERED_SECTION_CAVEAT', () => {
  it('never contains the word "safe"', () => {
    expect(NOT_COVERED_SECTION_CAVEAT.toLowerCase()).not.toContain('safe');
  });
  it('matches Spec B\'s verbatim not_covered detail wording', () => {
    expect(NOT_COVERED_SECTION_CAVEAT).toBe(
      'Not a clean bill of health — confirm against the vendor advisory before treating any of these as closed.');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `actionStatus`/`splitActionsByStatus`/`NOT_COVERED_SECTION_CAVEAT` not exported.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
// ---- Part 2: three sections once a version is recorded, not two ----

export type ActionStatus = 'affected' | 'unknown' | 'not_covered';

// An action can bundle several CVEs sharing one fix (Part 1) whose affectedStatus can genuinely
// differ — two ranges ending at the same fixed version don't have to share the same starting
// bound. Conservative, worst-case-wins precedence: 'affected' the moment any item still needs
// the fix, 'not_covered' only once every item in the bundle already reads that way. The same
// posture server/version_compare.js already applies everywhere: never launder a partial
// abstention into a resolved claim.
export function actionStatus(action: RemediationAction): ActionStatus {
  if (action.items.some((i) => i.status === 'affected')) return 'affected';
  if (action.items.some((i) => i.status === 'unknown')) return 'unknown';
  return 'not_covered';
}

export interface ActionSections {
  affected: RemediationAction[];
  unknown: RemediationAction[];
  notCovered: RemediationAction[];
}

// Callers only invoke this once a version is known (group.versionState === 'known') — before
// that there is one bucket and no section chrome at all, per Part 2's own rule; that gate lives
// in the component, not here, so this function's contract stays "split what you're given."
export function splitActionsByStatus(actions: RemediationAction[]): ActionSections {
  const sections: ActionSections = { affected: [], unknown: [], notCovered: [] };
  for (const a of actions) {
    const status = actionStatus(a);
    if (status === 'affected') sections.affected.push(a);
    else if (status === 'unknown') sections.unknown.push(a);
    else sections.notCovered.push(a);
  }
  return sections;
}

// Verbatim from Spec B's affectedWording(), restated once per section instead of once per row
// (Part 2) — the system never tells anyone they are safe.
export const NOT_COVERED_SECTION_CAVEAT =
  'Not a clean bill of health — confirm against the vendor advisory before treating any of these as closed.';
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): split actions into affected/unknown/not_covered sections"
```

---

## Task 6: `core/remediation.ts` — `filterQueueItems` (Part 4: the filter field)

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (append)

**Interfaces:**
- Consumes: `RemediationQueueItem` (Task 2).
- Produces: `filterQueueItems(items, query)`. Consumed by Task 12/13 (`RemediationQueueComponent`).

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import { filterQueueItems } from './remediation';

describe('filterQueueItems', () => {
  it('matches a CVE id substring, case-insensitively', () => {
    const items = [item({ itemId: 1, cveId: 'CVE-2024-49039' }), item({ itemId: 2, cveId: 'CVE-2023-1' })];
    expect(filterQueueItems(items, '49039').map((i) => i.itemId)).toEqual([1]);
    expect(filterQueueItems(items, 'cve-2024').map((i) => i.itemId)).toEqual([1]);
  });
  it('matches the installed version', () => {
    const items = [item({ itemId: 1, installed: '14.8.5' }), item({ itemId: 2, installed: '26.0' })];
    expect(filterQueueItems(items, '14.8').map((i) => i.itemId)).toEqual([1]);
  });
  it('matches a version-kind fix target', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'version', value: '14.8.8' } }),
      item({ itemId: 2, fix: { kind: 'none' } }),
    ];
    expect(filterQueueItems(items, '14.8.8').map((i) => i.itemId)).toEqual([1]);
  });
  it('matches the matched range text', () => {
    const items = [item({
      itemId: 1,
      entry: {
        vendor: 'apple', product: 'macos', text: 'before 14.8.8',
        startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: '14.8.8', pinned: null,
      },
    })];
    expect(filterQueueItems(items, 'before').map((i) => i.itemId)).toEqual([1]);
  });
  it('returns everything for an empty or whitespace-only query', () => {
    const items = [item({ itemId: 1 }), item({ itemId: 2 })];
    expect(filterQueueItems(items, '   ')).toEqual(items);
  });
  it('returns nothing when the query matches nothing', () => {
    expect(filterQueueItems([item({ itemId: 1, cveId: 'CVE-2024-1' })], 'zzz')).toEqual([]);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `filterQueueItems` not exported.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
// ---- Part 4: the filter field ----

function includesQuery(value: string | null | undefined, query: string): boolean {
  return typeof value === 'string' && value.toLowerCase().includes(query);
}

// Matches a CVE id or a version-shaped substring (Part 4's own words) — checked against every
// version-ish value already on the item (what the reader runs, the fix target, and the matched
// range's own text) so a query like "14.8" finds an item whether it matches what's installed or
// what the range says, not just one of the two.
export function filterQueueItems(items: RemediationQueueItem[], query: string): RemediationQueueItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((item) => (
    includesQuery(item.cveId, q)
    || includesQuery(item.installed, q)
    || includesQuery(item.fix.kind === 'version' ? item.fix.value : null, q)
    || includesQuery(item.entry?.text ?? null, q)
  ));
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): filter queue items by CVE id or version substring"
```

---

## Task 7: `core/remediation.ts` — `reachDiagram` rewrite for Part 7 (`AC` annotation, `S:C` fourth node, per-metric `C`/`I`/`A`)

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (replace `outcomeNode` and `reachDiagram`, add new helpers)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (replace one outdated test, add new ones)

**Interfaces:**
- Produces: `ReachDiagram.nodes` widens from a fixed 3-tuple to `DiagramNode[]` (3, or 4 when `S:C`); `ReachDiagram` gains `acAnnotation: DiagramAnnotation | null`; `DiagramNode['id']` widens to include `'scope'`; `reachDiagram(metrics)` behavior changes (see below). Consumed by Task 8 (`diagramSvgWidth`/`diagramEdgeLines`), Task 9 (`ReachDiagramComponent`), and unchanged by `RemediationGuidedComponent` (still calls `reachDiagram(this.metrics())` the same way).
- Behavior changes from Spec B's version: (1) an `:L`-valued `C`/`I`/`A` metric now renders as `"partly <verb>"` in the outcome node instead of vanishing — only a metric truly absent (`N` or unset) is an absent slot; (2) `AC` now produces `acAnnotation`, describing whether the exploit is reliable (`AC:L`) or needs conditions to line up (`AC:H`); (3) `S:C` appends a fourth `scope` node (`"Reaches beyond this component"`) with a third edge `outcome -> scope`.

- [ ] **Step 1: Update the outdated test, then write the new failing tests**

In `frontend-v4/src/app/core/remediation.spec.ts`, inside the `describe('reachDiagram', ...)` block, find this test (now false under Part 7's rule that `:L` renders instead of vanishing):

```ts
  it('an L-valued metric never reaches the outcome node — only H does', () => {
    const d = reachDiagram({ C: 'L', I: 'L', A: 'L' });
    expect(d.nodes[2].title).toBe('No full-control outcome');
  });
```

Replace with:

```ts
  it('an L-valued metric now renders as "partly <verb>" — it no longer vanishes (Part 7)', () => {
    const d = reachDiagram({ C: 'L', I: 'L', A: 'L' });
    expect(d.nodes[2].title).toBe('partly read, partly change and partly shut down');
    expect(d.nodes[2].from).toBe('C:L/I:L/A:L');
  });
  it('mixes H and L verbs in one outcome — H plain, L "partly" (Part 7)', () => {
    const d = reachDiagram({ C: 'H', I: 'L' });
    expect(d.nodes[2].title).toBe('read and partly change');
    expect(d.nodes[2].from).toBe('C:H/I:L');
  });
  it('a metric at N is still an absent slot, not a struck-through verb (Part 7)', () => {
    const d = reachDiagram({ C: 'H', I: 'N', A: 'N' });
    expect(d.nodes[2].title).toBe('read');
    expect(d.nodes[2].from).toBe('C:H');
  });
```

Also find the existing edges test (now incomplete — it only covers the no-scope-change case):

```ts
  it('always returns exactly two edges, origin->gate and gate->outcome', () => {
    const d = reachDiagram({ AV: 'N', PR: 'N' });
    expect(d.edges).toEqual([{ from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }]);
  });
```

Replace with:

```ts
  it('returns exactly two edges when there is no scope change', () => {
    const d = reachDiagram({ AV: 'N', PR: 'N' });
    expect(d.edges).toEqual([{ from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }]);
  });
```

Then append (still within reach of the `reachDiagram` import, already present in the file):

```ts
describe('reachDiagram — AC annotation (Part 7)', () => {
  it('AC:L describes a reliable exploit', () => {
    expect(reachDiagram({ AC: 'L' }).acAnnotation).toEqual({ text: 'works whenever it is tried', from: 'AC:L' });
  });
  it('AC:H describes an opportunistic one', () => {
    expect(reachDiagram({ AC: 'H' }).acAnnotation).toEqual({ text: 'needs conditions to line up', from: 'AC:H' });
  });
  it('an absent AC produces no annotation at all, not a fabricated one', () => {
    expect(reachDiagram({}).acAnnotation).toBeNull();
  });
});

describe('reachDiagram — S:C scope change (Part 7)', () => {
  it('S:C adds a fourth node', () => {
    const d = reachDiagram({ S: 'C' });
    expect(d.nodes.length).toBe(4);
    expect(d.nodes[3].id).toBe('scope');
    expect(d.nodes[3].from).toBe('S:C');
    expect(d.nodes[3].title).toBe('Reaches beyond this component');
  });
  it('S:U produces only the original three nodes', () => {
    expect(reachDiagram({ S: 'U' }).nodes.length).toBe(3);
  });
  it('an absent S produces only the original three nodes', () => {
    expect(reachDiagram({}).nodes.length).toBe(3);
  });
  it('adds a third edge, outcome->scope, only when the scope node is present', () => {
    const withScope = reachDiagram({ S: 'C' });
    expect(withScope.edges).toEqual([
      { from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }, { from: 'outcome', to: 'scope' },
    ]);
    const withoutScope = reachDiagram({ S: 'U' });
    expect(withoutScope.edges).toEqual([{ from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }]);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — the replaced test now expects `'partly read, partly change and partly shut down'` but the current implementation still returns `'No full-control outcome'`; `acAnnotation` is `undefined`; `nodes.length` never exceeds 3.

- [ ] **Step 3: Implement**

In `frontend-v4/src/app/core/remediation.ts`, find the `DiagramNode` interface:

```ts
export interface DiagramNode {
  id: 'origin' | 'gate' | 'outcome';
  title: string;
  detail: string;
  from: string;
}
```

Replace with:

```ts
export interface DiagramNode {
  id: 'origin' | 'gate' | 'outcome' | 'scope';
  title: string;
  detail: string;
  from: string;
}
```

Find the `ReachDiagram` interface:

```ts
export interface ReachDiagram {
  nodes: [DiagramNode, DiagramNode, DiagramNode];
  edges: { from: string; to: string }[];
  gateAnnotation: DiagramAnnotation | null;
}
```

Replace with:

```ts
export interface ReachDiagram {
  // 3 nodes, or 4 when S:C adds the scope node (Part 7).
  nodes: DiagramNode[];
  edges: { from: string; to: string }[];
  gateAnnotation: DiagramAnnotation | null;
  // AC belongs on the edge between the gate and the outcome (Part 7) — a separate field from
  // gateAnnotation (which is UI-driven) rather than a second meaning for the same one, so a
  // caller can render "why" text for each edge independently.
  acAnnotation: DiagramAnnotation | null;
}
```

Find the `outcomeNode` function:

```ts
// Only H-valued C/I/A metrics reach this node — an :L metric is a real but partial effect, and
// rendering it here would overstate what the diagram is claiming (consequence.js's buildImpact()
// does render :L, as "partly read" etc.; this diagram deliberately does not, per the spec's own
// rule that C/I/A "at H" fill the outcome node).
function outcomeNode(metrics: Record<string, string>): DiagramNode {
  const verbs: string[] = [];
  const from: string[] = [];
  for (const key of ['C', 'I', 'A']) {
    if (metrics[key] === 'H') { verbs.push(OUTCOME_VERBS[key]); from.push(`${key}:H`); }
  }
  if (!verbs.length) {
    return { id: 'outcome', title: 'No full-control outcome', detail: 'Nothing in this vector reaches complete read, change or shutdown', from: 'C/I/A' };
  }
  return { id: 'outcome', title: joinVerbs(verbs), detail: joinVerbs(verbs), from: from.join('/') };
}
```

Replace with:

```ts
// Renders every non-N C/I/A metric at its real level (Part 7) — H as the plain verb, L as
// "partly" plus the verb, the same distinction consequence.js's buildImpact() already draws for
// the impact panel, reused here (not duplicated wording) so the two surfaces never describe the
// same H or L metric two different ways. A metric at N is an absent slot, not a struck-through
// verb — dropped entirely, same as before.
function outcomeNode(metrics: Record<string, string>): DiagramNode {
  const parts: string[] = [];
  const from: string[] = [];
  for (const key of ['C', 'I', 'A']) {
    const value = metrics[key];
    if (value === 'H') { parts.push(OUTCOME_VERBS[key]); from.push(`${key}:H`); }
    else if (value === 'L') { parts.push(`partly ${OUTCOME_VERBS[key]}`); from.push(`${key}:L`); }
  }
  if (!parts.length) {
    return { id: 'outcome', title: 'No full-control outcome', detail: 'Nothing in this vector states what it reads, changes or shuts down', from: 'C/I/A' };
  }
  return { id: 'outcome', title: joinVerbs(parts), detail: joinVerbs(parts), from: from.join('/') };
}

// AC:L means the exploit works whenever it's tried; AC:H means the attacker needs conditions to
// line up first — the difference between a reliable exploit and an opportunistic one (Part 7).
// Never rendered anywhere in the product before this.
const AC_ANNOTATION: Record<string, string> = {
  L: 'works whenever it is tried',
  H: 'needs conditions to line up',
};

function acAnnotationFor(ac: string | undefined): DiagramAnnotation | null {
  const text = ac ? AC_ANNOTATION[ac] : undefined;
  return text ? { text, from: `AC:${ac}` } : null;
}

// S:C means the flaw escapes the component it lives in and can affect the rest of the system —
// consequence.js:buildImpact concedes a scope-changed vector "can carry effects these three
// metrics do not express" and stops there; this is where that gets a fourth node instead of
// staying unsaid (Part 7). Never rendered anywhere in the product before this.
function scopeNode(s: string | undefined): DiagramNode | null {
  if (s !== 'C') return null;
  return {
    id: 'scope',
    title: 'Reaches beyond this component',
    detail: 'A scope change means the flaw can affect more than the part of the system it lives in',
    from: `S:${s}`,
  };
}
```

Find the `reachDiagram` function:

```ts
export function reachDiagram(metrics: Record<string, string> | null | undefined): ReachDiagram {
  const m = metrics ?? {};
  const origin = originNode(m['AV']);
  const gate = gateNode(m['PR']);
  const outcome = outcomeNode(m);
  const ui = m['UI'];
  const uiText = ui ? UI_ANNOTATION[ui] : undefined;
  return {
    nodes: [origin, gate, outcome],
    edges: [{ from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }],
    gateAnnotation: uiText ? { text: uiText, from: `UI:${ui}` } : null,
  };
}
```

Replace with:

```ts
export function reachDiagram(metrics: Record<string, string> | null | undefined): ReachDiagram {
  const m = metrics ?? {};
  const origin = originNode(m['AV']);
  const gate = gateNode(m['PR']);
  const outcome = outcomeNode(m);
  const scope = scopeNode(m['S']);
  const ui = m['UI'];
  const uiText = ui ? UI_ANNOTATION[ui] : undefined;

  const nodes: DiagramNode[] = scope ? [origin, gate, outcome, scope] : [origin, gate, outcome];
  const edges = [{ from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }];
  if (scope) edges.push({ from: 'outcome', to: 'scope' });

  return {
    nodes,
    edges,
    gateAnnotation: uiText ? { text: uiText, from: `UI:${ui}` } : null,
    acAnnotation: acAnnotationFor(m['AC']),
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): render AC and S:C on the reach diagram, per-metric C/I/A levels"
```

---

## Task 8: `core/remediation.ts` — `diagramSvgWidth`/`diagramEdgeLines` (Part 7 layout math)

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (append)

**Interfaces:**
- Consumes: `ReachDiagram` (Task 7).
- Produces: `DiagramEdgeLine`, `diagramSvgWidth(diagram)`, `diagramEdgeLines(diagram)`. Consumed by Task 9 (`ReachDiagramComponent`).

Kept as pure, tested math rather than component code, so a fourth node's on-screen placement is a checked fact rather than something only verified by eye in a browser — per this app's own convention that components stay thin bindings over `core/remediation.ts`.

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import { diagramSvgWidth, diagramEdgeLines } from './remediation';

describe('diagramSvgWidth', () => {
  it('is 760 for the three-node diagram (no scope change)', () => {
    expect(diagramSvgWidth(reachDiagram({}))).toBe(760);
  });
  it('is 1000 for the four-node diagram (S:C)', () => {
    expect(diagramSvgWidth(reachDiagram({ S: 'C' }))).toBe(1000);
  });
});

describe('diagramEdgeLines', () => {
  it('matches the two original hardcoded lines for a three-node diagram', () => {
    const lines = diagramEdgeLines(reachDiagram({}));
    expect(lines).toEqual([
      { key: 'origin-gate', x1: 180, y1: 55, x2: 230, y2: 55 },
      { key: 'gate-outcome', x1: 420, y1: 55, x2: 470, y2: 55 },
    ]);
  });
  it('adds a third line to the scope node when S:C', () => {
    const lines = diagramEdgeLines(reachDiagram({ S: 'C' }));
    expect(lines.length).toBe(3);
    expect(lines[2]).toEqual({ key: 'outcome-scope', x1: 660, y1: 55, x2: 710, y2: 55 });
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `diagramSvgWidth`/`diagramEdgeLines` not exported.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
// ---- Part 7's layout math for tf-reach-diagram's SVG ----

export interface DiagramEdgeLine {
  key: string;
  x1: number; y1: number;
  x2: number; y2: number;
}

// Every node's box spans [i*240, i*240+180] at y=10..100 (reach-diagram.component.ts's own
// translate(i*240, 0) positioning) — a fourth node needs the viewBox widened to fit it, so this
// is a function of how many nodes the diagram actually has rather than a fixed constant.
export function diagramSvgWidth(diagram: ReachDiagram): number {
  return diagram.nodes.length * 240 + 40;
}

// An edge is drawn from the tail node's right edge to 10px short of the head node's left edge —
// matching the component's two original hardcoded <line> elements (x1=180,x2=230 and
// x1=420,x2=470), generalized so a third edge (outcome->scope) places itself correctly without
// a third hardcoded line in the template.
export function diagramEdgeLines(diagram: ReachDiagram): DiagramEdgeLine[] {
  const indexOf = new Map(diagram.nodes.map((n, i) => [n.id, i]));
  return diagram.edges.map((e) => {
    const fromIdx = indexOf.get(e.from as DiagramNode['id']) ?? 0;
    const toIdx = indexOf.get(e.to as DiagramNode['id']) ?? 0;
    return { key: `${e.from}-${e.to}`, x1: fromIdx * 240 + 180, y1: 55, x2: toIdx * 240 - 10, y2: 55 };
  });
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): add pure layout math for the reach diagram's variable node count"
```

---

## Task 9: `ReachDiagramComponent` — render the variable node count, edges and `AC` annotation (Part 7 UI)

**Files:**
- Modify: `frontend-v4/src/app/ui/reach-diagram.component.ts`

**Interfaces:**
- Consumes: `ReachDiagram`, `diagramSvgWidth`, `diagramEdgeLines` (Tasks 7-8).
- No new pure logic — this task is template/class wiring only, per this app's "components stay thin bindings" convention. Verified by `tsc` and a manual browser check (no `.spec.ts` for this file, matching the existing convention — `RemediationQueueComponent`/`RemediationGuidedComponent` also have no component-level spec files).

- [ ] **Step 1: Replace the component**

Read the current file first (`frontend-v4/src/app/ui/reach-diagram.component.ts`), then replace its full contents with:

```ts
import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import type { ReachDiagram, DiagramNode } from '../core/remediation';
import { diagramSvgWidth, diagramEdgeLines } from '../core/remediation';

// Step 1's signature diagram: origin -> gate -> outcome, and (when the vector's scope changed)
// -> scope, drawn from whatever reachDiagram() (core/remediation.ts) already decided from the
// CVSS vector. This component owns no logic of its own beyond which node's "why" popover is
// open and which edge annotation is showing — the same idiom tf-impact-panel already uses for
// its provenance buttons, reused here rather than inventing a second interaction.
//
// Inline SVG, no chart library. Node count and edge geometry both come from core/remediation.ts's
// diagramSvgWidth()/diagramEdgeLines() (Part 7) rather than being hardcoded here, so a fourth
// node (S:C) places itself correctly without a template change beyond what's already here.
// Horizontal scroll on narrow viewports (own .scroll container) rather than reflowing into an
// unreadable stack.
@Component({
  selector: 'tf-reach-diagram',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="scroll">
      <svg [attr.viewBox]="'0 0 ' + svgWidth() + ' 170'" [attr.width]="svgWidth()" [attr.height]="170" role="img" [attr.aria-label]="ariaLabel()">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--ink-2)" />
          </marker>
        </defs>

        @for (e of edgeLines(); track e.key) {
          <line class="edge" [attr.x1]="e.x1" [attr.y1]="e.y1" [attr.x2]="e.x2" [attr.y2]="e.y2" marker-end="url(#arrow)" />
        }

        @for (n of diagram.nodes; track n.id; let i = $index) {
          <g class="node" [style.animation-delay.ms]="i * 80" [attr.transform]="'translate(' + (i * 240) + ', 0)'">
            <rect x="0" y="10" width="180" height="90" rx="10" class="box" />
            <text x="90" y="35" class="label">{{ n.title }}</text>
            <foreignObject x="10" y="45" width="160" height="45">
              <p class="detail" xmlns="http://www.w3.org/1999/xhtml">{{ n.detail }}</p>
            </foreignObject>
          </g>
        }
      </svg>

      @if (diagram.gateAnnotation; as ann) {
        <p class="annotation">{{ ann.from }} — {{ ann.text }}</p>
      }
      @if (diagram.acAnnotation; as ac) {
        <p class="annotation">{{ ac.from }} — {{ ac.text }}</p>
      }

      <div class="why-row">
        @for (n of diagram.nodes; track n.id) {
          <button type="button" class="why" [attr.aria-expanded]="isOpen(n.id)" (click)="toggle(n.id)">
            why: {{ n.title }}
          </button>
          @if (isOpen(n.id)) { <p class="prov">{{ n.from }}</p> }
        }
      </div>
    </div>
  `,
  styles: [`
    .scroll { overflow-x: auto; }
    svg { display: block; min-width: 640px; }
    .box { fill: var(--surface-2); stroke: var(--hairline); stroke-width: 1; }
    .label { font-size: 12px; font-weight: 600; fill: var(--ink); text-anchor: middle; }
    .detail { margin: 0; font-size: 11px; color: var(--ink-2); text-align: center; line-height: 1.3; }
    .annotation { margin: 6px 0 0; font-size: var(--fs-xs); color: var(--ink-2); text-align: center; }

    .node {
      opacity: 0;
      animation: node-in 240ms var(--ease-out) forwards;
    }
    @keyframes node-in {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    .edge {
      stroke: var(--ink-2);
      stroke-width: 1.5;
      stroke-dasharray: 60;
      stroke-dashoffset: 60;
      animation: draw 300ms var(--ease-out) forwards;
      animation-delay: 160ms;
    }
    @keyframes draw {
      to { stroke-dashoffset: 0; }
    }
    /* Runs once on creation, never loops or re-triggers on scroll — everything on this page is
       already urgent enough without ambient motion. */
    @media (prefers-reduced-motion: reduce) {
      .node, .edge { animation: none; opacity: 1; stroke-dashoffset: 0; }
    }

    .why-row { display: flex; flex-wrap: wrap; gap: 8px 14px; margin-top: 10px; }
    .why {
      font: inherit; font-size: var(--fs-xs); color: var(--ink-2); cursor: pointer;
      background: none; border: none; padding: 0; border-bottom: 1px dotted currentColor;
    }
    .why:hover, .why:focus-visible { color: var(--ink); }
    .why:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .prov { flex-basis: 100%; margin: 0; font-size: var(--fs-xs); color: var(--ink-2); }
  `],
})
export class ReachDiagramComponent {
  @Input() diagram!: ReachDiagram;

  private openNodes = new Set<string>();

  isOpen(id: string): boolean {
    return this.openNodes.has(id);
  }

  toggle(id: string): void {
    if (this.openNodes.has(id)) this.openNodes.delete(id);
    else this.openNodes.add(id);
  }

  ariaLabel(): string {
    return this.diagram.nodes.map((n) => n.title).join(' leads to ');
  }

  svgWidth(): number {
    return diagramSvgWidth(this.diagram);
  }

  edgeLines() {
    return diagramEdgeLines(this.diagram);
  }
}
```

- [ ] **Step 2: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 3: Manual browser check**

Chrome is connected (confirmed via `list_connected_browsers` — one local browser, "Browser 1"). Start the frontend dev server and API per `CLAUDE.md`'s commands, navigate to `/remediate/:itemId` for an item with a `CVSS:3.1` vector that includes `S:C` (e.g. seed or find one via the dev DB), and confirm: the fourth "Reaches beyond this component" node renders, the third edge connects outcome to it, and the `AC:L`/`AC:H` caption appears beneath the diagram alongside the existing `UI` caption. Then check an item without `S:C` still renders exactly three nodes with no layout regression.

- [ ] **Step 4: Commit**

```bash
git add frontend-v4/src/app/ui/reach-diagram.component.ts
git commit -m "feat(remediation): render the reach diagram's AC annotation and S:C scope node"
```

---

## Task 10: `core/remediation.ts` — `actionProvenance` (Part 5: "why this action?")

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (append)

**Interfaces:**
- Consumes: `RemediationAction` (Task 3).
- Produces: `ProvenanceLine`, `actionProvenance(action, asset)`. Consumed by Task 13 (`RemediationQueueComponent`).

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import { actionProvenance } from './remediation';

describe('actionProvenance', () => {
  const asset = { vendor: 'apple', product: 'macos' };

  it('states what matched the asset first', () => {
    const a = groupActions([item({ itemId: 1, fix: { kind: 'none' } })])[0];
    expect(actionProvenance(a, asset)[0]).toEqual({ label: 'Matched', text: 'apple macos (item_cpes)' });
  });
  it('names the NVD endExcluding bound for a version fix', () => {
    const a = groupActions([item({ itemId: 1, fix: { kind: 'version', value: '14.8.8' } })])[0];
    expect(actionProvenance(a, asset)[1]).toEqual({ label: 'Fix source', text: 'NVD cpeMatch endExcluding: 14.8.8' });
  });
  it('lists the distinct patch URLs backing a patch action', () => {
    const a = groupActions([
      item({ itemId: 1, fix: { kind: 'patch', value: 'https://x/a' }, patchUrl: 'https://x/a' }),
      item({ itemId: 2, fix: { kind: 'patch', value: 'https://x/b' }, patchUrl: 'https://x/b' }),
    ])[0];
    expect(actionProvenance(a, asset)[1].text).toBe('cve_intel.patch_url: https://x/a, https://x/b');
  });
  it('names the advisory link for an advisory fix', () => {
    const a = groupActions([item({ itemId: 1, fix: { kind: 'advisory', value: 'https://x/a' } })])[0];
    expect(actionProvenance(a, asset)[1]).toEqual({ label: 'Fix source', text: 'cve_intel.advisory_url: https://x/a' });
  });
  it('states the explicit absence for a none fix', () => {
    const a = groupActions([item({ itemId: 1, fix: { kind: 'none' } })])[0];
    expect(actionProvenance(a, asset)[1].text).toMatch(/no patch or advisory/i);
  });
  it('reports the worst item\'s source_count as the corroboration line', () => {
    const a = groupActions([
      item({ itemId: 1, fix: { kind: 'none' }, cvssScore: 9.8, sourceCount: 3 }),
      item({ itemId: 2, fix: { kind: 'none' }, cvssScore: 5.0, sourceCount: 1 }),
    ])[0];
    expect(actionProvenance(a, asset)[2]).toEqual({ label: 'Corroboration', text: '3 independent sources' });
  });
  it('singular wording for exactly one source', () => {
    const a = groupActions([item({ itemId: 1, fix: { kind: 'none' }, sourceCount: 1 })])[0];
    expect(actionProvenance(a, asset)[2].text).toBe('1 independent source');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `actionProvenance` not exported.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
// ---- Part 5: provenance on every action ----

export interface ProvenanceLine {
  label: string;
  text: string;
}

// Part 5's three facts, always in this order: what matched the asset, where the fix came from,
// how many sources corroborate. Corroboration and the fix source both draw on whichever item set
// the action's worst-CVSS ranking (see this plan's Spec Accuracy Finding 4) — the same item whose
// score and severity already anchor the row's headline number, so the panel never explains a
// different CVE than the one the numeral describes.
export function actionProvenance(
  action: RemediationAction,
  asset: { vendor: string; product: string },
): ProvenanceLine[] {
  const lines: ProvenanceLine[] = [
    { label: 'Matched', text: `${asset.vendor} ${asset.product} (item_cpes)` },
  ];

  if (action.fix.kind === 'version') {
    lines.push({ label: 'Fix source', text: `NVD cpeMatch endExcluding: ${action.fix.value}` });
  } else if (action.fix.kind === 'patch') {
    const urls = [...new Set(action.items.map((i) => i.patchUrl).filter((u): u is string => !!u))];
    lines.push({ label: 'Fix source', text: `cve_intel.patch_url: ${urls.join(', ')}` });
  } else if (action.fix.kind === 'advisory') {
    lines.push({ label: 'Fix source', text: `cve_intel.advisory_url: ${action.fix.value}` });
  } else {
    lines.push({ label: 'Fix source', text: 'No patch or advisory on file for any threat in this action' });
  }

  const worst = action.items.find((i) => i.cvssScore === action.worstScore) ?? action.items[0];
  const sourceCount = worst?.sourceCount ?? 0;
  lines.push({
    label: 'Corroboration',
    text: `${sourceCount} independent source${sourceCount === 1 ? '' : 's'}`,
  });

  return lines;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): build the why-this-action provenance lines"
```

---

## Task 11: `core/remediation.ts` — `buildTicketText` (Part 6: copy as ticket)

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (append)

**Interfaces:**
- Consumes: `RemediationAction` (Task 3).
- Produces: `buildTicketText(action, asset)`. Consumed by Task 13 (`RemediationQueueComponent`, via `tf-copy-button`'s existing `[value]` input — no clipboard API code of this plan's own; `frontend-v4/src/app/ui/copy-button.component.ts` already owns `navigator.clipboard.writeText`).

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import { buildTicketText } from './remediation';

describe('buildTicketText', () => {
  const asset = { vendor: 'apple', product: 'macos' };

  it('names the action, count, and worst severity for a version fix', () => {
    const a = groupActions([item({
      itemId: 1, fix: { kind: 'version', value: '14.8.8' }, cvssScore: 9.8, severity: 'critical', cveId: 'CVE-2026-1',
    })])[0];
    const text = buildTicketText(a, asset);
    expect(text).toContain('Upgrade apple macos to 14.8.8 or later');
    expect(text).toContain('Closes 1 threat');
    expect(text).toContain('Worst severity: critical (9.8)');
    expect(text).toContain('CVEs: CVE-2026-1');
  });
  it('pluralizes "threats" for more than one', () => {
    const a = groupActions([item({ itemId: 1, fix: { kind: 'none' } }), item({ itemId: 2, fix: { kind: 'none' } })])[0];
    expect(buildTicketText(a, asset)).toContain('Closes 2 threats');
  });
  it('includes a KEV line only when the action has a KEV item, noting ransomware and past-due', () => {
    const now = new Date('2026-08-04T00:00:00Z');
    const kevAction = groupActions(
      [item({ itemId: 1, fix: { kind: 'none' }, kevListed: true, kevRansomware: true, kevDueDate: '2024-12-03' })],
      now,
    )[0];
    expect(buildTicketText(kevAction, asset)).toContain('KEV: 1 listed, ransomware-associated, 1 past due');

    const plainAction = groupActions([item({ itemId: 1, fix: { kind: 'none' } })])[0];
    expect(buildTicketText(plainAction, asset)).not.toContain('KEV:');
  });
  it('lists every CVE id in the bundle', () => {
    const a = groupActions([
      item({ itemId: 1, fix: { kind: 'version', value: '1.0' }, cveId: 'CVE-2026-1' }),
      item({ itemId: 2, fix: { kind: 'version', value: '1.0' }, cveId: 'CVE-2026-2' }),
    ])[0];
    expect(buildTicketText(a, asset)).toContain('CVEs: CVE-2026-1, CVE-2026-2');
  });
  it('states "none on file" rather than an empty list when no item carries a CVE id', () => {
    const a = groupActions([item({ itemId: 1, fix: { kind: 'none' }, cveId: null })])[0];
    expect(buildTicketText(a, asset)).toContain('CVEs: none on file');
  });
  it('is plain text with no markup', () => {
    const a = groupActions([item({ itemId: 1, fix: { kind: 'none' } })])[0];
    expect(buildTicketText(a, asset)).not.toMatch(/[<>{}]/);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `buildTicketText` not exported.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
// ---- Part 6: ticket handoff, plain text only ----

// Clipboard-only, per Part 6's own scope: no ticket-system client, no markup — every tracker
// accepts plain text.
export function buildTicketText(action: RemediationAction, asset: { vendor: string; product: string }): string {
  const headline = action.fix.kind === 'version'
    ? `Upgrade ${asset.vendor} ${asset.product} to ${action.fix.value} or later`
    : action.fix.kind === 'patch'
      ? `Apply the vendor patch for ${asset.vendor} ${asset.product}`
      : action.fix.kind === 'advisory'
        ? `Follow vendor guidance for ${asset.vendor} ${asset.product}`
        : `No fix published yet for ${asset.vendor} ${asset.product}`;

  const lines = [
    headline,
    `Closes ${action.count} threat${action.count === 1 ? '' : 's'}`,
    `Worst severity: ${action.worstSeverity ?? 'unknown'}${action.worstScore != null ? ` (${action.worstScore})` : ''}`,
  ];

  if (action.kev) {
    const bits = [`${action.kev.count} listed`];
    if (action.kev.ransomware) bits.push('ransomware-associated');
    if (action.kev.pastDueCount > 0) bits.push(`${action.kev.pastDueCount} past due`);
    lines.push(`KEV: ${bits.join(', ')}`);
  }

  const cveIds = action.items.map((i) => i.cveId).filter((c): c is string => !!c);
  lines.push(`CVEs: ${cveIds.length ? cveIds.join(', ') : 'none on file'}`);

  return lines.join('\n');
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests. Report the actual total test count for the file at this point (baseline 176 total across the suite before Task 3; by here the suite should read somewhere around 220-230 total across all 12 files — report the exact number `vitest run` prints, not this estimate).

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): build the copy-as-ticket plain text"
```

---

## Task 12: `RemediationQueueComponent` redesign, part A — grouped, ranked, severity- and KEV-encoded action rows (Parts 1-3)

**Files:**
- Modify: `frontend-v4/src/app/pages/remediate/remediation-queue.component.ts`

**Interfaces:**
- Consumes: `groupActions`, `sortActions`, `actionStatus`, `splitActionsByStatus`, `NOT_COVERED_SECTION_CAVEAT` (Tasks 3-5), `fixWording` (Spec B), `severityToken` (`frontend-v4/src/app/core/format.ts`).
- No new pure logic of its own — this task wires Tasks 3-5's already-tested functions into the template. Verified by `tsc` and a manual browser check.

This is the biggest single UI change in the plan — the redesign the whole spec exists to ship. It's kept to grouping/ordering/sections/severity/KEV here (Parts 1-3); filtering, the sort toggle, provenance and ticket copy land in Task 13 so this commit stays reviewable as "what you see" before Task 13 adds "what you can do with it."

- [ ] **Step 1: Replace the component**

Read the current file first (`frontend-v4/src/app/pages/remediate/remediation-queue.component.ts`), then replace its full contents with:

```ts
import { Component, ChangeDetectionStrategy, inject, signal, computed, effect } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { PanelComponent } from '../../ui/panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { severityToken } from '../../core/format';
import {
  queueSummary, groupProgress, groupHasPastDue, oneUpgradeCloses, closesWording, formatDueDate,
  groupActions, sortActions, splitActionsByStatus, NOT_COVERED_SECTION_CAVEAT,
  fixWording,
} from '../../core/remediation';
import type { RemediationAction } from '../../core/remediation';
import type { RemediationQueueGroup, RemediationQueueItem } from '../../core/models';

// The routed "/remediate" page. Grouping and within-group sort by score are Spec A's own SQL
// (server/index.js) — everything from here down is the triage redesign: threats
// collapse into fix-based action rows (Part 1), ranked by worst CVSS with KEV overriding score
// (Part 3), split three ways once a version is known (Part 2). All of it is pure functions from
// core/remediation.ts; this component stays a thin binding over them.
@Component({
  selector: 'tf-page-remediate',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, PanelComponent, EmptyStateComponent, SkeletonComponent],
  template: `
    <tf-panel title="Remediation">
      @if (loading()) {
        <tf-skeleton [rows]="4" />
      } @else if (error()) {
        <div class="err">
          <p class="t">Couldn't load the remediation queue</p>
          <button type="button" (click)="load()">Retry</button>
        </div>
      } @else if (noAssets()) {
        <tf-empty-state
          title="Tell us what you run"
          reason="Add assets to your profile and this page fills itself in"
        />
        <a class="cta" routerLink="/onboarding">Go to profile setup &rarr;</a>
      } @else if (groups().length === 0) {
        <tf-empty-state
          title="Nothing open"
          reason="Nothing open against the software you've told us about"
        />
      } @else {
        <p class="summary">{{ summary().open }} open &middot; {{ summary().pastDue }} past due</p>
        <ul class="groups">
          @for (g of groups(); track g.vendor + '/' + g.product) {
            <li class="group">
              <div class="group-head">
                <span class="name">{{ g.vendor }} {{ g.product }}</span>
                @if (progressOf(g); as p) {
                  <span class="bar" role="progressbar" [attr.aria-valuenow]="p.done" [attr.aria-valuemax]="p.total">
                    <span class="fill" [style.width.%]="p.total ? (p.done / p.total) * 100 : 0"></span>
                  </span>
                  <span class="count">{{ p.done }} of {{ p.total }}</span>
                } @else {
                  <a class="tell-us" [routerLink]="['/remediate', g.items[0].itemId]">tell us &rarr;</a>
                }
                @if (hasPastDue(g)) { <span class="past-due">past due</span> }
              </div>
              @if (g.version) { <p class="running">you run {{ g.version }}</p> }
              @if (closesLine(g); as line) { <p class="closes">&#9656; {{ line }}</p> }

              @if (sectionsOf(g); as sections) {
                @if (sections.affected.length) {
                  <div class="section">
                    <p class="section-head">Still affects you</p>
                    <ul class="actions">
                      @for (a of sections.affected; track a.key) { <li>@template action(a)</li> }
                    </ul>
                  </div>
                }
                @if (sections.unknown.length) {
                  <div class="section">
                    <p class="section-head">Can't tell from your version</p>
                    <ul class="actions">
                      @for (a of sections.unknown; track a.key) { <li>@template action(a)</li> }
                    </ul>
                  </div>
                }
                @if (sections.notCovered.length) {
                  <div class="section">
                    <p class="section-head">No longer in range</p>
                    <p class="section-caveat">{{ notCoveredCaveat }}</p>
                    <ul class="actions">
                      @for (a of sections.notCovered; track a.key) { <li>@template action(a)</li> }
                    </ul>
                  </div>
                }
              } @else {
                <ul class="actions">
                  @for (a of actionsOf(g); track a.key) { <li>@template action(a)</li> }
                </ul>
              }
            </li>
          }
        </ul>
      }
    </tf-panel>

    <ng-template #action let-a>
      <div class="action-row" [style.--stripe]="stripeColor(a)">
        @if (a.kev; as kev) {
          <span class="kev-badge" [class.filled]="true">
            KEV
            @if (kev.pastDueCount > 0) { &middot; {{ kev.pastDueCount }} past due }
            @if (kev.ransomware) { &middot; ransomware }
          </span>
        }
        <div class="action-main">
          <span class="headline">{{ fixHeadline(a) }}</span>
          <span class="count tabular-nums">{{ a.count }} threat{{ a.count === 1 ? '' : 's' }}</span>
          @if (a.worstScore != null) {
            <span class="worst tabular-nums">
              {{ a.worstScore }}@if (a.worstVersion) { <span class="ver">v{{ a.worstVersion }}</span> }
            </span>
          }
        </div>
        <div class="dist">
          @for (band of severityBands; track band) {
            @if (a.severityCounts[band] > 0) {
              <span class="seg" [style.flexGrow]="a.severityCounts[band]" [style.background]="bandColor(band)"
                [attr.title]="band + ': ' + a.severityCounts[band]"></span>
            }
          }
        </div>
        <details class="disclosure">
          <summary>{{ a.count }} CVE{{ a.count === 1 ? '' : 's' }}</summary>
          <ul class="cves">
            @for (item of a.items; track item.itemId) {
              <li>
                <a [routerLink]="['/remediate', item.itemId]">{{ item.cveId || item.title }}</a>
                <span class="status" [class]="'status-' + item.status">{{ statusLabel(item.status) }}</span>
                @if (item.dueDate) { <span class="due">fix by {{ formatDueDate(item.dueDate) }}</span> }
              </li>
            }
          </ul>
        </details>
      </div>
    </ng-template>
  `,
  styles: [`
    .summary { margin: 0 0 14px; font-size: var(--fs-sm); color: var(--ink-2); }
    .groups { list-style: none; margin: 0; padding: 0; display: grid; gap: 16px; }
    .group { border-top: var(--hair) solid var(--hairline); padding-top: 12px; }
    .group:first-child { border-top: none; padding-top: 0; }
    .group-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .name { font-weight: 600; color: var(--ink); }
    .bar {
      display: inline-block; width: 90px; height: 6px; border-radius: 3px;
      background: var(--surface-3); overflow: hidden;
    }
    .fill { display: block; height: 100%; background: var(--accent); transition: width var(--dur-slow) var(--ease-out); }
    @media (prefers-reduced-motion: reduce) { .fill { transition: none; } }
    .count { font-size: var(--fs-xs); color: var(--ink-2); }
    .tell-us { font-size: var(--fs-xs); color: var(--accent); text-decoration: none; }
    .tell-us:hover { text-decoration: underline; }
    .past-due { margin-left: auto; font-size: var(--fs-xs); font-weight: 600; color: var(--sev-critical); }
    .running { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .closes { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink); }

    .tabular-nums { font-variant-numeric: tabular-nums; }

    .section { margin-top: 12px; }
    .section-head { margin: 0 0 6px; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2); text-transform: uppercase; letter-spacing: .02em; }
    .section-caveat { margin: 0 0 8px; font-size: var(--fs-xs); color: var(--ink-2); font-style: italic; }
    .actions { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }

    .action-row {
      display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 8px 12px;
      padding: 6px 0 6px 10px; border-left: 3px solid var(--stripe, var(--sev-unknown));
    }
    .kev-badge {
      grid-column: 1; font-size: var(--fs-xs); font-weight: 700; color: var(--bg);
      background: var(--sev-critical); padding: 2px 8px; border-radius: 999px; white-space: nowrap;
    }
    .action-main { grid-column: 2; display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; min-width: 0; }
    .headline { color: var(--ink); font-size: var(--fs-sm); }
    .worst { font-size: var(--fs-xs); color: var(--ink-2); }
    .ver { margin-left: 3px; font-size: 10px; color: var(--ink-2); }
    .dist { grid-column: 3; display: flex; width: 80px; height: 6px; border-radius: 3px; overflow: hidden; background: var(--surface-3); }
    .seg { display: block; }
    .disclosure { grid-column: 1 / -1; }
    .disclosure summary { cursor: pointer; font-size: var(--fs-xs); color: var(--ink-2); }
    .cves { list-style: none; margin: 6px 0 0; padding: 0; display: grid; gap: 4px; }
    .cves li { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; font-family: ui-monospace, monospace; font-size: var(--fs-xs); }
    .cves a { color: var(--ink); text-decoration: none; }
    .cves a:hover { color: var(--accent); }
    .status { font-family: inherit; color: var(--ink-2); }
    .status-not_covered { color: var(--sev-none); }
    .due { margin-left: auto; color: var(--ink-2); }

    .cta { display: inline-block; margin-top: 8px; font-size: var(--fs-sm); color: var(--accent); text-decoration: none; }
    .cta:hover { text-decoration: underline; }
    .err { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 24px; text-align: center; }
    .err button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0; padding: 6px 14px; border-radius: 8px;
    }
  `],
})
export class RemediationQueueComponent {
  private api = inject(ApiService);
  private profileService = inject(ProfileService);

  groups = signal<RemediationQueueGroup[]>([]);
  loading = signal(true);
  error = signal(false);

  noAssets = computed(() => (this.profileService.active()?.assets.length ?? 0) === 0);
  summary = computed(() => queueSummary(this.groups()));

  formatDueDate = formatDueDate;
  notCoveredCaveat = NOT_COVERED_SECTION_CAVEAT;
  severityBands = ['critical', 'high', 'medium', 'low', 'none', 'unknown'] as const;

  constructor() {
    effect(() => {
      this.profileService.dataVersion();
      const profile = this.profileService.active();
      if (!profile) return;
      this.load();
    });
  }

  load(): void {
    const profile = this.profileService.active();
    if (!profile) return;
    this.loading.set(true);
    this.error.set(false);
    this.api.remediationQueue(profile.id).subscribe({
      next: (rows) => { this.groups.set(rows); this.loading.set(false); },
      error: () => { this.error.set(true); this.loading.set(false); },
    });
  }

  progressOf(g: RemediationQueueGroup) {
    return groupProgress(g);
  }

  hasPastDue(g: RemediationQueueGroup): boolean {
    return groupHasPastDue(g.items);
  }

  closesLine(g: RemediationQueueGroup): string | null {
    return closesWording(oneUpgradeCloses(g.items));
  }

  // Part 3's default: risk order (worst CVSS descending, count breaking ties, KEV first
  // regardless). Task 13 adds the reach toggle on top of this.
  actionsOf(g: RemediationQueueGroup): RemediationAction[] {
    return sortActions(groupActions(g.items));
  }

  // Part 2: only once a version is known is there anything to split — before that there is one
  // bucket and no section chrome, so this returns null and the template falls back to the flat
  // actionsOf() list.
  sectionsOf(g: RemediationQueueGroup) {
    if (g.versionState !== 'known') return null;
    return splitActionsByStatus(this.actionsOf(g));
  }

  fixHeadline(a: RemediationAction): string {
    return fixWording(a.fix).headline;
  }

  stripeColor(a: RemediationAction): string {
    return severityToken(a.worstSeverity);
  }

  bandColor(band: string): string {
    return severityToken(band);
  }

  statusLabel(status: RemediationQueueItem['status']): string {
    if (status === 'affected') return 'affected';
    if (status === 'not_covered') return 'not covered';
    return 'unknown';
  }
}
```

**Note on `@template`:** Angular 19's built-in control flow does not have a `@template`/call syntax — the `<ng-template #action let-a>` + repeated inline invocation shown above is illustrative of intent but not valid Angular syntax. Replace every `@template action(a)` usage with `<ng-container *ngTemplateOutlet="action; context: { $implicit: a }"></ng-container>` (requires adding `NgTemplateOutlet` to the component's `imports` array), OR — simpler and this app's more common pattern elsewhere — inline the action-row markup directly inside each of the three section `@for` loops and the flat-list `@for` loop (four copies) rather than factoring it into a shared template fragment. Given this app's existing components (e.g. `remediation-guided.component.ts`'s `@for (v of [verdict()]; track v.headline)` trick) lean toward duplication over Angular's more awkward template-outlet ceremony for small blocks, **prefer inlining the action-row markup in all four call sites** over `ngTemplateOutlet`. Do this replacement as part of Step 1 before moving on — do not leave `@template` in the committed file.

- [ ] **Step 2: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 3: Manual browser check**

Chrome is connected. Start the frontend dev server and API, navigate to `/remediate` for a profile with open threats (per `CLAUDE.md`, profile 10 / `apple macos` is the measured 295-row case if the dev DB still has it seeded). Confirm: rows are grouped by fix (not one row per CVE), sorted with the worst-CVSS action first, KEV actions (if any in the seeded data) pinned above everything else, the severity distribution bar renders, and — for an asset with a known version — the three named sections appear with the not-covered caveat text.

- [ ] **Step 4: Commit**

```bash
git add frontend-v4/src/app/pages/remediate/remediation-queue.component.ts
git commit -m "feat(remediation): redesign the queue into grouped, risk-ranked action rows"
```

---

## Task 13: `RemediationQueueComponent` redesign, part B — filter, risk/reach toggle, provenance disclosure, copy-as-ticket (Parts 4-6)

**Files:**
- Modify: `frontend-v4/src/app/pages/remediate/remediation-queue.component.ts`

**Interfaces:**
- Consumes: `filterQueueItems` (Task 6), `actionProvenance` (Task 10), `buildTicketText` (Task 11), `RiskReachMode`/`sortActions` (Task 4), `CopyButtonComponent` (`frontend-v4/src/app/ui/copy-button.component.ts`, already exists — `[value]`/`[label]` inputs, own clipboard handling).
- No new pure logic — wires already-tested Task 6/10/11 functions into the template built in Task 12.

- [ ] **Step 1: Add the controls and wiring**

In `frontend-v4/src/app/pages/remediate/remediation-queue.component.ts`, extend the imports:

```ts
import {
  queueSummary, groupProgress, groupHasPastDue, oneUpgradeCloses, closesWording, formatDueDate,
  groupActions, sortActions, splitActionsByStatus, NOT_COVERED_SECTION_CAVEAT,
  fixWording, filterQueueItems, actionProvenance, buildTicketText,
} from '../../core/remediation';
import type { RemediationAction, RiskReachMode } from '../../core/remediation';
import { CopyButtonComponent } from '../../ui/copy-button.component';
```

Add `CopyButtonComponent` to the `imports` array on the `@Component` decorator.

Add a filter input and sort toggle right after the `<p class="summary">` line in the template:

```html
<p class="summary">{{ summary().open }} open &middot; {{ summary().pastDue }} past due</p>
<div class="controls">
  <input
    type="text" class="filter" placeholder="Filter by CVE id or version&hellip;"
    [value]="filterQuery()" (input)="onFilterInput($event)"
  />
  <button type="button" class="sort-toggle" (click)="toggleSort()">
    sort: {{ sortMode() === 'risk' ? 'risk' : 'reach' }} &#8646;
  </button>
</div>
```

In each of the four `<ng-container>`/inline action-row blocks written out in Task 12's Step 1 note, add a "why this action?" disclosure and a copy-as-ticket button right after the existing `<details class="disclosure">...</details>` block:

```html
<details class="why-disclosure">
  <summary>why this action?</summary>
  <dl class="prov">
    @for (line of provenanceOf(a, g); track line.label) {
      <div><dt>{{ line.label }}</dt><dd>{{ line.text }}</dd></div>
    }
  </dl>
</details>
<tf-copy-button [value]="ticketTextOf(a, g)" label="Copy as ticket" />
```

(`g` is the enclosing `RemediationQueueGroup` from the outer `@for` — in scope at every one of the four call sites already, since the action rows are nested inside `@for (g of groups(); ...)`.)

Replace `actionsOf(g)` and `sectionsOf(g)` with versions that apply the filter and the active sort mode:

```ts
  filterQuery = signal('');
  sortMode = signal<RiskReachMode>('risk');

  onFilterInput(ev: Event): void {
    this.filterQuery.set((ev.target as HTMLInputElement).value);
  }

  toggleSort(): void {
    this.sortMode.set(this.sortMode() === 'risk' ? 'reach' : 'risk');
  }

  // Part 4: the filter narrows the ITEMS first, so a filtered-out threat never survives inside a
  // surviving action's disclosure — actions are re-derived from the filtered set, not filtered
  // themselves after the fact.
  actionsOf(g: RemediationQueueGroup): RemediationAction[] {
    const filtered = filterQueueItems(g.items, this.filterQuery());
    return sortActions(groupActions(filtered), this.sortMode());
  }

  sectionsOf(g: RemediationQueueGroup) {
    if (g.versionState !== 'known') return null;
    return splitActionsByStatus(this.actionsOf(g));
  }

  provenanceOf(a: RemediationAction, g: RemediationQueueGroup) {
    return actionProvenance(a, { vendor: g.vendor, product: g.product });
  }

  ticketTextOf(a: RemediationAction, g: RemediationQueueGroup): string {
    return buildTicketText(a, { vendor: g.vendor, product: g.product });
  }
```

(Remove the earlier `actionsOf`/`sectionsOf` from Task 12 — this replaces them, it does not add a duplicate.)

Add the control and disclosure styles:

```css
.controls { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
.filter {
  flex: 1; min-width: 0; font: inherit; font-size: var(--fs-sm); background: var(--surface-2);
  border: var(--hair) solid var(--hairline); border-radius: 6px; padding: 6px 10px; color: var(--ink);
}
.sort-toggle {
  appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
  color: var(--ink); background: var(--surface-2); border: 0; padding: 6px 12px; border-radius: 8px;
  white-space: nowrap;
}
.why-disclosure { grid-column: 1 / -1; margin-top: 4px; }
.why-disclosure summary { cursor: pointer; font-size: var(--fs-xs); color: var(--ink-2); }
.prov { margin: 6px 0 0; display: grid; gap: 4px; }
.prov div { display: flex; gap: 8px; font-size: var(--fs-xs); }
.prov dt { color: var(--ink-2); min-width: 90px; }
.prov dd { margin: 0; color: var(--ink); }
```

- [ ] **Step 2: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 3: Manual browser check**

With the dev server running, on `/remediate`: type a known CVE id fragment into the filter and confirm only matching actions remain (and actions with zero remaining items disappear entirely, not render empty); click the sort toggle and confirm the ordering visibly changes to count-first; expand a "why this action?" disclosure and confirm the three provenance lines render; click "Copy as ticket" and paste the clipboard contents somewhere to confirm it's plain text matching `buildTicketText`'s shape.

- [ ] **Step 4: Commit**

```bash
git add frontend-v4/src/app/pages/remediate/remediation-queue.component.ts
git commit -m "feat(remediation): add the queue's filter, risk/reach toggle, provenance and ticket copy"
```

---

## Task 14: `RemediationGuidedComponent` — the KEV block (Part 8's fields on the guided page)

**Files:**
- Modify: `frontend-v4/src/app/pages/remediate/remediation-guided.component.ts`

**Interfaces:**
- Consumes: `isPastDue`, `formatDueDate` (both already imported from `core/remediation.ts` in this file, Spec B), plus the eight new `RemediationDetail` fields (Task 2).
- No new pure logic — `isPastDue`/`formatDueDate` are already tested (Spec B's plan, `describe('isPastDue', ...)`/`describe('formatDueDate', ...)` in `remediation.spec.ts`).

- [ ] **Step 1: Add the KEV block**

In `frontend-v4/src/app/pages/remediate/remediation-guided.component.ts`, extend the import from `../../core/remediation`:

```ts
import {
  parseVectorMetrics, reachDiagram, affectedWording, fixWording, countCleared, versionRecordedMessage,
  isPastDue, formatDueDate,
} from '../../core/remediation';
```

In the template, right after the `<tf-reach-diagram [diagram]="diagram()" />` line inside the `"What this does"` panel, add:

```html
@if (d.kevListed) {
  <p class="kev-badge" [class.past-due]="d.kevDueDate && isPastDue(d.kevDueDate)">
    Known exploited
    @if (d.kevRansomware) { &middot; ransomware-associated }
    @if (d.kevDueDate) {
      &middot; due {{ formatDueDate(d.kevDueDate) }}
      @if (isPastDue(d.kevDueDate)) { (past due) }
    }
  </p>
}
```

Add to the class body (`isPastDue`/`formatDueDate` are already imported functions, bind them the same way `formatDueDate` is already bound as a plain property elsewhere in this app's convention, e.g. `RemediationQueueComponent.formatDueDate = formatDueDate`):

```ts
  isPastDue = isPastDue;
  formatDueDate = formatDueDate;
```

Add the badge styles:

```css
.kev-badge {
  display: inline-block; margin-top: 8px; font-size: var(--fs-xs); font-weight: 700; color: var(--bg);
  background: var(--sev-critical); padding: 3px 10px; border-radius: 999px;
}
.kev-badge.past-due { background: var(--sev-critical); outline: 2px solid var(--sev-critical); outline-offset: 1px; }
```

- [ ] **Step 2: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 3: Manual browser check**

Navigate to `/remediate/:itemId` for a KEV-listed item (per `CLAUDE.md`, profile 8's `microsoft windows_11_24h2` / `CVE-2024-49039` is the measured past-due, ransomware-associated case if still present in the dev DB). Confirm the badge renders with "ransomware-associated" and the past-due date.

- [ ] **Step 4: Commit**

```bash
git add frontend-v4/src/app/pages/remediate/remediation-guided.component.ts
git commit -m "feat(remediation): show a KEV badge on the guided page"
```

---

## Task 15: `core/remediation.ts` — `matchingGroup` and `actionCountFor` (Part 9 prep)

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (append)

**Interfaces:**
- Consumes: `RemediationQueueGroup`, `groupActions` (Task 3).
- Produces: `matchingGroup(groups, asset)`, `actionCountFor(group, itemId)`. Consumed by Task 16 (`RemediationWidgetComponent`, `ItemDetailComponent`).

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import { matchingGroup, actionCountFor } from './remediation';

describe('matchingGroup', () => {
  it('finds the group whose vendor/product match the asset', () => {
    const groups = [group({ vendor: 'apple', product: 'macos' }), group({ vendor: 'fortinet', product: 'fortios' })];
    expect(matchingGroup(groups, { vendor: 'fortinet', product: 'fortios' })).toBe(groups[1]);
  });
  it('is null when nothing matches', () => {
    expect(matchingGroup([], { vendor: 'apple', product: 'macos' })).toBeNull();
  });
});

describe('actionCountFor', () => {
  it('counts every item sharing the same fix as the given item', () => {
    const g = group({ items: [
      item({ itemId: 1, fix: { kind: 'version', value: '14.8.8' } }),
      item({ itemId: 2, fix: { kind: 'version', value: '14.8.8' } }),
      item({ itemId: 3, fix: { kind: 'none' } }),
    ] });
    expect(actionCountFor(g, 1)).toBe(2);
  });
  it('is 1 when the item matches nothing in the group (defensive default)', () => {
    expect(actionCountFor(group({ items: [] }), 999)).toBe(1);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `matchingGroup`/`actionCountFor` not exported.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
// ---- Part 9 prep: the intel detail page's remediation widget ----

// The queue's own per-asset grouping (Spec A's SQL groups by vendor/product) — this just finds
// the one group matching a given asset, so the widget can show the SAME progress fraction the
// queue page shows for this asset, not a second calculation of it.
export function matchingGroup(
  groups: RemediationQueueGroup[],
  asset: { vendor: string; product: string },
): RemediationQueueGroup | null {
  return groups.find((g) => g.vendor === asset.vendor && g.product === asset.product) ?? null;
}

// How many threats against this asset share the SAME fix as the one item the widget is showing
// — reuses groupActions (Part 1) rather than a second grouping rule, so "3 threats" on the
// widget always agrees with the count on the matching queue row.
export function actionCountFor(group: RemediationQueueGroup, itemId: number): number {
  const bucket = groupActions(group.items).find((a) => a.items.some((i) => i.itemId === itemId));
  return bucket?.count ?? 1;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests. Report the final total test count for `remediation.spec.ts` (grew from Spec B's original ~64 through this plan's Tasks 3, 4, 5, 6, 7, 8, 10, 11, 15).

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): add matchingGroup and actionCountFor for the intel-page widget"
```

---

## Task 16: The intel detail page loses `tf-playbook-panel`, gains `tf-remediation-widget` (Part 9)

**Files:**
- Create: `frontend-v4/src/app/ui/remediation-widget.component.ts`
- Modify: `frontend-v4/src/app/pages/intel/item-detail.component.ts`

**Interfaces:**
- Consumes: `RemediationSummary`, `RemediationQueueGroup` (Task 2), `fixWording` (Spec B), `groupProgress` (Spec B), `actionCountFor`, `matchingGroup` (Task 15).
- No new pure logic in the component itself — thin binding, same convention as every other `ui/` component. `tf-playbook-panel` stays in the codebase (the guided page's Step 4 is its only remaining consumer, per Part 9's own text) — this task only stops `item-detail.component.ts` from importing/rendering it.

- [ ] **Step 1: Create `RemediationWidgetComponent`**

Create `frontend-v4/src/app/ui/remediation-widget.component.ts`:

```ts
import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { PanelComponent } from './panel.component';
import { fixWording, groupProgress, actionCountFor } from '../core/remediation';
import type { RemediationSummary, RemediationQueueGroup } from '../core/models';

// Replaces the intel detail page's inline tf-playbook-panel (Part 9 — reversing Spec B's own
// call to keep it there, recorded rather than silently dropped: "removing it would make the
// detail page worse for the common case of a quick look" was Spec B's reasoning; Part 9 reverses
// it). A compact summary that links into the guided walkthrough rather than duplicating it.
//
// Progress is never invented (Part 9's own rule): it is groupProgress()'s own fraction
// (core/remediation.ts, Spec B) — how many of the asset's actions currently read not_covered —
// rendered only when the group's version is 'known', same rule the queue page's own progress bar
// already follows. When the version is unset there is no ring, only the action and its count.
@Component({
  selector: 'tf-remediation-widget',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [PanelComponent, RouterLink],
  template: `
    @if (remediation) {
      <tf-panel title="Remediation">
        <div class="row">
          @if (ring(); as r) {
            <span class="ring" role="progressbar" [attr.aria-valuenow]="r.done" [attr.aria-valuemax]="r.total">
              <svg viewBox="0 0 36 36">
                <circle class="track" cx="18" cy="18" r="15.5" />
                <circle class="fill" cx="18" cy="18" r="15.5"
                  stroke-dasharray="97.4"
                  [attr.stroke-dashoffset]="r.total ? 97.4 * (1 - r.done / r.total) : 97.4" />
              </svg>
              <span class="ring-label">{{ r.done }}/{{ r.total }}</span>
            </span>
          }
          <div class="body">
            <p class="headline">{{ headline() }}</p>
            <p class="count">{{ count() }} threat{{ count() === 1 ? '' : 's' }}</p>
          </div>
        </div>
        <a class="cta" [routerLink]="['/remediate', itemId]">Open the guided walkthrough &rarr;</a>
      </tf-panel>
    }
  `,
  styles: [`
    .row { display: flex; align-items: center; gap: 12px; }
    .ring { position: relative; width: 44px; height: 44px; flex: none; }
    .ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
    .track { fill: none; stroke: var(--surface-3); stroke-width: 3; }
    .fill {
      fill: none; stroke: var(--accent); stroke-width: 3; stroke-linecap: round;
      transition: stroke-dashoffset var(--dur-slow) var(--ease-out);
    }
    @media (prefers-reduced-motion: reduce) { .fill { transition: none; } }
    .ring-label {
      position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
      font-size: 9px; color: var(--ink-2);
    }
    .body { flex: 1; min-width: 0; }
    .headline { margin: 0; font-weight: 600; color: var(--ink); }
    .count { margin: 2px 0 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .cta { display: inline-block; margin-top: 10px; font-size: var(--fs-xs); color: var(--accent); text-decoration: none; }
    .cta:hover { text-decoration: underline; }
  `],
})
export class RemediationWidgetComponent {
  @Input() remediation: RemediationSummary | null = null;
  @Input() group: RemediationQueueGroup | null = null;
  @Input() itemId!: number;

  headline(): string {
    return this.remediation ? fixWording(this.remediation.fix).headline : '';
  }

  count(): number {
    return this.group ? actionCountFor(this.group, this.itemId) : 1;
  }

  ring(): { done: number; total: number } | null {
    return this.group ? groupProgress(this.group) : null;
  }
}
```

(Circle geometry note: `2 * PI * 15.5 ≈ 97.39`, rounded to `97.4` for the `stroke-dasharray`/`stroke-dashoffset` pair — matches the `r="15.5"` circle radius above.)

- [ ] **Step 2: Wire it into `item-detail.component.ts`, removing `tf-playbook-panel`**

In `frontend-v4/src/app/pages/intel/item-detail.component.ts`, remove this import:

```ts
import { PlaybookPanelComponent } from '../../ui/playbook-panel.component';
```

Add these imports:

```ts
import { RemediationWidgetComponent } from '../../ui/remediation-widget.component';
import { ApiService } from '../../core/api.service';
import { matchingGroup } from '../../core/remediation';
import type { RemediationDetail, RemediationQueueGroup } from '../../core/models';
```

(`ApiService` is already imported in this file — do not duplicate the import line, just confirm it's present; if it already is, skip re-adding it.)

In the `@Component` decorator's `imports` array, remove `PlaybookPanelComponent` and add `RemediationWidgetComponent`.

Find this block in the template:

```html
      @if (d.playbook; as pb) {
        <tf-playbook-panel [playbook]="pb" [itemId]="d.id" [dueDate]="d.relevance?.consequence?.urgency?.due ?? null" />
      }
```

Replace with:

```html
      <tf-remediation-widget
        [remediation]="remediation()?.remediation ?? null"
        [group]="remediationGroup()"
        [itemId]="d.id"
      />
```

In the class body, add the new state and loading logic. Find the existing signals block:

```ts
  detail = signal<ItemDetail | null>(null);
  loading = signal(true);
  notFound = signal(false);
  error = signal(false);
  related = signal<RelatedStory[]>([]);
  private expandedIps = signal<Set<string>>(new Set());
```

Replace with:

```ts
  detail = signal<ItemDetail | null>(null);
  loading = signal(true);
  notFound = signal(false);
  error = signal(false);
  related = signal<RelatedStory[]>([]);
  private expandedIps = signal<Set<string>>(new Set());

  // Part 9's widget state. Fetched independently of `detail` (a different route,
  // GET /api/items/:id/remediation) and only when a profile is active — the widget renders
  // nothing at all rather than an error state when there's no profile or no matching asset,
  // the same "no panel when there's nothing to say" posture "Possibly related" already uses.
  remediation = signal<RemediationDetail | null>(null);
  remediationGroup = signal<RemediationQueueGroup | null>(null);
```

Find the `loadDetail()` method's `next` callback:

```ts
    this.api.item(this.id).subscribe({
      next: (d) => {
        this.detail.set(d);
        this.loading.set(false);
        // The count is on the detail payload, so a second request only happens when there is
        // something to fetch. No panel is rendered when there are no links — an empty-state
        // placeholder would advertise a feature that has nothing to say about this item.
        if (d.clusterId != null && d.relatedStoryCount > 0) this.loadRelated(d.clusterId);
      },
```

Replace with:

```ts
    this.api.item(this.id).subscribe({
      next: (d) => {
        this.detail.set(d);
        this.loading.set(false);
        // The count is on the detail payload, so a second request only happens when there is
        // something to fetch. No panel is rendered when there are no links — an empty-state
        // placeholder would advertise a feature that has nothing to say about this item.
        if (d.clusterId != null && d.relatedStoryCount > 0) this.loadRelated(d.clusterId);
        this.loadRemediation();
      },
```

Add the two new private loader methods, near `loadRelated` (wherever that's defined further down the file):

```ts
  private loadRemediation(): void {
    this.remediation.set(null);
    this.remediationGroup.set(null);
    const profile = this.profileService.active();
    if (!profile) return; // No profile: the widget stays hidden, not an error state.
    this.api.itemRemediation(this.id).subscribe({
      next: (r) => {
        this.remediation.set(r);
        if (r.asset) this.loadRemediationGroup(r.asset);
      },
      error: () => { /* No CVE data, or the item-remediation route 404s — widget stays hidden. */ },
    });
  }

  private loadRemediationGroup(asset: { vendor: string; product: string }): void {
    const profile = this.profileService.active();
    if (!profile) return;
    this.api.remediationQueue(profile.id).subscribe({
      next: (groups) => this.remediationGroup.set(matchingGroup(groups, asset)),
      error: () => { /* Progress ring just doesn't render — the headline/count still will. */ },
    });
  }
```

Find the `paramMap` subscription inside the constructor, which resets state on navigation:

```ts
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      const id = Number(pm.get('id'));
      if (!Number.isInteger(id) || id <= 0) {
        this.notFound.set(true);
        this.loading.set(false);
        return;
      }
      this.id = id;
      this.detail.set(null);
      this.related.set([]);
      this.expandedIps.set(new Set());
      this.loadDetail();
    });
```

Replace with:

```ts
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      const id = Number(pm.get('id'));
      if (!Number.isInteger(id) || id <= 0) {
        this.notFound.set(true);
        this.loading.set(false);
        return;
      }
      this.id = id;
      this.detail.set(null);
      this.related.set([]);
      this.expandedIps.set(new Set());
      this.remediation.set(null);
      this.remediationGroup.set(null);
      this.loadDetail();
    });
```

- [ ] **Step 3: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 4: Manual browser check**

Navigate to `/intel/:id` for an item with a matched asset and a known version — confirm the widget renders with a progress ring, the correct action headline, and a working link into `/remediate/:id`. Then check an item with no matching asset — confirm the widget section is simply absent (no blank panel, no error). Confirm `tf-playbook-panel` no longer renders on this page but still renders correctly on `/remediate/:itemId`'s Step 4 (unchanged from Task 14).

- [ ] **Step 5: Full verification**

Run the full backend suite: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test` — expect PASS with the count from Task 1's Step 4 (667/665/0/2), unchanged by this task.

Run the full frontend suite: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run` — expect PASS with the count from Task 15's Step 4, unchanged by this task (this task adds no new `.spec.ts` assertions).

Report both actual numbers.

- [ ] **Step 6: Commit**

```bash
git add frontend-v4/src/app/ui/remediation-widget.component.ts frontend-v4/src/app/pages/intel/item-detail.component.ts
git commit -m "feat(remediation): replace the intel page's playbook panel with a remediation widget"
```

---

## Self-Review

**Spec coverage:**
- Part 1 (grouping) — Task 3 (`groupActions`), Task 12 (rendering).
- Part 2 (three-way split) — Task 5 (`actionStatus`/`splitActionsByStatus`), Task 12 (rendering, no-chrome-before-known-version rule).
- Part 3 (risk ordering, severity/KEV encoding) — Task 3 (stats), Task 4 (`sortActions`), Task 12 (stripe/figure/distribution/KEV badge rendering).
- Part 4 (filter, sort toggle, density) — Task 4 (reach mode), Task 6 (`filterQueueItems`), Task 13 (controls). `tabular-nums`/monospace called out in Task 12/13's CSS.
- Part 5 (provenance) — Task 10 (`actionProvenance`), Task 13 (disclosure rendering).
- Part 6 (ticket handoff) — Task 11 (`buildTicketText`), Task 13 (`tf-copy-button` wiring).
- Part 7 (reach diagram `AC`/`S`/per-metric) — Task 7 (core rewrite), Task 8 (layout math), Task 9 (component wiring).
- Part 8 (backend additive fields) — Task 1 (routes), Task 2 (types).
- Part 9 (intel page widget) — Task 15 (`matchingGroup`/`actionCountFor`), Task 16 (`RemediationWidgetComponent` + wiring).
- Non-goals respected throughout: no `fixTarget`/`remediationFor`/`affectedStatus`/`version_compare.js` edits (grep confirms no task touches those files), no `consequence.js` edits, no new severity palette (every colour reference is `severityToken`/`--sev-*`), no EPSS surface, no ticket-system client, no cross-asset bulk action.
- Testing section's bullet list, checked one by one: action grouping (Task 3), risk ordering incl. the measured 5-vs-111 case (Task 4), KEV ordering (Task 4), three-way split incl. no-version-bound-never-not_covered (Task 5), not_covered wording never "safe" (Task 5, plus Spec B's own existing assertion untouched), severity colour from the route string not re-derived (asserted structurally — `groupActions`/`sortActions` never call `severityFromScore`-equivalent logic, and the component task uses `severityToken(a.worstSeverity)` directly), diagram node selection across `AV`/`PR`/`UI`/`AC`/`S` incl. absent metrics/`S:C`/`:L` "partly" (Task 7), progress arithmetic null when not `known` (Spec B's existing `groupProgress`, reused unchanged by Task 15/16).

**Placeholder scan:** no "TBD"/"handle it"/"similar to Task N" left in any step; Task 12's `@template` note is the one deliberate exception — flagged explicitly as *not* valid syntax with the concrete replacement instruction, not a placeholder for unspecified work.

**Type consistency:** `RemediationAction`, `ActionSections`, `RiskReachMode`, `ProvenanceLine`, `DiagramEdgeLine` are each defined exactly once (Tasks 3, 5, 4, 10, 8 respectively) and referenced by the same names in every later task. `groupActions`/`sortActions`/`splitActionsByStatus`/`filterQueueItems`/`actionProvenance`/`buildTicketText`/`matchingGroup`/`actionCountFor` signatures are declared once each and called identically everywhere they're consumed.
