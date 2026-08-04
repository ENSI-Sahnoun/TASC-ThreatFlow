# Remediation Experience (Spec B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the remediation queue (`/remediate`) and the guided per-item page (`/remediate/:itemId`) — the UI Spec B describes over the data Spec A already shipped (`server/version_compare.js`, `server/remediation.js`, the three remediation routes, `profile_assets.version/version_state`).

**Architecture:** Two small, additive backend fields close gaps between what Spec A's routes return and what Spec B's UI needs (a per-item due date on the queue, and the matched asset's identity on the detail route) — everything else is frontend. All remediation-specific *logic* (grouping math, the "one upgrade closes N" rule, the Step 1 diagram's node selection, status wording, progress arithmetic) lives in one pure module, `frontend-v4/src/app/core/remediation.ts`, tested without a DOM (vitest, node environment, no TestBed — this app's existing convention for `relevance.ts`/`playbook.ts`). Two new routed page components (`RemediationQueueComponent`, `RemediationGuidedComponent`) and one new presentational SVG component (`ReachDiagramComponent`) stay thin bindings over that module, per this app's established split between "core owns facts and rules, components own templates."

**Tech Stack:** Node 22 (`/home/sah/.nvm/versions/node/v22.23.1/bin/node`) · Express 4 · PostgreSQL 16 (`node:test`, colocated `*.test.js`, isolated stores via `test-helpers.js`) · Angular 19 standalone components (vitest, no TestBed).

## Global Constraints

- Existing tokens only (`frontend-v4/src/app/core/tokens.css`). No new palette, no new radius scale. `--accent` marks the active step and the primary action, nothing else. Severity uses the existing `--sev-*` ramp; the remediation surface introduces no severity colours of its own.
- Motion: `--ease-out` for anything entering or responding to input; `--ease-in-out` only for on-screen repositioning. Blur (`backdrop-filter`) is chrome only, never on scrolling content. `prefers-reduced-motion: reduce` renders the finished state with no draw, everywhere motion is added.
- The `not_covered` wording is load-bearing and specified verbatim in the spec: "This range does not cover your build." + "Not a clean bill of health — confirm against the vendor advisory before treating it as closed." It must never read as "you are safe" — asserted directly in a test, not just implied by code shape.
- Every empty/degraded state is a designed state with real copy, never a blank panel.
- `fixTarget`'s ladder (Spec A, already shipped and tested) is not modified: `endExcluding` → `patch` → `advisory` → `none`, exclusive — a `kind: 'version'` result never also carries a patch URL inside `fix` itself. Step 3's "patch link beneath a version target" is served by a sibling `patchUrl` field added additively on the route (Spec Accuracy Finding 3), never by widening `fixTarget`'s return shape.
- Non-integer `:id`/`:itemId` route params in the backend already 404 (Spec A). No new backend route is added by this plan — only two additive fields on Spec A's existing two GET routes.
- Use absolute node/npm paths per `CLAUDE.md`: `/home/sah/.nvm/versions/node/v22.23.1/bin/node`, `/home/sah/.nvm/versions/node/v22.23.1/bin/npm`, `/home/sah/.nvm/versions/node/v22.23.1/bin/npx`.
- No `Co-Authored-By` or Claude/Anthropic attribution in any commit (user's global instruction).

---

## Spec Accuracy Findings

Recorded here per the spec's own instruction, rather than silently reshaping scope. Seven findings, all confirmed against the actual shipped code (`server/remediation.js`, `server/index.js`'s three routes, `frontend-v4/src/app/core/models.ts`) before writing any task below.

### 1. Spec A shipped zero frontend surface — `models.ts`/`api.service.ts` are untouched

Checking `git show --stat` on every Spec A commit: none of them touch `frontend-v4/src/app/core/models.ts` or `frontend-v4/src/app/core/api.service.ts`. `ProfileAsset` still has no `version`/`versionState` fields, and there is no `remediationQueue`/`itemRemediation`/`recordAssetVersion` method anywhere in `ApiService`. Spec A's plan title ("Remediation Foundation") only ever promised the backend contract; this plan's Task 2 is not optional scaffolding, it is the entire frontend data layer this feature is missing.

### 2. The queue mockup's "past due" and "fix by <date>" need a field the queue route doesn't return

The spec's `/remediate` ASCII mockup shows `CVE-2026-49793   affected    fix by Aug 17` and a header `3 past due`. `GET /api/profiles/:id/remediation` (Spec A, `server/index.js`) returns per item exactly `{ itemId, title, tier, score, status, installed, versionState, entry, fix, mitigations }` — no due date. The due date already exists per-item (`item_relevance.consequence.urgency.due`, the same field `relevance.ts`'s `tierSubline()` reads for the impact panel) and is cheap to add: one extra selected column, no new join. Task 1 adds `dueDate` to each queue item. This is additive to Spec A's shape (existing consumers of the route are unaffected) — it does not touch `remediationFor`/`fixTarget`, which stay exactly as Spec A wrote and tested them.

### 3. `fixTarget`'s `kind: 'version'` result cannot carry a patch link — resolved additively on the route, the same pattern Findings 2 and 4 already use

Step 3 of the spec says the `version` case renders "Upgrade to 10.0.26100.8875 or later, with the vendor's patch link beneath it if one exists." `fixTarget(entry, cveIntel)` (Spec A, `server/remediation.js`) is an exclusive ladder: the moment `entry.endExcluding` exists it returns `{ kind: 'version', value }` and never looks at `cveIntel.patchUrl` at all — that data is simply not *in the result*. Spec A's own test suite (`remediation.test.js`) asserts this precedence directly, and it is the correct behavior for what `fixTarget` is *for* (one fix target, not a hedge).

The fix is not to widen `fixTarget`'s return shape (that would mean changing Spec A's already-shipped, already-tested pure function) and not to duplicate the ladder's decision a second time client-side (two copies of "which fix wins" is exactly the kind of drift this codebase's pure-function convention exists to prevent). Both routes already have `cveIntel.patchUrl` in scope for the `remediationFor()` call itself (`{ patchUrl: r.patchUrl, advisoryUrl: r.advisoryUrl }` / `ci.patchUrl`) — the same object Finding 2's `dueDate` and Finding 4's `asset` are already added to, on the same route, for the same reason.

**Resolution:** Task 1 adds `patchUrl: string | null` as a sibling field next to `fix`/`remediation` on both routes — never inside `fix` itself, so `fixTarget`'s shape and Spec A's test suite are untouched. It is the literal `cveIntel.patchUrl` value, independent of which `fix.kind` was chosen; the frontend (Task 9) only *renders* it when `fix.kind === 'version'`, which is where the spec's "beneath it if one exists" conditional actually belongs — in presentation, not in the ladder's own decision.

### 4. The guided page needs the matched asset's `vendor`/`product` to write a version back, and the detail route doesn't expose it

Step 2's version form and Step 4's "record the new version" prompt both call `PATCH /api/profiles/:id/assets/:vendor/:product` — but `GET /api/items/:id/remediation` (Spec A) responds with `{ item, relevance, playbook, remediation }`, and `remediation` (the `remediationFor()` output) carries no `vendor`/`product` field; `entry.vendor`/`entry.product` exist only when `affected_versions` matched something, which is not guaranteed even when an asset is. The route already computes the matched `asset` row internally (`server/index.js`'s `const asset = await store.get(...)`) and simply doesn't return it. Task 1 adds `asset: { vendor, product, exposure } | null` to the response — the exact object the route already has in scope, not a new query.

### 5. "2 closed this week" in the queue header has no data source and is dropped

The queue route only ever returns *currently open* (`tier IN ('act_now','watch')`) items — there is no history table recording when an item transitioned to closed, and Spec A's plan explicitly scoped no such table. `item_relevance` is overwritten wholesale on every recompute (`profile_version` keys the current snapshot only), so "closed this week" cannot be derived, only fabricated. The queue header renders `{open} open · {pastDue} past due` and stops there — a real, computable pair, instead of a manufactured third number. The moment when items actually do clear (Step 4's version-record flow) still gets a real answer: `countCleared`/`versionRecordedMessage` (Task 5) compute it live, from an explicit before/after read, at the one moment the spec itself calls a fact rather than a running counter ("**generated from the recomputed statuses, never predicted before the write**").

### 6. The detail route's `playbook` field has no `done` array — Step 4's checklist would forget every tick on reload

`GET /api/items/:id/remediation` returns `playbook: pb ? pb.steps : null` — steps only. Compare `GET /api/items/:id` (the existing item-detail route), which additionally queries `playbook_step_state` and returns `{ steps, done }`; the frontend's `Playbook` type and `stepBlocks()`/`playbookProgress()` (`core/playbook.ts`) both require `done` to know which steps render as ticked. The guided page's Step 4 embeds the same `tf-playbook-panel`, and this page's own flow reloads the detail (`loadDetail()`) after every version write (Step 2's submit, Step 4's version-bump confirmation) — without `done`, each reload would render every step as unticked again, even though the underlying `playbook_step_state` rows the reader already ticked are still there server-side. Task 1 adds the same `done` query the existing route already runs, so `playbook` becomes `{ steps, done } | null` instead of `steps | null`.

### 7. "One upgrade closes N" and the per-asset progress bar are correctly computable client-side without new backend work — but the interpretation had to be worked out from the actual route shape, not the mockup

The spec's Testing section asks for client-side "grouping by asset, and the sort within a group" — but `GET /api/profiles/:id/remediation` *already* groups by `(vendor, product)` and sorts within a group by `ir.score DESC` (Spec A, `server/index.js`). Re-implementing that client-side would be a second, potentially-drifting copy of a decision the backend already made once. What the spec's tests actually need, read against the real shape, is one level deeper: `oneUpgradeCloses` groups *within* an already-grouped asset's items by `fix.value` (only for `kind: 'version'` fixes) — genuine client-side logic the backend does not compute. Likewise, the mockup's progress bar ("4 of 6") cannot mean "closed vs. ever-opened" (no history, per Finding 5); it is defined here as "of the items currently matched to this asset, how many already read `not_covered`" — fully derivable from the queue response, and it correctly returns nothing (no bar shown) when `versionState !== 'known'`, matching the spec's own rule that progress against an unknown version is not measurable.

---

## Task 1: Backend — four additive fields the frontend needs (`dueDate`, `patchUrl`, matched `asset`, playbook `done`)

**Files:**
- Modify: `server/index.js` (both remediation GET routes)
- Test: `server/api.test.js` (append)

**Interfaces:**
- Produces: `GET /api/profiles/:id/remediation` — each item in a group's `items[]` gains `dueDate: string | null` (the `YYYY-MM-DD` KEV due date) and `patchUrl: string | null` (the CVE's vendor patch URL, independent of which `fix.kind` was chosen — see Spec Accuracy Finding 3). `GET /api/items/:id/remediation` — the response gains `asset: { vendor: string; product: string; exposure: string } | null` (the same asset row already computed for `remediationFor`, or `null` when none matched), a top-level `patchUrl: string | null` (same field, same reasoning), and `playbook` changes shape from `steps[] | null` to `{ steps, done } | null` (adding the same `playbook_step_state` query `GET /api/items/:id` already runs).
- Consumes: nothing new — every addition reads data the routes already have in scope (`ir.consequence`, `r.patchUrl`/`ci.patchUrl`, the existing `asset` local) or a query the sibling route already runs (`playbook_step_state`). `fixTarget`/`remediationFor` (Spec A) are not touched — `patchUrl` is added as a sibling of `remediation`/`fix`, never inside it.

- [ ] **Step 1: Write the failing tests**

First, update the one pre-existing test this task's shape change breaks — `server/api.test.js`'s `'GET /api/items/:id/remediation returns remediationFor output plus relevance and playbook'` (Spec A) currently asserts `assert.ok(Array.isArray(res.body.playbook));`. Change that one line to:

```js
    assert.ok(Array.isArray(res.body.playbook.steps));
```

Then append the new tests to `server/api.test.js`:

```js
test('GET /api/profiles/:id/remediation surfaces each item\'s KEV due date', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run("UPDATE cve_intel SET kev_due_date = '2026-08-17' WHERE cve_id = 'CVE-2026-1'");
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/profiles/${created.body.id}/remediation`);
    assert.strictEqual(res.status, 200);
    const item = res.body[0].items.find((i) => i.itemId === hitId);
    assert.strictEqual(item.dueDate, '2026-08-17');
  } finally { await cleanup(); }
});

test('GET /api/profiles/:id/remediation reports dueDate: null when the item has no KEV due date', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/profiles/${created.body.id}/remediation`);
    const item = res.body[0].items.find((i) => i.itemId === hitId);
    assert.strictEqual(item.dueDate, null);
  } finally { await cleanup(); }
});

// Finding 3's resolution: patchUrl travels alongside fix (never inside it), so a kind: 'version'
// fix (endExcluding-driven) can still be shown next to the vendor's patch link.
test('GET /api/profiles/:id/remediation surfaces patchUrl alongside fix, even when fix.kind is version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run(
      `UPDATE cve_intel SET patch_url = 'https://example.com/patch', affected_versions = $1 WHERE cve_id = 'CVE-2026-1'`,
      [JSON.stringify([{
        vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5',
        startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: '7.4.5', pinned: null,
      }])]);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/profiles/${created.body.id}/remediation`);
    const item = res.body[0].items.find((i) => i.itemId === hitId);
    assert.strictEqual(item.fix.kind, 'version');
    assert.strictEqual(item.patchUrl, 'https://example.com/patch');
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation includes the matched asset\'s vendor/product/exposure', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/items/${hitId}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body.asset, { vendor: 'fortinet', product: 'fortios', exposure: 'unknown' });
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation reports asset: null when no profile_assets row matches', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { missId } = await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    const res = await get(app, `/api/items/${missId}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.asset, null);
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation surfaces patchUrl at the top level, even when fix.kind is version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run(
      `UPDATE cve_intel SET patch_url = 'https://example.com/patch', affected_versions = $1 WHERE cve_id = 'CVE-2026-1'`,
      [JSON.stringify([{
        vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5',
        startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: '7.4.5', pinned: null,
      }])]);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/items/${hitId}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.remediation.fix.kind, 'version');
    assert.strictEqual(res.body.patchUrl, 'https://example.com/patch');
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation returns playbook as { steps, done }, carrying already-ticked steps', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    // Tick a step through the existing playbook-step route before reading remediation detail.
    const before = await get(app, `/api/items/${hitId}/remediation?profileId=${created.body.id}`);
    const firstKey = before.body.playbook.steps[0].key;
    await send(app, 'POST', `/api/items/${hitId}/playbook/steps/${firstKey}`, null,
      { 'X-Profile-Id': String(created.body.id) });

    const res = await get(app, `/api/items/${hitId}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.playbook.steps));
    assert.deepStrictEqual(res.body.playbook.done, [firstKey]);
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: FAIL — `item.dueDate` is `undefined`, `res.body.asset` is `undefined`.

- [ ] **Step 3: Implement**

In `server/index.js`, in the `GET /api/profiles/:id/remediation` handler, add `ir.consequence` to the `SELECT` list (it already selects `ir.tier, ir.score` — add the column right after `ir.score`):

```js
             i.id AS "itemId", i.title, ir.tier, ir.score, ir.consequence,
```

Then in the per-item push, add `dueDate` and `patchUrl` (the latter is Finding 3's resolution: a sibling of the `remediationFor()` spread, not a change to it — `r.patchUrl` is already read two lines above to build `remediationFor`'s own `cveIntel` argument):

```js
      const rem = remediationFor(asset, r.affectedVersions || [], { patchUrl: r.patchUrl, advisoryUrl: r.advisoryUrl }, r.steps || []);
      const dueDate = (r.consequence && r.consequence.urgency && r.consequence.urgency.due) || null;
      groups.get(key).items.push({
        itemId: r.itemId, title: r.title, tier: r.tier, score: r.score, dueDate,
        patchUrl: r.patchUrl || null, ...rem,
      });
```

In the `GET /api/items/:id/remediation` handler, find where `pb` is fetched:

```js
    const pb = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2 AND profile_version=$3',
      [id, profile.id, profile.profile_version]);
```

Right after it, add the same `playbook_step_state` query `GET /api/items/:id` already runs:

```js
    const pb = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2 AND profile_version=$3',
      [id, profile.id, profile.profile_version]);
    // Same query GET /api/items/:id already runs — without it, every reload of the guided page
    // (Step 2's version submit and Step 4's version-bump confirmation both call loadDetail())
    // would render every step as unticked again, even though the rows are still there.
    const pbDone = pb
      ? (await store.all(
          'SELECT step_key FROM playbook_step_state WHERE item_id = $1 AND profile_id = $2',
          [id, profile.id])).map((r) => r.step_key)
      : [];
```

Then find the response, which currently ends with:

```js
    res.json({
      item,
      relevance: rel ? { tier: rel.tier, matches: rel.matches, consequence: rel.consequence } : null,
      playbook: pb ? pb.steps : null,
      remediation,
    });
```

Change it to:

```js
    res.json({
      item,
      relevance: rel ? { tier: rel.tier, matches: rel.matches, consequence: rel.consequence } : null,
      playbook: pb ? { steps: pb.steps, done: pbDone } : null,
      remediation,
      // The asset the reader would write a version onto (Spec B's Step 2/Step 4 forms both PATCH
      // /api/profiles/:id/assets/:vendor/:product) — the route already resolves this row for
      // remediationFor above; this just also returns it, since remediation itself carries no
      // vendor/product (entry.vendor/product only exist when affected_versions matched).
      asset: asset ? { vendor: asset.vendor, product: asset.product, exposure: asset.exposure } : null,
      // Finding 3's resolution: sibling of `remediation`, never inside `fix` — `ci` (fetched
      // above for remediationFor's own cveIntel argument) already carries this.
      patchUrl: (ci && ci.patchUrl) || null,
    });
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: PASS, all tests including the seven new ones and the one updated assertion.

Run the full backend suite:
Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add server/index.js server/api.test.js
git commit -m "feat(remediation): surface item due dates and the matched asset on the two GET routes"
```

---

## Task 2: Frontend data layer — `models.ts` types + `api.service.ts` methods

**Files:**
- Modify: `frontend-v4/src/app/core/models.ts`
- Modify: `frontend-v4/src/app/core/api.service.ts`

**Interfaces:**
- Consumes: Task 1's two response shapes.
- Produces: `ProfileAsset` gains `version: string | null; versionState: VersionState`. New types: `VersionState`, `AffectedVersionEntry`, `RemediationFix`, `RemediationSummary`, `RemediationQueueItem`, `RemediationQueueGroup`, `RemediationItemRow`, `RemediationDetail`. New `ApiService` methods: `remediationQueue(profileId): Observable<RemediationQueueGroup[]>`, `itemRemediation(itemId): Observable<RemediationDetail>`, `recordAssetVersion(profileId, vendor, product, body): Observable<ProfileAsset>`. Consumed by Tasks 3–9.

No test file — this is a pure type/API-surface addition with no branching logic, same posture as every other `ApiService` method (no `api.service.spec.ts` exists in this codebase; verified by `tsc` plus every later task that actually exercises these types).

- [ ] **Step 1: Add the types to `models.ts`**

In `frontend-v4/src/app/core/models.ts`, replace the existing `ProfileAsset` interface:

```ts
// The tech-stack rows that actually earn urgency. The legacy vendors/products arrays are kept
// but cap at the `low` tier.
export interface ProfileAsset {
  vendor: string;
  product: string;
  exposure: Exposure;
}
```

with:

```ts
export type VersionState = 'unset' | 'known' | 'unknown';

// The tech-stack rows that actually earn urgency. The legacy vendors/products arrays are kept
// but cap at the `low` tier.
export interface ProfileAsset {
  vendor: string;
  product: string;
  exposure: Exposure;
  // The version a reader told us they run on this asset, and whether they were ever asked.
  // 'unset' (never asked) is distinct from 'unknown' (asked, declined) — collapsing them would
  // make the remediation page re-nag on every visit. See server/db.js's profile_assets columns.
  version: string | null;
  versionState: VersionState;
}
```

Then, after the `Relevance` interface (which ends just above `// Model-assigned signal quality...`), add:

```ts
// ---- Remediation (Spec B) ----

// One cve_intel.affected_versions element, exactly as server/consolidate.js's versionBounds()
// produces it and server/version_compare.js / server/remediation.js consume it.
export interface AffectedVersionEntry {
  vendor: string;
  product: string;
  text: string;
  startIncluding: string | null;
  startExcluding: string | null;
  endIncluding: string | null;
  endExcluding: string | null;
  pinned: string | null;
}

// server/remediation.js's fixTarget() ladder: endExcluding, then patch, then advisory, then
// none — exclusive, never a hedge between cases. A 'version' result never also carries a patch
// URL inside itself — endIncluding/pinned never produce 'version' at all (server/remediation.js's
// fabrication guard). See RemediationQueueItem.patchUrl / RemediationDetail.patchUrl for how a
// patch link is still shown alongside a 'version' fix (Spec Accuracy Finding 3): as a sibling
// field the route adds independently, never as a variant of this type.
export type RemediationFix =
  | { kind: 'version'; value: string }
  | { kind: 'patch'; value: string }
  | { kind: 'advisory'; value: string }
  | { kind: 'none' };

// server/remediation.js's remediationFor() output — one asset x one item.
export interface RemediationSummary {
  status: 'affected' | 'not_covered' | 'unknown';
  installed: string | null;
  versionState: VersionState;
  entry: AffectedVersionEntry | null;
  fix: RemediationFix;
  mitigations: PlaybookStep[];
}

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

// One element of GET /api/profiles/:id/remediation's response array — one profile_assets row
// plus every open (act_now/watch) threat matched to it.
export interface RemediationQueueGroup {
  vendor: string;
  product: string;
  exposure: Exposure;
  version: string | null;
  versionState: VersionState;
  items: RemediationQueueItem[];
}

// The `item` row from GET /api/items/:id/remediation — a raw `items` table SELECT *, narrower
// than ItemDetail: no source name, no cves/iocs/entities. The guided page links back to
// /intel/:id for everything this type doesn't carry.
export interface RemediationItemRow {
  id: number;
  title: string;
  summary: string | null;
  category: string;
  severity: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  link: string | null;
  published_at: string | null;
}

// GET /api/items/:id/remediation's full response. `playbook` is the same { steps, done } shape
// GET /api/items/:id already returns (Task 1 adds the matching playbook_step_state query to this
// route too) — reusing the existing Playbook type rather than a bespoke steps-only array, so a
// reload after a version write doesn't forget which steps were already ticked.
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

- [ ] **Step 2: Add the methods to `api.service.ts`**

In `frontend-v4/src/app/core/api.service.ts`, add to the type-only import block:

```ts
import type {
  DashboardStats, FeedRow, Source, SourceStats, Item, ItemDetail,
  CveIntel, CveDetail, EntityProfile, SearchResults, Facets, ClusterMember, IocRow, IocCheckResult,
  PreviewCheck, Profile, ProfilePayload, Sector, CpeFacet, DomainOption, RelatedStory,
  ProfileAsset, VersionState, RemediationQueueGroup, RemediationDetail,
} from './models';
```

Then, after the existing `cpeFacets(...)` method (the last method in the class, right before the closing `}`), add:

```ts

  // The remediation queue: every asset the profile has told us about, each carrying its open
  // (act_now/watch) threats and what remediationFor already decided about each. Grouped and
  // sorted server-side (server/index.js) — nothing here re-derives that grouping.
  remediationQueue(profileId: number): Observable<RemediationQueueGroup[]> {
    return this.http.get<RemediationQueueGroup[]>(`/api/profiles/${profileId}/remediation`);
  }

  // Per-item remediation detail for the guided page. X-Profile-Id travels via
  // profileInterceptor, same as every other profile-scoped call — no query param needed here.
  itemRemediation(itemId: number): Observable<RemediationDetail> {
    return this.http.get<RemediationDetail>(`/api/items/${itemId}/remediation`);
  }

  // Records a version on one asset. Omitting versionState lets the server infer it — a version
  // implies 'known', its absence implies 'unknown' (server/index.js's PATCH handler); 'unset' is
  // never reachable through this call, by design.
  recordAssetVersion(
    profileId: number, vendor: string, product: string,
    body: { version?: string | null; versionState?: VersionState },
  ): Observable<ProfileAsset> {
    return this.http.patch<ProfileAsset>(
      `/api/profiles/${profileId}/assets/${encodeURIComponent(vendor)}/${encodeURIComponent(product)}`, body);
  }
```

- [ ] **Step 3: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors. (If any other file constructs a `ProfileAsset` literal without `version`/`versionState`, this is where it will show up — Finding checked in advance: no such literal exists in the current codebase.)

- [ ] **Step 4: Commit**

```bash
git add frontend-v4/src/app/core/models.ts frontend-v4/src/app/core/api.service.ts
git commit -m "feat(remediation): add ProfileAsset version fields, remediation types and API methods"
```

---

## Task 3: `core/remediation.ts` — queue math (due dates, progress, the "one upgrade closes N" rule)

**Files:**
- Create: `frontend-v4/src/app/core/remediation.ts`
- Create: `frontend-v4/src/app/core/remediation.spec.ts`

**Interfaces:**
- Consumes: `RemediationQueueItem`, `RemediationQueueGroup` (Task 2).
- Produces: `isPastDue(dueDate, now?)`, `formatDueDate(iso)`, `groupHasPastDue(items, now?)`, `queueSummary(groups, now?)`, `groupProgress(group)`, `oneUpgradeCloses(items)`. Consumed by Task 8 (`RemediationQueueComponent`).

- [ ] **Step 1: Write the failing tests**

Create `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  isPastDue, formatDueDate, groupHasPastDue, queueSummary, groupProgress, oneUpgradeCloses,
} from './remediation';
import type { RemediationQueueGroup, RemediationQueueItem } from './models';

const item = (over: Partial<RemediationQueueItem> = {}): RemediationQueueItem => ({
  itemId: 1, title: 'T', tier: 'act_now', score: 1,
  status: 'affected', installed: null, versionState: 'unset', entry: null,
  fix: { kind: 'none' }, mitigations: [], dueDate: null,
  ...over,
});

const group = (over: Partial<RemediationQueueGroup> = {}): RemediationQueueGroup => ({
  vendor: 'fortinet', product: 'fortios', exposure: 'unknown',
  version: null, versionState: 'unset', items: [],
  ...over,
});

describe('isPastDue', () => {
  const now = new Date('2026-08-04T00:00:00Z');
  it('is false for a null due date', () => {
    expect(isPastDue(null, now)).toBe(false);
  });
  it('is true for a date before now', () => {
    expect(isPastDue('2026-07-01', now)).toBe(true);
  });
  it('is false for a date after now', () => {
    expect(isPastDue('2026-12-01', now)).toBe(false);
  });
  it('is false for an unparseable date rather than throwing', () => {
    expect(isPastDue('not-a-date', now)).toBe(false);
  });
});

describe('formatDueDate', () => {
  it('formats an ISO date as "Mon D"', () => {
    expect(formatDueDate('2026-08-17')).toBe('Aug 17');
  });
  it('passes through an unparseable value rather than rendering "Invalid Date"', () => {
    expect(formatDueDate('garbage')).toBe('garbage');
  });
});

describe('groupHasPastDue', () => {
  const now = new Date('2026-08-04T00:00:00Z');
  it('is true when at least one open item is past its due date', () => {
    const items = [item({ dueDate: '2026-07-01', status: 'affected' })];
    expect(groupHasPastDue(items, now)).toBe(true);
  });
  it('is false when the only past-due item already reads not_covered', () => {
    const items = [item({ dueDate: '2026-07-01', status: 'not_covered' })];
    expect(groupHasPastDue(items, now)).toBe(false);
  });
  it('is false with no items', () => {
    expect(groupHasPastDue([], now)).toBe(false);
  });
});

describe('queueSummary', () => {
  const now = new Date('2026-08-04T00:00:00Z');
  it('counts open items across all groups, excluding not_covered', () => {
    const groups = [
      group({ items: [item({ status: 'affected' }), item({ status: 'not_covered' })] }),
      group({ vendor: 'microsoft', product: 'windows', items: [item({ status: 'unknown' })] }),
    ];
    expect(queueSummary(groups, now).open).toBe(2);
  });
  it('counts past-due open items across all groups', () => {
    const groups = [
      group({ items: [
        item({ status: 'affected', dueDate: '2026-07-01' }),
        item({ status: 'affected', dueDate: '2026-12-01' }),
        item({ status: 'not_covered', dueDate: '2026-01-01' }),
      ] }),
    ];
    expect(queueSummary(groups, now)).toEqual({ open: 2, pastDue: 1 });
  });
  it('is all zero for an empty queue', () => {
    expect(queueSummary([], now)).toEqual({ open: 0, pastDue: 0 });
  });
});

describe('groupProgress', () => {
  it('is null when the version has never been asked (unset) — progress is not measurable', () => {
    expect(groupProgress(group({ versionState: 'unset', items: [item()] }))).toBeNull();
  });
  it('is null when the reader declined to say (unknown) — same reason, does not re-ask', () => {
    expect(groupProgress(group({ versionState: 'unknown', items: [item()] }))).toBeNull();
  });
  it('reports done/total from not_covered items once a version is known', () => {
    const items = [
      item({ itemId: 1, status: 'not_covered' }),
      item({ itemId: 2, status: 'not_covered' }),
      item({ itemId: 3, status: 'affected' }),
    ];
    expect(groupProgress(group({ versionState: 'known', version: '7.0.0', items }))).toEqual({ done: 2, total: 3 });
  });
  it('is 0 of 0 for a known version with no items, not null', () => {
    expect(groupProgress(group({ versionState: 'known', version: '7.0.0', items: [] }))).toEqual({ done: 0, total: 0 });
  });
});

describe('oneUpgradeCloses', () => {
  it('fires at two items sharing the same version fix target', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'version', value: '7.4.5' } }),
      item({ itemId: 2, fix: { kind: 'version', value: '7.4.5' } }),
    ];
    expect(oneUpgradeCloses(items)).toEqual({ value: '7.4.5', count: 2 });
  });
  it('does not fire for a single item, even with a version fix', () => {
    const items = [item({ itemId: 1, fix: { kind: 'version', value: '7.4.5' } })];
    expect(oneUpgradeCloses(items)).toBeNull();
  });
  it('never fires for patch targets, however many share the same URL', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'patch', value: 'https://x/patch' } }),
      item({ itemId: 2, fix: { kind: 'patch', value: 'https://x/patch' } }),
    ];
    expect(oneUpgradeCloses(items)).toBeNull();
  });
  it('never fires for advisory or none targets', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'advisory', value: 'https://x/a' } }),
      item({ itemId: 2, fix: { kind: 'advisory', value: 'https://x/a' } }),
      item({ itemId: 3, fix: { kind: 'none' } }),
      item({ itemId: 4, fix: { kind: 'none' } }),
    ];
    expect(oneUpgradeCloses(items)).toBeNull();
  });
  it('picks the larger group when two different version targets both qualify', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'version', value: '7.4.5' } }),
      item({ itemId: 2, fix: { kind: 'version', value: '7.4.5' } }),
      item({ itemId: 3, fix: { kind: 'version', value: '7.4.5' } }),
      item({ itemId: 4, fix: { kind: 'version', value: '9.0.0' } }),
      item({ itemId: 5, fix: { kind: 'version', value: '9.0.0' } }),
    ];
    expect(oneUpgradeCloses(items)).toEqual({ value: '7.4.5', count: 3 });
  });
  it('never counts one item twice even if fix values were somehow duplicated in the array', () => {
    const shared = item({ itemId: 1, fix: { kind: 'version', value: '7.4.5' } });
    const items = [shared, item({ itemId: 2, fix: { kind: 'version', value: '7.4.5' } })];
    expect(oneUpgradeCloses(items)!.count).toBe(items.length);
  });
  it('is null for an empty list', () => {
    expect(oneUpgradeCloses([])).toBeNull();
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `Cannot find module './remediation'`.

- [ ] **Step 3: Implement**

Create `frontend-v4/src/app/core/remediation.ts`:

```ts
import type { RemediationQueueGroup, RemediationQueueItem } from './models';

// Presentation and derived math over Spec A's remediation routes. Pure, no HTTP, no DOM — this
// app runs vitest in a node environment with no TestBed by design, so every rule the remediation
// pages need is specified and tested here; the components stay thin bindings over it.

// ---- due dates ----

export function isPastDue(dueDate: string | null, now: Date = new Date()): boolean {
  if (!dueDate) return false;
  const d = new Date(dueDate);
  if (Number.isNaN(d.getTime())) return false;
  return d.getTime() < now.getTime();
}

// Same formatting relevance.ts's tierSubline() and playbook-panel.component.ts's local
// formatDue() already use — kept as its own small copy here rather than a shared import, per
// this app's existing precedent of each call site owning its own one-liner.
export function formatDueDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
}

// A group is past due when at least one of its still-open items (not already not_covered) has
// slipped its due date. A cleared item's old due date is not a live commitment any more.
export function groupHasPastDue(items: RemediationQueueItem[], now: Date = new Date()): boolean {
  return items.some((i) => i.status !== 'not_covered' && isPastDue(i.dueDate, now));
}

// ---- header summary ----

export interface QueueSummary {
  open: number;
  pastDue: number;
}

// "Open" excludes not_covered: a range that no longer covers the reader's build is resolved for
// this asset, not a live threat, even though the row still renders (Spec A's tier scoring does
// not factor in version status — see CLAUDE.md's relevance_score.js note — so the item stays in
// the query result; this is where "open" is actually decided for the UI).
export function queueSummary(groups: RemediationQueueGroup[], now: Date = new Date()): QueueSummary {
  let open = 0;
  let pastDue = 0;
  for (const g of groups) {
    for (const item of g.items) {
      if (item.status === 'not_covered') continue;
      open += 1;
      if (isPastDue(item.dueDate, now)) pastDue += 1;
    }
  }
  return { open, pastDue };
}

// ---- per-asset progress ----

export interface GroupProgress {
  done: number;
  total: number;
}

// null when progress is not measurable at all (version never asked, or asked and declined) —
// the spec's own rule: an asset with version_state 'unset' shows a "tell us" affordance instead
// of a bar, and 'unknown' shows the threats without a bar and does not re-ask. Only 'known'
// produces a real fraction: how many of the items currently matched to this asset already read
// not_covered (i.e. the version on file is already past their range) out of every item matched.
export function groupProgress(group: RemediationQueueGroup): GroupProgress | null {
  if (group.versionState !== 'known') return null;
  const total = group.items.length;
  const done = group.items.filter((i) => i.status === 'not_covered').length;
  return { done, total };
}

// ---- "one upgrade closes N" ----

export interface UpgradeCloses {
  value: string;
  count: number;
}

// Fires only when two or more items in the SAME asset group share the same kind: 'version' fix
// target — never for patch/advisory/none, because two patch URLs are not one action, and a
// single vendor advisory page is not "one upgrade" either. When more than one version value
// would qualify, the larger group wins (the more consequential single action to surface).
export function oneUpgradeCloses(items: RemediationQueueItem[]): UpgradeCloses | null {
  const counts = new Map<string, number>();
  for (const item of items) {
    if (item.fix.kind !== 'version') continue;
    counts.set(item.fix.value, (counts.get(item.fix.value) ?? 0) + 1);
  }
  let best: UpgradeCloses | null = null;
  for (const [value, count] of counts) {
    if (count >= 2 && (!best || count > best.count)) best = { value, count };
  }
  return best;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): add queue math — due dates, progress, one-upgrade-closes-N"
```

---

## Task 4: `core/remediation.ts` — the Step 1 diagram as a pure function

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (append)

**Interfaces:**
- Produces: `parseVectorMetrics(vector)`, `DiagramNode`, `DiagramAnnotation`, `ReachDiagram`, `reachDiagram(metrics)`. Consumed by Task 6 (`ReachDiagramComponent`) and Task 9 (`RemediationGuidedComponent`).

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import { parseVectorMetrics, reachDiagram } from './remediation';

describe('parseVectorMetrics', () => {
  it('extracts a v3.1 vector\'s metrics into an uppercase map', () => {
    expect(parseVectorMetrics('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))
      .toEqual({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  });
  it('is null for null/undefined/non-string input', () => {
    expect(parseVectorMetrics(null)).toBeNull();
    expect(parseVectorMetrics(undefined)).toBeNull();
  });
  it('is null for a string with no CVSS: prefix', () => {
    expect(parseVectorMetrics('AV:N/AC:L')).toBeNull();
  });
});

describe('reachDiagram', () => {
  it('AV:N reads as the internet', () => {
    const d = reachDiagram({ AV: 'N', PR: 'N', UI: 'N', C: 'H', I: 'H', A: 'H' });
    expect(d.nodes[0].title).toBe('The internet');
    expect(d.nodes[0].from).toBe('AV:N');
  });
  it('AV:A reads as the adjacent network', () => {
    expect(reachDiagram({ AV: 'A' }).nodes[0].title).toBe('Adjacent network');
  });
  it('AV:L reads as already on the machine', () => {
    expect(reachDiagram({ AV: 'L' }).nodes[0].title).toBe('Already on the machine');
  });
  it('AV:P reads as physical access', () => {
    expect(reachDiagram({ AV: 'P' }).nodes[0].title).toBe('Physical access');
  });
  it('an absent or unrecognised AV is a stated gap, not a guess', () => {
    const noAv = reachDiagram({});
    expect(noAv.nodes[0].title).toBe('Reach not stated');
    const badAv = reachDiagram({ AV: 'X' });
    expect(badAv.nodes[0].title).toBe('Reach not stated');
    expect(badAv.nodes[0].from).toBe('AV:X');
  });

  it('PR:N reads as no account needed', () => {
    expect(reachDiagram({ PR: 'N' }).nodes[1].title).toBe('No account needed');
  });
  it('PR:L reads as a normal account', () => {
    expect(reachDiagram({ PR: 'L' }).nodes[1].title).toBe('A normal account');
  });
  it('PR:H reads as an admin account', () => {
    expect(reachDiagram({ PR: 'H' }).nodes[1].title).toBe('An admin account');
  });
  it('an absent PR is a stated gap', () => {
    expect(reachDiagram({}).nodes[1].title).toBe('Privilege not stated');
  });

  it('UI:N annotates the gate node with "needs nothing from anyone"', () => {
    const d = reachDiagram({ UI: 'N' });
    expect(d.gateAnnotation).toEqual({ text: 'needs nothing from anyone', from: 'UI:N' });
  });
  it('UI:R annotates the gate node with "needs someone to click something"', () => {
    const d = reachDiagram({ UI: 'R' });
    expect(d.gateAnnotation).toEqual({ text: 'needs someone to click something', from: 'UI:R' });
  });
  it('an absent UI produces no annotation at all, not a fabricated one', () => {
    expect(reachDiagram({}).gateAnnotation).toBeNull();
  });

  it('fills the outcome node with read/change/shut down only for H-valued C/I/A', () => {
    const d = reachDiagram({ C: 'H', I: 'H', A: 'H' });
    expect(d.nodes[2].title).toBe('read, change and shut down');
    expect(d.nodes[2].from).toBe('C:H/I:H/A:H');
  });
  it('a single H metric produces a single verb', () => {
    expect(reachDiagram({ C: 'H' }).nodes[2].title).toBe('read');
  });
  it('two H metrics join with "and", not a comma list', () => {
    expect(reachDiagram({ C: 'H', A: 'H' }).nodes[2].title).toBe('read and shut down');
  });
  it('an L-valued metric never reaches the outcome node — only H does', () => {
    const d = reachDiagram({ C: 'L', I: 'L', A: 'L' });
    expect(d.nodes[2].title).toBe('No full-control outcome');
  });
  it('no metrics at all is a stated gap on the outcome node too', () => {
    expect(reachDiagram({}).nodes[2].title).toBe('No full-control outcome');
  });

  it('null metrics produces the same three stated-gap nodes as an empty object', () => {
    expect(reachDiagram(null)).toEqual(reachDiagram({}));
  });

  it('always returns exactly two edges, origin->gate and gate->outcome', () => {
    const d = reachDiagram({ AV: 'N', PR: 'N' });
    expect(d.edges).toEqual([{ from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }]);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — `parseVectorMetrics`/`reachDiagram` not exported.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
// ---- Step 1 diagram: origin -> gate -> outcome ----
//
// Mirrors server/cvss.js's parseVector() metric extraction (client-side, since the guided page
// only ever receives the raw vector string, never pre-parsed metrics) — kept intentionally
// minimal: this extracts the metric map only, it does not score anything.
export function parseVectorMetrics(vector: string | null | undefined): Record<string, string> | null {
  if (typeof vector !== 'string') return null;
  const s = vector.trim();
  const m = s.match(/^CVSS:(\d\.\d)\/(.+)$/i);
  if (!m) return null;
  const metrics: Record<string, string> = {};
  for (const part of m[2].split('/')) {
    const [k, v] = part.split(':');
    if (k && v) metrics[k.toUpperCase()] = v.toUpperCase();
  }
  return metrics;
}

export interface DiagramNode {
  id: 'origin' | 'gate' | 'outcome';
  title: string;
  detail: string;
  from: string;
}

export interface DiagramAnnotation {
  text: string;
  from: string;
}

export interface ReachDiagram {
  nodes: [DiagramNode, DiagramNode, DiagramNode];
  edges: { from: string; to: string }[];
  gateAnnotation: DiagramAnnotation | null;
}

// Exact wording from the spec's own prose ("N internet, A adjacent network, L already on the
// machine, P physical access") — not the spec's own ASCII sketch, which mislabels the AV:L box
// as "already on network"; the prose is the more precise of the two and is what this follows.
const ORIGIN: Record<string, { title: string; detail: string }> = {
  N: { title: 'The internet', detail: 'Reachable without being on the network first' },
  A: { title: 'Adjacent network', detail: 'Reachable from the same network segment' },
  L: { title: 'Already on the machine', detail: 'Requires local access to the system first' },
  P: { title: 'Physical access', detail: 'Requires physically touching the device' },
};

const GATE: Record<string, { title: string; detail: string }> = {
  N: { title: 'No account needed', detail: 'No credentials are required' },
  L: { title: 'A normal account', detail: 'Any ordinary user account is enough' },
  H: { title: 'An admin account', detail: 'Requires administrative privileges' },
};

const UI_ANNOTATION: Record<string, string> = {
  N: 'needs nothing from anyone',
  R: 'needs someone to click something',
};

// Same verbs consequence.js's buildImpact() uses for C/I/A, reused so the diagram and the impact
// panel never describe the same H metric two different ways.
const OUTCOME_VERBS: Record<string, string> = { C: 'read', I: 'change', A: 'shut down' };

function joinVerbs(values: string[]): string {
  if (values.length === 1) return values[0];
  return `${values.slice(0, -1).join(', ')} and ${values[values.length - 1]}`;
}

function originNode(av: string | undefined): DiagramNode {
  const known = av ? ORIGIN[av] : undefined;
  return known
    ? { id: 'origin', title: known.title, detail: known.detail, from: `AV:${av}` }
    : { id: 'origin', title: 'Reach not stated', detail: 'The vector does not state where an attacker must be', from: `AV:${av ?? 'none'}` };
}

function gateNode(pr: string | undefined): DiagramNode {
  const known = pr ? GATE[pr] : undefined;
  return known
    ? { id: 'gate', title: known.title, detail: known.detail, from: `PR:${pr}` }
    : { id: 'gate', title: 'Privilege not stated', detail: 'The vector does not state what access is required first', from: `PR:${pr ?? 'none'}` };
}

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

// Renders the CVSS vector as a path: origin -> reach -> what it gets. Draws only what the vector
// already states via cvss.js's own metric letters — no attacker avatars, no blast radius, no
// simulation beyond what AV/PR/UI/C/I/A already say.
export function reachDiagram(metrics: Record<string, string> | null | undefined): ReachDiagram {
  const m = metrics ?? {};
  const origin = originNode(m.AV);
  const gate = gateNode(m.PR);
  const outcome = outcomeNode(m);
  const uiText = m.UI ? UI_ANNOTATION[m.UI] : undefined;
  return {
    nodes: [origin, gate, outcome],
    edges: [{ from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }],
    gateAnnotation: uiText ? { text: uiText, from: `UI:${m.UI}` } : null,
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): add reachDiagram — the Step 1 origin/gate/outcome path as data"
```

---

## Task 5: `core/remediation.ts` — status wording, fix wording, and the version-recorded message

**Files:**
- Modify: `frontend-v4/src/app/core/remediation.ts` (append)
- Modify: `frontend-v4/src/app/core/remediation.spec.ts` (append)

**Interfaces:**
- Consumes: `RemediationFix` (Task 2).
- Produces: `AffectedVerdict`, `affectedWording(status, installed, rangeText)`, `FixWording`, `fixWording(fix)`, `closesWording(closes)`, `countCleared(before, after, excludeItemId)`, `versionRecordedMessage(clearedCount)`. Consumed by Task 9 (`RemediationGuidedComponent`) and Task 8 (`closesWording`, already partly used by Task 3's `oneUpgradeCloses` output).

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/remediation.spec.ts`:

```ts
import {
  affectedWording, fixWording, closesWording, countCleared, versionRecordedMessage,
} from './remediation';
import type { RemediationFix } from './models';

describe('affectedWording', () => {
  it('affected: states it plainly', () => {
    const w = affectedWording('affected', '7.4.0', 'before 7.4.5');
    expect(w.headline).toBe('You are affected.');
    expect(w.detail).toBe('Your build is inside the range.');
  });

  // Load-bearing: the system must never tell anyone they are safe.
  it('not_covered: never contains the word "safe"', () => {
    const w = affectedWording('not_covered', '8.0.0', 'before 7.4.5');
    expect(`${w.headline} ${w.detail}`.toLowerCase()).not.toContain('safe');
  });
  it('not_covered: states the range doesn\'t cover the build and says to confirm', () => {
    const w = affectedWording('not_covered', '8.0.0', 'before 7.4.5');
    expect(w.headline).toBe('This range does not cover your build.');
    expect(w.detail).toMatch(/confirm/i);
  });

  it('unknown: shows the actual values to compare, not a generic message', () => {
    const w = affectedWording('unknown', 'v7.0', 'before 7.4.5');
    expect(w.detail).toContain('v7.0');
    expect(w.detail).toContain('before 7.4.5');
  });
  it('unknown: never contains the word "safe" either', () => {
    const w = affectedWording('unknown', null, null);
    expect(`${w.headline} ${w.detail}`.toLowerCase()).not.toContain('safe');
  });
});

describe('fixWording', () => {
  it('version: names the target version and nothing else', () => {
    const fix: RemediationFix = { kind: 'version', value: '7.4.5' };
    const w = fixWording(fix);
    expect(w.headline).toBe('Upgrade to 7.4.5 or later');
    expect(w.note).toBeNull();
  });
  it('patch: carries the URL verbatim as the note', () => {
    const fix: RemediationFix = { kind: 'patch', value: 'https://example.com/patch' };
    expect(fixWording(fix).note).toBe('https://example.com/patch');
  });
  it('advisory: states no direct patch link is published', () => {
    const fix: RemediationFix = { kind: 'advisory', value: 'https://example.com/advisory' };
    const w = fixWording(fix);
    expect(w.detail).toMatch(/no direct patch link/i);
    expect(w.note).toBe('https://example.com/advisory');
  });
  it('none: states the fact plainly, load-bearing wording', () => {
    const w = fixWording({ kind: 'none' });
    expect(w.headline).toBe('No fix has been published for this yet.');
  });
});

describe('closesWording', () => {
  it('renders the upgrade-closes-N sentence', () => {
    expect(closesWording({ value: '7.4.5', count: 3 })).toBe('one upgrade to 7.4.5 closes 3 of these');
  });
  it('is null when there is nothing to close', () => {
    expect(closesWording(null)).toBeNull();
  });
});

describe('countCleared', () => {
  it('counts items that flipped from something else to not_covered', () => {
    const before = [{ itemId: 1, status: 'affected' }, { itemId: 2, status: 'affected' }];
    const after = [{ itemId: 1, status: 'not_covered' }, { itemId: 2, status: 'not_covered' }];
    expect(countCleared(before, after, 0)).toBe(2);
  });
  it('excludes the item the reader is currently looking at', () => {
    const before = [{ itemId: 1, status: 'affected' }, { itemId: 2, status: 'affected' }];
    const after = [{ itemId: 1, status: 'not_covered' }, { itemId: 2, status: 'not_covered' }];
    expect(countCleared(before, after, 1)).toBe(1);
  });
  it('does not count an item that was already not_covered before the write', () => {
    const before = [{ itemId: 1, status: 'not_covered' }];
    const after = [{ itemId: 1, status: 'not_covered' }];
    expect(countCleared(before, after, 0)).toBe(0);
  });
  it('does not count an item that stayed affected', () => {
    const before = [{ itemId: 1, status: 'affected' }];
    const after = [{ itemId: 1, status: 'affected' }];
    expect(countCleared(before, after, 0)).toBe(0);
  });
  it('is 0 for empty input', () => {
    expect(countCleared([], [], 0)).toBe(0);
  });
});

describe('versionRecordedMessage', () => {
  it('is null when nothing cleared — never claims a consequence that didn\'t happen', () => {
    expect(versionRecordedMessage(0)).toBeNull();
  });
  it('singular wording for exactly one cleared threat', () => {
    expect(versionRecordedMessage(1)).toBe('Recorded. 1 other threat against this machine is no longer inside its affected range.');
  });
  it('plural wording for more than one', () => {
    expect(versionRecordedMessage(2)).toBe('Recorded. 2 other threats against this machine are no longer inside their affected range.');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: FAIL — the new exports don't exist yet.

- [ ] **Step 3: Implement**

Append to `frontend-v4/src/app/core/remediation.ts`:

```ts
import type { RemediationFix } from './models';

// ---- Step 2 wording: affectedStatus -> what the reader reads ----

export interface AffectedVerdict {
  headline: string;
  detail: string;
}

// Verbatim from the spec: the system never tells anyone they are safe. not_covered is a fact
// about one range, not a clean bill of health — server/version_compare.js's affectedStatus()
// already abstains to 'unknown' rather than guess; this is where that abstention becomes
// language, and the wording is specified here so it cannot drift.
export function affectedWording(
  status: 'affected' | 'not_covered' | 'unknown',
  installed: string | null,
  rangeText: string | null,
): AffectedVerdict {
  if (status === 'affected') {
    return { headline: 'You are affected.', detail: 'Your build is inside the range.' };
  }
  if (status === 'not_covered') {
    return {
      headline: 'This range does not cover your build.',
      detail: 'Not a clean bill of health — confirm against the vendor advisory before treating it as closed.',
    };
  }
  const compare = installed && rangeText ? `${installed} / ${rangeText}` : 'the two versions';
  return {
    headline: 'These two can\'t be ordered reliably.',
    detail: `Compare them yourself: ${compare}`,
  };
}

// ---- Step 3 wording: fixTarget -> what the reader reads ----

export interface FixWording {
  headline: string;
  detail: string;
  note: string | null;
}

// One case per fixTarget kind, no hedging between them. 'version' never carries a note — see
// this plan's Spec Accuracy Finding 3: fixTarget's ladder is exclusive, so a version target
// never also carries a patch URL to show underneath it.
export function fixWording(fix: RemediationFix): FixWording {
  switch (fix.kind) {
    case 'version':
      return { headline: `Upgrade to ${fix.value} or later`, detail: '', note: null };
    case 'patch':
      return { headline: 'Apply the vendor’s fix', detail: 'A fix is published for this vulnerability.', note: fix.value };
    case 'advisory':
      return {
        headline: 'Read the vendor’s guidance',
        detail: 'No direct patch link is published yet, but the vendor has guidance.',
        note: fix.value,
      };
    case 'none':
      return { headline: 'No fix has been published for this yet.', detail: '', note: null };
  }
}

// ---- the "one upgrade closes N" sentence ----

export function closesWording(closes: UpgradeCloses | null): string | null {
  return closes ? `one upgrade to ${closes.value} closes ${closes.count} of these` : null;
}

// ---- Step 4: the version-recorded consequence ----

// Counts items that read something other than not_covered before a version write and read
// not_covered after it — the reader's own currently-open item is excluded, since the message is
// about OTHER threats against the same machine, per the spec's exact wording.
export function countCleared(
  before: { itemId: number; status: string }[],
  after: { itemId: number; status: string }[],
  excludeItemId: number,
): number {
  const afterById = new Map(after.map((a) => [a.itemId, a.status]));
  let n = 0;
  for (const b of before) {
    if (b.itemId === excludeItemId) continue;
    if (b.status !== 'not_covered' && afterById.get(b.itemId) === 'not_covered') n += 1;
  }
  return n;
}

// Generated from the recomputed statuses, never predicted before the write — null when nothing
// cleared, so nothing is claimed (the spec's own rule: "If the recompute clears nothing, nothing
// is claimed").
export function versionRecordedMessage(clearedCount: number): string | null {
  if (clearedCount <= 0) return null;
  const plural = clearedCount === 1 ? 'threat' : 'threats';
  const verb = clearedCount === 1 ? 'is' : 'are';
  const pronoun = clearedCount === 1 ? 'its' : 'their';
  return `Recorded. ${clearedCount} other ${plural} against this machine ${verb} no longer inside ${pronoun} affected range.`;
}
```

Move the `import type { RemediationFix } from './models';` line up to join the existing `import type { RemediationQueueGroup, RemediationQueueItem } from './models';` line at the top of the file instead of leaving two separate import statements — combine them into one:

```ts
import type { RemediationFix, RemediationQueueGroup, RemediationQueueItem } from './models';
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/remediation.spec.ts`
Expected: PASS, all tests (this file now covers every bullet in the spec's Testing section).

Also type-check:
Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/remediation.ts frontend-v4/src/app/core/remediation.spec.ts
git commit -m "feat(remediation): add status/fix wording and the version-recorded message"
```

---

## Task 6: `ui/reach-diagram.component.ts` — the Step 1 SVG

**Files:**
- Create: `frontend-v4/src/app/ui/reach-diagram.component.ts`

**Interfaces:**
- Consumes: `ReachDiagram`, `DiagramNode` (Task 4).
- Produces: `ReachDiagramComponent` with `@Input() diagram!: ReachDiagram`. Consumed by Task 9.

No test file: a template over an already-tested pure function, same posture as `ImpactPanelComponent`/`PlaybookPanelComponent` (thin bindings, no spec file). Verified by `tsc` plus the (unavailable, see final report) browser check.

- [ ] **Step 1: Create the component**

Create `frontend-v4/src/app/ui/reach-diagram.component.ts`:

```ts
import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import type { ReachDiagram } from '../core/remediation';

// Step 1's signature diagram: origin -> gate -> outcome, drawn from whatever reachDiagram()
// (core/remediation.ts) already decided from the CVSS vector. This component owns no logic of
// its own beyond which node's "why" popover is open — the same idiom tf-impact-panel already
// uses for its provenance buttons, reused here rather than inventing a second interaction.
//
// Inline SVG, no chart library: this is three boxes and two arrows. Horizontal scroll on narrow
// viewports (own .scroll container) rather than reflowing into an unreadable stack.
@Component({
  selector: 'tf-reach-diagram',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="scroll">
      <svg viewBox="0 0 640 170" [attr.width]="640" [attr.height]="170" role="img" [attr.aria-label]="ariaLabel()">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--ink-2)" />
          </marker>
        </defs>

        <line class="edge" x1="180" y1="55" x2="230" y2="55" marker-end="url(#arrow)" />
        <line class="edge" x1="420" y1="55" x2="470" y2="55" marker-end="url(#arrow)" />

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
    .edge { stroke: var(--ink-2); stroke-width: 1.5; }
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
}
```

- [ ] **Step 2: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add frontend-v4/src/app/ui/reach-diagram.component.ts
git commit -m "feat(remediation): add tf-reach-diagram — the Step 1 origin/gate/outcome SVG"
```

---

## Task 7: `ui/playbook-panel.component.ts` — link into the guided page + a toggle event

**Files:**
- Modify: `frontend-v4/src/app/ui/playbook-panel.component.ts`

**Interfaces:**
- Produces: `PlaybookPanelComponent` gains `@Input() itemId` usage in a new template link (the input already exists, just unused in the template until now), and `@Output() toggled = new EventEmitter<{ key: string; done: boolean }>()`.
- Consumed by: Task 9 (`RemediationGuidedComponent` listens for `toggled` to offer the version-record prompt after the `patch` step is ticked).

No test file — same binding-layer posture as the rest of this component (already untested).

- [ ] **Step 1: Modify the component**

In `frontend-v4/src/app/ui/playbook-panel.component.ts`, change the import line:

```ts
import { Component, Input, ChangeDetectionStrategy, inject, signal, computed } from '@angular/core';
```

to:

```ts
import { Component, Input, Output, EventEmitter, ChangeDetectionStrategy, inject, signal, computed } from '@angular/core';
```

Add a `RouterLink` import:

```ts
import { RouterLink } from '@angular/router';
```

Add `RouterLink` to the `imports` array:

```ts
  imports: [PanelComponent, RouterLink],
```

In the template, add a link right after the `<tf-panel ...>` opening tag (before `<ol class="steps">`):

```html
        <a class="guided-link" [routerLink]="['/remediate', itemId]">Open the guided walkthrough &rarr;</a>
        <ol class="steps">
```

Add its style next to the other rules in the `styles` array:

```css
    .guided-link {
      display: inline-block; margin-bottom: 10px; font-size: var(--fs-xs); color: var(--accent);
      text-decoration: none;
    }
    .guided-link:hover { text-decoration: underline; }
    .guided-link:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 2px; }
```

Add the output, right after the `@Input() dueDate` line:

```ts
  // Fired with the NEW done state, right after the optimistic tick — lets the guided page
  // (Spec B) offer to record a new asset version once the 'patch' step is ticked and the fix was
  // a named version, without this component needing to know anything about that flow itself.
  @Output() toggled = new EventEmitter<{ key: string; done: boolean }>();
```

Change the `toggle()` method to emit after computing the new state:

```ts
  toggle(key: string): void {
    const nowDone = this.effectivePlaybook()?.done.includes(key) ?? false;
    const opt = this.optimistic();
    const added = new Set(opt.added);
    const removed = new Set(opt.removed);
    if (nowDone) { removed.add(key); added.delete(key); } else { added.add(key); removed.delete(key); }
    this.optimistic.set({ added, removed });
    this.toggled.emit({ key, done: !nowDone });

    const call = nowDone ? this.api.untickPlaybookStep(this.itemId, key) : this.api.tickPlaybookStep(this.itemId, key);
    call.subscribe();
  }
```

- [ ] **Step 2: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 3: Run the full frontend suite** (nothing tests this component directly, but confirm nothing else broke)

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, same counts as baseline.

- [ ] **Step 4: Commit**

```bash
git add frontend-v4/src/app/ui/playbook-panel.component.ts
git commit -m "feat(remediation): link tf-playbook-panel into the guided page, emit step-toggle events"
```

---

## Task 8: `RemediationQueueComponent` — the `/remediate` queue page

**Files:**
- Create: `frontend-v4/src/app/pages/remediate/remediation-queue.component.ts`
- Modify: `frontend-v4/src/app/app.routes.ts`
- Modify: `frontend-v4/src/app/shell/shell.component.ts`

**Interfaces:**
- Consumes: `ApiService.remediationQueue` (Task 2), `queueSummary`/`groupProgress`/`groupHasPastDue`/`oneUpgradeCloses`/`closesWording`/`formatDueDate` (Tasks 3 & 5), `ProfileService.active`/`dataVersion` (existing).
- Produces: `RemediationQueueComponent`, routed at `/remediate`.

No test file — a page component with an `effect()`-driven fetch, same untestable-binding-layer posture as `ExplorerComponent`/`ItemDetailComponent` (Spec A's own plan, Task 2's rationale). Verified by `tsc` plus the (unavailable) browser check.

- [ ] **Step 1: Create the component**

Create `frontend-v4/src/app/pages/remediate/remediation-queue.component.ts`:

```ts
import { Component, ChangeDetectionStrategy, inject, signal, computed, effect } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { PanelComponent } from '../../ui/panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import {
  queueSummary, groupProgress, groupHasPastDue, oneUpgradeCloses, closesWording, formatDueDate,
} from '../../core/remediation';
import type { RemediationQueueGroup, RemediationQueueItem } from '../../core/models';

// The routed "/remediate" page: every asset the active profile has told us about, grouped, each
// carrying its open threats. Grouping and within-group sort are Spec A's own SQL (server/index.js)
// — this component adds only what the backend cannot: the "one upgrade closes N" annotation and
// the header summary, both pure functions from core/remediation.ts (see that file's spec for the
// full rule set).
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
              <ul class="items">
                @for (item of g.items; track item.itemId) {
                  <li>
                    <a [routerLink]="['/remediate', item.itemId]">{{ item.title }}</a>
                    <span class="status" [class]="'status-' + item.status">{{ statusLabel(item.status) }}</span>
                    @if (item.dueDate) { <span class="due">fix by {{ formatDueDate(item.dueDate) }}</span> }
                  </li>
                }
              </ul>
            </li>
          }
        </ul>
      }
    </tf-panel>
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
    .count { font-size: var(--fs-xs); color: var(--ink-2); }
    .tell-us { font-size: var(--fs-xs); color: var(--accent); text-decoration: none; }
    .tell-us:hover { text-decoration: underline; }
    .past-due {
      margin-left: auto; font-size: var(--fs-xs); font-weight: 600; color: var(--sev-critical);
    }
    .running { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .closes { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink); }
    .items { list-style: none; margin: 8px 0 0; padding: 0; display: grid; gap: 6px; }
    .items li { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
    .items a { color: var(--ink); text-decoration: none; font-size: var(--fs-sm); }
    .items a:hover { color: var(--accent); }
    .status { font-size: var(--fs-xs); color: var(--ink-2); }
    .status-not_covered { color: var(--sev-none); }
    .due { font-size: var(--fs-xs); color: var(--ink-2); margin-left: auto; }
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

  constructor() {
    // No route param to combine with, unlike explorer/item-detail — the effect's own creation
    // run IS the initial load, so there is no "skip the first run" guard needed here.
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

  statusLabel(status: RemediationQueueItem['status']): string {
    if (status === 'affected') return 'affected';
    if (status === 'not_covered') return 'not covered';
    return 'unknown';
  }
}
```

- [ ] **Step 2: Wire the route**

In `frontend-v4/src/app/app.routes.ts`, add a new entry right after the `intel/:id` route:

```ts
  { path: 'remediate', loadComponent: () => import('./pages/remediate/remediation-queue.component').then((m) => m.RemediationQueueComponent) },
```

(Task 9 adds the `remediate/:itemId` entry right after this one.)

- [ ] **Step 3: Add the nav link**

In `frontend-v4/src/app/shell/shell.component.ts`, find the nav links block:

```html
        <a routerLink="/arsenal" routerLinkActive="on">Arsenal</a>
        <a routerLink="/intel" routerLinkActive="on">Intel</a>
        <a routerLink="/check" routerLinkActive="on">Check URL</a>
```

Add a new link after `/intel`:

```html
        <a routerLink="/arsenal" routerLinkActive="on">Arsenal</a>
        <a routerLink="/intel" routerLinkActive="on">Intel</a>
        <a routerLink="/remediate" routerLinkActive="on">Remediate</a>
        <a routerLink="/check" routerLinkActive="on">Check URL</a>
```

- [ ] **Step 4: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/pages/remediate/remediation-queue.component.ts frontend-v4/src/app/app.routes.ts frontend-v4/src/app/shell/shell.component.ts
git commit -m "feat(remediation): add the /remediate queue page"
```

---

## Task 9: `RemediationGuidedComponent` — the `/remediate/:itemId` guided page

**Files:**
- Create: `frontend-v4/src/app/pages/remediate/remediation-guided.component.ts`
- Modify: `frontend-v4/src/app/app.routes.ts`

**Interfaces:**
- Consumes: `ApiService.itemRemediation`/`recordAssetVersion`/`remediationQueue` (Task 2), `parseVectorMetrics`/`reachDiagram`/`affectedWording`/`fixWording`/`countCleared`/`versionRecordedMessage` (Tasks 4 & 5), `ReachDiagramComponent` (Task 6), `PlaybookPanelComponent`'s `toggled` output (Task 7).
- Produces: `RemediationGuidedComponent`, routed at `/remediate/:itemId`.

No test file — same posture as Task 8.

- [ ] **Step 1: Create the component**

Create `frontend-v4/src/app/pages/remediate/remediation-guided.component.ts`:

```ts
import { Component, ChangeDetectionStrategy, inject, signal, computed } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { PanelComponent } from '../../ui/panel.component';
import { ReachDiagramComponent } from '../../ui/reach-diagram.component';
import { PlaybookPanelComponent } from '../../ui/playbook-panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import {
  parseVectorMetrics, reachDiagram, affectedWording, fixWording, countCleared, versionRecordedMessage,
} from '../../core/remediation';
import type { RemediationDetail } from '../../core/models';

// The routed "/remediate/:itemId" guided page: one threat, walked through in four steps on a
// rail that traps nobody — every step is readable top to bottom with no interaction, per the
// spec's own "not a wizard" rule.
@Component({
  selector: 'tf-page-remediate-item',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, PanelComponent, ReachDiagramComponent, PlaybookPanelComponent, EmptyStateComponent, SkeletonComponent],
  template: `
    @if (loading()) {
      <tf-skeleton [rows]="10" />
    } @else if (notFound()) {
      <tf-empty-state title="Item not found" reason="GET /api/items/:id/remediation returned 404" />
    } @else if (detail(); as d) {
      <a class="back" [routerLink]="['/intel', d.item.id]">&larr; Back to item</a>
      <h1>{{ d.item.title }}</h1>

      <tf-panel title="What this does">
        <tf-reach-diagram [diagram]="diagram()" />
      </tf-panel>

      @if (!d.asset) {
        <tf-panel title="Are you affected">
          <tf-empty-state
            title="Tell us what you run"
            reason="No asset in your profile matches this item yet — add one and this page fills itself in"
          />
          <a class="cta" routerLink="/onboarding">Go to profile setup &rarr;</a>
        </tf-panel>
      } @else {
        <tf-panel title="Are you affected">
          <p class="range">
            Affected: {{ d.asset.vendor }} {{ d.asset.product }}
            @if (d.remediation?.entry?.text) { — {{ d.remediation!.entry!.text }} }
          </p>

          @for (v of [verdict()]; track v.headline) {
            <div class="verdict">
              <p class="headline">{{ v.headline }}</p>
              <p class="detail">{{ v.detail }}</p>
            </div>
          }

          <form class="version-form" (submit)="submitVersion($event)">
            <label>
              You run
              <input type="text" name="version" [value]="versionInput()" (input)="onVersionInput($event)" placeholder="e.g. 7.4.5" />
            </label>
            <button type="submit" class="primary">Save</button>
            <button type="button" (click)="declineVersion()">I don't know</button>
          </form>
        </tf-panel>

        <tf-panel title="The fix">
          <p class="headline">{{ fix().headline }}</p>
          @if (fix().detail) { <p class="detail">{{ fix().detail }}</p> }
          @if (fix().note) { <a class="note" [href]="fix().note" target="_blank" rel="noopener">{{ fix().note }}</a> }
          <!-- Finding 3's resolution: patchUrl is a sibling of remediation.fix, not a variant of
               it — shown only underneath a 'version' target, the spec's exact conditional
               ("with the vendor's patch link beneath it if one exists"). -->
          @if (d.remediation?.fix?.kind === 'version' && d.patchUrl) {
            <a class="note" [href]="d.patchUrl" target="_blank" rel="noopener">{{ d.patchUrl }}</a>
          }
          @if (d.remediation?.fix?.kind === 'none' && (d.remediation?.mitigations?.length ?? 0) > 0) {
            <ul class="mitigations">
              @for (m of d.remediation!.mitigations; track m.key) {
                <li><span class="t">{{ m.title }}</span><p>{{ m.detail }}</p></li>
              }
            </ul>
          }
        </tf-panel>
      }

      @if (d.playbook) {
        <tf-playbook-panel [playbook]="d.playbook" [itemId]="d.item.id" (toggled)="onStepToggled($event)" />
      }

      @if (offerVersionBump()) {
        <tf-panel title="Close it out">
          <p>Applied the fix. Record that you're now on {{ bumpTarget() }}?</p>
          <button type="button" class="primary" (click)="confirmVersionBump()">Yes</button>
          <button type="button" (click)="offerVersionBump.set(false)">Not yet</button>
        </tf-panel>
      }

      @if (recordedMessage(); as msg) {
        <tf-panel title="Close it out">
          <p>{{ msg }}</p>
          <a routerLink="/remediate">See them &rarr;</a>
        </tf-panel>
      }
    }
  `,
  styles: [`
    .back { font-size: var(--fs-xs); color: var(--ink-2); text-decoration: none; }
    h1 { font-size: var(--fs-lg); margin: 8px 0 12px; }
    .range { margin: 0 0 10px; font-size: var(--fs-sm); color: var(--ink-2); }
    .verdict { margin: 0 0 14px; animation: verdict-in 180ms var(--ease-out); }
    @keyframes verdict-in { from { opacity: 0; } to { opacity: 1; } }
    @media (prefers-reduced-motion: reduce) { .verdict { animation: none; } }
    .verdict .headline { margin: 0; font-weight: 600; color: var(--ink); }
    .verdict .detail { margin: 2px 0 0; font-size: var(--fs-sm); color: var(--ink-2); }
    .version-form { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .version-form input {
      font: inherit; background: var(--surface-2); border: var(--hair) solid var(--hairline);
      border-radius: 6px; padding: 5px 8px; color: var(--ink);
    }
    button.primary {
      appearance: none; cursor: pointer; font: inherit; font-weight: 590;
      color: var(--bg); background: var(--accent); border: 0; padding: 6px 14px; border-radius: 8px;
    }
    button { appearance: none; cursor: pointer; font: inherit; background: var(--surface-2); color: var(--ink); border: 0; padding: 6px 14px; border-radius: 8px; }
    .mitigations { list-style: none; margin: 10px 0 0; padding: 0; display: grid; gap: 8px; }
    .mitigations .t { font-weight: 600; }
    .cta { color: var(--accent); }
  `],
})
export class RemediationGuidedComponent {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private profileService = inject(ProfileService);

  id = NaN;
  detail = signal<RemediationDetail | null>(null);
  loading = signal(true);
  notFound = signal(false);

  versionInput = signal('');
  offerVersionBump = signal(false);
  recordedMessage = signal<string | null>(null);

  metrics = computed(() => parseVectorMetrics(this.detail()?.item.cvss_vector ?? null));
  diagram = computed(() => reachDiagram(this.metrics()));

  verdict = computed(() => {
    const r = this.detail()?.remediation;
    if (!r) return { headline: '', detail: '' };
    return affectedWording(r.status, r.installed, r.entry?.text ?? null);
  });

  fix = computed(() => {
    const r = this.detail()?.remediation;
    if (!r) return { headline: '', detail: '', note: null };
    return fixWording(r.fix);
  });

  bumpTarget = computed(() => {
    const fix = this.detail()?.remediation?.fix;
    return fix && fix.kind === 'version' ? fix.value : '';
  });

  constructor() {
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      const id = Number(pm.get('itemId'));
      if (!Number.isInteger(id) || id <= 0) {
        this.notFound.set(true);
        this.loading.set(false);
        return;
      }
      this.id = id;
      this.loadDetail();
    });
  }

  loadDetail(): void {
    this.loading.set(true);
    this.notFound.set(false);
    this.recordedMessage.set(null);
    this.api.itemRemediation(this.id).subscribe({
      next: (d) => {
        // No vector, nothing to guide through — redirect to the item detail page (spec's
        // "Item has no CVE / no vector" degraded state).
        if (!parseVectorMetrics(d.item.cvss_vector)) {
          this.router.navigate(['/intel', d.item.id], { replaceUrl: true });
          return;
        }
        this.detail.set(d);
        this.versionInput.set(d.remediation?.installed ?? '');
        this.loading.set(false);
      },
      error: (err) => {
        this.loading.set(false);
        if (err?.status === 404) this.notFound.set(true);
      },
    });
  }

  onVersionInput(ev: Event): void {
    this.versionInput.set((ev.target as HTMLInputElement).value);
  }

  submitVersion(ev: Event): void {
    ev.preventDefault();
    const asset = this.detail()?.asset;
    const profile = this.profileService.active();
    if (!asset || !profile) return;
    const value = this.versionInput().trim();
    this.api.recordAssetVersion(profile.id, asset.vendor, asset.product, {
      version: value || null,
      versionState: value ? 'known' : 'unknown',
    }).subscribe(() => this.loadDetail());
  }

  declineVersion(): void {
    const asset = this.detail()?.asset;
    const profile = this.profileService.active();
    if (!asset || !profile) return;
    this.api.recordAssetVersion(profile.id, asset.vendor, asset.product, { versionState: 'unknown' }).subscribe(() => this.loadDetail());
  }

  onStepToggled(e: { key: string; done: boolean }): void {
    const fix = this.detail()?.remediation?.fix;
    if (e.key === 'patch' && e.done && fix && fix.kind === 'version') {
      this.offerVersionBump.set(true);
    }
  }

  // Reads the whole queue before and after the write, filtered to this asset, to answer "how
  // many OTHER threats against this machine cleared" — generated from the recomputed statuses,
  // never predicted before the write, per the spec's own rule.
  confirmVersionBump(): void {
    const asset = this.detail()?.asset;
    const profile = this.profileService.active();
    const fix = this.detail()?.remediation?.fix;
    if (!asset || !profile || !fix || fix.kind !== 'version') return;
    const currentItemId = this.id;

    this.api.remediationQueue(profile.id).subscribe((before) => {
      const beforeItems = (before.find((g) => g.vendor === asset.vendor && g.product === asset.product)?.items ?? [])
        .map((i) => ({ itemId: i.itemId, status: i.status }));

      this.api.recordAssetVersion(profile.id, asset.vendor, asset.product, {
        version: fix.value, versionState: 'known',
      }).subscribe(() => {
        this.api.remediationQueue(profile.id).subscribe((after) => {
          const afterItems = (after.find((g) => g.vendor === asset.vendor && g.product === asset.product)?.items ?? [])
            .map((i) => ({ itemId: i.itemId, status: i.status }));
          const cleared = countCleared(beforeItems, afterItems, currentItemId);
          this.offerVersionBump.set(false);
          this.recordedMessage.set(versionRecordedMessage(cleared) ?? 'Recorded.');
          this.loadDetail();
        });
      });
    });
  }
}
```

- [ ] **Step 2: Wire the route**

In `frontend-v4/src/app/app.routes.ts`, add the second remediation entry right after the one Task 8 added:

```ts
  { path: 'remediate', loadComponent: () => import('./pages/remediate/remediation-queue.component').then((m) => m.RemediationQueueComponent) },
  { path: 'remediate/:itemId', loadComponent: () => import('./pages/remediate/remediation-guided.component').then((m) => m.RemediationGuidedComponent) },
```

- [ ] **Step 3: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add frontend-v4/src/app/pages/remediate/remediation-guided.component.ts frontend-v4/src/app/app.routes.ts
git commit -m "feat(remediation): add the /remediate/:itemId guided page"
```

---

## Task 10: Full-suite verification

**Files:** none — operational only.

- [ ] **Step 1: Full backend suite**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures (baseline 656 tests / 654 pass / 0 fail / 2 skipped, plus Task 1's four new tests).

- [ ] **Step 2: Full frontend suite**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures (baseline 112 pass / 11 files, plus Tasks 3–5's new `remediation.spec.ts` cases and file).

- [ ] **Step 3: Frontend type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: clean, exit 0.

- [ ] **Step 4: Browser check — attempt, and report honestly if unavailable**

Load the browser tools (`ToolSearch` for `mcp__claude-in-chrome__list_connected_browsers` etc.) and call `list_connected_browsers`. If it returns a non-empty list: start the backend (`node server/index.js`) and frontend (`npm start` in `frontend-v4`), navigate to `/remediate` and `/remediate/:itemId` for a real item with a CVSS vector, and confirm: the diagram renders and draws once, the verdict cross-fades on a version submit, the queue's progress bars/stagger read correctly, and every empty/degraded state (`no profile assets`, `no open threats`, `no asset matched`, `no vector` redirect) actually renders as designed rather than blank. If the list is empty, do not attempt any of this, do not simulate it, and say so plainly in the final report — passing vitest specs on `reachDiagram`/`affectedWording` are evidence the *data* is correct, not that the SVG paints or the animation plays.

- [ ] **Step 5: Final commit** (only if Steps 1–4 required a fix)

```bash
git status
# If clean, nothing to do. If a fix was needed, commit it with a message describing what was
# actually wrong, following the same Conventional Commits style as the tasks above.
```
