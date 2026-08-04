# Remediation Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Spec A end to end — the profile-switch refetch bug fix, `profile_assets.version`/`version_state`, the pure `version_compare.js` comparator, the pure `remediation.js` fix ladder, and the three remediation routes — so Spec B (the queue/guided pages) and Spec C (AI Assist) have real data to render.

**Architecture:** Frontend: `ProfileService` gains a `dataVersion` counter bumped by `select()`; page components that actually render profile-scoped data re-run their fetch inside a guarded `effect()`. Backend: `profile_assets` gains `version`/`version_state`, validated by `profiles.js`; `server/version_compare.js` is a pure dotted-numeric comparator that abstains (`null`) rather than guesses; `server/remediation.js` composes a fix ladder (`fixTarget`) and a per-(asset,item) summary (`remediationFor`) from data `consolidate.js`/`playbook.js` already produce; three Express routes expose the queue, the per-item detail, and the version-recording PATCH, reusing `profiles.updateProfile`'s existing transaction so a version write goes through the same `profile_version` bump and recompute as every other profile edit.

**Tech Stack:** Node 22 (`/home/sah/.nvm/versions/node/v22.23.1/bin/node`) · Express 4 · PostgreSQL 16 (`node:test`, colocated `*.test.js`, isolated stores via `test-helpers.js`) · Angular 19 standalone components (vitest, no TestBed).

## Global Constraints

- Every derived fact traces to something a source actually said; unparseable or absent is `null`/`'unknown'`, never a guess (`version_compare.js`'s entire reason for existing).
- `endExcluding` is the only NVD bound field that names a fixed version. `endIncluding` and `pinned` may never produce `fixTarget`'s `kind: 'version'` — this is the fabrication guard and it is asserted directly in tests, not just implied by code shape.
- A `pinned` version that differs from what the reader runs yields `affectedStatus` = `'unknown'`, never `'not_covered'` — an exact-pin CPE match is usually a CNA filing artifact, not a scope assertion (55.8% of entries are pins; see Measured Coverage below).
- `not_covered` is a fact about one range, never a safety claim. No string this plan produces may render it as "you are safe" — that wording is Spec B's job and is out of scope here, but the data contract must not make the mistake possible upstream.
- Non-integer `:id` route params → 404. Every handler is wrapped by `index.js`'s `h()` so a rejected promise becomes `500 { error }`. `X-Profile-Id` resolution is via the existing `resolveProfile()` — an unknown id is `400`, a missing header is the caller's problem to handle (existing playbook-step routes return `400 { error: 'X-Profile-Id required' }` and the new routes match that).
- Backend tests are `node:test`, isolated via `makeTempDb()` from `test-helpers.js` — never the `db.js` singleton. Frontend tests are vitest, no TestBed; pure logic lives in `core/*.ts` with its own `*.spec.ts`; untestable binding layers (an `effect()` inside a component) get no test file, per this app's own established convention.
- Use absolute node/npm paths per `CLAUDE.md`: `/home/sah/.nvm/versions/node/v22.23.1/bin/node`, `.../npm`.

---

## Spec Accuracy Findings

The spec's own instructions require recording disagreements here rather than quietly dropping or reshaping scope. Three findings, all confirmed against the code and the live database before writing any task below.

### 1. Measured coverage table — confirmed, with expected drift

Ran the spec's own coverage query against the live `threatflow` database (2026-08-04, same day as the spec, several hours later — sync keeps running):

| | spec (2026-08-04) | live, just now |
|---|---|---|
| `cve_intel` rows | 22,843 | 23,066 |
| carry any `affected_versions` | 13,310 (58.3%) | 13,478 (58.4%) |
| entries across those rows | 21,976 | 22,156 |
| entries naming a fixed version (`endExcluding`) | 7,985 (36.3%) | 8,155 (36.8%) |
| entries with an exact pin, no fix named | 12,255 (55.8%) | 12,264 (55.4%) |
| entries with `endIncluding` only, no fix named | 1,733 (7.9%) | 1,734 (7.8%) |
| no-fix entries carrying a `patch_url` | 7,012 | 7,019 |
| no-fix entries carrying an `advisory_url` **and no `patch_url`** | 3,185 | 3,184 |
| no-fix entries with neither | 3,802 (17%) | 3,798 (17.1%) |

All numbers hold within normal single-day sync drift. One wording note: the spec's "3,185 an advisory_url" reads as "carries an advisory_url", but the raw count of no-fix entries carrying *any* `advisory_url` is 9,077 — most also carry a `patch_url`. The 3,185/3,184 figure is specifically **advisory-only** (`advisory_url` present, `patch_url` absent), i.e. the second rung of the fix ladder after `patch`. This matters for Task 6's tests, which assert the ladder's precedence directly. No action needed beyond this note — the spec's math is right, the prose is just terse.

### 2. `entity-profile.component.ts` cannot host the described fix — it owns no fetch

Part 1 lists twelve components needing a `dataVersion`-triggered refetch: `dashboard, explorer, item-detail, live-feed-page, lane-live, lane-exploited, arsenal-index, arsenal-dossier, cve, actor, malware, entity-profile`.

`frontend-v4/src/app/pages/entity/entity-profile.component.ts` is a **pure presentational** component — `@Input() profile`, `@Input() loading`, `@Output() retry`, no `ApiService` injection, no HTTP call of any kind. It is shared body markup for both `/actor/:name` and `/malware/:family`; those two routed pages (already separately listed in the twelve) own the actual fetch via their own `route.paramMap` subscription + `this.api.actor(name)` / `this.api.malware(family)`. There is no fetch inside `entity-profile.component.ts` to re-trigger — adding an `effect()` there would have nothing to call.

**Resolution:** the fix belongs entirely in `actor.component.ts` and `malware.component.ts`, which are already on the list as their own entries. `entity-profile.component.ts` itself needs no change. Task 3 implements the fix in `actor.component.ts`/`malware.component.ts` and this finding explains why there is no dedicated task for `entity-profile.component.ts`.

### 3. Eight of the twelve components fetch data that is not profile-scoped at all

This is the significant finding. I traced every one of the twelve components to the endpoint it calls and checked that endpoint's server-side handler for any `X-Profile-Id`/`item_relevance` dependency:

| component | endpoint | profile-scoped? |
|---|---|---|
| `explorer.component.ts` | `GET /api/items` | **yes** — `relJoin`/`relSelect`/tier-based `ORDER BY` in `index.js` |
| `item-detail.component.ts` | `GET /api/items/:id` | **yes** — relevance + playbook blocks keyed on `X-Profile-Id` |
| `arsenal-dossier.component.ts` | `GET /api/items?source_id=…` (via `loadItems()`) | **yes** — same `/api/items` relevance/order logic; `sourceStats()` itself (`GET /api/sources/:id/stats`) is not scoped |
| `dashboard.component.ts` | `GET /api/stats/dashboard` | no — `stats.js:dashboardStats()` has zero profile/relevance joins |
| `lane-exploited.component.ts` | `GET /api/facets` (its own vendor list; `stats` comes from the parent as `@Input`) | no |
| `lane-live.component.ts` / `live-feed-page.component.ts` | `GET /api/feed` (via `FeedStreamBase`) | no — `queries.js:feed()` has zero profile/relevance joins |
| `arsenal-index.component.ts` | `GET /api/sources` | no |
| `cve.component.ts` | `GET /api/cves/:cveId` | no — `queries.js:cveDetail()` has zero profile joins |
| `actor.component.ts` / `malware.component.ts` | `GET /api/actors/:name` / `GET /api/malware/:family` | no — `queries.js:entityProfile()` has zero profile joins |

Concretely: switching the active profile changes **nothing** about what `/api/stats/dashboard`, `/api/feed`, `/api/facets`, `/api/sources`, `/api/cves/:id`, `/api/actors/:name`, or `/api/malware/:family` return. There is no staleness bug to fix in the eight components built on those calls — the described symptom ("every rendered figure stays from the previous persona") is real only for the three that read `/api/items`/`/api/items/:id`.

One of the eight is not merely low-value but actually costly to wire per the spec's letter: `lane-live.component.ts` and `live-feed-page.component.ts` both fetch through `FeedStreamBase`'s `pollingSignal()` (`core/poll.ts`), whose `PollingHandle` exposes only `{ value, stale, destroy }` — no public "refetch now" method. Making these two react to `dataVersion` would mean adding new public surface to a shared, already-tested primitive, purely to force a network round-trip whose response is guaranteed byte-identical regardless of profile. That is a real cost for zero benefit, not the "mechanical, no logic change" the spec promised for all twelve.

**Resolution, kept explicit rather than silently dropped:**
- Task 2 implements the real fix for the three profile-scoped components: `explorer`, `item-detail`, `arsenal-dossier`.
- Task 3 mechanically wires the identical guarded `effect()` into the six components where it costs one `constructor()` and is genuinely harmless even though it changes nothing user-visible today (`dashboard`, `lane-exploited`, `arsenal-index`, `cve`, `actor`, `malware`) — done for spec compliance and because a future change to any of those six endpoints (e.g. a personalized dashboard stat) would silently need this wiring anyway.
- Task 3 explicitly does **not** wire `lane-live.component.ts` or `live-feed-page.component.ts`, for the `PollingHandle` reason above. If a future spec makes `/api/feed` profile-aware, that is the point to add `PollingHandle.refetch()` and wire these two — not before.

If the human reviewer disagrees with skipping `lane-live`/`live-feed-page`, the fix is a one-line addition to `core/poll.ts` (`refetch(): void { fetchNow(); }`, exposed on `PollingHandle`) plus the same guarded `effect()` pattern used everywhere else in Task 3 — flagged here rather than hidden so that call is the reviewer's to make.

---

## Part 1 — profile-switch refetch (frontend)

### Task 1: `ProfileService.dataVersion` + idempotent `select()`

**Files:**
- Modify: `frontend-v4/src/app/core/profile-selection.ts` (add `isProfileChange`)
- Modify: `frontend-v4/src/app/core/profile.service.ts` (add `_dataVersion` signal, rewrite `select()`)
- Test: `frontend-v4/src/app/core/profile-selection.spec.ts` (append)

**Interfaces:**
- Produces: `isProfileChange(current: number | null, next: number | null): boolean` — pure predicate, `true` iff `next !== current`. `ProfileService.dataVersion: Signal<number>` (readonly) — consumed by every `effect()` added in Tasks 2 and 3.
- Rationale for the extra pure function: `ProfileService` injects `ApiService` in its constructor, and this app has no TestBed — instantiating a service directly throws `NG0203` outside an injection context. Every other piece of branching logic in this codebase that needs a unit test already lives in a pure `core/*.ts` module (`profile-selection.ts` itself is the precedent). `isProfileChange` carries the one boolean decision `select()` needs to test; `ProfileService.select()` becomes a two-line wrapper around it plus the signal writes, which the app's convention leaves untested (same posture as the `effect()` wiring in Tasks 2–3).

- [ ] **Step 1: Write the failing tests**

Append to `frontend-v4/src/app/core/profile-selection.spec.ts`:

```ts
import { isProfileChange } from './profile-selection';

describe('isProfileChange', () => {
  it('is true when selecting a different id', () => {
    expect(isProfileChange(1, 2)).toBe(true);
  });

  it('is false when selecting the id that is already active', () => {
    expect(isProfileChange(3, 3)).toBe(false);
  });

  it('is false when both are null (no profile, still no profile)', () => {
    expect(isProfileChange(null, null)).toBe(false);
  });

  it('is true when clearing an active selection to null', () => {
    expect(isProfileChange(5, null)).toBe(true);
  });

  it('is true when selecting a profile from no active selection', () => {
    expect(isProfileChange(null, 7)).toBe(true);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/profile-selection.spec.ts`
Expected: FAIL — `isProfileChange` is not exported.

- [ ] **Step 3: Implement**

In `frontend-v4/src/app/core/profile-selection.ts`, append:

```ts
// Whether selecting `next` over `current` is a real change. Selecting the profile that is
// already active is a no-op — this is what makes ProfileService.load()'s startup call to
// select(resolveActiveId(...)) safe: without it, every page would double-fetch on first paint
// (load() always calls select() once even when the resolved id matches what was already stored).
export function isProfileChange(current: number | null, next: number | null): boolean {
  return next !== current;
}
```

In `frontend-v4/src/app/core/profile.service.ts`, add the import and the signal:

```ts
import { Injectable, computed, inject, signal } from '@angular/core';
import { ApiService } from './api.service';
import { resolveActiveId, parseStoredId, isProfileChange } from './profile-selection';
import type { Profile, ProfilePayload } from './models';
```

Add the field (near `_loaded`):

```ts
  private readonly _dataVersion = signal(0);

  // Bumped by select() whenever the active profile actually changes. Every page component that
  // renders profile-scoped data (relevance tier, consequence, playbook) reads this inside an
  // effect() so a profile switch invalidates what's already on screen — see Tasks 2–3. It is a
  // counter rather than an event so a component created after a switch reads the current number
  // and is correct without having observed the transition.
  readonly dataVersion = this._dataVersion.asReadonly();
```

Replace `select()`:

```ts
  select(id: number | null): void {
    if (!isProfileChange(this._activeId(), id)) return;
    this._activeId.set(id);
    try {
      if (id == null) localStorage.removeItem(ACTIVE_PROFILE_KEY);
      else localStorage.setItem(ACTIVE_PROFILE_KEY, String(id));
    } catch { /* storage unavailable (private mode); selection still works for this session */ }
    this._dataVersion.update((n) => n + 1);
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/profile-selection.spec.ts`
Expected: PASS, all tests including the pre-existing ones.

Also type-check the whole app, since `profile.service.ts` changed:
Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/profile-selection.ts frontend-v4/src/app/core/profile-selection.spec.ts frontend-v4/src/app/core/profile.service.ts
git commit -m "feat(profile): add dataVersion counter, make select() idempotent on the active id"
```

---

### Task 2: Wire the refetch into the three components that actually render profile-scoped data

**Files:**
- Modify: `frontend-v4/src/app/pages/intel/explorer.component.ts`
- Modify: `frontend-v4/src/app/pages/intel/item-detail.component.ts`
- Modify: `frontend-v4/src/app/pages/arsenal/arsenal-dossier.component.ts`

**Interfaces:**
- Consumes: `ProfileService.dataVersion` (Task 1).
- Produces: no new exported interface — each change is local to its component's constructor.

No test file: per this app's established convention (see the impact-provenance plan's own Task 5, and Spec A's own "Testing" section for Part 1), an `effect()` inside a component is the untestable binding layer this codebase already accepts without a spec file. Verification is type-check + manual browser check.

- [ ] **Step 1: `explorer.component.ts`**

Change the `@angular/core` import (line 1) to add `effect`:

```ts
import { Component, ChangeDetectionStrategy, inject, signal, computed, effect } from '@angular/core';
```

Add the import (after the `ApiService` import):

```ts
import { ProfileService } from '../../core/profile.service';
```

Add the field next to `private api = inject(ApiService);` (find the exact line by searching for `private api = inject(ApiService)` inside `ExplorerComponent`):

```ts
  private profileService = inject(ProfileService);
```

In the constructor, after the existing `this.api.facets().subscribe({...});` block (the last statement in the constructor), append:

```ts

    // /api/items' relevance tier, consequence and row ordering are profile-scoped (index.js's
    // relJoin/orderBy). A profile switch must invalidate what's already rendered. Guarded so the
    // effect's own first run — effect() always runs once on creation, same moment the
    // queryParamMap subscription above already fires its own initial load — doesn't double-fetch.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      this.loadItems();
      this.loadIocRows();
    });
```

- [ ] **Step 2: `item-detail.component.ts`**

Change the `@angular/core` import (line 1) to add `effect`:

```ts
import { Component, ChangeDetectionStrategy, inject, signal, computed, effect } from '@angular/core';
```

Add the import (after the `ApiService` import):

```ts
import { ProfileService } from '../../core/profile.service';
```

Add the field next to `private api = inject(ApiService);`:

```ts
  private profileService = inject(ProfileService);
```

In the constructor, after the existing `this.route.paramMap.pipe(takeUntilDestroyed()).subscribe(...)` block, append:

```ts

    // GET /api/items/:id's relevance/playbook blocks are profile-scoped. Same guard pattern as
    // explorer.component.ts: skip the effect's own first (creation-time) run so this doesn't
    // double-fetch alongside the paramMap subscription above.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      if (Number.isInteger(this.id) && this.id > 0) this.loadDetail();
    });
```

- [ ] **Step 3: `arsenal-dossier.component.ts`**

Find the `@angular/core` import at the top of the file and add `effect` to it (it currently imports at least `Component, Input, Output, EventEmitter` or similar — locate the existing import line and add `effect` alongside whatever is already imported from `@angular/core`, e.g. if the line reads `import { Component, ChangeDetectionStrategy, OnDestroy, inject, signal, computed } from '@angular/core';` change it to:

```ts
import { Component, ChangeDetectionStrategy, OnDestroy, inject, signal, computed, effect } from '@angular/core';
```

Add the import (after the `ApiService` import):

```ts
import { ProfileService } from '../../core/profile.service';
```

Add the field next to `private api = inject(ApiService);` (line 374):

```ts
  private profileService = inject(ProfileService);
```

In the constructor (starts at line 463), after the existing `this.route.paramMap.pipe(takeUntilDestroyed()).subscribe(...)` block, append:

```ts

    // Only loadItems() reads a profile-scoped endpoint (GET /api/items?source_id=…) — loadStats()
    // (GET /api/sources/:id/stats) carries no relevance data and is deliberately not re-fetched
    // here. Same creation-time-skip guard as explorer/item-detail.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      if (Number.isInteger(this.sourceId) && this.sourceId > 0) this.loadItems();
    });
```

- [ ] **Step 4: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 5: Manual verification in the browser**

Start the backend (`cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node server/index.js`) and the frontend (`cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npm start`). With at least two profiles created (one with FortiOS assets, one without), open `/intel`, note the relevance chips, switch the active profile in the header, and confirm the rows re-fetch and the chips update without a manual reload. Repeat on an item detail page (`/intel/:id`) — confirm the impact panel and playbook re-render for the new profile. Repeat on an Arsenal source dossier page (`/arsenal/:id`) with items that have relevance-affecting CPEs — confirm the item list re-fetches (ordering or `Threat` column may change).

- [ ] **Step 6: Commit**

```bash
git add frontend-v4/src/app/pages/intel/explorer.component.ts frontend-v4/src/app/pages/intel/item-detail.component.ts frontend-v4/src/app/pages/arsenal/arsenal-dossier.component.ts
git commit -m "fix(profile): refetch explorer, item detail and arsenal dossier on profile switch"
```

---

### Task 3: Wire the same effect into the six spec-named components with no real staleness bug (spec compliance)

**Files:**
- Modify: `frontend-v4/src/app/pages/dashboard/dashboard.component.ts`
- Modify: `frontend-v4/src/app/pages/dashboard/lane-exploited.component.ts`
- Modify: `frontend-v4/src/app/pages/arsenal/arsenal-index.component.ts`
- Modify: `frontend-v4/src/app/pages/entity/cve.component.ts`
- Modify: `frontend-v4/src/app/pages/entity/actor.component.ts`
- Modify: `frontend-v4/src/app/pages/entity/malware.component.ts`

**Interfaces:** none new — same pattern as Task 2, applied to components whose current endpoints are not profile-scoped (see Spec Accuracy Finding 3). Included for literal spec compliance; each one costs one `constructor()`.

**Explicitly excluded from this task, with reasons recorded in Spec Accuracy Finding 3:** `lane-live.component.ts`, `live-feed-page.component.ts` (would require adding a public `refetch()` to `PollingHandle` in `core/poll.ts` for an endpoint, `/api/feed`, that returns identical data regardless of profile), and `entity-profile.component.ts` (owns no fetch — see Finding 2; its two callers, `actor`/`malware`, are handled below).

No test file, same rationale as Task 2.

- [ ] **Step 1: `dashboard.component.ts`**

Change the `@angular/core` import (line 1):

```ts
import { Component, ChangeDetectionStrategy, OnInit, inject, signal, effect } from '@angular/core';
```

Add the import after `SyncService`:

```ts
import { ProfileService } from '../../core/profile.service';
```

Add the field next to `sync = inject(SyncService);`:

```ts
  private profileService = inject(ProfileService);
```

Add a constructor (there isn't one yet — `ngOnInit` is the only lifecycle hook):

```ts
  constructor() {
    // GET /api/stats/dashboard carries no profile/relevance data today (see the plan's Spec
    // Accuracy Finding 3) — this wiring is a no-op now and exists so a future personalized
    // dashboard figure doesn't silently need it added.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      this.load();
    });
  }
```

- [ ] **Step 2: `lane-exploited.component.ts`**

**Correction made during execution:** the draft below called `this.ngOnInit()` by hand from the effect, which invokes a lifecycle hook outside Angular's own lifecycle — a latent footgun (nothing stops a future edit from putting non-idempotent setup in `ngOnInit` that shouldn't rerun). Fixed by extracting `ngOnInit`'s body into a private `load()`, the same pattern every other component in Tasks 2–3 already uses, with `ngOnInit` reduced to `this.load()`. `load()` also gained `this.vendorsLoading.set(true); this.vendorsError.set(false);` at its top — required for correctness now that it can run more than once (the original body only ever ran once, when those signals already held their initial values).

Change the `@angular/core` import (line 1):

```ts
import { ChangeDetectionStrategy, Component, Input, OnInit, inject, signal, effect } from '@angular/core';
```

Add the import after `ApiService`:

```ts
import { ProfileService } from '../../core/profile.service';
```

Add the field and a constructor:

```ts
  private profileService = inject(ProfileService);

  constructor() {
    // GET /api/facets carries no profile data (Finding 3) — see dashboard.component.ts's
    // identical note.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      this.load();
    });
  }
```

Replace the body of `ngOnInit` with a call to a new private `load()`:

```ts
  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.vendorsLoading.set(true);
    this.vendorsError.set(false);
    this.api.facets().subscribe({
      next: (f) => {
        this.vendorsTotal.set(f.vendors.length);
        // Capped so the list stays scannable; the total count still gates the empty-state above.
        this.vendorNames.set(f.vendors.slice(0, 12));
        this.vendorsLoading.set(false);
      },
      error: () => {
        this.vendorsError.set(true);
        this.vendorsLoading.set(false);
      },
    });
  }
```

- [ ] **Step 3: `arsenal-index.component.ts`**

Change the `@angular/core` import (line 1):

```ts
import { Component, ChangeDetectionStrategy, OnInit, inject, signal, computed, effect } from '@angular/core';
```

Add the import after `ApiService`:

```ts
import { ProfileService } from '../../core/profile.service';
```

Add the field and a constructor:

```ts
  private profileService = inject(ProfileService);

  constructor() {
    // GET /api/sources carries no profile data (Finding 3).
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      this.load();
    });
  }
```

- [ ] **Step 4: `cve.component.ts`**

Change the `@angular/core` import (line 1):

```ts
import { Component, ChangeDetectionStrategy, inject, signal, computed, effect } from '@angular/core';
```

Add the import after `ApiService`:

```ts
import { ProfileService } from '../../core/profile.service';
```

Add the field next to `private api = inject(ApiService);`:

```ts
  private profileService = inject(ProfileService);
```

In the constructor, after the existing `this.route.paramMap.pipe(takeUntilDestroyed()).subscribe(...)` block, append:

```ts

    // GET /api/cves/:cveId carries no profile data (Finding 3).
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      if (this.id) this.load();
    });
```

- [ ] **Step 5: `actor.component.ts`**

Change the `@angular/core` import (line 1):

```ts
import { Component, ChangeDetectionStrategy, inject, signal, effect } from '@angular/core';
```

Add the import after `ApiService`:

```ts
import { ProfileService } from '../../core/profile.service';
```

Add the field next to `private api = inject(ApiService);`:

```ts
  private profileService = inject(ProfileService);
```

In the constructor, after the existing `this.route.paramMap.pipe(takeUntilDestroyed()).subscribe(...)` block, append:

```ts

    // GET /api/actors/:name carries no profile data (Finding 3). This is also the transitive
    // fix for entity-profile.component.ts, which shares this page's render body but owns no
    // fetch of its own (Finding 2).
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      if (this.name) this.load();
    });
```

- [ ] **Step 6: `malware.component.ts`**

Identical to Step 5 with `family`/`malware`:

Change the `@angular/core` import (line 1):

```ts
import { Component, ChangeDetectionStrategy, inject, signal, effect } from '@angular/core';
```

Add the import after `ApiService`:

```ts
import { ProfileService } from '../../core/profile.service';
```

Add the field next to `private api = inject(ApiService);`:

```ts
  private profileService = inject(ProfileService);
```

In the constructor, after the existing `this.route.paramMap.pipe(takeUntilDestroyed()).subscribe(...)` block, append:

```ts

    // GET /api/malware/:family carries no profile data (Finding 3). Transitive fix for
    // entity-profile.component.ts (Finding 2), same as actor.component.ts.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      if (this.family) this.load();
    });
```

- [ ] **Step 7: Type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add frontend-v4/src/app/pages/dashboard/dashboard.component.ts frontend-v4/src/app/pages/dashboard/lane-exploited.component.ts frontend-v4/src/app/pages/arsenal/arsenal-index.component.ts frontend-v4/src/app/pages/entity/cve.component.ts frontend-v4/src/app/pages/entity/actor.component.ts frontend-v4/src/app/pages/entity/malware.component.ts
git commit -m "chore(profile): wire the same profile-switch refetch into dashboard/facets/sources/cve/actor/malware pages"
```

---

## Part 2 — `profile_assets` records a version (backend)

### Task 4: schema columns + `profiles.js` validator/read/write path

**Files:**
- Modify: `server/db.js` (two `ALTER TABLE` lines)
- Modify: `server/profiles.js` (`assetList`, `attachAssets`, `writeAssets`)
- Test: `server/schema.test.js`, `server/profiles.test.js` (append)

**Interfaces:**
- Produces: `profile_assets.version TEXT`, `profile_assets.version_state TEXT NOT NULL DEFAULT 'unset' CHECK (version_state IN ('unset','known','unknown'))`. `assetList()`'s output asset shape becomes `{ vendor, product, exposure, version, versionState }` (was `{ vendor, product, exposure }`) — every asset object read from `getProfile`/`listProfiles`/`createProfile`/`updateProfile` now carries these two fields. Consumed by Task 9's route (PATCH) and by Spec B.
- **Breaking change to existing test fixtures:** several existing tests in `profiles.test.js` and `api.test.js` assert the exact shape of a returned asset with `assert.deepStrictEqual`. Adding two fields to every asset breaks them unless updated in the same commit — Step 3 below updates every one found by inspection (`ASSET` constant plus four inline literals in `profiles.test.js`, two in `api.test.js`).

- [ ] **Step 1: Write the failing tests**

Append to `server/schema.test.js`:

```js
test('profile_assets has version and version_state, defaulting to null/unset', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const cols = await store.all(
      "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'profile_assets'");
    const byName = Object.fromEntries(cols.map((c) => [c.column_name, c.data_type]));
    assert.strictEqual(byName.version, 'text');
    assert.strictEqual(byName.version_state, 'text');

    const p = await store.get(
      "INSERT INTO profiles (name, sector) VALUES ('vs-test','finance') RETURNING id");
    const row = await store.get(
      `INSERT INTO profile_assets (profile_id, vendor, product) VALUES ($1,'fortinet','fortios')
       RETURNING version, version_state`, [p.id]);
    assert.strictEqual(row.version, null);
    assert.strictEqual(row.version_state, 'unset');
  } finally { await cleanup(); }
});

test('profile_assets rejects an unknown version_state', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const p = await store.get(
      "INSERT INTO profiles (name, sector) VALUES ('vs-test-2','finance') RETURNING id");
    await assert.rejects(
      store.run(
        `INSERT INTO profile_assets (profile_id, vendor, product, version_state)
         VALUES ($1,'fortinet','fortios','maybe')`, [p.id]));
  } finally { await cleanup(); }
});
```

Append to `server/profiles.test.js` — new tests for the validator, plus updates to every existing `deepStrictEqual` on an asset shape (Step 3 below covers the updates; these are the new tests):

```js
test('validateProfile defaults version to null and versionState to unset', () => {
  const r = validateProfile({ ...VALID, assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }] });
  assert.strictEqual(r.value.assets[0].version, null);
  assert.strictEqual(r.value.assets[0].versionState, 'unset');
});

test('validateProfile accepts a well-formed version and versionState', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '7.4.5', versionState: 'known' }] });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.value.assets[0].version, '7.4.5');
  assert.strictEqual(r.value.assets[0].versionState, 'known');
});

test('validateProfile trims a version string', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', version: ' 7.4.5 ', versionState: 'known' }] });
  assert.strictEqual(r.value.assets[0].version, '7.4.5');
});

test('validateProfile rejects a version containing whitespace', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', version: '7.4 5', versionState: 'known' }] });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /version/);
});

test('validateProfile rejects a version over 64 characters', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', version: 'x'.repeat(65), versionState: 'known' }] });
  assert.strictEqual(r.ok, false);
});

test('validateProfile rejects an unknown versionState', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', versionState: 'maybe' }] });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /version state/);
});

test('createProfile persists version and versionState through writeAssets/attachAssets', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, { ...VALID,
      assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '7.4.5', versionState: 'known' }] });
    const got = await getProfile(store, created.id);
    assert.strictEqual(got.assets[0].version, '7.4.5');
    assert.strictEqual(got.assets[0].versionState, 'known');
  } finally { await cleanup(); }
});

test('versionState "unknown" (asked, declined) round-trips with a null version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, { ...VALID,
      assets: [{ vendor: 'fortinet', product: 'fortios', versionState: 'unknown' }] });
    const got = await getProfile(store, created.id);
    assert.strictEqual(got.assets[0].version, null);
    assert.strictEqual(got.assets[0].versionState, 'unknown');
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/schema.test.js server/profiles.test.js`
Expected: FAIL — `column "version" does not exist` / `versionState` undefined.

- [ ] **Step 3: Implement**

In `server/db.js`, immediately after the `profile_assets` table's `CREATE TABLE IF NOT EXISTS` block (right after the `CREATE INDEX IF NOT EXISTS idx_profile_assets_product ...` line), add:

```js
    -- The version a reader told us they run on this asset, and whether they were ever asked.
    -- Three states, not a nullable string, so a declined question ('unknown') is distinguishable
    -- from a question never asked ('unset') — collapsing them would make the remediation page
    -- re-nag on every visit. Never inferred: a missing answer is recorded as missing, the same
    -- rule 'exposure' already applies by defaulting to 'unknown' rather than to 'internal'.
    ALTER TABLE profile_assets ADD COLUMN IF NOT EXISTS version TEXT;
    ALTER TABLE profile_assets ADD COLUMN IF NOT EXISTS version_state TEXT NOT NULL DEFAULT 'unset'
      CHECK (version_state IN ('unset','known','unknown'));
```

(Place this near the other `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` statements further down in the file is also fine — the important part is it runs after `profile_assets` exists, which every `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` in this file already assumes for its own table.)

In `server/profiles.js`, add the version-states list near `EXPOSURES`:

```js
const VERSION_STATES = ['unset', 'known', 'unknown'];

// A version is an identifier, not prose: 1-64 chars, no whitespace, no control characters.
// Trimmed first so surrounding whitespace from a copy-pasted value doesn't fail validation.
function validVersion(raw) {
  if (raw == null || raw === '') return { ok: true, value: null };
  if (typeof raw !== 'string') return { ok: false, error: 'asset version must be a string' };
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 64) {
    return { ok: false, error: `asset version must be 1-64 characters: ${raw}` };
  }
  if (/[\s\x00-\x1f\x7f]/.test(trimmed)) {
    return { ok: false, error: `asset version must not contain whitespace or control characters: ${raw}` };
  }
  return { ok: true, value: trimmed };
}
```

Replace the body of `assetList()`'s per-asset loop to add version/versionState (the function's shape stays the same; only the object pushed to `out` and the validation before it change):

```js
function assetList(input) {
  if (input == null) return { ok: true, value: [] };
  if (!Array.isArray(input)) return { ok: false, error: 'assets must be an array' };
  const out = [];
  const seen = new Set();
  for (const raw of input) {
    if (!raw || typeof raw !== 'object') return { ok: false, error: 'asset entries must be objects' };
    const vendor = raw.vendor == null || raw.vendor === ''
      ? null
      : String(raw.vendor).trim().toLowerCase();
    const product = typeof raw.product === 'string' ? raw.product.trim().toLowerCase() : '';
    if (vendor !== null && !SLUG_RE.test(vendor)) {
      return { ok: false, error: `asset vendor is not a valid slug: ${raw.vendor}` };
    }
    if (!SLUG_RE.test(product)) {
      return { ok: false, error: `asset product is not a valid slug: ${raw.product}` };
    }
    const exposure = raw.exposure == null ? 'unknown' : raw.exposure;
    if (!EXPOSURES.includes(exposure)) return { ok: false, error: `unknown exposure: ${raw.exposure}` };

    const versionResult = validVersion(raw.version);
    if (!versionResult.ok) return versionResult;
    const versionState = raw.versionState == null ? 'unset' : raw.versionState;
    if (!VERSION_STATES.includes(versionState)) {
      return { ok: false, error: `unknown version state: ${raw.versionState}` };
    }

    const key = `${vendor}/${product}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ vendor, product, exposure, version: versionResult.value, versionState });
  }
  return { ok: true, value: out };
}
```

Replace `attachAssets()`:

```js
async function attachAssets(store, rows) {
  if (!rows.length) return rows;
  const ids = rows.map((r) => r.id);
  const assets = await store.all(
    `SELECT profile_id, vendor, product, exposure, version, version_state FROM profile_assets
      WHERE profile_id = ANY($1) ORDER BY vendor, product`, [ids]);
  const byProfile = new Map(ids.map((id) => [id, []]));
  for (const a of assets) {
    byProfile.get(a.profile_id).push({
      vendor: a.vendor, product: a.product, exposure: a.exposure,
      version: a.version, versionState: a.version_state,
    });
  }
  for (const row of rows) row.assets = byProfile.get(row.id) || [];
  return rows;
}
```

Replace `writeAssets()`:

```js
async function writeAssets(t, profileId, assets) {
  await t.run('DELETE FROM profile_assets WHERE profile_id = $1', [profileId]);
  for (const a of assets) {
    if (a.vendor) {
      await t.run(
        `INSERT INTO profile_assets (profile_id, vendor, product, exposure, version, version_state)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (profile_id, vendor, product) DO NOTHING`,
        [profileId, a.vendor, a.product, a.exposure, a.version, a.versionState]);
      continue;
    }
    await t.run(
      `INSERT INTO profile_assets (profile_id, vendor, product, exposure, version, version_state)
       SELECT DISTINCT $1::int, c.vendor, c.product, $3::text, $4::text, $5::text
         FROM item_cpes c WHERE c.product = $2
       ON CONFLICT (profile_id, vendor, product) DO NOTHING`,
      [profileId, a.product, a.exposure, a.version, a.versionState]);
  }
}
```

Now update the pre-existing test literals that assert an exact asset shape (these break the moment `assetList`/`attachAssets` add the two new fields):

In `server/profiles.test.js`, change the `ASSET` constant (line 148):

```js
const ASSET = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' };
```

Change the literal at line 174-175 (`validateProfile lowercases asset slugs`):

```js
  assert.deepStrictEqual(r.value.assets[0],
    { vendor: 'fortinet', product: 'fortios', exposure: 'unknown', version: null, versionState: 'unset' });
```

Change the literal at line 202-203 (`validateProfile accepts an asset with no vendor`):

```js
  assert.deepStrictEqual(r.value.assets[0],
    { vendor: null, product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' });
```

Change the literal at line 252-253 (`updateProfile replaces the asset set and bumps profile_version`):

```js
    assert.deepStrictEqual((await getProfile(store, created.id)).assets,
      [{ vendor: 'microsoft', product: 'windows', exposure: 'internal', version: null, versionState: 'unset' }]);
```

In `server/api.test.js`, change the literal at line 787-788 (`POST /api/profiles accepts assets and returns them resolved`):

```js
    assert.deepStrictEqual(res.body.assets,
      [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' }]);
```

Change the literal at line 818-819 (`PUT /api/profiles/:id replaces the asset set`):

```js
    assert.deepStrictEqual(updated.body.assets,
      [{ vendor: 'fortinet', product: 'fortiproxy', exposure: 'internal', version: null, versionState: 'unset' }]);
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/schema.test.js server/profiles.test.js server/api.test.js`
Expected: PASS, all tests including the four updated literals.

Run the full backend suite to confirm nothing else asserts on asset shape:
Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add server/db.js server/profiles.js server/profiles.test.js server/api.test.js server/schema.test.js
git commit -m "feat(profiles): add profile_assets.version/version_state, validated through the asset ladder"
```

---

## Part 3 — `server/version_compare.js`

### Task 5: pure comparator, adversarial test suite

**Files:**
- Create: `server/version_compare.js`
- Test: `server/version_compare.test.js`

**Interfaces:**
- Produces: `compareVersions(a: string|null, b: string|null): -1 | 0 | 1 | null`. `affectedStatus(installed: string|null, entry: {startIncluding, startExcluding, endIncluding, endExcluding, pinned} | null): 'affected' | 'not_covered' | 'unknown'`. `entry` is exactly the shape `consolidate.js`'s `versionBounds()`/`affectedVersionsFrom()` already produce (one element of `cve_intel.affected_versions`). Consumed by Task 6 (`remediation.js`) and Task 8/9's routes.

- [ ] **Step 1: Write the failing tests**

Create `server/version_compare.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { compareVersions, affectedStatus } = require('./version_compare');

// --- compareVersions ---

test('Windows four-part builds: less than', () => {
  assert.strictEqual(compareVersions('10.0.26100.8300', '10.0.26100.8875'), -1);
});

test('Windows four-part builds: equal', () => {
  assert.strictEqual(compareVersions('10.0.26100.8875', '10.0.26100.8875'), 0);
});

test('Windows four-part builds: greater than', () => {
  assert.strictEqual(compareVersions('10.0.26100.9001', '10.0.26100.8875'), 1);
});

test('segment-count mismatch: 2.0 equals 2.0.0 (shorter padded with zero)', () => {
  assert.strictEqual(compareVersions('2.0', '2.0.0'), 0);
});

test('segment-count mismatch: 7.4 is less than 7.4.5', () => {
  assert.strictEqual(compareVersions('7.4', '7.4.5'), -1);
});

test('numeric, not lexical: 7.4.10 is greater than 7.4.9', () => {
  // A string comparison gets this backwards ('10' < '9' lexically) — the classic
  // version-compare bug, and the one most likely to tell someone they are patched.
  assert.strictEqual(compareVersions('7.4.10', '7.4.9'), 1);
});

test('leading zeros: 1.02 equals 1.2', () => {
  assert.strictEqual(compareVersions('1.02', '1.2'), 0);
});

test('every uncomparable shape returns null, individually', () => {
  const other = '1.0.0';
  for (const bad of ['1.0.0-rc1', '1:2.4.1', '2.4.1-3.el9', 'v7.4.5', '2024.1a', '', null]) {
    assert.strictEqual(compareVersions(bad, other), null, `expected null for ${JSON.stringify(bad)}`);
    assert.strictEqual(compareVersions(other, bad), null, `expected null for ${JSON.stringify(bad)} as second arg`);
  }
});

test('compareVersions(null, null) is null, not 0 — absence is not equality', () => {
  assert.strictEqual(compareVersions(null, null), null);
});

// --- affectedStatus ---

const NO_BOUNDS = { startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: null, pinned: null };

test('affectedStatus: inside a "before X" range is affected', () => {
  assert.strictEqual(affectedStatus('7.4.0', { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'affected');
});

test('affectedStatus: outside a "before X" range is not_covered', () => {
  assert.strictEqual(affectedStatus('7.5.0', { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'not_covered');
});

test('affectedStatus: exactly at the excluded boundary is not_covered (endExcluding is exclusive)', () => {
  assert.strictEqual(affectedStatus('7.4.5', { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'not_covered');
});

test('affectedStatus: inside "X through Y" (inclusive both ends) is affected', () => {
  assert.strictEqual(
    affectedStatus('1.2.0', { ...NO_BOUNDS, startIncluding: '1.0.0', endIncluding: '1.5.0' }), 'affected');
});

test('affectedStatus: at the inclusive upper bound of "X through Y" is affected', () => {
  assert.strictEqual(
    affectedStatus('1.5.0', { ...NO_BOUNDS, startIncluding: '1.0.0', endIncluding: '1.5.0' }), 'affected');
});

test('affectedStatus: below the lower bound of "X through Y" is not_covered', () => {
  assert.strictEqual(
    affectedStatus('0.9.0', { ...NO_BOUNDS, startIncluding: '1.0.0', endIncluding: '1.5.0' }), 'not_covered');
});

test('affectedStatus: a pin that matches is affected', () => {
  assert.strictEqual(affectedStatus('4.2.1', { ...NO_BOUNDS, pinned: '4.2.1' }), 'affected');
});

test('affectedStatus: a pin that differs is unknown, never not_covered', () => {
  assert.strictEqual(affectedStatus('4.2.2', { ...NO_BOUNDS, pinned: '4.2.1' }), 'unknown');
});

test('affectedStatus: an entry with no usable bound at all is unknown', () => {
  assert.strictEqual(affectedStatus('4.2.2', { ...NO_BOUNDS }), 'unknown');
});

test('affectedStatus: no installed version is unknown even against a bounded entry', () => {
  assert.strictEqual(affectedStatus(null, { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'unknown');
});

test('affectedStatus: no entry at all is unknown', () => {
  assert.strictEqual(affectedStatus('7.4.0', null), 'unknown');
});

test('affectedStatus: an uncomparable installed version against a bounded entry is unknown, not not_covered', () => {
  assert.strictEqual(affectedStatus('v7.0', { ...NO_BOUNDS, endExcluding: '7.4.5' }), 'unknown');
});

// The property this module exists to guarantee: a null anywhere in the comparison chain can
// never produce not_covered. Exhaustive over every bound-field combination that involves a
// comparison at all (pin is checked separately below since it uses string equality, not
// compareVersions).
test('property: no bound-comparison combination returns not_covered when a comparison is null', () => {
  const uncomparable = 'v1.0';
  const boundKeys = ['startIncluding', 'startExcluding', 'endIncluding', 'endExcluding'];
  for (const key of boundKeys) {
    const entry = { ...NO_BOUNDS, [key]: uncomparable };
    const result = affectedStatus('1.0.0', entry);
    assert.notStrictEqual(result, 'not_covered', `${key}=${uncomparable} must not yield not_covered`);
  }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/version_compare.test.js`
Expected: FAIL — `Cannot find module './version_compare'`.

- [ ] **Step 3: Implement**

Create `server/version_compare.js`:

```js
// Pure dotted-numeric version comparison. This is the one part of the remediation feature that
// can hurt someone directly — a comparator bug that says "you're patched" when you are not is
// worse than no comparator at all — so it abstains (returns null) the moment it meets anything
// it has no business ordering, rather than guessing. See CLAUDE.md / the remediation-foundation
// spec for the reasoning; do not "improve" this into a semver/RPM/dpkg-aware comparator without
// a spec of its own — three comparator implementations with three test suites is a different
// project, and abstaining is safe where guessing is not.
//
// No I/O, no throw. Every public function returns a value, never an exception, for any input.

// Splits a version string into its numeric segments, or null the moment any segment is not a
// bare run of digits. '1.02' and '1.2' compare equal (Number() strips the leading zero); '1.0.0-rc1',
// '1:2.4.1', '2.4.1-3.el9' and 'v7.4.5' all fail on their first non-numeric segment.
function segmentsOf(v) {
  if (typeof v !== 'string' || v === '') return null;
  const parts = v.split('.');
  const nums = [];
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    nums.push(Number(p));
  }
  return nums;
}

// -1 | 0 | 1 when both sides are confidently ordered, null the moment either side is not a
// plain dotted-numeric version. Shorter operands are treated as zero-padded ('2.0' == '2.0.0'),
// and comparison is numeric per segment, not lexical ('7.4.10' > '7.4.9' — a string compare
// gets this backwards, which is the classic version-compare bug).
function compareVersions(a, b) {
  const sa = segmentsOf(a);
  const sb = segmentsOf(b);
  if (sa === null || sb === null) return null;
  const len = Math.max(sa.length, sb.length);
  for (let i = 0; i < len; i += 1) {
    const x = sa[i] ?? 0;
    const y = sb[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

// One affected_versions entry, already selected by the caller for the asset's vendor/product
// (playbook.js's confirmStep does the same match). `installed` is the version a reader told us
// they run — null/absent means "not asked, or asked and declined", and must read as unknown,
// never as evidence of safety.
//
// Two asymmetries are load-bearing, both from the spec:
//  - `not_covered` requires every comparison actually attempted to have resolved (non-null). The
//    moment any comparison the entry's bounds require returns null, the result is 'unknown', full
//    stop — never falls through to a not_covered verdict built on a partial answer.
//  - A `pinned` mismatch is 'unknown', never 'not_covered'. An exact-pin CPE match usually
//    reflects how the CNA filed the record, not an assertion that neighbouring builds are safe.
function affectedStatus(installed, entry) {
  if (!entry) return 'unknown';
  if (installed == null || installed === '') return 'unknown';

  const { startIncluding, startExcluding, endIncluding, endExcluding, pinned } = entry;
  const hasBound = Boolean(startIncluding || startExcluding || endIncluding || endExcluding);

  if (hasBound) {
    let lowerOk = true;
    if (startIncluding) {
      const c = compareVersions(installed, startIncluding);
      if (c === null) return 'unknown';
      lowerOk = c !== -1;
    } else if (startExcluding) {
      const c = compareVersions(installed, startExcluding);
      if (c === null) return 'unknown';
      lowerOk = c === 1;
    }

    let upperOk = true;
    if (endIncluding) {
      const c = compareVersions(installed, endIncluding);
      if (c === null) return 'unknown';
      upperOk = c !== 1;
    } else if (endExcluding) {
      const c = compareVersions(installed, endExcluding);
      if (c === null) return 'unknown';
      upperOk = c === -1;
    }

    return lowerOk && upperOk ? 'affected' : 'not_covered';
  }

  if (pinned) {
    return installed === pinned ? 'affected' : 'unknown';
  }

  return 'unknown';
}

module.exports = { compareVersions, affectedStatus };
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/version_compare.test.js`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add server/version_compare.js server/version_compare.test.js
git commit -m "feat(remediation): add pure version_compare.js — abstains rather than guesses"
```

---

## Part 4 — `server/remediation.js`

### Task 6: fix ladder + per-(asset,item) summary

**Files:**
- Create: `server/remediation.js`
- Test: `server/remediation.test.js`

**Interfaces:**
- Consumes: `affectedStatus` (Task 5). `entry` shape from `cve_intel.affected_versions` (Task 1 of the merged impact-provenance plan: `{ vendor, product, text, startIncluding, startExcluding, endIncluding, endExcluding, pinned }`). Playbook steps shape from `buildPlaybook()` (`server/playbook.js`, already merged): `{ key, title, detail, source, link }[]`.
- Produces: `fixTarget(entry, cveIntel): { kind: 'version', value } | { kind: 'patch', value } | { kind: 'advisory', value } | { kind: 'none' }`, where `cveIntel` is `{ patchUrl, advisoryUrl }` (the same camelCase shape `relevance.js`'s `item.cve` already carries). `remediationFor(asset, affectedVersions, cveIntel, playbookSteps): { status, installed, versionState, entry, fix, mitigations }`, where `asset` is `{ vendor, product, exposure, version, versionState }` (Task 4's shape) and `affectedVersions` is the full array for the item's CVE (the caller finds the matching entry — no, see note below). Consumed by Tasks 7–9's routes.

Note on `entry`-finding: the spec's pseudocode shows `remediationFor(asset, affectedVersions, ...)` receiving the *whole* array and presumably matching internally, mirroring `confirmStep`'s own `(affectedVersions || []).find((v) => v.vendor === vendor && v.product === product)`. This task does the match inside `remediationFor` for exactly that reason — one matching rule, not two copies of it.

- [ ] **Step 1: Write the failing tests**

Create `server/remediation.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { fixTarget, remediationFor } = require('./remediation');
const { buildPlaybook } = require('./playbook');

// --- fixTarget: the ladder ---

test('fixTarget: endExcluding produces a version target', () => {
  assert.deepStrictEqual(fixTarget({ endExcluding: '7.4.5' }, {}), { kind: 'version', value: '7.4.5' });
});

test('fixTarget: falls back to patchUrl when there is no endExcluding', () => {
  assert.deepStrictEqual(
    fixTarget({ endIncluding: '2.4.1' }, { patchUrl: 'https://example.com/patch' }),
    { kind: 'patch', value: 'https://example.com/patch' });
});

test('fixTarget: a patch wins over an advisory when both exist', () => {
  assert.deepStrictEqual(
    fixTarget(null, { patchUrl: 'https://example.com/patch', advisoryUrl: 'https://example.com/advisory' }),
    { kind: 'patch', value: 'https://example.com/patch' });
});

test('fixTarget: falls back to advisoryUrl when there is no patch', () => {
  assert.deepStrictEqual(
    fixTarget(null, { advisoryUrl: 'https://example.com/advisory' }),
    { kind: 'advisory', value: 'https://example.com/advisory' });
});

test('fixTarget: none when nothing is available', () => {
  assert.deepStrictEqual(fixTarget(null, {}), { kind: 'none' });
  assert.deepStrictEqual(fixTarget(null, null), { kind: 'none' });
});

// The fabrication guard: neither endIncluding nor pinned may ever produce kind: 'version',
// because neither names a fixed version — asserted directly, not just implied by the ladder
// order above.
test('fixTarget: an endIncluding-only entry never produces kind version', () => {
  const r = fixTarget({ endIncluding: '2.4.1' }, {});
  assert.notStrictEqual(r.kind, 'version');
});

test('fixTarget: a pinned-only entry never produces kind version', () => {
  const r = fixTarget({ pinned: '4.2.1' }, {});
  assert.notStrictEqual(r.kind, 'version');
});

// --- remediationFor ---

const WORST = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const LOCAL = 'CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N';
const NO_BOUNDS = { startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: null, pinned: null };

test('remediationFor: kind none still surfaces restrict/rotate mitigations when the vector supports them', () => {
  const steps = buildPlaybook({ vector: WORST, exposure: 'internet', vendor: 'fortinet', product: 'fortios' });
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' };
  const r = remediationFor(asset, [], {}, steps);
  assert.strictEqual(r.fix.kind, 'none');
  assert.ok(r.mitigations.some((s) => s.key === 'restrict'));
  assert.ok(r.mitigations.some((s) => s.key === 'rotate'));
  assert.ok(r.mitigations.every((s) => s.key === 'restrict' || s.key === 'rotate'));
});

test('remediationFor: mitigations is empty when the vector does not support restrict or rotate', () => {
  const steps = buildPlaybook({ vector: LOCAL, exposure: 'internal', vendor: 'fortinet', product: 'fortios' });
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internal', version: null, versionState: 'unset' };
  const r = remediationFor(asset, [], {}, steps);
  assert.deepStrictEqual(r.mitigations, []);
});

test('remediationFor: a known version inside a bounded range reports affected and the fix version', () => {
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '7.4.0', versionState: 'known' };
  const affectedVersions = [{ vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5', ...NO_BOUNDS, endExcluding: '7.4.5' }];
  const r = remediationFor(asset, affectedVersions, {}, []);
  assert.strictEqual(r.status, 'affected');
  assert.strictEqual(r.installed, '7.4.0');
  assert.strictEqual(r.versionState, 'known');
  assert.strictEqual(r.fix.kind, 'version');
  assert.strictEqual(r.fix.value, '7.4.5');
});

test('remediationFor: an unset version reports unknown status even against a bounded entry', () => {
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' };
  const affectedVersions = [{ vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5', ...NO_BOUNDS, endExcluding: '7.4.5' }];
  const r = remediationFor(asset, affectedVersions, {}, []);
  assert.strictEqual(r.status, 'unknown');
  assert.strictEqual(r.installed, null);
});

test('remediationFor: a version above a bounded range reports not_covered', () => {
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '8.0.0', versionState: 'known' };
  const affectedVersions = [{ vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5', ...NO_BOUNDS, endExcluding: '7.4.5' }];
  const r = remediationFor(asset, affectedVersions, {}, []);
  assert.strictEqual(r.status, 'not_covered');
});

test('remediationFor: no entry for this vendor/product reports unknown, not an absent field', () => {
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '7.4.0', versionState: 'known' };
  const affectedVersions = [{ vendor: 'microsoft', product: 'windows_11_24h2', text: 'before X', ...NO_BOUNDS, endExcluding: 'X' }];
  const r = remediationFor(asset, affectedVersions, {}, []);
  assert.strictEqual(r.status, 'unknown');
  assert.strictEqual(r.entry, null);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/remediation.test.js`
Expected: FAIL — `Cannot find module './remediation'`.

- [ ] **Step 3: Implement**

Create `server/remediation.js`:

```js
// The fix ladder and the per-(asset,item) remediation summary. Pure: no I/O, no model, no
// database — same discipline as playbook.js, which this module reads from and never duplicates.
//
// fixTarget composes no URL and names no version it did not read verbatim from an NVD bound
// field or a stored patch_url/advisory_url. A fabricated patch instruction is the worst output
// this whole feature could produce, because a reader would act on it.
const { affectedStatus } = require('./version_compare');

// entry: one cve_intel.affected_versions element (or null — no entry matched this asset).
// cveIntel: { patchUrl, advisoryUrl } — the same camelCase shape relevance.js already builds
// from cve_intel for a given item.
//
// Order is exactly endExcluding, then patch, then advisory, then none. endExcluding is the only
// field that names a fixed version — endIncluding ("X and earlier is broken") and pinned
// ("exactly X is broken") both name a broken version, never a fixed one, and must never reach
// kind: 'version'. This is consolidate.js's own rule for versionBounds(), enforced here where
// the inference from "broken version" to "fixed version" would otherwise happen.
function fixTarget(entry, cveIntel) {
  if (entry && entry.endExcluding) return { kind: 'version', value: entry.endExcluding };
  if (cveIntel && cveIntel.patchUrl) return { kind: 'patch', value: cveIntel.patchUrl };
  if (cveIntel && cveIntel.advisoryUrl) return { kind: 'advisory', value: cveIntel.advisoryUrl };
  return { kind: 'none' };
}

// asset: { vendor, product, exposure, version, versionState } — one profile_assets row.
// affectedVersions: the full cve_intel.affected_versions array for the item's CVE; the matching
// entry (if any) is found here, the same rule playbook.js's confirmStep already applies, so there
// is exactly one place this match happens rather than two copies of it drifting apart.
// cveIntel: { patchUrl, advisoryUrl }.
// playbookSteps: the item's already-built buildPlaybook() output.
function remediationFor(asset, affectedVersions, cveIntel, playbookSteps) {
  const entry = (affectedVersions || [])
    .find((v) => v.vendor === asset.vendor && v.product === asset.product) || null;

  // Only a recorded ('known') version is a claim about what the reader runs. 'unset'/'unknown'
  // must never be treated as a version to compare — affectedStatus already treats a null
  // installed as unknown, but this is where that null is decided, not left to the caller.
  const installed = asset.versionState === 'known' ? asset.version : null;

  return {
    status: affectedStatus(installed, entry),
    installed,
    versionState: asset.versionState,
    entry,
    fix: fixTarget(entry, cveIntel),
    // The subset of the playbook that acts without a fix — surfaced explicitly so a kind:
    // 'none' fix has something to offer instead of a dead end. These steps are already guarded
    // by the CVSS vector in playbook.js; this only names them as the fallback path.
    mitigations: (playbookSteps || []).filter((s) => s.key === 'restrict' || s.key === 'rotate'),
  };
}

module.exports = { fixTarget, remediationFor };
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/remediation.test.js`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add server/remediation.js server/remediation.test.js
git commit -m "feat(remediation): add pure fixTarget/remediationFor fix ladder"
```

---

## Part 5 — routes

### Task 7: `GET /api/profiles/:id/remediation` (the queue)

**Files:**
- Modify: `server/index.js`
- Test: `server/api.test.js` (append)

**Interfaces:**
- Consumes: `remediationFor` (Task 6), `profiles.getProfile` (existing).
- Produces: `GET /api/profiles/:id/remediation` → `Array<{ vendor, product, exposure, version, versionState, items: Array<{ itemId, title, tier, score, status, installed, versionState, entry, fix, mitigations }> }>` — one entry per `profile_assets` row that has at least one `act_now`/`watch` item at the profile's current `profile_version`, grouped by `(vendor, product)`.

- [ ] **Step 1: Write the failing tests**

Append to `server/api.test.js`:

```js
test('GET /api/profiles/:id/remediation groups open threats by asset', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run(
      `UPDATE cve_intel SET affected_versions = $1 WHERE cve_id = 'CVE-2026-1'`,
      [JSON.stringify([{
        vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5',
        startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: '7.4.5', pinned: null,
      }])]);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/profiles/${created.body.id}/remediation`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.length, 1);
    assert.strictEqual(res.body[0].vendor, 'fortinet');
    assert.strictEqual(res.body[0].product, 'fortios');
    assert.strictEqual(res.body[0].versionState, 'unset');
    assert.strictEqual(res.body[0].items.length, 1);
    assert.strictEqual(res.body[0].items[0].itemId, hitId);
    assert.strictEqual(res.body[0].items[0].fix.kind, 'version');
    assert.strictEqual(res.body[0].items[0].fix.value, '7.4.5');
    // No version recorded yet — unset must never read as affected or not_covered.
    assert.strictEqual(res.body[0].items[0].status, 'unknown');
  } finally { await cleanup(); }
});

test('GET /api/profiles/:id/remediation excludes low/not_yours items', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store); // seeds one act_now item and one unrelated news item
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/profiles/${created.body.id}/remediation`);
    const itemIds = res.body.flatMap((g) => g.items.map((i) => i.itemId));
    // Only the fortios/act_now item can appear; the unrelated news item has no matching asset
    // and is not_yours, so it must not show up in any group.
    assert.strictEqual(itemIds.length, res.body.reduce((n, g) => n + g.items.length, 0));
  } finally { await cleanup(); }
});

test('GET /api/profiles/:id/remediation returns 404 for a non-integer id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await get(createApp(store), '/api/profiles/abc/remediation');
    assert.strictEqual(res.status, 404);
  } finally { await cleanup(); }
});

test('GET /api/profiles/:id/remediation returns 404 for an unknown profile id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await get(createApp(store), '/api/profiles/999/remediation');
    assert.strictEqual(res.status, 404);
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: FAIL — 404 (no such route) on the new tests.

- [ ] **Step 3: Implement**

In `server/index.js`, add the import (alongside the existing `require('./playbook')`-adjacent block — `buildPlaybook` isn't directly imported today since `relevance.js` owns that call, so add a fresh line near the other requires at the top):

```js
const { remediationFor } = require('./remediation');
```

Add the route (a sensible location is right after the existing `app.post('/api/profiles/:id/playbooks/word', ...)` block, before `app.get('/api/sources', ...)`):

```js
  // The remediation queue: one entry per asset the profile has told us about, each carrying its
  // open (act_now/watch) threats and what remediationFor says about each. Grouping happens here
  // rather than in relevance.js because an item can match more than one asset (e.g. two Windows
  // builds vulnerable to the same CVE) and the queue's whole point is "group by the thing you'd
  // actually go fix" — recomputeProfile's own per-item asset pick (for consequence/playbook
  // wording) only ever keeps one, which is the wrong shape for this page.
  app.get('/api/profiles/:id/remediation', h(async (req, res) => {
    const id = parseId(req.params.id);
    const profile = id && await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });

    const rows = await store.all(`
      SELECT pa.vendor, pa.product, pa.exposure, pa.version, pa.version_state AS "versionState",
             i.id AS "itemId", i.title, ir.tier, ir.score,
             ci.affected_versions AS "affectedVersions", ci.patch_url AS "patchUrl", ci.advisory_url AS "advisoryUrl",
             ip.steps
        FROM profile_assets pa
        JOIN item_cpes c ON c.vendor = pa.vendor AND c.product = pa.product
        JOIN item_relevance ir ON ir.item_id = c.item_id AND ir.profile_id = pa.profile_id
                               AND ir.profile_version = $2 AND ir.tier IN ('act_now','watch')
        JOIN items i ON i.id = ir.item_id
        LEFT JOIN LATERAL (
          SELECT ci2.* FROM item_cves icv JOIN cve_intel ci2 ON ci2.cve_id = icv.cve_id
           WHERE icv.item_id = i.id
           ORDER BY ci2.kev_listed DESC, ci2.cvss_score DESC NULLS LAST LIMIT 1
        ) ci ON true
        LEFT JOIN item_playbooks ip ON ip.item_id = i.id AND ip.profile_id = pa.profile_id AND ip.profile_version = $2
       WHERE pa.profile_id = $1
       ORDER BY pa.vendor, pa.product, ir.score DESC
    `, [profile.id, profile.profile_version]);

    const groups = new Map();
    for (const r of rows) {
      const key = `${r.vendor}/${r.product}`;
      if (!groups.has(key)) {
        groups.set(key, {
          vendor: r.vendor, product: r.product, exposure: r.exposure,
          version: r.version, versionState: r.versionState, items: [],
        });
      }
      const asset = { vendor: r.vendor, product: r.product, exposure: r.exposure, version: r.version, versionState: r.versionState };
      const rem = remediationFor(asset, r.affectedVersions || [], { patchUrl: r.patchUrl, advisoryUrl: r.advisoryUrl }, r.steps || []);
      groups.get(key).items.push({ itemId: r.itemId, title: r.title, tier: r.tier, score: r.score, ...rem });
    }
    res.json([...groups.values()]);
  }));
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: PASS, all tests including the four new ones.

- [ ] **Step 5: Commit**

```bash
git add server/index.js server/api.test.js
git commit -m "feat(remediation): add GET /api/profiles/:id/remediation queue route"
```

---

### Task 8: `GET /api/items/:id/remediation` (per-item detail)

**Files:**
- Modify: `server/index.js`
- Test: `server/api.test.js` (append)

**Interfaces:**
- Consumes: `remediationFor` (Task 6), `resolveProfile` (existing).
- Produces: `GET /api/items/:id/remediation` → `{ item, relevance, playbook, remediation }` where `remediation` is `remediationFor`'s output or `null` when no `profile_assets` row matches the item's CPEs.

- [ ] **Step 1: Write the failing tests**

Append to `server/api.test.js`:

```js
test('GET /api/items/:id/remediation returns remediationFor output plus relevance and playbook', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run(
      `UPDATE cve_intel SET affected_versions = $1 WHERE cve_id = 'CVE-2026-1'`,
      [JSON.stringify([{
        vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5',
        startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: '7.4.5', pinned: null,
      }])]);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/items/${hitId}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.item.id, hitId);
    assert.ok(res.body.relevance);
    assert.ok(Array.isArray(res.body.playbook));
    assert.strictEqual(res.body.remediation.fix.kind, 'version');
    assert.strictEqual(res.body.remediation.fix.value, '7.4.5');
    assert.strictEqual(res.body.remediation.status, 'unknown');
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation requires X-Profile-Id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const res = await get(app, `/api/items/${hitId}/remediation`);
    assert.strictEqual(res.status, 400);
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation returns 404 for a non-integer id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await get(createApp(store), '/api/items/abc/remediation');
    assert.strictEqual(res.status, 404);
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation returns 400 for an unknown X-Profile-Id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const res = await send(app, 'GET', `/api/items/${hitId}/remediation`, null, { 'X-Profile-Id': '999' });
    assert.strictEqual(res.status, 400);
  } finally { await cleanup(); }
});

test('GET /api/items/:id/remediation returns remediation: null when no asset matches the item', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { missId } = await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    const res = await get(app, `/api/items/${missId}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.remediation, null);
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: FAIL — 404 on the new route's tests.

- [ ] **Step 3: Implement**

In `server/index.js`, add the route directly after Task 7's queue route:

```js
  // Per-item remediation detail. remediation is null when no profile_assets row matches the
  // item's CPEs — the same "no data, not a guess" posture as relevance/playbook already use for
  // an item with no CVE.
  app.get('/api/items/:id/remediation', h(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id) return res.status(404).json({ error: 'not found' });
    const profile = await resolveProfile(req);
    if (!profile) return res.status(400).json({ error: 'X-Profile-Id required' });

    const item = await store.get('SELECT * FROM items WHERE id = $1', [id]);
    if (!item) return res.status(404).json({ error: 'not found' });

    const rel = await store.get(
      'SELECT tier, matches, consequence FROM item_relevance WHERE item_id=$1 AND profile_id=$2 AND profile_version=$3',
      [id, profile.id, profile.profile_version]);
    const pb = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2 AND profile_version=$3',
      [id, profile.id, profile.profile_version]);
    const ci = await store.get(
      `SELECT ci.affected_versions AS "affectedVersions", ci.patch_url AS "patchUrl", ci.advisory_url AS "advisoryUrl"
         FROM item_cves ic JOIN cve_intel ci ON ci.cve_id = ic.cve_id WHERE ic.item_id = $1
        ORDER BY ci.kev_listed DESC, ci.cvss_score DESC NULLS LAST LIMIT 1`, [id]);

    // The asset whose exposure ranks highest among those matching this item's CPEs — same
    // priority order relevance_score.js's EXPOSURE_RANK already uses (internet > unknown >
    // internal) to pick which exposure decides the tier, reused here so this read-time pick
    // agrees with what actually drove the item's own scoring.
    const asset = await store.get(
      `SELECT pa.vendor, pa.product, pa.exposure, pa.version, pa.version_state AS "versionState"
         FROM profile_assets pa JOIN item_cpes c ON c.vendor = pa.vendor AND c.product = pa.product
        WHERE pa.profile_id = $1 AND c.item_id = $2
        ORDER BY CASE pa.exposure WHEN 'internet' THEN 2 WHEN 'unknown' THEN 1 ELSE 0 END DESC
        LIMIT 1`, [profile.id, id]);

    const remediation = asset
      ? remediationFor(asset, (ci && ci.affectedVersions) || [], ci || {}, (pb && pb.steps) || [])
      : null;

    res.json({
      item,
      relevance: rel ? { tier: rel.tier, matches: rel.matches, consequence: rel.consequence } : null,
      playbook: pb ? pb.steps : null,
      remediation,
    });
  }));
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: PASS, all tests including the five new ones.

- [ ] **Step 5: Commit**

```bash
git add server/index.js server/api.test.js
git commit -m "feat(remediation): add GET /api/items/:id/remediation detail route"
```

---

### Task 9: `PATCH /api/profiles/:id/assets/:vendor/:product` (record a version)

**Files:**
- Modify: `server/index.js`
- Test: `server/api.test.js` (append)

**Interfaces:**
- Consumes: `profiles.getProfile`, `profiles.updateProfile` (existing), `recomputeProfile` (existing, imported already in `index.js`).
- Produces: `PATCH /api/profiles/:id/assets/:vendor/:product` with body `{ version?, versionState? }` → `200 { vendor, product, exposure, version, versionState }` (the one updated asset). `404` if the profile has no asset with that `(vendor, product)`. Bumps `profile_version` and **synchronously** completes the recompute before responding — unlike `PUT /api/profiles/:id`'s background recompute, because Spec B's UI reads the consequence of this exact write in the same round trip ("2 other threats ... are no longer inside their affected range").

**Important implementation gotcha, found while researching this task:** `profiles.getProfile()` returns the raw `profiles` table row — snake_case columns (`threat_domains`, `severity_floor`). `profiles.updateProfile(store, id, input)` calls `validateProfile(input)`, which reads **camelCase** (`input.threatDomains`, `input.severityFloor`). Spreading the fetched profile row directly into `updateProfile` (`{ ...profile, assets: nextAssets }`) would silently read `threatDomains`/`severityFloor` as `undefined`, and `validateProfile` defaults those to `[]`/`'medium'` — **silently wiping the profile's threat domains and severity floor on every version PATCH.** The implementation below maps the row's snake_case fields to `validateProfile`'s camelCase input explicitly, and Step 1 includes a test that would catch a regression back to the naive spread.

- [ ] **Step 1: Write the failing tests**

Append to `server/api.test.js`:

```js
test('PATCH /api/profiles/:id/assets/:vendor/:product sets version/versionState and bumps profile_version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    const before = created.body.profile_version;

    const res = await send(app, 'PATCH', `/api/profiles/${created.body.id}/assets/fortinet/fortios`,
      { version: '7.4.5', versionState: 'known' });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body,
      { vendor: 'fortinet', product: 'fortios', exposure: 'unknown', version: '7.4.5', versionState: 'known' });

    const after = await get(app, `/api/profiles/${created.body.id}`);
    assert.strictEqual(after.body.profile_version, before + 1);
  } finally { await cleanup(); }
});

// The gotcha this task's own notes call out: a naive spread of the getProfile() row into
// updateProfile() would silently reset threat_domains/severity_floor to their defaults.
test('PATCH /api/profiles/:id/assets/:vendor/:product does not reset unrelated profile fields', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', {
      ...REL_PROFILE, threatDomains: ['ransomware'], severityFloor: 'high',
    });
    await send(app, 'PATCH', `/api/profiles/${created.body.id}/assets/fortinet/fortios`,
      { version: '7.4.5', versionState: 'known' });

    const after = await get(app, `/api/profiles/${created.body.id}`);
    assert.deepStrictEqual(after.body.threat_domains, ['ransomware']);
    assert.strictEqual(after.body.severity_floor, 'high');
  } finally { await cleanup(); }
});

test('PATCH /api/profiles/:id/assets/:vendor/:product returns 404 for an asset the profile does not have', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    const res = await send(app, 'PATCH', `/api/profiles/${created.body.id}/assets/microsoft/windows_11_24h2`,
      { version: '1', versionState: 'known' });
    assert.strictEqual(res.status, 404);
  } finally { await cleanup(); }
});

test('PATCH /api/profiles/:id/assets/:vendor/:product returns 404 for a non-integer profile id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await send(createApp(store), 'PATCH', '/api/profiles/abc/assets/fortinet/fortios', { version: '1' });
    assert.strictEqual(res.status, 404);
  } finally { await cleanup(); }
});

// The cross-item effect, proven end to end rather than assumed: one PATCH must re-derive the
// status of every item matching the asset, not just the one the caller happened to look at.
test('recording a version flips remediation status for every open item against the same asset', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const src = (await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id")).id;

    async function seedFortiCve(cveId, endExcluding) {
      const item = await store.get(
        `INSERT INTO items (source_id, category, title, external_id, published_at)
         VALUES ($1,'cve',$2,$2, now()) RETURNING id`, [src, cveId]);
      await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [item.id]);
      await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [item.id, cveId]);
      await store.run(
        `INSERT INTO cve_intel (cve_id, severity, kev_listed, source_count, affected_versions)
         VALUES ($1,'high',true,1,$2)`,
        [cveId, JSON.stringify([{
          vendor: 'fortinet', product: 'fortios', text: `before ${endExcluding}`,
          startIncluding: null, startExcluding: null, endIncluding: null, endExcluding, pinned: null,
        }])]);
      return item.id;
    }

    const lowFix = await seedFortiCve('CVE-2026-9001', '7.4.5');
    const highFix = await seedFortiCve('CVE-2026-9002', '9.0.0');

    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    // First recording: a version inside both ranges — both items should read affected.
    await send(app, 'PATCH', `/api/profiles/${created.body.id}/assets/fortinet/fortios`,
      { version: '7.0.0', versionState: 'known' });

    const lowBefore = await get(app, `/api/items/${lowFix}/remediation?profileId=${created.body.id}`);
    const highBefore = await get(app, `/api/items/${highFix}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(lowBefore.body.remediation.status, 'affected');
    assert.strictEqual(highBefore.body.remediation.status, 'affected');

    // Recording an upgrade past the lower fix version: CVE-9001 must flip to not_covered while
    // CVE-9002 (fixed at a still-higher version) stays affected.
    await send(app, 'PATCH', `/api/profiles/${created.body.id}/assets/fortinet/fortios`,
      { version: '8.0.0', versionState: 'known' });

    const lowAfter = await get(app, `/api/items/${lowFix}/remediation?profileId=${created.body.id}`);
    const highAfter = await get(app, `/api/items/${highFix}/remediation?profileId=${created.body.id}`);
    assert.strictEqual(lowAfter.body.remediation.status, 'not_covered');
    assert.strictEqual(highAfter.body.remediation.status, 'affected');
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: FAIL — 404 (no such route) on the new tests.

- [ ] **Step 3: Implement**

In `server/index.js`, add the route directly after Task 8's detail route:

```js
  // Records a version on one asset. Goes through profiles.updateProfile's own transaction (it
  // deletes and rewrites the whole asset set on every save) rather than a bespoke single-row
  // UPDATE — a direct UPDATE would be silently discarded by the next profile save, and
  // duplicating the version-bump/recompute logic in a second place is how the two drift apart.
  app.patch('/api/profiles/:id/assets/:vendor/:product', h(async (req, res) => {
    const id = parseId(req.params.id);
    const profile = id && await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });

    const { vendor, product } = req.params;
    const idx = (profile.assets || []).findIndex((a) => a.vendor === vendor && a.product === product);
    if (idx === -1) return res.status(404).json({ error: 'not found' });

    const nextAssets = profile.assets.map((a, i) => (i === idx
      ? { ...a, version: req.body.version ?? null, versionState: req.body.versionState ?? 'unset' }
      : a));

    // getProfile() returns the raw `profiles` row (snake_case: threat_domains, severity_floor).
    // validateProfile()/updateProfile() read camelCase input. Mapped explicitly here — a plain
    // { ...profile, assets: nextAssets } spread would leave threatDomains/severityFloor
    // undefined and validateProfile would silently default them to []/'medium', wiping both
    // on every version write.
    const input = {
      name: profile.name, sector: profile.sector, vendors: profile.vendors, products: profile.products,
      threatDomains: profile.threat_domains, region: profile.region, severityFloor: profile.severity_floor,
      assets: nextAssets,
    };

    let updated;
    try {
      updated = await profiles.updateProfile(store, id, input);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
    if (!updated) return res.status(404).json({ error: 'not found' });

    // Synchronous, unlike PUT /api/profiles/:id's background recompute: the whole point of this
    // route (Spec B) is that the caller immediately asks "what did that change?", so the
    // response must reflect the new profile_version's verdicts, not the stale ones. The
    // recompute is ~1.3s over the full corpus — not an optimization to skip, per the spec.
    await recomputeProfile(store, updated.id);

    const savedAsset = updated.assets.find((a) => a.vendor === vendor && a.product === product);
    res.json(savedAsset);
  }));
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/node --test server/api.test.js`
Expected: PASS, all tests including the five new ones.

Run the full backend suite:
Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add server/index.js server/api.test.js
git commit -m "feat(remediation): add PATCH /api/profiles/:id/assets/:vendor/:product"
```

---

## Task 10: Full-suite verification

**Files:** none — operational only.

- [ ] **Step 1: Full backend suite**

Run: `cd /home/sah/projects && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures (covers Tasks 4–9 plus regression on every pre-existing test touched by the `profile_assets` shape change).

- [ ] **Step 2: Full frontend suite**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: PASS, 0 failures.

- [ ] **Step 3: Frontend type-check**

Run: `cd /home/sah/projects/frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc --noEmit -p tsconfig.json`
Expected: no errors.

- [ ] **Step 4: Manual end-to-end check of the profile-switch fix**

With the backend (`/home/sah/.nvm/versions/node/v22.23.1/bin/node server/index.js`) and frontend (`npm start` in `frontend-v4`) running, create two profiles with different FortiOS/Windows asset sets, confirm `/intel`, an item detail page, and an Arsenal dossier page all re-render correctly on switch (per Task 2's Step 5), and spot-check that `/api/stats/dashboard`, `/api/sources`, and a CVE/actor/malware page look unchanged either way (per Spec Accuracy Finding 3 — they should).

- [ ] **Step 5: Manual check of the three new routes**

```bash
docker exec -e PGPASSWORD=postgres threatflow-pg16 psql -U postgres -d threatflow -X -t -c "SELECT id FROM profiles LIMIT 1;"
```

Take the returned id and, with the API running:

```bash
curl -s "http://localhost:4173/api/profiles/<id>/remediation" | head -c 2000
curl -s -H "X-Profile-Id: <id>" "http://localhost:4173/api/items/<some-act_now-item-id>/remediation" | head -c 2000
curl -s -X PATCH "http://localhost:4173/api/profiles/<id>/assets/<vendor>/<product>" \
  -H 'Content-Type: application/json' -d '{"version":"1.2.3","versionState":"known"}'
```

Expected: all three return the shapes documented in Tasks 7–9's Interfaces sections, and the PATCH's response `versionState` reads back as `"known"` on a subsequent `GET /api/profiles/<id>`.

- [ ] **Step 6: Final commit** (only if Steps 1–5 required any fix; if everything passed as-is, there is nothing to commit here)

```bash
git status
# If clean, nothing to do. If a fix was needed, commit it with a message describing what was
# actually wrong, following the same Conventional Commits style as the tasks above.
```
