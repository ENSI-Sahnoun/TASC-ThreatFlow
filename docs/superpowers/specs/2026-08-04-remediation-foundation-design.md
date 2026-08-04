# Remediation foundation — versioned assets, comparison, fix ladder

Design, 2026-08-04. Spec A of three. Companion specs:
[`2026-08-04-remediation-experience-design.md`](2026-08-04-remediation-experience-design.md) (B, the pages)
and [`2026-08-04-remediation-ai-assist-design.md`](2026-08-04-remediation-ai-assist-design.md) (C, AI Assist).

Builds directly on [`2026-08-04-impact-provenance-and-affected-versions-design.md`](2026-08-04-impact-provenance-and-affected-versions-design.md),
implemented and merged 2026-08-04, which put NVD's raw version bound fields into
`cve_intel.affected_versions`.

## Problem

The playbook can now say *which versions are affected* — "Affected: the computers your staff use —
before 10.0.26100.8875". It still cannot say the two things a reader actually wants:

1. **"Am I on an affected version?"** The system has never asked which version they run.
   `profile_assets` records `(vendor, product, exposure)` and nothing else.
2. **"What do I upgrade to?"** The data is present for a minority of entries and absent for the
   rest, and nothing reads it either way.

Underneath both sits a defect that makes either unverifiable: **switching profile does not switch
what you see.** `ProfileService.select()` sets a signal, `profile.interceptor.ts` reads it per
request, and no page refetches. Twelve page components fetch on `ngOnInit`/`constructor` and never
again. A profile switch changes the header for *future* requests while every rendered figure stays
from the previous persona.

This spec is the whole backend and the bug fix. It ships nothing a user can see. That is
deliberate: the version comparator is the one part of this feature that can hurt somebody, and it
should be reviewed on its own rather than inside a large UI diff.

## Measured coverage

Live corpus, 2026-08-04, after `consolidate()`:

| | count | share |
|---|---|---|
| `cve_intel` rows | 22,843 | |
| carry any `affected_versions` | 13,310 | 58.3% |
| entries across those rows | 21,976 | |
| entries naming a fixed version (`endExcluding`) | 7,985 | 36.3% |
| entries with an exact pin, no fix named | 12,255 | 55.8% |
| entries with `endIncluding` only, no fix named | 1,733 | 7.9% |

Of the 13,999 entries that name no fixed version, 7,012 still carry a `patch_url` and 3,185 an
`advisory_url`. Only 3,802 — 17% of all entries — have neither. **"No fixed version" is not "no
remediation"**, and the fix ladder below is built on that.

## Part 1 — profile switching refetches

`ProfileService` gains a monotonically increasing counter, bumped by `select()`:

```ts
private readonly _dataVersion = signal(0);
readonly dataVersion = this._dataVersion.asReadonly();

select(id: number | null): void {
  if (id === this._activeId()) return;   // idempotent: re-selecting the active profile is not a change
  this._activeId.set(id);
  this.persist(id);
  this._dataVersion.update((n) => n + 1);
}
```

Each page component's fetch reads `dataVersion()` inside an `effect()`, so selecting a profile
re-runs it. This is a signal counter rather than an observable because the pages that need it are
already signal-based, and because a counter makes "the data is stale" a value rather than an event
— a component created *after* a switch reads the current number and is correct without having
observed the transition.

**The honest cost: twelve components.** `dashboard`, `explorer`, `item-detail`, `live-feed-page`,
`lane-live`, `lane-exploited`, `arsenal-index`, `arsenal-dossier`, `cve`, `actor`, `malware`,
`entity-profile`. One `effect()` each, mechanical, no logic change. There is no single-file fix
here that is not `location.reload()`, and a full reload would discard filter state and scroll
position on every switch.

`select()` becoming a no-op when the id is unchanged also fixes a latent waste: `load()` calls
`select(resolveActiveId(...))` on every startup, which would otherwise bump the counter and
double-fetch every page on first paint.

### Testing

`profile-selection.spec.ts` covers the pure resolution logic already. Add: `select()` to a
different id increments `dataVersion`; `select()` to the same id does not; `select(null)`
increments. The per-page `effect()` wiring has no test — this app runs vitest in a node
environment with no TestBed by design, and an `effect()` in a component is exactly the untestable
binding layer that convention accepts.

## Part 2 — `profile_assets` records a version

```sql
ALTER TABLE profile_assets ADD COLUMN IF NOT EXISTS version TEXT;
ALTER TABLE profile_assets ADD COLUMN IF NOT EXISTS version_state TEXT NOT NULL DEFAULT 'unset'
  CHECK (version_state IN ('unset','known','unknown'));
```

Three states, not a nullable string:

- `unset` — never asked. The UI may ask.
- `known` — the user supplied a version; it is in `version`.
- `unknown` — the user was asked and answered "I don't know". `version` stays NULL.

`unknown` exists so the page does not re-ask a question the user has already declined. Collapsing
it into NULL would make a declined question indistinguishable from an unasked one, and the
remediation page would nag on every visit. This is the same reasoning `exposure` already applies
by defaulting to `'unknown'` rather than to `'internal'`: a missing answer is recorded as missing,
never inferred.

`profiles.js`'s `assetList()` validator gains `version` (an optional string, trimmed, max 64
chars, rejected if it contains whitespace or control characters — it is a version identifier, not
prose) and `versionState` (must be one of the three). `writeAssets()` carries both through. Both
default to `null` / `'unset'` so every existing caller — the survey, the profile editor, every
test fixture — is unchanged.

## Part 3 — `server/version_compare.js`

A new pure module. This is the part of the feature that can hurt someone, so its contract is
written to make the dangerous answer unrepresentable.

```js
// -1 | 0 | 1 when confidently ordered, null when not.
compareVersions(a, b)

// 'affected' | 'not_covered' | 'unknown'
affectedStatus(installed, entry)
```

`compareVersions` splits on `.` and compares numerically, segment by segment, shorter padded with
zero (`2.0` equals `2.0.0`). It returns **`null`** — not a guess — the moment it meets a segment
that is not a run of digits. That covers prereleases (`1.0.0-rc1`), Debian epochs (`1:2.4.1`), RPM
release strings (`2.4.1-3.el9`), and anything else it has no business ordering.

`affectedStatus` takes **one** `affected_versions` entry, already selected. A CVE carries 1.7
entries on average, one per affected product; the caller picks the entry whose `vendor`/`product`
equal the asset's, exactly as `playbook.js`'s `confirmStep` already does. When no entry matches
the asset, the status is `unknown` — the CVE says nothing about the product this reader runs.
Never `not_covered`: an absent entry is missing data, not evidence of safety.

It reads the structured bound fields the merged spec already stores:

| bounds present | installed inside | result |
|---|---|---|
| any bound, comparison confident, inside | yes | `affected` |
| any bound, comparison confident, outside | no | `not_covered` |
| any comparison returns `null` | — | `unknown` |
| `pinned` equals installed exactly (string equality) | — | `affected` |
| `pinned` differs | — | `unknown`, **never `not_covered`** |
| no bounds and no pin | — | `unknown` |

Two asymmetries are deliberate and load-bearing:

**`not_covered` is never rendered as "you are safe."** It states a fact about the range — this
range does not cover your version — and Spec B renders it with an explicit instruction to confirm
against the vendor. A CVE routinely carries several `affected_versions` entries; being outside one
product's range says nothing about the others, and NVD's CPE data is itself incomplete.

**A differing `pinned` yields `unknown`, not `not_covered`.** An exact-pin CPE (`4.2.1`) means NVD
recorded that one build as vulnerable. It does *not* mean neighbouring builds are fine — pins are
usually an artifact of how the CNA filed the record, not an assertion of scope. 55.8% of entries
are pins, so treating a pin mismatch as evidence of safety would be the single largest source of
false reassurance in the whole feature.

### Testing

`version_compare.test.js`, adversarial by design, because a comparator bug is the failure mode
that matters:

- Windows four-part builds: `10.0.26100.8300` < `10.0.26100.8875`; equal builds; `10.0.26100.9001` >.
- Segment-count mismatch: `2.0` == `2.0.0`; `7.4` < `7.4.5`.
- Numeric, not lexical: `7.4.10` > `7.4.9`. (A string comparison gets this backwards, which is the
  classic version-compare bug and the one most likely to tell someone they are patched.)
- Leading zeros: `1.02` == `1.2`.
- Every uncomparable shape returns `null`, individually: `1.0.0-rc1`, `1:2.4.1`, `2.4.1-3.el9`,
  `v7.4.5`, `2024.1a`, `''`, `null`.
- `affectedStatus`: inside a `before X` range; outside it; inside `X through Y`; a pin that matches;
  a pin that differs (asserting `unknown`, not `not_covered`); an entry with no usable bound at all.
- One test asserting the property directly: **no input combination returns `not_covered` when any
  comparison in the chain returned `null`.**

## Part 4 — `server/remediation.js`

The fix ladder, pure, returning a tagged union so an absent fix is a distinct case rather than an
empty string:

```js
// { kind: 'version',  value: '10.0.26100.8875' }   from entry.endExcluding
// { kind: 'patch',    value: '<url>' }             from cve_intel.patch_url
// { kind: 'advisory', value: '<url>' }             from cve_intel.advisory_url
// { kind: 'none' }
fixTarget(entry, cveIntel)
```

Order is exactly that. `endExcluding` first because it is the only field that names a fixed
version: `endIncluding: "2.4.1"` says "≤ 2.4.1 is broken" and names no fix, and `pinned` names no
fix either. Neither may ever produce a `kind: 'version'`. This rule is stated in
`consolidate.js`'s own `versionBounds` comment and enforced here, where the inference would
otherwise happen.

`fixTarget` composes no URL. It returns `patch_url` / `advisory_url` verbatim or it returns
`none` — the same rule `playbook.js` states in its header, for the same reason: a fabricated patch
instruction is the worst output this feature can produce, because the reader would act on it.

A second function assembles what a page needs about one (asset, item) pair:

```js
// { status, installed, versionState, entry, fix, mitigations }
remediationFor(asset, affectedVersions, cveIntel, playbookSteps)
```

`status` comes from `affectedStatus`. `mitigations` is the subset of the already-built playbook
steps that act without a fix — `restrict` and `rotate` — surfaced explicitly so the `kind: 'none'`
case has something to offer instead of a dead end. Those steps already exist and are already
guarded by the CVSS vector; this only names them as the fallback path.

### Testing

`remediation.test.js`: the ladder in all four states; `endIncluding`-only and `pinned`-only
entries both producing a non-`version` kind (the fabrication guard, asserted directly); `none`
still returning mitigations when the vector supports them, and an empty list when it does not.

## Part 5 — routes

Three, following the existing conventions in `index.js` (non-integer `:id` → 404, handlers wrapped
so a rejected promise becomes `500 { error }`, `X-Profile-Id` resolved by the existing middleware
with an unknown id a 400 and never a silent fallback):

| method | path | returns |
|---|---|---|
| `GET` | `/api/profiles/:id/remediation` | the queue: one entry per asset, each with its open threats, counts, and `version_state` |
| `GET` | `/api/items/:id/remediation` | the per-threat detail: `remediationFor` output plus the item, its relevance and its playbook |
| `PATCH` | `/api/profiles/:id/assets/:vendor/:product` | sets `version` + `version_state`; returns the updated asset |

The `PATCH` handler reads the profile, replaces the `version`/`versionState` on the one matching
asset, and calls the existing `updateProfile` with the whole profile. It does **not** get a
bespoke `UPDATE profile_assets SET version = …`. `writeAssets` deletes and rewrites the asset set
inside `updateProfile`'s transaction, so a direct single-row update would be silently discarded by
the next profile save — and duplicating the version-bump and asset-write logic in a second place
is how the two drift apart. A 404 if the profile has no asset with that `(vendor, product)`.

That path bumps `profile_version`, which invalidates
cached verdicts and forces the recompute — which is precisely the mechanism that makes one
recorded upgrade close every other threat that upgrade fixes, and it costs the ~1.3s full
recompute that already exists. It is not an optimization to skip: a version written without a
recompute would leave every other item's status stale and wrong in the reassuring direction.

The queue query is scoped to `act_now`/`watch` at the current `profile_version`, the same tiers
that already get playbooks — a `low` item has no checklist to work through.

### Testing

`api.test.js` additions: each route's happy path; a non-integer `:id` returning 404; an unknown
`X-Profile-Id` returning 400; `PATCH` bumping `profile_version`; and one integration test
asserting that recording a version above the affected range flips a second item against the same
asset from `affected` to `not_covered` — the cross-item effect, proven end to end rather than
assumed.

## Non-goals

- **No UI.** Spec B owns every rendered thing, including how `not_covered` is worded.
- **No GitHub / package-manifest import.** Measured against the live corpus and deliberately
  dropped: OSV.dev (51 items) and GitHub Security Advisories (93 items) carry `purl`/`ecosystem`
  identifiers and have **zero `item_cpes` rows**, so they participate in no profile matching at
  all. The 22,000-CVE universe this feature operates on is CPE-shaped infrastructure. A repo scan
  yields `express@4.18.2`, which cannot be joined to `microsoft/windows_11_24h2` by any path that
  exists. Package matching is a separate subsystem — a second matching path beside `item_cpes`,
  plus widened OSV ingestion — and is not a convenience input to this one.
- **No per-ecosystem comparators.** One dotted-numeric comparator that abstains loudly. Real
  semver/RPM/dpkg comparators would shrink the `unknown` bucket and are a defensible follow-up,
  but three comparator implementations with three test suites is a spec of its own, and abstaining
  is safe where guessing is not.
- **No change to `relevance_score.js`.** A recorded version does not create a new rung on the
  ladder and cannot promote an item. It informs what the remediation surface *says*, not what tier
  a thing *is*.
