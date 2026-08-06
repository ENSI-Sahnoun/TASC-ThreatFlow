# Profile signal depth — sharper relevance without leaving the shared-corpus model

Design, 2026-08-06.

## Problem

The dashboard and intel feed feel nearly identical across profiles. Root-caused during this
design: `GET /api/stats/dashboard` → `dashboardStats(store)` in `server/stats.js` takes no profile
parameter at all — every query is a flat `SELECT ... FROM items GROUP BY ...` over the whole
corpus, never joined against `item_relevance`. That specific bug is real but is its own fix,
tracked separately (see Out of scope) — fixing it alone would surface differentiation that today's
profile *inputs* mostly can't produce anyway: `threatDomains` is an unordered set (in/out, no
weight), asset exposure is a single flat `internet/internal/unknown` value with no notion of
criticality, and the ransomware/data-breach playbooks already say "...or a vendor/partner you
depend on" with no field behind that claim at all.

This spec makes the *signal* richer. It does not touch the dashboard wiring, the widget layout, or
NER.

## Constraint carried over from the existing survey

`survey.component.ts`'s own rule, unchanged: *"there is no question here whose answer has no
column behind it."* Ruled out for that reason: company size, compliance regime, and
region/industry-based questions — none have a real matchable column today. `items.region` /
`items.industry` are 98.6% NULL, populated only by ransomware.live and `ip_intel`; asking a user's
region and matching against that would mostly match nothing, the same failure mode
`sector_profiles.js`'s header comment already warns against ("a slug that matches nothing is worse
than an omission").

## 1. Deeper asset exposure

`profile_assets` gains two columns:

```sql
ALTER TABLE profile_assets ADD COLUMN criticality text NOT NULL DEFAULT 'unknown';
ALTER TABLE profile_assets ADD COLUMN reaches_customer_data boolean NOT NULL DEFAULT false;
```

`criticality ∈ {'critical', 'standard', 'unknown'}`, validated in `profiles.js:assetList` the same
way `exposure`/`versionState` already are — unanswered stays `'unknown'`, never assumed.

Survey change: two additional toggles on the existing per-asset exposure step (no new step) —
"Is this business-critical?" / "Does it hold customer data?" Both optional, both default to the
honest-absence value.

**Ladder change** (`relevance_score.js`, additive to the existing rule at line 124, not a
replacement):

```js
// existing: if (assetHit && exposure !== 'internal' && kev && recent) tier = 'act_now';
const criticalExposed = assetHits.some((a) => a.criticality === 'critical' && a.exposure === 'internet');
if (assetHit && exposure !== 'internal' && kev && recent) tier = 'act_now';
else if (assetHit && criticalExposed && atLeastHigh && recent) tier = 'act_now';
else if (assetHit && (kev || atLeastHigh) && recent) tier = 'watch';
...
```

A critical, internet-facing asset at high/critical severity reaches `act_now` without waiting on
KEV — narrows the gap Ladder v3's KEV-only gate left for assets the profile has flagged as their
highest-stakes exposure. Every other rung is unchanged.

## 2. Ranked threat domains

`profiles.threat_domains` changes from an unordered `text[]` to an ordered array (Postgres arrays
are already ordered — this is a validation/UI change, not a schema change). `validateProfile`
caps it at 3 entries and preserves input order instead of dedup-in-arrival-order being incidental.

Survey change: Step 3 becomes drag-to-rank (top 3) instead of a checkbox list — same `DOMAINS`
catalogue from `domains.js`, no new data source.

**Ladder change:** `domainMatch` scoring (line ~138, `score += domainMatch ? 1 : 0`) becomes
rank-weighted:

```js
const domainRank = domainHits.length
  ? Math.min(...domainHits.map((d) => profDomains.indexOf(d)))
  : -1;
score += domainRank >= 0 ? (3 - domainRank) : 0;   // rank 0 (top pick) = +3, rank 2 = +1
```

This only reorders items *within* a tier — the act_now gate (exploitation evidence required,
line 124) and the watch gate (`domainMatch && atFloor && recent`, line 127) are unchanged. A
ranked-but-unmatched domain contributes nothing, same as today.

## 3. Vendor/partner dependency list

New table, separate from `profile_assets` because the semantics differ — "reaches me through
someone else," not "I run this":

```sql
CREATE TABLE profile_dependencies (
  profile_id INT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  vendor     text NOT NULL,
  product    text NOT NULL,
  PRIMARY KEY (profile_id, vendor, product)
);
```

Same slug validation as `vendors`/`products` (`SLUG_RE`, lowercase). Survey change: one new
optional step, "Any vendors or partners you depend on?" — same product-picker UI already used for
assets, different destination table.

**Ladder change:** a `profile_dependencies` hit against `item_cpes` is a new match kind,
`dependencyHit`, checked alongside but never merged into `assetHit` — it must never grant
`act_now` (no direct exposure claim exists), only contributes to `watch`/`low` the same way
`domainMatch` does today:

```js
else if (assetHit) tier = 'watch';
else if (dependencyHit && atFloor && recent) tier = 'watch';   // new
else if (domainMatch && atFloor && recent) tier = 'watch';
```

This is also what finally grounds `ransomware.js`'s existing `confirmStep` line — "...or a
vendor/partner you depend on" — which today has no data behind it at all; the ransomware module
can now pass `dependencyHit` into that step's guard/detail instead of stating it unconditionally.

## Facts touched

| Fact | Change |
|---|---|
| `profile_assets.criticality` | new column, feeds `act_now` promotion |
| `profile_assets.reaches_customer_data` | new column, stored but not scored by this spec — grounds future consequence wording only (e.g. "customer data may be exposed"), not a ladder input yet |
| `profiles.threat_domains` | now rank-ordered, capped at 3 |
| `profile_dependencies` | new table, new match kind `dependencyHit` |

`reaches_customer_data` is captured now because it belongs on the same survey step as
`criticality` and asking it twice later would be worse UX — but it isn't wired into the ladder or
any playbook in this spec. Flagged explicitly so it doesn't read as an oversight.

## Failure modes

| Condition | Behaviour |
|---|---|
| Existing profile, pre-migration | `criticality` backfills to `'unknown'`, `reaches_customer_data` to `false`, `threat_domains` keeps its existing (now-ordered-by-array-position) values, no `profile_dependencies` rows — every new rule's guard is false, ladder behaves exactly as before until the profile is re-edited |
| More than 3 domains submitted | `validateProfile` rejects with a 400, same posture as existing `unknown threat domain` validation |
| Dependency vendor/product matches nothing in `item_cpes` | No match, no step — same silent-absence rule every other guard in this codebase follows |
| Both `criticality='critical'` and KEV=true | `act_now` either way — the two rules are `||`'d in effect (first matching branch wins), not stacked |

## Testing

- `profiles.test.js`: `criticality`/`reaches_customer_data` validation (valid enum, default,
  rejection of invalid value); `threat_domains` order-preservation and 3-cap rejection;
  `profile_dependencies` slug validation mirroring `vendors`/`products`.
- `relevance_score.test.js`: table-driven cases for the new `act_now` branch (critical+internet+
  high severity, no KEV, still promotes), rank-weighted domain scoring (top-ranked match outscores
  third-ranked), `dependencyHit` reaching `watch` but never `act_now`.
- `ransomware.test.js`: `confirmStep` detail text changes when `dependencyHit` is true vs. false.
- Migration test: pre-migration profile row reads back with correct defaults, ladder output
  unchanged for a profile that hasn't been re-edited.

## Out of scope

- **`dashboardStats()` profile-awareness.** Real, separate bug (`server/stats.js` never reads
  `X-Profile-Id`) — this spec makes the input signal richer but does not make the dashboard consume
  it. Needs its own spec: threading profile id through `dashboardStats`, deciding which widgets
  filter by `item_relevance` tier vs. stay global.
- **Per-profile widget layout** (e.g. hiding "malware families" for profiles that don't care) —
  explicitly deferred by request.
- **NER.** Profile-scoping shrinks the blast radius a future NER attempt would have, but does not
  address the fabrication failure mode documented in CLAUDE.md's NER postmortem. Not started here.
- **`reaches_customer_data` scoring/consequence wiring.** Captured, stored, not yet consumed —
  wiring it into consequence text or the ladder is follow-on work once real usage data exists.
