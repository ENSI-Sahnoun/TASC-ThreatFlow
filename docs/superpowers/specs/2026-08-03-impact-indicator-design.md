# Impact indicator — "How does this affect me?"

Design, 2026-08-03.

## Problem

The relevance chip answers *whether* an item matched, not *what happens* if it is ignored.
Three specific failures, in the user's words:

1. **Says match, not consequence.** "Matches your stack (microsoft windows)" names the join
   condition. It does not name an attacker capability, a business outcome, or a blast radius.
2. **Tier labels carry no information.** "Watch" implies no urgency, no deadline, and no
   comparison against the other ~24k items in the corpus.
3. **Matching is too coarse.** `profiles.vendors` is matched against `item_cpes.vendor`. The slug
   `microsoft` has 7519 references, so a vendor-level match fires constantly and the verdict reads
   as noise.

The root cause of (1) is not a weak sentence writer. It is thin input: `relevance_prose.js` is
handed `matches[]`, a list of `{kind, value}` pairs, and no sentence written from that input can be
more specific than the input is.

## Decomposition

This work is two subsystems sharing one foundation. They are specified and built separately.

- **Spec A (this document) — the impact indicator.** Profile assets with exposure, `cvss_vector`
  backfill, product-to-role map, ladder v2, the consequence engine, prose v2, impact panel.
- **Spec B — remediation playbooks.** Per-item, grounded in CISA KEV `requiredAction`, NVD
  references tagged `Patch`, and the facts Spec A extracts. Deferred: its step derivation *is*
  Spec A's fact extraction, so it cannot be written honestly before A exists.

Spec A ships complete and useful on its own.

### Why A before B, measured

Spec B was considered first, on the theory that CISA KEV `requiredAction` and NVD references
tagged `Patch` are already ingested and need nothing from A. Measured against the live corpus on
2026-08-03 (11,149 items, 9,338 consolidated CVEs):

| grounding available without Spec A | items | share |
|---|---|---|
| KEV `requiredAction` | 104 | 0.9% |
| NVD reference tagged `Patch` | 1,542 | 13.8% |
| NVD reference tagged `Vendor Advisory` | 2,577 | 23.1% |

The union of the NVD tags is roughly a quarter of the corpus, and it is the quarter where the
honest playbook is little more than a link to the vendor's patch. The remaining ~75% fall to the
derived-skeleton path, which is Spec A's fact extraction with a different renderer.

Ordering is also a correctness matter, not only a coverage one. Playbooks attach to `act_now` and
`watch`, and those tiers are currently reachable by a vendor-level match. Building B first renders
step-by-step remediation for a product the user may not run — confidently wrong instructions, the
same failure class `BREACH_CLAIM_RE` exists to prevent.

## Audience

A non-expert owner or IT generalist. Consequence means a plain outcome — "someone could read your
company email without a password" — not a CVSS vector recital. This matches the existing onboarding
survey and the register `relevance_prose.js` already targets.

## Data model

Three changes, all additive. No existing column is dropped or repurposed.

### 1. `profile_assets`

```sql
CREATE TABLE IF NOT EXISTS profile_assets (
  profile_id INT  NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  vendor     TEXT NOT NULL,          -- lowercase CPE field
  product    TEXT NOT NULL,          -- lowercase CPE field
  exposure   TEXT NOT NULL,          -- 'internet' | 'internal' | 'unknown'
  UNIQUE(profile_id, vendor, product)
);
```

`profiles.vendors` and `profiles.products` are retained. They keep every existing profile working
and keep feeding the `low` tier. `profile_assets` is the only thing that can earn `act_now`.

Asset edits bump `profile_version` exactly like the other profile fields, so cached verdicts in
`item_relevance` invalidate through the mechanism that already exists.

**Migration.** Applying the schema seeds `profile_assets` from each profile's existing `products[]`
at `exposure = 'unknown'`, joined to `item_cpes` to recover the vendor for each product slug. Where
a product slug appears under several vendors, one row is inserted per distinct vendor — the profile
did not record which one it meant, and dropping the ambiguous ones would silently lose assets. A
product slug that matches no `item_cpes` row is skipped: storing it would store a value that can
never match, the same rule `profiles.js` already applies via `SLUG_RE`.

### 2. `items.cvss_vector TEXT`

Backfilled from `items.raw_json` by a new `server/backfill-cvss-vector.js` using the existing
`cvss.js:parseVector`. No new parsing logic and no re-sync.

Follows the convention of the two existing backfills, **including the inverted default: a bare
invocation writes, `--dry-run` previews.**

`cpe.js` is not changed. Version-range matching stays out of scope: users frequently do not know
their versions, and exposure is the larger consequence multiplier for the price.

### 3. `item_playbooks`

Named here only so the schema story is coherent. Defined and created in Spec B.

### Explicitly not added

No authentication (profiles remain personas behind the loopback bind). No CPE version ranges. No
new feed sources.

## The consequence engine

New pure module `server/consequence.js`. No I/O, no model, no database access.

**Input:** an item, its `cvss_vector`, the matched `profile_assets` row (or none), and the
consolidated `cve_intel` record.

**Output:** four independent fact slots, any of which may be `null`.

```js
{
  reach:   { text: 'anyone on the internet, with no password and no click from you',
             from: 'AV:N/PR:N/UI:N + exposure=internet' },
  impact:  { text: 'read, change and shut down',
             from: 'C:H/I:H/A:H' },
  role:    { text: 'your company email',
             from: 'asset_roles: microsoft/exchange_server' },
  urgency: { text: 'already used in real attacks', due: '2026-08-17',
             from: 'KEV' },
}
```

The `from` field is retained on every slot and rendered in the UI. It is what makes the claim
auditable, and it is what Spec B's playbook steps cite.

### reach

`AV` crossed with the asset's `exposure`. This crossing is the reason exposure is worth collecting
at all.

| `AV` | `exposure` | reads as |
|---|---|---|
| `N` | `internet` | anyone on the internet |
| `N` | `internal` | anyone already inside your network |
| `N` | `unknown` | anyone who can reach it over the network |
| `A` | any | someone on the same network |
| `L` | any | someone who already has access to that machine |
| `P` | any | someone standing at the machine |

Then `PR:N` appends "with no password", `PR:L` "with any ordinary account", `PR:H` "only with admin
rights". `UI:R` appends "if a person clicks or opens something".

### impact

`C:H` → read, `I:H` → change, `A:H` → shut down, joined as a list. A `:L` metric is rendered as
"partly" (partly read / partly change). All three metrics `:N` yields `null` — an absent slot, not
the assertion "no impact".

### role

New curated map `server/asset_roles.js`, following the discipline `sector_profiles.js` established:
every slug verified against `item_cpes` before it is added, with reference counts recorded in
comments. A slug that matches nothing is worse than an omission, because it makes coverage look
richer than it is.

Examples: `exchange_server` → "your company email", `fortios` → "your VPN and firewall", `windows`
→ "the computers your staff use".

An unmapped product yields `null` and the sentence falls back to naming the product directly.

### urgency

KEV listed → "already used in real attacks", carrying the KEV `dueDate` as `due`. Otherwise EPSS
≥ 0.5 → "likely to be attacked soon". Otherwise `null`. No filler text for an item that is not
urgent.

The 0.5 EPSS threshold is deliberately conservative — it is a single named constant in
`consequence.js`, tuned against the existing `quality.eval.json` holdout method if it proves too
strict in practice.

### Missing data is a null slot, never a guess

No `cvss_vector` — v4-only feeds, non-CVE items such as ransomware.live victim rows or news — means
no `reach` and no `impact`. The panel renders `role` plus the why-you explanation, and states
plainly that the rest is not available in the source data. This is the same posture as the
README's `confidence = NULL` rule: surface the gap rather than paper over it.

### Relationship to `matches[]`

`matches[]` is untouched and keeps its job: it answers **why you**. `consequence` answers **what
happens**. The panel renders both under separate labels. Neither replaces the other.

## Ladder v2

In `relevance_score.js`, the single `assetMatch` boolean splits into two signals of very different
strength:

```js
assetHit  = profile_assets row matching item_cpes (vendor, product)      // precise
legacyHit = profiles.vendors or profiles.products match item_cpes        // weak
```

```js
if (assetHit && exposure !== 'internal' && (kev || atLeastHigh) && recent) act_now
else if (assetHit && (kev || atLeastHigh) && recent)                       watch  // internal only
else if (assetHit)                                                         watch
else if (domainMatch && atFloor && recent)                                 watch
else if (sectorMatch && recent)                                            watch
else if (legacyHit || domainMatch || atFloor)                              low
else                                                                       not_yours
```

Two deliberate decisions:

**`legacyHit` alone can never exceed `low`.** This is the entire coarseness fix. "We use software
from Microsoft" is not evidence of exposure to a specific flaw. Note that after migration a
profile's `products[]` entries also exist as `profile_assets` rows, so they are evaluated through
`assetHit` too; `legacyHit` only decides what happens when they are not.

**`exposure === 'unknown'` still reaches `act_now`; only `internal` demotes.** Withholding an
act-now verdict on an actively-exploited flaw because the user skipped a survey question fails in
the wrong direction. The impact panel states that exposure is unanswered and links to the question.

The numeric `score` keeps its existing role: intra-tier ordering only, never rendered.

## Tier labels

Labels gain time rather than adjectives.

| tier | label | sub-line |
|---|---|---|
| `act_now` | Act now | KEV `dueDate` when present, otherwise "within 48 hours" |
| `watch` | Plan a fix | "this month" |
| `low` | Background | — |
| `not_yours` | Not yours | — |

## Prose v2

`relevance_prose.js` keeps its architecture: the model rewords a verdict it cannot change, and
`item_relevance_prose` still has no tier column, so a bad output remains structurally incapable of
promoting an item.

The prompt input changes from `matches[]` key/value pairs to the four consequence slots.

`SCAFFOLD_RE` and `BREACH_CLAIM_RE` are retained unchanged. Both are load-bearing and both were
paid for in observed failures — falsely telling a user they have already been breached is still the
most damaging thing this feature could do, and a small local model does not reliably obey a
negative constraint.

The real safety improvement is on the fallback path: the template is now assembled from the same
four slots, so a rejected model output degrades to a sentence that is still specific. Today a
rejection degrades to "Matches your stack (microsoft windows)."

`isModelWritten()` continues to gate the AI-generated label.

## API

Additive only.

- `GET /api/items` and `GET /api/items/:id` — `relevance` gains `consequence: { reach, impact,
  role, urgency }` with nullable slots, and `exposure`. List rows carry it because the chip
  sub-line needs `urgency.due`.
- `POST` / `PATCH /api/profiles` — accept `assets: [{ vendor, product, exposure }]`. Validated in
  `profiles.js` with the existing `SLUG_RE`; `exposure` is restricted to the three literals. An
  invalid asset returns `400` in the same shape as today's `unknown sector` error.

## UI

### `tf-impact-panel` (item detail)

A real page section, not a tooltip. Four labelled blocks, so a missing slot is visible as a gap
rather than as silence:

```
How this affects you
  Who could do it   anyone on the internet, no password needed
  What they'd get   read, change and shut down your company email
  How urgent        already used in real attacks · fix by Aug 17
  Why you           you run Microsoft Exchange, internet-facing
```

A null slot renders its label with "not stated in the source data".

### `tf-relevance-chip` (list rows)

Keeps its existing job and gains the sub-line from the tier table above. The tooltip continues to
carry the one-sentence prose.

### Onboarding survey

Gains one step: for each chosen or recommended product, exposure as a three-way choice. The default
is `unknown` and the step is skippable — a skipped answer is honest, an assumed one is not.

## Failure modes

Every failure degrades rather than breaks.

| condition | behaviour |
|---|---|
| Ollama unreachable | Template sentence from the same slots; panel fully populated |
| No `cvss_vector` | `reach` and `impact` null; panel states the gap |
| Unmapped product | `role` null; product named directly |
| No `profile_assets` rows | Legacy `vendorHit` path only; every verdict caps at `low` |
| Backend unreachable | Existing banner, unchanged |

## Measured after implementation (2026-08-03)

Against the live corpus (12,736 items), with a verification profile carrying three assets:
`windows_server_2022` (internet), `linux_kernel` (internal), `chrome` (unknown).

| measure | result |
|---|---|
| Items with a readable v3 vector after backfill | 7,685 / 12,736 (60%) |
| `item_cpes` references covered by `asset_roles` | 77.6%, from 64 of 599 distinct pairs |
| Prominent-tier rows with `reach` and `impact` | 1,396 / 1,412 (98.9%) |
| Prominent-tier rows with `role` | 1,388 / 1,412 (98.3%) |

### Open finding: `act_now` is too large to be actionable

The verification profile produced **310 `act_now` items, of which exactly 1 carries any
exploitation evidence** (KEV or EPSS ≥ 0.5). The other 309 reach the top rung through
`atLeastHigh && recent` — an ordinary high-severity CVE, recent, in software the profile runs.

This is a faithful implementation of the approved ladder, and it is still the wrong outcome:
"Act now · within 48 hours" on 310 items restores the vagueness this spec set out to remove,
just with better sentences underneath it. The cause is that the asset path now works: matching
`linux_kernel` (853 references) or `windows_server_2022` (469) is precise about *what the user
runs* and says nothing about *whether anyone is attacking it*.

Options, not yet decided:

1. **Require exploitation evidence for `act_now`.** `assetHit && kev && recent` earns the top
   rung; `assetHit && atLeastHigh && recent` becomes `watch`. Would put ~1–30 items in
   `act_now` for this profile and move the rest to "Plan a fix", which is what they are.
2. **Require internet exposure as well**, keeping the KEV path exposure-independent.
3. **Leave as specified** and rely on intra-tier ordering, accepting that `act_now` is a
   sizeable queue rather than a short list.

Option 1 matches what the tier label promises. It is a change to an approved decision, so it is
recorded here rather than made unilaterally.

## Testing

Pure modules carry the weight, matching the repo's existing structure.

- `consequence.test.js` — table-driven across `AV` × `PR` × `UI` × `exposure`, and across `C`/`I`/`A`
  combinations. Explicit null-slot cases: missing vector, v4-only vector, non-CVE item.
- `asset_roles.test.js` — slug format, no duplicate slugs, no role text without a slug.
- `relevance_score.test.js` — new cases: `vendorHit` alone never exceeds `low`; `assetHit` + KEV +
  `unknown` reaches `act_now`; the same input with `internal` lands on `watch`.
- `profiles.test.js` — asset validation, exposure literal enforcement, and the migration seeding
  `profile_assets` from `products[]` at `unknown`.
- `backfill-cvss-vector.test.js` — `--dry-run` writes nothing; a second run is a no-op.
- `relevance_prose.test.js` — the slot-built template fallback is specific; existing `SCAFFOLD_RE`
  and `BREACH_CLAIM_RE` cases retained unchanged.
- Frontend `relevance.spec.ts` — labels, sub-lines, KEV due-date formatting; panel renders with
  every slot null.

Backend tests are `node:test` against isolated databases from `server/test-helpers.js`, never the
`db.js` singleton.
