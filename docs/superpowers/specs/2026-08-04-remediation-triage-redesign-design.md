# Remediation triage — action-first queue, risk ordering, richer reach

Design, 2026-08-04. Revises the queue and guided pages shipped by
[`2026-08-04-remediation-experience-design.md`](2026-08-04-remediation-experience-design.md) (Spec B),
on the foundation from
[`2026-08-04-remediation-foundation-design.md`](2026-08-04-remediation-foundation-design.md) (Spec A).
Spec C ([AI Assist](2026-08-04-remediation-ai-assist-design.md)) is unbuilt and unaffected — it hangs
a panel off the guided page and none of its attachment points move here.

## Problem

Spec B shipped and is correct against its own text. Rendered against the live corpus it is unusable.

`/remediate` for profile 10 (`schoenbrunn tasc`, asset `apple macos`) draws **295 rows in a flat
list, every one reading `unknown`**. The status is right — no version is recorded, so
`affectedStatus` abstains, exactly as Spec A designed. Rendering that abstention 295 times is the
failure. The one line worth reading, "one upgrade to 14.8.8 closes 111 of these," sits above the
wall as an annotation.

Three things are wrong, and only the first is a rendering bug:

1. **The list enumerates threats when the unit of work is a fix.** 295 rows are nine actions.
2. **Severity is fully populated and entirely unused.** 75 of those 295 are CVSS ≥ 9 and they are
   drawn identically to the other 220. Sorted by count, an unfixable CVSS 10.0 lands last.
3. **KEV is invisible.** `cve_intel` carries `kev_listed`, `kev_due_date`, `kev_required_action` and
   `kev_ransomware`. Profile 8's `microsoft windows_11_24h2` holds `CVE-2024-49039` — CVSS 8.8,
   ransomware-associated, CISA deadline **2024-12-03**, 610 days past due. Nothing on the page says so.

Separately, the guided page's reach diagram renders `C`/`I`/`A` as one merged blob ("read · change ·
shut down") and ignores `AC` and `S` entirely — two metrics `cvss.js:parseVector` already returns
and nothing in the product has ever surfaced.

## Measured

Live, 2026-08-04, scoped through the queue route's own join (`profile_assets` → `item_cpes` →
`item_relevance` at the current `profile_version`, tiers `act_now`/`watch`).

Profile 10 / `apple macos` — 295 open, **0 KEV**, 0 past due, CVSS present on 295 of 295:

| action | threats | worst CVSS | ≥ 9 | corroboration |
|---|---|---|---|---|
| No fix published | 5 | **10.0** | 1 | 1 |
| Vendor advisory | 76 | 9.9 | 18 | 2 |
| Upgrade to 14.8.8 | 111 | 9.8 | 39 | 1 |
| Upgrade to 26.6 | 34 | 9.8 | 11 | 1 |
| Upgrade to 15.7.8 | 13 | 9.8 | 5 | 1 |
| Upgrade to 26.5.2 | 35 | 9.1 | 1 | 1 |
| Vendor patch | 15 | 8.8 | 0 | 3 |
| Upgrade to 26.5 | 4 | 7.5 | 0 | 1 |
| Upgrade to 14.8.7 | 2 | 7.5 | 0 | 1 |

199 of 295 resolve to one of six version targets. **96 do not** — 76 advisory, 15 patch, 5 no-fix.
Those entries carry no version bound, which matters in Part 2.

Profile 8 / `microsoft windows_11_24h2` — 2 KEV rows, both past their CISA due date, one
ransomware-associated. This is the only KEV data across profiles 7–10, and the KEV treatment must be
built against it rather than mocked.

EPSS is **not usable**: 2 non-null `epss_score` values across the entire open set. No EPSS surface.

## Part 1 — the queue groups by action, not by threat

Within an asset, threats group by their `fixTarget`. Each group renders as one row: what to do, how
many it closes, how bad the worst one is. The CVE list moves inside a disclosure.

Grouping key is the fix itself — `kind:'version'` groups on `fix.value`, and `patch` / `advisory` /
`none` each collapse to a single group per asset. Two patch URLs are not one action, but for the
purposes of *this page* they are one decision ("go read the vendor's links"), and splitting 76
advisory threats into 76 rows reproduces the wall this spec exists to remove.

The asset stays the outer grouping, because an upgrade applies to an asset. Nothing here re-sorts
what the backend already ordered; this adds a level *inside* the group the route returns.

## Part 2 — three sections once a version is recorded, not two

Recording a version splits the actions:

- **Still affects you** — `affectedStatus` returned `affected`.
- **Can't tell from your version** — returned `unknown`.
- **No longer in range** — returned `not_covered`.

The third section carries the caveat verbatim from Spec B, once on the section rather than repeated
per row: *not a clean bill of health — confirm against the vendor advisory before treating any of
these as closed.*

**The middle section is the load-bearing addition.** 96 of 295 threats carry no version bound at all.
They cannot go in "still affects you" — nothing was compared. They must not go in "no longer in
range" — that would launder the comparator's abstention into a safety claim, which is the single
thing Spec A's design forbids everywhere else. A two-way split forces one of those two lies. The
third section is where the abstention stays visible.

Before any version is recorded there is one bucket and therefore no section chrome.

## Part 3 — risk ordering and severity encoding

Actions sort by **worst CVSS in the bundle**, descending, count breaking ties. Not by count.

The measured consequence is deliberate: "No fix published" (5 threats, one CVSS 10.0) sorts above
"upgrade to 14.8.8" (111 threats, worst 9.8). An unfixable 10.0 is the thing a reader must not miss,
and it is precisely what a count-ordered list buries. The leverage story is not lost — the count is
on the row, and a **reach** toggle re-sorts by it.

Each action row carries three encodings, all from data already on the item:

- a severity stripe on the leading edge, from the existing `--sev-*` ramp keyed on worst CVSS
- the worst score as a figure
- a distribution bar showing the critical / high / medium split, so "111 threats, 39 critical" reads
  as a shape rather than one number

**The band is not computed on the client.** `severityFromScore(score, version)` lives in
`server/cvss.js` and has no frontend equivalent; `cve_intel.severity` already holds its result. The
route returns that string (Part 8) and the page maps it straight onto the `--sev-*` ramp.
Re-deriving bands in TypeScript would mean a second copy of the v2/v3 rule — and CLAUDE.md is
explicit that a v2 5.0 and a v3.1 5.0 are different claims that must never be renormalized into each
other. `cvss_score` and `cvss_version` still travel to the page, for the numeral and for ordering;
they are not what picks the colour.

**KEV outranks CVSS.** An action containing any KEV-listed CVE renders a filled badge with the count
past its CISA due date; a ransomware-associated one says so. KEV sorts above every non-KEV action
regardless of score. This is not a new severity colour — it is `--sev-critical` rendered filled
rather than soft, so the ramp keeps one meaning.

## Part 4 — density and control

A filter field (CVE id or version substring), an explicit **risk ⇄ reach** sort toggle, tighter row
rhythm, and monospace for every CVE id and version so digits align. Counts use `tabular-nums`.

This re-balances Spec B's "calm about urgent things" rather than abandoning it: the calm was about
tone and motion, not about density. Nothing blinks, nothing pulses, nothing animates on scroll.

## Part 5 — provenance on every action

A `why this action?` control on each row, in the idiom the impact panel already established —
same component, same wording, no second interaction to learn. It reveals:

- what matched the asset — the `item_cpes` vendor/product pair
- where the fix came from — `NVD cpeMatch endExcluding` for a version, or the `cve_intel` column for
  a patch/advisory link, or the explicit absence of both for `none`
- how many independent sources corroborate — `source_count`

No new backend beyond Part 8's field additions. Every value is already in scope on the route.

## Part 6 — ticket handoff

**Copy as ticket** on each action produces plain text: the action, threats closed, worst severity,
KEV status when present, and the CVE list. Clipboard only.

No integration, no API, no ticket-system client. A remediation tool whose output cannot leave it is
a dead end, and plain text is the format every tracker accepts. Anything richer is a separate spec.

## Part 7 — the reach diagram states more than three verbs

Today the diagram draws origin → gate → outcome, with the outcome node reading `read · change ·
shut down` whenever `C`/`I`/`A` are `H`. It is too coarse in three specific ways, each fixable from
metrics `parseVector` already returns.

**`AC` is never rendered anywhere in the product.** `AC:L` means it works whenever it is tried;
`AC:H` means the attacker needs conditions to line up. That is the difference between a reliable
exploit and an opportunistic one, and it belongs on the edge between the gate and the outcome.

**`S` is never rendered anywhere in the product.** `S:C` — scope changed — means the flaw escapes
the component it lives in and affects the rest of the system. `consequence.js:buildImpact` carries a
comment conceding that a scope-changed vector "can carry effects these three metrics do not
express", and then nothing surfaces it. A scope-changed vector gets a fourth node: what else it
reaches.

**`C`/`I`/`A` render per metric, at their real level.** `buildImpact` already distinguishes `:H`
("read") from `:L` ("partly read"); the diagram flattens both into one blob and drops the
distinction. `C:H/I:N/A:N` is a read-only disclosure and must not draw the same as `C:H/I:H/A:H`. A
metric at `N` renders as absent, not as a struck-through verb.

**Where this lives.** In the diagram's own pure function in `core/remediation.ts`, reading
`parseVector` output — **not** in `consequence.js`. `buildImpact`'s prose is consumed by the impact
panel and by `relevance_prose.js`; changing its wording changes surfaces this spec does not own.
The diagram is a second rendering of the same parsed metrics, not a second source of truth.

The verb vocabulary stays `consequence.js`'s (`read` / `change` / `shut down`, `partly` for `:L`) so
the two surfaces cannot drift into different words for the same metric.

Motion is unchanged: draws once, left to right, `--ease-out`, finished state under
`prefers-reduced-motion`. A fourth node extends the sequence; it does not add a second animation.

## Part 8 — backend: additive fields on the queue route

`GET /api/profiles/:id/remediation` already runs a `LATERAL` join onto `cve_intel` picking the
KEV-then-score-ranked row per item. It selects `affected_versions`, `patch_url` and `advisory_url`
from it. It must also select, per item:

`cvss_score` · `cvss_version` · `severity` · `kev_listed` · `kev_due_date` · `kev_ransomware` ·
`source_count`

Purely additive to the existing projection — no new join, no new query, no change to
`remediationFor` or `fixTarget`, which stay exactly as Spec A wrote and tested them. Existing
consumers are unaffected.

The same fields go onto `GET /api/items/:id/remediation` for the guided page's KEV block.

## Part 9 — the intel detail page loses the panel, gains a widget

`item-detail.component.ts` renders `<tf-playbook-panel>` inline. It is replaced by a compact widget:
progress, the current action, and a link into `/remediate/:itemId`.

**Spec B argued the opposite** — "removing it would make the detail page worse for the common case
of a quick look." That call is reversed here by the product owner. Recorded rather than quietly
dropped, so the reversal is visible to whoever reads these specs next.

Progress is **not** invented. It is the fraction of the asset's actions currently reading
`not_covered` — derivable from the queue response, and rendered only when `version_state = 'known'`,
because progress against an unknown version is not measurable. When the version is unset the widget
shows the action and the count with no ring. There is no per-asset progress table and this spec does
not add one.

`tf-playbook-panel` itself stays in the codebase — the guided page's Step 4 is its only remaining
consumer.

## Non-goals

- **No EPSS.** 2 non-null scores across the open set. Revisit when the feed is populated.
- **No new severity palette.** The `--sev-*` ramp and `--accent` keep their existing single meanings.
  KEV differentiates by fill weight, not by a new hue.
- **No ticket-system integration.** Clipboard text only.
- **No change to `fixTarget` / `remediationFor` / `affectedStatus` / `version_compare.js`.** Every
  verdict on this page comes from Spec A's already-tested pure functions. This spec changes what is
  *rendered* and *ordered*, never what is *decided*.
- **No cross-asset bulk action.** Recording a version stays per asset and explicit, per Spec B.
- **No `consequence.js` wording change.** Part 7 reads its vocabulary; it does not edit it.

## Testing

Pure logic in `core/remediation.ts` with its colocated `.spec.ts`, per the convention `relevance.ts`
and `playbook.ts` already follow — vitest, node environment, no TestBed:

- action grouping: threats collapse on `fix.value` for `version`; `patch`/`advisory`/`none` each
  collapse to one group; no threat is counted twice
- risk ordering: sorts on worst CVSS descending, count breaking ties; the measured case asserted
  directly — a 5-threat CVSS 10.0 action outranks a 111-threat CVSS 9.8 action
- KEV ordering: any KEV action outranks every non-KEV action regardless of score
- the three-way split: `affected` / `unknown` / `not_covered` land in their own sections, and an
  action with no version bound never reaches the `not_covered` section
- `not_covered` wording still never contains the word "safe" (the existing assertion, kept)
- severity colour comes from the route's `severity` string, not from a client-side re-derivation of
  the band — asserted so the v2/v3 rule cannot be duplicated into TypeScript and drift
- diagram node selection across every `AV`/`PR`/`UI`/`AC`/`S` combination, including absent metrics,
  `S:C` adding its fourth node, and `:L` rendering "partly" rather than the bare verb
- progress arithmetic returns nothing when `version_state` is not `known`

Backend: `api.test.js` asserts the seven new fields appear on both routes and that the existing
response shape is otherwise unchanged.

Component classes stay thin bindings. The diagram is a pure function returning node/edge
descriptors, tested as data; the SVG is a template over it.
