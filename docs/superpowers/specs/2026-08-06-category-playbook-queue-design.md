# Category-playbook items on the Remediate dashboard

Design, 2026-08-06.

## Problem

`GET /api/profiles/:id/remediation` (`server/index.js`, backs `remediation-queue.component.ts`,
the "Remediate" dashboard) is scoped entirely to
`profile_assets pa JOIN item_cpes c ON c.vendor = pa.vendor AND c.product = pa.product`. Phishing
items — and every other category-playbook category (`ioc`/`malware`/`ransomware`/`data-breach`) —
have no CPEs at all, so they cannot appear on this dashboard today regardless of relevance tier or
playbook state. A phishing item that just escalated to `act_now` (via the click-report feature
shipped earlier today, or the ordinary relevance ladder) has a real playbook — including the new
branching flowchart — but nothing on the dashboard ever says so. It's only reachable by knowing
the item id and visiting `/remediate/:itemId` directly.

Separately, the new phishing flowchart's "Done" end node is inert. There is no way to close an
item out from the flowchart itself — only by ticking every step individually.

## Decisions made during brainstorming

- **Add category-playbook items to the dashboard**, not just fix the flowchart's Done button in
  isolation — the button closing something the dashboard can't even show would still leave the
  reader with no way to see "this is open" in the first place.
- **"Done" is a bulk-tick shortcut**, not new state. Clicking it ticks every remaining step at
  once — the same idiom `remediation-guided.component.ts`'s `confirmVersionBump` already uses for
  the CVE page's "I've upgraded" flow. "Closed" is simply "every step in `playbook.steps` is in
  `playbook.done`." No new table, no new flag, still fully reversible by unticking any step.
- **Grouped by category**, one section per category (`Phishing` today), even though only one
  category exists right now — the roadmap already calls for malware/ransomware/data-breach/ioc
  flowcharts next, and grouping by category from the start avoids a second migration once they
  land.
- **A new, separate endpoint**, not a reshaped `GET /api/profiles/:id/remediation` response. That
  endpoint's array-of-groups contract has real consumers (`remediation-widget.component.ts`,
  `core/remediation.ts`'s `matchingGroup`/`actionCountFor`, the queue page itself) built entirely
  around CVE-shaped fields (`RemediationSummary`'s `status`/`fix`/`entry`, CVSS-based action
  collapsing). A category-playbook item has none of that — forcing it through the same shape
  would mean fabricating fields that don't apply. A second endpoint with its own minimal shape
  avoids both the fabrication and any risk to the existing, well-tested contract.

## Architecture

### New endpoint

```
GET /api/profiles/:id/remediation/categories
```

Same profile-required, 404-on-unknown-profile posture as the existing route. Response:

```ts
interface CategoryQueueItem {
  itemId: number;
  title: string;
  category: string;       // 'phishing' today
  tier: 'act_now' | 'watch';
  score: number;
  playbookDone: number;
  playbookTotal: number;
}
interface CategoryQueueGroup {
  category: string;
  items: CategoryQueueItem[];  // sorted by score desc, same tiebreak the existing route uses
}
// GET .../remediation/categories -> CategoryQueueGroup[]
```

Query: `item_relevance` (tier in act_now/watch) joined to `items` and `item_playbooks`/
`playbook_step_state` for that profile/profile_version, **excluding** any item that also has a
CPE match in `profile_assets` (so nothing double-counts between this endpoint and the existing
one). An item with no playbook at all (`item_playbooks` has no row — e.g. a `news`/`osint` item
that happens to reach `watch` some day) is excluded here too: nothing to close out means nothing
to show on a page whose whole point is trackable open items.

**Correction made during implementation, verified against real data:** the CVE builder
(`server/playbook.js`) produces a playbook for any item carrying a CVE or CVSS vector at all,
regardless of the item's own `category` column — a `news` or `malware` item reporting on a
specific CVE still gets the CVE-shaped playbook, not a category one. Filtering on
`category <> 'cve'` alone let those leak into this route under their own category (confirmed live
against the dev database: real `news`/`malware`/`advisory` rows appeared here before the fix). The
real discriminator is the step keys themselves — `server/playbooks/*.js`'s builders namespace
every key (`phishing:confirm`), the CVE builder never does (`confirm`, `patch`) — the same fact
`core/playbook.ts`'s `groundingFooter()` already relies on client-side. The query checks the first
step's key for a `:` instead.

### Frontend types and API call

`core/models.ts` gains `CategoryQueueItem`/`CategoryQueueGroup` (exact shape above).
`ApiService` gains `categoryRemediationQueue(profileId: number): Observable<CategoryQueueGroup[]>`
hitting the new route.

### The queue page

`remediation-queue.component.ts` loads both the existing `groups` and the new `categoryGroups` in
the same `load()` call (two requests, both required before `loading` clears — a partial load
reading as complete would hide a genuinely open phishing item). A new section renders after the
existing vendor/product groups: one `<li>` per `CategoryQueueGroup`, header naming the category,
flat list of its items (title, tier, score, a slim progress bar reusing the same `.bar`/`.fill`
markup the asset groups already use, linking to `/remediate/:itemId`).

`noAssets()` — today `(profileService.active()?.assets.length ?? 0) === 0`, which currently gates
the *entire* page behind "tell us what you run" — changes to also check whether any
`categoryGroups` came back. The page's true empty state is "nothing open at all," not "no assets
declared"; a profile with zero assets but an open phishing item must still see that item.

`core/remediation.ts`'s `queueSummary()` (the "N open / N past due" header stats) takes the
category groups as a second argument and folds their items into `open` — every category item
counted here is by definition open (the endpoint only ever returns act_now/watch items with an
incomplete-or-complete-but-still-listed playbook; "past due" has no equivalent for category items
today, since only KEV carries a due date, so they never contribute to `pastDue`).

### The flowchart's Done button

`playbook-flow.component.ts`'s `end` node becomes a real `<button>` (styled identically to the
current pill) instead of inert `<g>`/`<text>`. Click handler ticks every step in `playbook.steps`
not already in `playbook.done`, reusing `ApiService.tickPlaybookStep` — the exact loop
`remediation-guided.component.ts`'s private `autoTickAppliedSteps` already runs, just triggered
by this button instead of a version-bump confirmation. No new endpoint. The existing subtitle
("N of M done") already reflects the closed state once every tick lands — no separate confirmation
panel needed.

## Failure modes

| Condition | Behaviour |
|---|---|
| A category item has zero playbook steps (shouldn't happen — the category dispatcher returns `null` rather than an empty array — but defensively) | Excluded from the endpoint's query entirely, same as "no playbook at all" above. |
| The Done button's tick loop partially fails (one step's `tickPlaybookStep` call errors mid-loop) | Same posture as `autoTickAppliedSteps` today: `settle()` fires on both success and error per step, the page reloads once all have settled, and whichever steps actually landed show as done — a partial failure is visible as an incomplete progress count, not silently hidden. |
| A profile with assets AND open category items | Both dashboard sections render; `noAssets()` is false either way since assets exist. |
| A profile with neither assets nor any relevant item in any category | Existing "Tell us what you run" empty state, unchanged wording. |

## Testing

- `server/index.js`/`api.test.js`: new route tests — a seeded phishing item at `watch` with a
  materialized playbook appears; the same item additionally matching a `profile_assets` CPE is
  excluded (no double-count); a CVE item at `watch` never appears here regardless of playbook
  state; 404 for an unknown profile.
- `core/remediation.spec.ts`: `queueSummary()` extended-signature cases — a category item folds
  into `open`, an empty `categoryGroups` array behaves identically to today (no signature-only
  regression for the CVE-only callers).
- `remediation-queue.component.ts`: no dedicated component spec, matching this app's existing
  precedent (`playbook-panel.component.ts`, `playbook-flow.component.ts`) — typecheck plus the
  pure-function coverage above carries this the same way it already does for the rest of the page.
- `playbook-flow.component.ts`: no dedicated spec either, same reasoning — the tick loop reuses
  `ApiService.tickPlaybookStep`, already exercised indirectly wherever it's called today.

## Out of scope

- **Malware/ransomware/data-breach/ioc category sections.** The grouping is category-shaped from
  day one, but only `phishing` has a flow template (and therefore ever reaches `watch`/`act_now`
  in practice) as of this spec. Each new category flowchart automatically gains a dashboard
  section the moment its items start scoring into a materialized playbook — no further dashboard
  work needed per category.
- **A "past due" concept for category items.** Only KEV carries a due date today; nothing here
  invents an equivalent for phishing.
- **Reordering or restyling the existing vendor/product groups.** This spec only adds a new,
  separate section after them.
