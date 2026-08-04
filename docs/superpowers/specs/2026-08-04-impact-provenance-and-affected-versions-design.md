# Clickable provenance + real affected-version ranges

Design, 2026-08-04. Small follow-up to Spec A
([`2026-08-03-impact-indicator-design.md`](2026-08-03-impact-indicator-design.md)) and Spec B
([`2026-08-03-remediation-playbooks-design.md`](2026-08-03-remediation-playbooks-design.md)),
both implemented and merged.

## Problem

Two usability gaps reported directly against the shipped impact panel and playbook:

1. The "why" provenance link next to each impact fact (`AV:N/PR:N/UI:R + exposure=internal`) is
   a bare `title` attribute — hover-only. Not reachable by keyboard, invisible on touch, and
   doesn't visually read as interactive.
2. The playbook's "confirm" step ("Check whether you run the affected version") never states
   *which* version is affected, even though the reader has already been told their asset matches.
   It feels generic because it is — "Affected: the computers your staff use" doesn't tell someone
   with three Windows builds in service which one to worry about.

## Part A — clickable provenance

`impact-panel.component.ts` renders each of the four impact-block facts as:

```html
<dd>{{ b.text }} @if (b.from) { <span class="from" [title]="b.from">why</span> }</dd>
```

Change the `<span title>` to a `<button type="button">`, toggled per block. State is a
`Set<string>` of open block labels (the four labels are static and unique, so the label itself is
the key — no synthetic id needed). Clicking, tapping, or pressing Enter/Space on a `button`
element gets all three for free; a `title` attribute gets none of them.

```html
<dd>
  {{ b.text }}
  @if (b.from) {
    <button type="button" class="from" [attr.aria-expanded]="isOpen(b.label)" (click)="toggle(b.label)">why</button>
  }
  @if (b.from && isOpen(b.label)) { <p class="prov">{{ b.from }}</p> }
</dd>
```

No popover/floating-UI: the reveal is inline, below the fact, pushing later blocks down — same
non-overlapping, no-positioning-logic tradeoff the rest of this panel already makes (e.g. the
`.gap` styling for a missing fact). Playbook steps already show `from:` unconditionally inline;
this makes the impact panel consistent with that instead of introducing a second interaction
pattern.

`RelevanceChipComponent`'s own `title`-based tooltip (the row-list "Act now" chip) is unaffected —
it's a single summary tooltip on a dense list row, not a per-fact provenance drill-down, and
changing it isn't part of either reported problem.

## Part B — real affected-version ranges

### Where the data already is

`item_cpes` deliberately keeps only `(part, vendor, product)` — `cpe.js`'s own comment states
it's "not a version inventory." But the version bound fields are still sitting unused in
`items.raw_json`, inside `configurations[].nodes[].cpeMatch[]`:

```json
{
  "vulnerable": true,
  "criteria": "cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*",
  "versionEndExcluding": "10.0.26100.8875"
}
```

### Measured coverage (NVD CVE API items, live corpus, 2026-08-04)

| | count |
|---|---|
| NVD items total | 20,271 |
| Carry `configurations` at all | 14,242 |
| Carry ≥1 `vulnerable: true` CPE match | 14,082 (69.5%) |
| Of those, ≥1 match has a version bound (`versionStart/EndIncluding/Excluding`) | 4,927 |
| Of those, ≥1 match has an exact pinned version instead (no bound fields, version field ≠ `*`) | 9,945 |
| Average distinct (vendor, product) pairs per item with a vulnerable match | 1.7 |

So ~70% of NVD items can say *something* about which versions are affected, split roughly
1:2 between a real range and an exact pin. The remaining ~30% (no `configurations`, or only
`vulnerable: false` platform-dependency entries) get no version text — the confirm step falls
back to today's generic wording, same graceful-null posture as `patch_url`/`advisory_url`/every
other derived fact in this codebase.

This coverage number is for *any* matching product on the CVE. Whether it covers the specific
vendor/product the reader's profile asset matched is necessarily lower and isn't separately
measurable without picking a profile — the design doesn't depend on that number, since a miss
degrades to the existing generic sentence rather than failing.

### New pure functions, `consolidate.js`

Same file, same pattern as the existing `referenceUrlFrom`/`kevDueDateFrom` — reads
`raw_json`, never fabricates, returns `null` on anything unparseable.

```js
// Formats one CPE match's version bound into a plain-English fragment. Only vulnerable:true
// matches are ever passed in — a "runs on" platform dependency isn't a statement about which
// version of the affected product itself is unsafe.
function versionRangeText(match) {
  const { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding } = match;
  const start = versionStartIncluding || versionStartExcluding;
  const end = versionEndIncluding || versionEndExcluding;
  if (start && end) {
    return `${start} through ${versionEndIncluding ? end : `before ${end}`}`;
  }
  if (end) return versionEndExcluding ? `before ${end}` : `${end} and earlier`;
  if (start) return versionStartExcluding ? `after ${start}` : `${start} and later`;
  // No bound fields — fall back to the CPE's own pinned version segment (5th colon field),
  // when it isn't the wildcard '*' or not-applicable '-'.
  const version = typeof match.criteria === 'string' ? match.criteria.split(':')[5] : null;
  return version && version !== '*' && version !== '-' ? `version ${version}` : null;
}

// One line of text per distinct (vendor, product) the real NVD row calls vulnerable, in the
// order NVD lists them. Reuses parseCpe from cpe.js so the vendor/product spelling matches
// item_cpes exactly — this is what buildPlaybook/buildConsequence key their lookup on.
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
        out.push({ vendor: parsed.vendor, product: parsed.product, text });
      }
    }
  }
  return out;
}
```

`parseCpe` is imported from `./cpe.js` (already a sibling module, already used for `item_cpes`) —
not reimplemented.

### Storage: `cve_intel.affected_versions JSONB`

```sql
ALTER TABLE cve_intel ADD COLUMN IF NOT EXISTS affected_versions JSONB;
```

Written in `rebuildCveIntel`'s existing batched insert (the `cveIntel.*` arrays), computed from
the same `nvdRow` lookup `patchUrl`/`advisoryUrl` already do — no second raw_json parse. This is
CVE-level, not profile-level: it lists every affected product's range, and the profile-specific
lookup (which vendor/product the reader's asset actually matched) happens downstream in
`playbook.js`, exactly like `roleFor(vendor, product)` already does. No new backfill script —
`affected_versions` repopulates on the next `consolidate()` pass, which already runs every sync
(same as how `patch_url`/`kev_due_date` arrived without one).

### Wiring: `relevance.js`

`assembleItems`'s existing lateral join already fetches one `cve_intel` row (`ci`) per item.
Add `ci.affected_versions` to the select list and `item.cve.affectedVersions = r.affected_versions
|| []` to the mapped shape, alongside the existing `patchUrl`/`advisoryUrl`. Pass it through to
`buildPlaybook` the same way.

### `playbook.js`: `confirmStep`

```js
function confirmStep(vendor, product, affectedVersions) {
  const target = targetPhrase(vendor, product);
  const match = (affectedVersions || []).find((v) => v.vendor === vendor && v.product === product);
  return {
    key: 'confirm',
    title: 'Check whether you run the affected version',
    detail: match ? `Affected: ${target} — ${match.text}` : `Affected: ${target}`,
    source: match
      ? 'NVD CPE match (version range)'
      : (vendor && product ? 'your profile assets' : 'this item’s CVE match'),
    link: null,
  };
}
```

`buildPlaybook` gains one new param, `affectedVersions = []`, passed straight to `confirmStep`.
When there's no asset match (`vendor`/`product` both null) the lookup trivially misses and
behavior is unchanged.

## Testing

- `consolidate.test.js`: `affectedVersionsFrom` — a match with `versionEndExcluding` only, a
  match with both start+end, a match with neither (falls back to the exact pinned version), a
  match with truly nothing meaningful (`*` version, no bounds → excluded from the array,
  confirming the fallback to nothing rather than a hallucinated range), two arch variants of the
  same product deduping to one entry, a `vulnerable: false` platform-dependency entry being
  skipped. Round out with a `rebuildCveIntel` integration test asserting `affected_versions` lands
  in the row.
- `playbook.test.js`: `confirmStep` with a matching `affectedVersions` entry produces the
  version-qualified detail; with no match, or empty array, produces today's generic detail
  unchanged.
- `relevance-chip`/impact panel: existing `relevance.spec.ts` + a new interaction test for
  `impact-panel.component.ts` — actually there's no TestBed in this app (per Spec A's own note:
  "runs vitest in a node environment with no TestBed by design"), so the toggle behavior itself
  (`isOpen`/`toggle`) should be a couple of plain-JS unit assertions on the component class
  instance, not a rendered-DOM click test.

## Non-goals

- No UI to browse *all* affected products for a CVE (the confirm step names only the one product
  the reader's own asset matched — showing the other 1.7-average unrelated products would be
  noise, same reasoning Spec A already applied to `item_cpes` matching).
- No change to the row-list relevance chip's tooltip (Part A's button conversion is scoped to the
  four impact-panel blocks only).
- No re-derivation for non-NVD sources — `affectedVersionsFrom` only ever reads the real NVD row,
  same restriction `referenceUrlFrom` already has and for the same reason: an incidentally-shared
  CVE from another source has no CPE configuration to read.
