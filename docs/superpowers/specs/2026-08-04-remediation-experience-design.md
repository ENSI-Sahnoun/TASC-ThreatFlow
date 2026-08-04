# Remediation experience — the queue and the guided page

Design, 2026-08-04. Spec B of three. Depends on
[`2026-08-04-remediation-foundation-design.md`](2026-08-04-remediation-foundation-design.md) (A),
which must ship first. AI Assist is
[`2026-08-04-remediation-ai-assist-design.md`](2026-08-04-remediation-ai-assist-design.md) (C).

## Problem

`tf-playbook-panel` is a checklist inside a detail page. It answers "what are the steps" and
stops. It cannot show what the flaw actually does, cannot ask which version the reader runs,
cannot say what to upgrade to, and treats each threat as unrelated to every other threat against
the same machine — so a single upgrade that closes five CVEs reads as five separate chores.

Spec A supplies the missing facts. This spec is what a person sees.

## Shape: an index and a detail, not one or the other

Two routes:

- **`/remediate`** — the queue. Grouped by asset, because the unit of work is an upgrade, not a
  CVE. "FortiOS: 5 open, 1 upgrade clears 3 of them" is a plan; a flat list of five CVEs is a
  backlog.
- **`/remediate/:itemId`** — the guided page. One threat, full width, walked through.

The existing `tf-playbook-panel` on the item detail page stays and gains a link into the guided
page. It is a summary; this is the workspace. Removing it would make the detail page worse for the
common case of a quick look.

## Visual language

Everything below is expressed in the existing tokens (`core/tokens.css`) and the existing
`tf-panel` shell. No new palette, no new radius scale, no second card style. Specifically:

- Surfaces step `--surface` → `--surface-2` → `--surface-3` for nesting, never a new gray.
- `--accent` (aqua) marks the active step and the primary action, and nothing else. It is the
  brand's one loud colour and it stops meaning "here" if it also means "danger".
- Severity uses the existing ramp (`--sev-critical` … `--sev-unknown`). The remediation surface
  introduces no severity colours of its own.
- Motion uses the declared easings: `--ease-out` for anything entering or responding to input,
  `--ease-in-out` only for on-screen repositioning. The token file states this rule; this spec
  does not get an exception.
- Blur is chrome only, per `panel.component.ts`'s own comment. The step rail may use it. Scrolling
  content may not.

Tone follows the rest of the product: statements of fact, provenance attached, no exclamation, no
threat theatre. The page is calm about urgent things.

## The queue — `/remediate`

```
┌─ Remediation ────────────────────────────────────────────┐
│  8 open · 3 past due · 2 closed this week                │
├──────────────────────────────────────────────────────────┤
│  Windows 11 24H2            ▓▓▓▓░░  4 of 6               │
│  you run 10.0.26100.8300 · internet-facing               │
│    ▸ one upgrade to 10.0.26100.8875 closes 3 of these    │
│    CVE-2026-49793   affected    fix by Aug 17            │
│    CVE-2026-49801   affected                             │
│    CVE-2026-49830   unknown     version not comparable   │
├──────────────────────────────────────────────────────────┤
│  FortiOS                    ▓░░░░░  1 of 5      past due │
│  version not recorded                    [ tell us → ]   │
│    CVE-2026-30      no fix published                     │
└──────────────────────────────────────────────────────────┘
```

Grouping is by `(vendor, product)` from `profile_assets`. Within a group, threats sort by the
relevance score already materialized in `item_relevance` — this page introduces no second ordering
opinion.

**The "one upgrade closes N" line is computed, not asserted.** It appears only when two or more
threats in the group share the same `fixTarget` of `kind: 'version'`, and N is the count of those.
It never appears for `patch`/`advisory`/`none` targets, because two patch URLs are not one action.

An asset with `version_state: 'unset'` shows a `tell us` affordance instead of a progress bar,
since progress against an unknown version is not measurable. An asset at `'unknown'` shows the
threats without the bar and does not re-ask.

## The guided page — `/remediate/:itemId`

Four steps on a rail. The rail is a progress indicator, not a wizard that traps you: every step is
reachable at any time, and the page is fully readable scrolled top to bottom with no interaction.
A remediation page that hides the fix behind three "Next" clicks is worse than the panel it
replaces.

### Step 1 — What this does

The signature diagram, and the only new visual invention in this spec.

It renders the CVSS vector as a path: **origin → reach → what it gets**. Every element is driven
by metrics `cvss.js:parseVector` already returns and `consequence.js` already turns into prose —
this draws the same facts rather than deriving new ones.

```
   AV:L               PR:L              C:H I:H A:H
 ┌────────┐        ┌────────┐        ┌────────────┐
 │ already│───────▶│ normal │───────▶│  read      │
 │  on    │        │  user  │        │  change    │
 │ network│        │ account│        │  shut down │
 └────────┘        └────────┘        └────────────┘
                        │
                   UI:N — needs nothing from anyone
```

- `AV` picks the origin node: `N` internet, `A` adjacent network, `L` already on the machine,
  `P` physical access.
- `PR` picks the gate: `N` no account, `L` a normal account, `H` an admin account.
- `UI` annotates it: `N` needs nothing from anyone, `R` needs someone to click something.
- `C`/`I`/`A` at `H` fill the outcome node with the verbs `consequence.js` already uses.

Inline SVG, no chart library — this is four boxes and two arrows, and `echarts` is for data
series. It sits at the page's natural width and scrolls horizontally inside its own container on
narrow viewports rather than reflowing into an unreadable stack.

**Motion:** on first view, the path draws left to right, ~600ms total, `--ease-out`, nodes fading
in 80ms apart. It runs once. It does not loop, pulse, or re-trigger on scroll — a threat
dashboard that animates continuously reads as an alarm, and everything here is already urgent
enough without help. Under `prefers-reduced-motion: reduce` the finished state renders
immediately, with no draw.

**What it does not do:** no attacker avatars, no blast radius, no packet flight. The diagram
states reachability, not a simulation. Its job is to make `AV:L/PR:L/UI:N` legible to someone who
has never read a CVSS vector, and it fails if it dramatizes beyond what the vector supports.

Provenance is attached the way the impact panel now does it: a `why` button revealing the exact
metrics behind each node. Same pattern, same component idiom, no second interaction to learn.

### Step 2 — Are you affected

Where the version question is asked, at the moment the reader has a reason to answer it.

```
Affected:  Windows 11 24H2, before 10.0.26100.8875
                                     from NVD CPE match · why

You run:   [ 10.0.26100.____        ]   [ I don't know ]
```

Three outcomes, from `affectedStatus` (Spec A) and never from the client:

| status | rendering |
|---|---|
| `affected` | **You are affected.** Your build is inside the range. |
| `not_covered` | This range does not cover your build. *Not a clean bill of health* — confirm against the vendor advisory before treating it as closed. |
| `unknown` | These two can't be ordered reliably. Compare them yourself: `<installed>` / `<range text>` |

The `not_covered` wording is load-bearing and is specified here so it cannot drift: the system
never tells anyone they are safe. Spec A's comparator abstains rather than guess; this is where
that abstention is honoured in language.

Choosing **I don't know** writes `version_state: 'unknown'`, is never treated as a failure, and
the page continues to the fix — knowing what to upgrade to is useful whether or not you know what
you are on. The input is never a blocker.

**Motion:** the verdict block cross-fades in at 180ms `--ease-out` when a version is submitted. No
count-up, no shake on `affected`. The word "affected" is doing the work.

### Step 3 — The fix

Renders `fixTarget` (Spec A) — four cases, four different pages, no hedging between them:

- **`version`** — "Upgrade to 10.0.26100.8875 or later", with the vendor's patch link beneath it if
  one exists. The only case that names a target version, because `endExcluding` is the only field
  that names one.
- **`patch`** — the vendor's fix link, verbatim from `patch_url`, shown as the URL it is.
- **`advisory`** — the vendor's guidance link, with the plain statement that no direct patch link
  is published.
- **`none`** — **"No fix has been published for this yet."** Stated as fact, then the mitigations
  from the playbook (`restrict`, `rotate`) presented as what to do meanwhile. 17% of entries land
  here; it is a real state of the world, not an error, and it gets a real answer rather than an
  empty panel.

### Step 4 — Close it out

The existing playbook checklist, unchanged in behaviour — `playbook_step_state`, optimistic ticks,
and the grounding footer all keep working exactly as they do today.

One addition. When the fix was `kind: 'version'` and the reader ticks the patch step, the page
offers to record the new version on the asset:

```
  ✓ Applied the fix
    Record that you're now on 10.0.26100.8875?     [ yes ]  [ not yet ]
```

Accepting `PATCH`es the asset (Spec A), which bumps `profile_version` and triggers the recompute.
The consequence is then shown, because it is the payoff of the whole design:

```
  Recorded. 2 other threats against this machine
  are no longer inside their affected range.      [ see them → ]
```

**That sentence is generated from the recomputed statuses, never predicted before the write.** If
the recompute clears nothing, nothing is claimed. `not yet` is a first-class answer — a reader who
ticked the step to track their own progress has not necessarily finished the rollout, and assuming
they have would corrupt the asset version for every other threat.

**Motion:** the cleared threats animate out of the queue on next view, 240ms `--ease-out`, staggered
40ms. Progress bars grow to their new value over 400ms. This is the one place the page celebrates,
and it celebrates a real state change.

## Empty and degraded states

Every one of these is a designed state, not a blank panel:

- **No profile assets.** "Tell us what you run and this page fills itself in" → the survey.
- **No open threats.** "Nothing open against the software you've told us about." Explicitly not
  "you're secure" — same rule as `not_covered`.
- **All versions `unset`.** The queue renders, threats and all, with version prompts inline. The
  page is useful before any version is known.
- **Item has no CVE / no vector.** The guided page redirects to the item detail. There is nothing
  to guide through.

## Testing

Pure logic in `core/remediation.ts` with its own `.spec.ts`, per the convention this app already
follows for `relevance.ts` and `playbook.ts` — vitest in a node environment, no TestBed:

- grouping items by asset, and the sort within a group
- the "one upgrade closes N" rule: fires at N ≥ 2 sharing a `version` target; never fires for
  `patch`/`advisory`/`none`; never counts a threat twice
- diagram node selection from every `AV`/`PR`/`UI` combination, including absent metrics
- status → wording, asserting `not_covered` never produces the word "safe"
- progress arithmetic when `version_state` is `unset` / `unknown`

Component classes stay thin bindings. The diagram is a pure function returning node/edge
descriptors, tested as data; the SVG is a template over it.

## Non-goals

- **No new chart library.** Inline SVG for the diagram; `echarts` remains for data series.
- **No wizard lock.** No step gates another. Everything is readable in one scroll.
- **No cross-asset "fix everything" bulk action.** Recording a version is per asset and explicit.
  A bulk write would set versions the user never confirmed, on the strength of an inference — the
  exact failure this design refuses everywhere else.
- **No editing assets here.** Adding or removing an asset stays in the profile survey. This page
  records a version on an asset that already exists.
- **No continuous or ambient animation.** Motion marks transitions and state changes, and stops.
