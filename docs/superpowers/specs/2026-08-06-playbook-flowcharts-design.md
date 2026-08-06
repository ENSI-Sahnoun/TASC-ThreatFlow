# Branching visual playbooks — phishing first

Design, 2026-08-06.

## Problem

Every non-CVE category (`ioc`, `malware`, `ransomware`, `phishing`, `data-breach`) renders its
"what to do about this" section as a flat checklist (`tf-playbook-panel`, `core/playbook.ts`),
built server-side by `server/playbooks/*.js`. Those builders already contain real conditional
logic — e.g. `buildPhishingPlaybook` only pushes a `phishing:block-iocs` step when the item
actually has indicators — but that logic is invisible to the reader. A user asked for something
closer to the classic SOC "decision diamond" playbook poster (attached reference image, a phishing
triage flowchart with Yes/No branches), applied to every category the checklist currently covers.

The CVE category already has a comparable visual — `reach-diagram.component.ts` /
`remediation.ts`'s `reachDiagram()` — but it draws a straight-line path (origin → gate → outcome)
derived from the CVSS vector, not a branching flow, and it explains what the vulnerability *does*,
not what to *do about it*. It is out of scope here; CVE's own playbook checklist (from
`server/playbook.js`, the confirm/patch steps under the CVE guided page) is untouched by this spec.

## Decisions made during brainstorming

- **Resolved path, not a generic tree.** Unlike a real-world SOC responder who doesn't yet know if
  an email has an attachment, ThreatFlow already knows the facts (indicators on file, indicator
  type) before the page renders. The diagram always shows the one path already true for this item
  — taken branches lit up, not-taken branches shown collapsed/grey — never an interactive
  Yes/No the reader has to answer themselves. This matches the app's existing rule that the system
  never asks the reader to re-derive something the data already answers.
- **Replaces the checklist**, doesn't sit alongside it, for any category that has a flow built.
- **Ship phishing first**, prove the pattern, then port to malware/ransomware/data-breach/ioc as
  small follow-ups (new shape file each, no new engine work).
- **Vertical layout**, matching the reference image's grammar directly (top-to-bottom, start pill
  → action boxes → decision diamonds → end pill) rather than the CVE diagram's horizontal rail.
- **Side-rail merge for "no" branches** — a skipped decision's action box still renders (dashed,
  muted, no checkbox interaction), and a dashed line from the diamond routes around it and merges
  back in before the next node — rather than silently deleting that part of the diagram. Keeps the
  diagram's shape legible and its height predictable across different items in the same category.

## Architecture

No backend changes. The key realization: because a category's step builder only includes an
optional step when its guard is true, **the presence of a given step key in the `steps` array the
server already returns is itself the yes/no fact** — the same trick `core/playbook.ts`'s
`groundingFooter()` already uses (matching step-key suffixes to decide what to show in the
"grounded in" footer). No new field, no new endpoint.

```
frontend-v4/src/app/core/
  playbook-flow.ts        -- pure: flow shape templates + resolver + SVG layout math
  playbook-flow.spec.ts

frontend-v4/src/app/ui/
  playbook-flow.component.ts   -- draws the SVG, owns the checkbox/tick wiring
```

`playbook-panel.component.ts` and `core/playbook.ts` are untouched — they remain the rendering
path for every category without a flow template yet (currently: everything except phishing, plus
CVE indefinitely).

### Flow templates

A template is a fixed, hand-authored sequence per category — the procedural shape, not
per-item data (same spirit as `reach-diagram.ts`'s hardcoded `ORIGIN`/`GATE` vocabulary maps).

```ts
type FlowNode =
  | { type: 'start' | 'end'; label: string }
  | { type: 'action'; key: string }               // key matches a PlaybookStep.key exactly
  | { type: 'decision'; question: string; gates: string }; // gates: the key of the ACTION NODE
                                                            // immediately following this one

const PHISHING_FLOW: FlowNode[] = [
  { type: 'start', label: 'Suspect phishing item' },
  { type: 'action', key: 'phishing:confirm' },
  { type: 'decision', question: 'Any indicators on file?', gates: 'phishing:block-iocs' },
  { type: 'action', key: 'phishing:block-iocs' },
  { type: 'decision', question: 'Includes a URL indicator?', gates: 'phishing:report-phishing-url' },
  { type: 'action', key: 'phishing:report-phishing-url' },
  { type: 'action', key: 'phishing:check-clicked' },
  { type: 'end', label: 'Done' },
];

const FLOW_TEMPLATES: Record<string, FlowNode[]> = { phishing: PHISHING_FLOW };
```

A `decision` node is always immediately followed by exactly one `action` node — the one it gates.
This keeps every decision a local, self-contained unit (diamond → maybe-box → rejoin) rather than
a general graph, which is also why multiple decisions can chain in sequence (ransomware has two)
without any nesting or rail-collision logic: each rail only spans its own diamond's local
y-range, and ranges never overlap because the template is a flat sequence, never a tree.

### Resolver

```ts
interface ResolvedNode extends FlowNode {
  resolved: boolean;   // for 'action' nodes gated by a decision: was this step present?
  done: boolean;        // for 'action' nodes: is this step ticked?
}

function resolveFlow(template: FlowNode[], playbook: Playbook): ResolvedNode[]
```

Pure function: for each `action` node, `resolved = playbook.steps.some(s => s.key === node.key)`.
Un-gated action nodes (not preceded by a `decision`) are always `resolved: true` — the server's
builders already guarantee "always" steps are unconditionally present. A `decision` node's own
branch outcome is read off its paired action node's `resolved` value, so there is exactly one
source of truth per decision, never a second boolean that could disagree with it.

### Layout

A second pure function turns `ResolvedNode[]` into absolute SVG coordinates — same idea as
`remediation.ts`'s existing `diagramEdgeLines`/`diagramSvgWidth`, but a vertical cumulative stack
instead of a fixed horizontal stride, because node types here have different heights:

| Node | Size | Notes |
|---|---|---|
| start / end | 160×30, pill (rx 15) | |
| action | 220×48, rx 7 | checkbox glyph at top-left when interactive |
| decision | 140×92 diamond | always rendered filled — it's always resolved |
| rail offset | 150px right of the center column | dashed, only drawn when the paired action is `resolved: false` |
| vertical gap | 26px between any two node edges | arrowhead drawn on every connecting edge |

Column x is fixed (center-aligned); y advances by each node's height plus the fixed gap above —
these are the exact numbers validated against a real phishing item in the brainstorming session's
visual mockup (side-rail-merge option), starting values for implementation, not final polish. A
skipped action node still occupies its vertical slot (dashed outline, muted fill, no checkbox) so
diagram height stays predictable across different items in the same category — the "no" path is
drawn, not deleted, per the brainstorming decision above.

### Component

`playbook-flow.component.ts` takes the same `[playbook]`/`[itemId]` inputs and emits the same
`(toggled)` output as `playbook-panel.component.ts` does today, and calls the same
`tickPlaybookStep`/`untickPlaybookStep` API methods — it is a drop-in replacement at the call site,
not a new interaction model. Only `action` nodes that are `resolved: true` get a checkbox;
`decision` nodes and skipped `action` nodes are inert (no click target).

### Wiring into the guided page

```html
@if (hasFlow(d.item.category)) {
  <tf-playbook-flow [playbook]="d.playbook" [itemId]="d.item.id" (toggled)="onStepToggled($event)" />
} @else if (d.playbook) {
  <tf-playbook-panel [playbook]="d.playbook" [itemId]="d.item.id" (toggled)="onStepToggled($event)" />
}
```

`hasFlow(category)` is `category in FLOW_TEMPLATES`. Every category other than `phishing`
(including `cve`) keeps rendering exactly what it renders today — zero behavior change for them in
this pass.

## Failure modes

| Condition | Behaviour |
|---|---|
| `playbook` is `null` (category builder returned no playbook at all) | Neither component renders — same as today. |
| A step key in the template has no matching entry in `FLOW_TEMPLATES`'s expected server keys (e.g. a future rename of `phishing:block-iocs` in `server/playbooks/phishing.js`) | That action node resolves to `false` unconditionally — reads as "always skipped," a silent-looking but detectable regression. Mitigated by the test below asserting every template key exists in the category's real builder output for at least one fixture. |
| A category's builder adds a NEW conditional step not yet reflected in its flow template (template drift) | The new step is simply absent from the diagram — no crash, but incomplete. Only a risk once a category has both a template and ongoing step-builder changes; phishing's builder is stable today. |

## Testing

- `playbook-flow.spec.ts`: `resolveFlow()` against four fixture step lists for phishing (no
  indicators; indicators, none URL-typed; indicators including a URL; all steps ticked) — asserts
  the right nodes resolve `true`/`false` and `done` reflects `playbook.done`.
- Same file: layout function produces the expected node count, no overlapping y-ranges, and rail
  x-offset only appears for unresolved action nodes.
- `playbook-flow.component` gets a minimal DOM-free assertion the same way `playbook-panel` does
  today — toggling emits the same `{key, done}` shape.

## Out of scope

- **Malware, ransomware, data-breach, ioc flow templates.** Explicitly deferred to fast-follow work
  once phishing is validated in the real app — each is a new `FlowNode[]` constant plus a
  `FLOW_TEMPLATES` entry, no new engine code expected.
- **CVE's own playbook checklist** (`server/playbook.js` output, rendered today via
  `tf-playbook-panel` on the same guided page). Stays a flat checklist indefinitely unless
  requested separately; `reach-diagram.component.ts` (the CVSS "what this does" diagram) is
  unrelated and also untouched.
- **Any backend change.** The whole design reads existing `Playbook.steps`/`.done` — no new API
  field, no new column.
