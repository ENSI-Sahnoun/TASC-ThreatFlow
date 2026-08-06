# Branching Visual Playbooks (Phishing) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat checklist on the remediation guided page with a vertical decision-diamond
flowchart for phishing items only, reusing existing playbook step keys as the yes/no facts.

**Architecture:** Two new pure-logic + one new component file in `frontend-v4/`, following the
same split the CVE reach-diagram already uses: `core/playbook-flow.ts` (flow shape, resolver,
SVG layout math — no DOM, no HTTP) and `ui/playbook-flow.component.ts` (renders the SVG, owns
checkbox ticking). `remediation-guided.component.ts` picks the new component for phishing items
and falls back to the existing `tf-playbook-panel` checklist for every other category.

**Tech Stack:** Angular 19 (standalone components, signals), inline SVG (no chart library),
vitest for pure-function tests.

## Global Constraints

- No backend changes — everything reads the existing `Playbook { steps, done }` shape already
  returned by `GET /api/items/:id/remediation`.
- Only the `phishing` category gets a flow template in this pass. Every other category
  (`malware`, `ransomware`, `data-breach`, `ioc`, `cve`, anything else) must render byte-identical
  to today via the untouched `tf-playbook-panel`.
- Layout is vertical (top-to-bottom), resolved-path only — no interactive yes/no, the diagram
  always shows the one path already true for the item.
- Geometry: start/end pill 160×30 (rx 15); action box 220×48 (rx 7); decision diamond 140×92;
  rail offset 150px right of the center column; 26px gap between any two node edges. Center
  column x = 180 (so a 220-wide action box spans x=70..290, a 160-wide pill spans x=100..260).
- A `decision` node in a flow template is always immediately followed by exactly one `action`
  node — the one it gates. This invariant is what lets the resolver and layout code treat every
  decision as a local, self-contained unit instead of a general graph.
- A skipped (`not resolved`/`not taken`) node still occupies its vertical slot in the diagram
  (dashed outline, muted, no checkbox) — never deleted from the layout.

---

## File Structure

- Create: `frontend-v4/src/app/core/playbook-flow.ts` — `FlowNode` types, `PHISHING_FLOW`,
  `FLOW_TEMPLATES`, `hasFlow()`, `resolveFlow()`, layout constants, `layoutFlow()`.
- Create: `frontend-v4/src/app/core/playbook-flow.spec.ts` — vitest coverage for the above.
- Create: `frontend-v4/src/app/ui/playbook-flow.component.ts` — SVG rendering + checkbox wiring.
- Modify: `frontend-v4/src/app/pages/remediate/remediation-guided.component.ts` — swap in the new
  component for phishing items.

---

### Task 1: Flow shape + resolver (`core/playbook-flow.ts` part 1)

**Files:**
- Create: `frontend-v4/src/app/core/playbook-flow.ts`
- Test: `frontend-v4/src/app/core/playbook-flow.spec.ts`

**Interfaces:**
- Consumes: `Playbook`, `PlaybookStep` from `./models` (already defined — `Playbook = { steps: PlaybookStep[]; done: string[] }`, `PlaybookStep = { key, title, detail, source, link }`).
- Produces (used by Task 2 and Task 3):
  - `type FlowNode = { type: 'start' | 'end'; key: string; label: string } | { type: 'action'; key: string } | { type: 'decision'; key: string; question: string; gates: string }`
  - `type ResolvedFlowNode = FlowNode & { resolved?: boolean; done?: boolean; taken?: boolean }` — `resolved`/`done` present only when `type === 'action'`; `taken` present only when `type === 'decision'`.
  - `const FLOW_TEMPLATES: Record<string, FlowNode[]>`
  - `function hasFlow(category: string | null | undefined): boolean`
  - `function resolveFlow(template: FlowNode[], playbook: Playbook | null | undefined): ResolvedFlowNode[]`

- [ ] **Step 1: Write the failing test**

Create `frontend-v4/src/app/core/playbook-flow.spec.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { FLOW_TEMPLATES, hasFlow, resolveFlow } from './playbook-flow';
import type { Playbook, PlaybookStep } from './models';

const step = (key: string): PlaybookStep => ({ key, title: 't', detail: 'd', source: 's', link: null });

describe('hasFlow', () => {
  it('is true for phishing', () => {
    expect(hasFlow('phishing')).toBe(true);
  });

  it('is false for any category without a template, including cve', () => {
    expect(hasFlow('cve')).toBe(false);
    expect(hasFlow('malware')).toBe(false);
    expect(hasFlow(null)).toBe(false);
    expect(hasFlow(undefined)).toBe(false);
  });
});

describe('resolveFlow (phishing)', () => {
  const template = FLOW_TEMPLATES['phishing'];

  it('resolves every optional node false when the item has no indicators', () => {
    const pb: Playbook = { steps: [step('phishing:confirm'), step('phishing:check-clicked')], done: [] };
    const resolved = resolveFlow(template, pb);

    const hasIndicators = resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:block-iocs');
    expect(hasIndicators?.taken).toBe(false);

    const hasUrl = resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:report-phishing-url');
    expect(hasUrl?.taken).toBe(false);

    const blockIocs = resolved.find((n) => n.type === 'action' && n.key === 'phishing:block-iocs');
    expect(blockIocs?.resolved).toBe(false);
  });

  it('resolves the indicators decision true but the URL decision false when indicators exist with no URL type', () => {
    const pb: Playbook = {
      steps: [step('phishing:confirm'), step('phishing:block-iocs'), step('phishing:check-clicked')],
      done: [],
    };
    const resolved = resolveFlow(template, pb);

    expect(resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:block-iocs')?.taken).toBe(true);
    expect(resolved.find((n) => n.type === 'action' && n.key === 'phishing:block-iocs')?.resolved).toBe(true);
    expect(resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:report-phishing-url')?.taken).toBe(false);
  });

  it('resolves both decisions true when a URL indicator is present', () => {
    const pb: Playbook = {
      steps: [
        step('phishing:confirm'), step('phishing:block-iocs'),
        step('phishing:report-phishing-url'), step('phishing:check-clicked'),
      ],
      done: [],
    };
    const resolved = resolveFlow(template, pb);

    expect(resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:block-iocs')?.taken).toBe(true);
    expect(resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:report-phishing-url')?.taken).toBe(true);
  });

  it('reflects done[] on resolved action nodes', () => {
    const pb: Playbook = {
      steps: [step('phishing:confirm'), step('phishing:check-clicked')],
      done: ['phishing:confirm'],
    };
    const resolved = resolveFlow(template, pb);
    expect(resolved.find((n) => n.type === 'action' && n.key === 'phishing:confirm')?.done).toBe(true);
    expect(resolved.find((n) => n.type === 'action' && n.key === 'phishing:check-clicked')?.done).toBe(false);
  });

  it('leaves start/end nodes unchanged and never throws on a null playbook', () => {
    const resolved = resolveFlow(template, null);
    expect(resolved[0]).toEqual(template[0]);
    expect(resolved.every((n) => n.type !== 'action' || n.resolved === false)).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/playbook-flow.spec.ts`
Expected: FAIL — `Cannot find module './playbook-flow'`.

- [ ] **Step 3: Write the implementation**

Create `frontend-v4/src/app/core/playbook-flow.ts`:

```ts
import type { Playbook } from './models';

// Branching visual playbooks (Part 1 of the design doc
// docs/superpowers/specs/2026-08-06-playbook-flowcharts-design.md). A flow template is a fixed,
// hand-authored procedural shape per category — same spirit as reach-diagram's hardcoded
// ORIGIN/GATE vocabulary maps in remediation.ts, not a per-item calculation.
//
// A `decision` node is always immediately followed by exactly one `action` node: the one it
// gates. This keeps every decision a local, self-contained unit (diamond -> maybe-box -> rejoin)
// so templates can chain multiple decisions in sequence with no nesting or graph logic.
export type FlowNode =
  | { type: 'start' | 'end'; key: string; label: string }
  | { type: 'action'; key: string }
  | { type: 'decision'; key: string; question: string; gates: string };

export type ResolvedFlowNode = FlowNode & {
  resolved?: boolean; // 'action' nodes only: was this step present in playbook.steps?
  done?: boolean;     // 'action' nodes only: is this step ticked?
  taken?: boolean;    // 'decision' nodes only: did the gated action resolve true?
};

// Mirrors server/playbooks/phishing.js's buildPhishingPlaybook() exactly: confirm and
// check-clicked are unconditional, block-iocs requires at least one indicator, and
// report-phishing-url further requires one of those indicators to be url-typed.
export const PHISHING_FLOW: FlowNode[] = [
  { type: 'start', key: 'start', label: 'Suspect phishing item' },
  { type: 'action', key: 'phishing:confirm' },
  { type: 'decision', key: 'phishing:has-indicators', question: 'Any indicators on file?', gates: 'phishing:block-iocs' },
  { type: 'action', key: 'phishing:block-iocs' },
  { type: 'decision', key: 'phishing:has-url', question: 'Includes a URL indicator?', gates: 'phishing:report-phishing-url' },
  { type: 'action', key: 'phishing:report-phishing-url' },
  { type: 'action', key: 'phishing:check-clicked' },
  { type: 'end', key: 'end', label: 'Done' },
];

export const FLOW_TEMPLATES: Record<string, FlowNode[]> = {
  phishing: PHISHING_FLOW,
};

export function hasFlow(category: string | null | undefined): boolean {
  return !!category && category in FLOW_TEMPLATES;
}

// Pure: the presence of a given step key in playbook.steps IS the yes/no fact, because
// server/playbooks/*.js only ever includes an optional step when its guard was true — the same
// trick core/playbook.ts's groundingFooter() already relies on. No new server field needed.
export function resolveFlow(template: FlowNode[], playbook: Playbook | null | undefined): ResolvedFlowNode[] {
  const stepKeys = new Set((playbook?.steps ?? []).map((s) => s.key));
  const doneKeys = new Set(playbook?.done ?? []);

  return template.map((node) => {
    if (node.type === 'action') {
      const resolved = stepKeys.has(node.key);
      return { ...node, resolved, done: doneKeys.has(node.key) };
    }
    if (node.type === 'decision') {
      return { ...node, taken: stepKeys.has(node.gates) };
    }
    return node;
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/playbook-flow.spec.ts`
Expected: PASS, all 7 tests green.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/playbook-flow.ts frontend-v4/src/app/core/playbook-flow.spec.ts
git commit -m "feat(remediation): add phishing flow template and resolver"
```

---

### Task 2: Layout math (`core/playbook-flow.ts` part 2)

**Files:**
- Modify: `frontend-v4/src/app/core/playbook-flow.ts`
- Modify: `frontend-v4/src/app/core/playbook-flow.spec.ts`

**Interfaces:**
- Consumes: `ResolvedFlowNode` from Task 1.
- Produces (used by Task 3):
  - `const FLOW_CENTER_X = 180`
  - `interface PositionedFlowNode { node: ResolvedFlowNode; x: number; y: number; width: number; height: number }`
  - `interface FlowEdge { key: string; x1: number; y1: number; x2: number; y2: number; dashed: boolean; label: string | null }`
  - `interface FlowLayout { width: number; height: number; nodes: PositionedFlowNode[]; edges: FlowEdge[] }`
  - `function layoutFlow(resolved: ResolvedFlowNode[]): FlowLayout`

- [ ] **Step 1: Write the failing test**

Append to `frontend-v4/src/app/core/playbook-flow.spec.ts`:

```ts
import { layoutFlow } from './playbook-flow';

describe('layoutFlow', () => {
  it('positions one row per template node, all sharing the same width center', () => {
    const template = FLOW_TEMPLATES['phishing'];
    const pb: Playbook = {
      steps: [
        step('phishing:confirm'), step('phishing:block-iocs'),
        step('phishing:report-phishing-url'), step('phishing:check-clicked'),
      ],
      done: [],
    };
    const layout = layoutFlow(resolveFlow(template, pb));

    expect(layout.nodes).toHaveLength(template.length);
    // No two nodes may overlap vertically: each node's y must be >= the previous node's bottom.
    for (let i = 1; i < layout.nodes.length; i++) {
      expect(layout.nodes[i].y).toBeGreaterThanOrEqual(layout.nodes[i - 1].y + layout.nodes[i - 1].height);
    }
    expect(layout.height).toBeGreaterThan(0);
  });

  it('draws no rail edges when every decision is taken', () => {
    const pb: Playbook = {
      steps: [
        step('phishing:confirm'), step('phishing:block-iocs'),
        step('phishing:report-phishing-url'), step('phishing:check-clicked'),
      ],
      done: [],
    };
    const layout = layoutFlow(resolveFlow(FLOW_TEMPLATES['phishing'], pb));
    expect(layout.edges.some((e) => e.dashed)).toBe(false);
  });

  it('draws a 3-segment dashed rail around a skipped action, and gives the skipped box no edges', () => {
    const pb: Playbook = { steps: [step('phishing:confirm'), step('phishing:check-clicked')], done: [] };
    const layout = layoutFlow(resolveFlow(FLOW_TEMPLATES['phishing'], pb));

    const railEdges = layout.edges.filter((e) => e.dashed);
    // Two skipped decisions (has-indicators, has-url) x 3 rail segments each.
    expect(railEdges).toHaveLength(6);

    const blockIocsKey = 'phishing:block-iocs';
    expect(layout.edges.some((e) => e.key.includes(blockIocsKey))).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/playbook-flow.spec.ts`
Expected: FAIL — `layoutFlow is not a function` (or "no export named 'layoutFlow'").

- [ ] **Step 3: Write the implementation**

Append to `frontend-v4/src/app/core/playbook-flow.ts`:

```ts
export const FLOW_CENTER_X = 180;
const FLOW_PILL_WIDTH = 160;
const FLOW_PILL_HEIGHT = 30;
const FLOW_ACTION_WIDTH = 220;
const FLOW_ACTION_HEIGHT = 48;
const FLOW_DIAMOND_WIDTH = 140;
const FLOW_DIAMOND_HEIGHT = 92;
const FLOW_GAP = 26;
const FLOW_RAIL_OFFSET = 150;
const FLOW_TOP_MARGIN = 10;

export interface PositionedFlowNode {
  node: ResolvedFlowNode;
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface FlowEdge {
  key: string;
  x1: number; y1: number;
  x2: number; y2: number;
  dashed: boolean;
  label: string | null;
}

export interface FlowLayout {
  width: number;
  height: number;
  nodes: PositionedFlowNode[];
  edges: FlowEdge[];
}

function nodeSize(node: ResolvedFlowNode): { width: number; height: number } {
  if (node.type === 'decision') return { width: FLOW_DIAMOND_WIDTH, height: FLOW_DIAMOND_HEIGHT };
  if (node.type === 'action') return { width: FLOW_ACTION_WIDTH, height: FLOW_ACTION_HEIGHT };
  return { width: FLOW_PILL_WIDTH, height: FLOW_PILL_HEIGHT };
}

function solidEdge(a: PositionedFlowNode, b: PositionedFlowNode, label: string | null = null): FlowEdge {
  return {
    key: `${a.node.key}-${b.node.key}`,
    x1: a.x + a.width / 2, y1: a.y + a.height,
    x2: b.x + b.width / 2, y2: b.y,
    dashed: false,
    label,
  };
}

// Rail routes a skipped decision's "no" branch around its (unrendered-with-edges) gated action
// box: out from the diamond's right edge, down to the merge target's top, back in to its
// top-center. Three segments so the component can draw each leg as its own dashed <line>.
function railEdges(decision: PositionedFlowNode, after: PositionedFlowNode): FlowEdge[] {
  const railX = FLOW_CENTER_X + FLOW_RAIL_OFFSET;
  const midY = decision.y + decision.height / 2;
  const mergeY = after.y;
  const base = decision.node.key;
  return [
    { key: `${base}-rail-out`, x1: decision.x + decision.width, y1: midY, x2: railX, y2: midY, dashed: true, label: 'no' },
    { key: `${base}-rail-down`, x1: railX, y1: midY, x2: railX, y2: mergeY, dashed: true, label: null },
    { key: `${base}-rail-in`, x1: railX, y1: mergeY, x2: after.x + after.width / 2, y2: mergeY, dashed: true, label: null },
  ];
}

export function layoutFlow(resolved: ResolvedFlowNode[]): FlowLayout {
  const nodes: PositionedFlowNode[] = [];
  let cursorY = FLOW_TOP_MARGIN;
  for (const node of resolved) {
    const { width, height } = nodeSize(node);
    nodes.push({ node, x: FLOW_CENTER_X - width / 2, y: cursorY, width, height });
    cursorY += height + FLOW_GAP;
  }

  const edges: FlowEdge[] = [];
  let i = 0;
  while (i < nodes.length - 1) {
    const cur = nodes[i];
    if (cur.node.type === 'decision') {
      const action = nodes[i + 1];
      const after = nodes[i + 2];
      if (cur.node.taken) {
        edges.push(solidEdge(cur, action, 'yes'));
        i += 1;
      } else {
        edges.push(...railEdges(cur, after));
        i += 2;
      }
      continue;
    }
    edges.push(solidEdge(cur, nodes[i + 1]));
    i += 1;
  }

  return {
    width: FLOW_CENTER_X + FLOW_RAIL_OFFSET + 40,
    height: cursorY - FLOW_GAP + FLOW_TOP_MARGIN,
    nodes,
    edges,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx vitest run src/app/core/playbook-flow.spec.ts`
Expected: PASS, all tests green (10 total).

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/playbook-flow.ts frontend-v4/src/app/core/playbook-flow.spec.ts
git commit -m "feat(remediation): add vertical layout math for playbook flowcharts"
```

---

### Task 3: `tf-playbook-flow` component

**Files:**
- Create: `frontend-v4/src/app/ui/playbook-flow.component.ts`

**Interfaces:**
- Consumes: `FLOW_TEMPLATES`, `resolveFlow`, `layoutFlow`, `FLOW_CENTER_X` from `../core/playbook-flow`; `playbookProgress`, `groundingFooter` from `../core/playbook` (reused unchanged, same as `playbook-panel.component.ts` already does); `ApiService.tickPlaybookStep`/`untickPlaybookStep` from `../core/api.service`; `Playbook` from `../core/models`; `PanelComponent` from `./panel.component`.
- Produces: `PlaybookFlowComponent` — selector `tf-playbook-flow`, inputs `[playbook]: Playbook | null`, `[itemId]: number`, `[category]: string`, output `(toggled): EventEmitter<{ key: string; done: boolean }>`. Same input/output contract as `PlaybookPanelComponent` plus one new required input (`category`, to pick the template) — a drop-in replacement at the call site.

No component-level spec file: `playbook-panel.component.ts` — the component this replaces for
phishing — has none either. All real logic (resolving, layout) already has full pure-function
coverage from Tasks 1–2; this component is a thin binding over it, same division the rest of the
app already draws (`core/*.ts` carries the tests, `ui/*.component.ts` stays untested glue).

- [ ] **Step 1: Write the component**

Create `frontend-v4/src/app/ui/playbook-flow.component.ts`:

```ts
import { Component, Input, Output, EventEmitter, ChangeDetectionStrategy, inject, signal, computed } from '@angular/core';
import { PanelComponent } from './panel.component';
import { ApiService } from '../core/api.service';
import { playbookProgress, groundingFooter } from '../core/playbook';
import { FLOW_TEMPLATES, resolveFlow, layoutFlow, FLOW_CENTER_X } from '../core/playbook-flow';
import type { ResolvedFlowNode } from '../core/playbook-flow';
import type { Playbook } from '../core/models';

// Branching companion to tf-playbook-panel (docs/superpowers/specs/2026-08-06-playbook-flowcharts-design.md).
// Same optimistic-tick idiom as tf-playbook-panel: a click flips the checkbox immediately, ahead
// of the server round-trip, reconciled whenever a fresh [playbook] input arrives.
@Component({
  selector: 'tf-playbook-flow',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [PanelComponent],
  template: `
    @if (playbook) {
      <tf-panel title="What to do about this" [subtitle]="subtitle()">
        <div class="scroll">
          <svg [attr.viewBox]="'0 0 ' + layout().width + ' ' + layout().height" [attr.width]="layout().width" [attr.height]="layout().height" role="img" [attr.aria-label]="ariaLabel()">
            <defs>
              <marker id="flow-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="var(--ink-2)" />
              </marker>
            </defs>

            @for (e of layout().edges; track e.key) {
              <line
                class="edge" [class.dashed]="e.dashed"
                [attr.x1]="e.x1" [attr.y1]="e.y1" [attr.x2]="e.x2" [attr.y2]="e.y2" marker-end="url(#flow-arrow)"
              />
              @if (e.label) {
                <text class="edge-label" [attr.x]="e.x2 + 6" [attr.y]="e.y1 - 4">{{ e.label }}</text>
              }
            }

            @for (p of layout().nodes; track p.node.key) {
              @switch (p.node.type) {
                @case ('start') {
                  <g [attr.transform]="'translate(' + p.x + ',' + p.y + ')'">
                    <rect width="160" height="30" rx="15" class="pill" />
                    <text x="80" y="19" class="pill-label">{{ p.node.label }}</text>
                  </g>
                }
                @case ('end') {
                  <g [attr.transform]="'translate(' + p.x + ',' + p.y + ')'">
                    <rect width="160" height="30" rx="15" class="pill" />
                    <text x="80" y="19" class="pill-label">{{ p.node.label }}</text>
                  </g>
                }
                @case ('decision') {
                  <g [attr.transform]="'translate(' + p.x + ',' + p.y + ')'">
                    <polygon [attr.points]="diamondPoints(p.width, p.height)" class="diamond" />
                    <foreignObject width="140" height="92">
                      <p class="diamond-label" xmlns="http://www.w3.org/1999/xhtml">{{ p.node.question }}</p>
                    </foreignObject>
                  </g>
                }
                @case ('action') {
                  <g [attr.transform]="'translate(' + p.x + ',' + p.y + ')'" [class.skipped]="!p.node.resolved">
                    <rect width="220" height="48" rx="7" class="box" [class.taken]="p.node.resolved" />
                    @if (p.node.resolved) {
                      <foreignObject x="8" y="8" width="204" height="32">
                        <label class="check-row" xmlns="http://www.w3.org/1999/xhtml">
                          <input type="checkbox" [checked]="p.node.done" (change)="toggle(p.node.key)" />
                          <span class="title">{{ titleFor(p.node.key) }}</span>
                        </label>
                      </foreignObject>
                    } @else {
                      <foreignObject x="8" y="8" width="204" height="32">
                        <p class="skipped-label" xmlns="http://www.w3.org/1999/xhtml">{{ titleFor(p.node.key) }}</p>
                      </foreignObject>
                    }
                  </g>
                }
              }
            }
          </svg>
        </div>
        @if (footer().groundedIn.length || footer().missing.length) {
          <p class="footer">
            @if (footer().groundedIn.length) { Grounded in: {{ footer().groundedIn.join(' · ') }} }
            @if (footer().missing.length) { <span class="missing">Not available: {{ footer().missing.join(', ') }}</span> }
          </p>
        }
      </tf-panel>
    }
  `,
  styles: [`
    .scroll { overflow-x: auto; }
    svg { display: block; margin: 0 auto; }
    .pill { fill: var(--surface-2); stroke: var(--accent); stroke-width: 1.5; }
    .pill-label { font-size: 10.5px; fill: var(--ink); text-anchor: middle; dominant-baseline: middle; }
    .diamond { fill: var(--accent); }
    .diamond-label {
      margin: 0; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center;
      text-align: center; font-size: 9px; font-weight: 700; color: var(--bg); line-height: 1.25; padding: 0 10px;
    }
    .box { fill: var(--surface-2); stroke: var(--hairline); stroke-width: 1.5; }
    .box.taken { stroke: var(--accent); }
    .skipped .box { stroke-dasharray: 4 3; opacity: .55; }
    .skipped-label { margin: 0; font-size: 10px; color: var(--ink-2); text-align: center; line-height: 1.3; }
    .edge { stroke: var(--ink-2); stroke-width: 1.5; }
    .edge.dashed { stroke-dasharray: 4 3; opacity: .7; }
    .edge-label { font-size: 9px; fill: var(--ink-2); }
    .check-row { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 10px; color: var(--ink); }
    .check-row input { width: 14px; height: 14px; accent-color: var(--accent); cursor: pointer; }
    .title { line-height: 1.3; }
    .footer { margin: 10px 16px 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .missing { margin-left: 10px; }
    @media (prefers-reduced-motion: reduce) { * { animation: none !important; } }
  `],
})
export class PlaybookFlowComponent {
  private api = inject(ApiService);

  @Input() itemId!: number;
  @Input() category!: string;

  @Output() toggled = new EventEmitter<{ key: string; done: boolean }>();

  private _playbook = signal<Playbook | null>(null);
  @Input() set playbook(value: Playbook | null | undefined) {
    this._playbook.set(value ?? null);
  }
  get playbook(): Playbook | null {
    return this._playbook();
  }

  // Same optimistic-tick pattern as tf-playbook-panel: layered over the server's done[], added on
  // POST before the response returns, removed on DELETE before the response returns.
  private optimistic = signal<{ added: Set<string>; removed: Set<string> }>({ added: new Set(), removed: new Set() });

  private effectivePlaybook = computed<Playbook | null>(() => {
    const pb = this._playbook();
    if (!pb) return null;
    const opt = this.optimistic();
    const done = new Set(pb.done);
    for (const k of opt.added) done.add(k);
    for (const k of opt.removed) done.delete(k);
    return { ...pb, done: [...done] };
  });

  private resolved = computed<ResolvedFlowNode[]>(() => {
    const template = FLOW_TEMPLATES[this.category] ?? [];
    return resolveFlow(template, this.effectivePlaybook());
  });

  layout = computed(() => layoutFlow(this.resolved()));
  progress = computed(() => playbookProgress(this.effectivePlaybook()));
  footer = computed(() => groundingFooter(this._playbook()));

  centerX = FLOW_CENTER_X;

  diamondPoints(width: number, height: number): string {
    const hw = width / 2;
    const hh = height / 2;
    return `${hw},0 ${width},${hh} ${hw},${height} 0,${hh}`;
  }

  titleFor(key: string): string {
    return this._playbook()?.steps.find((s) => s.key === key)?.title ?? '';
  }

  ariaLabel(): string {
    const template = FLOW_TEMPLATES[this.category] ?? [];
    return template.map((n) => ('label' in n ? n.label : 'question' in n ? n.question : n.key)).join(' then ');
  }

  subtitle(): string {
    const { done, total } = this.progress();
    return `${done} of ${total} done`;
  }

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
}
```

- [ ] **Step 2: Typecheck**

Run: `cd frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npx tsc -p tsconfig.spec.json --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add frontend-v4/src/app/ui/playbook-flow.component.ts
git commit -m "feat(remediation): add tf-playbook-flow component"
```

---

### Task 4: Wire into the guided page

**Files:**
- Modify: `frontend-v4/src/app/pages/remediate/remediation-guided.component.ts`

**Interfaces:**
- Consumes: `hasFlow` from `../../core/playbook-flow`, `PlaybookFlowComponent` from `../../ui/playbook-flow.component` (both from Tasks 1 and 3).

- [ ] **Step 1: Add the imports**

In `frontend-v4/src/app/pages/remediate/remediation-guided.component.ts`, add to the import block
(near the existing `PlaybookPanelComponent` import, around line 9):

```ts
import { PlaybookFlowComponent } from '../../ui/playbook-flow.component';
import { hasFlow } from '../../core/playbook-flow';
```

- [ ] **Step 2: Register the component**

In the `@Component` decorator's `imports: [...]` array (line 25), add `PlaybookFlowComponent`
next to `PlaybookPanelComponent`:

```ts
imports: [RouterLink, PanelComponent, ReachDiagramComponent, PlaybookPanelComponent, PlaybookFlowComponent, EmptyStateComponent, SkeletonComponent],
```

- [ ] **Step 3: Swap the template block**

Replace the existing playbook block (lines 113–115):

```html
      @if (d.playbook) {
        <tf-playbook-panel [playbook]="d.playbook" [itemId]="d.item.id" (toggled)="onStepToggled($event)" />
      }
```

with:

```html
      @if (hasFlow(d.item.category)) {
        <tf-playbook-flow [playbook]="d.playbook" [itemId]="d.item.id" [category]="d.item.category" (toggled)="onStepToggled($event)" />
      } @else if (d.playbook) {
        <tf-playbook-panel [playbook]="d.playbook" [itemId]="d.item.id" (toggled)="onStepToggled($event)" />
      }
```

- [ ] **Step 4: Expose `hasFlow` to the template**

In the `RemediationGuidedComponent` class body, next to the existing bound helpers
(`isPastDue = isPastDue;` / `formatDueDate = formatDueDate;`, around line 341-342), add:

```ts
  hasFlow = hasFlow;
```

- [ ] **Step 5: Typecheck and run the full frontend test suite**

Run: `cd frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npm test`
Expected: typecheck passes, all vitest suites pass (including the new `playbook-flow.spec.ts` and
the untouched `playbook.spec.ts`).

- [ ] **Step 6: Commit**

```bash
git add frontend-v4/src/app/pages/remediate/remediation-guided.component.ts
git commit -m "feat(remediation): show the flowchart for phishing items on the guided page"
```

---

### Task 5: Manual verification

**Files:** none (verification only).

- [ ] **Step 1: Start the backend**

Run: `/home/sah/.nvm/versions/node/v22.23.1/bin/node server/index.js` (from the repo root, in its
own terminal/background — check nothing else is already bound to port 4173 first).

- [ ] **Step 2: Start the frontend**

Run: `cd frontend-v4 && /home/sah/.nvm/versions/node/v22.23.1/bin/npm start`

- [ ] **Step 3: Find a phishing item with an active profile**

Query the dev database for a phishing-category item that has a playbook (any tier that attaches
one) and a profile-visible id:

```bash
docker exec -e PGPASSWORD=postgres threatflow-pg16 psql -U postgres -d threatflow -X -c \
  "SELECT id, title FROM items WHERE category = 'phishing' ORDER BY published_at DESC NULLS LAST LIMIT 5;"
```

- [ ] **Step 4: Load the guided page in the browser and confirm**

Navigate to `http://localhost:4400/remediate/<id>` for one of the ids from Step 3, with an active
profile selected. Confirm:
- The flowchart renders (start pill, decision diamonds, action boxes, end pill) instead of the
  flat checklist.
- Boxes for steps this item actually has (visible in the old checklist form, cross-check via
  `GET /api/items/:id/remediation`) are solid with a working checkbox; ticking one persists after
  a reload.
- Any decision this item's data resolves "no" for shows its rail (dashed line bypassing a muted,
  checkbox-less box) rather than a crash or a blank gap.
- The "Grounded in: ..." footer still appears when indicators/mitigations back the item.

- [ ] **Step 5: Confirm every other category is unaffected**

Load the guided page for a `malware`, `ransomware`, `data-breach`, `ioc`, and `cve` item (query
similarly to Step 3 with a different `category` filter) and confirm each still renders the
original flat checklist, unchanged.

- [ ] **Step 6: Report results**

No commit — this task is verification only. If any check in Steps 4–5 fails, stop and fix the
relevant earlier task before proceeding.
