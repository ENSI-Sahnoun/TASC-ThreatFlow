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

// ---- vertical layout math ----

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
