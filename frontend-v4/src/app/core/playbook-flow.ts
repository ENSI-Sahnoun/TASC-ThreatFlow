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
