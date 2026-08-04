import type { Playbook, PlaybookStep } from './models';

// Presentation over the server's `{ steps, done }` payload. `groundedIn`/`missing` are derived
// here rather than stored server-side — the same split the codebase already uses for
// consequence (server owns facts, core/relevance.ts owns presentation), and it means the footer
// can never drift from the steps actually rendered.

export function playbookProgress(playbook: Playbook | null | undefined): { done: number; total: number } {
  if (!playbook) return { done: 0, total: 0 };
  const keys = new Set(playbook.steps.map((s) => s.key));
  const done = playbook.done.filter((k) => keys.has(k)).length;
  return { done, total: playbook.steps.length };
}

export interface PlaybookStepBlock extends PlaybookStep {
  done: boolean;
}

// Built here, not in the template, so the whole spec of "which steps render as ticked" is
// testable without a DOM — this app runs vitest in a node environment with no TestBed by design.
export function stepBlocks(playbook: Playbook | null | undefined): PlaybookStepBlock[] {
  if (!playbook) return [];
  const done = new Set(playbook.done);
  return playbook.steps.map((s) => ({ ...s, done: done.has(s.key) }));
}

// Which sources actually contributed a step, and which expected one is absent — read off the
// step keys themselves rather than re-deriving from raw CVE facts the client never receives.
export function groundingFooter(playbook: Playbook | null | undefined): { groundedIn: string[]; missing: string[] } {
  if (!playbook) return { groundedIn: [], missing: [] };
  const keys = new Set(playbook.steps.map((s) => s.key));
  const groundedIn: string[] = [];
  const missing: string[] = [];

  if (keys.has('ransomware')) groundedIn.push('CISA KEV');

  if (keys.has('patch')) groundedIn.push('NVD Patch reference');
  else if (keys.has('vendor')) groundedIn.push('NVD Vendor Advisory');
  else if (keys.has('watch-vendor')) missing.push('vendor patch link');

  if (keys.has('restrict') || keys.has('rotate')) groundedIn.push('CVSS vector');

  return { groundedIn, missing };
}
