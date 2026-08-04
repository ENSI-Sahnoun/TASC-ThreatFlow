import type { RemediationFix, RemediationQueueGroup, RemediationQueueItem } from './models';

// Presentation and derived math over Spec A's remediation routes. Pure, no HTTP, no DOM — this
// app runs vitest in a node environment with no TestBed by design, so every rule the remediation
// pages need is specified and tested here; the components stay thin bindings over it.

// ---- due dates ----

export function isPastDue(dueDate: string | null, now: Date = new Date()): boolean {
  if (!dueDate) return false;
  const d = new Date(dueDate);
  if (Number.isNaN(d.getTime())) return false;
  return d.getTime() < now.getTime();
}

// Same formatting relevance.ts's tierSubline() and playbook-panel.component.ts's local
// formatDue() already use — kept as its own small copy here rather than a shared import, per
// this app's existing precedent of each call site owning its own one-liner.
export function formatDueDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
}

// A group is past due when at least one of its still-open items (not already not_covered) has
// slipped its due date. A cleared item's old due date is not a live commitment any more.
export function groupHasPastDue(items: RemediationQueueItem[], now: Date = new Date()): boolean {
  return items.some((i) => i.status !== 'not_covered' && isPastDue(i.dueDate, now));
}

// ---- header summary ----

export interface QueueSummary {
  open: number;
  pastDue: number;
}

// "Open" excludes not_covered: a range that no longer covers the reader's build is resolved for
// this asset, not a live threat, even though the row still renders (Spec A's tier scoring does
// not factor in version status — see CLAUDE.md's relevance_score.js note — so the item stays in
// the query result; this is where "open" is actually decided for the UI).
export function queueSummary(groups: RemediationQueueGroup[], now: Date = new Date()): QueueSummary {
  let open = 0;
  let pastDue = 0;
  for (const g of groups) {
    for (const item of g.items) {
      if (item.status === 'not_covered') continue;
      open += 1;
      if (isPastDue(item.dueDate, now)) pastDue += 1;
    }
  }
  return { open, pastDue };
}

// ---- per-asset progress ----

export interface GroupProgress {
  done: number;
  total: number;
}

// null when progress is not measurable at all (version never asked, or asked and declined) —
// the spec's own rule: an asset with version_state 'unset' shows a "tell us" affordance instead
// of a bar, and 'unknown' shows the threats without a bar and does not re-ask. Only 'known'
// produces a real fraction: how many of the items currently matched to this asset already read
// not_covered (i.e. the version on file is already past their range) out of every item matched.
export function groupProgress(group: RemediationQueueGroup): GroupProgress | null {
  if (group.versionState !== 'known') return null;
  const total = group.items.length;
  const done = group.items.filter((i) => i.status === 'not_covered').length;
  return { done, total };
}

// ---- "one upgrade closes N" ----

export interface UpgradeCloses {
  value: string;
  count: number;
}

// Fires only when two or more items in the SAME asset group share the same kind: 'version' fix
// target — never for patch/advisory/none, because two patch URLs are not one action, and a
// single vendor advisory page is not "one upgrade" either. When more than one version value
// would qualify, the larger group wins (the more consequential single action to surface).
export function oneUpgradeCloses(items: RemediationQueueItem[]): UpgradeCloses | null {
  const counts = new Map<string, number>();
  for (const item of items) {
    if (item.fix.kind !== 'version') continue;
    counts.set(item.fix.value, (counts.get(item.fix.value) ?? 0) + 1);
  }
  let best: UpgradeCloses | null = null;
  for (const [value, count] of counts) {
    if (count >= 2 && (!best || count > best.count)) best = { value, count };
  }
  return best;
}
