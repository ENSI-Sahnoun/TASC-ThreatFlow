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

// ---- Step 1 diagram: origin -> gate -> outcome ----
//
// Mirrors server/cvss.js's parseVector() metric extraction (client-side, since the guided page
// only ever receives the raw vector string, never pre-parsed metrics) — kept intentionally
// minimal: this extracts the metric map only, it does not score anything.
export function parseVectorMetrics(vector: string | null | undefined): Record<string, string> | null {
  if (typeof vector !== 'string') return null;
  const s = vector.trim();
  const m = s.match(/^CVSS:(\d\.\d)\/(.+)$/i);
  if (!m) return null;
  const metrics: Record<string, string> = {};
  for (const part of m[2].split('/')) {
    const [k, v] = part.split(':');
    if (k && v) metrics[k.toUpperCase()] = v.toUpperCase();
  }
  return metrics;
}

export interface DiagramNode {
  id: 'origin' | 'gate' | 'outcome' | 'scope';
  title: string;
  detail: string;
  from: string;
}

export interface DiagramAnnotation {
  text: string;
  from: string;
}

export interface ReachDiagram {
  // 3 nodes, or 4 when S:C adds the scope node (Part 7).
  nodes: DiagramNode[];
  edges: { from: string; to: string }[];
  gateAnnotation: DiagramAnnotation | null;
  // AC belongs on the edge between the gate and the outcome (Part 7) — a separate field from
  // gateAnnotation (which is UI-driven) rather than a second meaning for the same one, so a
  // caller can render "why" text for each edge independently.
  acAnnotation: DiagramAnnotation | null;
}

// Exact wording from the spec's own prose ("N internet, A adjacent network, L already on the
// machine, P physical access") — not the spec's own ASCII sketch, which mislabels the AV:L box
// as "already on network"; the prose is the more precise of the two and is what this follows.
const ORIGIN: Record<string, { title: string; detail: string }> = {
  N: { title: 'The internet', detail: 'Reachable without being on the network first' },
  A: { title: 'Adjacent network', detail: 'Reachable from the same network segment' },
  L: { title: 'Already on the machine', detail: 'Requires local access to the system first' },
  P: { title: 'Physical access', detail: 'Requires physically touching the device' },
};

const GATE: Record<string, { title: string; detail: string }> = {
  N: { title: 'No account needed', detail: 'No credentials are required' },
  L: { title: 'A normal account', detail: 'Any ordinary user account is enough' },
  H: { title: 'An admin account', detail: 'Requires administrative privileges' },
};

const UI_ANNOTATION: Record<string, string> = {
  N: 'needs nothing from anyone',
  R: 'needs someone to click something',
};

// Same verbs consequence.js's buildImpact() uses for C/I/A, reused so the diagram and the impact
// panel never describe the same H metric two different ways.
const OUTCOME_VERBS: Record<string, string> = { C: 'read', I: 'change', A: 'shut down' };

function joinVerbs(values: string[]): string {
  if (values.length === 1) return values[0];
  return `${values.slice(0, -1).join(', ')} and ${values[values.length - 1]}`;
}

function originNode(av: string | undefined): DiagramNode {
  const known = av ? ORIGIN[av] : undefined;
  return known
    ? { id: 'origin', title: known.title, detail: known.detail, from: `AV:${av}` }
    : { id: 'origin', title: 'Reach not stated', detail: 'The vector does not state where an attacker must be', from: `AV:${av ?? 'none'}` };
}

function gateNode(pr: string | undefined): DiagramNode {
  const known = pr ? GATE[pr] : undefined;
  return known
    ? { id: 'gate', title: known.title, detail: known.detail, from: `PR:${pr}` }
    : { id: 'gate', title: 'Privilege not stated', detail: 'The vector does not state what access is required first', from: `PR:${pr ?? 'none'}` };
}

// Renders every non-N C/I/A metric at its real level (Part 7) — H as the plain verb, L as
// "partly" plus the verb, the same distinction consequence.js's buildImpact() already draws for
// the impact panel, reused here (not duplicated wording) so the two surfaces never describe the
// same H or L metric two different ways. A metric at N is an absent slot, not a struck-through
// verb — dropped entirely, same as before.
function outcomeNode(metrics: Record<string, string>): DiagramNode {
  const parts: string[] = [];
  const from: string[] = [];
  for (const key of ['C', 'I', 'A']) {
    const value = metrics[key];
    if (value === 'H') { parts.push(OUTCOME_VERBS[key]); from.push(`${key}:H`); }
    else if (value === 'L') { parts.push(`partly ${OUTCOME_VERBS[key]}`); from.push(`${key}:L`); }
  }
  if (!parts.length) {
    return { id: 'outcome', title: 'No full-control outcome', detail: 'Nothing in this vector states what it reads, changes or shuts down', from: 'C/I/A' };
  }
  return { id: 'outcome', title: joinVerbs(parts), detail: joinVerbs(parts), from: from.join('/') };
}

// AC:L means the exploit works whenever it's tried; AC:H means the attacker needs conditions to
// line up first — the difference between a reliable exploit and an opportunistic one (Part 7).
// Never rendered anywhere in the product before this.
const AC_ANNOTATION: Record<string, string> = {
  L: 'works whenever it is tried',
  H: 'needs conditions to line up',
};

function acAnnotationFor(ac: string | undefined): DiagramAnnotation | null {
  const text = ac ? AC_ANNOTATION[ac] : undefined;
  return text ? { text, from: `AC:${ac}` } : null;
}

// S:C means the flaw escapes the component it lives in and can affect the rest of the system —
// consequence.js:buildImpact concedes a scope-changed vector "can carry effects these three
// metrics do not express" and stops there; this is where that gets a fourth node instead of
// staying unsaid (Part 7). Never rendered anywhere in the product before this.
function scopeNode(s: string | undefined): DiagramNode | null {
  if (s !== 'C') return null;
  return {
    id: 'scope',
    title: 'Reaches beyond this component',
    detail: 'A scope change means the flaw can affect more than the part of the system it lives in',
    from: `S:${s}`,
  };
}

// Renders the CVSS vector as a path: origin -> reach -> what it gets. Draws only what the vector
// already states via cvss.js's own metric letters — no attacker avatars, no blast radius, no
// simulation beyond what AV/PR/UI/C/I/A already say.
export function reachDiagram(metrics: Record<string, string> | null | undefined): ReachDiagram {
  const m = metrics ?? {};
  const origin = originNode(m['AV']);
  const gate = gateNode(m['PR']);
  const outcome = outcomeNode(m);
  const scope = scopeNode(m['S']);
  const ui = m['UI'];
  const uiText = ui ? UI_ANNOTATION[ui] : undefined;

  const nodes: DiagramNode[] = scope ? [origin, gate, outcome, scope] : [origin, gate, outcome];
  const edges = [{ from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }];
  if (scope) edges.push({ from: 'outcome', to: 'scope' });

  return {
    nodes,
    edges,
    gateAnnotation: uiText ? { text: uiText, from: `UI:${ui}` } : null,
    acAnnotation: acAnnotationFor(m['AC']),
  };
}

// ---- Step 2 wording: affectedStatus -> what the reader reads ----

export interface AffectedVerdict {
  headline: string;
  detail: string;
}

// Verbatim from the spec: the system never tells anyone they are safe. not_covered is a fact
// about one range, not a clean bill of health — server/version_compare.js's affectedStatus()
// already abstains to 'unknown' rather than guess; this is where that abstention becomes
// language, and the wording is specified here so it cannot drift.
export function affectedWording(
  status: 'affected' | 'not_covered' | 'unknown',
  installed: string | null,
  rangeText: string | null,
): AffectedVerdict {
  if (status === 'affected') {
    return { headline: 'You are affected.', detail: 'Your build is inside the range.' };
  }
  if (status === 'not_covered') {
    return {
      headline: 'This range does not cover your build.',
      detail: 'Not a clean bill of health — confirm against the vendor advisory before treating it as closed.',
    };
  }
  const compare = installed && rangeText ? `${installed} / ${rangeText}` : 'the two versions';
  return {
    headline: 'These two can\'t be ordered reliably.',
    detail: `Compare them yourself: ${compare}`,
  };
}

// ---- Step 3 wording: fixTarget -> what the reader reads ----

export interface FixWording {
  headline: string;
  detail: string;
  note: string | null;
}

// One case per fixTarget kind, no hedging between them. 'version' never carries a note — a
// vendor patch link is shown alongside a version target as a sibling field (patchUrl, Spec
// Accuracy Finding 3), rendered by the component, not by this function.
export function fixWording(fix: RemediationFix): FixWording {
  switch (fix.kind) {
    case 'version':
      return { headline: `Upgrade to ${fix.value} or later`, detail: '', note: null };
    case 'patch':
      return { headline: 'Apply the vendor’s fix', detail: 'A fix is published for this vulnerability.', note: fix.value };
    case 'advisory':
      return {
        headline: 'Read the vendor’s guidance',
        detail: 'No direct patch link is published yet, but the vendor has guidance.',
        note: fix.value,
      };
    case 'none':
      return { headline: 'No fix has been published for this yet.', detail: '', note: null };
  }
}

// ---- the "one upgrade closes N" sentence ----

export function closesWording(closes: UpgradeCloses | null): string | null {
  return closes ? `one upgrade to ${closes.value} closes ${closes.count} of these` : null;
}

// ---- Step 4: the version-recorded consequence ----

// Counts items that read something other than not_covered before a version write and read
// not_covered after it — the reader's own currently-open item is excluded, since the message is
// about OTHER threats against the same machine, per the spec's exact wording.
export function countCleared(
  before: { itemId: number; status: string }[],
  after: { itemId: number; status: string }[],
  excludeItemId: number,
): number {
  const afterById = new Map(after.map((a) => [a.itemId, a.status]));
  let n = 0;
  for (const b of before) {
    if (b.itemId === excludeItemId) continue;
    if (b.status !== 'not_covered' && afterById.get(b.itemId) === 'not_covered') n += 1;
  }
  return n;
}

// Generated from the recomputed statuses, never predicted before the write — null when nothing
// cleared, so nothing is claimed (the spec's own rule: "If the recompute clears nothing, nothing
// is claimed").
export function versionRecordedMessage(clearedCount: number): string | null {
  if (clearedCount <= 0) return null;
  const plural = clearedCount === 1 ? 'threat' : 'threats';
  const verb = clearedCount === 1 ? 'is' : 'are';
  const pronoun = clearedCount === 1 ? 'its' : 'their';
  return `Recorded. ${clearedCount} other ${plural} against this machine ${verb} no longer inside ${pronoun} affected range.`;
}

// ---- Part 1: threats collapse into fix-based action rows ----

export type SeverityBand = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown';

export interface RemediationAction {
  key: string;
  fix: RemediationFix;
  items: RemediationQueueItem[];
  count: number;
  worstScore: number | null;
  worstSeverity: string | null;
  // The worst-scoring item's OWN cvssVersion — for the numeral only, not for picking the
  // severity colour (that already comes from `worstSeverity`, itself server-derived). See the
  // triage redesign plan's Spec Accuracy Finding 1: cve_intel carries no version, so this is the
  // best available pairing, not a guaranteed-consistent one.
  worstVersion: string | null;
  severityCounts: Record<SeverityBand, number>;
  kev: { count: number; ransomware: boolean; pastDueCount: number } | null;
}

// Grouping key is the fix itself (Part 1): kind:'version' groups on fix.value (a distinct
// upgrade target is a distinct action), but patch/advisory/none each collapse to ONE group per
// asset regardless of the specific URL — two patch links are not two decisions, they're one
// ("go read the vendor's links"), and splitting patch/advisory by URL would reproduce the wall
// this whole redesign exists to remove.
function actionKey(fix: RemediationFix): string {
  return fix.kind === 'version' ? `version:${fix.value}` : fix.kind;
}

const EMPTY_SEVERITY_COUNTS: Record<SeverityBand, number> = {
  critical: 0, high: 0, medium: 0, low: 0, none: 0, unknown: 0,
};

function isSeverityBand(value: string | null): value is SeverityBand {
  return value != null && value in EMPTY_SEVERITY_COUNTS;
}

export function groupActions(items: RemediationQueueItem[], now: Date = new Date()): RemediationAction[] {
  const byKey = new Map<string, RemediationQueueItem[]>();
  for (const item of items) {
    const key = actionKey(item.fix);
    const bucket = byKey.get(key);
    if (bucket) bucket.push(item); else byKey.set(key, [item]);
  }

  const actions: RemediationAction[] = [];
  for (const [key, bucketItems] of byKey) {
    const severityCounts = { ...EMPTY_SEVERITY_COUNTS };
    let worst: RemediationQueueItem | null = null;
    let kevCount = 0;
    let kevRansomware = false;
    let kevPastDue = 0;

    for (const item of bucketItems) {
      const band = isSeverityBand(item.severity) ? item.severity : 'unknown';
      severityCounts[band] += 1;

      if (worst === null || (item.cvssScore ?? -1) > (worst.cvssScore ?? -1)) worst = item;

      if (item.kevListed) {
        kevCount += 1;
        if (item.kevRansomware) kevRansomware = true;
        if (isPastDue(item.kevDueDate, now)) kevPastDue += 1;
      }
    }

    actions.push({
      key,
      fix: bucketItems[0].fix,
      items: bucketItems,
      count: bucketItems.length,
      worstScore: worst?.cvssScore ?? null,
      worstSeverity: worst?.severity ?? null,
      worstVersion: worst?.cvssVersion ?? null,
      severityCounts,
      kev: kevCount > 0 ? { count: kevCount, ransomware: kevRansomware, pastDueCount: kevPastDue } : null,
    });
  }
  return actions;
}

// ---- Part 3 (risk ordering) + Part 4 (the risk <-> reach toggle) ----

export type RiskReachMode = 'risk' | 'reach';

// Part 3's default: worst CVSS in the bundle, descending, count breaking ties. Deliberately
// buries nothing behind volume — "No fix published" (5 threats, one CVSS 10.0) outranks "upgrade
// to 14.8.8" (111 threats, worst 9.8): the unfixable 10.0 is what a reader must not miss, and a
// count-ordered list is exactly what would bury it.
function riskCompare(a: RemediationAction, b: RemediationAction): number {
  const as = a.worstScore ?? -1;
  const bs = b.worstScore ?? -1;
  if (as !== bs) return bs - as;
  return b.count - a.count;
}

// Part 4's toggle: how many threats one action closes, descending, worst score breaking ties.
function reachCompare(a: RemediationAction, b: RemediationAction): number {
  if (a.count !== b.count) return b.count - a.count;
  return (b.worstScore ?? -1) - (a.worstScore ?? -1);
}

// KEV sorts above every non-KEV action regardless of score (Part 3) — "regardless of score"
// reads as unconditional, so this precedence holds in both risk and reach mode: an actively
// exploited action is the thing a reader must not miss no matter which axis they're currently
// sorting by. Among several KEV actions, the active mode still decides their relative order.
export function sortActions(actions: RemediationAction[], mode: RiskReachMode = 'risk'): RemediationAction[] {
  const compare = mode === 'reach' ? reachCompare : riskCompare;
  return [...actions].sort((a, b) => {
    const aKev = a.kev ? 1 : 0;
    const bKev = b.kev ? 1 : 0;
    if (aKev !== bKev) return bKev - aKev;
    return compare(a, b);
  });
}

// ---- Part 2: three sections once a version is recorded, not two ----

export type ActionStatus = 'affected' | 'unknown' | 'not_covered';

// An action can bundle several CVEs sharing one fix (Part 1) whose affectedStatus can genuinely
// differ — two ranges ending at the same fixed version don't have to share the same starting
// bound. Conservative, worst-case-wins precedence: 'affected' the moment any item still needs
// the fix, 'not_covered' only once every item in the bundle already reads that way. The same
// posture server/version_compare.js already applies everywhere: never launder a partial
// abstention into a resolved claim.
export function actionStatus(action: RemediationAction): ActionStatus {
  if (action.items.some((i) => i.status === 'affected')) return 'affected';
  if (action.items.some((i) => i.status === 'unknown')) return 'unknown';
  return 'not_covered';
}

export interface ActionSections {
  affected: RemediationAction[];
  unknown: RemediationAction[];
  notCovered: RemediationAction[];
}

// Callers only invoke this once a version is known (group.versionState === 'known') — before
// that there is one bucket and no section chrome at all, per Part 2's own rule; that gate lives
// in the component, not here, so this function's contract stays "split what you're given."
export function splitActionsByStatus(actions: RemediationAction[]): ActionSections {
  const sections: ActionSections = { affected: [], unknown: [], notCovered: [] };
  for (const a of actions) {
    const status = actionStatus(a);
    if (status === 'affected') sections.affected.push(a);
    else if (status === 'unknown') sections.unknown.push(a);
    else sections.notCovered.push(a);
  }
  return sections;
}

// Verbatim from Spec B's affectedWording(), restated once per section instead of once per row
// (Part 2) — the system never tells anyone they are safe.
export const NOT_COVERED_SECTION_CAVEAT =
  'Not a clean bill of health — confirm against the vendor advisory before treating any of these as closed.';

// ---- Part 4: the filter field ----

function includesQuery(value: string | null | undefined, query: string): boolean {
  return typeof value === 'string' && value.toLowerCase().includes(query);
}

// Matches a CVE id or a version-shaped substring (Part 4's own words) — checked against every
// version-ish value already on the item (what the reader runs, the fix target, and the matched
// range's own text) so a query like "14.8" finds an item whether it matches what's installed or
// what the range says, not just one of the two.
export function filterQueueItems(items: RemediationQueueItem[], query: string): RemediationQueueItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((item) => (
    includesQuery(item.cveId, q)
    || includesQuery(item.installed, q)
    || includesQuery(item.fix.kind === 'version' ? item.fix.value : null, q)
    || includesQuery(item.entry?.text ?? null, q)
  ));
}
