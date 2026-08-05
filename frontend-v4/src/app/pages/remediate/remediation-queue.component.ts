import { Component, ChangeDetectionStrategy, inject, signal, computed, effect } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { PanelComponent } from '../../ui/panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { severityToken } from '../../core/format';
import {
  queueSummary, groupProgress, groupHasPastDue, oneUpgradeCloses, closesWording, formatDueDate,
  groupActions, sortActions, splitActionsByStatus, NOT_COVERED_SECTION_CAVEAT,
  fixWording, actionSubtitle, filterQueueItems, actionProvenance, buildTicketText,
} from '../../core/remediation';
import type { RemediationAction, RiskReachMode } from '../../core/remediation';
import type { RemediationQueueGroup, RemediationQueueItem } from '../../core/models';
import { CopyButtonComponent } from '../../ui/copy-button.component';

// One rendered section of an asset's actions. Before a version is known there's exactly one,
// unlabeled section (Part 2's "no section chrome" rule) — labeled sections only appear once
// splitActionsByStatus has something to say. Always an array so the template has one loop
// instead of a labeled-vs-flat fork.
interface ActionSectionView {
  label: string | null;
  caveat: string | null;
  actions: RemediationAction[];
}

const CVE_PAGE_SIZE = 8;

// The routed "/remediate" page. Grouping and within-group sort by score are Spec A's own SQL
// (server/index.js) — everything from here down is the triage redesign: threats collapse into
// fix-based action rows (Part 1), ranked by worst CVSS with KEV overriding score (Part 3), split
// three ways once a version is known (Part 2). All of it is pure functions from
// core/remediation.ts; this component stays a thin binding over them.
@Component({
  selector: 'tf-page-remediate',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, PanelComponent, EmptyStateComponent, SkeletonComponent, CopyButtonComponent],
  template: `
    <tf-panel title="Remediation">
      @if (loading()) {
        <tf-skeleton [rows]="4" />
      } @else if (error()) {
        <div class="err">
          <p class="t">Couldn't load the remediation queue</p>
          <button type="button" (click)="load()">Retry</button>
        </div>
      } @else if (noAssets()) {
        <tf-empty-state
          title="Tell us what you run"
          reason="Add assets to your profile and this page fills itself in"
        />
        <a class="cta" routerLink="/onboarding">Go to profile setup &rarr;</a>
      } @else if (groups().length === 0) {
        <tf-empty-state
          title="Nothing open"
          reason="Nothing open against the software you've told us about"
        />
      } @else {
        <div class="stats">
          <div class="stat-block">
            <span class="stat-num tabular-nums">{{ summary().open }}</span>
            <span class="stat-label">open</span>
          </div>
          <div class="stat-block" [class.hot]="summary().pastDue > 0">
            <span class="stat-num tabular-nums">{{ summary().pastDue }}</span>
            <span class="stat-label">past due</span>
          </div>
          <div class="stat-block">
            <span class="stat-num tabular-nums">{{ totalActions() }}</span>
            <span class="stat-label">actions</span>
          </div>
        </div>

        <div class="controls">
          <input
            type="text" class="filter" placeholder="Filter by CVE id or version&hellip;"
            [value]="filterQuery()" (input)="onFilterInput($event)"
          />
          <div class="sort-group" role="group" aria-label="Sort order">
            <button type="button" class="sort-btn" [class.active]="sortMode() === 'risk'" (click)="setSort('risk')">risk</button>
            <button type="button" class="sort-btn" [class.active]="sortMode() === 'reach'" (click)="setSort('reach')">reach</button>
          </div>
        </div>

        <ul class="groups">
          @for (g of groups(); track g.vendor + '/' + g.product) {
            <li class="group">
              <div class="group-head">
                <span class="name">{{ g.vendor }} {{ g.product }}</span>
                @if (progressOf(g); as p) {
                  <span class="bar" role="progressbar" [attr.aria-valuenow]="p.done" [attr.aria-valuemax]="p.total">
                    <span class="fill" [style.width.%]="p.total ? (p.done / p.total) * 100 : 0"></span>
                  </span>
                  <span class="count">{{ p.done }} of {{ p.total }}</span>
                } @else {
                  <a class="tell-us" [routerLink]="['/remediate', g.items[0].itemId]">tell us &rarr;</a>
                }
                @if (hasPastDue(g)) { <span class="past-due">past due</span> }
              </div>
              @if (g.version) { <p class="running">you run {{ g.version }}</p> }
              @if (closesLine(g); as line) { <p class="closes">&#9656; {{ line }}</p> }

              @for (section of sectionsFor(g); track section.label ?? '') {
                <div class="section">
                  @if (section.label) {
                    <div class="section-head-row">
                      <p class="section-head">{{ section.label }}</p>
                      <span class="section-count tabular-nums">{{ section.actions.length }} action{{ section.actions.length === 1 ? '' : 's' }}</span>
                    </div>
                    @if (section.caveat) { <p class="section-caveat">{{ section.caveat }}</p> }
                  }
                  <ul class="actions">
                    @for (a of section.actions; track a.key) {
                      <li class="action" [class.open]="isOpen(a.key)">
                        <button
                          type="button" class="action-head"
                          [attr.aria-expanded]="isOpen(a.key)"
                          (click)="toggle(a.key)"
                        >
                          <svg class="chevron" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
                            <path d="M2 1 L7 5 L2 9" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
                          </svg>
                          <span class="action-title">
                            <span class="headline-row">
                              <span class="headline">{{ fixHeadline(a) }}</span>
                              @if (a.kev; as kev) {
                                <span class="kev-badge">
                                  KEV
                                  @if (kev.pastDueCount > 0) { &middot; {{ kev.pastDueCount }} past due }
                                  @if (kev.ransomware) { &middot; ransomware }
                                </span>
                              }
                            </span>
                            <span class="subtitle">{{ subtitleOf(a) }}</span>
                          </span>
                          <span class="dist" [attr.aria-hidden]="true">
                            @for (band of severityBands; track band) {
                              @if (a.severityCounts[band] > 0) {
                                <span class="seg" [style.flexGrow]="a.severityCounts[band]" [style.background]="bandColor(band)"></span>
                              }
                            }
                          </span>
                          @if (a.worstScore != null) {
                            <span class="stat">
                              <span class="stat-num tabular-nums" [style.color]="stripeColor(a)">{{ a.worstScore }}</span>
                              <span class="stat-label">worst</span>
                            </span>
                          }
                          <span class="stat">
                            <span class="stat-num tabular-nums">{{ a.count }}</span>
                            <span class="stat-label">closes</span>
                          </span>
                        </button>

                        @if (isOpen(a.key)) {
                          <div class="action-body">
                            <p class="lede">{{ ledeOf(a) }}</p>
                            <details class="why-disclosure">
                              <summary>why this action?</summary>
                              <dl class="prov">
                                @for (line of provenanceOf(a, g); track line.label) {
                                  <div><dt>{{ line.label }}</dt><dd>{{ line.text }}</dd></div>
                                }
                              </dl>
                            </details>
                            <tf-copy-button [value]="ticketTextOf(a, g)" label="Copy as ticket" />
                            <ul class="cves">
                              @for (item of visibleCves(a); track item.itemId) {
                                <li>
                                  <a [routerLink]="['/remediate', item.itemId]">{{ item.cveId || item.title }}</a>
                                  <span class="status" [class]="'status-' + item.status">{{ statusLabel(item.status) }}</span>
                                  @if (item.dueDate) { <span class="due">fix by {{ formatDueDate(item.dueDate) }}</span> }
                                </li>
                              }
                            </ul>
                            @if (a.items.length > CVE_PAGE_SIZE && !isExpandedCves(a.key)) {
                              <button type="button" class="more-cves" (click)="showAllCves(a.key)">
                                &hellip; {{ a.items.length - CVE_PAGE_SIZE }} more
                              </button>
                            }
                          </div>
                        }
                      </li>
                    }
                  </ul>
                </div>
              }
            </li>
          }
        </ul>
      }
    </tf-panel>
  `,
  styles: [`
    .stats { display: flex; align-items: baseline; gap: 22px; margin-bottom: 16px; }
    .stat-block { display: flex; flex-direction: column; gap: 1px; }
    .stat-block .stat-num { font-size: var(--fs-xl); font-weight: 650; color: var(--ink); line-height: 1.1; }
    .stat-block.hot .stat-num { color: var(--sev-critical); }
    .stat-block .stat-label { font-size: 10px; font-weight: 600; color: var(--ink-2); text-transform: uppercase; letter-spacing: .04em; }

    .groups { list-style: none; margin: 0; padding: 0; display: grid; gap: 20px; }
    .group { border-top: var(--hair) solid var(--hairline); padding-top: 14px; }
    .group:first-child { border-top: none; padding-top: 0; }
    .group-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .name { font-weight: 600; color: var(--ink); }
    .bar {
      display: inline-block; width: 90px; height: 6px; border-radius: 3px;
      background: var(--surface-3); overflow: hidden;
    }
    .fill { display: block; height: 100%; background: var(--accent); transition: width var(--dur-slow) var(--ease-out); }
    @media (prefers-reduced-motion: reduce) { .fill { transition: none; } }
    .count { font-size: var(--fs-xs); color: var(--ink-2); }
    .tell-us { font-size: var(--fs-xs); color: var(--accent); text-decoration: none; }
    .tell-us:hover { text-decoration: underline; }
    .past-due { margin-left: auto; font-size: var(--fs-xs); font-weight: 600; color: var(--sev-critical); }
    .running { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .closes { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink); }

    .tabular-nums { font-variant-numeric: tabular-nums; }

    .section + .section { margin-top: 18px; }
    .section-head-row { display: flex; align-items: baseline; gap: 8px; margin: 0 0 2px; }
    .section-head { margin: 0; font-size: var(--fs-xs); font-weight: 650; color: var(--ink-2); text-transform: uppercase; letter-spacing: .04em; }
    .section-count { margin-left: auto; font-size: var(--fs-xs); color: var(--ink-3); }
    .section-caveat { margin: 2px 0 10px; font-size: var(--fs-xs); color: var(--ink-2); font-style: italic; }
    .actions { list-style: none; margin: 8px 0 0; padding: 0; display: grid; gap: 2px; }
    .section-head-row + .actions, .section-caveat + .actions { margin-top: 0; }

    .action { border-radius: 10px; }
    .action.open { background: var(--surface-2); box-shadow: inset 0 0 0 1px var(--hairline); margin: 4px 0; }

    .action-head {
      appearance: none; width: 100%; display: grid; align-items: center;
      grid-template-columns: 16px minmax(0, 1fr) 64px auto auto; gap: 14px;
      padding: 11px 10px; border: 0; border-radius: 10px; background: transparent; color: inherit;
      font: inherit; text-align: left; cursor: pointer;
      transition: background var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    .action-head:hover { background: var(--surface-2); }
    .action.open .action-head:hover { background: transparent; }
    .action-head:active { transform: scale(.997); }
    .action-head:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }

    .chevron { flex: none; color: var(--ink-3); transition: transform var(--dur-fast) var(--ease-out); }
    .action-head[aria-expanded="true"] .chevron { transform: rotate(90deg); color: var(--ink-2); }
    @media (prefers-reduced-motion: reduce) { .chevron { transition: none; } }

    .action-title { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
    .headline-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .headline { color: var(--ink); font-size: var(--fs-sm); font-weight: 560; }
    .subtitle { font-size: var(--fs-xs); color: var(--ink-3); }
    .kev-badge {
      font-size: 10px; font-weight: 700; color: var(--bg); line-height: 1;
      background: var(--sev-critical); padding: 3px 7px; border-radius: 999px; white-space: nowrap;
    }

    .dist { display: flex; width: 64px; height: 5px; border-radius: 3px; overflow: hidden; background: var(--surface-3); flex: none; }
    .seg { display: block; }

    .stat { display: flex; flex-direction: column; align-items: flex-end; gap: 0; min-width: 34px; }
    .stat .stat-num { font-size: var(--fs-md); font-weight: 650; color: var(--ink); line-height: 1.15; }
    .stat .stat-label { font-size: 9px; font-weight: 600; color: var(--ink-3); text-transform: uppercase; letter-spacing: .03em; }

    .action-body { padding: 2px 10px 14px 40px; display: grid; gap: 10px; }
    .lede { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }
    .lede strong { color: var(--ink); font-weight: 600; }
    .why-disclosure summary { cursor: pointer; font-size: var(--fs-xs); color: var(--ink-2); width: fit-content; }
    .why-disclosure summary:hover { color: var(--ink); }
    .why-disclosure { width: fit-content; }
    .prov { margin: 6px 0 0; display: grid; gap: 4px; }
    .prov div { display: flex; gap: 8px; font-size: var(--fs-xs); }
    .prov dt { color: var(--ink-2); min-width: 90px; }
    .prov dd { margin: 0; color: var(--ink); }

    .cves { list-style: none; margin: 0; padding: 0; display: grid; gap: 5px; }
    .cves li { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; font-family: ui-monospace, monospace; font-size: var(--fs-xs); }
    .cves a { color: var(--ink); text-decoration: none; border-bottom: 1px solid transparent; }
    .cves a:hover { color: var(--accent); border-bottom-color: currentColor; }
    .status { font-family: inherit; color: var(--ink-2); }
    .status-not_covered { color: var(--sev-none); }
    .due { margin-left: auto; color: var(--ink-2); }
    .more-cves {
      appearance: none; justify-self: start; cursor: pointer; font: inherit; font-size: var(--fs-xs);
      color: var(--accent); background: none; border: 0; padding: 2px 0;
    }
    .more-cves:hover { text-decoration: underline; }

    .controls { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
    .filter {
      flex: 1; min-width: 0; font: inherit; font-size: var(--fs-sm); background: var(--surface-2);
      border: var(--hair) solid var(--hairline); border-radius: 8px; padding: 7px 11px; color: var(--ink);
      transition: border-color var(--dur-fast) var(--ease-out);
    }
    .filter:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .sort-group { display: flex; background: var(--surface-2); border-radius: 8px; padding: 2px; gap: 2px; }
    .sort-btn {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink-2); background: transparent; border: 0; padding: 5px 12px; border-radius: 6px;
      transition: background var(--dur-fast) var(--ease-out), color var(--dur-fast) var(--ease-out);
    }
    .sort-btn.active { background: var(--accent-soft); color: var(--accent); }
    .sort-btn:hover:not(.active) { color: var(--ink); }
    .sort-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

    .cta { display: inline-block; margin-top: 8px; font-size: var(--fs-sm); color: var(--accent); text-decoration: none; }
    .cta:hover { text-decoration: underline; }
    .err { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 24px; text-align: center; }
    .err button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0; padding: 6px 14px; border-radius: 8px;
    }
  `],
})
export class RemediationQueueComponent {
  private api = inject(ApiService);
  private profileService = inject(ProfileService);

  groups = signal<RemediationQueueGroup[]>([]);
  loading = signal(true);
  error = signal(false);

  noAssets = computed(() => (this.profileService.active()?.assets.length ?? 0) === 0);
  summary = computed(() => queueSummary(this.groups()));

  formatDueDate = formatDueDate;
  severityBands = ['critical', 'high', 'medium', 'low', 'none', 'unknown'] as const;
  CVE_PAGE_SIZE = CVE_PAGE_SIZE;

  filterQuery = signal('');
  sortMode = signal<RiskReachMode>('risk');

  // Which action rows are expanded, and which expanded rows have had their CVE list fully
  // revealed past the first page — both keyed by RemediationAction.key, both reset to closed
  // whenever the queue reloads (a stale key from a prior response would just miss every match).
  private openKeys = signal<Set<string>>(new Set());
  private expandedCveKeys = signal<Set<string>>(new Set());

  constructor() {
    effect(() => {
      this.profileService.dataVersion();
      const profile = this.profileService.active();
      if (!profile) return;
      this.load();
    });
  }

  load(): void {
    const profile = this.profileService.active();
    if (!profile) return;
    this.loading.set(true);
    this.error.set(false);
    this.openKeys.set(new Set());
    this.expandedCveKeys.set(new Set());
    this.api.remediationQueue(profile.id).subscribe({
      next: (rows) => { this.groups.set(rows); this.loading.set(false); },
      error: () => { this.error.set(true); this.loading.set(false); },
    });
  }

  progressOf(g: RemediationQueueGroup) {
    return groupProgress(g);
  }

  hasPastDue(g: RemediationQueueGroup): boolean {
    return groupHasPastDue(g.items);
  }

  closesLine(g: RemediationQueueGroup): string | null {
    return closesWording(oneUpgradeCloses(g.items));
  }

  onFilterInput(ev: Event): void {
    this.filterQuery.set((ev.target as HTMLInputElement).value);
  }

  setSort(mode: RiskReachMode): void {
    this.sortMode.set(mode);
  }

  isOpen(key: string): boolean {
    return this.openKeys().has(key);
  }

  toggle(key: string): void {
    const next = new Set(this.openKeys());
    if (next.has(key)) next.delete(key); else next.add(key);
    this.openKeys.set(next);
  }

  isExpandedCves(key: string): boolean {
    return this.expandedCveKeys().has(key);
  }

  showAllCves(key: string): void {
    const next = new Set(this.expandedCveKeys());
    next.add(key);
    this.expandedCveKeys.set(next);
  }

  visibleCves(a: RemediationAction): RemediationQueueItem[] {
    return this.isExpandedCves(a.key) ? a.items : a.items.slice(0, CVE_PAGE_SIZE);
  }

  // Part 3's default: risk order (worst CVSS descending, count breaking ties, KEV first
  // regardless); Part 4's toggle switches to reach. Part 4's filter narrows the ITEMS first, so
  // a filtered-out threat never survives inside a surviving action's disclosure — actions are
  // re-derived from the filtered set, not filtered themselves after the fact.
  actionsOf(g: RemediationQueueGroup): RemediationAction[] {
    const filtered = filterQueueItems(g.items, this.filterQuery());
    return sortActions(groupActions(filtered), this.sortMode());
  }

  totalActions(): number {
    return this.groups().reduce((n, g) => n + this.actionsOf(g).length, 0);
  }

  // Part 2: before a version is known there's one unlabeled section and no chrome; once known,
  // splitActionsByStatus's three named sections replace it, empty ones dropped.
  sectionsFor(g: RemediationQueueGroup): ActionSectionView[] {
    const actions = this.actionsOf(g);
    if (g.versionState !== 'known') return [{ label: null, caveat: null, actions }];
    const s = splitActionsByStatus(actions);
    const views: ActionSectionView[] = [];
    if (s.affected.length) views.push({ label: 'Still affects you', caveat: null, actions: s.affected });
    if (s.unknown.length) views.push({ label: "Can't tell from your version", caveat: null, actions: s.unknown });
    if (s.notCovered.length) views.push({ label: 'No longer in range', caveat: NOT_COVERED_SECTION_CAVEAT, actions: s.notCovered });
    return views;
  }

  provenanceOf(a: RemediationAction, g: RemediationQueueGroup) {
    return actionProvenance(a, { vendor: g.vendor, product: g.product });
  }

  ticketTextOf(a: RemediationAction, g: RemediationQueueGroup): string {
    return buildTicketText(a, { vendor: g.vendor, product: g.product });
  }

  fixHeadline(a: RemediationAction): string {
    return fixWording(a.fix).headline;
  }

  subtitleOf(a: RemediationAction): string {
    return actionSubtitle(a.fix);
  }

  // One plain-English line inside the expanded row, built from fields already on the action —
  // not a new tested function, since it's presentation glue over already-tested data and isn't
  // reused anywhere else (unlike buildTicketText, which is).
  ledeOf(a: RemediationAction): string {
    const scorePart = a.worstScore != null ? `worst of them CVSS ${a.worstScore}` : 'severity unscored';
    const critPart = `${a.severityCounts.critical} at critical`;
    return `Closes ${a.count} threat${a.count === 1 ? '' : 's'} — ${scorePart}, ${critPart}.`;
  }

  stripeColor(a: RemediationAction): string {
    return severityToken(a.worstSeverity);
  }

  bandColor(band: string): string {
    return severityToken(band);
  }

  statusLabel(status: RemediationQueueItem['status']): string {
    if (status === 'affected') return 'affected';
    if (status === 'not_covered') return 'not covered';
    return 'unknown';
  }
}
