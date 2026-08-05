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
  fixWording, filterQueueItems, actionProvenance, buildTicketText,
} from '../../core/remediation';
import type { RemediationAction, RiskReachMode } from '../../core/remediation';
import type { RemediationQueueGroup, RemediationQueueItem } from '../../core/models';
import { CopyButtonComponent } from '../../ui/copy-button.component';

// One rendered section of an asset's actions once a version is known (Part 2) — 'Still affects
// you' / "Can't tell from your version" / 'No longer in range', each carrying only the actions
// that belong there. Empty sections are omitted rather than rendered blank.
interface ActionSectionView {
  label: string;
  caveat: string | null;
  actions: RemediationAction[];
}

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
        <p class="summary">{{ summary().open }} open &middot; {{ summary().pastDue }} past due</p>
        <div class="controls">
          <input
            type="text" class="filter" placeholder="Filter by CVE id or version&hellip;"
            [value]="filterQuery()" (input)="onFilterInput($event)"
          />
          <button type="button" class="sort-toggle" (click)="toggleSort()">
            sort: {{ sortMode() === 'risk' ? 'risk' : 'reach' }} &#8646;
          </button>
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

              @if (sectionsFor(g); as sections) {
                @for (section of sections; track section.label) {
                  <div class="section">
                    <p class="section-head">{{ section.label }}</p>
                    @if (section.caveat) { <p class="section-caveat">{{ section.caveat }}</p> }
                    <ul class="actions">
                      @for (a of section.actions; track a.key) {
                        <li class="action-row" [style.--stripe]="stripeColor(a)">
                          @if (a.kev; as kev) {
                            <span class="kev-badge">
                              KEV
                              @if (kev.pastDueCount > 0) { &middot; {{ kev.pastDueCount }} past due }
                              @if (kev.ransomware) { &middot; ransomware }
                            </span>
                          }
                          <div class="action-main">
                            <span class="headline">{{ fixHeadline(a) }}</span>
                            <span class="count tabular-nums">{{ a.count }} threat{{ a.count === 1 ? '' : 's' }}</span>
                            @if (a.worstScore != null) {
                              <span class="worst tabular-nums">
                                {{ a.worstScore }}@if (a.worstVersion) { <span class="ver">v{{ a.worstVersion }}</span> }
                              </span>
                            }
                          </div>
                          <div class="dist">
                            @for (band of severityBands; track band) {
                              @if (a.severityCounts[band] > 0) {
                                <span class="seg" [style.flexGrow]="a.severityCounts[band]" [style.background]="bandColor(band)"
                                  [attr.title]="band + ': ' + a.severityCounts[band]"></span>
                              }
                            }
                          </div>
                          <details class="disclosure">
                            <summary>{{ a.count }} CVE{{ a.count === 1 ? '' : 's' }}</summary>
                            <ul class="cves">
                              @for (item of a.items; track item.itemId) {
                                <li>
                                  <a [routerLink]="['/remediate', item.itemId]">{{ item.cveId || item.title }}</a>
                                  <span class="status" [class]="'status-' + item.status">{{ statusLabel(item.status) }}</span>
                                  @if (item.dueDate) { <span class="due">fix by {{ formatDueDate(item.dueDate) }}</span> }
                                </li>
                              }
                            </ul>
                          </details>
                          <details class="why-disclosure">
                            <summary>why this action?</summary>
                            <dl class="prov">
                              @for (line of provenanceOf(a, g); track line.label) {
                                <div><dt>{{ line.label }}</dt><dd>{{ line.text }}</dd></div>
                              }
                            </dl>
                          </details>
                          <tf-copy-button [value]="ticketTextOf(a, g)" label="Copy as ticket" />
                        </li>
                      }
                    </ul>
                  </div>
                }
              } @else {
                <ul class="actions">
                  @for (a of actionsOf(g); track a.key) {
                    <li class="action-row" [style.--stripe]="stripeColor(a)">
                      @if (a.kev; as kev) {
                        <span class="kev-badge">
                          KEV
                          @if (kev.pastDueCount > 0) { &middot; {{ kev.pastDueCount }} past due }
                          @if (kev.ransomware) { &middot; ransomware }
                        </span>
                      }
                      <div class="action-main">
                        <span class="headline">{{ fixHeadline(a) }}</span>
                        <span class="count tabular-nums">{{ a.count }} threat{{ a.count === 1 ? '' : 's' }}</span>
                        @if (a.worstScore != null) {
                          <span class="worst tabular-nums">
                            {{ a.worstScore }}@if (a.worstVersion) { <span class="ver">v{{ a.worstVersion }}</span> }
                          </span>
                        }
                      </div>
                      <div class="dist">
                        @for (band of severityBands; track band) {
                          @if (a.severityCounts[band] > 0) {
                            <span class="seg" [style.flexGrow]="a.severityCounts[band]" [style.background]="bandColor(band)"
                              [attr.title]="band + ': ' + a.severityCounts[band]"></span>
                          }
                        }
                      </div>
                      <details class="disclosure">
                        <summary>{{ a.count }} CVE{{ a.count === 1 ? '' : 's' }}</summary>
                        <ul class="cves">
                          @for (item of a.items; track item.itemId) {
                            <li>
                              <a [routerLink]="['/remediate', item.itemId]">{{ item.cveId || item.title }}</a>
                              <span class="status" [class]="'status-' + item.status">{{ statusLabel(item.status) }}</span>
                              @if (item.dueDate) { <span class="due">fix by {{ formatDueDate(item.dueDate) }}</span> }
                            </li>
                          }
                        </ul>
                      </details>
                      <details class="why-disclosure">
                        <summary>why this action?</summary>
                        <dl class="prov">
                          @for (line of provenanceOf(a, g); track line.label) {
                            <div><dt>{{ line.label }}</dt><dd>{{ line.text }}</dd></div>
                          }
                        </dl>
                      </details>
                      <tf-copy-button [value]="ticketTextOf(a, g)" label="Copy as ticket" />
                    </li>
                  }
                </ul>
              }
            </li>
          }
        </ul>
      }
    </tf-panel>
  `,
  styles: [`
    .summary { margin: 0 0 14px; font-size: var(--fs-sm); color: var(--ink-2); }
    .groups { list-style: none; margin: 0; padding: 0; display: grid; gap: 16px; }
    .group { border-top: var(--hair) solid var(--hairline); padding-top: 12px; }
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

    .section { margin-top: 12px; }
    .section-head { margin: 0 0 6px; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2); text-transform: uppercase; letter-spacing: .02em; }
    .section-caveat { margin: 0 0 8px; font-size: var(--fs-xs); color: var(--ink-2); font-style: italic; }
    .actions { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }

    .action-row {
      display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 8px 12px;
      padding: 6px 0 6px 10px; border-left: 3px solid var(--stripe, var(--sev-unknown));
    }
    .kev-badge {
      grid-column: 1; font-size: var(--fs-xs); font-weight: 700; color: var(--bg);
      background: var(--sev-critical); padding: 2px 8px; border-radius: 999px; white-space: nowrap;
    }
    .action-main { grid-column: 2; display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; min-width: 0; }
    .headline { color: var(--ink); font-size: var(--fs-sm); }
    .worst { font-size: var(--fs-xs); color: var(--ink-2); }
    .ver { margin-left: 3px; font-size: 10px; color: var(--ink-2); }
    .dist { grid-column: 3; display: flex; width: 80px; height: 6px; border-radius: 3px; overflow: hidden; background: var(--surface-3); }
    .seg { display: block; }
    .disclosure { grid-column: 1 / -1; }
    .disclosure summary { cursor: pointer; font-size: var(--fs-xs); color: var(--ink-2); }
    .cves { list-style: none; margin: 6px 0 0; padding: 0; display: grid; gap: 4px; }
    .cves li { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; font-family: ui-monospace, monospace; font-size: var(--fs-xs); }
    .cves a { color: var(--ink); text-decoration: none; }
    .cves a:hover { color: var(--accent); }
    .status { font-family: inherit; color: var(--ink-2); }
    .status-not_covered { color: var(--sev-none); }
    .due { margin-left: auto; color: var(--ink-2); }

    .controls { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
    .filter {
      flex: 1; min-width: 0; font: inherit; font-size: var(--fs-sm); background: var(--surface-2);
      border: var(--hair) solid var(--hairline); border-radius: 6px; padding: 6px 10px; color: var(--ink);
    }
    .sort-toggle {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--surface-2); border: 0; padding: 6px 12px; border-radius: 8px;
      white-space: nowrap;
    }
    .why-disclosure { grid-column: 1 / -1; margin-top: 4px; }
    .why-disclosure summary { cursor: pointer; font-size: var(--fs-xs); color: var(--ink-2); }
    .prov { margin: 6px 0 0; display: grid; gap: 4px; }
    .prov div { display: flex; gap: 8px; font-size: var(--fs-xs); }
    .prov dt { color: var(--ink-2); min-width: 90px; }
    .prov dd { margin: 0; color: var(--ink); }

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

  filterQuery = signal('');
  sortMode = signal<RiskReachMode>('risk');

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

  toggleSort(): void {
    this.sortMode.set(this.sortMode() === 'risk' ? 'reach' : 'risk');
  }

  // Part 3's default: risk order (worst CVSS descending, count breaking ties, KEV first
  // regardless); Part 4's toggle switches to reach. Part 4's filter narrows the ITEMS first, so
  // a filtered-out threat never survives inside a surviving action's disclosure — actions are
  // re-derived from the filtered set, not filtered themselves after the fact.
  actionsOf(g: RemediationQueueGroup): RemediationAction[] {
    const filtered = filterQueueItems(g.items, this.filterQuery());
    return sortActions(groupActions(filtered), this.sortMode());
  }

  // Part 2: only once a version is known is there anything to split — before that there is one
  // bucket and no section chrome, so this returns null and the template falls back to the flat
  // actionsOf() list. Empty sections are dropped rather than rendered with no rows.
  sectionsFor(g: RemediationQueueGroup): ActionSectionView[] | null {
    if (g.versionState !== 'known') return null;
    const s = splitActionsByStatus(this.actionsOf(g));
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
