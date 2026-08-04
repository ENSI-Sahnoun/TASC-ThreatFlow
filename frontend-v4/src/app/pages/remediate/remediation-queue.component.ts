import { Component, ChangeDetectionStrategy, inject, signal, computed, effect } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { PanelComponent } from '../../ui/panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import {
  queueSummary, groupProgress, groupHasPastDue, oneUpgradeCloses, closesWording, formatDueDate,
} from '../../core/remediation';
import type { RemediationQueueGroup, RemediationQueueItem } from '../../core/models';

// The routed "/remediate" page: every asset the active profile has told us about, grouped, each
// carrying its open threats. Grouping and within-group sort are Spec A's own SQL (server/index.js)
// — this component adds only what the backend cannot: the "one upgrade closes N" annotation and
// the header summary, both pure functions from core/remediation.ts (see that file's spec for the
// full rule set).
@Component({
  selector: 'tf-page-remediate',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, PanelComponent, EmptyStateComponent, SkeletonComponent],
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
              <ul class="items">
                @for (item of g.items; track item.itemId) {
                  <li>
                    <a [routerLink]="['/remediate', item.itemId]">{{ item.title }}</a>
                    <span class="status" [class]="'status-' + item.status">{{ statusLabel(item.status) }}</span>
                    @if (item.dueDate) { <span class="due">fix by {{ formatDueDate(item.dueDate) }}</span> }
                  </li>
                }
              </ul>
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
    .count { font-size: var(--fs-xs); color: var(--ink-2); }
    .tell-us { font-size: var(--fs-xs); color: var(--accent); text-decoration: none; }
    .tell-us:hover { text-decoration: underline; }
    .past-due {
      margin-left: auto; font-size: var(--fs-xs); font-weight: 600; color: var(--sev-critical);
    }
    .running { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .closes { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink); }
    .items { list-style: none; margin: 8px 0 0; padding: 0; display: grid; gap: 6px; }
    .items li { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
    .items a { color: var(--ink); text-decoration: none; font-size: var(--fs-sm); }
    .items a:hover { color: var(--accent); }
    .status { font-size: var(--fs-xs); color: var(--ink-2); }
    .status-not_covered { color: var(--sev-none); }
    .due { font-size: var(--fs-xs); color: var(--ink-2); margin-left: auto; }
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

  constructor() {
    // No route param to combine with, unlike explorer/item-detail — the effect's own creation
    // run IS the initial load, so there is no "skip the first run" guard needed here.
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

  statusLabel(status: RemediationQueueItem['status']): string {
    if (status === 'affected') return 'affected';
    if (status === 'not_covered') return 'not covered';
    return 'unknown';
  }
}
