import { Component, ChangeDetectionStrategy, inject, signal, computed } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import type { HttpErrorResponse } from '@angular/common/http';
import { ApiService } from '../../core/api.service';
import { PanelComponent } from '../../ui/panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { SourceDotComponent } from '../../ui/source-dot.component';
import { ChipComponent } from '../../ui/chip.component';
import { StatCardComponent } from '../../ui/stat-card.component';
import {
  relativeTime, cvssBand, severityLabel, epssPercent, cvssDisagreement, formatDate, severityToken,
} from '../../core/format';
import type { CveDetail } from '../../core/models';

// The routed "/cve/:id" page — a risk console, not a record list. The three stat cards (CVSS /
// EPSS / KEV) lead because that's what an analyst opening a CVE page needs first; the per-source
// evidence table is the second centrepiece — `cve_sources` retains every contributing source's
// own score/severity rather than averaging them at consolidation time, specifically so genuine
// scoring disagreement between feeds (e.g. NVD vs. Red Hat) stays visible instead of being
// smoothed away. cvssDisagreement() (in core/format.ts) surfaces that spread as a banner above
// the table when it exists.
@Component({
  selector: 'tf-page-cve',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    RouterLink, PanelComponent, EmptyStateComponent, SkeletonComponent, SourceDotComponent,
    ChipComponent, StatCardComponent,
  ],
  template: `
    @if (detail(); as d) {
      <a class="back" routerLink="/intel">&larr; Back to Intel Explorer</a>

      <section class="header" [style.--sev-c]="severityToken(d.cve.severity)">
        <div class="head-row">
          <h1>{{ d.cve.cve_id }}</h1>
          <tf-chip [severity]="d.cve.severity" />
        </div>

        @if (d.cve.description) {
          <p class="description">{{ d.cve.description }}</p>
        }

        <dl class="timeline">
          <div><dt>First seen</dt><dd>{{ relativeTime(d.cve.first_seen) }}</dd></div>
          <div><dt>Last seen</dt><dd>{{ relativeTime(d.cve.last_seen) }}</dd></div>
        </dl>
      </section>

      <div class="stat-row">
        <tf-stat-card
          label="CVSS"
          [value]="d.cve.cvss_score != null ? d.cve.cvss_score + '' : 'Not scored'"
          [caption]="d.cve.cvss_score != null ? cvssBandLabel(d.cve.cvss_score) + (d.cve.cvss_source ? ' · ' + d.cve.cvss_source : '') : ''"
          [tone]="d.cve.cvss_score != null ? cvssBand(d.cve.cvss_score) : null"
        />
        <tf-stat-card
          label="EPSS"
          [value]="epssPercent(d.cve.epss_score)"
          caption="exploitation probability"
        />
        <tf-stat-card
          label="KEV"
          [value]="d.cve.kev_listed ? 'Known exploited' : 'Not in KEV catalog'"
          [caption]="d.cve.kev_listed && d.cve.kev_added_at ? 'Added ' + formatDate(d.cve.kev_added_at) : ''"
          [tone]="d.cve.kev_listed ? 'critical' : null"
          [emphasis]="d.cve.kev_listed"
        />
      </div>

      <tf-panel title="Attribution">
        @if (attributedActors().length === 0 && attributedFamilies().length === 0) {
          <tf-empty-state reason="No actors or malware families linked to this CVE" />
        } @else {
          <div class="attribution-groups">
            <div class="group">
              <p class="group-label">Actors</p>
              @if (attributedActors().length) {
                <div class="entities">
                  @for (a of attributedActors(); track a) { <a class="entity" [routerLink]="['/actor', a]">{{ a }}</a> }
                </div>
              } @else {
                <p class="group-empty">None linked</p>
              }
            </div>
            <div class="group">
              <p class="group-label">Malware families</p>
              @if (attributedFamilies().length) {
                <div class="entities">
                  @for (f of attributedFamilies(); track f) { <a class="entity" [routerLink]="['/malware', f]">{{ f }}</a> }
                </div>
              } @else {
                <p class="group-empty">None linked</p>
              }
            </div>
          </div>
        }
      </tf-panel>

      <tf-panel title="Per-source evidence" [subtitle]="d.sources.length + ' source' + (d.sources.length === 1 ? '' : 's')">
        @if (disagreement(); as spread) {
          <p class="disagree">Sources disagree · {{ spread }}</p>
        }
        @if (d.sources.length === 0) {
          <tf-empty-state reason="No contributing sources recorded for this CVE" />
        } @else {
          <div class="tf-scroll">
          <table>
            <thead>
              <tr><th>Source</th><th>CVSS</th><th>Severity</th><th>Item</th><th>Published</th></tr>
            </thead>
            <tbody>
              @for (s of d.sources; track s.item_id) {
                <tr [style.--row-c]="severityToken(s.severity)" [class.hot]="s.severity === 'critical' || s.severity === 'high'">
                  <td>
                    <span class="src-cell">
                      <tf-source-dot [status]="s.last_status" [name]="s.source_name" />
                      {{ s.source_name }}
                    </span>
                  </td>
                  <td>{{ s.cvss_score ?? '—' }}</td>
                  <td><tf-chip [severity]="s.severity" /></td>
                  <td class="title"><a [routerLink]="['/intel', s.item_id]">{{ s.title }}</a></td>
                  <td>{{ relativeTime(s.published_at) }}</td>
                </tr>
              }
            </tbody>
          </table>
          </div>
        }
      </tf-panel>
    } @else if (loading()) {
      <tf-skeleton [rows]="10" />
    } @else if (notFound()) {
      <div class="not-found">
        <tf-empty-state title="CVE not found" reason="GET /api/cves/:id returned 404" />
        <a class="back" routerLink="/intel">&larr; Back to Intel Explorer</a>
      </div>
    } @else if (error()) {
      <div class="err">
        <p class="t">Couldn't load this CVE</p>
        <p class="r">GET /api/cves/{{ id }} failed</p>
        <button type="button" (click)="load()">Retry</button>
      </div>
    }
  `,
  styles: [`
    :host { display: flex; flex-direction: column; gap: 16px; }

    .back { align-self: flex-start; font-size: var(--fs-xs); color: var(--ink-2); text-decoration: none; transition: color var(--dur-fast) var(--ease); }
    .back:hover { color: var(--ink); }
    .not-found { display: flex; flex-direction: column; align-items: center; gap: 10px; padding: 32px 0; }
    .not-found .back { align-self: center; }

    .header {
      background: var(--surface); border-radius: var(--radius-card); border: var(--hair) solid var(--hairline);
      border-top: 3px solid var(--sev-c); padding: 18px 16px 16px; display: flex; flex-direction: column; gap: 12px;
    }
    .head-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    h1 {
      margin: 0; font-size: var(--fs-2xl); font-weight: 680; color: var(--ink); letter-spacing: -.02em;
      font-variant-numeric: tabular-nums;
    }

    dl.timeline { display: flex; flex-wrap: wrap; gap: 12px 28px; margin: 0; }
    dl.timeline dt { font-size: var(--fs-xs); color: var(--ink-2); }
    dl.timeline dd { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    dl.timeline div { display: flex; flex-direction: column; gap: 2px; }

    .description { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); line-height: 1.5; white-space: pre-wrap; }

    .stat-row { display: flex; flex-wrap: wrap; gap: 10px; }
    .stat-row tf-stat-card { flex: 1 1 160px; }

    .attribution-groups { display: flex; flex-wrap: wrap; gap: 20px; }
    .group { display: flex; flex-direction: column; gap: 6px; min-width: 160px; }
    .group-label { margin: 0; font-size: var(--fs-xs); font-weight: 590; color: var(--ink-2); text-transform: uppercase; letter-spacing: .04em; }
    .group-empty { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); font-style: italic; }

    .entities { display: flex; flex-wrap: wrap; gap: 6px; }
    .entity {
      font-size: var(--fs-xs); font-weight: 510; color: var(--ink); text-decoration: none;
      background: var(--surface-2); padding: 4px 10px; border-radius: 999px;
      transition: background var(--dur-fast) var(--ease);
    }
    a.entity:hover { background: var(--surface-3); }
    a.entity:active { background: var(--surface-4); }
    a.entity:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

    .disagree {
      margin: 0 0 10px; font-size: var(--fs-xs); font-weight: 590; color: var(--ink);
      background: color-mix(in srgb, var(--sev-medium) 18%, transparent);
      padding: 6px 10px; border-radius: 8px; display: inline-block;
    }

    .tf-scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    thead th, tbody td { border-bottom: var(--hair) solid var(--hairline); }
    thead th { text-align: left; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2); padding: 6px 10px; white-space: nowrap; }
    tbody tr { transition: background var(--dur-fast) var(--ease); }
    tbody tr.hot { background: color-mix(in srgb, var(--row-c) 9%, transparent); }
    tbody td { padding: 7px 10px; font-size: var(--fs-sm); color: var(--ink-2); }
    .src-cell { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
    td.title a { color: var(--ink); text-decoration: none; transition: color var(--dur-fast) var(--ease); }
    td.title a:hover { color: var(--accent); }
    td.title a:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

    .err {
      display: flex; flex-direction: column; align-items: center; gap: 8px;
      min-height: 200px; justify-content: center; text-align: center; padding: 16px;
    }
    .err .t { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    .err .r { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); background: var(--surface-2); padding: 4px 10px; border-radius: 6px; }
    .err button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0; padding: 6px 14px; border-radius: 8px;
      transition: opacity var(--dur-fast) var(--ease);
    }
    .err button:hover { opacity: .88; }
    .err button:focus-visible, .back:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .err button:active { opacity: .74; }

    @media (prefers-reduced-motion: reduce) {
      .back, .entity, td.title a, .err button { transition: none; }
    }
  `],
})
export class CveComponent {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);

  id = '';

  detail = signal<CveDetail | null>(null);
  loading = signal(true);
  notFound = signal(false);
  error = signal(false);

  relativeTime = relativeTime;
  epssPercent = epssPercent;
  formatDate = formatDate;
  cvssBand = cvssBand;
  severityToken = severityToken;

  attributedActors = computed<string[]>(() => this.detail()?.actors ?? []);
  attributedFamilies = computed<string[]>(() => this.detail()?.families ?? []);

  disagreement = computed<string | null>(() => {
    const d = this.detail();
    return d ? cvssDisagreement(d.sources) : null;
  });

  constructor() {
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      const id = pm.get('id');
      if (!id) { this.notFound.set(true); this.loading.set(false); return; }
      this.id = id;
      this.detail.set(null);
      this.load();
    });
  }

  load(): void {
    this.loading.set(true);
    this.notFound.set(false);
    this.error.set(false);
    this.api.cve(this.id).subscribe({
      next: (d) => { this.detail.set(d); this.loading.set(false); },
      error: (err: HttpErrorResponse) => {
        this.loading.set(false);
        if (err.status === 404) this.notFound.set(true);
        else this.error.set(true);
      },
    });
  }

  cvssBandLabel(score: number | null): string {
    return severityLabel(cvssBand(score));
  }
}
