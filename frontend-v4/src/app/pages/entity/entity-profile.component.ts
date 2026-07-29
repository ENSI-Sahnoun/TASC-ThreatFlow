import { Component, Input, Output, EventEmitter, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { PanelComponent } from '../../ui/panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { SourceDotComponent } from '../../ui/source-dot.component';
import { ChipComponent } from '../../ui/chip.component';
import { BarChartComponent, type ChartDatum } from '../../charts/bar-chart.component';
import { relativeTime, compactNumber } from '../../core/format';
import type { EntityProfile } from '../../core/models';

// Shared presentational body for /actor/:name and /malware/:family — the two routed pages own
// their own fetch (which ApiService method, which heading noun) and pass the resulting
// EntityProfile straight through. Fetch/loading/error state lives in the parent so this stays a
// pure "given a profile, render it" component with no HTTP awareness of its own.
@Component({
  selector: 'tf-entity-profile',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    RouterLink, PanelComponent, EmptyStateComponent, SkeletonComponent, SourceDotComponent,
    ChipComponent, BarChartComponent,
  ],
  template: `
    @if (profile; as p) {
      <a class="back" routerLink="/intel">&larr; Back to Intel Explorer</a>

      <section class="header">
        <p class="kind">{{ heading }}</p>
        <h1>{{ p.name }}</h1>
        <p class="count">{{ compactNumber(p.itemCount) }} item{{ p.itemCount === 1 ? '' : 's' }}</p>
      </section>

      <tf-panel [title]="p.kind === 'actor' ? 'Arsenal' : 'Attribution'">
        @if (p.related.length === 0 && p.cves.length === 0) {
          <tf-empty-state [reason]="p.kind === 'actor' ? 'No malware families or CVEs linked to this actor' : 'No actors or CVEs linked to this family'" />
        } @else {
          <div class="attribution-groups">
            <div class="group">
              <p class="group-label">{{ p.kind === 'actor' ? 'Malware families' : 'Threat actors' }}</p>
              @if (p.related.length) {
                <div class="entities">
                  @for (r of p.related; track r) {
                    <a class="entity" [routerLink]="p.kind === 'actor' ? ['/malware', r] : ['/actor', r]">{{ r }}</a>
                  }
                </div>
              } @else {
                <p class="group-empty">None linked</p>
              }
            </div>
            <div class="group">
              <p class="group-label">CVEs exploited</p>
              @if (p.cves.length) {
                <div class="entities">
                  @for (c of p.cves; track c) { <a class="entity" [routerLink]="['/cve', c]">{{ c }}</a> }
                </div>
              } @else {
                <p class="group-empty">None linked</p>
              }
            </div>
          </div>
        }
      </tf-panel>

      <tf-panel title="Activity over time">
        @if (timelineData.length) {
          <tf-bar-chart [data]="timelineData" [showLabels]="true" />
        } @else {
          <tf-empty-state reason="No dated items yet" />
        }
      </tf-panel>

      <tf-panel title="Contributing sources">
        @if (p.sources.length) {
          <div class="sources">
            @for (s of p.sources; track s.id) {
              <span class="source">
                <tf-source-dot [status]="s.last_status" [name]="s.name" />
                {{ s.name }}
                <span class="src-count">{{ s.count }}</span>
              </span>
            }
          </div>
        } @else {
          <tf-empty-state reason="No source breakdown available" />
        }
      </tf-panel>

      <tf-panel title="Items" [subtitle]="p.items.length + ' shown'">
        @if (p.items.length === 0) {
          <tf-empty-state reason="No items found" />
        } @else {
          <div class="tf-scroll">
          <table>
            <thead>
              <tr><th>Title</th><th>Source</th><th>Category</th><th>Severity</th><th>Published</th></tr>
            </thead>
            <tbody>
              @for (item of p.items; track item.id) {
                <tr>
                  <td class="title"><a [routerLink]="['/intel', item.id]">{{ item.title }}</a></td>
                  <td>
                    <span class="src-cell">
                      <tf-source-dot [status]="item.last_status" [name]="item.source_name" />
                      {{ item.source_name }}
                    </span>
                  </td>
                  <td>{{ item.category }}</td>
                  <td><tf-chip [severity]="item.severity" /></td>
                  <td>{{ relativeTime(item.published_at) }}</td>
                </tr>
              }
            </tbody>
          </table>
          </div>
        }
      </tf-panel>
    } @else if (loading) {
      <tf-skeleton [rows]="10" />
    } @else if (notFound) {
      <div class="not-found">
        <tf-empty-state title="No intelligence on this entity" />
        <a class="back" routerLink="/intel">&larr; Back to Intel Explorer</a>
      </div>
    } @else if (error) {
      <div class="err">
        <p class="t">Couldn't load this profile</p>
        <p class="r">Request failed</p>
        <button type="button" (click)="retry.emit()">Retry</button>
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
      padding: 16px; display: flex; flex-direction: column; gap: 4px;
    }
    .kind { margin: 0; font-size: var(--fs-xs); font-weight: 590; color: var(--ink-2); text-transform: uppercase; letter-spacing: .04em; }
    h1 { margin: 0; font-size: var(--fs-xl); font-weight: 620; color: var(--ink); letter-spacing: -.01em; word-break: break-word; }
    .count { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }

    .sources { display: flex; flex-wrap: wrap; gap: 8px; }
    .source {
      display: inline-flex; align-items: center; gap: 6px; font-size: var(--fs-xs); color: var(--ink);
      background: var(--surface-2); padding: 4px 10px; border-radius: 999px;
    }
    .src-count { color: var(--ink-2); }

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

    .tf-scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    thead th, tbody td { border-bottom: var(--hair) solid var(--hairline); }
    thead th { text-align: left; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2); padding: 6px 10px; white-space: nowrap; }
    tbody td { padding: 7px 10px; font-size: var(--fs-sm); color: var(--ink-2); }
    td.title a {
      color: var(--ink); text-decoration: none; transition: color var(--dur-fast) var(--ease);
    }
    td.title a:hover { color: var(--accent); }
    td.title a:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .src-cell { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }

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
    .err button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .err button:active { opacity: .74; }

    @media (prefers-reduced-motion: reduce) {
      .back, .entity, td.title a, .err button { transition: none; }
    }
  `],
})
export class EntityProfileComponent {
  @Input() heading = 'Entity';
  @Input() profile: EntityProfile | null = null;
  @Input() loading = false;
  @Input() notFound = false;
  @Input() error = false;
  @Output() retry = new EventEmitter<void>();

  relativeTime = relativeTime;
  compactNumber = compactNumber;

  get timelineData(): ChartDatum[] {
    return (this.profile?.timeline ?? []).map((t) => ({ label: t.bucket, value: t.count }));
  }
}
