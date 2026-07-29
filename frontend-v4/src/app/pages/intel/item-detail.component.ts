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
import { CopyButtonComponent } from '../../ui/copy-button.component';
import { BrowserWindowComponent } from '../../ui/browser-window.component';
import { relativeTime, stripHtml } from '../../core/format';
import type { ItemDetail } from '../../core/models';

interface EntityLink { key: string; label: string; path: string[]; }

// The routed "/intel/:id" page — the full record behind one explorer row. Confidence is always
// labelled as derived (never presented as if the source itself supplied a score — see
// server/confidence.js / CLAUDE.md's data-quality notes: it's a post-sync consolidation
// heuristic and can be NULL for a row inserted since the last sync). Entities link out to their
// profile pages; domains have no dedicated route yet so render as plain tags, not links.
@Component({
  selector: 'tf-page-item-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    RouterLink, PanelComponent, EmptyStateComponent, SkeletonComponent, SourceDotComponent,
    ChipComponent, CopyButtonComponent, BrowserWindowComponent,
  ],
  template: `
    @if (detail(); as d) {
      <a class="back" routerLink="/intel">&larr; Back to Intel Explorer</a>

      <section class="header">
        <div class="head-row">
          <tf-source-dot [status]="sourceStatus()" [name]="d.source_name ?? 'Unknown source'" />
          <span class="source-name">{{ d.source_name ?? 'Unknown source' }}</span>
          <span class="time">{{ relativeTime(d.published_at) }}</span>
          <tf-chip [severity]="d.severity" />
        </div>
        <h1 class="sr-only">{{ d.title }}</h1>

        @if (d.confidence != null) {
          <p class="confidence">Confidence {{ d.confidence.toFixed(2) }} · derived from source tier and corroboration</p>
        } @else {
          <p class="confidence muted">
            Confidence not yet computed — populated by the next sync-all's consolidation pass, not at ingest
          </p>
        }

        <tf-browser-window
          [url]="d.link" [title]="d.title" [sourceName]="d.source_name ?? 'Unknown source'"
          [sourceStatus]="sourceStatus()" [time]="relativeTime(d.published_at)"
          [summary]="cleanedSummary()"
          [allowExpand]="sourceFetchKind() === 'rss'"
        />

        <dl class="meta">
          <div><dt>Category</dt><dd>{{ d.category }}</dd></div>
          @if (d.vendor) { <div><dt>Vendor</dt><dd>{{ d.vendor }}</dd></div> }
          @if (d.region) { <div><dt>Region</dt><dd>{{ d.region }}</dd></div> }
          @if (d.industry) { <div><dt>Industry</dt><dd>{{ d.industry }}</dd></div> }
          @if (d.cvss_score != null) { <div><dt>CVSS</dt><dd>{{ d.cvss_score }}</dd></div> }
          @if (d.exploitation_status) { <div><dt>Exploitation</dt><dd>{{ d.exploitation_status }}</dd></div> }
        </dl>
      </section>

      <tf-panel title="Entities">
        @if (entities().length === 0 && d.domains.length === 0) {
          <tf-empty-state reason="No CVEs, actors, malware families or domain tags extracted for this item" />
        } @else {
          <div class="entities">
            @for (e of entities(); track e.key) {
              <a class="entity" [routerLink]="e.path">{{ e.label }}</a>
            }
            @for (dom of d.domains; track dom) {
              <span class="entity tag">{{ dom }}</span>
            }
          </div>
        }
      </tf-panel>

      <tf-panel title="Indicators of compromise" [subtitle]="d.iocs.length + ' total'">
        @if (d.iocs.length === 0) {
          <tf-empty-state reason="No IOCs extracted for this item" />
        } @else {
          <div class="tf-scroll">
          <table>
            <thead><tr><th>Type</th><th>Value</th><th></th></tr></thead>
            <tbody>
              @for (ioc of d.iocs; track ioc.type + ioc.value) {
                <tr>
                  <td>{{ ioc.type }}</td>
                  <td class="value">{{ ioc.value }}</td>
                  <td class="row-actions">
                    <tf-copy-button [value]="ioc.value" label="Copy" />
                    @if (ipEntry(d, ioc); as entry) {
                      <button type="button" class="expand" (click)="toggleIp(ioc.value)">
                        {{ isIpExpanded(ioc.value) ? 'Hide intel' : 'IP intel' }}
                      </button>
                    }
                  </td>
                </tr>
                @if (ipEntry(d, ioc); as entry) {
                  @if (isIpExpanded(ioc.value)) {
                    <tr class="ip-expand">
                      <td colspan="3">
                        <dl class="ip-meta">
                          <div><dt>Org</dt><dd>{{ entry.org ?? '—' }}</dd></div>
                          <div><dt>ISP</dt><dd>{{ entry.isp ?? '—' }}</dd></div>
                          <div><dt>Geo</dt><dd>{{ entry.city ?? '—' }}{{ entry.country_code ? ', ' + entry.country_code : '' }}</dd></div>
                          <div><dt>Ports</dt><dd>{{ entry.ports?.length ? entry.ports!.join(', ') : '—' }}</dd></div>
                          <div><dt>Vulns</dt><dd>{{ entry.vulns?.length ? entry.vulns!.join(', ') : '—' }}</dd></div>
                          <div><dt>Source</dt><dd>{{ entry.source ?? '—' }}</dd></div>
                        </dl>
                      </td>
                    </tr>
                  }
                }
              }
            </tbody>
          </table>
          </div>
        }
      </tf-panel>

      <details class="raw">
        <summary>Raw JSON</summary>
        <pre>{{ rawJsonText() }}</pre>
      </details>
    } @else if (loading()) {
      <tf-skeleton [rows]="10" />
    } @else if (notFound()) {
      <div class="not-found">
        <tf-empty-state title="Item not found" reason="GET /api/items/:id returned 404" />
        <a class="back" routerLink="/intel">&larr; Back to Intel Explorer</a>
      </div>
    } @else if (error()) {
      <div class="err">
        <p class="t">Couldn't load this item</p>
        <p class="r">GET /api/items/{{ id }} failed</p>
        <button type="button" (click)="loadDetail()">Retry</button>
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
      padding: 16px; display: flex; flex-direction: column; gap: 10px;
    }
    .head-row { display: flex; align-items: center; gap: 8px; }
    .source-name { font-size: var(--fs-sm); color: var(--ink-2); }
    .time { font-size: var(--fs-xs); color: var(--ink-2); margin-right: auto; }
    .sr-only {
      position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden;
      clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
    }

    .confidence { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .confidence.muted { font-style: italic; }
    tf-browser-window { display: block; }

    dl.meta { display: flex; flex-wrap: wrap; gap: 12px 24px; margin: 4px 0 0; }
    dl.meta dd { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    dl.meta a { color: var(--accent); }

    .entities { display: flex; flex-wrap: wrap; gap: 6px; }
    .entity {
      font-size: var(--fs-xs); font-weight: 510; color: var(--ink); text-decoration: none;
      background: var(--surface-2); padding: 4px 10px; border-radius: 999px;
      transition: background var(--dur-fast) var(--ease);
    }
    a.entity:hover { background: var(--surface-3); }
    a.entity:active { background: var(--surface-4); }
    .entity.tag { color: var(--ink-2); cursor: default; }

    .tf-scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    thead th, tbody td { border-bottom: var(--hair) solid var(--hairline); }
    thead th { text-align: left; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2); padding: 6px 10px; }
    tbody td { padding: 7px 10px; font-size: var(--fs-sm); color: var(--ink-2); }
    td.value { color: var(--ink); font-family: ui-monospace, monospace; font-size: var(--fs-xs); word-break: break-all; }
    .row-actions { display: flex; align-items: center; gap: 6px; white-space: nowrap; }

    .expand {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 510;
      color: var(--ink-2); background: var(--surface-2); border: 0; padding: 3px 9px; border-radius: 6px;
      transition: color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
    }
    .expand:hover { color: var(--ink); background: var(--surface-3); }
    a.entity:focus-visible, .expand:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .expand:active { background: var(--surface-4); }

    tr.ip-expand td { background: var(--surface-2); padding: 10px 14px; }
    dl.ip-meta { display: flex; flex-wrap: wrap; gap: 10px 20px; margin: 0; }
    dl.ip-meta div { min-width: 120px; }
    dl.ip-meta dd { margin: 0; font-size: var(--fs-xs); color: var(--ink); word-break: break-word; }
    dl.meta div, dl.ip-meta div { display: flex; flex-direction: column; gap: 2px; }
    dl.meta dt, dl.ip-meta dt { font-size: var(--fs-xs); color: var(--ink-2); }

    details.raw {
      background: var(--surface); border-radius: var(--radius-card); border: var(--hair) solid var(--hairline); padding: 12px 16px;
    }
    details.raw summary { cursor: pointer; font-size: var(--fs-sm); font-weight: 590; color: var(--ink); }
    details.raw pre {
      margin: 10px 0 0; font-size: var(--fs-xs); color: var(--ink-2); white-space: pre-wrap; word-break: break-word;
      max-height: 400px; overflow: auto;
    }

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
    .err button:focus-visible, details.raw summary:focus-visible, .back:focus-visible {
      outline: 2px solid var(--accent); outline-offset: 2px;
    }
    .err button:active { opacity: .74; }

    @media (prefers-reduced-motion: reduce) {
      .back, .entity, .expand, .err button { transition: none; }
    }
  `],
})
export class ItemDetailComponent {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);

  id = NaN;

  detail = signal<ItemDetail | null>(null);
  loading = signal(true);
  notFound = signal(false);
  error = signal(false);
  sourceStatus = signal<string | null>(null);
  sourceFetchKind = signal<string | null>(null);
  private expandedIps = signal<Set<string>>(new Set());

  relativeTime = relativeTime;

  rawJsonText = computed(() => {
    const d = this.detail();
    return d ? JSON.stringify(d.raw, null, 2) : '';
  });

  entities = computed<EntityLink[]>(() => {
    const d = this.detail();
    if (!d) return [];
    return [
      ...d.cves.map((c): EntityLink => ({ key: `cve-${c}`, label: c, path: ['/cve', c] })),
      ...d.actors.map((a): EntityLink => ({ key: `actor-${a}`, label: a, path: ['/actor', a] })),
      ...d.families.map((f): EntityLink => ({ key: `family-${f}`, label: f, path: ['/malware', f] })),
    ];
  });

  constructor() {
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      const id = Number(pm.get('id'));
      if (!Number.isInteger(id) || id <= 0) {
        this.notFound.set(true);
        this.loading.set(false);
        return;
      }
      this.id = id;
      this.detail.set(null);
      this.sourceStatus.set(null);
      this.sourceFetchKind.set(null);
      this.expandedIps.set(new Set());
      this.loadDetail();
    });
  }

  loadDetail(): void {
    this.loading.set(true);
    this.notFound.set(false);
    this.error.set(false);
    this.api.item(this.id).subscribe({
      next: (d) => {
        this.detail.set(d);
        this.loading.set(false);
        this.loadSourceStatus(d.source_id);
      },
      error: (err: HttpErrorResponse) => {
        this.loading.set(false);
        if (err.status === 404) this.notFound.set(true);
        else this.error.set(true);
      },
    });
  }

  cleanedSummary(): string | null {
    return stripHtml(this.detail()?.summary ?? null);
  }

  ipEntry(d: ItemDetail, ioc: { type: string; value: string }) {
    return ioc.type === 'ip' ? d.ip_intel[ioc.value] : undefined;
  }

  isIpExpanded(value: string): boolean {
    return this.expandedIps().has(value);
  }

  toggleIp(value: string): void {
    const next = new Set(this.expandedIps());
    if (next.has(value)) next.delete(value); else next.add(value);
    this.expandedIps.set(next);
  }

  // Source health for the item's dot isn't part of GET /api/items/:id (only name/tier/url are
  // joined in) — fetch it from the same sourceStats endpoint the Arsenal dossier already uses.
  // A failure here just leaves the dot in its "never synced" fallback state; it isn't fatal to
  // viewing the record.
  private loadSourceStatus(sourceId: number): void {
    this.api.sourceStats(sourceId).subscribe({
      next: (s) => {
        this.sourceStatus.set(s.source.last_status);
        this.sourceFetchKind.set(s.source.fetch_kind);
      },
      error: () => { /* dot falls back to its default state; expand stays hidden until it loads */ },
    });
  }
}
