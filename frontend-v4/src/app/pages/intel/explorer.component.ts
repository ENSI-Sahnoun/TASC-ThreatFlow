import { Component, ChangeDetectionStrategy, inject, signal, computed } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { SourceDotComponent } from '../../ui/source-dot.component';
import { ChipComponent } from '../../ui/chip.component';
import { RelevanceChipComponent } from '../../ui/relevance-chip.component';
import { CopyButtonComponent } from '../../ui/copy-button.component';
import { DataTableComponent, type DataTableColumn } from '../../ui/data-table.component';
import { UrlCheckComponent } from '../../ui/url-check.component';
import { FilterBarComponent, type FilterBarSource } from './filter-bar.component';
import { toQueryParams, fromQueryParams, type IntelFilters } from '../../core/filters';
import { relativeTime, compactNumber, isRatedSeverity, categoryToken } from '../../core/format';
import { qualityLabel, qualityHint } from '../../core/relevance';
import type { Item, ClusterMember, Facets, IocRow } from '../../core/models';

const PAGE_SIZE = 25;

const COLUMNS: DataTableColumn[] = [
  { key: 'title', label: 'Title' },
  { key: 'category', label: 'Category' },
  { key: 'severity', label: 'Severity' },
  // Sits next to severity deliberately: severity is how bad this is in general, threat is how
  // much it should matter to the active profile.
  { key: 'threat', label: 'Threat' },
  { key: 'published', label: 'Published' },
  { key: 'confidence', label: 'Confidence' },
  { key: 'sources', label: 'Sources' },
];

// Title gets whatever's left; every metadata column is fixed to its content's actual width
// instead of the browser's auto table layout, which was handing "1h" and "95%" the same width
// as "Chinese-Speaking Threat Actor Harnesses AI Models…". Keep this in sync with `.row`'s own
// grid-template-columns below — tf-data-table's header and this component's rows share the
// string so columns line up without the two components knowing about each other's markup.
const GRID_TEMPLATE = '1fr 120px 100px 92px 60px 56px 116px';

// The routed "/intel" page — the general intel browser. Filters live entirely in the URL
// (toQueryParams/fromQueryParams) so any filtered view is shareable and survives a reload or a
// dashboard drill-down link. Clustered stories collapse behind a "N sources" badge that expands
// in place via GET /api/clusters/:id/items rather than opening anything else. Copy-all/Export
// both read from the exact same filter set the table shows, via the export-filter-parity fix
// server-side (see server/queries.js#iocRows).
@Component({
  selector: 'tf-page-explorer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    RouterLink, EmptyStateComponent, SkeletonComponent, SourceDotComponent,
    ChipComponent, RelevanceChipComponent, CopyButtonComponent, DataTableComponent, UrlCheckComponent, FilterBarComponent,
  ],
  template: `
    <div class="explorer">
      <header class="page-head">
        <h1 class="tf-heading">Intel</h1>
        <p class="tagline">Complexity, simplified. Filter, cluster, export — your call.</p>
      </header>
      <tf-filter-bar
        [filters]="filters()"
        [sources]="sourceOptions()"
        [vendors]="facets().vendors"
        [regions]="facets().regions"
        (filtersChange)="onFiltersChange($event)"
      />

      @if (isPhishingOnly()) {
        <!-- Phishing feeds are just a wall of individual URLs (~500+) — nobody scrolls that
             looking for one address. A lookup answers the actual question: "is this URL bad?" -->
        <tf-url-check />
      } @else {
        <div class="toolbar">
          <p class="summary">
            @if (!loading() && !error()) {
              {{ total() }} item{{ total() === 1 ? '' : 's' }} match{{ total() === 1 ? 'es' : '' }} the current filters
            }
          </p>
          <div class="actions">
            <tf-copy-button [value]="iocClipboardText()" [label]="copyLabel()" />
            <a class="export" [href]="exportUrl()">{{ exportLabel() }}</a>
          </div>
        </div>

        @if (loading()) {
          <tf-skeleton [rows]="8" />
        } @else if (error()) {
          <div class="err">
            <p class="t">Couldn't load items</p>
            <p class="r">GET /api/items failed</p>
            <button type="button" (click)="loadItems()">Retry</button>
          </div>
        } @else if (rows().length === 0) {
          <tf-empty-state title="No items match these filters" [reason]="activeFiltersSummary()" />
        } @else {
          <tf-data-table
            [columns]="columns"
            [gridTemplate]="GRID_TEMPLATE"
            [rows]="rows()"
            [total]="total()"
            [page]="page()"
            [pageSize]="PAGE_SIZE"
            [rowTemplate]="rowTpl"
            [trackByFn]="trackById"
            (pageChange)="onPageChange($event)"
          />
        }
      }

      <ng-template #rowTpl let-row>
        <li class="row" [style.grid-template-columns]="GRID_TEMPLATE">
          <a class="hit" [routerLink]="['/intel', row.id]" [attr.aria-label]="'Open ' + row.title"></a>
          <span class="title">
            {{ row.title }}
            @if (qualityLabel(row.quality?.verdict); as q) {
              <span class="qbadge" [title]="qualityHint(row.quality?.verdict)">{{ q }}</span>
            }
          </span>
          <span class="cat">
            <span class="cat-dot" [style.--c]="categoryToken(row.category)"></span>{{ row.category }}
          </span>
          <span class="sev">
            @if (isRatedSeverity(row.severity)) {
              <tf-chip [severity]="row.severity" />
            } @else {
              <span class="unrated">—</span>
            }
          </span>
          <span class="threat">
            @if (row.relevance) {
              <tf-relevance-chip [relevance]="row.relevance" [compact]="true" />
            } @else {
              <span class="unrated">—</span>
            }
          </span>
          <span class="time">{{ relativeTime(row.published_at) }}</span>
          <span class="conf">{{ confidenceText(row.confidence) }}</span>
          <span class="src">
            @if (row.source_count > 1) {
              <button type="button" class="cluster-badge" (click)="toggleCluster(row)">
                {{ row.source_count }} <span class="chev">{{ isExpanded(row.cluster_id) ? '▲' : '▼' }}</span>
              </button>
            }
          </span>
        </li>
        @if (row.cluster_id != null && isExpanded(row.cluster_id)) {
          <li class="cluster-expand">
            @if (isClusterLoading(row.cluster_id)) {
              <tf-skeleton [rows]="2" />
            } @else if (isClusterError(row.cluster_id)) {
              <tf-empty-state title="Couldn't load sources" reason="GET /api/clusters/:id/items failed" />
            } @else {
              <ul class="cluster-list">
                @for (m of clusterMembersFor(row.cluster_id); track m.item_id) {
                  <li class="member">
                    <a class="hit" [routerLink]="['/intel', m.item_id]" [attr.aria-label]="'Open ' + m.source_name"></a>
                    <tf-source-dot [status]="m.source_status" [name]="m.source_name" />
                    <span class="name">{{ m.source_name }}</span>
                    <span class="time">{{ relativeTime(m.published_at) }}</span>
                  </li>
                }
              </ul>
            }
          </li>
        }
      </ng-template>
    </div>
  `,
  styles: [`
    .explorer { display: flex; flex-direction: column; gap: 16px; }
    .page-head { display: flex; flex-direction: column; gap: 2px; }
    .page-head h1 { margin: 0; font-size: var(--fs-xl); color: var(--ink); }
    .page-head .tagline { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }

    .toolbar {
      display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
    }
    .summary { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }
    .actions { display: flex; align-items: center; gap: 8px; }
    .export {
      font-size: var(--fs-xs); font-weight: 590; text-decoration: none;
      color: var(--ink); background: var(--surface-2); padding: 5px 12px; border-radius: 8px;
      transition: background var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    .export:hover { background: var(--surface-3); }
    .export:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .export:active { background: var(--surface-4); transform: scale(.97); }

    /* One row = one grid line. Title takes the leftover space; every metadata column is a fixed
       width sized to its actual content (see GRID_TEMPLATE) so short values like "1h" or "95%"
       stop being stretched wide by table auto-layout. Row click target is .hit, a single
       stretched <a> (the classic "stretched-link" pattern) instead of a role="button" wrapper —
       that keeps the cluster-expand <button> a sibling, not a control nested inside another
       interactive control, and gets real link semantics (Enter to open, no synthetic Space
       handler) for free. */
    .row {
      position: relative; display: grid; gap: 12px; align-items: center;
      padding: 11px 12px; border-bottom: var(--hair) solid var(--hairline);
      transition: background var(--dur-fast) var(--ease-out);
      animation: row-in 200ms var(--ease-out) backwards;
    }
    .row:hover, .row:has(.hit:focus-visible) { background: var(--surface-2); }
    .hit { position: absolute; inset: 0; z-index: 0; }
    .hit:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }

    /* No position on these — they must stay plain in-flow content so .hit (positioned,
       z-index 0) paints above them and catches the click. Give any of these a position, even
       relative, and it joins .hit's stacking layer; being later in the DOM it would then
       paint on top and swallow the click, leaving only the gaps between cells clickable. */
    .title {
      color: var(--ink); font-weight: 510;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .cat, .sev, .threat, .time, .conf, .src { font-size: var(--fs-sm); color: var(--ink-2); }
    /* Deliberately quiet: this marks a ranking decision, not a warning. It sits inline with the
       title so a scanning eye can skip it, and carries its reasoning in the tooltip. */
    .qbadge {
      margin-left: 6px; padding: 1px 6px; border-radius: 999px; cursor: help;
      font-size: var(--fs-xs); color: var(--ink-2);
      border: 1px solid color-mix(in srgb, var(--ink) 16%, transparent);
    }
    .cat { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .threat { overflow: hidden; }
    .cat-dot {
      display: inline-block; width: 7px; height: 7px; border-radius: 50%;
      background: var(--c); margin-right: 7px; vertical-align: middle;
    }
    /* "Unknown" is "not analyzed yet", not a rating — a loud chip on most rows drowned out the
       handful of rows with a real severity. Plain muted text keeps the eye on the pills that
       actually mean something. */
    .unrated { color: var(--ink-3); }

    .cluster-badge {
      position: relative; z-index: 1;
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0; padding: 3px 9px; border-radius: 999px;
      transition: opacity var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    .cluster-badge .chev { opacity: .7; }
    .cluster-badge:hover { opacity: .85; }
    .cluster-badge:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .cluster-badge:active { opacity: .7; transform: scale(.94); }

    li.cluster-expand { background: var(--surface-2); padding: 10px 14px; border-bottom: var(--hair) solid var(--hairline); }
    .cluster-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
    .cluster-list li.member {
      position: relative; display: flex; align-items: center; gap: 8px;
      font-size: var(--fs-xs); padding: 5px 8px; border-radius: 8px;
      transition: background var(--dur-fast) var(--ease-out);
      animation: row-in 180ms var(--ease-out) backwards;
    }
    .cluster-list li.member:hover, .cluster-list li.member:has(.hit:focus-visible) { background: var(--surface-3); }
    .cluster-list li:nth-child(1) { animation-delay: 0ms; }
    .cluster-list li:nth-child(2) { animation-delay: 30ms; }
    .cluster-list li:nth-child(3) { animation-delay: 60ms; }
    .cluster-list li:nth-child(4) { animation-delay: 90ms; }
    .cluster-list li:nth-child(n+5) { animation-delay: 120ms; }
    .cluster-list .hit { position: absolute; inset: 0; z-index: 0; border-radius: inherit; }
    .cluster-list .hit:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
    .cluster-list .name { color: var(--ink); }
    .cluster-list .time { color: var(--ink-2); margin-left: auto; }

    @keyframes row-in {
      from { opacity: 0; transform: translateY(-3px); }
      to { opacity: 1; transform: none; }
    }

    .err {
      display: flex; flex-direction: column; align-items: center; gap: 8px;
      min-height: 200px; justify-content: center; text-align: center; padding: 16px;
    }
    .err .t { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    .err .r { margin: 0; font-size: var(--fs-xs); color: var(--ink-2);
         background: var(--surface-2); padding: 4px 10px; border-radius: 6px; }
    .err button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0; padding: 6px 14px; border-radius: 8px;
      transition: opacity var(--dur-fast) var(--ease);
    }
    .err button:hover { opacity: .88; }
    .err button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .err button:active { opacity: .74; }

    @media (prefers-reduced-motion: reduce) {
      .export, .row, .cluster-badge, .cluster-list a, .err button { transition: none; }
      .row, .cluster-list li { animation: none; }
    }
  `],
})
export class ExplorerComponent {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);

  readonly PAGE_SIZE = PAGE_SIZE;
  readonly columns = COLUMNS;
  readonly GRID_TEMPLATE = GRID_TEMPLATE;

  filters = signal<IntelFilters>({});
  page = signal(0);

  rows = signal<Item[]>([]);
  total = signal(0);
  loading = signal(true);
  error = signal(false);

  sourceOptions = signal<FilterBarSource[]>([]);
  facets = signal<Facets>({ vendors: [], regions: [] });

  iocRowsForFilters = signal<IocRow[]>([]);
  iocCountLoading = signal(false);

  private expandedClusters = signal<Set<number>>(new Set());
  private clusterMembers = signal<Map<number, ClusterMember[]>>(new Map());
  private clusterLoadingIds = signal<Set<number>>(new Set());
  private clusterErrorIds = signal<Set<number>>(new Set());

  relativeTime = relativeTime;
  compactNumber = compactNumber;
  isRatedSeverity = isRatedSeverity;
  categoryToken = categoryToken;
  qualityLabel = qualityLabel;
  qualityHint = qualityHint;
  trackById = (r: Item): number => r.id;

  iocClipboardText = computed(() => this.iocRowsForFilters().map((r) => r.value).join('\n'));
  copyLabel = computed(() => (this.iocCountLoading() ? 'Copy all IOCs…' : `Copy all IOCs (${this.iocRowsForFilters().length})`));
  exportLabel = computed(() => (this.iocCountLoading() ? 'Export CSV…' : `Export CSV (${this.iocRowsForFilters().length} rows)`));
  exportUrl = computed(() => this.api.iocExportUrl(this.filters()));
  isPhishingOnly = computed(() => this.filters().category === 'phishing');

  constructor() {
    this.route.queryParamMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      const record: Record<string, string | undefined> = {};
      for (const key of pm.keys) record[key] = pm.get(key) ?? undefined;
      this.filters.set(fromQueryParams(record));
      this.page.set(0);
      this.expandedClusters.set(new Set());
      this.clusterMembers.set(new Map());
      this.clusterLoadingIds.set(new Set());
      this.clusterErrorIds.set(new Set());
      this.loadItems();
      this.loadIocRows();
    });

    this.api.sources().subscribe({
      next: (rows) => this.sourceOptions.set(
        [...rows].sort((a, b) => a.name.localeCompare(b.name)).map((s) => ({ id: s.id, name: s.name }))),
      error: () => { /* filter bar just shows "All" only for Source if this fails */ },
    });

    this.api.facets().subscribe({
      next: (f) => this.facets.set(f),
      error: () => { /* filter bar just shows "All" only for Vendor/Region if this fails */ },
    });
  }

  loadItems(): void {
    this.loading.set(true);
    this.error.set(false);
    this.api.items(this.filters(), this.PAGE_SIZE, this.page() * this.PAGE_SIZE).subscribe({
      next: ({ rows, total }) => {
        this.rows.set(rows);
        this.total.set(total);
        this.loading.set(false);
      },
      error: () => {
        this.error.set(true);
        this.loading.set(false);
      },
    });
  }

  loadIocRows(): void {
    this.iocCountLoading.set(true);
    this.api.iocRows(this.filters()).subscribe({
      next: (rows) => {
        this.iocRowsForFilters.set(rows);
        this.iocCountLoading.set(false);
      },
      error: () => {
        this.iocRowsForFilters.set([]);
        this.iocCountLoading.set(false);
      },
    });
  }

  activeFiltersSummary(): string {
    const qp = toQueryParams(this.filters());
    const parts = Object.entries(qp).map(([k, v]) => `${k}=${v}`);
    return parts.length ? parts.join(', ') : 'no filters applied — the catalog itself is empty';
  }

  confidenceText(c: number | null): string {
    if (c == null || Number.isNaN(c)) return '—';
    return `${Math.round(c * 100)}%`;
  }

  onFiltersChange(next: IntelFilters): void {
    this.router.navigate([], { relativeTo: this.route, queryParams: toQueryParams(next) });
  }

  onPageChange(next: number): void {
    this.page.set(next);
    this.loadItems();
  }

  // The cluster-expand button sits beside `.hit` (the row's stretched link), not inside it, so
  // there's no click-bubbling into the link to guard against here.
  toggleCluster(row: Item): void {
    const id = row.cluster_id;
    if (id == null) return;
    const next = new Set(this.expandedClusters());
    if (next.has(id)) {
      next.delete(id);
      this.expandedClusters.set(next);
      return;
    }
    next.add(id);
    this.expandedClusters.set(next);
    if (!this.clusterMembers().has(id) && !this.clusterLoadingIds().has(id)) this.loadClusterMembers(id);
  }

  isExpanded(id: number | null): boolean {
    return id != null && this.expandedClusters().has(id);
  }

  isClusterLoading(id: number | null): boolean {
    return id != null && this.clusterLoadingIds().has(id);
  }

  isClusterError(id: number | null): boolean {
    return id != null && this.clusterErrorIds().has(id);
  }

  clusterMembersFor(id: number | null): ClusterMember[] {
    return id != null ? (this.clusterMembers().get(id) ?? []) : [];
  }

  private loadClusterMembers(id: number): void {
    const loading = new Set(this.clusterLoadingIds());
    loading.add(id);
    this.clusterLoadingIds.set(loading);
    const cleared = new Set(this.clusterErrorIds());
    cleared.delete(id);
    this.clusterErrorIds.set(cleared);

    this.api.clusterItems(id).subscribe({
      next: (members) => {
        const map = new Map(this.clusterMembers());
        map.set(id, members);
        this.clusterMembers.set(map);
        const l = new Set(this.clusterLoadingIds());
        l.delete(id);
        this.clusterLoadingIds.set(l);
      },
      error: () => {
        const l = new Set(this.clusterLoadingIds());
        l.delete(id);
        this.clusterLoadingIds.set(l);
        const e = new Set(this.clusterErrorIds());
        e.add(id);
        this.clusterErrorIds.set(e);
      },
    });
  }
}
