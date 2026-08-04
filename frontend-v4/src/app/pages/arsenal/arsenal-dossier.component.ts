import { Component, ChangeDetectionStrategy, OnDestroy, inject, signal, computed, effect } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import type { HttpErrorResponse } from '@angular/common/http';
import { NgTemplateOutlet } from '@angular/common';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { PanelComponent } from '../../ui/panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { SourceDotComponent } from '../../ui/source-dot.component';
import { ChipComponent } from '../../ui/chip.component';
import { BarChartComponent, type ChartDatum } from '../../charts/bar-chart.component';
import { DonutChartComponent } from '../../charts/donut-chart.component';
import { FieldCoverageComponent } from './field-coverage.component';
import { StoryDrawerComponent } from '../dashboard/story-drawer.component';
import { itemToFeedRow } from './item-to-feed-row';
import {
  relativeTime, compactNumber, severityToken, severityLabel, severityDisplayLabel, needsKey, statusLabel, stripHtml,
} from '../../core/format';
import { BrowserWindowComponent } from '../../ui/browser-window.component';
import type { IntelFilters } from '../../core/filters';
import type { SourceStats, Item, FeedRow } from '../../core/models';

const PAGE_SIZE = 20;
const SEARCH_DEBOUNCE_MS = 300;
// Same open-delay/close-grace feel as lane-live.component.ts's hover-preview, so hovering a
// row anywhere in the app behaves consistently. No safe-triangle pointer-projection here (unlike
// lane-live) — this popover is small and anchored right at the row, not a wide side drawer.
const HOVER_OPEN_DELAY_MS = 200;
const HOVER_CLOSE_GRACE_MS = 150;
const HOVER_POPOVER_WIDTH = 280;

// The routed "/arsenal/:id" page — everything the catalog card links into. Identity + health up
// top, contribution counts, a volume timeline, three mix donuts, the field-coverage widget (the
// reason this page exists: it's the only place that shows two sources of the same fetch_kind
// actually filling in different fields), then a paginated/searchable items table with the same
// story-drawer the live lane uses.
@Component({
  selector: 'tf-page-arsenal-dossier',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    NgTemplateOutlet, RouterLink, PanelComponent, EmptyStateComponent, SkeletonComponent, SourceDotComponent,
    ChipComponent, BarChartComponent, DonutChartComponent, FieldCoverageComponent, StoryDrawerComponent,
    BrowserWindowComponent,
  ],
  template: `
    @if (stats(); as s) {
      <a class="back" routerLink="/arsenal">&larr; Back to Arsenal</a>

      <!-- Identity header -->
      <section class="identity">
        <header>
          <tf-source-dot [status]="s.source.last_status" [name]="s.source.name" />
          <h1>{{ s.source.name }}</h1>
          <span class="pill" [class]="badge().kind">{{ badge().text }}</span>
          @if (!editing()) {
            <button type="button" class="edit" (click)="startEdit()">Edit</button>
            <button type="button" class="sync" [disabled]="syncing()" (click)="syncNow()">
              {{ syncing() ? 'Syncing…' : 'Sync now' }}
            </button>
          }
        </header>

        @if (editing()) {
          <form class="edit-form" (submit)="saveEdit($event)">
            <label>
              <span>Name</span>
              <input type="text" [value]="editName()" (input)="editName.set($any($event.target).value)" required />
            </label>
            <label>
              <span>Category</span>
              <input type="text" [value]="editCategory()" (input)="editCategory.set($any($event.target).value)" />
            </label>
            <label class="wide">
              <span>URL</span>
              <input type="url" [value]="editUrl()" (input)="editUrl.set($any($event.target).value)" required />
            </label>
            <label>
              <span>Auth env var</span>
              <input type="text" [value]="editAuthRequired()" (input)="editAuthRequired.set($any($event.target).value)" />
            </label>
            <label class="checkbox">
              <input type="checkbox" [checked]="editActive()" (change)="editActive.set($any($event.target).checked)" />
              <span>Active</span>
            </label>
            <label class="wide">
              <span>Notes</span>
              <textarea rows="2" [value]="editNotes()" (input)="editNotes.set($any($event.target).value)"></textarea>
            </label>
            @if (saveError()) { <p class="pill error save-error">{{ saveError() }}</p> }
            <div class="edit-actions">
              <button type="submit" class="save" [disabled]="saving()">{{ saving() ? 'Saving…' : 'Save' }}</button>
              <button type="button" class="cancel" [disabled]="saving()" (click)="cancelEdit()">Cancel</button>
            </div>
          </form>
        } @else {
          <dl>
            <div><dt>Category</dt><dd>{{ s.source.category ?? 'Uncategorized' }}</dd></div>
            <div><dt>Feed kind</dt><dd>{{ s.source.fetch_kind }}</dd></div>
            <div><dt>Tier</dt><dd>{{ s.source.tier ?? 'unknown' }}</dd></div>
            <div><dt>Auth</dt><dd>{{ authText() }}</dd></div>
            <div><dt>Last sync</dt><dd>{{ relativeTime(s.source.last_synced_at) }}</dd></div>
          </dl>
          @if (s.source.notes) { <p class="notes">{{ s.source.notes }}</p> }
        }
        @if (syncError()) { <p class="pill error sync-error">Sync failed — try again in a moment.</p> }
      </section>

      <!-- KPI row -->
      <section class="kpis">
        <div class="kpi"><span class="label">Items</span><span class="value">{{ compactNumber(s.counts.items) }}</span></div>
        <div class="kpi"><span class="label">CVEs</span><span class="value">{{ compactNumber(s.counts.cves) }}</span></div>
        <div class="kpi"><span class="label">IOCs</span><span class="value">{{ compactNumber(s.counts.iocs) }}</span></div>
        <div class="kpi"><span class="label">Actors</span><span class="value">{{ compactNumber(s.counts.actors) }}</span></div>
        <div class="kpi"><span class="label">Families</span><span class="value">{{ compactNumber(s.counts.families) }}</span></div>
      </section>

      <!-- Volume over time -->
      <ng-template #volumeBody>
        @if (timelineData().length) {
          <tf-bar-chart [data]="timelineData()" [showLabels]="true" />
        } @else {
          <tf-empty-state reason="No dated items from this source yet" />
        }
      </ng-template>

      @if (onlySeverityMix()) {
        <!-- Category and domain are single-value (or empty) — severity is the only mix worth
             a donut, so it shares a row with the timeline instead of sitting alone below it. -->
        <div class="split">
          <tf-panel title="Volume over time" subtitle="Items by month">
            <ng-container [ngTemplateOutlet]="volumeBody" />
          </tf-panel>
          <tf-panel title="Severity mix">
            <tf-donut-chart [data]="severityData()" />
          </tf-panel>
        </div>
      } @else {
        <tf-panel title="Volume over time" subtitle="Items by month">
          <ng-container [ngTemplateOutlet]="volumeBody" />
        </tf-panel>

        @if (anyMixVisible()) {
          <div class="mix">
            @if (categoryMixVisible()) {
              <tf-panel title="Category mix"><tf-donut-chart [data]="categoryData()" /></tf-panel>
            }
            @if (domainMixVisible()) {
              <tf-panel title="Domain mix"><tf-donut-chart [data]="domainData()" /></tf-panel>
            }
            @if (severityMixVisible()) {
              <tf-panel title="Severity mix"><tf-donut-chart [data]="severityData()" /></tf-panel>
            }
          </div>
        }
      }

      <!-- Field coverage -->
      <tf-panel title="Field coverage" subtitle="Share of this source's items that carry each field">
        <tf-field-coverage [coverage]="s.fieldCoverage" />
      </tf-panel>

      <!-- Items table -->
      <tf-panel title="Items" [subtitle]="itemsTotal() + ' total'">
        <div panel-actions>
          <input
            class="search"
            type="search"
            placeholder="Search this source's items…"
            [value]="searchDraft()"
            (input)="onSearchInput($any($event.target).value)"
          />
        </div>

        @if (itemsLoading()) {
          <tf-skeleton [rows]="6" />
        } @else if (itemsError()) {
          <tf-empty-state title="Couldn't load items" reason="GET /api/items failed" />
        } @else if (items().length === 0) {
          <tf-empty-state reason="No items match this view" />
        } @else {
          <div class="tf-scroll">
            <table>
              <thead>
                <tr>
                  <th>Title</th><th>Category</th><th>Severity</th><th>Published</th><th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                @for (item of items(); track item.id) {
                  <tr
                    tabindex="0" role="button" [attr.aria-label]="'Open ' + item.title"
                    (click)="openItem(item)" (keydown.enter)="openItem(item)" (keydown.space)="onRowSpace($event, item)"
                    (mouseenter)="onRowEnter(item, $event)" (mouseleave)="onRowLeave()"
                  >
                    <td class="title">{{ item.title }}</td>
                    <td>{{ item.category }}</td>
                    <td><tf-chip [severity]="item.severity" [label]="chipLabel(item, s.source.fetch_kind)" /></td>
                    <td>{{ relativeTime(item.published_at) }}</td>
                    <td>{{ confidencePct(item.confidence) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>

          <div class="pager">
            <button type="button" [disabled]="page() === 0" (click)="prevPage()">Prev</button>
            <span>Page {{ page() + 1 }} of {{ totalPages() }}</span>
            <button type="button" [disabled]="isLastPage()" (click)="nextPage()">Next</button>
          </div>
        }
      </tf-panel>

      @if (hoverItem(); as hi) {
        <div
          class="row-preview" [class.expanded]="previewExpanded()"
          [style.top.px]="hoverPos()?.top" [style.left.px]="hoverPos()?.left"
          (mouseenter)="onPreviewEnter()" (mouseleave)="onRowLeave()"
        >
          <tf-browser-window
            size="compact" [url]="hi.link" [title]="hi.title"
            [sourceName]="s.source.name" [sourceStatus]="s.source.last_status"
            [time]="relativeTime(hi.published_at)" [summary]="stripHtml(hi.summary)"
            [allowExpand]="s.source.fetch_kind === 'rss'"
            (expandedChange)="onPreviewExpandedChange($event)"
          />
        </div>
      }

      <tf-story-drawer [row]="drawerRow()" [pinned]="!!drawerRow()" (closed)="closeDrawer()" (walk)="walkDrawer($event)" />
    } @else if (loading()) {
      <tf-skeleton [rows]="10" />
    } @else if (notFound()) {
      <div class="not-found">
        <tf-empty-state title="Source not found" reason="GET /api/sources/:id/stats returned 404" />
        <a class="back" routerLink="/arsenal">&larr; Back to Arsenal</a>
      </div>
    } @else if (error()) {
      <div class="err">
        <p class="t">Couldn't load this source's dossier</p>
        <p class="r">GET /api/sources/{{ sourceId }}/stats failed</p>
        <button type="button" (click)="loadStats()">Retry</button>
      </div>
    }
  `,
  styles: [`
    :host { display: flex; flex-direction: column; gap: 20px; }

    .back {
      align-self: flex-start; font-size: var(--fs-xs); color: var(--ink-2); text-decoration: none;
      transition: color var(--dur-fast) var(--ease);
    }
    .back:hover { color: var(--ink); }

    .not-found { display: flex; flex-direction: column; align-items: center; gap: 10px; padding: 32px 0; }
    .not-found .back { align-self: center; }

    .identity, .kpi {
      background: var(--surface); border-radius: var(--radius-card);
      border: var(--hair) solid var(--hairline);
    }
    .identity { padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; }
    .identity header { display: flex; align-items: center; gap: 10px; }
    .identity h1 { margin: 0; font-size: var(--fs-lg); font-weight: 620; color: var(--ink); }
    .pill {
      font-size: var(--fs-xs); font-weight: 590; padding: 3px 9px; border-radius: 999px;
      background: var(--surface-2); color: var(--ink-2);
    }
    .pill.error { color: var(--ink); background: color-mix(in srgb, var(--sev-critical) 18%, transparent); }
    .pill.needs-key { color: var(--ink); background: color-mix(in srgb, var(--sev-medium) 18%, transparent); }

    .sync { margin-left: auto; }
    .edit { margin-left: auto; }
    .edit + .sync { margin-left: 0; }
    /* Reuses the .pill.error treatment (ink text, sev-critical-tinted chip) — a <p> just needs
       its margin reset to sit flush under the identity header. */
    .sync-error, .save-error { margin: 0; display: inline-block; }

    dl { display: flex; flex-wrap: wrap; gap: 16px 28px; margin: 0; }
    dl div { display: flex; flex-direction: column; gap: 2px; }
    dt { font-size: var(--fs-xs); color: var(--ink-2); }
    dd { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    .notes { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); white-space: pre-wrap; }

    .edit-form {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px 16px; align-items: end;
    }
    .edit-form label { display: flex; flex-direction: column; gap: 4px; font-size: var(--fs-xs); color: var(--ink-2); }
    .edit-form label.wide { grid-column: 1 / -1; }
    .edit-form label.checkbox { flex-direction: row; align-items: center; gap: 6px; }
    .edit-form input[type=text], .edit-form input[type=url], .edit-form textarea {
      font: inherit; font-size: var(--fs-sm); color: var(--ink); background: var(--surface-2);
      border: var(--hair) solid var(--hairline); border-radius: 8px; padding: 6px 10px;
    }
    .edit-form input[type=checkbox] { width: 16px; height: 16px; }
    .edit-form textarea { resize: vertical; font-family: inherit; }
    .edit-form input:focus-visible, .edit-form textarea:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .edit-actions { grid-column: 1 / -1; display: flex; gap: 10px; }
    .save { background: var(--accent-soft); }
    .cancel { background: var(--surface-2); }
    .edit { background: var(--surface-2); }

    .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
    .kpi { padding: 12px 14px; display: flex; flex-direction: column; gap: 4px; }
    .kpi .label { font-size: var(--fs-xs); color: var(--ink-2); }
    .kpi .value { font-size: var(--fs-xl); font-weight: 620; color: var(--ink); }

    .mix { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
    .split { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; }

    .search {
      font: inherit; font-size: var(--fs-sm); color: var(--ink); background: var(--surface-2);
      border: var(--hair) solid var(--hairline); border-radius: 8px; padding: 6px 10px; width: 220px;
      transition: background var(--dur-fast) var(--ease);
    }
    .search:hover { background: var(--surface-3); }
    .search:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

    .tf-scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    thead th, tbody td { border-bottom: var(--hair) solid var(--hairline); }
    thead th { text-align: left; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2); padding: 6px 10px; }
    tbody td { padding: 8px 10px; font-size: var(--fs-sm); color: var(--ink-2); }
    td.title { color: var(--ink); max-width: 46ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    tbody tr { cursor: pointer; transition: background var(--dur-fast) var(--ease); }
    tbody tr:hover { background: var(--surface-2); }
    tbody tr:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; background: var(--surface-2); }
    tbody tr:active { background: var(--surface-3); }

    .pager {
      display: flex; align-items: center; justify-content: center; gap: 12px;
      padding-top: 12px; font-size: var(--fs-xs); color: var(--ink-2);
    }

    .row-preview { position: fixed; z-index: var(--z-tooltip); }
    /* Stays mounted (not destroyed) while its expand modal is open — see onRowLeave's comment —
       but must not paint on top of/behind the centered modal as a second floating window. */
    .row-preview.expanded { visibility: hidden; pointer-events: none; }

    .err {
      display: flex; flex-direction: column; align-items: center; gap: 8px;
      min-height: 200px; justify-content: center; text-align: center; padding: 16px;
    }
    .err .t { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    .err .r { margin: 0; font-size: var(--fs-xs); color: var(--ink-2);
         background: var(--surface-2); padding: 4px 10px; border-radius: 6px; }

    .sync, .edit, .save, .cancel, .err button, .pager button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); border: 0; border-radius: 8px;
      transition: background var(--dur-fast) var(--ease), opacity var(--dur-fast) var(--ease);
    }
    .sync, .save, .err button { background: var(--accent-soft); padding: 6px 14px; }
    .edit, .cancel { background: var(--surface-2); padding: 6px 14px; }
    .pager button { background: var(--surface-2); padding: 5px 12px; }
    .sync:hover:not(:disabled), .save:hover:not(:disabled), .err button:hover { opacity: .88; }
    .edit:hover, .cancel:hover:not(:disabled), .pager button:hover:not(:disabled) { background: var(--surface-3); }
    .back:focus-visible, .sync:focus-visible, .edit:focus-visible, .save:focus-visible, .cancel:focus-visible,
    .err button:focus-visible, .pager button:focus-visible {
      outline: 2px solid var(--accent); outline-offset: 2px;
    }
    .sync:active:not(:disabled), .save:active:not(:disabled), .err button:active { opacity: .74; }
    .cancel:active:not(:disabled), .pager button:active:not(:disabled) { background: var(--surface-4); }
    .sync:disabled, .save:disabled, .cancel:disabled, .pager button:disabled { cursor: default; opacity: .4; }

    @media (prefers-reduced-motion: reduce) {
      .back, .sync, .edit, .save, .cancel, .search, tbody tr, .pager button, .err button { transition: none; }
    }
  `],
})
export class ArsenalDossierComponent implements OnDestroy {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);
  private profileService = inject(ProfileService);

  sourceId = NaN;

  stats = signal<SourceStats | null>(null);
  loading = signal(true);
  notFound = signal(false);
  error = signal(false);

  syncing = signal(false);
  syncError = signal(false);

  editing = signal(false);
  saving = signal(false);
  saveError = signal<string | null>(null);
  editName = signal('');
  editCategory = signal('');
  editUrl = signal('');
  editNotes = signal('');
  editAuthRequired = signal('');
  editActive = signal(true);

  items = signal<Item[]>([]);
  itemsTotal = signal(0);
  itemsLoading = signal(false);
  itemsError = signal(false);
  page = signal(0);
  searchDraft = signal('');
  private searchTimer: ReturnType<typeof setTimeout> | null = null;

  pinnedItem = signal<Item | null>(null);

  hoverItem = signal<Item | null>(null);
  hoverPos = signal<{ top: number; left: number } | null>(null);
  previewExpanded = signal(false);
  private hoverOpenTimer: ReturnType<typeof setTimeout> | null = null;
  private hoverCloseTimer: ReturnType<typeof setTimeout> | null = null;

  relativeTime = relativeTime;
  compactNumber = compactNumber;
  stripHtml = stripHtml;

  timelineData = computed<ChartDatum[]>(() =>
    (this.stats()?.timeline ?? []).map((t) => ({ label: t.bucket, value: t.count })));

  categoryData = computed<ChartDatum[]>(() =>
    (this.stats()?.byCategory ?? []).map((c) => ({ label: c.category, value: c.count })));

  domainData = computed<ChartDatum[]>(() =>
    (this.stats()?.byDomain ?? []).map((d) => ({ label: d.domain, value: d.count })));

  severityData = computed<ChartDatum[]>(() =>
    (this.stats()?.bySeverity ?? []).map((s) => ({
      label: severityLabel(s.severity), value: s.count, color: severityToken(s.severity),
    })));

  // A donut with one slice is a plain color swatch, not a chart — skip the cell entirely
  // rather than rendering it (or an empty-state placeholder) so the grid reflows around it.
  categoryMixVisible = computed(() => this.categoryData().length > 1);
  domainMixVisible = computed(() => this.domainData().length > 1);
  severityMixVisible = computed(() => this.severityData().length > 1);
  anyMixVisible = computed(() => this.categoryMixVisible() || this.domainMixVisible() || this.severityMixVisible());
  onlySeverityMix = computed(() =>
    this.severityMixVisible() && !this.categoryMixVisible() && !this.domainMixVisible());

  totalPages = computed(() => Math.max(1, Math.ceil(this.itemsTotal() / PAGE_SIZE)));
  isLastPage = computed(() => (this.page() + 1) * PAGE_SIZE >= this.itemsTotal());

  drawerRow = computed<FeedRow | null>(() => {
    const item = this.pinnedItem();
    const s = this.stats();
    if (!item || !s) return null;
    return itemToFeedRow(item, s.source.name, s.source.last_status, s.source.fetch_kind);
  });

  // Health/status badge: statusLabel() is the same helper the Arsenal index cards use, reused
  // rather than re-derived — needsKey wins the label slot the same way it does there.
  badge = computed(() => {
    const s = this.stats();
    if (!s) return { kind: 'count' as const, text: '' };
    return statusLabel({
      auth_required: s.source.auth_required,
      has_api_key: s.source.has_apikey,
      last_status: s.source.last_status,
      item_count: s.counts.items,
    });
  });

  constructor() {
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      const id = Number(pm.get('id'));
      if (!Number.isInteger(id) || id <= 0) {
        this.notFound.set(true);
        this.loading.set(false);
        return;
      }
      this.sourceId = id;
      this.pinnedItem.set(null);
      this.page.set(0);
      this.searchDraft.set('');
      this.loadStats();
    });

    // Only loadItems() reads a profile-scoped endpoint (GET /api/items?source_id=…) — loadStats()
    // (GET /api/sources/:id/stats) carries no relevance data and is deliberately not re-fetched
    // here. Same creation-time-skip guard as explorer/item-detail.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      if (Number.isInteger(this.sourceId) && this.sourceId > 0) this.loadItems();
    });
  }

  ngOnDestroy(): void {
    this.cancelSearchDebounce();
    this.cancelHoverOpen();
    this.cancelHoverClose();
  }

  private cancelSearchDebounce(): void {
    if (this.searchTimer !== null) { clearTimeout(this.searchTimer); this.searchTimer = null; }
  }

  // "Needs a key" reuses needsKey() exactly like the Arsenal index; SourceStats.source has
  // `has_apikey` (no underscore) rather than Source's `has_api_key`, so a trivial adapter
  // object bridges the two shapes instead of re-deriving the boolean inline.
  authText(): string {
    const s = this.stats()?.source;
    if (!s) return '';
    if (needsKey({ auth_required: s.auth_required, has_api_key: s.has_apikey })) {
      return `Needs API key (${s.auth_required})`;
    }
    if (s.auth_required) return `Key configured (${s.auth_required})`;
    return 'No key required';
  }

  confidencePct(c: number | null): string {
    if (c == null || Number.isNaN(c)) return '—';
    return `${Math.round(c * 100)}%`;
  }

  loadStats(): void {
    this.loading.set(true);
    this.notFound.set(false);
    this.error.set(false);
    this.api.sourceStats(this.sourceId).subscribe({
      next: (s) => {
        this.stats.set(s);
        this.loading.set(false);
        this.loadItems();
      },
      error: (err: HttpErrorResponse) => {
        this.loading.set(false);
        if (err.status === 404) this.notFound.set(true);
        else this.error.set(true);
      },
    });
  }

  loadItems(): void {
    this.itemsLoading.set(true);
    this.itemsError.set(false);
    const filters: IntelFilters = { source_id: this.sourceId };
    const q = this.searchDraft().trim();
    if (q) filters.q = q;
    this.api.items(filters, PAGE_SIZE, this.page() * PAGE_SIZE).subscribe({
      next: ({ rows, total }) => {
        this.items.set(rows);
        this.itemsTotal.set(total);
        this.itemsLoading.set(false);
      },
      error: () => {
        this.itemsError.set(true);
        this.itemsLoading.set(false);
      },
    });
  }

  onSearchInput(value: string): void {
    this.searchDraft.set(value);
    this.cancelSearchDebounce();
    this.searchTimer = setTimeout(() => {
      this.searchTimer = null;
      this.page.set(0);
      this.loadItems();
    }, SEARCH_DEBOUNCE_MS);
  }

  prevPage(): void {
    if (this.page() === 0) return;
    this.cancelSearchDebounce();
    this.page.update((p) => p - 1);
    this.loadItems();
  }

  nextPage(): void {
    if (this.isLastPage()) return;
    this.cancelSearchDebounce();
    this.page.update((p) => p + 1);
    this.loadItems();
  }

  syncNow(): void {
    if (this.syncing()) return;
    this.syncing.set(true);
    this.syncError.set(false);
    this.api.syncSource(this.sourceId).subscribe({
      next: () => {
        this.syncing.set(false);
        this.loadStats();
      },
      error: () => {
        this.syncing.set(false);
        this.syncError.set(true);
      },
    });
  }

  startEdit(): void {
    const s = this.stats()?.source;
    if (!s) return;
    this.editName.set(s.name);
    this.editCategory.set(s.category ?? '');
    this.editUrl.set(s.url ?? '');
    this.editNotes.set(s.notes ?? '');
    this.editAuthRequired.set(s.auth_required ?? '');
    this.editActive.set(s.active);
    this.saveError.set(null);
    this.editing.set(true);
  }

  cancelEdit(): void {
    this.editing.set(false);
    this.saveError.set(null);
  }

  saveEdit(e: Event): void {
    e.preventDefault();
    if (this.saving()) return;
    this.saving.set(true);
    this.saveError.set(null);
    this.api.updateSource(this.sourceId, {
      name: this.editName().trim(),
      category: this.editCategory().trim(),
      url: this.editUrl().trim(),
      notes: this.editNotes().trim(),
      auth_required: this.editAuthRequired().trim(),
      active: this.editActive(),
    }).subscribe({
      next: () => {
        this.saving.set(false);
        this.editing.set(false);
        this.loadStats();
      },
      error: (err: HttpErrorResponse) => {
        this.saving.set(false);
        this.saveError.set(err.error?.error ?? 'Save failed — try again.');
      },
    });
  }

  openItem(item: Item): void {
    this.pinnedItem.set(item);
  }

  // Empty string here means "let tf-chip fall back to its own severityLabel" — only the
  // News-for-unclassified-RSS case needs an override.
  chipLabel(item: Item, fetchKind: string): string {
    return severityDisplayLabel(item.severity, fetchKind) === 'News' ? 'News' : '';
  }

  // Space must activate a role="button" row the same as Enter (native <button> does this for
  // free; this custom-role <tr> doesn't). preventDefault stops the page from scrolling.
  onRowSpace(e: Event, item: Item): void {
    e.preventDefault();
    this.openItem(item);
  }

  onRowEnter(item: Item, e: MouseEvent): void {
    this.cancelHoverClose();
    this.cancelHoverOpen();
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    this.hoverOpenTimer = setTimeout(() => {
      this.hoverOpenTimer = null;
      this.hoverPos.set({
        top: rect.bottom + 6,
        left: Math.min(rect.left, window.innerWidth - HOVER_POPOVER_WIDTH - 16),
      });
      this.hoverItem.set(item);
    }, HOVER_OPEN_DELAY_MS);
  }

  onRowLeave(): void {
    this.cancelHoverOpen();
    this.cancelHoverClose();
    // Keep the popover mounted while its expanded modal (teleported to document.body, so it's
    // outside this row/preview's mouse bounds) is open — otherwise leaving it for the iframe
    // tears down tf-browser-window and force-closes the modal. Only the modal's own close
    // button/backdrop/Escape should end it; onPreviewExpandedChange(false) resumes normal close.
    if (this.previewExpanded()) return;
    this.hoverCloseTimer = setTimeout(() => {
      this.hoverCloseTimer = null;
      this.hoverItem.set(null);
    }, HOVER_CLOSE_GRACE_MS);
  }

  onPreviewEnter(): void {
    this.cancelHoverClose();
  }

  onPreviewExpandedChange(expanded: boolean): void {
    this.previewExpanded.set(expanded);
    if (!expanded) this.onRowLeave();
  }

  private cancelHoverOpen(): void {
    if (this.hoverOpenTimer !== null) { clearTimeout(this.hoverOpenTimer); this.hoverOpenTimer = null; }
  }

  private cancelHoverClose(): void {
    if (this.hoverCloseTimer !== null) { clearTimeout(this.hoverCloseTimer); this.hoverCloseTimer = null; }
  }

  closeDrawer(): void {
    this.pinnedItem.set(null);
  }

  walkDrawer(direction: -1 | 1): void {
    const current = this.pinnedItem();
    if (!current) return;
    const rows = this.items();
    const idx = rows.findIndex((r) => r.id === current.id);
    if (idx === -1) return;
    const next = rows[Math.min(Math.max(idx + direction, 0), rows.length - 1)];
    this.pinnedItem.set(next);
  }
}
