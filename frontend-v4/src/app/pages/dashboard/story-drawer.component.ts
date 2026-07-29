import {
  Component, Input, Output, EventEmitter, OnChanges, OnDestroy, SimpleChanges,
  ChangeDetectionStrategy, inject, signal,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { relativeTime, stripHtml } from '../../core/format';
import { ChipComponent } from '../../ui/chip.component';
import { SourceDotComponent } from '../../ui/source-dot.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { BrowserWindowComponent } from '../../ui/browser-window.component';
import type { FeedRow, ItemDetail, ClusterMember } from '../../core/models';

interface EntityLink { key: string; label: string; path: string[]; }

// Content stays mounted whenever the DOM node ever received a row, so the CSS transition can
// actually animate a close, not just vanish. `row` going back to null starts the slide-out;
// `displayRow` intentionally lags it by one animation frame's worth of time so there's no
// flash of empty content mid-slide.
const CONTENT_LINGER_MS = 300;

@Component({
  selector: 'tf-story-drawer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    RouterLink, ChipComponent, SourceDotComponent, EmptyStateComponent, SkeletonComponent,
    BrowserWindowComponent,
  ],
  host: {
    role: 'complementary',
    'aria-label': 'Story detail',
    '[class.open]': 'open()',
    '[attr.aria-hidden]': '!open()',
    '[attr.inert]': 'open() ? null : \'\'',
    '(document:keydown)': 'onKeydown($event)',
  },
  template: `
    @if (displayRow(); as row) {
      <header class="drawer-head">
        <tf-chip [severity]="row.severity" />
        <span class="time">{{ relativeTime(row.last_seen) }}</span>
        <button type="button" class="close" aria-label="Close story detail" (click)="closed.emit()">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
            <path d="M6 6 18 18M18 6 6 18" />
          </svg>
        </button>
      </header>

      <div class="scroll">
        <tf-browser-window
          [url]="row.link" [title]="row.title" [sourceName]="row.source_name"
          [sourceStatus]="row.source_status" [time]="relativeTime(row.last_seen)"
          [summary]="stripHtml(row.summary)"
          [allowExpand]="row.source_fetch_kind === 'rss'"
          (expandedChange)="previewExpandedChange.emit($event)"
        />

        <section class="block">
          <h3>Entities</h3>
          @if (detailLoading()) {
            <tf-skeleton [rows]="2" />
          } @else if (detailError()) {
            <tf-empty-state title="Couldn't load entity detail" reason="GET /api/items/:id failed" />
          } @else if (entities().length) {
            <div class="entities">
              @for (e of entities(); track e.key) {
                <a class="entity" [routerLink]="e.path">{{ e.label }}</a>
              }
            </div>
          } @else {
            <tf-empty-state reason="No CVEs, actors or malware families extracted for this story" />
          }
        </section>

        <section class="block">
          <h3>Sources</h3>
          <div class="source-row">
            <tf-source-dot [status]="row.source_status" [name]="row.source_name" />
            <span class="source-name">{{ row.source_name }}</span>
            <span class="source-time">{{ relativeTime(row.last_seen) }}</span>
          </div>
          @if (row.source_count > 1) {
            <!-- The feed API clusters corroborating stories under one row (source_count) but
                 only ever returns the primary item's single source. GET /api/clusters/:id/items
                 (same endpoint the Intel explorer's cluster badge already uses) breaks the
                 cluster back out into its full member list, so fetch it and render the real
                 corroborating sources instead of describing the limitation away. -->
            <p class="cluster-note">
              +{{ row.source_count - 1 }} more source{{ row.source_count > 2 ? 's' : '' }} corroborate this story.
            </p>
            @if (clusterLoading()) {
              <tf-skeleton [rows]="2" />
            } @else if (clusterError()) {
              <tf-empty-state title="Couldn't load sources" reason="GET /api/clusters/:id/items failed" />
            } @else {
              <ul class="cluster-list">
                @for (m of corroboratingSources(row); track m.item_id) {
                  <li>
                    <tf-source-dot [status]="m.source_status" [name]="m.source_name" />
                    <a [routerLink]="['/intel', m.item_id]">{{ m.source_name }}</a>
                    <span class="time">{{ relativeTime(m.published_at) }}</span>
                  </li>
                }
              </ul>
            }
          }
        </section>

        <section class="block actions">
          <a class="btn" [routerLink]="['/intel', row.item_id]">Open full record</a>
          @if (firstCve(); as cve) { <a class="btn" [routerLink]="['/cve', cve]">Jump to CVE</a> }
          @if (row.link) {
            <a class="btn secondary" [href]="row.link" target="_blank" rel="noopener noreferrer">Read at source</a>
          }
        </section>
      </div>
    }
  `,
  styles: [`
    :host {
      position: fixed; right: 0; top: 0; bottom: 0; width: min(420px, 92vw);
      background: var(--chrome); backdrop-filter: blur(34px) saturate(180%);
      z-index: var(--z-drawer);
      border-left: var(--hair) solid var(--hairline);
      display: flex; flex-direction: column;
      transform: translateX(100%);
      pointer-events: none;
      transition: transform var(--dur-drawer) var(--ease);
    }
    :host(.open) { transform: translateX(0); pointer-events: auto; }

    @media (max-width: 640px) {
      :host { width: 100vw; border-left: 0; }
    }

    @media (prefers-reduced-motion: reduce) {
      :host {
        transform: translateX(0);
        opacity: 0;
        transition: opacity var(--dur-drawer) linear;
      }
      :host(.open) { opacity: 1; }
    }

    .drawer-head {
      display: flex; align-items: center; gap: 8px; flex: none;
      padding: 14px 16px; border-bottom: var(--hair) solid var(--hairline);
    }
    .drawer-head .time { color: var(--ink-2); font-size: var(--fs-xs); }
    .close {
      margin-left: auto; appearance: none; border: 0; cursor: pointer; background: transparent;
      color: var(--ink-3); width: 24px; height: 24px; border-radius: 6px;
      display: flex; align-items: center; justify-content: center;
      transition: color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
    }
    .close:hover { color: var(--ink); background: var(--surface-2); }
    .close:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .close:active { background: var(--surface-3); }

    .scroll { overflow-y: auto; padding: 16px; flex: 1; }
    tf-browser-window { display: block; margin-bottom: 18px; }

    .block { margin-bottom: 18px; }
    .block h3 {
      margin: 0 0 8px; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2);
      text-transform: uppercase; letter-spacing: .04em;
    }

    .entities { display: flex; flex-wrap: wrap; gap: 6px; }
    .entity {
      font-size: var(--fs-xs); font-weight: 510; color: var(--ink); text-decoration: none;
      background: var(--surface-2); padding: 4px 10px; border-radius: 999px;
      transition: background var(--dur-fast) var(--ease);
    }
    .entity:hover { background: var(--surface-3); }
    .entity:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .entity:active { background: var(--surface-4); }
    /* Light theme: --surface-2 alone reads as barely-there pale gray against a white drawer —
       darker so pills/buttons read as solid controls, not washed-out tints. */
    :host-context([data-theme='light']) .entity { background: var(--surface-3); }
    :host-context([data-theme='light']) .entity:hover { background: var(--surface-4); }

    .source-row { display: flex; align-items: center; gap: 8px; font-size: var(--fs-sm); color: var(--ink); }
    .source-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .source-time { color: var(--ink-2); font-size: var(--fs-xs); }
    .cluster-note { margin: 8px 0 6px; font-size: var(--fs-xs); color: var(--ink-2); }
    .cluster-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
    .cluster-list li { display: flex; align-items: center; gap: 8px; font-size: var(--fs-xs); }
    .cluster-list a { color: var(--ink); text-decoration: none; transition: color var(--dur-fast) var(--ease); }
    .cluster-list a:hover { color: var(--accent); }
    .cluster-list a:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .cluster-list .time { color: var(--ink-2); margin-left: auto; }

    .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .btn {
      font-size: var(--fs-xs); font-weight: 590; text-decoration: none; text-align: center;
      color: var(--bg); background: var(--accent); padding: 7px 12px; border-radius: 8px;
      transition: opacity var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
    }
    .btn:hover { opacity: .88; }
    .btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .btn:active { opacity: .74; }
    .btn.secondary { color: var(--ink); background: var(--surface-2); }
    .btn.secondary:hover { background: var(--surface-3); }
    .btn.secondary:active { background: var(--surface-4); }

    /* Light theme: --accent (Aqua) at full brightness behind white text reads as pale/washed
       out rather than a solid call-to-action, and --surface-2 secondary buttons barely
       separate from the white drawer. Darker, not a token change — dark mode keeps the
       brighter Aqua button since it already has enough contrast against the dark drawer. */
    :host-context([data-theme='light']) .btn { color: #fff; background: #0f9e90; }
    :host-context([data-theme='light']) .btn.secondary { color: var(--ink); background: var(--surface-3); }
    :host-context([data-theme='light']) .btn.secondary:hover { background: var(--surface-4); }
  `],
})
export class StoryDrawerComponent implements OnChanges, OnDestroy {
  @Input() row: FeedRow | null = null;
  @Input() pinned = false;

  @Output() closed = new EventEmitter<void>();
  /** -1 walks to the previous row, +1 to the next. Only meaningful while pinned. */
  @Output() walk = new EventEmitter<-1 | 1>();
  // Forwards tf-browser-window's own expandedChange so a hover-driven host (e.g. lane-live's
  // pause-on-hover preview) knows its iframe modal is open and can hold the drawer open instead
  // of tearing it (and the modal inside it) down the moment the cursor drifts off the row.
  @Output() previewExpandedChange = new EventEmitter<boolean>();

  private api = inject(ApiService);

  open = signal(false);
  displayRow = signal<FeedRow | null>(null);
  detail = signal<ItemDetail | null>(null);
  detailLoading = signal(false);
  detailError = signal(false);

  clusterMembers = signal<ClusterMember[]>([]);
  clusterLoading = signal(false);
  clusterError = signal(false);

  private lastFetchedItemId: number | null = null;
  private lastFetchedClusterId: number | null = null;
  private lingerTimer: ReturnType<typeof setTimeout> | null = null;
  private fetchToken = 0;
  private clusterFetchToken = 0;

  relativeTime = relativeTime;
  stripHtml = stripHtml;

  ngOnChanges(changes: SimpleChanges): void {
    if (!('row' in changes)) return;
    const row = this.row;

    if (row) {
      if (this.lingerTimer !== null) { clearTimeout(this.lingerTimer); this.lingerTimer = null; }
      this.displayRow.set(row);
      this.open.set(true);
      if (row.item_id !== this.lastFetchedItemId) this.fetchDetail(row.item_id);
      if (row.source_count > 1) {
        if (row.cluster_id !== this.lastFetchedClusterId) this.fetchClusterMembers(row.cluster_id);
      } else {
        this.lastFetchedClusterId = null;
        this.clusterMembers.set([]);
        this.clusterError.set(false);
        this.clusterLoading.set(false);
      }
    } else {
      this.open.set(false);
      if (this.lingerTimer !== null) clearTimeout(this.lingerTimer);
      this.lingerTimer = setTimeout(() => {
        this.lingerTimer = null;
        this.displayRow.set(null);
      }, CONTENT_LINGER_MS);
    }
  }

  ngOnDestroy(): void {
    if (this.lingerTimer !== null) clearTimeout(this.lingerTimer);
  }

  onKeydown(e: KeyboardEvent): void {
    if (!this.pinned) return;
    if (e.key === 'Escape') { e.stopPropagation(); this.closed.emit(); }
    else if (e.key === 'ArrowLeft') { e.preventDefault(); this.walk.emit(-1); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); this.walk.emit(1); }
  }

  entities(): EntityLink[] {
    const d = this.detail();
    if (!d) return [];
    return [
      ...d.cves.map((c): EntityLink => ({ key: `cve-${c}`, label: c, path: ['/cve', c] })),
      ...d.actors.map((a): EntityLink => ({ key: `actor-${a}`, label: a, path: ['/actor', a] })),
      ...d.families.map((f): EntityLink => ({ key: `family-${f}`, label: f, path: ['/malware', f] })),
    ];
  }

  firstCve(): string | null {
    return this.detail()?.cves[0] ?? null;
  }

  // The primary source is already rendered in the row above (from `row` itself, no fetch
  // needed); this list is only the *other* cluster members, so the same source never appears
  // twice in the Sources block.
  corroboratingSources(row: FeedRow): ClusterMember[] {
    return this.clusterMembers().filter((m) => m.item_id !== row.item_id);
  }

  private fetchDetail(itemId: number): void {
    this.lastFetchedItemId = itemId;
    const token = ++this.fetchToken;
    this.detailLoading.set(true);
    this.detailError.set(false);
    this.api.item(itemId).subscribe({
      next: (d) => {
        if (token !== this.fetchToken) return;
        this.detail.set(d);
        this.detailLoading.set(false);
      },
      error: () => {
        if (token !== this.fetchToken) return;
        this.detailError.set(true);
        this.detailLoading.set(false);
      },
    });
  }

  private fetchClusterMembers(clusterId: number): void {
    this.lastFetchedClusterId = clusterId;
    const token = ++this.clusterFetchToken;
    this.clusterLoading.set(true);
    this.clusterError.set(false);
    this.api.clusterItems(clusterId).subscribe({
      next: (members) => {
        if (token !== this.clusterFetchToken) return;
        this.clusterMembers.set(members);
        this.clusterLoading.set(false);
      },
      error: () => {
        if (token !== this.clusterFetchToken) return;
        this.clusterError.set(true);
        this.clusterLoading.set(false);
      },
    });
  }
}
