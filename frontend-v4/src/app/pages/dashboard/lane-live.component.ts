import {
  Component, ChangeDetectionStrategy, ElementRef, ViewChild, OnDestroy, OnInit,
  inject, signal, computed, effect,
} from '@angular/core';
import { LaneComponent } from './lane.component';
import { FeedRowComponent } from './feed-row.component';
import { StoryDrawerComponent } from './story-drawer.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { ApiService } from '../../core/api.service';
import { pollingSignal } from '../../core/poll';
import { readWatermark, writeWatermark, countNewSince } from '../../core/watermark';
import type { FeedRow } from '../../core/models';

const OPEN_DELAY_MS = 200;
const CLOSE_GRACE_MS = 150;
const FEED_INTERVAL_MS = 15_000;
// Unbounded, this lane just kept growing past whatever the neighboring lane's panels added up
// to — a "Show more" cutoff instead of the full 50-row feed page keeps the dashboard's two
// columns roughly level.
const INITIAL_ROW_COUNT = 20;

interface Point { x: number; y: number; }

// The live lane: streams `/api/feed` every 15s, freezes what's rendered while the analyst is
// reading a row (mouse over the list, or the drawer pinned open), and surfaces what arrived in
// the meantime as a count rather than silently splicing rows out from under the cursor.
//
// Design note: `pollingSignal`'s own `paused` suspension is deliberately NOT wired to hover here.
// The lane is still "live" underneath a hover — the network keeps polling in the background so
// the "paused · N new" pill has something real to report *while* the analyst is still reading,
// not just a flash of a number the instant they look away. What hover/pin actually gate is only
// this component's own splice of fetched rows into the rendered list (`visibleRows`).
@Component({
  selector: 'tf-lane-live',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LaneComponent, FeedRowComponent, StoryDrawerComponent, EmptyStateComponent, SkeletonComponent],
  template: `
    <tf-lane title="Live intel" accent="var(--accent)">
      <div class="lane-sub">
        @if (newSinceWatermark() > 0) {
          <span class="since">{{ newSinceWatermark() }} new since {{ watermarkClock() }}</span>
        }
        @if (paused()) {
          <span class="pause-pill">paused · {{ queuedCount() }} new</span>
        }
        @if (feed.stale() && visibleRows().length) {
          <span class="stale-pill" title="Last refresh failed — showing last known data">stale</span>
        }
      </div>

      <div class="rows" (mouseenter)="onContainerEnter()" (mouseleave)="onContainerLeave($event)">
        @if (loading()) {
          <tf-skeleton [rows]="6" />
        } @else if (loadError()) {
          <tf-empty-state title="Live feed unavailable" reason="GET /api/feed failed" />
        } @else if (visibleRows().length === 0) {
          <tf-empty-state reason="No recent intel in the current window" />
        } @else {
          @for (row of shownRows(); track row.cluster_id) {
            <tf-feed-row
              [row]="row"
              [isNew]="isRowNew(row)"
              (mouseenter)="onRowEnter(row)"
              (mouseleave)="onRowLeave($event)"
              (focus)="onRowFocus(row)"
              (blur)="onRowBlur()"
              (click)="onRowClick(row)"
              (keydown.enter)="onRowClick(row)"
              (keydown.space)="onRowSpace($event, row)"
            />
          }
        }
      </div>
      @if (hiddenRowCount() > 0) {
        <button type="button" class="show-more" (click)="showAllRows()">
          Show {{ hiddenRowCount() }} more
        </button>
      }
    </tf-lane>

    <tf-story-drawer
      #drawer
      [row]="drawerRow()"
      [pinned]="pinned()"
      (mouseenter)="onDrawerEnter()"
      (mouseleave)="onDrawerLeave($event)"
      (closed)="onDrawerClosed()"
      (walk)="onWalk($event)"
      (previewExpandedChange)="onPreviewExpandedChange($event)"
    />
  `,
  styles: [`
    .lane-sub { display: flex; align-items: center; gap: 8px; min-height: 20px; }
    .since { font-size: var(--fs-xs); color: var(--ink-2); }
    .pause-pill, .stale-pill {
      font-size: var(--fs-xs); font-weight: 590; padding: 2px 8px; border-radius: 999px;
    }
    .pause-pill { color: var(--ink); background: var(--accent-soft); }
    .stale-pill { color: var(--ink); background: color-mix(in srgb, var(--sev-high) 20%, transparent); }
    .rows { display: flex; flex-direction: column; gap: 2px; }
    .show-more {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink-2); background: var(--surface-2); border: 0; align-self: flex-start;
      padding: 6px 12px; border-radius: 8px; margin-top: 4px;
      transition: color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
    }
    .show-more:hover { color: var(--ink); background: var(--surface-3); }
    .show-more:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .show-more:active { background: var(--surface-4); }
    @media (prefers-reduced-motion: reduce) { .show-more { transition: none; } }
  `],
})
export class LaneLiveComponent implements OnInit, OnDestroy {
  private api = inject(ApiService);

  @ViewChild('drawer', { read: ElementRef }) private drawerEl?: ElementRef<HTMLElement>;

  feed = pollingSignal<FeedRow[]>(() => this.api.feed(), FEED_INTERVAL_MS, () => false);

  visibleRows = signal<FeedRow[]>([]);
  pointerActive = signal(false);
  hoverRow = signal<FeedRow | null>(null);
  pinnedRow = signal<FeedRow | null>(null);
  previewExpanded = signal(false);
  rowLimit = signal(INITIAL_ROW_COUNT);

  pinned = computed(() => this.pinnedRow() !== null);
  paused = computed(() => this.pointerActive() || this.pinned());
  drawerRow = computed(() => this.pinnedRow() ?? this.hoverRow());
  shownRows = computed(() => this.visibleRows().slice(0, this.rowLimit()));
  hiddenRowCount = computed(() => Math.max(0, this.visibleRows().length - this.rowLimit()));

  loading = computed(() => this.feed.value() === null && !this.feed.stale());
  loadError = computed(() => this.feed.value() === null && this.feed.stale());

  queuedCount = computed(() => {
    const latest = this.feed.value();
    if (!latest) return 0;
    const visibleIds = new Set(this.visibleRows().map((r) => r.cluster_id));
    return latest.filter((r) => !visibleIds.has(r.cluster_id)).length;
  });

  private watermark: string | null = null;

  newSinceWatermark = computed(() => {
    const latest = this.feed.value();
    if (!latest || !this.watermark) return 0;
    return countNewSince(latest.map((r) => ({ published_at: r.last_seen })), this.watermark);
  });

  private openDelayTimer: ReturnType<typeof setTimeout> | null = null;
  private closeGraceTimer: ReturnType<typeof setTimeout> | null = null;
  private closeGraceCleanup: (() => void) | null = null;

  constructor() {
    // The stream keeps flowing in the background at all times; only splice it into view when
    // nothing is actively being read.
    effect(() => {
      const latest = this.feed.value();
      if (latest && !this.paused()) this.visibleRows.set(latest);
    });
  }

  ngOnInit(): void {
    // "Since you last looked": read the prior visit's watermark for the badge, then stamp a
    // fresh one for next time. Deliberately read-then-write here (not on destroy) so a mid-
    // session refresh doesn't inflate the count with items that arrived during this same visit.
    this.watermark = readWatermark(localStorage);
    writeWatermark(localStorage, new Date().toISOString());
  }

  ngOnDestroy(): void {
    this.feed.destroy();
    this.cancelOpenDelay();
    this.cancelCloseGrace();
  }

  isRowNew(row: FeedRow): boolean {
    if (!this.watermark || !row.last_seen) return false;
    const mark = Date.parse(this.watermark);
    const seen = Date.parse(row.last_seen);
    return !Number.isNaN(mark) && !Number.isNaN(seen) && seen > mark;
  }

  watermarkClock(): string {
    if (!this.watermark) return '';
    const d = new Date(this.watermark);
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
  }

  // --- Row-list hover (pause-on-hover) ---------------------------------------------------

  onContainerEnter(): void {
    this.pointerActive.set(true);
    this.cancelCloseGrace();
  }

  onContainerLeave(e: MouseEvent): void {
    this.maybeStartCloseGrace(e);
  }

  onRowEnter(row: FeedRow): void {
    this.pointerActive.set(true);
    this.cancelCloseGrace();
    if (this.pinned()) return;
    this.cancelOpenDelay();
    this.openDelayTimer = setTimeout(() => { this.hoverRow.set(row); this.openDelayTimer = null; }, OPEN_DELAY_MS);
  }

  onRowLeave(e: MouseEvent): void {
    this.cancelOpenDelay();
    this.maybeStartCloseGrace(e);
  }

  onRowFocus(row: FeedRow): void {
    if (this.pinned()) return;
    this.pointerActive.set(true);
    this.cancelOpenDelay();
    this.cancelCloseGrace();
    // Keyboard focus is always deliberate — no need for the 200ms brush-by delay hover gets.
    this.hoverRow.set(row);
  }

  onRowBlur(): void {
    if (this.pinned()) return;
    this.maybeStartCloseGrace();
  }

  onRowClick(row: FeedRow): void {
    this.cancelOpenDelay();
    this.cancelCloseGrace();
    this.pointerActive.set(true);
    this.hoverRow.set(row);
    this.pinnedRow.set(row);
  }

  // Space must activate a role="button" row the same as Enter (native <button> does this for
  // free; this custom-role host doesn't). preventDefault stops the page from scrolling.
  onRowSpace(e: Event, row: FeedRow): void {
    e.preventDefault();
    this.onRowClick(row);
  }

  showAllRows(): void {
    this.rowLimit.set(this.visibleRows().length);
  }

  // --- Drawer hover (the drawer is itself part of the same hoverable surface) ------------

  onDrawerEnter(): void {
    this.pointerActive.set(true);
    this.cancelCloseGrace();
  }

  onDrawerLeave(e: MouseEvent): void {
    this.maybeStartCloseGrace(e);
  }

  onDrawerClosed(): void {
    this.pinnedRow.set(null);
    this.hoverRow.set(null);
    this.cancelOpenDelay();
    this.cancelCloseGrace();
    this.flushQueue();
  }

  onPreviewExpandedChange(expanded: boolean): void {
    this.previewExpanded.set(expanded);
    // The modal is teleported into document.body (see BrowserWindowComponent), so it sits
    // outside the row/drawer's mouse bounds entirely — moving the cursor onto it looks like
    // "left everything" to the hover machinery below and used to tear the drawer (and the open
    // modal inside it) down mid-read. Once it closes, resume normal close-grace tracking.
    if (!expanded) this.maybeStartCloseGrace();
  }

  onWalk(direction: -1 | 1): void {
    const current = this.pinnedRow();
    if (!current) return;
    const rows = this.visibleRows();
    const idx = rows.findIndex((r) => r.cluster_id === current.cluster_id);
    if (idx === -1) return;
    const next = rows[Math.min(Math.max(idx + direction, 0), rows.length - 1)];
    this.pinnedRow.set(next);
    this.hoverRow.set(next);
  }

  // --- Shared close-grace / safe-triangle -------------------------------------------------

  private maybeStartCloseGrace(initial?: MouseEvent): void {
    if (this.pinned() || this.previewExpanded()) return;
    this.cancelCloseGrace();

    const positions: Point[] = initial ? [{ x: initial.clientX, y: initial.clientY }] : [];
    const onMove = (e: MouseEvent) => {
      positions.push({ x: e.clientX, y: e.clientY });
      if (positions.length > 2) positions.shift();
      if (positions.length === 2 && this.movingTowardDrawer(positions[0], positions[1])) {
        this.cancelCloseGrace();
      }
    };
    document.addEventListener('mousemove', onMove);
    this.closeGraceCleanup = () => document.removeEventListener('mousemove', onMove);

    this.closeGraceTimer = setTimeout(() => {
      this.closeGraceTimer = null;
      this.closeGraceCleanup?.();
      this.closeGraceCleanup = null;
      this.hoverRow.set(null);
      this.pointerActive.set(false);
      this.flushQueue();
    }, CLOSE_GRACE_MS);
  }

  private cancelOpenDelay(): void {
    if (this.openDelayTimer !== null) { clearTimeout(this.openDelayTimer); this.openDelayTimer = null; }
  }

  private cancelCloseGrace(): void {
    if (this.closeGraceTimer !== null) { clearTimeout(this.closeGraceTimer); this.closeGraceTimer = null; }
    this.closeGraceCleanup?.();
    this.closeGraceCleanup = null;
  }

  private flushQueue(): void {
    const latest = this.feed.value();
    if (latest) this.visibleRows.set(latest);
  }

  // Safe-triangle: the pointer is "heading for" the drawer if projecting its last movement
  // vector forward lands inside the drawer's current bounding box. Only rightward motion can
  // approach it since the drawer is pinned to the viewport's right edge.
  private movingTowardDrawer(p0: Point, p1: Point): boolean {
    const rect = this.drawerEl?.nativeElement.getBoundingClientRect();
    if (!rect) return false;
    const dx = p1.x - p0.x;
    const dy = p1.y - p0.y;
    if (dx <= 0) return false;
    const len = Math.hypot(dx, dy) || 1;
    const ux = dx / len;
    const uy = dy / len;
    for (let dist = 20; dist <= 600; dist += 40) {
      const x = p1.x + ux * dist;
      const y = p1.y + uy * dist;
      if (x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom) return true;
    }
    return false;
  }
}
