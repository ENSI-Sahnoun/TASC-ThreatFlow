import { Component, ChangeDetectionStrategy, ElementRef, ViewChild, OnInit, OnDestroy } from '@angular/core';
import { FeedRowComponent } from '../dashboard/feed-row.component';
import { StoryDrawerComponent } from '../dashboard/story-drawer.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { FeedStreamBase } from '../dashboard/feed-stream-base';

// The backend's own cap on GET /api/feed (see server/queries.js#feed) — the most rows this page
// could ever show regardless of what it asks for.
const FEED_LIMIT = 200;

// Full-page version of the dashboard's "Live intel" lane, routed at /live. Same live-polling,
// hover-preview/pin/keyboard-walk drawer behavior (see FeedStreamBase) as the lane, just without
// the lane's row cap — this is where its "Show more" link lands.
@Component({
  selector: 'tf-page-live-feed',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FeedRowComponent, StoryDrawerComponent, EmptyStateComponent, SkeletonComponent],
  template: `
    <div class="live-page">
      <header class="page-head">
        <h1 class="tf-heading">Live intel</h1>
        <p class="tagline">Everything as it lands, up to the last {{ feedLimitDisplay }} stories.</p>
      </header>

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
          <tf-skeleton [rows]="10" />
        } @else if (loadError()) {
          <tf-empty-state title="Live feed unavailable" reason="GET /api/feed failed" />
        } @else if (visibleRows().length === 0) {
          <tf-empty-state reason="No recent intel in the current window" />
        } @else {
          @for (row of visibleRows(); track row.cluster_id) {
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
    </div>

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
    .live-page { display: flex; flex-direction: column; gap: 16px; }
    .page-head { display: flex; flex-direction: column; gap: 2px; }
    .page-head h1 { margin: 0; font-size: var(--fs-xl); color: var(--ink); }
    .page-head .tagline { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }

    .lane-sub { display: flex; align-items: center; gap: 8px; min-height: 20px; }
    .since { font-size: var(--fs-xs); color: var(--ink-2); }
    .pause-pill, .stale-pill {
      font-size: var(--fs-xs); font-weight: 590; padding: 2px 8px; border-radius: 999px;
    }
    .pause-pill { color: var(--ink); background: var(--accent-soft); }
    .stale-pill { color: var(--ink); background: color-mix(in srgb, var(--sev-high) 20%, transparent); }
    .rows { display: flex; flex-direction: column; gap: 2px; }
  `],
})
export class LiveFeedPageComponent extends FeedStreamBase implements OnInit, OnDestroy {
  @ViewChild('drawer', { read: ElementRef }) private drawerElRef?: ElementRef<HTMLElement>;
  protected override get drawerEl(): ElementRef<HTMLElement> | undefined { return this.drawerElRef; }
  protected override get feedLimit(): number { return FEED_LIMIT; }

  readonly feedLimitDisplay = FEED_LIMIT;

  ngOnInit(): void {
    this.initWatermark();
  }

  ngOnDestroy(): void {
    this.teardown();
  }
}
