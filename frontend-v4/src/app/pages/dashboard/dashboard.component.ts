import { Component, ChangeDetectionStrategy, OnInit, inject, signal, effect } from '@angular/core';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { SyncService } from '../../core/sync.service';
import { KpiStripComponent } from './kpi-strip.component';
import { LaneExploitedComponent } from './lane-exploited.component';
import { LaneSpreadingComponent } from './lane-spreading.component';
import { LaneLiveComponent } from './lane-live.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import type { DashboardStats } from '../../core/models';

// The routed "/" page. Fetches DashboardStats exactly once and hands it down to the KPI strip
// and the first two lanes as an `@Input` — they never fetch it themselves. The live lane is the
// one exception: it owns its own polling loop against `/api/feed` and takes no `stats` input.
@Component({
  selector: 'tf-page-dashboard',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [KpiStripComponent, LaneExploitedComponent, LaneSpreadingComponent, LaneLiveComponent, SkeletonComponent],
  template: `
    <header class="page-head">
      <div class="page-head-row">
        <div>
          <h1 class="tf-heading">Dashboard</h1>
          <p class="tagline">Cybersecurity, made a business enabler — no compromises.</p>
        </div>
        <div class="sync-ctl">
          <button type="button" class="sync-btn" [disabled]="sync.syncing()" (click)="syncAll()">
            @if (sync.syncing()) { Syncing… } @else { Sync all sources }
          </button>
          @if (sync.syncResult(); as r) {
            <span class="sync-result" [class.err]="r.fail > 0">
              {{ r.ok }}/{{ r.ok + r.fail }} synced
            </span>
          }
          @if (sync.syncError()) {
            <span class="sync-result err">Sync failed</span>
          }
        </div>
      </div>
    </header>
    @if (sync.syncing() && !sync.overlayDismissed()) {
      <div class="sync-overlay" role="status" aria-live="polite">
        <div class="sync-logo" [innerHTML]="sync.logoSvg()"></div>
        <p>Syncing sources…</p>
        <button type="button" class="overlay-dismiss" (click)="sync.dismissOverlay()">Continue in background</button>
      </div>
    }
    @if (loading()) {
      <tf-skeleton [rows]="8" />
    } @else if (error()) {
      <div class="dash-error">
        <p class="t">Couldn't load the dashboard</p>
        <p class="r">GET /api/stats/dashboard failed</p>
        <button type="button" (click)="load()">Retry</button>
      </div>
    } @else if (stats()) {
      <tf-kpi-strip [stats]="stats()!" />
      <div class="lanes">
        <tf-lane-exploited [stats]="stats()!" />
        <tf-lane-spreading [stats]="stats()!" />
        <tf-lane-live />
      </div>
    }
  `,
  styles: [`
    :host { display: flex; flex-direction: column; gap: 20px; }
    .page-head { display: flex; flex-direction: column; gap: 2px; }
    .page-head h1 { margin: 0; font-size: var(--fs-xl); color: var(--ink); }
    .page-head .tagline { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }
    .page-head-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
    .sync-ctl { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
    .sync-btn {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0;
      padding: 6px 14px; border-radius: 8px;
      display: inline-flex; align-items: center; gap: 6px;
      transition: opacity var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    .sync-btn:hover:not(:disabled) { opacity: .88; }
    .sync-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .sync-btn:active:not(:disabled) { opacity: .74; transform: scale(.97); }
    .sync-btn:disabled { cursor: default; opacity: .7; }
    .sync-result { font-size: var(--fs-xs); color: var(--ink-2); }
    .sync-result.err { color: var(--danger, #d33); }
    .sync-overlay {
      position: fixed; inset: 0; z-index: var(--z-modal);
      display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px;
      background: color-mix(in srgb, var(--bg) 80%, transparent);
      backdrop-filter: blur(8px);
    }
    .sync-overlay p { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }
    .overlay-dismiss {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs);
      color: var(--ink-2); background: transparent; border: var(--hair) solid var(--hairline);
      padding: 5px 12px; border-radius: 8px;
      transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
    }
    .overlay-dismiss:hover { color: var(--ink); border-color: var(--ink-2); }
    .overlay-dismiss:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .sync-logo { width: 72px; height: 100px; }
    /* [innerHTML] content is raw DOM Angular never compiled, so it carries none of the
       component's _ngcontent scoping attribute — plain scoped selectors can't reach it.
       ::ng-deep drops that attribute requirement for the rest of the selector. */
    .sync-logo ::ng-deep svg { width: 100%; height: 100%; display: block; }
    /* The outline (stroke) is always fully drawn and always visible — only the fill breathes
       between transparent and solid. Earlier versions animated stroke-dashoffset (draw from
       nothing) and opacity (fade in/out), which read as the mark vanishing each cycle; this
       keeps the shape permanently on screen and only ever loses its *color*, not its presence. */
    .sync-logo ::ng-deep .logo-path {
      fill: var(--accent); stroke: var(--accent); stroke-opacity: 1; stroke-width: 3;
      stroke-linecap: round; stroke-linejoin: round;
      animation: logo-pulse 1.6s linear infinite;
    }
    /* Solid (filled) is the resting state and holds most of the cycle; the outline-only look is
       a quick dip, not an equal partner — swapped from the original even 50/50 alternate.
       Per-keyframe timing-function (not one curve for the whole animation) is what keeps it
       fluid: the flat hold before the dip ends at zero slope, so the dip-down leg starts with
       ease-in (also zero slope at its start) to join it with no kink; the dip-up leg ends with
       ease-out (zero slope at its end) to join the next flat hold the same way. One ease-out
       across the whole loop — the first version — put a steep slope right where a flat hold
       ended, which reads as a snap, not a breath. */
    @keyframes logo-pulse {
      0%   { fill-opacity: 1; }
      62%  { fill-opacity: 1; animation-timing-function: ease-in; }
      80%  { fill-opacity: .12; animation-timing-function: ease-out; }
      100% { fill-opacity: 1; }
    }
    @media (prefers-reduced-motion: reduce) {
      .sync-logo ::ng-deep .logo-path { animation: none; fill-opacity: 1; }
    }
    .lanes {
      display: grid;
      /* min(420px, 100%) — not a bare 420px — so the single remaining column can still shrink
         to fit a viewport narrower than 420px+padding (e.g. 390px) instead of forcing the grid
         wider than its container and scrolling the whole page sideways. */
      grid-template-columns: repeat(auto-fit, minmax(min(420px, 100%), 1fr));
      gap: 16px;
    }
    .dash-error {
      display: flex; flex-direction: column; align-items: center; gap: 8px;
      min-height: 200px; justify-content: center; text-align: center; padding: 16px;
    }
    .t { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    .r { margin: 0; font-size: var(--fs-xs); color: var(--ink-2);
         background: var(--surface-2); padding: 4px 10px; border-radius: 6px; }
    button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0;
      padding: 6px 14px; border-radius: 8px;
      transition: opacity var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    button:hover { opacity: .88; }
    button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    button:active { opacity: .74; transform: scale(.97); }
    @media (prefers-reduced-motion: reduce) { button, .sync-btn { transition: none; } }
  `],
})
export class DashboardComponent implements OnInit {
  private api = inject(ApiService);
  private profileService = inject(ProfileService);
  sync = inject(SyncService);

  stats = signal<DashboardStats | null>(null);
  loading = signal(true);
  error = signal(false);

  constructor() {
    // GET /api/stats/dashboard carries no profile/relevance data today — this wiring is a no-op
    // now and exists so a future personalized dashboard figure doesn't silently need it added.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      this.load();
    });
  }

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(false);
    this.api.dashboard().subscribe({
      next: (d) => {
        this.stats.set(d);
        this.loading.set(false);
      },
      error: () => {
        this.error.set(true);
        this.loading.set(false);
      },
    });
  }

  syncAll(): void {
    this.sync.syncAll(() => this.load());
  }
}
