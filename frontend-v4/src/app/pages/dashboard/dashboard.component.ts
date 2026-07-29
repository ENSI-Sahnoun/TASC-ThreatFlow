import { Component, ChangeDetectionStrategy, OnInit, inject, signal } from '@angular/core';
import { ApiService } from '../../core/api.service';
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
          <button type="button" class="sync-btn" [disabled]="syncing()" (click)="syncAll()">
            @if (syncing()) {
              <span class="spinner" aria-hidden="true"></span> Syncing…
            } @else {
              Sync all sources
            }
          </button>
          @if (syncResult(); as r) {
            <span class="sync-result" [class.err]="r.fail > 0">
              {{ r.ok }}/{{ r.ok + r.fail }} synced
            </span>
          }
          @if (syncError()) {
            <span class="sync-result err">Sync failed</span>
          }
        </div>
      </div>
    </header>
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
      transition: opacity var(--dur-fast) var(--ease);
    }
    .sync-btn:hover:not(:disabled) { opacity: .88; }
    .sync-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .sync-btn:active:not(:disabled) { opacity: .74; }
    .sync-btn:disabled { cursor: default; opacity: .7; }
    .sync-result { font-size: var(--fs-xs); color: var(--ink-2); }
    .sync-result.err { color: var(--danger, #d33); }
    .spinner {
      width: 10px; height: 10px; border-radius: 50%;
      border: 2px solid currentColor; border-top-color: transparent;
      animation: spin .7s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    @media (prefers-reduced-motion: reduce) { .spinner { animation-duration: 1.4s; } }
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
      transition: opacity var(--dur-fast) var(--ease);
    }
    button:hover { opacity: .88; }
    button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    button:active { opacity: .74; }
    @media (prefers-reduced-motion: reduce) { button { transition: none; } }
  `],
})
export class DashboardComponent implements OnInit {
  private api = inject(ApiService);

  stats = signal<DashboardStats | null>(null);
  loading = signal(true);
  error = signal(false);

  syncing = signal(false);
  syncResult = signal<{ ok: number; fail: number } | null>(null);
  syncError = signal(false);

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
    this.syncing.set(true);
    this.syncResult.set(null);
    this.syncError.set(false);
    this.api.syncAll().subscribe({
      next: (res) => {
        const fail = res.results.filter((r) => r.error).length;
        this.syncResult.set({ ok: res.results.length - fail, fail });
        this.syncing.set(false);
        this.load();
      },
      error: () => {
        this.syncing.set(false);
        this.syncError.set(true);
      },
    });
  }
}
