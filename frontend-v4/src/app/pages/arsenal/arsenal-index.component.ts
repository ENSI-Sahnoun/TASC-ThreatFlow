import { Component, ChangeDetectionStrategy, OnInit, inject, signal, computed, effect } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { SourceDotComponent } from '../../ui/source-dot.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { relativeTime, sourceHealth, needsKey, statusLabel } from '../../core/format';
import type { Source } from '../../core/models';

const ALL = 'All';
type HealthFilter = 'All' | 'ok' | 'error' | 'unsupported' | 'never' | 'needs-key';

interface CategoryGroup { category: string; sources: Source[]; }

function uniqueSorted(values: Iterable<string>): string[] {
  return [ALL, ...[...new Set(values)].sort((a, b) => a.localeCompare(b))];
}

// The routed "/arsenal" page — the full 43-source catalog, grouped by category so the shape of
// the catalog stays visible instead of one uniform 43-card wall. Broken/needs-key sources render
// inline with the reason rather than being hidden or silently blended in with healthy ones.
@Component({
  selector: 'tf-page-arsenal-index',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, SourceDotComponent, SkeletonComponent],
  template: `
    <header class="page-head">
      <h1 class="tf-heading">Arsenal</h1>
      <p class="tagline">Every source, tracked. Pragmatic, not perfect — and we say so.</p>
    </header>
    @if (loading()) {
      <tf-skeleton [rows]="10" />
    } @else if (error()) {
      <div class="arsenal-error">
        <p class="t">Couldn't load the source catalog</p>
        <p class="r">GET /api/sources failed</p>
        <button type="button" (click)="load()">Retry</button>
      </div>
    } @else {
      <div class="filters">
        <label>
          <span>Category</span>
          <select [value]="category()" (change)="category.set($any($event.target).value)">
            @for (c of categories(); track c) { <option [value]="c">{{ c }}</option> }
          </select>
        </label>
        <label>
          <span>Feed kind</span>
          <select [value]="feedKind()" (change)="feedKind.set($any($event.target).value)">
            @for (k of feedKinds(); track k) { <option [value]="k">{{ k }}</option> }
          </select>
        </label>
        <label>
          <span>Health</span>
          <select [value]="health()" (change)="health.set($any($event.target).value)">
            @for (h of healthOptions; track h.value) { <option [value]="h.value">{{ h.label }}</option> }
          </select>
        </label>
        <p class="count">{{ filteredCount() }} of {{ sources().length }} sources</p>
      </div>

      @if (filteredCount() === 0) {
        <p class="none">No sources match these filters.</p>
      }

      @for (group of grouped(); track group.category) {
        <section class="group">
          <h2>{{ group.category }} <span class="n">{{ group.sources.length }}</span></h2>
          <div class="grid">
            @for (s of group.sources; track s.id) {
              <a class="card" [class.broken]="sourceHealth(s.last_status) === 'error'" [routerLink]="['/arsenal', s.id]">
                <header>
                  <tf-source-dot [status]="s.last_status" [name]="s.name" />
                  <span class="name">{{ s.name }}</span>
                </header>
                <dl>
                  <div><dt>Feed kind</dt><dd>{{ s.fetch_kind }}</dd></div>
                  <div><dt>Tier</dt><dd>{{ s.tier ?? 'unknown' }}</dd></div>
                  <div><dt>Last sync</dt><dd>{{ relativeTime(s.last_synced_at) }}</dd></div>
                </dl>
                <p class="status" [class]="statusLabel(s).kind">{{ statusLabel(s).text }}</p>
              </a>
            }
          </div>
        </section>
      }
    }
  `,
  styles: [`
    :host { display: flex; flex-direction: column; gap: 20px; }
    .page-head { display: flex; flex-direction: column; gap: 2px; }
    .page-head h1 { margin: 0; font-size: var(--fs-xl); color: var(--ink); }
    .page-head .tagline { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }

    .filters {
      display: flex; align-items: flex-end; gap: 16px; flex-wrap: wrap;
    }
    .filters label {
      display: flex; flex-direction: column; gap: 4px;
      font-size: var(--fs-xs); color: var(--ink-2);
    }
    .filters select {
      appearance: none; font: inherit; font-size: var(--fs-sm); color: var(--ink);
      background: var(--surface-2); border: var(--hair) solid var(--hairline);
      border-radius: 8px; padding: 6px 10px; cursor: pointer;
      transition: background var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
    }
    .filters select:hover { background: var(--surface-3); }
    .filters select:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .count { margin: 0 0 0 auto; font-size: var(--fs-xs); color: var(--ink-2); }
    .none { color: var(--ink-2); font-size: var(--fs-sm); }

    .group { display: flex; flex-direction: column; gap: 10px; }
    .group h2 {
      margin: 0; font-size: var(--fs-sm); font-weight: 600; color: var(--ink);
      letter-spacing: -.01em; display: flex; align-items: center; gap: 8px;
    }
    .group h2 .n {
      font-size: var(--fs-xs); font-weight: 510; color: var(--ink-2);
      background: var(--surface-2); border-radius: 999px; padding: 1px 8px;
    }

    .grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px;
    }

    /* Cards live in a scrolling grid — surface, no blur, per the chrome-only-blur constraint. */
    .card {
      display: flex; flex-direction: column; gap: 10px;
      background: var(--surface); border-radius: var(--radius-card);
      border: var(--hair) solid var(--hairline);
      padding: 12px 14px; text-decoration: none; color: inherit;
      transition: background var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease), transform var(--dur-fast) var(--ease);
    }
    .card:hover { background: var(--surface-2); transform: translateY(-1px); }
    .card:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .card:active { background: var(--surface-3); transform: translateY(0); }
    .card.broken { border-color: color-mix(in srgb, var(--sev-critical) 30%, var(--hairline)); }

    .card header { display: flex; align-items: center; gap: 8px; min-width: 0; }
    .name {
      font-size: var(--fs-sm); font-weight: 590; color: var(--ink);
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }

    dl { display: flex; flex-direction: column; gap: 3px; margin: 0; }
    dl div { display: flex; gap: 6px; font-size: var(--fs-xs); }
    dt { color: var(--ink-2); flex: none; min-width: 6.5ch; }
    dd { margin: 0; color: var(--ink-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .status {
      margin: 0; font-size: var(--fs-xs); font-weight: 510;
      padding: 4px 8px; border-radius: 6px; background: var(--surface-2); color: var(--ink-2);
    }
    .status.error {
      color: var(--ink); background: color-mix(in srgb, var(--sev-critical) 16%, transparent);
    }
    .status.needs-key {
      color: var(--ink); background: color-mix(in srgb, var(--sev-medium) 16%, transparent);
    }

    .arsenal-error {
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

    @media (prefers-reduced-motion: reduce) {
      .filters select, .card, button { transition: none; }
      .card:hover { transform: none; }
    }
  `],
})
export class ArsenalIndexComponent implements OnInit {
  private api = inject(ApiService);
  private profileService = inject(ProfileService);

  private allSources = signal<Source[]>([]);
  loading = signal(true);
  error = signal(false);

  constructor() {
    // GET /api/sources carries no profile data.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      this.load();
    });
  }

  category = signal(ALL);
  feedKind = signal(ALL);
  health = signal<HealthFilter>('All');

  readonly healthOptions: { value: HealthFilter; label: string }[] = [
    { value: 'All', label: 'All' },
    { value: 'ok', label: 'Syncing OK' },
    { value: 'error', label: 'Erroring' },
    { value: 'needs-key', label: 'Needs API key' },
    { value: 'unsupported', label: 'Unsupported' },
    { value: 'never', label: 'Never synced' },
  ];

  sources = computed(() => this.allSources());
  categories = computed(() => uniqueSorted(this.allSources().map((s) => s.category ?? 'Uncategorized')));
  feedKinds = computed(() => uniqueSorted(this.allSources().map((s) => s.fetch_kind)));

  filtered = computed(() => {
    const cat = this.category();
    const kind = this.feedKind();
    const h = this.health();
    return this.allSources().filter((s) => {
      if (cat !== ALL && (s.category ?? 'Uncategorized') !== cat) return false;
      if (kind !== ALL && s.fetch_kind !== kind) return false;
      if (h !== 'All') {
        if (h === 'needs-key') { if (!needsKey(s)) return false; }
        else if (sourceHealth(s.last_status) !== h) return false;
      }
      return true;
    });
  });

  filteredCount = computed(() => this.filtered().length);

  grouped = computed<CategoryGroup[]>(() => {
    const groups = new Map<string, Source[]>();
    for (const s of this.filtered()) {
      const cat = s.category ?? 'Uncategorized';
      const bucket = groups.get(cat);
      if (bucket) bucket.push(s); else groups.set(cat, [s]);
    }
    return [...groups.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([cat, list]) => ({ category: cat, sources: list.sort((a, b) => a.name.localeCompare(b.name)) }));
  });

  // Exposed for the template.
  relativeTime = relativeTime;
  sourceHealth = sourceHealth;
  statusLabel = statusLabel;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(false);
    this.api.sources().subscribe({
      next: (rows) => {
        this.allSources.set(rows);
        this.loading.set(false);
      },
      error: () => {
        this.error.set(true);
        this.loading.set(false);
      },
    });
  }
}
