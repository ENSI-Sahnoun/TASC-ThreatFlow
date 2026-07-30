import {
  Component, Input, Output, EventEmitter, OnChanges, OnDestroy, SimpleChanges,
  ChangeDetectionStrategy, signal, computed,
} from '@angular/core';
import { isEmpty, type IntelFilters } from '../../core/filters';
import { SEVERITY_ORDER } from '../../core/format';

export interface FilterBarSource { id: number; name: string; }

const CATEGORIES = ['cve', 'ransomware', 'phishing', 'data-breach', 'malware', 'ioc', 'advisory', 'osint', 'news', 'other'];
// The only exploitation_status value enrich.js actually sets today (see server/consolidate.js) —
// a select rather than free text keeps the filter honest about what the field can contain.
const EXPLOITATION_STATUSES = ['actively_exploited'];
const DEBOUNCE_MS = 300;

type TextKey = 'q' | 'industry' | 'domain' | 'actor' | 'malware_family' | 'cve';
type SelectKey = 'category' | 'severity' | 'exploitation_status' | 'vendor' | 'region';

// Every parameter GET /api/items (and now GET /api/export/iocs) supports. Emits a full, cleaned
// IntelFilters object on every change — text fields debounce so a search doesn't fire a request
// per keystroke; selects and the confidence number apply immediately. The parent owns URL sync.
@Component({
  selector: 'tf-filter-bar',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="bar">
      <label class="grow">
        <span>Search</span>
        <input type="search" placeholder="Title, summary, author, source…"
               [value]="draft().q ?? ''" (input)="onText('q', $any($event.target).value)" />
      </label>

      <label>
        <span>Category</span>
        <select [value]="draft().category ?? ''" (change)="onSelect('category', $any($event.target).value)">
          <option value="">All</option>
          @for (c of categories; track c) { <option [value]="c">{{ c }}</option> }
        </select>
      </label>

      <label>
        <span>Source</span>
        <select [value]="draft().source_id ?? ''" (change)="onSourceId($any($event.target).value)">
          <option value="">All</option>
          @for (s of sources; track s.id) { <option [value]="s.id">{{ s.name }}</option> }
        </select>
      </label>

      <label>
        <span>Severity</span>
        <select [value]="draft().severity ?? ''" (change)="onSelect('severity', $any($event.target).value)">
          <option value="">All</option>
          @for (s of severities; track s) { <option [value]="s">{{ s }}</option> }
        </select>
      </label>

      <label>
        <span>Exploitation</span>
        <select [value]="draft().exploitation_status ?? ''" (change)="onSelect('exploitation_status', $any($event.target).value)">
          <option value="">All</option>
          @for (s of exploitationStatuses; track s) { <option [value]="s">{{ s }}</option> }
        </select>
      </label>

      <label>
        <span>Vendor</span>
        <select [value]="draft().vendor ?? ''" (change)="onSelect('vendor', $any($event.target).value)">
          <option value="">All</option>
          @for (v of vendors; track v) { <option [value]="v">{{ v }}</option> }
        </select>
      </label>

      <label>
        <span>Region</span>
        <select [value]="draft().region ?? ''" (change)="onSelect('region', $any($event.target).value)">
          <option value="">All</option>
          @for (r of regions; track r) { <option [value]="r">{{ r }}</option> }
        </select>
      </label>

      <label>
        <span>Industry</span>
        <input type="text" placeholder="e.g. healthcare" [value]="draft().industry ?? ''" (input)="onText('industry', $any($event.target).value)" />
      </label>

      <label>
        <span>Domain tag</span>
        <input type="text" placeholder="e.g. ransomware" [value]="draft().domain ?? ''" (input)="onText('domain', $any($event.target).value)" />
      </label>

      <label>
        <span>Actor</span>
        <input type="text" placeholder="e.g. APT29" [value]="draft().actor ?? ''" (input)="onText('actor', $any($event.target).value)" />
      </label>

      <label>
        <span>Malware family</span>
        <input type="text" placeholder="e.g. Emotet" [value]="draft().malware_family ?? ''" (input)="onText('malware_family', $any($event.target).value)" />
      </label>

      <label>
        <span>CVE</span>
        <input type="text" placeholder="CVE-2024-…" [value]="draft().cve ?? ''" (input)="onText('cve', $any($event.target).value)" />
      </label>

      <label>
        <span>Min confidence</span>
        <input type="number" min="0" max="1" step="0.05" placeholder="0.0–1.0"
               [value]="draft().min_confidence ?? ''" (change)="onMinConfidence($any($event.target).value)" />
      </label>

      @if (hasActiveFilters()) {
        <button type="button" class="clear" (click)="clearAll()">Clear filters</button>
      }
    </div>
  `,
  styles: [`
    .bar {
      display: flex; align-items: flex-end; gap: 12px; flex-wrap: wrap;
      position: sticky; top: 8px; z-index: var(--z-sticky);
      background: color-mix(in srgb, var(--surface) 78%, transparent);
      backdrop-filter: blur(16px) saturate(160%);
      border: var(--hair) solid var(--hairline); border-radius: var(--radius-card);
      padding: 12px 14px;
    }
    label {
      display: flex; flex-direction: column; gap: 4px; font-size: var(--fs-xs); color: var(--ink-2);
    }
    label.grow { flex: 1 1 220px; min-width: 200px; }

    input, select {
      appearance: none; font: inherit; font-size: var(--fs-sm); color: var(--ink);
      background: var(--surface-2); border: var(--hair) solid var(--hairline);
      border-radius: 8px; padding: 6px 10px; width: 100%; box-sizing: border-box;
      transition: background var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out),
        transform var(--dur-fast) var(--ease-out);
    }
    select { cursor: pointer; }
    input[type="number"] { width: 110px; }
    input:hover, select:hover { background: var(--surface-3); }
    input:focus-visible, select:focus-visible {
      outline: 2px solid var(--accent); outline-offset: 1px; transform: translateY(-1px);
    }
    input:disabled, select:disabled { opacity: .4; cursor: not-allowed; }

    .clear {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0; padding: 7px 14px; border-radius: 8px;
      transition: opacity var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    .clear:hover { opacity: .88; }
    .clear:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .clear:active { opacity: .74; transform: scale(.96); }

    @media (prefers-reduced-motion: reduce) {
      input, select, .clear { transition: none; }
    }
    @media (prefers-reduced-transparency: reduce) {
      .bar { background: var(--surface); backdrop-filter: none; }
    }
  `],
})
export class FilterBarComponent implements OnChanges, OnDestroy {
  @Input() filters: IntelFilters = {};
  @Input() sources: FilterBarSource[] = [];
  @Input() vendors: string[] = [];
  @Input() regions: string[] = [];
  @Output() filtersChange = new EventEmitter<IntelFilters>();

  draft = signal<IntelFilters>({});
  hasActiveFilters = computed(() => !isEmpty(this.draft()));

  readonly categories = CATEGORIES;
  readonly severities = SEVERITY_ORDER.filter((s) => s !== 'unknown');
  readonly exploitationStatuses = EXPLOITATION_STATUSES;

  private timer: ReturnType<typeof setTimeout> | null = null;

  ngOnChanges(changes: SimpleChanges): void {
    // Only re-sync from the parent (e.g. a browser back/forward navigation, or a dashboard
    // drill-down link) — our own emits already reflect straight back into `filters` so this
    // must not fight the debounce timer for a filter the user is still typing.
    if ('filters' in changes) this.draft.set({ ...this.filters });
  }

  ngOnDestroy(): void {
    this.cancelTimer();
  }

  private cancelTimer(): void {
    if (this.timer !== null) { clearTimeout(this.timer); this.timer = null; }
  }

  private emitNow(): void {
    this.filtersChange.emit({ ...this.draft() });
  }

  onText(key: TextKey, value: string): void {
    this.draft.update((d) => ({ ...d, [key]: value || undefined }));
    this.cancelTimer();
    this.timer = setTimeout(() => { this.timer = null; this.emitNow(); }, DEBOUNCE_MS);
  }

  onSelect(key: SelectKey, value: string): void {
    this.cancelTimer();
    this.draft.update((d) => ({ ...d, [key]: value || undefined }));
    this.emitNow();
  }

  onSourceId(value: string): void {
    this.cancelTimer();
    const n = value === '' ? undefined : Number(value);
    this.draft.update((d) => ({ ...d, source_id: n }));
    this.emitNow();
  }

  onMinConfidence(value: string): void {
    this.cancelTimer();
    const n = value === '' ? undefined : Number(value);
    this.draft.update((d) => ({ ...d, min_confidence: (n === undefined || Number.isNaN(n)) ? undefined : n }));
    this.emitNow();
  }

  clearAll(): void {
    this.cancelTimer();
    this.draft.set({});
    this.emitNow();
  }
}
