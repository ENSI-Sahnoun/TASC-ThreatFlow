import {
  Component, ChangeDetectionStrategy, ElementRef, EventEmitter, Output, ViewChild,
  AfterViewInit, OnDestroy, inject, signal, computed, effect,
} from '@angular/core';
import { Router } from '@angular/router';
import { Subject, EMPTY, catchError, debounceTime, distinctUntilChanged, of, switchMap } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiService } from '../core/api.service';
import type { SearchResults } from '../core/models';
import { EmptyStateComponent } from '../ui/empty-state.component';
import { SkeletonComponent } from '../ui/skeleton.component';
import { ChipComponent } from '../ui/chip.component';
import { SourceDotComponent } from '../ui/source-dot.component';

type PaletteKind = 'source' | 'cve' | 'actor' | 'family' | 'item';

interface PaletteItem {
  kind: PaletteKind;
  id: string | number;
  key: string;
  primary: string;
  secondary?: string;
  severity?: string | null;
  status?: string | null;
}

interface PaletteRow extends PaletteItem { flatIndex: number; }

const KIND_LABEL: Record<PaletteKind, string> = {
  source: 'Source', cve: 'CVE', actor: 'Actor', family: 'Malware', item: 'Item',
};

// ⌘K search. Hosted in a native <dialog> so it always escapes the app's own stacking
// contexts; showModal()/close() also give us focus-trap-while-open and focus-restore-on-close
// for free from the platform, rather than reimplementing a focus trap in JS.
@Component({
  selector: 'tf-command-palette',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [EmptyStateComponent, SkeletonComponent, ChipComponent, SourceDotComponent],
  template: `
    <dialog #dlg class="palette" [class.closing]="closing()" (cancel)="onCancel($event)" (click)="onBackdropClick($event)" (keydown)="onDialogKeydown($event)">
      <div class="inner" (click)="$event.stopPropagation()">
        <div class="search-row">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <circle cx="11" cy="11" r="7" /><path d="m21 21-4.35-4.35" />
          </svg>
          <input
            #inputEl
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-autocomplete="list"
            aria-controls="cmdk-listbox"
            [attr.aria-activedescendant]="flat().length ? 'cmdk-opt-' + selectedIndex() : null"
            aria-label="Search items, CVEs, actors, malware and sources"
            placeholder="Search items, CVEs, actors, malware, sources…"
            autocomplete="off"
            autofocus
            [value]="query()"
            (input)="onInput($event)"
            (keydown)="onKeydown($event)"
          />
          <kbd>Esc</kbd>
          <button type="button" class="close-btn" aria-label="Close" (click)="dismiss()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
              <path d="M6 6 18 18M18 6 6 18" />
            </svg>
          </button>
        </div>

        <div class="results" id="cmdk-listbox" role="listbox" aria-label="Search results">
          @if (loading()) {
            <div class="state"><tf-skeleton [rows]="3" /></div>
          } @else if (error()) {
            <div class="state"><tf-empty-state title="Search failed" [detail]="error()!" /></div>
          } @else if (query().trim().length === 0) {
            <div class="state">
              <tf-empty-state title="Search ThreatFlow" detail="Type to search items, CVEs, actors, malware families and sources." />
            </div>
          } @else if (flat().length === 0) {
            <div class="state">
              <tf-empty-state title="No matches" [detail]="'No results for “' + query() + '”.'" />
            </div>
          } @else {
            @for (group of groups(); track group.label) {
              <div class="group">
                <p class="group-label">{{ group.label }}</p>
                @for (item of group.items; track item.key) {
                  <button
                    type="button"
                    class="row"
                    role="option"
                    [id]="'cmdk-opt-' + item.flatIndex"
                    [class.active]="item.flatIndex === selectedIndex()"
                    [attr.aria-selected]="item.flatIndex === selectedIndex()"
                    (mouseenter)="selectedIndex.set(item.flatIndex)"
                    (click)="select(item)"
                  >
                    @switch (item.kind) {
                      @case ('source') { <tf-source-dot [status]="item.status ?? null" [name]="item.primary" /> }
                      @case ('cve') { <tf-chip [severity]="item.severity ?? null" /> }
                      @default { <span class="dot-ph" aria-hidden="true"></span> }
                    }
                    <span class="primary">{{ item.primary }}</span>
                    @if (item.secondary) { <span class="secondary">{{ item.secondary }}</span> }
                    <span class="kind">{{ kindLabel(item.kind) }}</span>
                    @if (item.flatIndex === selectedIndex()) { <span class="enter-hint" aria-hidden="true">↵</span> }
                  </button>
                }
              </div>
            }
          }
        </div>
      </div>
    </dialog>
  `,
  styles: [`
    :host { display: contents; }

    dialog.palette {
      position: fixed; inset: 12vh 0 auto; margin: 0 auto;
      width: min(640px, 92vw); max-height: min(64vh, 520px);
      padding: 0; border: var(--hair) solid var(--hairline); border-radius: var(--radius-card);
      background: transparent; color: var(--ink); overflow: hidden;
      opacity: 0; transform: translateY(-8px) scale(.98);
      transition: opacity var(--dur) var(--ease), transform var(--dur) var(--ease);
    }
    dialog.palette[open] { opacity: 1; transform: translateY(0) scale(1); }
    dialog.palette.closing { opacity: 0; transform: translateY(-8px) scale(.98); }
    @starting-style { dialog.palette[open]:not(.closing) { opacity: 0; transform: translateY(-8px) scale(.98); } }

    dialog.palette::backdrop { background: color-mix(in srgb, var(--bg) 28%, transparent); opacity: 0; transition: opacity var(--dur) var(--ease); }
    dialog.palette[open]::backdrop { opacity: 1; }
    dialog.palette.closing::backdrop { opacity: 0; }
    @starting-style { dialog.palette[open]:not(.closing)::backdrop { opacity: 0; } }

    @media (prefers-reduced-motion: reduce) {
      dialog.palette, dialog.palette::backdrop { transition: none !important; }
    }

    .inner {
      display: flex; flex-direction: column; max-height: min(64vh, 520px);
      background: var(--chrome); backdrop-filter: blur(20px) saturate(140%);
    }

    .search-row {
      display: flex; align-items: center; gap: 10px; padding: 14px 16px; flex: none;
      border-bottom: var(--hair) solid var(--hairline); color: var(--ink-3);
    }
    .search-row input {
      flex: 1; min-width: 0; appearance: none; border: 0; background: transparent; color: var(--ink);
      font: inherit; font-size: var(--fs-md); outline: none;
    }
    .search-row input::placeholder { color: var(--ink-2); }
    .search-row kbd {
      font: inherit; font-size: var(--fs-xs); color: var(--ink-2);
      background: var(--surface-2); padding: 2px 6px; border-radius: 5px; flex: none;
    }
    .close-btn {
      appearance: none; border: 0; cursor: pointer; color: var(--ink-3); background: transparent;
      width: 22px; height: 22px; border-radius: 6px; display: flex; align-items: center; justify-content: center;
      flex: none; transition: color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
    }
    .close-btn:hover { color: var(--ink); background: var(--surface-2); }
    .close-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .close-btn:active { background: var(--surface-3); }

    .results { overflow-y: auto; padding: 8px; flex: 1; }
    .state { padding: 12px 10px; }

    .group + .group { margin-top: 6px; }
    .group-label {
      margin: 6px 10px 4px; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2);
      text-transform: uppercase; letter-spacing: .04em;
    }
    .row {
      width: 100%; display: flex; align-items: center; gap: 10px; text-align: left;
      appearance: none; border: 0; background: transparent; color: var(--ink); cursor: pointer;
      font: inherit; font-size: var(--fs-sm); padding: 8px 10px; border-radius: 9px;
      transition: background var(--dur-fast) var(--ease);
    }
    .row:hover { background: var(--surface-2); }
    .row.active { background: var(--surface-3); }
    .row:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
    .row:active { background: var(--surface-4); }
    .row .primary { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row .secondary { color: var(--ink-2); font-size: var(--fs-xs); flex: none; }
    .row .kind { color: var(--ink-2); font-size: var(--fs-xs); flex: none; }
    .row .enter-hint { color: var(--ink-2); font-size: var(--fs-xs); flex: none; }
    .dot-ph { width: 6px; height: 6px; flex: none; }
  `],
})
export class CommandPaletteComponent implements AfterViewInit, OnDestroy {
  private api = inject(ApiService);
  private router = inject(Router);

  @Output() closed = new EventEmitter<void>();
  @ViewChild('dlg') private dlgRef!: ElementRef<HTMLDialogElement>;

  private queryInput$ = new Subject<string>();
  private dismissTimer: ReturnType<typeof setTimeout> | null = null;

  query = signal('');
  loading = signal(false);
  error = signal<string | null>(null);
  closing = signal(false);
  private results = signal<SearchResults | null>(null);
  selectedIndex = signal(0);

  private sections = computed(() => {
    const r = this.results();
    if (!r) return [] as { label: string; items: PaletteItem[] }[];
    return [
      { label: 'Sources', items: r.sources.map((s): PaletteItem => ({ kind: 'source', id: s.id, key: `source-${s.id}`, primary: s.name, status: s.last_status })) },
      { label: 'CVEs', items: r.cves.map((c): PaletteItem => ({ kind: 'cve', id: c.cve_id, key: `cve-${c.cve_id}`, primary: c.cve_id, severity: c.severity, secondary: c.cvss_score != null ? `CVSS ${c.cvss_score.toFixed(1)}` : undefined })) },
      { label: 'Actors', items: r.actors.map((a): PaletteItem => ({ kind: 'actor', id: a.actor, key: `actor-${a.actor}`, primary: a.actor })) },
      { label: 'Malware', items: r.families.map((f): PaletteItem => ({ kind: 'family', id: f.family, key: `family-${f.family}`, primary: f.family })) },
      { label: 'Items', items: r.items.map((i): PaletteItem => ({ kind: 'item', id: i.id, key: `item-${i.id}`, primary: i.title, secondary: i.category })) },
    ].filter((g) => g.items.length > 0);
  });

  groups = computed<{ label: string; items: PaletteRow[] }[]>(() => {
    let idx = 0;
    return this.sections().map((g) => ({ label: g.label, items: g.items.map((it) => ({ ...it, flatIndex: idx++ })) }));
  });

  flat = computed(() => this.groups().flatMap((g) => g.items));

  constructor() {
    // A fresh search always highlights the first hit.
    effect(() => { this.flat(); this.selectedIndex.set(0); });

    this.queryInput$.pipe(
      debounceTime(200),
      distinctUntilChanged(),
      switchMap((q) => {
        const trimmed = q.trim();
        this.error.set(null);
        if (!trimmed) { this.loading.set(false); this.results.set(null); return EMPTY; }
        this.loading.set(true);
        return this.api.search(trimmed).pipe(catchError(() => of(null)));
      }),
      takeUntilDestroyed(),
    ).subscribe((r) => {
      this.loading.set(false);
      this.results.set(r);
      this.error.set(r ? null : (this.query().trim() ? 'Search failed — try again.' : null));
    });
  }

  ngAfterViewInit() {
    this.dlgRef.nativeElement.showModal();
  }

  ngOnDestroy() {
    if (this.dismissTimer !== null) clearTimeout(this.dismissTimer);
  }

  onInput(e: Event) {
    const v = (e.target as HTMLInputElement).value;
    this.query.set(v);
    this.queryInput$.next(v);
  }

  onKeydown(e: KeyboardEvent) {
    const total = this.flat().length;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (total) this.selectedIndex.update((i) => (i + 1) % total);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (total) this.selectedIndex.update((i) => (i - 1 + total) % total);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const row = this.flat()[this.selectedIndex()];
      if (row) this.select(row);
    }
  }

  // Native <dialog> fires 'cancel' (then would auto-close) on Esc. We intercept so Esc drives
  // the same animated-close path as every other dismissal.
  onCancel(e: Event) {
    e.preventDefault();
    this.dismiss();
  }

  // Esc bubbles from here past the dialog up to `document`, where ShellComponent's own
  // keydown listener also reacts to it (to support Esc from anywhere in the app, not just
  // while this palette happens to exist). If we let it through, ShellComponent flips
  // `paletteOpen` to false immediately and tears this component out of the DOM before
  // `dismiss()`'s own closing()-driven fade-out ever gets to run. Stopping it here makes
  // this component the sole authority over its own dismissal animation — ShellComponent only
  // ever finds out via the (closed) output, once the transition has actually played.
  onDialogKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') e.stopPropagation();
  }

  onBackdropClick(e: MouseEvent) {
    if (e.target === this.dlgRef.nativeElement) this.dismiss();
  }

  dismiss() {
    if (this.closing()) return;
    this.closing.set(true);
    const reduceMotion = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.dismissTimer = setTimeout(() => {
      this.dismissTimer = null;
      this.dlgRef.nativeElement.close();
      this.closed.emit();
    }, reduceMotion ? 0 : 200);
  }

  select(row: PaletteRow) {
    this.router.navigateByUrl(this.pathFor(row));
    this.dismiss();
  }

  kindLabel(k: PaletteKind) {
    return KIND_LABEL[k];
  }

  private pathFor(row: PaletteRow): string {
    switch (row.kind) {
      case 'source': return `/arsenal/${row.id}`;
      case 'cve': return `/cve/${encodeURIComponent(String(row.id))}`;
      case 'actor': return `/actor/${encodeURIComponent(String(row.id))}`;
      case 'family': return `/malware/${encodeURIComponent(String(row.id))}`;
      case 'item': return `/intel/${row.id}`;
    }
  }
}
