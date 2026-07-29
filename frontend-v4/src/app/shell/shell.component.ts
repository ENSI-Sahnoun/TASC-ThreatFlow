import { Component, ElementRef, ViewChild, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { map, catchError, of } from 'rxjs';
import { ApiService } from '../core/api.service';
import { ThemeService } from '../core/theme.service';
import { CommandPaletteComponent } from './command-palette.component';

@Component({
  selector: 'tf-shell',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, RouterLinkActive, RouterOutlet, CommandPaletteComponent],
  template: `
    <header class="nav">
      <a routerLink="/" class="brand tf-heading"><img [src]="theme.theme() === 'light' ? 'logo-dark.png' : 'logo.png'" alt="" class="brand-logo" />ThreatFlow</a>
      <nav>
        <a routerLink="/" routerLinkActive="on" [routerLinkActiveOptions]="{ exact: true }">Dashboard</a>
        <a routerLink="/arsenal" routerLinkActive="on">Arsenal</a>
        <a routerLink="/intel" routerLinkActive="on">Intel</a>
        <a routerLink="/check" routerLinkActive="on">Check URL</a>
      </nav>
      <button
        class="theme-toggle" type="button" (click)="theme.toggle()"
        [attr.aria-label]="theme.theme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'"
        title="Toggle theme"
      >
        @if (theme.theme() === 'dark') {
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
          </svg>
        } @else {
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z" />
          </svg>
        }
      </button>
      <button #searchBtn class="search" type="button" (click)="openPalette()">Search <kbd>⌘K</kbd></button>
    </header>

    <!-- Partial data is stated, never hidden. 8 of 43 sources are down and the interface
         must say so rather than quietly rendering 35 as if it were the whole picture. -->
    @if (health(); as h) {
      @if (h.error + h.unsupported + h.neverSynced > 0) {
        <p class="degraded">
          {{ h.ok }} of {{ h.total }} sources live, no compromises on saying so
          @if (h.error) { · {{ h.error }} erroring }
          @if (h.neverSynced + h.unsupported) { · {{ h.neverSynced + h.unsupported }} need keys or unsupported }
          <a routerLink="/arsenal">Review sources</a>
        </p>
      }
    }

    <main><router-outlet /></main>

    @if (paletteOpen()) { <tf-command-palette (closed)="closePalette()" /> }
  `,
  styles: [`
    .nav {
      position: sticky; top: 0; z-index: var(--z-sticky);
      display: flex; align-items: center; gap: 20px; padding: 10px 20px;
      /* Same brand rays as the page background (body::before) — a diagonal accent bleed
         through the glass instead of flat chrome. */
      background:
        linear-gradient(120deg, color-mix(in srgb, var(--accent) 16%, transparent), transparent 60%),
        var(--chrome);
      backdrop-filter: blur(30px) saturate(180%);
      border-bottom: var(--hair) solid var(--hairline);
    }
    .brand {
      display: flex; align-items: center; gap: 8px;
      color: var(--ink); text-decoration: none; letter-spacing: -.02em;
    }
    .brand-logo { width: 22px; height: 22px; object-fit: contain; }
    nav { display: flex; gap: 4px; }
    nav a {
      color: var(--ink-2); text-decoration: none; font-size: var(--fs-sm); font-weight: 510;
      padding: 5px 11px; border-radius: 8px;
      transition: color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
    }
    nav a:hover { color: var(--ink); background: var(--chrome-hover); }
    nav a.on { color: var(--ink); background: var(--chrome-hover); }
    .theme-toggle {
      margin-left: auto; appearance: none; cursor: pointer; border: 0; color: var(--ink-2);
      background: var(--chrome-hover); width: 30px; height: 30px; border-radius: 8px;
      display: flex; align-items: center; justify-content: center; flex: none;
      transition: color var(--dur-fast) var(--ease);
    }
    .theme-toggle:hover { color: var(--ink); }
    .search {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs);
      color: var(--ink-2); background: var(--chrome-hover); border: 0;
      padding: 6px 12px; border-radius: 8px; display: flex; gap: 8px; align-items: center;
    }
    .search:hover { color: var(--ink); }
    kbd { font: inherit; font-size: 10px; color: var(--ink-2); }
    .degraded {
      margin: 0; padding: 7px 20px; font-size: var(--fs-xs); color: var(--ink-2);
      background: color-mix(in srgb, var(--sev-high) 12%, transparent);
      border-bottom: var(--hair) solid var(--hairline);
    }
    .degraded a { color: var(--ink); margin-left: 8px; }
    main { padding: 20px; max-width: 1680px; margin: 0 auto; }

    /* Below 640px the brand + nav links + search button no longer fit on one row (that's what
       was causing the page body itself to scroll sideways). Wrap structurally onto a second row
       rather than letting flex shrink text or overflow. Deliberately no order override here:
       flexbox order only changes paint position, never DOM/tab order, so an earlier version of
       this fix (order: 3 on nav) made Tab visit brand -> nav links -> search while the visual
       rows read brand+search -> nav underneath -- a keyboard user tabbed down into row two, then
       jumped back up to row one. Letting flex-wrap lay elements out in DOM order instead keeps
       visual reading order and tab order identical by construction: brand, then nav (forced to
       its own full-width row by nav's own width: 100%), then search. */
    @media (max-width: 640px) {
      .nav { flex-wrap: wrap; row-gap: 8px; }
      nav { width: 100%; }
    }
  `],
  host: { '(document:keydown)': 'onKey($event)' },
})
export class ShellComponent {
  private api = inject(ApiService);
  theme = inject(ThemeService);
  paletteOpen = signal(false);
  // Guarded against errors: a failed fetch must not blank the whole shell (which owns
  // <router-outlet>) — it just means the degradation banner has nothing to report this time.
  health = toSignal(
    this.api.dashboard().pipe(map((d) => d.sourceHealth), catchError(() => of(null))),
    { initialValue: null },
  );

  @ViewChild('searchBtn') private searchBtn?: ElementRef<HTMLButtonElement>;

  // Escape is deliberately NOT handled here while the palette is open. It used to be ("if
  // Escape, paletteOpen.set(false)"), on the theory that CommandPaletteComponent's own
  // `onDialogKeydown` stopping propagation would keep the two from racing. That guard only
  // works when the keydown event actually bubbles up *through* the dialog element — which
  // requires the currently-focused element to be a descendant of it. It isn't always: tabbing
  // to the last focusable control inside a native <dialog> and pressing Tab once more can
  // transiently land focus on `<body>` (an artifact of how this engine's dialog wraps Tab),
  // and a `<body>`-targeted Escape keydown bubbles straight to `document` without ever passing
  // through the dialog. That let this handler race dismiss()'s own animated close/native
  // `.close()` sequence, tearing the dialog's DOM node out while it was still flagged "open" —
  // which left focus stranded on `<body>` instead of back on the trigger button. The dialog's
  // native `cancel` event (wired in CommandPaletteComponent) is dispatched directly at the
  // dialog by the browser whenever Escape is pressed and a modal is showing, independent of
  // where focus happens to be — so it is the one and only authority for Escape while open.
  onKey(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); this.openPalette(); }
  }

  openPalette(): void {
    this.paletteOpen.set(true);
  }

  closePalette(): void {
    this.paletteOpen.set(false);
    // Belt-and-suspenders: the native <dialog> already restores focus to whatever was focused
    // when showModal() ran, but re-asserting it here keeps the trigger button focused even in
    // engine edge cases around the dialog's own restoration timing.
    this.searchBtn?.nativeElement.focus();
  }
}
