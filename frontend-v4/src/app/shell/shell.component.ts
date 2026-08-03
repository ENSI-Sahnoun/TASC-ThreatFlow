import { Component, ElementRef, ViewChild, inject, signal, effect, DestroyRef, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet, NavigationEnd } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { map, catchError, of, filter } from 'rxjs';
import { Router } from '@angular/router';
import { ApiService } from '../core/api.service';
import { ThemeService } from '../core/theme.service';
import { SyncService } from '../core/sync.service';
import { CommandPaletteComponent } from './command-palette.component';
import { ProfileService } from '../core/profile.service';
import { ProfilePickerComponent } from '../pages/onboarding/profile-picker.component';
import { healthPoll } from '../core/health-poll';

@Component({
  selector: 'tf-shell',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, RouterLinkActive, RouterOutlet, CommandPaletteComponent, ProfilePickerComponent],
  template: `
    <header class="nav">
      <a routerLink="/" class="brand tf-heading"><img [src]="theme.theme() === 'light' ? 'logo-dark.png' : 'logo.png'" alt="" class="brand-logo" [class.swap]="logoSwapping()" />ThreatFlow</a>
      <nav>
        <a routerLink="/" routerLinkActive="on" [routerLinkActiveOptions]="{ exact: true }">Dashboard</a>
        <a routerLink="/arsenal" routerLinkActive="on">Arsenal</a>
        <a routerLink="/intel" routerLinkActive="on">Intel</a>
        <a routerLink="/check" routerLinkActive="on">Check URL</a>
      </nav>
      <tf-profile-picker />
      <button
        class="theme-toggle" type="button" (click)="toggleTheme()"
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

    <!-- Only for the backend being unreachable, not degraded — a slow or erroring API is
         still answering (the banner above covers that). This is "nothing is answering at all",
         which today's incident showed can otherwise look like a page loading forever with no
         explanation. Auto-recovers: see the reload effect in the constructor. -->
    @if (backendUnreachable()) {
      <p class="unreachable">Backend unreachable — retrying automatically…</p>
    }

    <main><router-outlet /></main>

    <!-- Persists across route changes (the dashboard's own overlay/badge do not — that
         component gets destroyed on navigation, which used to make "syncing" vanish from the
         UI even though the sync-all request was still running server-side). Suppressed only
         while the dashboard's own full-screen overlay is up, so the two don't stack. -->
    @if (sync.syncing() && (!onDashboard() || sync.overlayDismissed())) {
      <button type="button" class="sync-badge" (click)="reopenSyncOverlay()" aria-label="Sync in progress, click to view">
        <span class="sync-logo" [innerHTML]="sync.logoSvg()"></span>
        Syncing…
      </button>
    }

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
    .brand-logo {
      width: 22px; height: 22px; object-fit: contain;
      transition: transform var(--dur-fast) var(--ease);
    }
    .brand:hover .brand-logo { transform: scale(1.12) rotate(-6deg); }
    /* Src swap between logo.png / logo-dark.png on theme toggle is otherwise an instant,
       jarring replace — this pulse masks the swap instead of animating it directly, since
       there's no way to crossfade between two different \`src\` values on one <img>. */
    .brand-logo.swap { animation: logo-swap var(--dur-slow) var(--ease); }
    @keyframes logo-swap {
      0% { transform: scale(1) rotate(0deg); opacity: 1; }
      45% { transform: scale(.55) rotate(10deg); opacity: .3; }
      100% { transform: scale(1) rotate(0deg); opacity: 1; }
    }
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
    .unreachable {
      margin: 0; padding: 7px 20px; font-size: var(--fs-xs); color: var(--ink-2);
      background: color-mix(in srgb, var(--sev-critical) 16%, transparent);
      border-bottom: var(--hair) solid var(--hairline);
    }
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
    /* Matches the KPI tile "widget" language on the dashboard (kpi-tile.component.ts): flat
       accent-tinted surface, hairline border, chrome radius — no glass/blur/shadow, which
       reads as a floating toast rather than a page-native control. */
    .sync-badge {
      position: fixed; right: 20px; bottom: 20px; z-index: var(--z-toast);
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 510; color: var(--ink-2);
      display: flex; align-items: center; gap: 8px;
      background: color-mix(in srgb, var(--accent) 6%, var(--surface));
      border: var(--hair) solid var(--hairline); border-radius: var(--radius-chrome);
      padding: 6px 14px 6px 8px;
      transition: background var(--dur) var(--ease-out), transform var(--dur-fast) var(--ease-out);
    }
    .sync-badge:hover { background: color-mix(in srgb, var(--accent) 10%, var(--surface)); transform: translateY(-1px); }
    .sync-badge:active { transform: translateY(0) scale(.98); }
    .sync-badge:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .sync-logo { width: 20px; height: 28px; flex-shrink: 0; }
    /* [innerHTML] content is raw DOM Angular never compiled, so it carries none of the
       component's _ngcontent scoping attribute — plain scoped selectors can't reach it.
       ::ng-deep drops that attribute requirement for the rest of the selector. */
    .sync-logo ::ng-deep svg { width: 100%; height: 100%; display: block; }
    .sync-logo ::ng-deep .logo-path {
      fill: var(--accent); stroke: var(--accent); stroke-opacity: 1; stroke-width: 3;
      stroke-linecap: round; stroke-linejoin: round;
      animation: logo-pulse 1.6s linear infinite;
    }
    @keyframes logo-pulse {
      0%   { fill-opacity: 1; }
      62%  { fill-opacity: 1; animation-timing-function: ease-in; }
      80%  { fill-opacity: .12; animation-timing-function: ease-out; }
      100% { fill-opacity: 1; }
    }
    @media (prefers-reduced-motion: reduce) {
      .sync-logo ::ng-deep .logo-path { animation: none; fill-opacity: 1; }
    }
  `],
  host: { '(document:keydown)': 'onKey($event)' },
})
export class ShellComponent {
  private api = inject(ApiService);
  private router = inject(Router);
  theme = inject(ThemeService);
  sync = inject(SyncService);
  profiles = inject(ProfileService);
  paletteOpen = signal(false);
  logoSwapping = signal(false);
  onDashboard = toSignal(
    this.router.events.pipe(filter((e) => e instanceof NavigationEnd), map(() => this.router.url === '/')),
    { initialValue: this.router.url === '/' },
  );
  // Guarded against errors: a failed fetch must not blank the whole shell (which owns
  // <router-outlet>) — it just means the degradation banner has nothing to report this time.
  health = toSignal(
    this.api.dashboard().pipe(map((d) => d.sourceHealth), catchError(() => of(null))),
    { initialValue: null },
  );

  // 3 consecutive failed checks (~15s), not 1 — a single slow response is not an outage, and
  // today's own incident (a stuck schema migration) took several seconds to resolve on its own.
  private healthHandle = healthPoll(() => this.api.health());
  backendUnreachable = this.healthHandle.unreachable;
  private wasUnreachable = false;

  constructor() {
    this.profiles.load();
    // The gate fires only once the profile list has actually arrived — needsOnboarding() stays
    // false until then, so a slow response cannot bounce a user who does have profiles.
    effect(() => {
      if (this.profiles.needsOnboarding() && !this.router.url.startsWith('/onboarding')) {
        this.router.navigateByUrl('/onboarding');
      }
    });
    // Reload only on the true -> false transition, never on the initial (already-reachable)
    // state — otherwise every normal app boot would reload itself once.
    effect(() => {
      const down = this.backendUnreachable();
      if (!down && this.wasUnreachable) window.location.reload();
      this.wasUnreachable = down;
    });
    inject(DestroyRef).onDestroy(() => this.healthHandle.destroy());
  }

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

  toggleTheme(): void {
    this.theme.toggle();
    this.logoSwapping.set(true);
    setTimeout(() => this.logoSwapping.set(false), 240);
  }

  reopenSyncOverlay(): void {
    this.sync.reopenOverlay();
    if (!this.onDashboard()) this.router.navigateByUrl('/');
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
