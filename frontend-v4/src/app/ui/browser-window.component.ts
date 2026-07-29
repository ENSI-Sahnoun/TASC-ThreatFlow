import {
  Component, Input, Output, EventEmitter, ChangeDetectionStrategy, ViewChild, TemplateRef, ViewContainerRef,
  EmbeddedViewRef, Renderer2, OnDestroy, inject, signal,
} from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { Subscription } from 'rxjs';
import { SourceDotComponent } from './source-dot.component';
import { hostname } from '../core/format';
import { ThemeService } from '../core/theme.service';
import { ApiService } from '../core/api.service';
import type { PreviewCheck } from '../core/models';

// Backstop only, now that /api/preview-check rules out the refusal case up front: a page that
// passed the header check can still hang forever (slow origin, a consent wall that never
// paints). If `load` hasn't fired by now, stop showing a spinner and offer the link instead.
const IFRAME_LOAD_TIMEOUT_MS = 15000;

// Verdicts that mean "the check failed", not "the page said no". These never suppress the
// iframe — the browser may well succeed where our server-side fetch was refused.
const INCONCLUSIVE_REASONS = ['unreachable', 'http-error'];

// A small Safari/macOS-window frame around an item's title/summary — used at two densities:
// full-size inside tf-story-drawer, compact as a hover popover in the arsenal items table.
// The window itself only ever shows the summary (client-side data, no fetching); clicking the
// expand button opens a centered modal that loads the real article link in a sandboxed iframe —
// on demand only, since most upstream sites block framing via X-Frame-Options/CSP and there's no
// reliable way to detect that from script before the click.
@Component({
  selector: 'tf-browser-window',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SourceDotComponent],
  host: {
    '[class.compact]': "size === 'compact'",
    '[class.dark]': 'isDark()',
    '(document:keydown.escape)': 'closeExpand()',
  },
  template: `
    <div class="chrome">
      <span class="dot red"></span><span class="dot yellow"></span><span class="dot green"></span>
      <div class="address">
        <svg class="lock" width="9" height="10" viewBox="0 0 24 26" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
          <rect x="4" y="11" width="16" height="12" rx="2" />
          <path d="M8 11V7a4 4 0 0 1 8 0v4" />
        </svg>
        <span class="host">{{ addressText() }}</span>
      </div>
      @if (url && allowExpand) {
        <button
          type="button" class="expand-btn" title="Open full preview" aria-label="Open full preview"
          [attr.aria-expanded]="expanded()" (click)="openExpand()"
        >
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M8 3H5a2 2 0 0 0-2 2v3M16 3h3a2 2 0 0 1 2 2v3M21 16v3a2 2 0 0 1-2 2h-3M3 16v3a2 2 0 0 0 2 2h3" />
          </svg>
        </button>
      }
    </div>
    <div class="page">
      <header class="byline">
        <tf-source-dot [status]="sourceStatus" [name]="sourceName" />
        <span class="source">{{ sourceName }}</span>
        <span class="time">{{ time }}</span>
      </header>
      <h2 class="headline">{{ title }}</h2>
      @if (summary) {
        <p class="summary">{{ summary }}</p>
      } @else {
        <p class="summary muted">No summary provided</p>
      }
    </div>

    <ng-template #modalTpl>
      <div class="modal-backdrop" [class.dark]="isDark()" (click)="closeExpand()">
        <div class="modal-box" (click)="$event.stopPropagation()">
          <div class="modal-head">
            <span class="dot red"></span><span class="dot yellow"></span><span class="dot green"></span>
            <div class="address">
              <svg class="lock" width="9" height="10" viewBox="0 0 24 26" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
                <rect x="4" y="11" width="16" height="12" rx="2" />
                <path d="M8 11V7a4 4 0 0 1 8 0v4" />
              </svg>
              <span class="host">{{ addressText() }}</span>
            </div>
            <button type="button" class="modal-close" aria-label="Close preview" (click)="closeExpand()">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
                <path d="M6 6 18 18M18 6 6 18" />
              </svg>
            </button>
          </div>
          <div class="modal-frame-wrap">
            <!-- Mounted only once the server-side check says this page permits framing. Rendering
                 it unconditionally is what let the browser's own refusal page ("Firefox Can't Open
                 This Page") occupy the frame: that page fires a load event like any other, so
                 nothing here could tell it apart from a real render and swap in our card. -->
            @if (phase() === 'loading' || phase() === 'ready') {
            <!-- allow-scripts + allow-same-origin together are the combination MDN warns never to
                 grant an untrusted frame — normally it lets framed script strip its own sandbox.
                 That warning is about framing something on YOUR OWN origin; here the framed site
                 (e.g. theregister.com) is never same-origin with this app, so there's nothing of
                 ours for it to reach into either way. What it needs is real access to ITS OWN
                 cookies/storage: without allow-same-origin the frame gets an opaque origin, and
                 the site's own consent/paywall/session script can't read or write that storage —
                 first this left a scroll-lock overlay stuck closed forever (bare sandbox, no
                 allow-scripts at all), then with scripts enabled but storage still denied, the
                 same script's own error-recovery path started reloading the frame in a loop
                 instead. Granting both fixes it; no allow-top-navigation is still what stops the
                 framed page from hijacking this tab entirely. Tradeoff: the site now sees a normal
                 visit from its own cookies/session, same as opening the link directly would. -->
            <iframe
              class="modal-frame" [src]="safeUrl()" referrerpolicy="no-referrer"
              sandbox="allow-scripts allow-same-origin allow-popups"
              (load)="onIframeLoad()"
            ></iframe>
            }

            @if (phase() === 'checking' || phase() === 'loading') {
              <div class="frame-loading" role="status" aria-live="polite">
                <span class="spinner" aria-hidden="true"></span>
                <p class="frame-loading-text">
                  @if (phase() === 'checking') {
                    Checking whether {{ addressText() }} allows previews…
                  } @else {
                    Loading {{ addressText() }}…
                  }
                </p>
              </div>
            }

            @if (block(); as b) {
              <div class="frame-error">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                  <circle cx="12" cy="12" r="9.5" />
                  <path d="M12 8v5M12 16h.01" stroke-linecap="round" />
                </svg>
                <p class="frame-error-title">{{ b.title }}</p>
                <p class="frame-error-body">{{ b.body }}</p>
                @if (b.detail) { <p class="frame-error-detail">{{ b.detail }}</p> }
                <a class="frame-error-link" [href]="url" target="_blank" rel="noopener noreferrer">Open in a new tab</a>
              </div>
            }
          </div>
        </div>
      </div>
    </ng-template>
  `,
  styles: [`
    /* Fixed chrome — always the *opposite* of the app's current theme (dark app -> light
       browser window, light app -> dark browser window), never following the app's own
       tokens directly. The contrast is what sells the "screenshot of a page" illusion; a
       browser window matching its surroundings reads as flat, not like a window on top of one. */
    :host {
      display: block; background: #fff; border-radius: var(--radius-card);
      border: var(--hair) solid rgba(0, 0, 0, .12); overflow: hidden;
      box-shadow: 0 8px 24px rgba(0, 0, 0, .35);
      animation: tf-window-in var(--dur-fast) var(--ease);
    }
    :host(.dark) {
      background: #14142a; border-color: rgba(255, 255, 255, .12);
      box-shadow: 0 8px 24px rgba(0, 0, 0, .5);
    }
    @keyframes tf-window-in { from { opacity: 0; } to { opacity: 1; } }
    @media (prefers-reduced-motion: reduce) { :host { animation: none; } }

    .chrome {
      display: flex; align-items: center; gap: 6px; padding: 8px 10px;
      background: #f5f5f7; border-bottom: var(--hair) solid rgba(0, 0, 0, .1);
    }
    :host(.dark) .chrome { background: #202038; border-bottom-color: rgba(255, 255, 255, .1); }
    /* Decorative macOS traffic-light colors — fixed, not app severity tokens, same in both
       variants. Never read these as a severity signal; tf-chip (severity) is a separate element. */
    .dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
    .dot.red { background: #ff5f57; }
    .dot.yellow { background: #febc2e; }
    .dot.green { background: #28c840; }

    .address {
      display: flex; align-items: center; justify-content: center; gap: 4px; flex: 1;
      min-width: 0; margin: 0 8px; padding: 3px 10px; border-radius: 6px;
      background: #e8e8ed; color: #6e6e73; font-size: var(--fs-xs);
    }
    :host(.dark) .address { background: #2c2c46; color: #a8a8c0; }
    .lock { flex: none; }
    .host { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .expand-btn {
      appearance: none; border: 0; cursor: pointer; background: transparent; color: #6e6e73;
      width: 20px; height: 20px; border-radius: 5px; flex: none;
      display: flex; align-items: center; justify-content: center;
      transition: background var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease);
    }
    .expand-btn:hover { background: rgba(0, 0, 0, .06); color: #1d1d1f; }
    .expand-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .expand-btn:active { background: rgba(0, 0, 0, .1); }
    :host(.dark) .expand-btn { color: #a8a8c0; }
    :host(.dark) .expand-btn:hover { background: rgba(255, 255, 255, .08); color: #fff; }
    :host(.dark) .expand-btn:active { background: rgba(255, 255, 255, .14); }

    .page { padding: 16px; }
    .byline { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
    .byline .source { font-size: var(--fs-xs); font-weight: 590; color: #1d1d1f; }
    .byline .time { font-size: var(--fs-xs); color: #6e6e73; margin-left: auto; }
    :host(.dark) .byline .source { color: #fff; }
    :host(.dark) .byline .time { color: #a8a8c0; }
    .headline {
      margin: 0 0 8px; font-size: var(--fs-lg); font-weight: 620; color: #1d1d1f;
      letter-spacing: -.01em; line-height: 1.25;
    }
    :host(.dark) .headline { color: #fff; }
    .summary { margin: 0; font-size: var(--fs-sm); color: #48484a; line-height: 1.5; }
    .summary.muted { color: #8e8e93; font-style: italic; }
    :host(.dark) .summary { color: #c7c7d9; }
    :host(.dark) .summary.muted { color: #7d7d94; }

    /* Compact density for the arsenal table's hover popover — smaller chrome, tighter type,
       fixed width so it reads as a small floating card rather than the full drawer treatment. */
    :host(.compact) { width: 280px; }
    :host(.compact) .page { padding: 12px; }
    :host(.compact) .headline { font-size: var(--fs-sm); margin-bottom: 6px; }
    :host(.compact) .summary {
      font-size: var(--fs-xs); display: -webkit-box; -webkit-line-clamp: 3;
      -webkit-box-orient: vertical; overflow: hidden;
    }
    :host(.compact) .byline { margin-bottom: 6px; }

    /* Rendered detached in document.body (see openExpand()) — tf-story-drawer's :host has a
       transform: translateX(...) for its slide animation, and any transform in the ancestor
       chain turns position: fixed into "relative to that ancestor" instead of the viewport.
       Teleporting the DOM node is what actually centers this on the page instead of the drawer. */
    .modal-backdrop {
      position: fixed; inset: 0; z-index: var(--z-modal);
      background: rgba(0, 0, 0, .6); backdrop-filter: blur(4px);
      display: flex; align-items: center; justify-content: center; padding: 24px;
    }
    .modal-box {
      width: min(900px, 100%); height: min(720px, 90vh);
      background: #fff; border-radius: var(--radius-card); overflow: hidden;
      display: flex; flex-direction: column; box-shadow: 0 24px 64px rgba(0, 0, 0, .5);
    }
    /* Teleported into document.body (see openExpand()'s comment on .modal-backdrop), so it's no
       longer a DOM descendant of :host — the .dark class is bound directly on this element too
       (not inherited via :host(.dark) ancestry, which wouldn't reach across that boundary).
       Note what .dark does NOT reach: only the chrome bar inverts. The canvas below it stays
       white in both themes because a real page is rendered onto it and we don't control that
       page's own background — a site that leaves gaps transparent, or lays out narrower than
       the frame, showed our dark box through its own layout and looked broken. */
    .modal-backdrop.dark .modal-box { box-shadow: 0 24px 64px rgba(0, 0, 0, .7); }
    .modal-head {
      display: flex; align-items: center; gap: 6px; flex: none;
      padding: 8px 10px; background: #f5f5f7; border-bottom: var(--hair) solid rgba(0, 0, 0, .1);
    }
    .modal-backdrop.dark .modal-head { background: #202038; border-bottom-color: rgba(255, 255, 255, .1); }
    .modal-backdrop.dark .modal-head .address { background: #2c2c46; color: #a8a8c0; }
    .modal-close {
      appearance: none; border: 0; cursor: pointer; background: transparent; color: #6e6e73;
      width: 22px; height: 22px; border-radius: 6px; flex: none;
      display: flex; align-items: center; justify-content: center;
      transition: background var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease);
    }
    .modal-close:hover { background: rgba(0, 0, 0, .08); color: #1d1d1f; }
    .modal-close:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .modal-backdrop.dark .modal-close { color: #a8a8c0; }
    .modal-backdrop.dark .modal-close:hover { background: rgba(255, 255, 255, .08); color: #fff; }
    /* Explicitly white rather than inherited: this is the surface a third-party page paints on,
       and it must read as a browser viewport regardless of which theme the app is in. */
    .modal-frame-wrap { position: relative; flex: 1; min-height: 0; background: #fff; }
    .modal-frame { position: absolute; inset: 0; border: 0; width: 100%; height: 100%; background: #fff; }

    /* --accent (#32fae6) is tuned for the app's dark surfaces and washes out to near-invisible
       on the white frame canvas, so these two states use a darkened version of it instead —
       same hue family, ~5.4:1 against white. Local rather than a token: the canvas is fixed
       white here by design (see .modal-frame-wrap), so it can't reuse a theme-reactive value.
       Declared on .modal-backdrop, not :host — the modal is teleported into document.body, so
       nothing declared on the host is in its inheritance chain to cascade down from. */
    .modal-backdrop { --frame-accent: #0a6b60; }

    /* Opaque, not translucent: it covers the frame while the page paints, so a half-rendered
       article never shows through underneath the spinner. */
    .frame-loading {
      position: absolute; inset: 0; z-index: 1; background: #fff;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      gap: 14px; padding: 32px; text-align: center;
    }
    .spinner {
      width: 26px; height: 26px; border-radius: 50%; flex: none;
      border: 2.5px solid rgba(0, 0, 0, .12); border-top-color: var(--frame-accent);
      animation: tf-spin 700ms linear infinite;
    }
    @keyframes tf-spin { to { transform: rotate(360deg); } }
    .frame-loading-text { margin: 0; font-size: var(--fs-sm); color: #6e6e73; max-width: 40ch; }
    /* Reduced motion still needs a "something is happening" signal, so the spinner pulses
       opacity in place rather than disappearing entirely. */
    @media (prefers-reduced-motion: reduce) {
      .spinner { animation: tf-pulse 1.4s ease-in-out infinite; border-top-color: var(--frame-accent); }
      @keyframes tf-pulse { 0%, 100% { opacity: .35; } 50% { opacity: 1; } }
    }

    .frame-error {
      position: absolute; inset: 0; z-index: 1; background: #fff;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      text-align: center; gap: 6px; padding: 32px; color: #6e6e73;
    }
    .frame-error-title { margin: 8px 0 0; font-size: var(--fs-md); font-weight: 620; color: #1d1d1f; }
    .frame-error-body { margin: 0; font-size: var(--fs-sm); max-width: 36ch; }
    /* The literal header text that produced the verdict — useful when it's surprising, but
       never the headline; it's set smaller and monospaced so it reads as evidence, not copy. */
    .frame-error-detail {
      margin: 2px 0 0; font-family: var(--font-mono, ui-monospace, monospace);
      font-size: var(--fs-xs); color: #8e8e93; max-width: 44ch; word-break: break-word;
    }
    /* No .dark variants for the loading/error states either — they occupy the same white canvas
       the framed page would have, so they stay light in both themes for the same reason. */
    /* Underlined at rest, not only on hover: it's the one action on this card, and a colour-only
       link on a card whose whole message is "this didn't work" is easy to read past. */
    .frame-error-link {
      margin-top: 10px; font-size: var(--fs-sm); font-weight: 620; color: var(--frame-accent);
      text-decoration: underline; text-underline-offset: 3px;
    }
    .frame-error-link:hover { color: #06514a; }
    .frame-error-link:focus-visible { outline: 2px solid var(--frame-accent); outline-offset: 3px; border-radius: 3px; }
  `],
})
export class BrowserWindowComponent implements OnDestroy {
  @Input() url: string | null = null;
  @Input() title = '';
  @Input() sourceName = '';
  @Input() sourceStatus: string | null = null;
  @Input() time = '';
  @Input() summary: string | null = null;
  @Input() size: 'full' | 'compact' = 'full';
  // The iframe preview only makes sense for RSS items — most JSON-API/OSV/MISP/etc. sources
  // either have no browsable article page at all or point at a raw feed/API document, not
  // something worth framing. Callers pass this from the item's source fetch_kind.
  @Input() allowExpand = true;

  // Lets a hover-driven host (e.g. the arsenal table's popover) know a modal is open, so it can
  // keep the triggering popover alive instead of tearing this component down mid-preview.
  @Output() expandedChange = new EventEmitter<boolean>();

  @ViewChild('modalTpl') private modalTpl!: TemplateRef<unknown>;

  private sanitizer = inject(DomSanitizer);
  private vcr = inject(ViewContainerRef);
  private renderer = inject(Renderer2);
  private doc = inject(DOCUMENT);
  private themeService = inject(ThemeService);
  private api = inject(ApiService);

  // Inverted, not mirrored: a light app gets a dark preview window and vice versa (see the
  // :host(.dark) comment above) — this component never simply follows the app's own theme.
  isDark = () => this.themeService.theme() === 'light';
  private modalView: EmbeddedViewRef<unknown> | null = null;
  private modalHost: HTMLElement | null = null;
  private loadTimer: ReturnType<typeof setTimeout> | null = null;
  private checkSub: Subscription | null = null;
  private safeUrlCache: { raw: string; safe: SafeResourceUrl } | null = null;

  expanded = signal(false);
  // checking -> asking the API whether the page permits framing; loading -> iframe mounted,
  // waiting for its first load; ready -> loaded; blocked -> our own card is showing instead.
  phase = signal<'checking' | 'loading' | 'ready' | 'blocked'>('checking');
  block = signal<{ title: string; body: string; detail?: string } | null>(null);

  ngOnDestroy(): void {
    this.closeExpand();
  }

  addressText(): string {
    return hostname(this.url) ?? 'no source link';
  }

  // Memoized per raw URL, and that is load-bearing rather than a micro-optimization: Angular
  // compares property-binding values by reference, and bypassSecurityTrustResourceUrl() returns a
  // brand-new SafeResourceUrl every call. Returning a fresh object from the [src] binding made
  // every change-detection pass look like a src change, so the frame re-navigated — and since
  // (load) itself triggers change detection, the reload was self-sustaining, with every mouse
  // move / scroll / keypress over the modal kicking off another one. Same object in, same object
  // out, and the frame navigates exactly once.
  safeUrl(): SafeResourceUrl | null {
    if (!this.url) return null;
    if (this.safeUrlCache?.raw !== this.url) {
      this.safeUrlCache = { raw: this.url, safe: this.sanitizer.bypassSecurityTrustResourceUrl(this.url) };
    }
    return this.safeUrlCache.safe;
  }

  // The modal template is mounted into document.body rather than left in place — see the CSS
  // comment on .modal-backdrop for why an in-place `position: fixed` isn't good enough here.
  openExpand(): void {
    if (!this.url || this.modalView) return;
    this.expanded.set(true);
    this.expandedChange.emit(true);
    this.phase.set('checking');
    this.block.set(null);
    this.modalHost = this.renderer.createElement('div');
    this.renderer.appendChild(this.doc.body, this.modalHost);
    this.modalView = this.vcr.createEmbeddedView(this.modalTpl);
    this.modalView.rootNodes.forEach((node) => this.renderer.appendChild(this.modalHost, node));
    this.modalView.detectChanges();

    // The verdict comes from the server because the browser will not tell us — see the endpoint
    // comment in server/index.js.
    //
    // Only a POSITIVE refusal keeps the iframe from mounting. A check that merely failed to
    // reach a verdict must not: several of these sites (Dark Reading, BleepingComputer) answer
    // a server-side fetch with 403 from bot management while serving a browser normally, so
    // treating "couldn't check" as "blocked" replaced previews that used to work with our error
    // card. When the check is inconclusive we mount the frame anyway and fall back to the load
    // timeout — no better than before this endpoint existed, but no worse either.
    this.checkSub = this.api.previewCheck(this.url).subscribe({
      next: (result) => {
        this.checkSub = null;
        if (result.frameable) this.startFrameLoad();
        else if (INCONCLUSIVE_REASONS.includes(result.reason as string)) this.startFrameLoad(this.blockFor(result));
        else this.showBlock(this.blockFor(result));
      },
      // Our own API being unreachable says nothing at all about the target site, so this is the
      // most inconclusive case there is — try the frame rather than blaming the page.
      error: () => {
        this.checkSub = null;
        this.startFrameLoad({
          title: 'This page can’t be previewed here',
          body: `${this.addressText()} didn't load, and the embedding check was unavailable.`,
        });
      },
    });
  }

  private blockFor(result: PreviewCheck): { title: string; body: string; detail?: string } {
    const host = this.addressText();
    switch (result.reason) {
      case 'x-frame-options':
      case 'frame-ancestors':
        return {
          title: 'This page refuses to be embedded',
          body: `${host} sends a header telling browsers not to display it inside another site.`,
          detail: result.detail,
        };
      // The two inconclusive reasons. Copy is written for the moment it actually gets shown —
      // after the frame was mounted anyway and then failed to load — so it reports both facts:
      // the page didn't render here, and the check that might have explained why never landed.
      case 'unreachable':
        return { title: 'Couldn’t load this page', body: `${host} didn't respond to the preview.`, detail: result.detail };
      case 'http-error':
        return {
          title: 'Couldn’t load this page',
          body: `${host} refused our embedding check, which often means it blocks automated requests. Opening it directly usually still works.`,
          detail: result.detail,
        };
      default:
        return { title: 'This page can’t be previewed here', body: `${host} could not be embedded.`, detail: result.detail };
    }
  }

  // `onTimeout` carries the reason the check was inconclusive, for the case where the frame was
  // mounted on an unproven verdict and then never loaded — that explanation is worth more to a
  // user than a bare "took too long". Absent for a clean pass, where a timeout really is just slow.
  private startFrameLoad(onTimeout?: { title: string; body: string; detail?: string }): void {
    this.phase.set('loading');
    this.modalView?.detectChanges();
    this.loadTimer = setTimeout(() => {
      this.loadTimer = null;
      this.showBlock(onTimeout ?? {
        title: 'This page took too long to load',
        body: `${this.addressText()} passed the embedding check but never finished rendering.`,
      });
    }, IFRAME_LOAD_TIMEOUT_MS);
  }

  private showBlock(info: { title: string; body: string; detail?: string }): void {
    if (this.loadTimer !== null) { clearTimeout(this.loadTimer); this.loadTimer = null; }
    this.block.set(info);
    this.phase.set('blocked');
    this.modalView?.detectChanges();
  }

  // Not proof the page rendered — cross-origin gives us no visibility into that — just that the
  // frame's navigation settled, which is enough to drop the loading overlay and cancel the
  // "stuck" timeout. The earlier debounce here is gone: it existed to absorb the repeat `load`
  // a browser's own refusal page fires (about:blank → error document), and that page no longer
  // reaches the frame at all now that the header check runs first.
  onIframeLoad(): void {
    if (this.loadTimer !== null) { clearTimeout(this.loadTimer); this.loadTimer = null; }
    if (this.phase() === 'loading') {
      this.phase.set('ready');
      this.modalView?.detectChanges();
    }
  }

  closeExpand(): void {
    if (!this.modalView) return;
    if (this.loadTimer !== null) { clearTimeout(this.loadTimer); this.loadTimer = null; }
    this.checkSub?.unsubscribe();
    this.checkSub = null;
    this.expanded.set(false);
    this.expandedChange.emit(false);
    this.modalView.destroy();
    this.modalView = null;
    if (this.modalHost) {
      this.renderer.removeChild(this.doc.body, this.modalHost);
      this.modalHost = null;
    }
  }
}
