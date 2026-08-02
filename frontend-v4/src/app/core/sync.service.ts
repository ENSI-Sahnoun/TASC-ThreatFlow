import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser';
import { ApiService } from './api.service';

// App-wide sync state. Root-provided so it survives route changes — syncAll() is triggered
// from the dashboard but the request and its "syncing" state must outlive that component if
// the user navigates elsewhere before it resolves (the shell shows a persistent badge for it).
@Injectable({ providedIn: 'root' })
export class SyncService {
  private api = inject(ApiService);
  private http = inject(HttpClient);
  private sanitizer = inject(DomSanitizer);

  syncing = signal(false);
  syncResult = signal<{ ok: number; fail: number } | null>(null);
  syncError = signal(false);
  overlayDismissed = signal(false);
  logoSvg = signal<SafeHtml | null>(null);

  constructor() {
    this.fetchLogoSvg();
  }

  // The overlay/badge pulse the mark's own path (see dashboard's .logo-path keyframes), which
  // needs a `class` hook the raw asset doesn't have — tag it on before injecting the markup.
  private fetchLogoSvg(): void {
    this.http.get('logo-mark.svg', { responseType: 'text' }).subscribe((raw) => {
      const tagged = raw.replace('<path ', '<path class="logo-path" ');
      this.logoSvg.set(this.sanitizer.bypassSecurityTrustHtml(tagged));
    });
  }

  syncAll(onDone?: () => void): void {
    this.syncing.set(true);
    this.syncResult.set(null);
    this.syncError.set(false);
    this.overlayDismissed.set(false);
    this.api.syncAll().subscribe({
      next: (res) => {
        const fail = res.results.filter((r) => r.error).length;
        this.syncResult.set({ ok: res.results.length - fail, fail });
        this.syncing.set(false);
        onDone?.();
      },
      error: () => {
        this.syncing.set(false);
        this.syncError.set(true);
      },
    });
  }

  dismissOverlay(): void {
    this.overlayDismissed.set(true);
  }

  reopenOverlay(): void {
    this.overlayDismissed.set(false);
  }
}
