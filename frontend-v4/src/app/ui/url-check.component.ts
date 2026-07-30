import { Component, ChangeDetectionStrategy, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService } from '../core/api.service';
import { formatDate } from '../core/format';
import type { IocCheckResult } from '../core/models';

// Standalone URL-reputation lookup: type a URL, get back every item across every category
// (phishing, malware/C2, ...) whose IOCs contain an exact match. Used both as its own route
// and embedded in Explorer in place of the raw phishing item list, which was ~500 URLs deep
// and not something anyone was going to scroll through looking for one address.
@Component({
  selector: 'tf-url-check',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink],
  template: `
    <div class="url-check">
      <form class="row" (submit)="check($event)">
        <div class="input-wrap">
          <svg class="input-icon" viewBox="0 0 20 20" fill="none" aria-hidden="true">
            <circle cx="9" cy="9" r="6.5" stroke="currentColor" stroke-width="1.5"/>
            <path d="M13.5 13.5L17.5 17.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
          </svg>
          <input
            type="text" name="url" [(ngModel)]="url" placeholder="https://example.com/path"
            autocomplete="off" spellcheck="false"
          />
        </div>
        <button type="submit" class="check-btn" [disabled]="loading() || !url.trim()">
          @if (loading()) {
            <span class="spinner" aria-hidden="true"></span> Checking…
          } @else {
            Check URL
          }
        </button>
      </form>

      @if (result(); as r) {
        @if (r.found) {
          <div class="alert alert-danger" role="alert">
            <div class="alert-head">
              <svg class="alert-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M12 3.5 21.5 20h-19L12 3.5Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
                <path d="M12 9.5v4.25" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
                <circle cx="12" cy="17" r="1" fill="currentColor"/>
              </svg>
              <div class="alert-text">
                <p class="alert-title">Reported {{ r.matches.length }} time{{ r.matches.length === 1 ? '' : 's' }}</p>
                <p class="alert-sub">This URL appears in {{ r.matches.length === 1 ? 'an ingested feed' : 'multiple ingested feeds' }}</p>
              </div>
            </div>
            <ul class="matches">
              @for (m of r.matches; track m.itemId; let i = $index) {
                <li class="match-row" [style.animation-delay.ms]="i * 40">
                  <a [routerLink]="['/intel', m.itemId]">{{ m.title || 'Untitled' }}</a>
                  <span class="meta">{{ m.category }} · {{ m.sourceName }} · {{ formatDate(m.publishedAt) }}</span>
                </li>
              }
            </ul>
          </div>
        } @else {
          <div class="alert alert-clear" role="status">
            <svg class="alert-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="12" cy="12" r="9.25" stroke="currentColor" stroke-width="1.6"/>
              <path d="M8 12.5 10.75 15.25 16.25 9.25" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <p>No match — this URL isn't reported in any ingested feed.</p>
          </div>
        }
      } @else if (error()) {
        <div class="alert alert-error" role="alert">
          <svg class="alert-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="9.25" stroke="currentColor" stroke-width="1.6"/>
            <path d="M12 7.5v5.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
            <circle cx="12" cy="16.25" r="1" fill="currentColor"/>
          </svg>
          <p>Couldn't check that URL — request failed.</p>
        </div>
      }
    </div>
  `,
  styles: [`
    .url-check { display: flex; flex-direction: column; align-items: center; gap: 14px; }
    .row { display: flex; gap: 8px; justify-content: center; width: 100%; }

    .input-wrap { position: relative; flex: 1; display: flex; align-items: center; }
    .input-icon {
      position: absolute; left: 12px; width: 16px; height: 16px; color: var(--ink-3);
      pointer-events: none;
    }
    input {
      width: 100%; font: inherit; font-size: var(--fs-sm); color: var(--ink);
      background: var(--surface-2); border: 1px solid var(--hairline); border-radius: 10px;
      padding: 9px 12px 9px 34px;
      transition: border-color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
    }
    input::placeholder { color: var(--ink-3); }
    input:hover { background: var(--surface-3); }
    input:focus-visible {
      outline: none; background: var(--surface); border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-soft);
    }

    .check-btn {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-sm); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0; border-radius: 10px;
      padding: 9px 18px; white-space: nowrap; display: inline-flex; align-items: center; gap: 8px;
      transition: transform 120ms var(--ease-out), background var(--dur-fast) var(--ease), opacity var(--dur-fast) var(--ease);
    }
    @media (hover: hover) and (pointer: fine) {
      .check-btn:not(:disabled):hover { background: color-mix(in oklch, var(--accent-soft), var(--accent) 20%); }
    }
    .check-btn:not(:disabled):active { transform: scale(.97); }
    .check-btn:disabled { cursor: default; opacity: .55; }

    .spinner {
      width: 12px; height: 12px; border-radius: 50%;
      border: 1.5px solid color-mix(in oklch, var(--ink), transparent 70%);
      border-top-color: var(--ink);
      animation: spin .6s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    .alert {
      width: 100%; box-sizing: border-box; border-radius: var(--radius-card);
      border: 1px solid var(--hairline); background: var(--surface);
      padding: 14px 16px; display: flex; flex-direction: column; gap: 10px;
      opacity: 1; transform: translateY(0);
      transition: opacity var(--dur-slow) var(--ease-out), transform var(--dur-slow) var(--ease-out);
      @starting-style { opacity: 0; transform: translateY(6px); }
    }

    .alert-head { display: flex; align-items: flex-start; gap: 10px; }
    .alert-icon { width: 22px; height: 22px; flex-shrink: 0; margin-top: 1px; }
    .alert-text { display: flex; flex-direction: column; gap: 1px; }
    .alert-title { margin: 0; font-size: var(--fs-md); font-weight: 650; }
    .alert-sub { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); }

    .alert-danger {
      border-color: color-mix(in oklch, var(--sev-critical), transparent 65%);
      background: color-mix(in oklch, var(--sev-critical) 9%, var(--surface));
    }
    .alert-danger .alert-icon, .alert-danger .alert-title { color: var(--sev-critical); }

    .alert-clear, .alert-error {
      flex-direction: row; align-items: center; padding: 12px 16px;
    }
    .alert-clear .alert-icon { color: var(--sev-none); }
    .alert-clear p { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }

    .alert-error { border-color: var(--hairline); }
    .alert-error .alert-icon { color: var(--ink-3); }
    .alert-error p { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }

    .matches {
      list-style: none; margin: 0; padding: 10px 0 0; display: flex; flex-direction: column; gap: 2px;
      border-top: var(--hair) solid color-mix(in oklch, var(--sev-critical), transparent 75%);
    }
    .match-row {
      display: flex; flex-direction: column; gap: 2px; padding: 8px 8px; margin: 0 -8px;
      border-radius: 8px;
      animation: rowIn var(--dur-slow) var(--ease-out) both;
      transition: background var(--dur-fast) var(--ease);
    }
    @media (hover: hover) and (pointer: fine) {
      .match-row:hover { background: var(--chrome-hover); }
    }
    @keyframes rowIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
    .matches a { color: var(--ink); font-size: var(--fs-sm); font-weight: 540; }
    .matches a:hover { text-decoration: underline; }
    .matches .meta { font-size: var(--fs-xs); color: var(--ink-2); }

    @media (prefers-reduced-motion: reduce) {
      .alert, .match-row, .check-btn, .spinner { animation-duration: 1ms !important; transition-duration: 1ms !important; }
      .alert { transform: none; }
      .alert { @starting-style { transform: none; } }
    }
  `],
})
export class UrlCheckComponent {
  private api = inject(ApiService);

  url = '';
  loading = signal(false);
  error = signal(false);
  result = signal<IocCheckResult | null>(null);

  formatDate = formatDate;

  check(e: Event): void {
    e.preventDefault();
    const url = this.url.trim();
    if (!url) return;
    this.loading.set(true);
    this.error.set(false);
    this.api.checkIoc(url).subscribe({
      next: (r) => {
        this.result.set(r);
        this.loading.set(false);
      },
      error: () => {
        this.error.set(true);
        this.result.set(null);
        this.loading.set(false);
      },
    });
  }
}
