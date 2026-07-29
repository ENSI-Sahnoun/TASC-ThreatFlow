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
        <input
          type="text" name="url" [(ngModel)]="url" placeholder="https://example.com/path"
          autocomplete="off" spellcheck="false"
        />
        <button type="submit" [disabled]="loading() || !url.trim()">
          @if (loading()) { Checking… } @else { Check URL }
        </button>
      </form>

      @if (result(); as r) {
        @if (r.found) {
          <div class="msg hit">
            <p class="t">Reported {{ r.matches.length }} time{{ r.matches.length === 1 ? '' : 's' }}</p>
            <ul class="matches">
              @for (m of r.matches; track m.itemId) {
                <li>
                  <a [routerLink]="['/intel', m.itemId]">{{ m.title || 'Untitled' }}</a>
                  <span class="meta">{{ m.category }} · {{ m.sourceName }} · {{ formatDate(m.publishedAt) }}</span>
                </li>
              }
            </ul>
          </div>
        } @else {
          <p class="msg clear">No match — this URL isn't reported in any ingested feed.</p>
        }
      } @else if (error()) {
        <p class="msg err">Couldn't check that URL — request failed.</p>
      }
    </div>
  `,
  styles: [`
    .url-check { display: flex; flex-direction: column; gap: 12px; }
    .row { display: flex; gap: 8px; }
    input {
      flex: 1; font: inherit; font-size: var(--fs-sm); color: var(--ink);
      background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
      padding: 8px 12px;
    }
    input:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-sm); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0; border-radius: 8px;
      padding: 8px 16px; white-space: nowrap;
    }
    button:disabled { cursor: default; opacity: .6; }
    .msg { margin: 0; font-size: var(--fs-sm); }
    .msg.err, .msg.hit .t { color: var(--danger, #d33); }
    .msg.clear { color: var(--ink-2); }
    .msg.hit .t { margin: 0 0 8px; font-weight: 590; }
    .matches { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
    .matches li { display: flex; flex-direction: column; gap: 2px; }
    .matches a { color: var(--ink); font-size: var(--fs-sm); }
    .matches .meta { font-size: var(--fs-xs); color: var(--ink-2); }
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
