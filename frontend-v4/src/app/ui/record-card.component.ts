import { Component, Input, ChangeDetectionStrategy, signal } from '@angular/core';
import { ChipComponent } from './chip.component';
import { stripHtml, epssPercent, cvssBand, severityToken, isRatedSeverity, cardVariant } from '../core/format';
import type { ItemDetail } from '../core/models';

// Non-RSS replacement for tf-browser-window's inner "webpage" card. Most non-RSS sources (OSV,
// json_api, MISP, abuse.ch, bespoke) have no browsable article — framing them as a fake Safari
// window ("no source link" in the address bar) reads as broken, not as a webpage screenshot. This
// renders the same slot as a plain data card instead, with badges that vary by cardVariant() so a
// CVE record, an IOC record, and a ransomware/breach record each surface the field that matters
// most at a glance — without duplicating the Entities/IOCs panels item-detail already renders
// below. No byline here: the caller's own header (source dot/name/time) sits directly above this
// slot, so repeating it inside the card was showing the same source and timestamp twice.
@Component({
  selector: 'tf-record-card',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ChipComponent],
  template: `
    <div class="badges">
      @switch (variant()) {
        @case ('vulnerability') {
          @if (item.cvss_score != null) {
            <span class="badge mono" [style.--c]="cvssColor()">CVSS {{ item.cvss_score }}</span>
          }
          @if (item.epss_score != null) {
            <span class="badge mono" style="--c: var(--sev-medium)">EPSS {{ epssPercent(item.epss_score) }}</span>
          }
          @if (item.exploitation_status === 'actively_exploited') {
            <span class="badge" style="--c: var(--sev-critical)">Actively exploited</span>
          }
        }
        @case ('indicator') {
          @if (item.iocs.length) {
            <span class="badge" style="--c: var(--accent)">{{ item.iocs.length }} indicator{{ item.iocs.length === 1 ? '' : 's' }}</span>
          }
        }
        @case ('incident') {
          @if (item.region) { <span class="badge" style="--c: var(--accent)">{{ item.region }}</span> }
          @if (item.industry) { <span class="badge" style="--c: var(--sev-unknown)">{{ item.industry }}</span> }
        }
      }
      @if (variant() !== 'vulnerability' && isRatedSeverity(item.severity)) {
        <tf-chip [severity]="item.severity" />
      }
    </div>

    <h2 class="title">{{ item.title }}</h2>
    @if (cleanedSummary(); as s) {
      <p class="summary">{{ s }}</p>
    } @else {
      <p class="summary muted">No summary provided</p>
    }
  `,
  styles: [`
    :host {
      display: block; background: var(--surface-2); border-radius: var(--radius-card);
      border: var(--hair) solid var(--hairline); padding: 16px;
      animation: tf-card-in var(--dur-fast) var(--ease-out);
    }
    @keyframes tf-card-in { from { opacity: 0; } to { opacity: 1; } }
    @media (prefers-reduced-motion: reduce) { :host { animation: none; } }

    .badges { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
    .badges:empty { display: none; }
    .badge {
      font-size: 12.5px; font-weight: 590; padding: 3px 9px; border-radius: 999px;
      color: var(--ink); background: color-mix(in srgb, var(--c) 16%, transparent);
      white-space: nowrap;
    }
    .badge.mono { font-family: ui-monospace, monospace; }

    .title {
      margin: 0 0 8px; font-family: 'Montserrat', -apple-system, system-ui, sans-serif;
      font-weight: 600; letter-spacing: -.01em; line-height: 1.2;
      font-size: var(--fs-lg); color: var(--ink);
    }
    .summary { margin: 0; font-size: var(--fs-md); line-height: 1.6; color: color-mix(in srgb, var(--ink-2) 88%, var(--ink) 12%); }
    .summary.muted { font-style: italic; color: var(--ink-2); }
  `],
})
export class RecordCardComponent {
  @Input({ required: true }) set item(value: ItemDetail) {
    this._item = value;
    this._variant.set(cardVariant(value.category));
  }
  get item(): ItemDetail { return this._item; }
  private _item!: ItemDetail;

  private _variant = signal(cardVariant(null));
  variant = this._variant.asReadonly();

  cvssColor(): string { return severityToken(cvssBand(this.item.cvss_score)); }
  cleanedSummary(): string | null { return stripHtml(this.item.summary); }

  epssPercent = epssPercent;
  isRatedSeverity = isRatedSeverity;
}
