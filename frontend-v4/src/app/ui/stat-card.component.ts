import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { severityToken } from '../core/format';

// A single labelled stat, toned by a `--sev-*` token when `tone` is set (CVSS band, KEV
// critical/none) or the neutral `--accent` when it isn't (EPSS has no severity of its own).
// `emphasis` marks the one fact on the row that's actually actionable right now — the CVE page
// sets it on the KEV card only when the vulnerability is listed as known-exploited, so a real
// signal earns the stronger tint instead of every card competing for the same attention.
@Component({
  selector: 'tf-stat-card',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="card" [class.emphasis]="emphasis" [style.--accent-c]="accentColor">
      <p class="label"><span class="dot"></span>{{ label }}</p>
      <p class="value">{{ value }}</p>
      @if (caption) { <p class="caption">{{ caption }}</p> }
    </div>
  `,
  styles: [`
    .card {
      background: var(--surface); border-radius: var(--radius-card); border: var(--hair) solid var(--hairline);
      padding: 12px 16px; display: flex; flex-direction: column; gap: 4px; min-width: 0;
      transition: background var(--dur) var(--ease), border-color var(--dur) var(--ease);
    }
    .card.emphasis {
      background: color-mix(in srgb, var(--accent-c) 12%, var(--surface));
      border-color: color-mix(in srgb, var(--accent-c) 40%, var(--hairline));
    }
    .label {
      margin: 0; display: flex; align-items: center; gap: 6px;
      font-size: var(--fs-xs); font-weight: 590; color: var(--ink-2); text-transform: uppercase; letter-spacing: .04em;
    }
    .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--accent-c); flex-shrink: 0; }
    .card.emphasis .dot { animation: pulse 2s var(--ease) infinite; }
    .value {
      margin: 0; font-size: var(--fs-xl); font-weight: 650; color: var(--ink); letter-spacing: -.015em;
      font-variant-numeric: tabular-nums;
    }
    .card.emphasis .value { color: var(--accent-c); }
    .caption { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: .35; }
    }
    @media (prefers-reduced-motion: reduce) {
      .card.emphasis .dot { animation: none; }
    }
  `],
})
export class StatCardComponent {
  @Input() label = '';
  @Input() value = '';
  @Input() caption = '';
  @Input() tone: string | null = null;
  @Input() emphasis = false;

  get accentColor(): string {
    return this.tone ? severityToken(this.tone) : 'var(--accent)';
  }
}
