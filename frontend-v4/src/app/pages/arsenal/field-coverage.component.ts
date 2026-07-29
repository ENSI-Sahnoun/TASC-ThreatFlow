import { Component, Input, ChangeDetectionStrategy } from '@angular/core';

interface CoverageBar { field: string; label: string; pct: number; }

// Raw DB column names -> a human label. Anything not in this map falls back to the raw key
// itself rather than hiding an unrecognised field silently.
const FIELD_LABELS: Record<string, string> = {
  summary: 'Summary', link: 'Link', published_at: 'Published date', severity: 'Severity',
  cvss_score: 'CVSS score', vendor: 'Vendor', region: 'Region', industry: 'Industry',
  confidence: 'Confidence',
};

// One horizontal bar per field, 0-100%. This is the widget that makes per-source data quality
// legible: it's the only place in the app that shows OpenPhish supplies no severity and no
// publication date while NVD supplies both, for the exact same-looking "item" row.
@Component({
  selector: 'tf-field-coverage',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="rows">
      @for (b of bars; track b.field) {
        <div class="row">
          <span class="label">{{ b.label }}</span>
          <div class="track" role="img" [attr.aria-label]="b.label + ' coverage: ' + b.pct + ' percent'">
            <div class="fill" [style.width.%]="b.pct"></div>
          </div>
          <span class="pct">{{ b.pct }}%</span>
        </div>
      }
    </div>
  `,
  styles: [`
    .rows { display: flex; flex-direction: column; gap: 8px; }
    .row { display: grid; grid-template-columns: 11ch 1fr 4ch; align-items: center; gap: 10px; }
    .label { font-size: var(--fs-xs); color: var(--ink-2); }
    .track {
      height: 6px; border-radius: 3px; background: var(--surface-2); overflow: hidden;
    }
    .fill {
      height: 100%; border-radius: 3px; background: var(--accent);
      transition: width var(--dur-slow) var(--ease);
    }
    .pct {
      font-size: var(--fs-xs); font-weight: 590; color: var(--ink); text-align: right;
      font-variant-numeric: tabular-nums;
    }
    @media (prefers-reduced-motion: reduce) { .fill { transition: none; } }
  `],
})
export class FieldCoverageComponent {
  @Input({ required: true }) coverage: Record<string, number> = {};

  get bars(): CoverageBar[] {
    return Object.entries(this.coverage).map(([field, pct]) => ({
      field, label: FIELD_LABELS[field] ?? field, pct: Math.round(pct),
    }));
  }
}
