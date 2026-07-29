import { Component, Input, OnInit, signal, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { SparkComponent } from './spark.component';
import { compactNumber } from '../core/format';
import type { Kpi } from '../core/models';

@Component({
  selector: 'tf-kpi-tile',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, SparkComponent],
  template: `
    <a class="tile" [style.--c]="color" [routerLink]="link" [queryParams]="queryParams">
      <span class="label">{{ label }}</span>
      <span class="value">{{ display() }}</span>
      <span class="delta" [attr.aria-label]="deltaLabel()">
        <span class="arrow" [class.up]="kpi.delta > 0" [class.down]="kpi.delta < 0" aria-hidden="true">{{ kpi.delta > 0 ? '↑' : kpi.delta < 0 ? '↓' : '·' }}</span>
        <span aria-hidden="true">{{ abs(kpi.delta) }} in 24h</span>
      </span>
      <tf-spark [series]="kpi.series" [color]="color" [label]="label + ' trend'" />
    </a>
  `,
  styles: [`
    .tile {
      display: flex; flex-direction: column; gap: 1px; text-decoration: none;
      /* Flat surface tinted toward each tile's trend colour (--c, same one the spark line
         uses) so tiles stay distinguishable without glass/blur — backdrop-filter over a flat
         page background blurs nothing and triggers a Chromium bug where the blur's paint
         region ignores border-radius, showing as a hard rectangular edge. */
      background: color-mix(in srgb, var(--c) 6%, var(--surface));
      border: var(--hair) solid var(--hairline); border-radius: var(--radius-chrome);
      padding: 13px 15px;
      transition: background var(--dur) var(--ease), transform var(--dur) var(--ease);
    }
    .tile:hover {
      background: color-mix(in srgb, var(--c) 10%, var(--surface));
      transform: translateY(-1px);
    }
    .tile:active { transform: translateY(0); }
    .label { font-size: var(--fs-xs); font-weight: 510; color: var(--ink-2); }
    .value { font-size: var(--fs-2xl); font-weight: 600; letter-spacing: -.032em; color: var(--ink); font-variant-numeric: tabular-nums; line-height: 1.06; }
    /* The delta's own text is always --ink-2 — severity colour is reserved for the arrow glyph,
       a decorative (aria-hidden) mark, never for the readable "N in 24h" text itself. */
    .delta { font-size: var(--fs-xs); font-weight: 510; color: var(--ink-2); }
    .delta .arrow.up { color: var(--sev-low); }
    .delta .arrow.down { color: var(--sev-critical); }
  `],
})
export class KpiTileComponent implements OnInit {
  @Input({ required: true }) label!: string;
  @Input({ required: true }) kpi!: Kpi;
  @Input() color = 'var(--accent)';
  @Input() link: unknown[] = ['/intel'];
  @Input() queryParams: Record<string, string> = {};

  display = signal('—');
  abs = Math.abs;

  deltaLabel(): string {
    const dir = this.kpi.delta > 0 ? 'up' : this.kpi.delta < 0 ? 'down' : 'unchanged';
    return `${dir} ${this.abs(this.kpi.delta)} in the last 24 hours`;
  }

  ngOnInit() {
    // Count-up runs once, on the four tiles only, and never on a re-poll. It signals "these
    // are live values", which is the whole point of the strip. Reduced motion skips it.
    const target = this.kpi.value;
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) { this.display.set(compactNumber(target)); return; }

    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / 600);
      const eased = 1 - Math.pow(1 - t, 4);
      this.display.set(compactNumber(Math.round(target * eased)));
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
}
