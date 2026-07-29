import { AfterViewInit, ChangeDetectionStrategy, ChangeDetectorRef, Component, EventEmitter, Input, OnChanges, Output, ViewChild, effect, inject } from '@angular/core';
import type { EChartsOption } from 'echarts';
import { EchartsDirective } from './echarts.directive';
import { ink2, resolveVar } from './theme';
import { describeBarChart } from './chart-summary';
import { ThemeService } from '../core/theme.service';

export interface ChartDatum {
  label: string;
  value: number;
  /** Bare CSS custom-property name ("--sev-critical") or a var(--x) reference. Resolved via token(). */
  color?: string;
}

// Horizontal bars: a category axis of labels, one bar per datum, click emits the category label
// so callers can drill into /intel, /cve/:id, /actor/:name etc without this component knowing
// about routing.
@Component({
  selector: 'tf-bar-chart',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [EchartsDirective],
  // A canvas is invisible to a screen reader — role="img" + aria-label gives every bar chart a
  // words-only equivalent of the same data (see chart-summary.ts).
  template: `<div class="chart" role="img" [attr.aria-label]="summary" [tfChart]="option"></div>`,
  styles: [`.chart { width: 100%; height: 220px; }`],
})
export class BarChartComponent implements OnChanges, AfterViewInit {
  @Input({ required: true }) data: ChartDatum[] = [];
  // Fallback colour for bars that carry no per-datum `color`. Same bare-name/var() convention.
  @Input() colorBy = '--accent';
  // Real count-based usages (CVSS distribution, top CVEs, top actors) want the number labelled.
  // Presence-only data (e.g. the vendors-affected chart, where every bar is a fabricated `1`)
  // should suppress it — a uniform-length bar already communicates "present", a "1" label next
  // to it reads as a measured count that was never actually taken.
  @Input() showLabels = true;
  @Output() pick = new EventEmitter<string>();

  @ViewChild(EchartsDirective) private chartDir?: EchartsDirective;
  private themeService = inject(ThemeService);
  private cdr = inject(ChangeDetectorRef);

  option: EChartsOption = { series: [] };
  summary = '';

  constructor() {
    // buildOption() resolves ink2()/resolveVar() live, but only ever runs from ngOnChanges — a
    // theme toggle doesn't touch @Input data, so without this the chart keeps whichever theme's
    // colours were live the last time `data` changed.
    effect(() => {
      this.themeService.theme();
      this.option = this.buildOption();
      this.cdr.markForCheck();
    });
  }

  ngOnChanges(): void {
    this.option = this.buildOption();
    this.summary = describeBarChart(this.data, this.showLabels);
  }

  ngAfterViewInit(): void {
    this.chartDir?.on('click', (params) => {
      const name = (params as { name?: string }).name;
      if (name) this.pick.emit(name);
    });
  }

  private buildOption(): EChartsOption {
    const fallback = resolveVar(this.colorBy, '#0a84ff');
    return {
      grid: { left: 4, right: 28, top: 4, bottom: 4, containLabel: true },
      xAxis: { type: 'value', axisLabel: { show: false }, splitLine: { show: false } },
      // Colour set live (not left to the registered echarts theme, which is captured once at
      // first chart init and never re-resolves on a light/dark toggle) so labels stay legible
      // after a theme switch.
      yAxis: { type: 'category', inverse: true, data: this.data.map((d) => d.label), axisLabel: { color: ink2() } },
      series: [{
        type: 'bar',
        data: this.data.map((d) => ({
          value: d.value,
          itemStyle: { color: d.color ? resolveVar(d.color, fallback) : fallback },
        })),
        barWidth: 8,
        itemStyle: { borderRadius: 4 },
        label: { show: this.showLabels, position: 'right', color: ink2(), fontSize: 11 },
      }],
      tooltip: { trigger: 'item' },
    } as EChartsOption;
  }
}
