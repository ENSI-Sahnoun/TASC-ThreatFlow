import { ChangeDetectionStrategy, Component, Input, OnChanges } from '@angular/core';
import type { EChartsOption } from 'echarts';
import { EchartsDirective } from '../charts/echarts.directive';
import { resolveVar } from '../charts/theme';

// KPI-tile trend line: same ECharts instance every other chart in the app uses, just stripped
// down to a bare sparkline (no axes, no grid) — real hover tooltip instead of the old inert SVG.
@Component({
  selector: 'tf-spark',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [EchartsDirective],
  template: `<div class="chart" role="img" [attr.aria-label]="label" [tfChart]="option"></div>`,
  styles: [`.chart { width: 100%; height: 28px; }`],
})
export class SparkComponent implements OnChanges {
  @Input() series: number[] = [];
  @Input() color = 'var(--accent)';
  @Input() label = '';

  option: EChartsOption = {};

  ngOnChanges(): void {
    const color = resolveVar(this.color, '#0a84ff');
    this.option = {
      grid: { left: 0, right: 0, top: 2, bottom: 2 },
      xAxis: { type: 'category', show: false, boundaryGap: false, data: this.series.map((_, i) => i) },
      yAxis: { type: 'value', show: false, min: (v) => Math.min(0, v.min), scale: true },
      series: [{
        type: 'line',
        data: this.series,
        showSymbol: false,
        lineStyle: { width: 1.5, color },
        areaStyle: { color, opacity: .18 },
      }],
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'none' },
        position: (pt) => [pt[0], -10],
        formatter: (params) => Array.isArray(params) ? String((params[0] as { value: number }).value) : '',
      },
    } as EChartsOption;
  }
}
