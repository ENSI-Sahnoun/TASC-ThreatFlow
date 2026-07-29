import { AfterViewInit, ChangeDetectionStrategy, ChangeDetectorRef, Component, EventEmitter, Input, OnChanges, Output, ViewChild, effect, inject } from '@angular/core';
import type { EChartsOption } from 'echarts';
import { EchartsDirective } from './echarts.directive';
import { ink2, resolveVar, token } from './theme';
import type { ChartDatum } from './bar-chart.component';
import { describeDonutChart } from './chart-summary';
import { ThemeService } from '../core/theme.service';

// --cat-1..8 in source order jumps around the hue wheel (cyan, blue, yellow-green, pink, teal,
// mint, purple, pink again) — fine for a legend where slices aren't adjacent, but a donut ring
// puts consecutive palette entries right next to each other, so that order reads as a clash.
// This is the same 8 tokens re-walked in hue order so neighbouring slices are neighbouring hues.
const HUE_ORDERED_CAT_INDEXES = [3, 6, 1, 5, 2, 7, 4, 8];

// Donut: one slice per datum. Distinct slices need distinct hues to read at all — the categorical
// palette (--cat-1..8) cycles for data without an explicit colour, same source the ECharts theme
// itself is built from, so a slice's colour is never a fresh literal.
@Component({
  selector: 'tf-donut-chart',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [EchartsDirective],
  template: `<div class="chart" role="img" [attr.aria-label]="summary" [tfChart]="option"></div>`,
  styles: [`.chart { width: 100%; height: 220px; }`],
})
export class DonutChartComponent implements OnChanges, AfterViewInit {
  @Input({ required: true }) data: ChartDatum[] = [];
  @Output() pick = new EventEmitter<string>();

  @ViewChild(EchartsDirective) private chartDir?: EchartsDirective;
  private themeService = inject(ThemeService);
  private cdr = inject(ChangeDetectorRef);

  option: EChartsOption = { series: [] };
  summary = '';

  constructor() {
    // ink2()/token() are resolved live inside buildOption(), but that only runs from
    // ngOnChanges — a theme toggle doesn't touch @Input data, so without this the chart keeps
    // whichever theme's colours were live the last time `data` changed (see bar-chart.component
    // for the same fix on the axis-label side).
    effect(() => {
      this.themeService.theme();
      this.option = this.buildOption();
      this.cdr.markForCheck();
    });
  }

  ngOnChanges(): void {
    this.option = this.buildOption();
    this.summary = describeDonutChart(this.data);
  }

  ngAfterViewInit(): void {
    this.chartDir?.on('click', (params) => {
      const name = (params as { name?: string }).name;
      if (name) this.pick.emit(name);
    });
  }

  private buildOption(): EChartsOption {
    const border = token('--bg', '#000000');
    const palette = HUE_ORDERED_CAT_INDEXES.map((i) => token(`--cat-${i}`, '#0a84ff'));
    return {
      tooltip: { trigger: 'item' },
      series: [{
        type: 'pie',
        radius: ['55%', '78%'],
        avoidLabelOverlap: true,
        itemStyle: { borderRadius: 4, borderColor: border, borderWidth: 2 },
        label: { show: true, color: ink2(), fontSize: 11, formatter: '{b}' },
        labelLine: { show: true },
        data: this.data.map((d, i) => {
          const fallback = palette[i % palette.length];
          return { name: d.label, value: d.value, itemStyle: { color: d.color ? resolveVar(d.color, fallback) : fallback } };
        }),
      }],
    } as EChartsOption;
  }
}
