import { Directive, ElementRef, Input, OnDestroy, OnInit, inject, NgZone } from '@angular/core';
import * as echarts from 'echarts';
import type { EChartsOption } from 'echarts';
import { buildTheme, THEME_NAME } from './theme';

let themeRegistered = false;

// A wrapper library would couple chart rendering to a third party's Angular-version support.
// This is the whole surface we need: init, set, resize, dispose.
@Directive({ selector: '[tfChart]', standalone: true })
export class EchartsDirective implements OnInit, OnDestroy {
  private host = inject(ElementRef<HTMLElement>);
  private zone = inject(NgZone);
  private chart: echarts.ECharts | null = null;
  private ro: ResizeObserver | null = null;

  @Input('tfChart') set option(value: EChartsOption | null) {
    this._option = value;
    if (this.chart && value) this.chart.setOption(value, { notMerge: true });
  }
  private _option: EChartsOption | null = null;

  ngOnInit(): void {
    if (!themeRegistered) { echarts.registerTheme(THEME_NAME, buildTheme()); themeRegistered = true; }
    // Charts run outside Angular: ECharts fires high-frequency events and every one of them
    // would otherwise trigger change detection across the whole dashboard.
    this.zone.runOutsideAngular(() => {
      this.chart = echarts.init(this.host.nativeElement, THEME_NAME, { renderer: 'canvas' });
      if (this._option) this.chart.setOption(this._option, { notMerge: true });
      this.ro = new ResizeObserver(() => this.chart?.resize());
      this.ro.observe(this.host.nativeElement);
    });
  }

  ngOnDestroy(): void {
    this.ro?.disconnect();
    this.chart?.dispose();
    this.chart = null;
  }

  on(event: string, handler: (params: unknown) => void): void {
    this.chart?.on(event, handler);
  }
}
