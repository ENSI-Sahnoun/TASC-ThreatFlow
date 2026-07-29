import { ChangeDetectionStrategy, ChangeDetectorRef, Component, EventEmitter, Input, OnChanges, Output, ViewChild, effect, inject } from '@angular/core';
import type { EChartsOption } from 'echarts';
import { EchartsDirective } from './echarts.directive';
import { ensureWorldMap, ISO2_TO_ID } from './world-map';
import { token } from './theme';
import { ThemeService } from '../core/theme.service';
import { EmptyStateComponent } from '../ui/empty-state.component';
import { describeWorldMap } from './chart-summary';

export interface CountryDatum { code: string; count: number; }

const ID_TO_ISO2: Record<string, string> = Object.fromEntries(
  Object.entries(ISO2_TO_ID).map(([iso2, id]) => [id, iso2]),
);

// Choropleth over world-atlas's 110m topology. The map itself is loaded lazily (ensureWorldMap)
// and only once process-wide; this component just waits for it before handing ECharts an option.
@Component({
  selector: 'tf-world-map',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [EchartsDirective, EmptyStateComponent],
  template: `
    @if (!data.length) {
      <tf-empty-state reason="Geography is only available from ransomware victim reports and IP geolocation" />
    } @else if (ready) {
      <div class="chart" role="img" [attr.aria-label]="summary" [tfChart]="option"></div>
    }
  `,
  styles: [`.chart { width: 100%; height: 320px; }`],
})
export class WorldMapComponent implements OnChanges {
  @Input({ required: true }) data: CountryDatum[] = [];
  @Output() pick = new EventEmitter<string>();

  private cdr = inject(ChangeDetectorRef);
  private themeService = inject(ThemeService);
  ready = false;
  option: EChartsOption | null = null;
  summary = '';

  // The chart div only exists in the template once `ready` flips true, so this must be a setter
  // (a static @ViewChild would stay undefined forever on the first, empty-data render).
  @ViewChild(EchartsDirective) set chartDir(dir: EchartsDirective | undefined) {
    dir?.on('click', (params) => {
      const id = (params as { name?: string }).name ?? '';
      const iso2 = ID_TO_ISO2[id];
      if (iso2) this.pick.emit(iso2);
    });
  }

  constructor() {
    // buildOption() resolves --map-empty/--map-border/--accent live off getComputedStyle, but
    // only ever ran from ngOnChanges — a theme toggle doesn't touch @Input data, so the map kept
    // showing whichever theme's colours were live the first (and usually only) time `data` ever
    // changed, regardless of which theme was active afterward. Same fix bar/donut/line-chart
    // already use for the identical problem.
    effect(() => {
      this.themeService.theme();
      if (this.ready && this.data?.length) {
        this.option = this.buildOption();
        this.cdr.markForCheck();
      }
    });
  }

  ngOnChanges(): void {
    if (!this.data?.length) {
      this.ready = false;
      this.option = null;
      return;
    }
    this.summary = describeWorldMap(this.data);
    ensureWorldMap().then(() => {
      this.ready = true;
      this.option = this.buildOption();
      this.cdr.markForCheck();
    });
  }

  private buildOption(): EChartsOption {
    const accent = token('--accent', '#0a84ff');
    const mapEmpty = token('--map-empty', '#2c2c2e');
    const mapBorder = token('--map-border', 'rgba(255,255,255,.11)');
    const max = Math.max(...this.data.map((d) => d.count), 1);
    const seriesData = this.data
      .map((d) => ({ name: ISO2_TO_ID[d.code.toUpperCase()], value: d.count }))
      .filter((d): d is { name: string; value: number } => !!d.name);

    return {
      tooltip: {
        trigger: 'item',
        formatter: (p: unknown) => {
          const { name, value } = p as { name?: string; value?: number };
          return `${(name && ID_TO_ISO2[name]) ?? name ?? 'Unknown'}: ${value ?? 0}`;
        },
      },
      visualMap: { min: 0, max, show: false, inRange: { color: [mapEmpty, accent] } },
      series: [{
        type: 'map',
        map: 'world',
        // Wheel zooms, drag pans.
        roam: true,
        scaleLimit: { min: 1, max: 8 },
        // The click-to-drill-into-/intel behavior is our own (dir.on('click', ...) below), not
        // echarts' built-in region select — which defaults selectedMode:true and, past a click
        // mid-drag, quietly dims every other region and (via select/emphasis' own label.show:true
        // defaults) prints the region's raw "name" on the map. That name is the topology's numeric
        // ISO id, never a human label (see ensureWorldMap's comment), so it must never render.
        selectedMode: false,
        label: { show: false },
        itemStyle: { areaColor: mapEmpty, borderColor: mapBorder, borderWidth: 1 },
        emphasis: { label: { show: false }, itemStyle: { areaColor: accent } },
        select: { label: { show: false }, itemStyle: { areaColor: accent } },
        data: seriesData,
      }],
    } as EChartsOption;
  }
}
