import { ChangeDetectionStrategy, Component, Input, inject } from '@angular/core';
import { Router } from '@angular/router';
import { LaneComponent } from './lane.component';
import { PanelComponent } from '../../ui/panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { BarChartComponent, type ChartDatum } from '../../charts/bar-chart.component';
import { DonutChartComponent } from '../../charts/donut-chart.component';
import { WorldMapComponent } from '../../charts/world-map.component';
import type { DashboardStats } from '../../core/models';

// "Spreading": where an incident is showing up geographically, what malware keeps recurring, and
// which actors are named across sources. All three come straight off DashboardStats.
@Component({
  selector: 'tf-lane-spreading',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LaneComponent, PanelComponent, EmptyStateComponent, BarChartComponent, DonutChartComponent, WorldMapComponent],
  template: `
    <tf-lane title="Spreading" accent="var(--cat-2)">
      <tf-panel
        title="Victim & infrastructure geography"
        subtitle="Sourced only from ransomware.live victim reports and IP geolocation — never inferred from an advisory issuer's country"
      >
        <tf-world-map [data]="stats.targetedCountries" (pick)="onCountry($event)" />
      </tf-panel>

      <tf-panel title="Malware families">
        @if (malwareData.length) {
          <tf-donut-chart [data]="malwareData" (pick)="onMalware($event)" />
        } @else {
          <tf-empty-state reason="No malware families in the current window" />
        }
      </tf-panel>

      <tf-panel title="Top actors">
        @if (actorData.length) {
          <tf-bar-chart [data]="actorData" colorBy="--cat-2" (pick)="onActor($event)" />
        } @else {
          <tf-empty-state reason="No actor attributions in the current window" />
        }
      </tf-panel>
    </tf-lane>
  `,
})
export class LaneSpreadingComponent {
  @Input({ required: true }) stats!: DashboardStats;

  private router = inject(Router);

  get malwareData(): ChartDatum[] {
    return this.stats.topMalware.map((m) => ({ label: m.family, value: m.count }));
  }

  get actorData(): ChartDatum[] {
    return this.stats.topActors.map((a) => ({ label: a.actor, value: a.count }));
  }

  onCountry(code: string): void {
    this.router.navigate(['/intel'], { queryParams: { region: code } });
  }

  onMalware(family: string): void {
    this.router.navigate(['/malware', family]);
  }

  onActor(actor: string): void {
    this.router.navigate(['/actor', actor]);
  }
}
