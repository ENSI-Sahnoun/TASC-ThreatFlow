import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { KpiTileComponent } from '../../ui/kpi-tile.component';
import type { DashboardStats } from '../../core/models';

@Component({
  selector: 'tf-kpi-strip',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [KpiTileComponent],
  template: `
    <div class="strip">
      <tf-kpi-tile
        label="Actively exploited"
        [kpi]="stats.kpis.activelyExploited"
        color="var(--sev-critical)"
        [link]="['/intel']"
        [queryParams]="{ exploitation_status: 'actively_exploited' }"
      />
      <tf-kpi-tile
        label="New IOCs"
        [kpi]="stats.kpis.newIocs24h"
        color="var(--accent)"
        [link]="['/intel']"
        [queryParams]="{ category: 'ioc' }"
      />
      <tf-kpi-tile
        label="Critical advisories"
        [kpi]="stats.kpis.criticalAdvisories7d"
        color="var(--sev-high)"
        [link]="['/intel']"
        [queryParams]="{ severity: 'critical' }"
      />
      <tf-kpi-tile
        label="Sources healthy"
        [kpi]="stats.kpis.sourcesHealthy"
        color="var(--sev-low)"
        [link]="['/arsenal']"
        [queryParams]="{}"
      />
    </div>
  `,
  styles: [`
    .strip {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }
  `],
})
export class KpiStripComponent {
  @Input({ required: true }) stats!: DashboardStats;
}
