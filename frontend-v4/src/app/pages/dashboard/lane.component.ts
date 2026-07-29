import { Component, Input, ChangeDetectionStrategy } from '@angular/core';

// Every widget on the dashboard sits inside a lane; there are no orphan charts. A lane is just a
// named question ("what's exploited right now?") with an accent dot and its content stacked
// beneath it — the panels/charts inside are the answer.
@Component({
  selector: 'tf-lane',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="lane">
      <header>
        <span class="dot" [style.background]="accent"></span>
        <h2>{{ title }}</h2>
      </header>
      <div class="content"><ng-content /></div>
    </section>
  `,
  styles: [`
    .lane { display: flex; flex-direction: column; gap: 12px; }
    header { display: flex; align-items: center; gap: 8px; }
    .dot { width: 6px; height: 6px; border-radius: 50%; flex: none; }
    h2 { margin: 0; font-size: var(--fs-md); font-weight: 600; color: var(--ink); letter-spacing: -.01em; }
    .content { display: flex; flex-direction: column; gap: 12px; }
  `],
})
export class LaneComponent {
  @Input({ required: true }) title!: string;
  @Input() accent = 'var(--accent)';
}
