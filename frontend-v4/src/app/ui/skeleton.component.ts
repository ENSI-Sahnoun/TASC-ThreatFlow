import { Component, Input, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'tf-skeleton',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `@for (r of bars; track r) { <div class="bar" [style.width.%]="r"></div> }`,
  styles: [`
    .bar { height: 10px; border-radius: 5px; margin: 8px 0; background: var(--surface-2); animation: pulse 1.4s ease-in-out infinite; }
    @keyframes pulse { 0%, 100% { opacity: .5 } 50% { opacity: .9 } }
    @media (prefers-reduced-motion: reduce) { .bar { animation: none; opacity: .6 } }
  `],
})
export class SkeletonComponent {
  @Input() rows = 4;
  get bars() { return Array.from({ length: this.rows }, (_, i) => 100 - (i % 3) * 18); }
}
