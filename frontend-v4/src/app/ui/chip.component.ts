import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { severityToken, severityLabel } from '../core/format';

@Component({
  selector: 'tf-chip',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<span class="chip" [style.--c]="color">{{ text }}</span>`,
  styles: [`
    /* Colour + label together. The label is what carries meaning; colour only reinforces it,
       so the component still works in greyscale and for colour-blind users. */
    .chip {
      display: inline-block; font-size: var(--fs-xs); font-weight: 590;
      padding: 2px 8px; border-radius: 999px;
      background: color-mix(in srgb, var(--c) 16%, transparent);
      color: var(--ink);
      white-space: nowrap;
    }
  `],
})
export class ChipComponent {
  @Input() severity: string | null = null;
  @Input() label = '';
  get color() { return severityToken(this.severity); }
  get text() { return this.label || severityLabel(this.severity); }
}
