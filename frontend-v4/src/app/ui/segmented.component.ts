import { Component, Input, Output, EventEmitter, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'tf-segmented',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="seg" role="tablist">
      @for (o of options; track o) {
        <button type="button" role="tab" [attr.aria-selected]="o === value"
                [class.on]="o === value" (click)="valueChange.emit(o)">{{ o }}</button>
      }
    </div>
  `,
  styles: [`
    .seg { display: inline-flex; padding: 2px; gap: 2px; background: var(--surface-2); border-radius: 9px; }
    button {
      appearance: none; border: 0; background: transparent; cursor: pointer;
      font: inherit; font-size: var(--fs-xs); font-weight: 510; color: var(--ink-2);
      padding: 4px 11px; border-radius: 7px; transition: background var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease);
    }
    button:hover:not(.on) { color: var(--ink); }
    button.on { background: var(--surface-4); color: var(--ink); }
    button:disabled { opacity: .4; cursor: not-allowed; }
  `],
})
export class SegmentedComponent {
  @Input() options: string[] = [];
  @Input() value = '';
  @Output() valueChange = new EventEmitter<string>();
}
