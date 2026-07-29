import { Component, Input, signal, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'tf-copy-button',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <button type="button" (click)="copy()" [attr.aria-label]="'Copy ' + label">
      {{ done() ? 'Copied' : label }}
    </button>
  `,
  styles: [`
    button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 510;
      color: var(--ink-2); background: var(--surface-2); border: 0;
      padding: 3px 9px; border-radius: 6px;
      transition: color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
    }
    button:hover { color: var(--ink); background: var(--surface-3); }
    button:active { transform: translateY(.5px); }
  `],
})
export class CopyButtonComponent {
  @Input() value = '';
  @Input() label = 'Copy';
  done = signal(false);

  async copy() {
    try {
      await navigator.clipboard.writeText(this.value);
      this.done.set(true);
      setTimeout(() => this.done.set(false), 1400);
    } catch { /* clipboard blocked — the button simply doesn't confirm */ }
  }
}
