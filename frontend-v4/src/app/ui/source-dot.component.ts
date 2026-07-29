import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { sourceHealth } from '../core/format';

const TITLES = {
  ok: 'syncing normally', error: 'last sync failed',
  unsupported: 'not syncable', never: 'never synced',
} as const;

@Component({
  selector: 'tf-source-dot',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  // An analyst should never read an intel claim without seeing whether the pipe behind it
  // is alive. The title is the accessible text; the colour is redundant reinforcement.
  template: `<span class="dot" [class]="state" [title]="name + ' — ' + titleText" role="img" [attr.aria-label]="name + ' ' + titleText"></span>`,
  styles: [`
    .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; flex: none; }
    .ok { background: var(--sev-low); }
    .error { background: var(--sev-critical); }
    .unsupported { background: var(--sev-unknown); }
    .never { background: transparent; box-shadow: inset 0 0 0 1px var(--ink-3); }
  `],
})
export class SourceDotComponent {
  @Input() status: string | null = null;
  @Input() name = '';
  get state() { return sourceHealth(this.status); }
  get titleText() { return TITLES[this.state]; }
}
