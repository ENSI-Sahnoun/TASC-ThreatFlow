import { Component, Input, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'tf-empty-state',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  // An empty chart must say WHY it is empty. "No data" is a dead end; "OpenPhish supplies no
  // severity" tells the analyst something true about the pipeline.
  template: `
    <div class="empty">
      @if (title) { <p class="t">{{ title }}</p> }
      @if (detail) { <p class="d">{{ detail }}</p> }
      @if (reason) { <p class="r">{{ reason }}</p> }
    </div>
  `,
  styles: [`
    .empty { display: flex; flex-direction: column; gap: 4px; align-items: center; justify-content: center;
             min-height: 120px; text-align: center; padding: 16px; }
    .t { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    .d { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); max-width: 46ch; }
    .r { margin: 4px 0 0; font-size: var(--fs-xs); color: var(--ink-2);
         background: var(--surface-2); padding: 4px 10px; border-radius: 6px; }
  `],
})
export class EmptyStateComponent {
  // No generic filler default ("Nothing to show" etc.) — every call site either passes a real
  // title or, more often, just `reason`, which already says why. A vacant heading over a real
  // reason reads as an unfinished screen, not a considered one.
  @Input() title = '';
  @Input() detail = '';
  @Input() reason = '';
}
