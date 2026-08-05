import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { PanelComponent } from './panel.component';
import { fixWording, groupProgress, actionCountFor } from '../core/remediation';
import type { RemediationSummary, RemediationQueueGroup } from '../core/models';

// Replaces the intel detail page's inline tf-playbook-panel (Part 9 — reversing Spec B's own
// call to keep it there, recorded rather than silently dropped: "removing it would make the
// detail page worse for the common case of a quick look" was Spec B's reasoning; Part 9 reverses
// it). A compact summary that links into the guided walkthrough rather than duplicating it.
//
// Progress is never invented (Part 9's own rule): it is groupProgress()'s own fraction
// (core/remediation.ts, Spec B) — how many of the asset's actions currently read not_covered —
// rendered only when the group's version is 'known', same rule the queue page's own progress bar
// already follows. When the version is unset there is no ring, only the action and its count.
@Component({
  selector: 'tf-remediation-widget',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [PanelComponent, RouterLink],
  template: `
    @if (remediation) {
      <tf-panel title="Remediation">
        <div class="row">
          @if (ring(); as r) {
            <span class="ring" role="progressbar" [attr.aria-valuenow]="r.done" [attr.aria-valuemax]="r.total">
              <svg viewBox="0 0 36 36">
                <circle class="track" cx="18" cy="18" r="15.5" />
                <circle class="fill" cx="18" cy="18" r="15.5"
                  stroke-dasharray="97.4"
                  [attr.stroke-dashoffset]="r.total ? 97.4 * (1 - r.done / r.total) : 97.4" />
              </svg>
              <span class="ring-label">{{ r.done }}/{{ r.total }}</span>
            </span>
          }
          <div class="body">
            <p class="headline">{{ headline() }}</p>
            <p class="count">{{ count() }} threat{{ count() === 1 ? '' : 's' }}</p>
          </div>
        </div>
        <a class="cta" [routerLink]="['/remediate', itemId]">Open the guided walkthrough &rarr;</a>
      </tf-panel>
    }
  `,
  styles: [`
    .row { display: flex; align-items: center; gap: 12px; }
    .ring { position: relative; width: 44px; height: 44px; flex: none; }
    .ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
    .track { fill: none; stroke: var(--surface-3); stroke-width: 3; }
    .fill {
      fill: none; stroke: var(--accent); stroke-width: 3; stroke-linecap: round;
      transition: stroke-dashoffset var(--dur-slow) var(--ease-out);
    }
    @media (prefers-reduced-motion: reduce) { .fill { transition: none; } }
    .ring-label {
      position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
      font-size: 9px; color: var(--ink-2);
    }
    .body { flex: 1; min-width: 0; }
    .headline { margin: 0; font-weight: 600; color: var(--ink); }
    .count { margin: 2px 0 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .cta { display: inline-block; margin-top: 10px; font-size: var(--fs-xs); color: var(--accent); text-decoration: none; }
    .cta:hover { text-decoration: underline; }
  `],
})
export class RemediationWidgetComponent {
  @Input() remediation: RemediationSummary | null = null;
  @Input() group: RemediationQueueGroup | null = null;
  @Input() itemId!: number;

  headline(): string {
    return this.remediation ? fixWording(this.remediation.fix).headline : '';
  }

  count(): number {
    return this.group ? actionCountFor(this.group, this.itemId) : 1;
  }

  ring(): { done: number; total: number } | null {
    return this.group ? groupProgress(this.group) : null;
  }
}
