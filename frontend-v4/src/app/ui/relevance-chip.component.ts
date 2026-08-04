import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { tierLabel, tierToken, tierIsProminent, tierSubline, explanation } from '../core/relevance';
import type { Relevance } from '../core/models';

// The "Possible Threat" indicator. Sits beside the severity chip and answers a different
// question: severity is how bad this is in general, this is how much it should matter to you.
//
// The label carries the meaning and the colour only reinforces it, so it still works in
// greyscale — same rule as ChipComponent. The reasoning lives in the tooltip rather than the
// row, because a feed of 24k items has to stay scannable.
@Component({
  selector: 'tf-relevance-chip',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (relevance) {
      <span
        class="rel"
        [class.quiet]="!prominent"
        [style.--c]="color"
        [title]="sentence"
      >{{ label }}@if (subline && !compact) {<span class="sub"> · {{ subline }}</span>}</span>
    }
  `,
  styles: [`
    .rel {
      display: inline-block; font-size: var(--fs-xs); font-weight: 590;
      padding: 2px 8px; border-radius: 999px; white-space: nowrap; cursor: help;
      background: color-mix(in srgb, var(--c) 18%, transparent);
      color: var(--ink);
    }
    /* low / not_yours stay legible and stay in the list — they just do not compete for
       attention with the tiers that need action. */
    .quiet { background: transparent; color: var(--ink-2); border: 1px solid color-mix(in srgb, var(--ink) 14%, transparent); }
    /* The deadline rides along at lower weight — present while scanning, never competing with
       the tier itself. */
    .sub { font-weight: 400; opacity: 0.75; }
  `],
})
export class RelevanceChipComponent {
  @Input() relevance: Relevance | null = null;
  // Dense lists (the intel table) have no room for the deadline text beside the label — it
  // pushed the chip past its fixed column width and bled into the next one. The tooltip still
  // carries it so nothing is lost, just deferred to hover.
  @Input() compact = false;

  get label() { return tierLabel(this.relevance?.tier); }
  get color() { return tierToken(this.relevance?.tier); }
  get prominent() { return tierIsProminent(this.relevance?.tier); }
  get subline() { return tierSubline(this.relevance); }
  get sentence() {
    const base = explanation(this.relevance);
    return this.compact && this.subline ? `${base} (${this.subline})` : base;
  }
}
