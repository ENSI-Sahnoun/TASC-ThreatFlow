import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { PanelComponent } from './panel.component';
import {
  tierLabel, tierSubline, impactBlocks, explanation, isModelWritten,
} from '../core/relevance';
import type { Relevance } from '../core/models';

// "How does this affect you" as a real page section rather than a tooltip.
//
// Severity says how bad an issue is in general. This says what it would do to THIS reader, and
// splits that into four labelled blocks so a missing fact reads as a visible gap instead of as
// silence — the same rule the README applies to a NULL confidence.
//
// All of the logic lives in core/relevance.ts as pure functions. This app runs vitest in a node
// environment with no TestBed by design, so a component is a thin binding and its behaviour is
// specified by relevance.spec.ts.
@Component({
  selector: 'tf-impact-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [PanelComponent],
  template: `
    @if (relevance) {
      <tf-panel title="How this affects you" [subtitle]="subtitle">
        <dl class="blocks">
          @for (b of blocks; track b.label) {
            <div [class.gap]="b.missing">
              <dt>{{ b.label }}</dt>
              <dd>
                {{ b.text }}
                <!-- Provenance, so a claim about the reader's own estate can be checked rather
                     than taken on trust. -->
                @if (b.from) { <span class="from" [title]="b.from">why</span> }
              </dd>
            </div>
          }
          <div>
            <dt>Why you</dt>
            <dd>
              {{ explanation(relevance) }}
              @if (isModelWritten(relevance)) {
                <span class="ai-tag" title="Written by a local model — the tier itself is decided by deterministic rules, not the model">AI-generated</span>
              }
            </dd>
          </div>
        </dl>
        @if (relevance.exposure === 'unknown') {
          <p class="unknown">
            You have not told us whether this is reachable from the internet, so this assumes the
            worst. Answering it in your profile sharpens the verdict.
          </p>
        }
      </tf-panel>
    }
  `,
  styles: [`
    .blocks { display: grid; gap: 10px; margin: 0; }
    .blocks > div { display: grid; grid-template-columns: 170px 1fr; gap: 12px; align-items: baseline; }
    dt { color: var(--ink-2); font-size: var(--fs-xs); }
    dd { margin: 0; }
    /* A stated gap is quieter than a fact, but still present and still readable. */
    .gap dd { color: var(--ink-2); font-style: italic; }
    .from {
      font-size: var(--fs-xs); color: var(--ink-2); cursor: help;
      border-bottom: 1px dotted currentColor; margin-left: 6px;
    }
    .ai-tag { font-size: var(--fs-xs); color: var(--ink-2); margin-left: 6px; }
    .unknown { color: var(--ink-2); font-size: var(--fs-xs); margin: 12px 0 0; }
    @media (max-width: 560px) {
      .blocks > div { grid-template-columns: 1fr; gap: 2px; }
    }
  `],
})
export class ImpactPanelComponent {
  @Input() relevance: Relevance | null = null;

  explanation = explanation;
  isModelWritten = isModelWritten;

  get blocks() { return impactBlocks(this.relevance); }

  // Tier and deadline read as one line: "Act now · fix by Aug 17".
  get subtitle() {
    const label = tierLabel(this.relevance?.tier);
    const sub = tierSubline(this.relevance);
    return sub ? `${label} · ${sub}` : label;
  }
}
