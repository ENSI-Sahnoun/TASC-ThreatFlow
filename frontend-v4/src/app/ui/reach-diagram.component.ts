import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import type { ReachDiagram } from '../core/remediation';

// Step 1's signature diagram: origin -> gate -> outcome, drawn from whatever reachDiagram()
// (core/remediation.ts) already decided from the CVSS vector. This component owns no logic of
// its own beyond which node's "why" popover is open — the same idiom tf-impact-panel already
// uses for its provenance buttons, reused here rather than inventing a second interaction.
//
// Inline SVG, no chart library: this is three boxes and two arrows. Horizontal scroll on narrow
// viewports (own .scroll container) rather than reflowing into an unreadable stack.
@Component({
  selector: 'tf-reach-diagram',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="scroll">
      <svg viewBox="0 0 640 170" [attr.width]="640" [attr.height]="170" role="img" [attr.aria-label]="ariaLabel()">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--ink-2)" />
          </marker>
        </defs>

        <line class="edge" x1="180" y1="55" x2="230" y2="55" marker-end="url(#arrow)" />
        <line class="edge" x1="420" y1="55" x2="470" y2="55" marker-end="url(#arrow)" />

        @for (n of diagram.nodes; track n.id; let i = $index) {
          <g class="node" [style.animation-delay.ms]="i * 80" [attr.transform]="'translate(' + (i * 240) + ', 0)'">
            <rect x="0" y="10" width="180" height="90" rx="10" class="box" />
            <text x="90" y="35" class="label">{{ n.title }}</text>
            <foreignObject x="10" y="45" width="160" height="45">
              <p class="detail" xmlns="http://www.w3.org/1999/xhtml">{{ n.detail }}</p>
            </foreignObject>
          </g>
        }
      </svg>

      @if (diagram.gateAnnotation; as ann) {
        <p class="annotation">{{ ann.from }} — {{ ann.text }}</p>
      }

      <div class="why-row">
        @for (n of diagram.nodes; track n.id) {
          <button type="button" class="why" [attr.aria-expanded]="isOpen(n.id)" (click)="toggle(n.id)">
            why: {{ n.title }}
          </button>
          @if (isOpen(n.id)) { <p class="prov">{{ n.from }}</p> }
        }
      </div>
    </div>
  `,
  styles: [`
    .scroll { overflow-x: auto; }
    svg { display: block; min-width: 640px; }
    .box { fill: var(--surface-2); stroke: var(--hairline); stroke-width: 1; }
    .label { font-size: 12px; font-weight: 600; fill: var(--ink); text-anchor: middle; }
    .detail { margin: 0; font-size: 11px; color: var(--ink-2); text-align: center; line-height: 1.3; }
    .annotation { margin: 6px 0 0; font-size: var(--fs-xs); color: var(--ink-2); text-align: center; }

    .node {
      opacity: 0;
      animation: node-in 240ms var(--ease-out) forwards;
    }
    @keyframes node-in {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    .edge {
      stroke: var(--ink-2);
      stroke-width: 1.5;
      stroke-dasharray: 60;
      stroke-dashoffset: 60;
      animation: draw 300ms var(--ease-out) forwards;
      animation-delay: 160ms;
    }
    @keyframes draw {
      to { stroke-dashoffset: 0; }
    }
    /* Runs once on creation, never loops or re-triggers on scroll — everything on this page is
       already urgent enough without ambient motion. */
    @media (prefers-reduced-motion: reduce) {
      .node, .edge { animation: none; opacity: 1; stroke-dashoffset: 0; }
    }

    .why-row { display: flex; flex-wrap: wrap; gap: 8px 14px; margin-top: 10px; }
    .why {
      font: inherit; font-size: var(--fs-xs); color: var(--ink-2); cursor: pointer;
      background: none; border: none; padding: 0; border-bottom: 1px dotted currentColor;
    }
    .why:hover, .why:focus-visible { color: var(--ink); }
    .why:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .prov { flex-basis: 100%; margin: 0; font-size: var(--fs-xs); color: var(--ink-2); }
  `],
})
export class ReachDiagramComponent {
  @Input() diagram!: ReachDiagram;

  private openNodes = new Set<string>();

  isOpen(id: string): boolean {
    return this.openNodes.has(id);
  }

  toggle(id: string): void {
    if (this.openNodes.has(id)) this.openNodes.delete(id);
    else this.openNodes.add(id);
  }

  ariaLabel(): string {
    return this.diagram.nodes.map((n) => n.title).join(' leads to ');
  }
}
