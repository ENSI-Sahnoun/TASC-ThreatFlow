import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import type { ReachDiagram } from '../core/remediation';
import { diagramSvgWidth, diagramEdgeLines, DIAGRAM_SLOT_WIDTH } from '../core/remediation';

// Step 1's signature diagram: origin -> gate -> outcome, and (when the vector's scope changed)
// -> scope, drawn from whatever reachDiagram() (core/remediation.ts) already decided from the
// CVSS vector. This component owns no logic of its own beyond which node's "why" popover is
// open and which edge annotation is showing — the same idiom tf-impact-panel already uses for
// its provenance buttons, reused here rather than inventing a second interaction.
//
// Inline SVG, no chart library. Node count and edge geometry both come from core/remediation.ts's
// diagramSvgWidth()/diagramEdgeLines() (Part 7) rather than being hardcoded here, so a fourth
// node (S:C) places itself correctly without a template change beyond what's already here.
// Horizontal scroll on narrow viewports (own .scroll container) rather than reflowing into an
// unreadable stack.
@Component({
  selector: 'tf-reach-diagram',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="scroll">
      <svg [attr.viewBox]="'0 0 ' + svgWidth() + ' 170'" [attr.width]="svgWidth()" [attr.height]="170" role="img" [attr.aria-label]="ariaLabel()">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--ink-2)" />
          </marker>
        </defs>

        @for (e of edgeLines(); track e.key) {
          <line
            class="edge" [attr.x1]="e.x1" [attr.y1]="e.y1" [attr.x2]="e.x2" [attr.y2]="e.y2" marker-end="url(#arrow)"
            [attr.stroke-dasharray]="e.x2 - e.x1" [attr.stroke-dashoffset]="e.x2 - e.x1"
          />
        }

        @for (n of diagram.nodes; track n.id; let i = $index) {
          <g class="node" [style.animation-delay.ms]="i * 80" [attr.transform]="'translate(' + (i * slotWidth) + ', 0)'">
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
      @if (diagram.acAnnotation; as ac) {
        <p class="annotation">{{ ac.from }} — {{ ac.text }}</p>
      }

      <div class="why-row">
        @for (n of diagram.nodes; track n.id) {
          <div class="why-item" [class.open]="isOpen(n.id)">
            <button type="button" class="why" [attr.aria-expanded]="isOpen(n.id)" (click)="toggle(n.id)">
              why: {{ n.title }}
            </button>
            <p class="prov">{{ n.from }}</p>
          </div>
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
      /* stroke-dasharray/stroke-dashoffset are bound per-edge in the template to the edge's own
         length (e.x2 - e.x1) — a fixed CSS value here would only draw correctly for whatever
         node spacing happened to match it at the time, and silently break (a short dash then a
         gap before the arrowhead) the next time DIAGRAM_SLOT_WIDTH changes. */
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

    .why-row { display: flex; flex-wrap: wrap; gap: 10px 18px; margin-top: 10px; }
    .why-item { display: flex; flex-direction: column; }
    .why {
      font: inherit; font-size: var(--fs-xs); color: var(--ink-2); cursor: pointer;
      background: none; border: none; padding: 0; border-bottom: 1px dotted currentColor;
      width: fit-content;
    }
    .why:hover, .why:focus-visible { color: var(--ink); }
    .why:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    /* Revealed on hover or focus (no click needed) — the click/toggle behavior still works
       underneath for touch and keyboard users who can't hover. */
    .prov {
      margin: 0; font-size: var(--fs-xs); color: var(--ink-2);
      max-height: 0; opacity: 0; overflow: hidden;
      transition: max-height var(--dur-fast) var(--ease-out), opacity var(--dur-fast) var(--ease-out), margin-top var(--dur-fast) var(--ease-out);
    }
    .why-item:hover .prov, .why-item:focus-within .prov, .why-item.open .prov {
      max-height: 40px; opacity: 1; margin-top: 4px;
    }
    @media (prefers-reduced-motion: reduce) { .prov { transition: none; } }
  `],
})
export class ReachDiagramComponent {
  @Input() diagram!: ReachDiagram;

  slotWidth = DIAGRAM_SLOT_WIDTH;

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

  svgWidth(): number {
    return diagramSvgWidth(this.diagram);
  }

  edgeLines() {
    return diagramEdgeLines(this.diagram);
  }
}
