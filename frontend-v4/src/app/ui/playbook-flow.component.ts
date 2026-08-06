import { Component, Input, Output, EventEmitter, ChangeDetectionStrategy, inject, signal, computed } from '@angular/core';
import { PanelComponent } from './panel.component';
import { ApiService } from '../core/api.service';
import { playbookProgress, groundingFooter } from '../core/playbook';
import { FLOW_TEMPLATES, resolveFlow, layoutFlow, FLOW_CENTER_X } from '../core/playbook-flow';
import type { ResolvedFlowNode } from '../core/playbook-flow';
import type { Playbook } from '../core/models';

// Branching companion to tf-playbook-panel (docs/superpowers/specs/2026-08-06-playbook-flowcharts-design.md).
// Same optimistic-tick idiom as tf-playbook-panel: a click flips the checkbox immediately, ahead
// of the server round-trip, reconciled whenever a fresh [playbook] input arrives.
@Component({
  selector: 'tf-playbook-flow',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [PanelComponent],
  template: `
    @if (playbook) {
      <tf-panel title="What to do about this" [subtitle]="subtitle()">
        <div class="scroll">
          <svg [attr.viewBox]="'0 0 ' + layout().width + ' ' + layout().height" [attr.width]="layout().width" [attr.height]="layout().height" role="img" [attr.aria-label]="ariaLabel()">
            <defs>
              <marker id="flow-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="var(--ink-2)" />
              </marker>
            </defs>

            @for (e of layout().edges; track e.key) {
              <line
                class="edge" [class.dashed]="e.dashed"
                [attr.x1]="e.x1" [attr.y1]="e.y1" [attr.x2]="e.x2" [attr.y2]="e.y2" marker-end="url(#flow-arrow)"
              />
              @if (e.label) {
                <text class="edge-label" [attr.x]="e.labelX" [attr.y]="e.labelY">{{ e.label }}</text>
              }
            }

            @for (p of layout().nodes; track p.node.key) {
              @switch (p.node.type) {
                @case ('start') {
                  <g [attr.transform]="'translate(' + p.x + ',' + p.y + ')'">
                    <rect width="160" height="30" rx="15" class="pill" />
                    <text x="80" y="19" class="pill-label">{{ p.node.label }}</text>
                  </g>
                }
                @case ('end') {
                  <g [attr.transform]="'translate(' + p.x + ',' + p.y + ')'">
                    <foreignObject width="160" height="30">
                      <button
                        type="button" class="done-btn" xmlns="http://www.w3.org/1999/xhtml"
                        [class.done]="allDone()" [disabled]="allDone() || closing()"
                        (click)="markDone()"
                      >
                        {{ closing() ? 'Closing…' : allDone() ? p.node.label : 'Mark done' }}
                      </button>
                    </foreignObject>
                  </g>
                }
                @case ('decision') {
                  <g [attr.transform]="'translate(' + p.x + ',' + p.y + ')'">
                    <polygon [attr.points]="diamondPoints(p.width, p.height)" class="diamond" />
                    <foreignObject width="140" height="92">
                      <p class="diamond-label" xmlns="http://www.w3.org/1999/xhtml">{{ p.node.question }}</p>
                    </foreignObject>
                  </g>
                }
                @case ('action') {
                  <g [attr.transform]="'translate(' + p.x + ',' + p.y + ')'" [class.skipped]="!p.node.resolved">
                    <rect width="220" height="48" rx="7" class="box" [class.taken]="p.node.resolved" />
                    @if (p.node.resolved) {
                      <foreignObject x="8" y="8" width="204" height="32">
                        <label class="check-row" xmlns="http://www.w3.org/1999/xhtml">
                          <input type="checkbox" [checked]="p.node.done" (change)="toggle(p.node.key)" />
                          <span class="title">{{ titleFor(p.node.key) }}</span>
                        </label>
                      </foreignObject>
                    } @else {
                      <foreignObject x="8" y="8" width="204" height="32">
                        <p class="skipped-label" xmlns="http://www.w3.org/1999/xhtml">{{ titleFor(p.node.key) }}</p>
                      </foreignObject>
                    }
                  </g>
                }
              }
            }
          </svg>
        </div>
        @if (footer().groundedIn.length || footer().missing.length) {
          <p class="footer">
            @if (footer().groundedIn.length) { Grounded in: {{ footer().groundedIn.join(' · ') }} }
            @if (footer().missing.length) { <span class="missing">Not available: {{ footer().missing.join(', ') }}</span> }
          </p>
        }
      </tf-panel>
    }
  `,
  styles: [`
    .scroll { overflow-x: auto; }
    svg { display: block; margin: 0 auto; }
    .pill { fill: var(--surface-2); stroke: var(--accent); stroke-width: 1.5; }
    .pill-label { font-size: 10.5px; fill: var(--ink); text-anchor: middle; dominant-baseline: middle; }
    .done-btn {
      appearance: none; cursor: pointer; font: inherit; font-size: 10.5px; font-weight: 590;
      width: 160px; height: 30px; border-radius: 15px; text-align: center;
      color: var(--bg); background: var(--accent); border: 1.5px solid var(--accent);
      transition: opacity var(--dur-fast) var(--ease-out);
    }
    .done-btn:hover:not(:disabled) { opacity: .9; }
    .done-btn:disabled { cursor: default; }
    .done-btn.done { color: var(--ink); background: var(--surface-2); opacity: 1; }
    .diamond { fill: var(--accent); }
    .diamond-label {
      margin: 0; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center;
      text-align: center; font-size: 9px; font-weight: 700; color: var(--bg); line-height: 1.25; padding: 0 10px;
    }
    .box { fill: var(--surface-2); stroke: var(--hairline); stroke-width: 1.5; }
    .box.taken { stroke: var(--accent); }
    .skipped .box { stroke-dasharray: 4 3; opacity: .55; }
    .skipped-label { margin: 0; font-size: 10px; color: var(--ink-2); text-align: center; line-height: 1.3; }
    .edge { stroke: var(--ink-2); stroke-width: 1.5; }
    .edge.dashed { stroke-dasharray: 4 3; opacity: .7; }
    .edge-label { font-size: 9px; fill: var(--ink-2); }
    .check-row { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 10px; color: var(--ink); }
    .check-row input { width: 14px; height: 14px; accent-color: var(--accent); cursor: pointer; }
    .title { line-height: 1.3; }
    .footer { margin: 10px 16px 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .missing { margin-left: 10px; }
    @media (prefers-reduced-motion: reduce) { * { animation: none !important; } }
  `],
})
export class PlaybookFlowComponent {
  private api = inject(ApiService);

  @Input() itemId!: number;
  @Input() category!: string;

  @Output() toggled = new EventEmitter<{ key: string; done: boolean }>();

  private _playbook = signal<Playbook | null>(null);
  @Input() set playbook(value: Playbook | null | undefined) {
    this._playbook.set(value ?? null);
  }
  get playbook(): Playbook | null {
    return this._playbook();
  }

  // Same optimistic-tick pattern as tf-playbook-panel: layered over the server's done[], added on
  // POST before the response returns, removed on DELETE before the response returns.
  private optimistic = signal<{ added: Set<string>; removed: Set<string> }>({ added: new Set(), removed: new Set() });

  private effectivePlaybook = computed<Playbook | null>(() => {
    const pb = this._playbook();
    if (!pb) return null;
    const opt = this.optimistic();
    const done = new Set(pb.done);
    for (const k of opt.added) done.add(k);
    for (const k of opt.removed) done.delete(k);
    return { ...pb, done: [...done] };
  });

  private resolved = computed<ResolvedFlowNode[]>(() => {
    const template = FLOW_TEMPLATES[this.category] ?? [];
    return resolveFlow(template, this.effectivePlaybook());
  });

  layout = computed(() => layoutFlow(this.resolved()));
  progress = computed(() => playbookProgress(this.effectivePlaybook()));
  footer = computed(() => groundingFooter(this._playbook()));

  allDone = computed(() => {
    const { done, total } = this.progress();
    return total > 0 && done >= total;
  });
  closing = signal(false);

  centerX = FLOW_CENTER_X;

  diamondPoints(width: number, height: number): string {
    const hw = width / 2;
    const hh = height / 2;
    return `${hw},0 ${width},${hh} ${hw},${height} 0,${hh}`;
  }

  titleFor(key: string): string {
    return this._playbook()?.steps.find((s) => s.key === key)?.title ?? '';
  }

  ariaLabel(): string {
    const template = FLOW_TEMPLATES[this.category] ?? [];
    return template.map((n) => ('label' in n ? n.label : 'question' in n ? n.question : n.key)).join(' then ');
  }

  subtitle(): string {
    const { done, total } = this.progress();
    return `${done} of ${total} done`;
  }

  toggle(key: string): void {
    const nowDone = this.effectivePlaybook()?.done.includes(key) ?? false;
    const opt = this.optimistic();
    const added = new Set(opt.added);
    const removed = new Set(opt.removed);
    if (nowDone) { removed.add(key); added.delete(key); } else { added.add(key); removed.delete(key); }
    this.optimistic.set({ added, removed });
    this.toggled.emit({ key, done: !nowDone });

    const call = nowDone ? this.api.untickPlaybookStep(this.itemId, key) : this.api.tickPlaybookStep(this.itemId, key);
    call.subscribe();
  }

  // Bulk-tick shortcut: ticks every remaining step at once, same loop
  // remediation-guided.component.ts's autoTickAppliedSteps already runs for the CVE version-bump
  // flow. "Closed" on the Remediate dashboard is simply "every step ticked" — no separate flag.
  markDone(): void {
    if (this.allDone() || this.closing()) return;
    const pb = this.effectivePlaybook();
    if (!pb) return;
    const doneKeys = new Set(pb.done);
    const remaining = pb.steps.map((s) => s.key).filter((k) => !doneKeys.has(k));
    if (!remaining.length) return;

    this.closing.set(true);
    const opt = this.optimistic();
    const added = new Set(opt.added);
    for (const k of remaining) added.add(k);
    this.optimistic.set({ added, removed: opt.removed });

    let pending = remaining.length;
    const settle = () => { pending -= 1; if (pending === 0) this.closing.set(false); };
    for (const k of remaining) {
      this.toggled.emit({ key: k, done: true });
      this.api.tickPlaybookStep(this.itemId, k).subscribe({ next: settle, error: settle });
    }
  }
}
