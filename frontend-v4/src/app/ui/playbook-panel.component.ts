import { Component, Input, ChangeDetectionStrategy, inject, signal, computed } from '@angular/core';
import { PanelComponent } from './panel.component';
import { ApiService } from '../core/api.service';
import { playbookProgress, stepBlocks, groundingFooter } from '../core/playbook';
import type { Playbook } from '../core/models';

// "What to do about this" as a real page section, directly below tf-impact-panel — the two read
// as one thought: what this does to you, then what to do about it.
//
// All logic lives in core/playbook.ts as pure functions. This app runs vitest in a node
// environment with no TestBed by design, so this component is a thin binding plus one piece of
// local, optimistic state: which steps read as ticked right now, ahead of the server's response
// — a checklist that waits on a round-trip for every click feels broken.
@Component({
  selector: 'tf-playbook-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [PanelComponent],
  template: `
    @if (playbook) {
      <tf-panel title="What to do about this" [subtitle]="subtitle()">
        <ol class="steps">
          @for (s of blocks(); track s.key) {
            <li [class.done]="s.done">
              <label>
                <input type="checkbox" [checked]="s.done" (change)="toggle(s.key)" />
                <span class="title">{{ s.title }}</span>
              </label>
              <p class="detail">{{ s.detail }}</p>
              @if (s.link) {
                <a class="link" [href]="s.link" target="_blank" rel="noopener">{{ s.link }}</a>
              }
              <p class="source">from: {{ s.source }}</p>
            </li>
          }
        </ol>
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
    .steps { list-style: none; margin: 0; padding: 0; display: grid; gap: 14px; }
    .steps > li { border-left: 2px solid var(--border); padding-left: 10px; }
    .steps > li.done { border-left-color: var(--sev-low, #2a2); opacity: 0.75; }
    label { display: flex; align-items: center; gap: 8px; cursor: pointer; }
    .title { font-weight: 600; }
    .done .title { text-decoration: line-through; }
    .detail { margin: 4px 0 2px; color: var(--ink-2); }
    .link { font-size: var(--fs-xs); word-break: break-all; }
    .source { margin: 2px 0 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .footer { margin-top: 14px; font-size: var(--fs-xs); color: var(--ink-2); }
    .missing { margin-left: 10px; }
  `],
})
export class PlaybookPanelComponent {
  private api = inject(ApiService);

  @Input() itemId!: number;
  @Input() dueDate: string | null = null;

  private _playbook = signal<Playbook | null>(null);
  @Input() set playbook(value: Playbook | null | undefined) {
    this._playbook.set(value ?? null);
  }
  get playbook(): Playbook | null {
    return this._playbook();
  }

  // Optimistic ticks layered over the server's `done[]`: added on POST before the response
  // returns, removed on DELETE before the response returns, reconciled whenever a fresh
  // `[playbook]` input arrives. Merged into one Playbook so stepBlocks()/playbookProgress()
  // stay the single source of truth for "is this step done" — no second done-check in the
  // template.
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

  blocks = computed(() => stepBlocks(this.effectivePlaybook()));
  progress = computed(() => playbookProgress(this.effectivePlaybook()));
  // Grounding reflects which sources produced steps, not which are ticked — read off the base
  // playbook so an in-flight optimistic tick never changes the footer.
  footer = computed(() => groundingFooter(this._playbook()));

  toggle(key: string): void {
    const nowDone = this.effectivePlaybook()?.done.includes(key) ?? false;
    const opt = this.optimistic();
    const added = new Set(opt.added);
    const removed = new Set(opt.removed);
    if (nowDone) { removed.add(key); added.delete(key); } else { added.add(key); removed.delete(key); }
    this.optimistic.set({ added, removed });

    const call = nowDone ? this.api.untickPlaybookStep(this.itemId, key) : this.api.tickPlaybookStep(this.itemId, key);
    call.subscribe();
  }

  subtitle(): string {
    const { done, total } = this.progress();
    const base = `${done} of ${total} done`;
    return this.dueDate ? `${base} · due ${this.formatDue(this.dueDate)}` : base;
  }

  private formatDue(iso: string): string {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
  }
}
