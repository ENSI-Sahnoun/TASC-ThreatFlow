import { Component, Input, Output, EventEmitter, ChangeDetectionStrategy, inject, signal, computed } from '@angular/core';
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
              <label class="check-row">
                <span class="check">
                  <input type="checkbox" [checked]="s.done" (change)="toggle(s.key)" />
                  <span class="box" aria-hidden="true">
                    <svg class="tick" viewBox="0 0 16 16">
                      <path d="M3 8.5 L6.5 12 L13 4.5" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                    </svg>
                  </span>
                </span>
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
    .steps { list-style: none; margin: 0; padding: 0; display: grid; gap: 16px; }
    .steps > li + li { padding-top: 16px; border-top: var(--hair) solid var(--hairline); }
    .steps > li.done { opacity: 0.7; }
    .title { font-weight: 600; }
    .done .title { text-decoration: line-through; color: var(--ink-2); }
    .detail { margin: 6px 0 2px 30px; color: var(--ink-2); }
    .link { display: block; margin-left: 30px; font-size: var(--fs-xs); word-break: break-all; }
    .source { margin: 2px 0 0 30px; font-size: var(--fs-xs); color: var(--ink-2); }
    .footer { margin-top: 14px; font-size: var(--fs-xs); color: var(--ink-2); }
    .missing { margin-left: 10px; }

    /* Custom checkbox: the native control stays for a11y/semantics (screen readers, keyboard,
       form participation) but is visually hidden — the box + tick are a sibling that reads its
       :checked/:focus-visible state, so no JS is needed beyond the existing toggle() handler. */
    .check-row { display: flex; align-items: center; gap: 10px; cursor: pointer; min-height: 28px; }
    .check { position: relative; width: 20px; height: 20px; flex: none; }
    .check input {
      position: absolute; inset: -6px; margin: 0; opacity: 0; cursor: pointer; /* -6px: real hit target ~32px */
    }
    .box {
      position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
      border-radius: 6px; border: 1.5px solid var(--ink-3); background: var(--surface-2);
      transition: background var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out),
        transform 100ms var(--ease-out);
    }
    .check:hover .box { border-color: var(--ink-2); }
    .check input:checked + .box { background: var(--accent); border-color: var(--accent); }
    .check input:focus-visible + .box { outline: 2px solid var(--accent); outline-offset: 2px; }
    .check input:active + .box { transform: scale(.9); }
    .tick { width: 12px; height: 12px; stroke: var(--bg); opacity: 0; transform: scale(.4); transform-origin: center; transition: opacity 120ms var(--ease-out), transform 160ms var(--ease-out); }
    .check input:checked + .box .tick { opacity: 1; transform: scale(1); }
    @media (prefers-reduced-motion: reduce) {
      .box, .tick, .check input { transition: none; }
    }
  `],
})
export class PlaybookPanelComponent {
  private api = inject(ApiService);

  @Input() itemId!: number;
  @Input() dueDate: string | null = null;

  // Fired with the NEW done state, right after the optimistic tick — lets the guided page
  // (Spec B) offer to record a new asset version once the 'patch' step is ticked and the fix was
  // a named version, without this component needing to know anything about that flow itself.
  @Output() toggled = new EventEmitter<{ key: string; done: boolean }>();

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
    this.toggled.emit({ key, done: !nowDone });

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
