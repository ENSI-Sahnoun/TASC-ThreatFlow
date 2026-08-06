import { Component, ChangeDetectionStrategy, inject, signal, computed, effect, ElementRef, ViewChild } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import type { HttpErrorResponse } from '@angular/common/http';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { PanelComponent } from '../../ui/panel.component';
import { ReachDiagramComponent } from '../../ui/reach-diagram.component';
import { PlaybookPanelComponent } from '../../ui/playbook-panel.component';
import { PlaybookFlowComponent } from '../../ui/playbook-flow.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import {
  parseVectorMetrics, reachDiagram, affectedWording, fixWording, countCleared, versionRecordedMessage,
  isPastDue, formatDueDate,
} from '../../core/remediation';
import { hasFlow } from '../../core/playbook-flow';
import type { RemediationDetail } from '../../core/models';

// The routed "/remediate/:itemId" guided page: one threat, walked through in four steps on a
// rail that traps nobody — every step is readable top to bottom with no interaction, per the
// spec's own "not a wizard" rule.
@Component({
  selector: 'tf-page-remediate-item',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, PanelComponent, ReachDiagramComponent, PlaybookPanelComponent, PlaybookFlowComponent, EmptyStateComponent, SkeletonComponent],
  template: `
    @if (loading()) {
      <tf-skeleton [rows]="10" />
    } @else if (notFound()) {
      <tf-empty-state title="Item not found" reason="GET /api/items/:id/remediation returned 404" />
    } @else if (detail()) {
      @let d = detail()!;
      <a class="back" [routerLink]="['/intel', d.item.id]">&larr; Back to item</a>
      <h1>{{ d.item.title }}</h1>

      <div class="layout">
      <div class="stack">
      <tf-panel title="What this does">
        <tf-reach-diagram [diagram]="diagram()" />
        @if (d.kevListed) {
          <p class="kev-badge" [class.past-due]="d.kevDueDate && isPastDue(d.kevDueDate)">
            Known exploited
            @if (d.kevRansomware) { &middot; ransomware-associated }
            @if (d.kevDueDate) {
              &middot; due {{ formatDueDate(d.kevDueDate) }}
              @if (isPastDue(d.kevDueDate)) { (past due) }
            }
          </p>
        }
      </tf-panel>

      @if (!d.asset) {
        <tf-panel title="Are you affected">
          <tf-empty-state
            title="Tell us what you run"
            reason="No asset in your profile matches this item yet — add one and this page fills itself in"
          />
          <a class="cta" routerLink="/onboarding">Go to profile setup &rarr;</a>
        </tf-panel>
      } @else {
        <tf-panel title="Are you affected">
          <p class="range">
            Affected: {{ d.asset.vendor }} {{ d.asset.product }}
            @if (d.remediation?.entry?.text) { — {{ d.remediation!.entry!.text }} }
          </p>

          @for (v of [verdict()]; track v.headline) {
            <div class="verdict">
              <p class="headline">{{ v.headline }}</p>
              <p class="detail">{{ v.detail }}</p>
            </div>
          }

          <form class="version-form" (submit)="submitVersion($event)">
            <label>
              You run
              <input
                type="text" name="version" [value]="versionInput()" (input)="onVersionInput($event)"
                placeholder="e.g. 7.4.5" [disabled]="versionSaving()"
              />
            </label>
            @if (fixVersionValue(); as fv) {
              <button type="button" class="chip" [disabled]="versionSaving()" (click)="useFixVersion(fv)">use {{ fv }}</button>
            }
            <button type="submit" class="primary" [disabled]="versionSaving()">
              {{ versionSaving() ? 'Saving…' : 'Save' }}
            </button>
            <button type="button" [disabled]="versionSaving()" (click)="declineVersion()">I don't know</button>
          </form>
          @if (versionError(); as err) { <p class="version-error">{{ err }}</p> }
        </tf-panel>

        <tf-panel title="The fix">
          <p class="headline">{{ fix().headline }}</p>
          @if (fix().detail) { <p class="detail">{{ fix().detail }}</p> }
          @if (fix().note) { <a class="note" [href]="fix().note" target="_blank" rel="noopener">{{ fix().note }}</a> }
          <!-- patchUrl is a sibling of remediation.fix, not a variant of it — shown only
               underneath a 'version' target, the spec's exact conditional ("with the vendor's
               patch link beneath it if one exists"). -->
          @if (d.remediation?.fix?.kind === 'version' && d.patchUrl) {
            <a class="note" [href]="d.patchUrl" target="_blank" rel="noopener">{{ d.patchUrl }}</a>
          }
          @if (d.remediation?.fix?.kind === 'none' && (d.remediation?.mitigations?.length ?? 0) > 0) {
            <ul class="mitigations">
              @for (m of d.remediation!.mitigations; track m.key) {
                <li><span class="t">{{ m.title }}</span><p>{{ m.detail }}</p></li>
              }
            </ul>
          }
        </tf-panel>
      }

      @if (hasFlow(d.item.category)) {
        <tf-playbook-flow [playbook]="d.playbook" [itemId]="d.item.id" [category]="d.item.category" (toggled)="onStepToggled($event)" />
      } @else if (d.playbook) {
        <tf-playbook-panel [playbook]="d.playbook" [itemId]="d.item.id" (toggled)="onStepToggled($event)" />
      }

      <dialog #bumpDialog class="bump-dialog" (cancel)="offerVersionBump.set(false)" (click)="onDialogClick($event, bumpDialog)">
        <div class="bump-content">
          <h2>Close it out</h2>
          <p>Applied the fix. Record that you're now on {{ bumpTarget() }}?</p>
          <div class="bump-actions">
            <button type="button" class="primary" [disabled]="versionSaving()" (click)="confirmVersionBump()">
              {{ versionSaving() ? 'Recording…' : 'Yes' }}
            </button>
            <button type="button" [disabled]="versionSaving()" (click)="offerVersionBump.set(false)">Not yet</button>
          </div>
          @if (versionError(); as err) { <p class="version-error">{{ err }}</p> }
        </div>
      </dialog>

      @if (recordedMessage(); as msg) {
        <tf-panel title="Close it out">
          <p>{{ msg }}</p>
          <a routerLink="/remediate">See them &rarr;</a>
        </tf-panel>
      }
      </div>

      <aside class="assist" [class.open]="assistOpen()">
        <button type="button" class="assist-toggle" [attr.aria-expanded]="assistOpen()" (click)="assistOpen.set(!assistOpen())">
          <span>AI Assist</span>
        </button>
        @if (assistOpen()) {
          <div class="assist-body">
            <h2>AI Assist</h2>
            <p class="assist-status">Coming soon</p>
            <p>A plain-language explanation of this vulnerability, generated on demand from the facts already on this page.</p>
          </div>
        }
      </aside>
      </div>
    }
  `,
  styles: [`
    .back { font-size: var(--fs-xs); color: var(--ink-2); text-decoration: none; }
    h1 { font-size: var(--fs-lg); margin: 8px 0 12px; }
    .stack { display: grid; gap: 16px; }
    .layout { display: flex; align-items: flex-start; gap: 16px; }
    .layout > .stack { flex: 1; min-width: 0; }
    .assist {
      flex: 0 0 34px; display: flex; flex-direction: column; align-items: stretch;
      background: var(--surface); border: var(--hair) solid var(--hairline); border-radius: var(--radius-card);
      overflow: hidden; transition: flex-basis var(--dur) var(--ease-out);
    }
    .assist.open { flex-basis: 280px; }
    .assist-toggle {
      appearance: none; cursor: pointer; font: inherit; background: none; border: 0; color: var(--ink-2);
      padding: 12px 0; display: flex; align-items: center; justify-content: center; flex: none;
    }
    .assist:not(.open) .assist-toggle span {
      writing-mode: vertical-rl; font-size: var(--fs-xs); font-weight: 600; letter-spacing: .02em;
    }
    .assist.open .assist-toggle { justify-content: flex-start; padding: 12px 16px 0; }
    .assist-body { padding: 4px 16px 16px; }
    .assist-body h2 { margin: 0 0 4px; font-size: var(--fs-sm); font-weight: 600; color: var(--ink); }
    .assist-status {
      display: inline-block; margin: 0 0 8px; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2);
      background: var(--surface-2); padding: 2px 8px; border-radius: 999px;
    }
    .assist-body p:not(.assist-status) { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }
    @media (prefers-reduced-motion: reduce) { .assist { transition: none; } }
    .range { margin: 0 0 10px; font-size: var(--fs-sm); color: var(--ink-2); }
    .verdict { margin: 0 0 14px; animation: verdict-in 180ms var(--ease-out); }
    @keyframes verdict-in { from { opacity: 0; } to { opacity: 1; } }
    @media (prefers-reduced-motion: reduce) { .verdict { animation: none; } }
    .verdict .headline { margin: 0; font-weight: 600; color: var(--ink); }
    .verdict .detail { margin: 2px 0 0; font-size: var(--fs-sm); color: var(--ink-2); }
    .version-form { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .version-form input {
      font: inherit; background: var(--surface-2); border: var(--hair) solid var(--hairline);
      border-radius: 6px; padding: 5px 8px; color: var(--ink);
      transition: opacity var(--dur-fast) var(--ease-out);
    }
    .version-form input:disabled { opacity: .6; }
    .version-error { margin: 8px 0 0; font-size: var(--fs-xs); color: var(--sev-critical); }
    button.chip {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--accent); background: var(--accent-soft); border: 0; padding: 5px 12px; border-radius: 999px;
      transition: opacity var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    button.primary {
      appearance: none; cursor: pointer; font: inherit; font-weight: 590;
      color: var(--bg); background: var(--accent); border: 0; padding: 6px 14px; border-radius: 8px;
      transition: opacity var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    button {
      appearance: none; cursor: pointer; font: inherit; background: var(--surface-2); color: var(--ink);
      border: 0; padding: 6px 14px; border-radius: 8px;
      transition: opacity var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    button:active:not(:disabled) { transform: scale(.97); }
    button:disabled { opacity: .55; cursor: default; }
    button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    @media (prefers-reduced-motion: reduce) { button, .version-form input { transition: none; } }
    .mitigations { list-style: none; margin: 10px 0 0; padding: 0; display: grid; gap: 8px; }
    .mitigations .t { font-weight: 600; }
    .note { display: block; margin-top: 6px; font-size: var(--fs-xs); word-break: break-all; }
    .cta { color: var(--accent); }
    .kev-badge {
      display: inline-block; margin-top: 8px; font-size: var(--fs-xs); font-weight: 700; color: var(--bg);
      background: var(--sev-critical); padding: 3px 10px; border-radius: 999px;
    }
    .kev-badge.past-due { background: var(--sev-critical); outline: 2px solid var(--sev-critical); outline-offset: 1px; }

    .bump-dialog {
      border: 0; border-radius: var(--radius-card); padding: 0; background: var(--surface);
      color: var(--ink); box-shadow: 0 24px 60px -20px rgba(0, 0, 20, .6);
    }
    .bump-dialog::backdrop { background: rgba(0, 0, 20, .55); backdrop-filter: blur(3px); }
    .bump-content { padding: 20px; display: grid; gap: 12px; min-width: 280px; max-width: 380px; }
    .bump-content h2 { margin: 0; font-size: var(--fs-md); font-weight: 650; }
    .bump-content p { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }
    .bump-actions { display: flex; gap: 8px; }
    /* Materializes rather than just fading — a real surface arriving, not an opacity toggle. */
    @starting-style {
      .bump-dialog[open] { opacity: 0; transform: scale(.96) translateY(4px); }
      .bump-dialog[open]::backdrop { opacity: 0; }
    }
    .bump-dialog[open] {
      opacity: 1; transform: none;
      transition: opacity var(--dur) var(--ease-out), transform var(--dur) var(--ease-out), overlay var(--dur) allow-discrete, display var(--dur) allow-discrete;
    }
    .bump-dialog[open]::backdrop {
      opacity: 1; transition: opacity var(--dur) var(--ease-out);
    }
    @media (prefers-reduced-motion: reduce) {
      .bump-dialog[open], .bump-dialog[open]::backdrop { transition: opacity var(--dur-fast) linear; }
      @starting-style { .bump-dialog[open] { transform: none; } }
    }
  `],
})
export class RemediationGuidedComponent {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private profileService = inject(ProfileService);

  @ViewChild('bumpDialog') private bumpDialogRef?: ElementRef<HTMLDialogElement>;

  id = NaN;
  detail = signal<RemediationDetail | null>(null);
  loading = signal(true);
  notFound = signal(false);

  versionInput = signal('');
  offerVersionBump = signal(false);
  recordedMessage = signal<string | null>(null);
  assistOpen = signal(false);

  // Shared across submitVersion/declineVersion/confirmVersionBump — only one of the three write
  // actions can plausibly be in flight from this form at once. Without this, a slow PATCH read
  // as "the Save button did nothing" (no disabled state, no error surfaced on failure — the
  // request had no error handler at all before this).
  versionSaving = signal(false);
  versionError = signal<string | null>(null);

  metrics = computed(() => parseVectorMetrics(this.detail()?.item.cvss_vector ?? null));
  diagram = computed(() => reachDiagram(this.metrics()));

  isPastDue = isPastDue;
  formatDueDate = formatDueDate;
  hasFlow = hasFlow;

  verdict = computed(() => {
    const r = this.detail()?.remediation;
    if (!r) return { headline: '', detail: '' };
    return affectedWording(r.status, r.installed, r.entry?.text ?? null);
  });

  fix = computed(() => {
    const r = this.detail()?.remediation;
    if (!r) return { headline: '', detail: '', note: null };
    return fixWording(r.fix);
  });

  bumpTarget = computed(() => {
    const fix = this.detail()?.remediation?.fix;
    return fix && fix.kind === 'version' ? fix.value : '';
  });

  // The one version value already known to matter for this item — the fix target itself. A
  // one-click shortcut for the single most common real answer ("I'm already on the fixed
  // build") beside the free-text field, rather than a fabricated list of candidate versions the
  // app has no data for.
  fixVersionValue = computed(() => {
    const fix = this.detail()?.remediation?.fix;
    return fix && fix.kind === 'version' ? fix.value : null;
  });

  constructor() {
    // Native <dialog> owns its own top layer, backdrop and focus trap — showModal()/close() are
    // the only correct way to drive it; toggling an [open] attribute skips the backdrop and lets
    // focus escape. The dialog element is always in the DOM (never behind @if) so this ref
    // resolves before the first offerVersionBump write.
    effect(() => {
      const open = this.offerVersionBump();
      const dialog = this.bumpDialogRef?.nativeElement;
      if (!dialog) return;
      if (open && !dialog.open) dialog.showModal();
      if (!open && dialog.open) dialog.close();
    });

    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      const id = Number(pm.get('itemId'));
      if (!Number.isInteger(id) || id <= 0) {
        this.notFound.set(true);
        this.loading.set(false);
        return;
      }
      this.id = id;
      this.loadDetail();
    });
  }

  loadDetail(): void {
    this.loading.set(true);
    this.notFound.set(false);
    this.recordedMessage.set(null);
    this.versionSaving.set(false);
    this.versionError.set(null);
    this.api.itemRemediation(this.id).subscribe({
      next: (d) => {
        // No vector, nothing to guide through — redirect to the item detail page (spec's
        // "Item has no CVE / no vector" degraded state).
        if (!parseVectorMetrics(d.item.cvss_vector)) {
          this.router.navigate(['/intel', d.item.id], { replaceUrl: true });
          return;
        }
        this.detail.set(d);
        this.versionInput.set(d.remediation?.installed ?? '');
        this.loading.set(false);
      },
      error: (err: HttpErrorResponse) => {
        this.loading.set(false);
        if (err.status === 404) this.notFound.set(true);
      },
    });
  }

  onVersionInput(ev: Event): void {
    this.versionInput.set((ev.target as HTMLInputElement).value);
  }

  useFixVersion(value: string): void {
    this.versionInput.set(value);
  }

  submitVersion(ev: Event): void {
    ev.preventDefault();
    if (this.versionSaving()) return; // Guards a double-submit while the first request is in flight.
    const asset = this.detail()?.asset;
    const profile = this.profileService.active();
    if (!asset || !profile) return;
    const value = this.versionInput().trim();
    this.versionSaving.set(true);
    this.versionError.set(null);
    this.api.recordAssetVersion(profile.id, asset.vendor, asset.product, {
      version: value || null,
      versionState: value ? 'known' : 'unknown',
    }).subscribe({
      next: () => this.loadDetail(), // loadDetail() itself resets versionSaving back to false.
      error: () => {
        this.versionSaving.set(false);
        this.versionError.set("Couldn't save that — try again.");
      },
    });
  }

  declineVersion(): void {
    if (this.versionSaving()) return;
    const asset = this.detail()?.asset;
    const profile = this.profileService.active();
    if (!asset || !profile) return;
    this.versionSaving.set(true);
    this.versionError.set(null);
    this.api.recordAssetVersion(profile.id, asset.vendor, asset.product, { versionState: 'unknown' }).subscribe({
      next: () => this.loadDetail(),
      error: () => {
        this.versionSaving.set(false);
        this.versionError.set("Couldn't save that — try again.");
      },
    });
  }

  // A click that lands on the <dialog> element itself (not inside .bump-content) is a click on
  // the ::backdrop — dialog has no native backdrop-click event, so this is the standard way to
  // detect it.
  onDialogClick(ev: MouseEvent, dialog: HTMLDialogElement): void {
    if (ev.target === dialog) this.offerVersionBump.set(false);
  }

  onStepToggled(e: { key: string; done: boolean }): void {
    const fix = this.detail()?.remediation?.fix;
    if (e.key === 'patch' && e.done && fix && fix.kind === 'version') {
      this.offerVersionBump.set(true);
    }
  }

  // Reads the whole queue before and after the write, filtered to this asset, to answer "how
  // many OTHER threats against this machine cleared" — generated from the recomputed statuses,
  // never predicted before the write, per the spec's own rule.
  confirmVersionBump(): void {
    if (this.versionSaving()) return;
    const asset = this.detail()?.asset;
    const profile = this.profileService.active();
    const fix = this.detail()?.remediation?.fix;
    if (!asset || !profile || !fix || fix.kind !== 'version') return;
    const currentItemId = this.id;
    this.versionSaving.set(true);
    this.versionError.set(null);

    this.api.remediationQueue(profile.id).subscribe({
      next: (before) => {
        const beforeItems = (before.find((g) => g.vendor === asset.vendor && g.product === asset.product)?.items ?? [])
          .map((i) => ({ itemId: i.itemId, status: i.status }));

        this.api.recordAssetVersion(profile.id, asset.vendor, asset.product, {
          version: fix.value, versionState: 'known',
        }).subscribe({
          next: () => {
            this.api.remediationQueue(profile.id).subscribe({
              next: (after) => {
                const afterItems = (after.find((g) => g.vendor === asset.vendor && g.product === asset.product)?.items ?? [])
                  .map((i) => ({ itemId: i.itemId, status: i.status }));
                const cleared = countCleared(beforeItems, afterItems, currentItemId);
                this.offerVersionBump.set(false);
                this.recordedMessage.set(versionRecordedMessage(cleared) ?? 'Recorded.');
                this.autoTickAppliedSteps(currentItemId);
              },
              error: () => this.versionBumpFailed(),
            });
          },
          error: () => this.versionBumpFailed(),
        });
      },
      error: () => this.versionBumpFailed(),
    });
  }

  private versionBumpFailed(): void {
    this.versionSaving.set(false);
    this.versionError.set("Couldn't record that — try again.");
  }

  // Recording the version bump already IS "check whether you run the affected version" (key
  // 'confirm') and, when the fix was a named version, IS "apply the vendor's fix" (key 'patch')
  // — ticking both automatically means the reader doesn't re-do by hand what they just told the
  // app. Only ticks steps this item's own playbook actually has and that aren't already done;
  // loadDetail() (which itself resets versionSaving) runs last so the reload picks up every tick.
  private autoTickAppliedSteps(itemId: number): void {
    const steps = this.detail()?.playbook?.steps ?? [];
    const done = new Set(this.detail()?.playbook?.done ?? []);
    const toTick = steps.map((s) => s.key).filter((key) => (key === 'confirm' || key === 'patch') && !done.has(key));

    if (toTick.length === 0) {
      this.loadDetail();
      return;
    }
    let remaining = toTick.length;
    const settle = () => { remaining -= 1; if (remaining === 0) this.loadDetail(); };
    for (const key of toTick) {
      this.api.tickPlaybookStep(itemId, key).subscribe({ next: settle, error: settle });
    }
  }
}
