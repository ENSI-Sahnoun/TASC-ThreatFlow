import { Component, ChangeDetectionStrategy, inject, signal, computed, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import type { Sector, DomainOption, CpeFacet, Exposure } from '../../core/models';
import { syncAssets, setExposure, type SurveyAsset } from './assets';

// Mandatory first-run survey. Five steps, each mapping to something the relevance scorer can
// actually match on — there is no question here whose answer has no column behind it.
//
// Step 2 is the point of the whole flow: a user who knows nothing picks a sector and accepts
// a recommended set, and still ends up with a profile that matches real data.
@Component({
  selector: 'tf-survey',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule],
  template: `
    <div class="survey">
      <header class="head">
        <h1 class="tf-heading">Set up your threat profile</h1>
        <p class="tagline">Five quick questions. They decide which of the {{ '' }}corpus you see first.</p>
        <ol class="steps" aria-label="Progress">
          @for (s of stepLabels; track s; let i = $index) {
            <li [class.done]="step() > i + 1" [class.current]="step() === i + 1">{{ s }}</li>
          }
        </ol>
      </header>

      <!-- 1. Sector -->
      @if (step() === 1) {
        <section class="panel">
          <h2>What sector are you in?</h2>
          <p class="hint">This preselects a starting set you can accept or edit.</p>
          <div class="grid">
            @for (s of sectors(); track s.slug) {
              <button type="button" class="opt" [class.sel]="sector()?.slug === s.slug" (click)="chooseSector(s)">
                {{ s.label }}
              </button>
            }
          </div>
        </section>
      }

      <!-- 2. Recommended set -->
      @if (step() === 2 && sector(); as sec) {
        <section class="panel">
          <h2>Recommended for {{ sec.label }}</h2>
          <p class="hint">Accept these to finish quickly, or customize them.</p>
          <div class="rec">
            <div class="rec-row">
              <span class="rec-label">Interests</span>
              <div class="chips">
                @for (d of sec.recommendation.threatDomains; track d) {
                  <span class="chip">{{ domainLabel(d) }}</span>
                }
              </div>
            </div>
            <div class="rec-row">
              <span class="rec-label">Tech</span>
              <div class="chips">
                @for (v of sec.recommendation.vendors; track v) { <span class="chip">{{ v }}</span> }
                @if (!sec.recommendation.vendors.length) { <span class="hint">none — interests do the work here</span> }
              </div>
            </div>
            <div class="rec-row">
              <span class="rec-label">Minimum severity</span>
              <div class="chips"><span class="chip">{{ sec.recommendation.severityFloor }}</span></div>
            </div>
          </div>
          <div class="actions">
            <button type="button" class="primary" (click)="goToExposure()">Use these</button>
            <button type="button" class="ghost" (click)="step.set(3)">Customize</button>
          </div>
        </section>
      }

      <!-- 3. Tech stack -->
      @if (step() === 3) {
        <section class="panel">
          <h2>What do you run?</h2>
          <p class="hint">Suggestions come from vendors that actually appear in the corpus.</p>
          <div class="kind-toggle">
            <button type="button" [class.sel]="kind() === 'vendor'" (click)="setKind('vendor')">Vendors</button>
            <button type="button" [class.sel]="kind() === 'product'" (click)="setKind('product')">Products</button>
          </div>
          <input
            type="text" class="search" [ngModel]="term()" (ngModelChange)="search($event)"
            placeholder="Type to search, e.g. fortinet" autocomplete="off" spellcheck="false"
          />
          <div class="chips results">
            @for (f of facets(); track f.value) {
              <button type="button" class="chip pick" [class.sel]="isPicked(f.value)" (click)="togglePick(f.value)">
                {{ f.value }} <span class="refs">{{ f.refs }}</span>
              </button>
            }
            @if (term() && !facets().length) { <span class="hint">No match in the corpus — nothing to select.</span> }
          </div>
          <div class="chips selected">
            @for (v of vendors(); track v) {
              <button type="button" class="chip sel" (click)="removeVendor(v)">{{ v }} ✕</button>
            }
            @for (p of products(); track p) {
              <button type="button" class="chip sel" (click)="removeProduct(p)">{{ p }} ✕</button>
            }
          </div>
          <div class="actions">
            <button type="button" class="primary" (click)="goToExposure()">Continue</button>
            <button type="button" class="ghost" (click)="step.set(2)">Back</button>
          </div>
        </section>
      }

      <!-- 4. Exposure. One question per product, and the single biggest lever on how personal
           the verdict can be: AV:N alone is a property of a flaw, AV:N on an internet-facing
           asset is a statement about this user. -->
      @if (step() === 4) {
        <section class="panel">
          <h2>Can these be reached from the internet?</h2>
          <p class="hint">
            "Not sure" is a fine answer — it is treated as the worst case, which is safer than a
            guess.
          </p>
          @if (assets().length) {
            <ul class="exposure">
              @for (a of assets(); track a.product) {
                <li>
                  <span class="prod">{{ a.product }}</span>
                  <span class="opts">
                    @for (opt of exposureOptions; track opt.value) {
                      <button
                        type="button" class="chip pick"
                        [class.sel]="a.exposure === opt.value"
                        [attr.aria-pressed]="a.exposure === opt.value"
                        (click)="chooseExposure(a.product, opt.value)"
                      >{{ opt.label }}</button>
                    }
                  </span>
                </li>
              }
            </ul>
          } @else {
            <p class="hint">No products selected, so there is nothing to answer here.</p>
          }

          <div class="actions">
            <button type="button" class="primary" (click)="step.set(5)">Continue</button>
            <button type="button" class="ghost" (click)="step.set(3)">Back</button>
          </div>
        </section>
      }

      <!-- 5. Interests, name, finish -->
      @if (step() === 5) {
        <section class="panel">
          <h2>What should we surface?</h2>
          <div class="chips">
            @for (d of domains(); track d.slug) {
              <button type="button" class="chip pick" [class.sel]="isDomainOn(d.slug)" (click)="toggleDomain(d.slug)">
                {{ d.label }} <span class="refs">{{ d.count }}</span>
              </button>
            }
          </div>

          <div class="fields">
            <label>
              <span>Profile name</span>
              <input type="text" [(ngModel)]="name" placeholder="e.g. Acme Bank" autocomplete="off" />
            </label>
            <label>
              <span>Region <em>(optional)</em></span>
              <input type="text" [(ngModel)]="region" placeholder="e.g. EU" autocomplete="off" />
            </label>
            <label>
              <span>Minimum severity</span>
              <select [(ngModel)]="severityFloor">
                @for (s of severities; track s) { <option [value]="s">{{ s }}</option> }
              </select>
            </label>
          </div>

          @if (error(); as e) { <p class="err" role="alert">{{ e }}</p> }

          <div class="actions">
            <button type="button" class="primary" [disabled]="!canSubmit || saving()" (click)="submit()">
              {{ saving() ? 'Saving…' : 'Finish' }}
            </button>
            <button type="button" class="ghost" (click)="step.set(4)">Back</button>
          </div>
        </section>
      }
    </div>
  `,
  styles: [`
    :host { display: block; max-width: 760px; margin: 0 auto; width: 100%; padding: 24px 0; }
    .head { display: flex; flex-direction: column; gap: 4px; margin-bottom: 20px; }
    .head h1 { margin: 0; font-size: var(--fs-xl); color: var(--ink); }
    .tagline { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }
    .steps { display: flex; gap: 8px; list-style: none; padding: 0; margin: 12px 0 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .steps li { padding: 2px 10px; border-radius: 999px; background: color-mix(in srgb, var(--ink) 6%, transparent); }
    .steps li.current { color: var(--ink); background: color-mix(in srgb, var(--accent, currentColor) 18%, transparent); }
    .steps li.done { opacity: 0.55; }

    .panel { display: flex; flex-direction: column; gap: 12px; }
    .panel h2 { margin: 0; font-size: var(--fs-lg); color: var(--ink); }
    .hint { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); }

    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }
    .opt {
      text-align: left; padding: 12px 14px; border-radius: 10px; cursor: pointer;
      border: 1px solid color-mix(in srgb, var(--ink) 14%, transparent);
      background: transparent; color: var(--ink); font-size: var(--fs-sm);
    }
    .opt:hover, .opt.sel { border-color: currentColor; background: color-mix(in srgb, var(--ink) 6%, transparent); }

    .rec { display: flex; flex-direction: column; gap: 10px; }
    .rec-row { display: flex; gap: 12px; align-items: baseline; }
    .rec-label { min-width: 120px; font-size: var(--fs-xs); color: var(--ink-2); }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; }
    .exposure { list-style: none; margin: 12px 0 0; padding: 0; display: grid; gap: 8px; }
    .exposure li { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    .exposure .prod { font-size: var(--fs-sm); color: var(--ink); }
    .exposure .opts { display: flex; gap: 6px; }
    .chip {
      display: inline-flex; align-items: center; gap: 6px;
      font-size: var(--fs-xs); padding: 3px 10px; border-radius: 999px;
      background: color-mix(in srgb, var(--ink) 8%, transparent); color: var(--ink);
      border: 1px solid transparent;
    }
    .chip.pick { cursor: pointer; }
    .chip.sel { border-color: currentColor; background: color-mix(in srgb, var(--ink) 14%, transparent); }
    .refs { font-size: var(--fs-xs); opacity: 0.55; }
    .results { min-height: 32px; }
    .selected { margin-top: 4px; }

    .kind-toggle { display: flex; gap: 4px; }
    .kind-toggle button {
      font-size: var(--fs-xs); padding: 4px 12px; border-radius: 999px; cursor: pointer;
      border: 1px solid color-mix(in srgb, var(--ink) 14%, transparent); background: transparent; color: var(--ink-2);
    }
    .kind-toggle button.sel { color: var(--ink); border-color: currentColor; }

    .search, .fields input, .fields select {
      width: 100%; padding: 9px 12px; border-radius: 8px; font-size: var(--fs-sm);
      border: 1px solid color-mix(in srgb, var(--ink) 16%, transparent);
      background: transparent; color: var(--ink);
    }
    .fields { display: flex; flex-direction: column; gap: 10px; margin-top: 4px; }
    .fields label { display: flex; flex-direction: column; gap: 4px; font-size: var(--fs-xs); color: var(--ink-2); }
    .fields em { font-style: normal; opacity: 0.7; }

    .actions { display: flex; gap: 8px; margin-top: 8px; }
    .primary, .ghost {
      padding: 9px 18px; border-radius: 8px; font-size: var(--fs-sm); cursor: pointer;
      border: 1px solid color-mix(in srgb, var(--ink) 16%, transparent);
    }
    .primary { background: var(--ink); color: var(--bg, #fff); border-color: var(--ink); }
    .primary:disabled { opacity: 0.45; cursor: not-allowed; }
    .ghost { background: transparent; color: var(--ink-2); }
    .err { margin: 0; font-size: var(--fs-xs); color: var(--danger, #c0392b); }
  `],
})
export class SurveyComponent implements OnInit {
  private api = inject(ApiService);
  private profileSvc = inject(ProfileService);
  private router = inject(Router);

  readonly stepLabels = ['Sector', 'Recommended', 'Tech', 'Exposure', 'Interests'];
  readonly severities = ['critical', 'high', 'medium', 'low'];

  readonly step = signal(1);
  readonly assets = signal<SurveyAsset[]>([]);

  // "Not sure" is offered explicitly rather than left as a skip, because an unanswered exposure
  // is a real answer the scorer treats as worst-case — the user should be able to say it.
  readonly exposureOptions: { value: Exposure; label: string }[] = [
    { value: 'internet', label: 'Yes' },
    { value: 'internal', label: 'No' },
    { value: 'unknown', label: 'Not sure' },
  ];
  readonly sectors = signal<Sector[]>([]);
  readonly domains = signal<DomainOption[]>([]);
  readonly sector = signal<Sector | null>(null);
  readonly vendors = signal<string[]>([]);
  readonly products = signal<string[]>([]);
  readonly threatDomains = signal<string[]>([]);
  readonly facets = signal<CpeFacet[]>([]);
  readonly term = signal('');
  readonly kind = signal<'vendor' | 'product'>('vendor');
  readonly saving = signal(false);
  readonly error = signal<string | null>(null);

  name = '';
  region = '';
  severityFloor = 'medium';

  // A getter, not a computed(): `name` is bound with ngModel and is not a signal, so a
  // computed would never recompute and the Finish button would stay disabled forever.
  get canSubmit(): boolean { return this.name.trim().length > 0; }

  ngOnInit(): void {
    this.api.sectors().subscribe((s) => this.sectors.set(s));
    this.api.domainOptions().subscribe((d) => this.domains.set(d));
  }

  domainLabel(slug: string): string {
    return this.domains().find((d) => d.slug === slug)?.label ?? slug;
  }

  // Choosing a sector seeds every later step, so a user who accepts the recommendation at
  // step 2 already has a complete, matchable profile.
  chooseSector(s: Sector): void {
    this.sector.set(s);
    this.vendors.set([...s.recommendation.vendors]);
    this.products.set([...s.recommendation.products]);
    this.threatDomains.set([...s.recommendation.threatDomains]);
    this.severityFloor = s.recommendation.severityFloor;
    this.step.set(2);
  }

  setKind(k: 'vendor' | 'product'): void {
    this.kind.set(k);
    this.search(this.term());
  }

  search(term: string): void {
    this.term.set(term);
    if (!term.trim()) { this.facets.set([]); return; }
    this.api.cpeFacets(term.trim(), this.kind()).subscribe((f) => this.facets.set(f));
  }

  isPicked(v: string): boolean {
    return this.kind() === 'vendor' ? this.vendors().includes(v) : this.products().includes(v);
  }

  // Only slugs the API returned can be added — free text that matched nothing could never
  // match an item, and the backend rejects it anyway.
  togglePick(v: string): void {
    const sig = this.kind() === 'vendor' ? this.vendors : this.products;
    sig.update((list) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]));
  }

  removeVendor(v: string): void { this.vendors.update((l) => l.filter((x) => x !== v)); }
  removeProduct(p: string): void { this.products.update((l) => l.filter((x) => x !== p)); }

  // Assets are synced on the way into the exposure step rather than derived from products(),
  // so an answer survives the user going back to edit their product list.
  goToExposure(): void {
    this.assets.update((existing) => syncAssets(this.products(), existing));
    this.step.set(4);
  }

  chooseExposure(product: string, exposure: Exposure): void {
    this.assets.update((list) => setExposure(list, product, exposure));
  }

  isDomainOn(slug: string): boolean { return this.threatDomains().includes(slug); }

  toggleDomain(slug: string): void {
    this.threatDomains.update((l) => (l.includes(slug) ? l.filter((x) => x !== slug) : [...l, slug]));
  }

  submit(): void {
    const sec = this.sector();
    if (!sec || !this.canSubmit) return;
    this.saving.set(true);
    this.error.set(null);
    this.profileSvc.create(
      {
        name: this.name.trim(),
        sector: sec.slug,
        vendors: this.vendors(),
        products: this.products(),
        threatDomains: this.threatDomains(),
        region: this.region.trim() || null,
        severityFloor: this.severityFloor,
        // products[] is still sent: it keeps feeding the low tier for anything the asset path
        // misses, and keeps an older backend working unchanged.
        assets: this.assets(),
      },
      () => { this.saving.set(false); this.router.navigateByUrl('/'); },
      // Without this a rejected name (duplicate, or a slug the backend refuses) would leave
      // the button spinning with no explanation.
      (msg) => { this.saving.set(false); this.error.set(msg); },
    );
  }
}
