import { Component, ChangeDetectionStrategy, inject, signal, computed, effect } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import type { HttpErrorResponse } from '@angular/common/http';
import { ApiService } from '../../core/api.service';
import { ProfileService } from '../../core/profile.service';
import { PanelComponent } from '../../ui/panel.component';
import { ImpactPanelComponent } from '../../ui/impact-panel.component';
import { EmptyStateComponent } from '../../ui/empty-state.component';
import { SkeletonComponent } from '../../ui/skeleton.component';
import { SourceDotComponent } from '../../ui/source-dot.component';
import { ChipComponent } from '../../ui/chip.component';
import { CopyButtonComponent } from '../../ui/copy-button.component';
import { BrowserWindowComponent } from '../../ui/browser-window.component';
import { RecordCardComponent } from '../../ui/record-card.component';
import { RemediationWidgetComponent } from '../../ui/remediation-widget.component';
import { relativeTime, stripHtml } from '../../core/format';
import { tierLabel, explanation, isModelWritten } from '../../core/relevance';
import { matchingGroup } from '../../core/remediation';
import type { ItemDetail, RelatedStory, RemediationDetail, RemediationQueueGroup } from '../../core/models';

interface EntityLink { key: string; label: string; path: string[]; }

// The routed "/intel/:id" page — the full record behind one explorer row. Confidence is always
// labelled as derived (never presented as if the source itself supplied a score — see
// server/confidence.js / CLAUDE.md's data-quality notes: it's a post-sync consolidation
// heuristic and can be NULL for a row inserted since the last sync). Entities link out to their
// profile pages; domains have no dedicated route yet so render as plain tags, not links.
@Component({
  selector: 'tf-page-item-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    RouterLink, PanelComponent, ImpactPanelComponent, EmptyStateComponent, SkeletonComponent,
    SourceDotComponent, ChipComponent, CopyButtonComponent, BrowserWindowComponent, RecordCardComponent,
    RemediationWidgetComponent,
  ],
  template: `
    @if (detail(); as d) {
      <a class="back" routerLink="/intel">&larr; Back to Intel Explorer</a>

      <section class="header">
        <div class="head-row">
          @if (d.source_fetch_kind !== 'rss') {
            <tf-source-dot [status]="d.source_status" [name]="d.source_name ?? 'Unknown source'" />
            <span class="source-name">{{ d.source_name ?? 'Unknown source' }}</span>
          }
          <span class="time">{{ relativeTime(d.published_at) }}</span>
          <tf-chip [severity]="d.severity" />
        </div>
        <h1 class="sr-only">{{ d.title }}</h1>

        @if (d.confidence != null) {
          <p class="confidence">Confidence {{ d.confidence.toFixed(2) }} · derived from source tier and corroboration</p>
        } @else {
          <p class="confidence muted">
            Confidence not yet computed — populated by the next sync-all's consolidation pass, not at ingest
          </p>
        }

        @if (d.source_fetch_kind !== 'rss') {
          <tf-record-card [item]="d" />
        } @else {
          <tf-browser-window
            [url]="d.link" [title]="d.title" [sourceName]="d.source_name ?? 'Unknown source'"
            [sourceStatus]="d.source_status" [time]="relativeTime(d.published_at)"
            [summary]="cleanedSummary()"
            [allowExpand]="d.source_fetch_kind === 'rss'"
          />
        }

        <dl class="meta">
          <div><dt>Category</dt><dd>{{ d.category }}</dd></div>
          @if (d.vendor) { <div><dt>Vendor</dt><dd>{{ d.vendor }}</dd></div> }
          @if (d.region) { <div><dt>Region</dt><dd>{{ d.region }}</dd></div> }
          @if (d.industry) { <div><dt>Industry</dt><dd>{{ d.industry }}</dd></div> }
          @if (d.cvss_score != null) { <div><dt>CVSS</dt><dd>{{ d.cvss_score }}</dd></div> }
          @if (d.exploitation_status) { <div><dt>Exploitation</dt><dd>{{ d.exploitation_status }}</dd></div> }
        </dl>
      </section>

      @if (d.relevance; as rel) {
        <tf-impact-panel [relevance]="rel" />
      }

      <tf-remediation-widget
        [remediation]="remediation()?.remediation ?? null"
        [group]="remediationGroup()"
        [itemId]="d.id"
        [severity]="remediation()?.severity ?? null"
      />

      <tf-panel title="Entities">
        @if (entities().length === 0 && d.domains.length === 0) {
          <tf-empty-state reason="No CVEs, actors, malware families or domain tags extracted for this item" />
        } @else {
          <div class="entities">
            @for (e of entities(); track e.key) {
              <a class="entity" [routerLink]="e.path">{{ e.label }}</a>
            }
            @for (dom of d.domains; track dom) {
              <span class="entity tag">{{ dom }}</span>
            }
          </div>
        }
      </tf-panel>

      <tf-panel title="Indicators of compromise" [subtitle]="d.iocs.length + ' total'">
        @if (d.iocs.length === 0) {
          <tf-empty-state reason="No IOCs extracted for this item" />
        } @else {
          <div class="tf-scroll">
          <table>
            <thead><tr><th>Type</th><th>Value</th><th></th></tr></thead>
            <tbody>
              @for (ioc of d.iocs; track ioc.type + ioc.value) {
                <tr>
                  <td>{{ ioc.type }}</td>
                  <td class="value">{{ ioc.value }}</td>
                  <td class="row-actions">
                    <tf-copy-button [value]="ioc.value" label="Copy" />
                    @if (ipEntry(d, ioc); as entry) {
                      <button type="button" class="expand" (click)="toggleIp(ioc.value)">
                        {{ isIpExpanded(ioc.value) ? 'Hide intel' : 'IP intel' }}
                      </button>
                    }
                  </td>
                </tr>
                @if (ipEntry(d, ioc); as entry) {
                  @if (isIpExpanded(ioc.value)) {
                    <tr class="ip-expand">
                      <td colspan="3">
                        <dl class="ip-meta">
                          <div><dt>Org</dt><dd>{{ entry.org ?? '—' }}</dd></div>
                          <div><dt>ISP</dt><dd>{{ entry.isp ?? '—' }}</dd></div>
                          <div><dt>Geo</dt><dd>{{ entry.city ?? '—' }}{{ entry.country_code ? ', ' + entry.country_code : '' }}</dd></div>
                          <div><dt>Ports</dt><dd>{{ entry.ports?.length ? entry.ports!.join(', ') : '—' }}</dd></div>
                          <div><dt>Vulns</dt><dd>{{ entry.vulns?.length ? entry.vulns!.join(', ') : '—' }}</dd></div>
                          <div><dt>Source</dt><dd>{{ entry.source ?? '—' }}</dd></div>
                        </dl>
                      </td>
                    </tr>
                  }
                }
              }
            </tbody>
          </table>
          </div>
        }
      </tf-panel>

      @if (related().length > 0) {
        <tf-panel title="Possibly related" subtitle="suggested by a local model — not corroboration">
          <ul class="related">
            @for (r of related(); track r.clusterId) {
              <li>
                <a [routerLink]="['/intel', r.primaryItemId]">{{ r.title }}</a>
                <span class="rel-label">{{ r.label }}</span>
              </li>
            }
          </ul>
        </tf-panel>
      }

      <details class="raw">
        <summary>Raw JSON</summary>
        <pre>{{ rawJsonText() }}</pre>
      </details>
    } @else if (loading()) {
      <tf-skeleton [rows]="10" />
    } @else if (notFound()) {
      <div class="not-found">
        <tf-empty-state title="Item not found" reason="GET /api/items/:id returned 404" />
        <a class="back" routerLink="/intel">&larr; Back to Intel Explorer</a>
      </div>
    } @else if (error()) {
      <div class="err">
        <p class="t">Couldn't load this item</p>
        <p class="r">GET /api/items/{{ id }} failed</p>
        <button type="button" (click)="loadDetail()">Retry</button>
      </div>
    }
  `,
  styles: [`
    :host { display: flex; flex-direction: column; gap: 16px; }

    .back { align-self: flex-start; font-size: var(--fs-xs); color: var(--ink-2); text-decoration: none; transition: color var(--dur-fast) var(--ease-out); }
    .back:hover { color: var(--ink); }
    .not-found { display: flex; flex-direction: column; align-items: center; gap: 10px; padding: 32px 0; }
    .not-found .back { align-self: center; }

    .header {
      background: color-mix(in srgb, var(--surface) 82%, transparent);
      backdrop-filter: blur(20px) saturate(160%);
      border-radius: var(--radius-card); border: var(--hair) solid var(--hairline);
      box-shadow: 0 12px 32px -16px rgba(0, 0, 20, .5);
      padding: 16px; display: flex; flex-direction: column; gap: 10px;
      animation: card-in 240ms var(--ease-out) backwards;
    }
    @keyframes card-in {
      from { opacity: 0; transform: translateY(6px) scale(.99); }
      to { opacity: 1; transform: none; }
    }
    @media (prefers-reduced-transparency: reduce) {
      .header { background: var(--surface); backdrop-filter: none; }
    }
    .head-row { display: flex; align-items: center; gap: 8px; }
    .source-name { font-size: var(--fs-sm); color: var(--ink-2); }
    .time { font-size: var(--fs-xs); color: var(--ink-2); margin-right: auto; }
    .sr-only {
      position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden;
      clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
    }

    .confidence { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); }
    .confidence.muted { font-style: italic; }
    tf-browser-window { display: block; }

    dl.meta { display: flex; flex-wrap: wrap; gap: 12px 24px; margin: 4px 0 0; }
    dl.meta dd { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    dl.meta a { color: var(--accent); }

    .entities { display: flex; flex-wrap: wrap; gap: 6px; }
    .entity {
      font-size: var(--fs-xs); font-weight: 510; color: var(--ink); text-decoration: none;
      background: var(--surface-2); padding: 4px 10px; border-radius: 999px;
      transition: background var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    a.entity:hover { background: var(--surface-3); }
    a.entity:active { background: var(--surface-4); transform: scale(.95); }
    .entity.tag { color: var(--ink-2); cursor: default; }

    /* Deliberately quieter than the entity chips above: these are model suggestions, and they
       must not read with the same authority as extracted, source-derived data. */
    ul.related { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
    ul.related li { display: flex; align-items: baseline; gap: 10px; }
    ul.related a {
      font-size: var(--fs-sm); color: var(--ink); text-decoration: none;
      transition: color var(--dur-fast) var(--ease-out);
    }
    ul.related a:hover { color: var(--accent); text-decoration: underline; }
    ul.related a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
    .rel-label {
      flex: none; margin-left: auto; font-size: var(--fs-xs); color: var(--ink-2);
      background: var(--surface-2); padding: 2px 8px; border-radius: 999px; white-space: nowrap;
    }

    .rel-sentence { margin: 0; font-size: var(--fs-sm); color: var(--ink); line-height: 1.5; }
    /* Distinguishes actual model output from the deterministic fallback sentence, which reads
       like prose but isn't AI-written and must not be tagged as if it were. */
    .ai-tag {
      display: inline-block; margin-left: 8px; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink-2); background: var(--surface-2); padding: 2px 8px; border-radius: 999px;
      vertical-align: middle; cursor: help;
    }

    .tf-scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    thead th, tbody td { border-bottom: var(--hair) solid var(--hairline); }
    thead th { text-align: left; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2); padding: 6px 10px; }
    tbody td { padding: 7px 10px; font-size: var(--fs-sm); color: var(--ink-2); }
    td.value { color: var(--ink); font-family: ui-monospace, monospace; font-size: var(--fs-xs); word-break: break-all; }
    .row-actions { display: flex; align-items: center; gap: 6px; white-space: nowrap; }

    .expand {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 510;
      color: var(--ink-2); background: var(--surface-2); border: 0; padding: 3px 9px; border-radius: 6px;
      transition: color var(--dur-fast) var(--ease-out), background var(--dur-fast) var(--ease-out), transform 100ms var(--ease-out);
    }
    .expand:hover { color: var(--ink); background: var(--surface-3); }
    a.entity:focus-visible, .expand:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .expand:active { background: var(--surface-4); transform: scale(.95); }

    tbody tr { animation: row-in 180ms var(--ease-out) backwards; }
    @keyframes row-in {
      from { opacity: 0; transform: translateY(-3px); }
      to { opacity: 1; transform: none; }
    }

    tr.ip-expand td { background: var(--surface-2); padding: 10px 14px; }
    dl.ip-meta { display: flex; flex-wrap: wrap; gap: 10px 20px; margin: 0; animation: row-in 180ms var(--ease-out); }
    dl.ip-meta div { min-width: 120px; }
    dl.ip-meta dd { margin: 0; font-size: var(--fs-xs); color: var(--ink); word-break: break-word; }
    dl.meta div, dl.ip-meta div { display: flex; flex-direction: column; gap: 2px; }
    dl.meta dt, dl.ip-meta dt { font-size: var(--fs-xs); color: var(--ink-2); }

    details.raw {
      background: var(--surface); border-radius: var(--radius-card); border: var(--hair) solid var(--hairline); padding: 12px 16px;
    }
    details.raw summary { cursor: pointer; font-size: var(--fs-sm); font-weight: 590; color: var(--ink); }
    details.raw pre {
      margin: 10px 0 0; font-size: var(--fs-xs); color: var(--ink-2); white-space: pre-wrap; word-break: break-word;
      max-height: 400px; overflow: auto;
    }

    .err {
      display: flex; flex-direction: column; align-items: center; gap: 8px;
      min-height: 200px; justify-content: center; text-align: center; padding: 16px;
    }
    .err .t { margin: 0; font-size: var(--fs-sm); color: var(--ink); }
    .err .r { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); background: var(--surface-2); padding: 4px 10px; border-radius: 6px; }
    .err button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--accent-soft); border: 0; padding: 6px 14px; border-radius: 8px;
      transition: opacity var(--dur-fast) var(--ease);
    }
    .err button:hover { opacity: .88; }
    .err button:focus-visible, details.raw summary:focus-visible, .back:focus-visible {
      outline: 2px solid var(--accent); outline-offset: 2px;
    }
    .err button:active { opacity: .74; }

    @media (prefers-reduced-motion: reduce) {
      .back, .entity, .expand, .err button, ul.related a { transition: none; }
      .header, tbody tr, dl.ip-meta { animation: none; }
    }
  `],
})
export class ItemDetailComponent {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);
  private profileService = inject(ProfileService);

  id = NaN;

  detail = signal<ItemDetail | null>(null);
  loading = signal(true);
  notFound = signal(false);
  error = signal(false);
  related = signal<RelatedStory[]>([]);
  private expandedIps = signal<Set<string>>(new Set());

  // Part 9's widget state. Fetched independently of `detail` (a different route,
  // GET /api/items/:id/remediation) and only when a profile is active — the widget renders
  // nothing at all rather than an error state when there's no profile or no matching asset,
  // the same "no panel when there's nothing to say" posture "Possibly related" already uses.
  remediation = signal<RemediationDetail | null>(null);
  remediationGroup = signal<RemediationQueueGroup | null>(null);

  relativeTime = relativeTime;
  tierLabel = tierLabel;
  explanation = explanation;
  isModelWritten = isModelWritten;

  rawJsonText = computed(() => {
    const d = this.detail();
    return d ? JSON.stringify(d.raw, null, 2) : '';
  });

  entities = computed<EntityLink[]>(() => {
    const d = this.detail();
    if (!d) return [];
    return [
      ...d.cves.map((c): EntityLink => ({ key: `cve-${c}`, label: c, path: ['/cve', c] })),
      ...d.actors.map((a): EntityLink => ({ key: `actor-${a}`, label: a, path: ['/actor', a] })),
      ...d.families.map((f): EntityLink => ({ key: `family-${f}`, label: f, path: ['/malware', f] })),
    ];
  });

  constructor() {
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      const id = Number(pm.get('id'));
      if (!Number.isInteger(id) || id <= 0) {
        this.notFound.set(true);
        this.loading.set(false);
        return;
      }
      this.id = id;
      this.detail.set(null);
      this.related.set([]);
      this.expandedIps.set(new Set());
      this.remediation.set(null);
      this.remediationGroup.set(null);
      this.loadDetail();
    });

    // GET /api/items/:id's relevance/playbook blocks are profile-scoped. Same guard pattern as
    // explorer.component.ts: skip the effect's own first (creation-time) run so this doesn't
    // double-fetch alongside the paramMap subscription above.
    let firstProfileRun = true;
    effect(() => {
      this.profileService.dataVersion();
      if (firstProfileRun) { firstProfileRun = false; return; }
      if (Number.isInteger(this.id) && this.id > 0) this.loadDetail();
    });
  }

  loadDetail(): void {
    this.loading.set(true);
    this.notFound.set(false);
    this.error.set(false);
    this.api.item(this.id).subscribe({
      next: (d) => {
        this.detail.set(d);
        this.loading.set(false);
        // The count is on the detail payload, so a second request only happens when there is
        // something to fetch. No panel is rendered when there are no links — an empty-state
        // placeholder would advertise a feature that has nothing to say about this item.
        if (d.clusterId != null && d.relatedStoryCount > 0) this.loadRelated(d.clusterId);
        this.loadRemediation();
      },
      error: (err: HttpErrorResponse) => {
        this.loading.set(false);
        if (err.status === 404) this.notFound.set(true);
        else this.error.set(true);
      },
    });
  }

  cleanedSummary(): string | null {
    return stripHtml(this.detail()?.summary ?? null);
  }

  ipEntry(d: ItemDetail, ioc: { type: string; value: string }) {
    return ioc.type === 'ip' ? d.ip_intel[ioc.value] : undefined;
  }

  isIpExpanded(value: string): boolean {
    return this.expandedIps().has(value);
  }

  toggleIp(value: string): void {
    const next = new Set(this.expandedIps());
    if (next.has(value)) next.delete(value); else next.add(value);
    this.expandedIps.set(next);
  }

  // Suggestions are the lowest-stakes thing on the page: a failure leaves the panel unrendered
  // rather than showing an error, exactly as if the model had never linked anything.
  private loadRelated(clusterId: number): void {
    this.api.relatedStories(clusterId).subscribe({
      next: (rows) => this.related.set(rows),
      error: () => { /* no panel — a suggestion that cannot load is not worth reporting */ },
    });
  }

  private loadRemediation(): void {
    this.remediation.set(null);
    this.remediationGroup.set(null);
    const profile = this.profileService.active();
    if (!profile) return; // No profile: the widget stays hidden, not an error state.
    this.api.itemRemediation(this.id).subscribe({
      next: (r) => {
        this.remediation.set(r);
        if (r.asset) this.loadRemediationGroup(r.asset);
      },
      error: () => { /* No CVE data, or the item-remediation route 404s — widget stays hidden. */ },
    });
  }

  private loadRemediationGroup(asset: { vendor: string; product: string }): void {
    const profile = this.profileService.active();
    if (!profile) return;
    this.api.remediationQueue(profile.id).subscribe({
      next: (groups) => this.remediationGroup.set(matchingGroup(groups, asset)),
      error: () => { /* Progress ring just doesn't render — the headline/count still will. */ },
    });
  }

}
