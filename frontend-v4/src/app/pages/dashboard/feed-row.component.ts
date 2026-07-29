import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { ChipComponent } from '../../ui/chip.component';
import { SourceDotComponent } from '../../ui/source-dot.component';
import { relativeTime, severityDisplayLabel } from '../../core/format';
import type { FeedRow } from '../../core/models';

// One row in the live lane. Purely presentational — all hover/focus/click/pin timing lives in
// the parent (`lane-live.component.ts`), which needs a single document-level view of pointer
// state to run the drawer's safe-triangle logic. This component just renders and stays
// focusable/clickable; the parent binds native `(mouseenter)`/`(mouseleave)`/`(focus)`/`(click)`
// straight onto the `<tf-feed-row>` tag the same way it would on a plain element.
@Component({
  selector: 'tf-feed-row',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ChipComponent, SourceDotComponent],
  host: {
    role: 'button',
    tabindex: '0',
    class: 'row',
    '[class.new]': 'isNew',
    '[attr.aria-label]': 'ariaLabel',
  },
  template: `
    <tf-chip [severity]="row.severity" [label]="chipLabel" />
    <span class="title">{{ row.title }}</span>
    <span class="meta">
      <tf-source-dot [status]="row.source_status" [name]="row.source_name" />
      <span class="source-name">{{ row.source_name }}</span>
      @if (row.source_count > 1) { <span class="cluster">+{{ row.source_count - 1 }}</span> }
      <span class="time">{{ time }}</span>
    </span>
  `,
  styles: [`
    :host {
      display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 12px;
      padding: 9px 12px; border-radius: 9px; cursor: pointer;
      border-left: 2px solid transparent;
      transition: background var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
    }
    :host(.new) { border-left-color: var(--accent); }
    :host(:hover) { background: var(--surface-2); }
    :host(:focus-visible) { outline: 2px solid var(--accent); outline-offset: -2px; background: var(--surface-2); }
    :host(:active) { background: var(--surface-3); }

    .title {
      color: var(--ink); font-size: var(--fs-sm); font-weight: 510;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0;
    }
    .meta {
      display: flex; align-items: center; gap: 6px; flex: none;
      font-size: var(--fs-xs); color: var(--ink-2);
    }
    .source-name { color: var(--ink-2); max-width: 14ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .cluster {
      color: var(--ink); background: var(--surface-3); border-radius: 999px; padding: 1px 6px;
      font-weight: 600;
    }
    .time { min-width: 2.5em; text-align: right; }
  `],
})
export class FeedRowComponent {
  @Input({ required: true }) row!: FeedRow;
  @Input() isNew = false;

  get time(): string {
    return relativeTime(this.row.last_seen);
  }

  // Empty string here means "let tf-chip fall back to its own severityLabel" — only the
  // News-for-unclassified-RSS case needs an override.
  get chipLabel(): string {
    return severityDisplayLabel(this.row.severity, this.row.source_fetch_kind) === 'News' ? 'News' : '';
  }

  get ariaLabel(): string {
    const clustered = this.row.source_count > 1 ? `, ${this.row.source_count} sources` : '';
    return `${this.row.title} — ${this.row.source_name}${clustered}, open story`;
  }
}
