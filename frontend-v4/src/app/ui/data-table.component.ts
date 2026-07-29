import {
  Component, Input, Output, EventEmitter, TemplateRef, ChangeDetectionStrategy,
} from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';

export interface DataTableColumn { key: string; label: string; }

// Generic server-side-paginated table shell. It owns the header row, the pager, and structural
// styling only — row rendering is delegated entirely to the caller's own <ng-template> so any
// page can project whatever cell markup (chips, links, expand-in-place rows) it needs without
// this component knowing about item/CVE/actor shapes.
@Component({
  selector: 'tf-data-table',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [NgTemplateOutlet],
  template: `
    <div class="tf-scroll">
      <table>
        <thead>
          <tr>
            @for (c of columns; track c.key) { <th>{{ c.label }}</th> }
          </tr>
        </thead>
        <tbody>
          @for (row of rows; track trackByFn(row)) {
            <ng-container [ngTemplateOutlet]="rowTemplate" [ngTemplateOutletContext]="{ $implicit: row }" />
          }
        </tbody>
      </table>
    </div>

    <div class="pager">
      <span class="count">{{ total }} row{{ total === 1 ? '' : 's' }}</span>
      <div class="nav">
        <button type="button" [disabled]="page === 0" (click)="pageChange.emit(page - 1)">Prev</button>
        <span>Page {{ page + 1 }} of {{ totalPages }}</span>
        <button type="button" [disabled]="isLast" (click)="pageChange.emit(page + 1)">Next</button>
      </div>
    </div>
  `,
  styles: [`
    :host { display: flex; flex-direction: column; gap: 10px; }

    .tf-scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    thead th {
      text-align: left; font-size: var(--fs-xs); font-weight: 600; color: var(--ink-2);
      padding: 6px 10px; border-bottom: var(--hair) solid var(--hairline); white-space: nowrap;
    }

    .pager {
      display: flex; align-items: center; justify-content: space-between; gap: 12px;
      padding-top: 4px; font-size: var(--fs-xs); color: var(--ink-2);
    }
    .nav { display: flex; align-items: center; gap: 10px; }

    button {
      appearance: none; cursor: pointer; font: inherit; font-size: var(--fs-xs); font-weight: 590;
      color: var(--ink); background: var(--surface-2); border: 0; padding: 5px 12px; border-radius: 8px;
      transition: background var(--dur-fast) var(--ease), opacity var(--dur-fast) var(--ease);
    }
    button:hover:not(:disabled) { background: var(--surface-3); }
    button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    button:active:not(:disabled) { background: var(--surface-4); }
    button:disabled { cursor: default; opacity: .4; }

    @media (prefers-reduced-motion: reduce) {
      button { transition: none; }
    }
  `],
})
export class DataTableComponent<T = unknown> {
  @Input() columns: DataTableColumn[] = [];
  @Input() rows: T[] = [];
  @Input() total = 0;
  @Input() page = 0;
  @Input() pageSize = 25;
  @Input({ required: true }) rowTemplate!: TemplateRef<{ $implicit: T }>;
  @Input() trackByFn: (row: T) => unknown = (r: unknown) => (r as { id?: unknown })?.id ?? r;

  @Output() pageChange = new EventEmitter<number>();

  get totalPages(): number {
    return Math.max(1, Math.ceil(this.total / this.pageSize));
  }

  get isLast(): boolean {
    return (this.page + 1) * this.pageSize >= this.total;
  }
}
