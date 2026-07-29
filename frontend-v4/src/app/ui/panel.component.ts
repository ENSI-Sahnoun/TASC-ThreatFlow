import { Component, Input, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'tf-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="panel" [class.chrome]="chrome">
      @if (title) {
        <header>
          <h2>{{ title }}</h2>
          @if (subtitle) { <p>{{ subtitle }}</p> }
          <ng-content select="[panel-actions]" />
        </header>
      }
      <div class="body"><ng-content /></div>
    </section>
  `,
  styles: [`
    .panel {
      background: var(--surface);
      border-radius: var(--radius-card);
      border: var(--hair) solid var(--hairline);
      overflow: hidden;
    }
    /* Blur is a CHROME material only. Never applied to scrolling content. */
    .panel.chrome {
      background: var(--chrome);
      backdrop-filter: blur(30px) saturate(180%);
      border-radius: var(--radius-chrome);
    }
    header {
      display: flex; align-items: baseline; gap: 10px;
      padding: 14px 16px 0;
    }
    h2 { margin: 0; font-size: var(--fs-sm); font-weight: 600; color: var(--ink); letter-spacing: -.01em; }
    p { margin: 0; font-size: var(--fs-xs); color: var(--ink-2); }
    [panel-actions] { margin-left: auto; }
    .body { padding: 14px 16px 16px; }
  `],
})
export class PanelComponent {
  @Input() title = '';
  @Input() subtitle = '';
  @Input() chrome = false;
}
