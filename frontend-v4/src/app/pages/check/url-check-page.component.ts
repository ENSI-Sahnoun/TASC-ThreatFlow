import { Component, ChangeDetectionStrategy } from '@angular/core';
import { UrlCheckComponent } from '../../ui/url-check.component';

@Component({
  selector: 'tf-page-check',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [UrlCheckComponent],
  template: `
    <header class="page-head">
      <h1 class="tf-heading">Check a URL</h1>
      <p class="tagline">Look up whether a URL has been reported across all ingested threat feeds.</p>
    </header>
    <tf-url-check />
  `,
  styles: [`
    :host { display: flex; flex-direction: column; gap: 20px; max-width: 640px; }
    .page-head { display: flex; flex-direction: column; gap: 2px; }
    .page-head h1 { margin: 0; font-size: var(--fs-xl); color: var(--ink); }
    .page-head .tagline { margin: 0; font-size: var(--fs-sm); color: var(--ink-2); }
  `],
})
export class UrlCheckPageComponent {}
