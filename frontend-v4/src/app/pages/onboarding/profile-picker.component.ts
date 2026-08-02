import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import { Router } from '@angular/router';
import { ProfileService } from '../../core/profile.service';

// Header control for switching persona. Selecting a profile changes what the relevance scoring
// treats as "yours"; it is not a login and grants no access.
@Component({
  selector: 'tf-profile-picker',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (svc.profiles().length) {
      <div class="picker">
        <select
          [value]="svc.active()?.id ?? ''"
          (change)="pick($event)"
          aria-label="Active profile"
        >
          @for (p of svc.profiles(); track p.id) {
            <option [value]="p.id">{{ p.name }}</option>
          }
        </select>
        <button type="button" class="add" title="Add profile" (click)="add()">+</button>
      </div>
    }
  `,
  styles: [`
    .picker { display: inline-flex; align-items: center; gap: 4px; }
    select {
      font-size: var(--fs-xs); padding: 4px 8px; border-radius: 8px;
      border: 1px solid color-mix(in srgb, var(--ink) 16%, transparent);
      background: transparent; color: var(--ink); max-width: 160px;
    }
    .add {
      width: 26px; height: 26px; border-radius: 8px; cursor: pointer; line-height: 1;
      border: 1px solid color-mix(in srgb, var(--ink) 16%, transparent);
      background: transparent; color: var(--ink-2); font-size: var(--fs-sm);
    }
    .add:hover { color: var(--ink); border-color: currentColor; }
  `],
})
export class ProfilePickerComponent {
  readonly svc = inject(ProfileService);
  private router = inject(Router);

  pick(e: Event): void {
    const raw = (e.target as HTMLSelectElement).value;
    const id = Number(raw);
    if (Number.isInteger(id) && id > 0) this.svc.select(id);
  }

  add(): void { this.router.navigateByUrl('/onboarding'); }
}
