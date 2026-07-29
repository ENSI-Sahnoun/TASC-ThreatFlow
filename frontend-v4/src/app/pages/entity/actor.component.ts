import { Component, ChangeDetectionStrategy, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute } from '@angular/router';
import type { HttpErrorResponse } from '@angular/common/http';
import { ApiService } from '../../core/api.service';
import { EntityProfileComponent } from './entity-profile.component';
import type { EntityProfile } from '../../core/models';

// The routed "/actor/:name" page. Owns the fetch against GET /api/actors/:name and nothing else
// — rendering is entirely delegated to <tf-entity-profile>, shared with malware.component so the
// two pages differ only in API method and heading noun (per the task brief).
@Component({
  selector: 'tf-page-actor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [EntityProfileComponent],
  template: `
    <tf-entity-profile
      heading="Threat actor"
      [profile]="profile()"
      [loading]="loading()"
      [notFound]="notFound()"
      [error]="error()"
      (retry)="load()"
    />
  `,
})
export class ActorComponent {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);

  private name = '';

  profile = signal<EntityProfile | null>(null);
  loading = signal(true);
  notFound = signal(false);
  error = signal(false);

  constructor() {
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((pm) => {
      this.name = pm.get('name') ?? '';
      this.profile.set(null);
      this.load();
    });
  }

  load(): void {
    if (!this.name) { this.notFound.set(true); this.loading.set(false); return; }
    this.loading.set(true);
    this.notFound.set(false);
    this.error.set(false);
    this.api.actor(this.name).subscribe({
      next: (p) => { this.profile.set(p); this.loading.set(false); },
      error: (err: HttpErrorResponse) => {
        this.loading.set(false);
        if (err.status === 404) this.notFound.set(true);
        else this.error.set(true);
      },
    });
  }
}
