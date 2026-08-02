import { Injectable, computed, inject, signal } from '@angular/core';
import { ApiService } from './api.service';
import { resolveActiveId, parseStoredId } from './profile-selection';
import type { Profile, ProfilePayload } from './models';

export const ACTIVE_PROFILE_KEY = 'threatflow.activeProfileId';

// Profiles are personas, not accounts: selecting one is a display preference, not a login.
// The id lives in localStorage so a reload keeps the same view.
//
// Selection logic lives in profile-selection.ts as pure functions — this class only wires
// them to storage, HTTP and signals.
@Injectable({ providedIn: 'root' })
export class ProfileService {
  private api = inject(ApiService);

  private readonly _profiles = signal<Profile[]>([]);
  private readonly _activeId = signal<number | null>(readStoredId());
  private readonly _loaded = signal(false);

  readonly profiles = this._profiles.asReadonly();
  readonly loaded = this._loaded.asReadonly();
  readonly active = computed(() => this._profiles().find((p) => p.id === this._activeId()) ?? null);

  // Only true once the list has actually arrived — otherwise a slow response would bounce a
  // user who does have profiles straight into onboarding.
  readonly needsOnboarding = computed(() => this._loaded() && this._profiles().length === 0);

  load(): void {
    this.api.profiles().subscribe({
      next: (rows) => {
        this._profiles.set(rows);
        this._loaded.set(true);
        this.select(resolveActiveId(rows, this._activeId()));
      },
      // A failed load must not claim "no profiles" and blank the header; leave the previous
      // state and let the next load try again.
      error: () => { this._loaded.set(false); },
    });
  }

  select(id: number | null): void {
    this._activeId.set(id);
    try {
      if (id == null) localStorage.removeItem(ACTIVE_PROFILE_KEY);
      else localStorage.setItem(ACTIVE_PROFILE_KEY, String(id));
    } catch { /* storage unavailable (private mode); selection still works for this session */ }
  }

  create(payload: ProfilePayload, done?: (p: Profile) => void, fail?: (message: string) => void): void {
    this.api.createProfile(payload).subscribe({
      next: (p) => {
        this._profiles.update((rows) => [p, ...rows]);
        this._loaded.set(true);
        this.select(p.id);
        done?.(p);
      },
      // The API returns 400 with a specific reason (duplicate name, unknown sector, non-slug
      // vendor). Surfacing it beats a generic failure the user cannot act on.
      error: (e) => fail?.(e?.error?.error ?? 'Could not save the profile.'),
    });
  }

  update(id: number, payload: ProfilePayload, done?: (p: Profile) => void): void {
    this.api.updateProfile(id, payload).subscribe((p) => {
      this._profiles.update((rows) => rows.map((r) => (r.id === p.id ? p : r)));
      done?.(p);
    });
  }
}

function readStoredId(): number | null {
  try {
    return parseStoredId(localStorage.getItem(ACTIVE_PROFILE_KEY));
  } catch {
    return null;
  }
}
