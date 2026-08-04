import { Injectable, computed, inject, signal } from '@angular/core';
import { ApiService } from './api.service';
import { resolveActiveId, parseStoredId, isProfileChange } from './profile-selection';
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
  private readonly _dataVersion = signal(0);

  readonly profiles = this._profiles.asReadonly();
  readonly loaded = this._loaded.asReadonly();
  readonly active = computed(() => this._profiles().find((p) => p.id === this._activeId()) ?? null);

  // Bumped by select() whenever the active profile actually changes. Every page component that
  // renders profile-scoped data (relevance tier, consequence, playbook) reads this inside an
  // effect() so a profile switch invalidates what's already on screen. It is a counter rather
  // than an event so a component created after a switch reads the current number and is correct
  // without having observed the transition.
  readonly dataVersion = this._dataVersion.asReadonly();

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
    if (!isProfileChange(this._activeId(), id)) return;
    this._activeId.set(id);
    try {
      if (id == null) localStorage.removeItem(ACTIVE_PROFILE_KEY);
      else localStorage.setItem(ACTIVE_PROFILE_KEY, String(id));
    } catch { /* storage unavailable (private mode); selection still works for this session */ }
    this._dataVersion.update((n) => n + 1);
  }

  // The server already recomputes relevance in the background on create/update (~1s, so it
  // isn't worth blocking the write itself on) — but nothing else waits for it, so a caller that
  // navigates straight to the item list races it and reads every item at the 'not_yours'
  // default. `done` fires only once this explicit recompute call resolves, so anyone reacting
  // to it (navigation, a reload) sees the real verdicts on the very first paint.
  //
  // Prose is the opposite: it takes minutes and needs Ollama, so it is fired and forgotten —
  // waiting for it would make every profile save feel broken.
  create(payload: ProfilePayload, done?: (p: Profile) => void, fail?: (message: string) => void): void {
    this.api.createProfile(payload).subscribe({
      next: (p) => {
        this._profiles.update((rows) => [p, ...rows]);
        this._loaded.set(true);
        this.select(p.id);
        this.api.generateProfileProse(p.id).subscribe({ error: () => {} });
        this.api.recomputeProfileRelevance(p.id).subscribe({
          next: () => done?.(p),
          error: () => done?.(p),
        });
      },
      // The API returns 400 with a specific reason (duplicate name, unknown sector, non-slug
      // vendor). Surfacing it beats a generic failure the user cannot act on.
      error: (e) => fail?.(e?.error?.error ?? 'Could not save the profile.'),
    });
  }

  update(id: number, payload: ProfilePayload, done?: (p: Profile) => void): void {
    this.api.updateProfile(id, payload).subscribe((p) => {
      this._profiles.update((rows) => rows.map((r) => (r.id === p.id ? p : r)));
      this.api.generateProfileProse(p.id).subscribe({ error: () => {} });
      this.api.recomputeProfileRelevance(p.id).subscribe({
        next: () => done?.(p),
        error: () => done?.(p),
      });
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
