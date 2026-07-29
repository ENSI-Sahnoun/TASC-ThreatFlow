import { Injectable, signal } from '@angular/core';

export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'tf-theme';

// index.html runs an inline script that sets documentElement's data-theme attribute before
// first paint (avoids a flash of the wrong theme while Angular boots). This service exists to
// let components read/change theme afterward — it reads that same attribute back rather than
// re-deriving from localStorage/matchMedia, so the two can never disagree.
@Injectable({ providedIn: 'root' })
export class ThemeService {
  theme = signal<Theme>(
    (document.documentElement.getAttribute('data-theme') as Theme | null) ?? 'dark',
  );

  toggle(): void {
    this.set(this.theme() === 'dark' ? 'light' : 'dark');
  }

  set(theme: Theme): void {
    this.theme.set(theme);
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);
  }
}
