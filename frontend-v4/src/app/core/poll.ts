// Framework-light polling primitive. Uses Angular's standalone `signal()` (a plain reactive
// primitive, not a DI service) so components can bind straight to `.value()`/`.stale()` in an
// OnPush template, but everything else here is hand-rolled timer bookkeeping — no TestBed, no
// zone.js, no injection context required. That's what lets `poll.spec.ts` exercise it with
// nothing but `vi.useFakeTimers()`, the same way `watermark.ts` stays testable by taking its
// `Storage` as a parameter instead of touching a global.
//
// Visibility is the other global this file would otherwise reach for directly. Instead it takes
// a small `VisibilitySource` abstraction — `documentVisibilitySource()` is the real one, a fake
// one drives the tests.

import { signal, type Signal } from '@angular/core';
import type { Observable, Subscription } from 'rxjs';

export interface VisibilitySource {
  /** True when the page is not currently visible to the user. */
  hidden(): boolean;
  /** Subscribe to visibility changes; returns an unsubscribe function. */
  onChange(cb: () => void): () => void;
}

export function documentVisibilitySource(): VisibilitySource {
  const hasDocument = typeof document !== 'undefined';
  return {
    hidden: () => (hasDocument ? document.hidden : false),
    onChange(cb: () => void) {
      if (!hasDocument) return () => {};
      document.addEventListener('visibilitychange', cb);
      return () => document.removeEventListener('visibilitychange', cb);
    },
  };
}

export interface PollingHandle<T> {
  /** Latest successfully-fetched value, or null before the first success. */
  value: Signal<T | null>;
  /**
   * True when the most recent fetch attempt failed. The last good `value` is left in place —
   * callers must consult `stale()` themselves rather than assume a present `value` is current.
   */
  stale: Signal<boolean>;
  /** Stops polling and releases the visibility listener. Idempotent. */
  destroy(): void;
}

/**
 * Polls `source()` every `intervalMs`, exposing the latest result as a signal.
 *
 * - While the page is hidden (per `visibility`), polling suspends entirely and resumes with an
 *   immediate fetch the moment it becomes visible again — no reason to hit the network for a
 *   tab nobody is looking at, and no reason to make the user wait out a full interval once they
 *   come back.
 * - While `paused()` reads true, each scheduled tick is skipped (checked lazily, once per
 *   interval) rather than fetching. Unlike visibility, there is no push notification for when a
 *   signal flips — `paused` is just re-read at the next tick boundary.
 * - A failed fetch sets `stale()` true and is retried on the same cadence; it does not clear the
 *   last good `value`, so it's on the caller to render a staleness cue rather than presenting
 *   old data as current.
 */
export function pollingSignal<T>(
  source: () => Observable<T>,
  intervalMs: number,
  paused: () => boolean,
  visibility: VisibilitySource = documentVisibilitySource(),
): PollingHandle<T> {
  const value = signal<T | null>(null);
  const stale = signal(false);

  let timer: ReturnType<typeof setTimeout> | null = null;
  let sub: Subscription | null = null;
  let destroyed = false;

  const clearTimer = () => {
    if (timer !== null) { clearTimeout(timer); timer = null; }
  };

  const scheduleNext = () => {
    clearTimer();
    if (destroyed) return;
    timer = setTimeout(tick, intervalMs);
  };

  function fetchNow(): void {
    if (destroyed) return;
    clearTimer();
    sub?.unsubscribe();
    sub = source().subscribe({
      next: (v) => { if (!destroyed) { value.set(v); stale.set(false); } },
      error: () => { if (!destroyed) { stale.set(true); scheduleNext(); } },
      complete: () => { if (!destroyed) scheduleNext(); },
    });
  }

  function tick(): void {
    if (destroyed) return;
    if (visibility.hidden() || paused()) { scheduleNext(); return; }
    fetchNow();
  }

  const unsubscribeVisibility = visibility.onChange(() => {
    if (destroyed) return;
    if (visibility.hidden()) {
      // Gone hidden: drop any pending tick. Nothing fetches again until we're visible.
      clearTimer();
    } else {
      // Back from hidden: refetch immediately rather than waiting out the rest of the interval.
      if (paused()) scheduleNext(); else fetchNow();
    }
  });

  // Kick off — an immediate first fetch unless we start out hidden or paused.
  if (!visibility.hidden() && !paused()) fetchNow(); else scheduleNext();

  return {
    value: value.asReadonly(),
    stale: stale.asReadonly(),
    destroy(): void {
      if (destroyed) return;
      destroyed = true;
      clearTimer();
      sub?.unsubscribe();
      unsubscribeVisibility();
    },
  };
}
