// Backend-reachability primitive, sibling to poll.ts rather than built on top of it.
// pollingSignal's `stale` flips true on the *first* failure and only changes again on a
// success — repeated consecutive failures never produce a new signal value, so nothing built
// on top of `stale` could count "N in a row" without missing updates. This tracks its own
// consecutive-failure counter instead, so a single slow response doesn't flash the banner.

import { signal, type Signal } from '@angular/core';
import type { Observable, Subscription } from 'rxjs';
import { documentVisibilitySource, type VisibilitySource } from './poll';

export interface HealthPollHandle {
  /** True once `failureThreshold` consecutive checks have failed. Flips back to false on the next success. */
  unreachable: Signal<boolean>;
  /** Stops polling and releases the visibility listener. Idempotent. */
  destroy(): void;
}

/**
 * Polls `check()` every `intervalMs`, declaring the backend unreachable only after
 * `failureThreshold` consecutive failures. Pauses while the tab is hidden and checks
 * immediately upon becoming visible again, matching pollingSignal's behavior.
 */
export function healthPoll(
  check: () => Observable<unknown>,
  intervalMs = 5000,
  failureThreshold = 3,
  visibility: VisibilitySource = documentVisibilitySource(),
): HealthPollHandle {
  const unreachable = signal(false);
  let consecutiveFailures = 0;

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
    sub = check().subscribe({
      next: () => {
        if (destroyed) return;
        consecutiveFailures = 0;
        unreachable.set(false);
        scheduleNext();
      },
      error: () => {
        if (destroyed) return;
        consecutiveFailures += 1;
        if (consecutiveFailures >= failureThreshold) unreachable.set(true);
        scheduleNext();
      },
    });
  }

  function tick(): void {
    if (destroyed) return;
    if (visibility.hidden()) { scheduleNext(); return; }
    fetchNow();
  }

  const unsubscribeVisibility = visibility.onChange(() => {
    if (destroyed) return;
    if (!visibility.hidden()) fetchNow();
    else clearTimer();
  });

  if (!visibility.hidden()) fetchNow(); else scheduleNext();

  return {
    unreachable: unreachable.asReadonly(),
    destroy(): void {
      if (destroyed) return;
      destroyed = true;
      clearTimer();
      sub?.unsubscribe();
      unsubscribeVisibility();
    },
  };
}
