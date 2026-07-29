import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { of, throwError } from 'rxjs';
import { pollingSignal, type VisibilitySource } from './poll';

function fakeVisibility(initiallyHidden = false): VisibilitySource & { setHidden(v: boolean): void } {
  let hidden = initiallyHidden;
  let listener: (() => void) | null = null;
  return {
    hidden: () => hidden,
    onChange(cb) {
      listener = cb;
      return () => { listener = null; };
    },
    setHidden(v: boolean) {
      hidden = v;
      listener?.();
    },
  };
}

describe('pollingSignal', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('fetches immediately, then again every intervalMs', () => {
    const fetcher = vi.fn(() => of('a'));
    const handle = pollingSignal(fetcher, 1000, () => false, fakeVisibility());

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(handle.value()).toBe('a');

    vi.advanceTimersByTime(1000);
    expect(fetcher).toHaveBeenCalledTimes(2);

    vi.advanceTimersByTime(1000);
    expect(fetcher).toHaveBeenCalledTimes(3);

    handle.destroy();
  });

  it('suspends while hidden and refetches immediately when visible again', () => {
    const fetcher = vi.fn(() => of('a'));
    const visibility = fakeVisibility(false);
    const handle = pollingSignal(fetcher, 1000, () => false, visibility);
    expect(fetcher).toHaveBeenCalledTimes(1);

    visibility.setHidden(true);
    // Time passes with the tab hidden — no further fetches, no matter how many intervals elapse.
    vi.advanceTimersByTime(5000);
    expect(fetcher).toHaveBeenCalledTimes(1);

    // Coming back triggers an immediate fetch, not a wait for the next scheduled tick.
    visibility.setHidden(false);
    expect(fetcher).toHaveBeenCalledTimes(2);

    handle.destroy();
  });

  it('suspends while paused() is true', () => {
    const fetcher = vi.fn(() => of('a'));
    let paused = true;
    const handle = pollingSignal(fetcher, 1000, () => paused, fakeVisibility());

    // Starts paused: no initial fetch.
    expect(fetcher).toHaveBeenCalledTimes(0);

    vi.advanceTimersByTime(5000);
    expect(fetcher).toHaveBeenCalledTimes(0);

    paused = false;
    // paused() is only re-checked at the next scheduled tick, not pushed instantly.
    vi.advanceTimersByTime(1000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(handle.value()).toBe('a');

    handle.destroy();
  });

  it('flips stale() true on a failed fetch without clearing the last good value', () => {
    let shouldFail = false;
    const fetcher = vi.fn(() => (shouldFail ? throwError(() => new Error('boom')) : of('ok')));
    const handle = pollingSignal(fetcher, 1000, () => false, fakeVisibility());

    expect(handle.value()).toBe('ok');
    expect(handle.stale()).toBe(false);

    shouldFail = true;
    vi.advanceTimersByTime(1000);
    expect(handle.stale()).toBe(true);
    expect(handle.value()).toBe('ok'); // last good value is retained, not wiped

    shouldFail = false;
    vi.advanceTimersByTime(1000);
    expect(handle.stale()).toBe(false);

    handle.destroy();
  });

  it('stops all activity after destroy()', () => {
    const fetcher = vi.fn(() => of('a'));
    const visibility = fakeVisibility();
    const handle = pollingSignal(fetcher, 1000, () => false, visibility);
    expect(fetcher).toHaveBeenCalledTimes(1);

    handle.destroy();
    vi.advanceTimersByTime(5000);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
