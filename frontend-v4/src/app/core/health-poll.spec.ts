import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { of, throwError } from 'rxjs';
import { healthPoll } from './health-poll';
import type { VisibilitySource } from './poll';

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

describe('healthPoll', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('stays reachable while checks succeed', () => {
    const check = vi.fn(() => of(null));
    const handle = healthPoll(check, 1000, 3, fakeVisibility());

    expect(handle.unreachable()).toBe(false);
    vi.advanceTimersByTime(3000);
    expect(handle.unreachable()).toBe(false);

    handle.destroy();
  });

  it('does not flip on 1 or 2 failures, only on the 3rd consecutive one', () => {
    const check = vi.fn(() => throwError(() => new Error('down')));
    const handle = healthPoll(check, 1000, 3, fakeVisibility());

    // Failure #1 (the initial fetch).
    expect(handle.unreachable()).toBe(false);

    vi.advanceTimersByTime(1000); // #2
    expect(handle.unreachable()).toBe(false);

    vi.advanceTimersByTime(1000); // #3
    expect(handle.unreachable()).toBe(true);

    handle.destroy();
  });

  it('resets the counter on a success and recovers from unreachable', () => {
    let shouldFail = true;
    const check = vi.fn(() => (shouldFail ? throwError(() => new Error('down')) : of(null)));
    const handle = healthPoll(check, 1000, 3, fakeVisibility());

    vi.advanceTimersByTime(2000); // 3 consecutive failures total
    expect(handle.unreachable()).toBe(true);

    shouldFail = false;
    vi.advanceTimersByTime(1000);
    expect(handle.unreachable()).toBe(false);

    handle.destroy();
  });

  it('a single success between failures prevents the threshold from ever being reached', () => {
    let fail = true;
    const check = vi.fn(() => (fail ? throwError(() => new Error('down')) : of(null)));
    const handle = healthPoll(check, 1000, 3, fakeVisibility());

    fail = true; vi.advanceTimersByTime(1000); // failure #2
    fail = false; vi.advanceTimersByTime(1000); // success — resets counter
    expect(handle.unreachable()).toBe(false);

    fail = true; vi.advanceTimersByTime(1000); // failure #1 again
    fail = true; vi.advanceTimersByTime(1000); // failure #2
    expect(handle.unreachable()).toBe(false);

    handle.destroy();
  });

  it('suspends while hidden and checks immediately when visible again', () => {
    const check = vi.fn(() => of(null));
    const visibility = fakeVisibility(false);
    const handle = healthPoll(check, 1000, 3, visibility);
    expect(check).toHaveBeenCalledTimes(1);

    visibility.setHidden(true);
    vi.advanceTimersByTime(5000);
    expect(check).toHaveBeenCalledTimes(1);

    visibility.setHidden(false);
    expect(check).toHaveBeenCalledTimes(2);

    handle.destroy();
  });

  it('stops all activity after destroy()', () => {
    const check = vi.fn(() => of(null));
    const handle = healthPoll(check, 1000, 3, fakeVisibility());
    expect(check).toHaveBeenCalledTimes(1);

    handle.destroy();
    vi.advanceTimersByTime(5000);
    expect(check).toHaveBeenCalledTimes(1);
  });
});
