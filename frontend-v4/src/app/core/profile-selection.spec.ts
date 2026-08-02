import { describe, it, expect } from 'vitest';
import { resolveActiveId, parseStoredId } from './profile-selection';

const P = (id: number) => ({ id });

describe('resolveActiveId', () => {
  it('returns null when there are no profiles', () => {
    expect(resolveActiveId([], null)).toBeNull();
    expect(resolveActiveId([], 3)).toBeNull();
  });

  it('keeps the stored profile when it still exists', () => {
    expect(resolveActiveId([P(1), P(2)], 2)).toBe(2);
  });

  it('falls back to the first profile when nothing is stored', () => {
    expect(resolveActiveId([P(7), P(8)], null)).toBe(7);
  });

  // A stored id pointing at a deleted profile must not leave the app with no active profile.
  it('falls back to the first profile when the stored id no longer exists', () => {
    expect(resolveActiveId([P(1), P(2)], 99)).toBe(1);
  });
});

describe('parseStoredId', () => {
  it('accepts a positive integer', () => {
    expect(parseStoredId('4')).toBe(4);
  });

  it('rejects anything that could not be a profile id', () => {
    for (const bad of [null, '', 'abc', '-1', '0', '1.5', 'NaN']) {
      expect(parseStoredId(bad)).toBeNull();
    }
  });
});
