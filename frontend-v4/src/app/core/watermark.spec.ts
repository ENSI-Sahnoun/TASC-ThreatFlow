import { describe, it, expect } from 'vitest';
import { readWatermark, writeWatermark, countNewSince } from './watermark';

function fakeStorage(): Storage {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => { map.set(k, v); },
    removeItem: (k: string) => { map.delete(k); },
    clear: () => map.clear(),
    key: () => null,
    length: 0,
  } as unknown as Storage;
}

describe('visit watermark', () => {
  it('round-trips through storage and starts empty', () => {
    const s = fakeStorage();
    expect(readWatermark(s)).toBeNull();
    writeWatermark(s, '2026-07-26T12:00:00Z');
    expect(readWatermark(s)).toBe('2026-07-26T12:00:00Z');
  });

  it('counts items newer than the watermark', () => {
    const items = [
      { published_at: '2026-07-26T13:00:00Z' },
      { published_at: '2026-07-26T11:00:00Z' },
      { published_at: null },
    ];
    expect(countNewSince(items, '2026-07-26T12:00:00Z')).toBe(1);
    expect(countNewSince(items, null)).toBe(0);
  });
});
