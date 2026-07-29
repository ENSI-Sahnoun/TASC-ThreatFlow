// "Since you last looked" — turns the dashboard from a snapshot into something worth
// returning to. Storage is injected so this stays testable without a browser.

const KEY = 'threatflow.lastVisit';

export function readWatermark(storage: Storage): string | null {
  try { return storage.getItem(KEY); } catch { return null; }
}

export function writeWatermark(storage: Storage, iso: string): void {
  try { storage.setItem(KEY, iso); } catch { /* private mode — the feature degrades, nothing breaks */ }
}

export function countNewSince(items: { published_at: string | null }[], watermark: string | null): number {
  if (!watermark) return 0;
  const mark = Date.parse(watermark);
  if (Number.isNaN(mark)) return 0;
  return items.filter((i) => {
    if (!i.published_at) return false;
    const t = Date.parse(i.published_at);
    return !Number.isNaN(t) && t > mark;
  }).length;
}
