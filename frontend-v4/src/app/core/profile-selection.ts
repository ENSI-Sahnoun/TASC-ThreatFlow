// Which profile should be active, given what the server returned and what was last selected.
//
// Pure and storage-free so it can be tested without a DOM — ProfileService owns localStorage.
// The fallback matters: a stored id pointing at a deleted profile would otherwise leave the
// app with no active profile forever, and every request would drop its X-Profile-Id silently.
export function resolveActiveId(profiles: { id: number }[], storedId: number | null): number | null {
  if (!profiles.length) return null;
  if (storedId != null && profiles.some((p) => p.id === storedId)) return storedId;
  return profiles[0].id;
}

// Rejects anything that is not a positive integer, so a corrupted or hand-edited storage value
// falls back to the first profile rather than being sent to the API as a bad header.
export function parseStoredId(raw: string | null): number | null {
  if (raw == null || raw === '') return null;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : null;
}
