// Adapter ctx (injected by syncSource, stubbed in tests):
//   ctx.request(url, opts) -> Promise<{ status, headers, body }>  (wraps safeRequest)
//   ctx.now() -> Date
const { displayTitle, cleanSummary, normalizeLink, extractTitleUrl } = require('../present');

const TITLE_KEY_RE = /title|name|headline|subject/i;
const ID_KEY_RE = /^id$|_id$|^uuid$|^cve/i;

// Best-effort guess when an adapter didn't resolve a title/id: scan the raw record
// for a key that looks title-ish/id-ish rather than falling straight to '(untitled)'.
function guessFromRaw(raw, keyRe) {
  if (!raw || typeof raw !== 'object') return null;
  for (const [k, v] of Object.entries(raw)) {
    if (keyRe.test(k) && typeof v === 'string' && v.trim()) return v;
  }
  return null;
}

function normalizedItem(fields = {}) {
  const native = fields.native || {};
  const rawTitle = fields.title || guessFromRaw(fields.raw, TITLE_KEY_RE);
  const externalId = fields.external_id != null ? fields.external_id : guessFromRaw(fields.raw, ID_KEY_RE);
  const category = fields.category || 'other';

  // A URL-only title still carries the one fact that matters — the URL. Move it to `link`
  // (when the feed gave us none) and keep it as an IOC rather than dropping it on the floor.
  const titleUrl = extractTitleUrl(rawTitle);
  const iocs = [...(native.iocs || [])];
  if (titleUrl && !iocs.some((i) => i.type === 'url' && i.value === titleUrl)) {
    iocs.push({ type: 'url', value: titleUrl });
  }

  return {
    external_id: externalId != null ? String(externalId) : null,
    title: displayTitle(rawTitle, { category }) || '(untitled)',
    summary: cleanSummary(fields.summary),
    author: fields.author || null,
    link: normalizeLink(fields.link) || titleUrl || null,
    published_at: fields.published_at || null,
    category,
    raw: fields.raw != null ? fields.raw : null,
    native: {
      cveIds: native.cveIds || [],
      iocs,
      cpes: native.cpes || [],
      cwes: native.cwes || [],
      malwareFamilies: native.malwareFamilies || [],
      actors: native.actors || [],
      vendor: native.vendor || null,
      region: native.region || null,
      industry: native.industry || null,
      cvssScore: native.cvssScore != null ? native.cvssScore : null,
      cvssVersion: native.cvssVersion || null,
      epssScore: native.epssScore != null ? Number(native.epssScore) : null,
      // Not stored on items, only consumed by enrichItem() to derive cvssScore when the
      // feed gave no number (see server/adapters/osv.js). Must stay on the whitelist below
      // or an adapter-supplied vector is silently dropped before enrichment ever sees it.
      cvssVector: native.cvssVector || null,
      severity: native.severity || null,
      exploitation: native.exploitation || null,
    },
  };
}
module.exports = { normalizedItem };
