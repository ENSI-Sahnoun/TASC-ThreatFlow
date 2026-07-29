// Scheme and a trailing slash are the two differences a human copy-pasting a URL is most likely
// to introduce by accident (https vs the feed's http, or a browser address bar dropping the
// slash) — normalizing just those two keeps the checker forgiving without going as loose as a
// bare-domain match, which would also flag unrelated pages on a compromised host.
function normalizeUrl(url) {
  return String(url || '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
}

module.exports = { normalizeUrl };
