// Can a given page be framed by us? Script inside the framing page gets no answer to that:
// when a site refuses (X-Frame-Options / CSP frame-ancestors) the browser renders its OWN error
// document inside the frame and still fires `load`, so from the outside a refusal is
// indistinguishable from a successful render. The only place the truth is legible is the
// response headers — hence deciding here, server-side, before an iframe is ever created.
//
// This is a deliberate subset of the real grammars: enough to answer "would a browser at
// viewerOrigin let us frame targetUrl", not a general CSP parser.

function headerList(value) {
  if (!value) return [];
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

function originOf(urlStr) {
  try {
    const u = new URL(urlStr);
    return `${u.protocol}//${u.host}`.toLowerCase();
  } catch {
    return null;
  }
}

// A single CSP header may carry several comma-separated policies, and a response may repeat the
// header; every policy applies independently, so any one of them refusing is a refusal.
function policiesFrom(headers) {
  return headerList(headers['content-security-policy'])
    .flatMap((v) => v.split(','))
    .map((p) => p.trim())
    .filter(Boolean);
}

function frameAncestorsOf(policy) {
  for (const directive of policy.split(';')) {
    const parts = directive.trim().split(/\s+/).filter(Boolean);
    if (parts.length && parts[0].toLowerCase() === 'frame-ancestors') {
      return parts.slice(1).map((s) => s.toLowerCase());
    }
  }
  return null;
}

function defaultPort(protocol) {
  return protocol === 'https:' ? '443' : protocol === 'http:' ? '80' : '';
}

// One frame-ancestors source-expression vs. the origin doing the framing. Host-source syntax is
// `[scheme://]host[:port][/path]` — the path is meaningless for an ancestor check (an ancestor is
// matched by origin, not by URL) so it is stripped rather than compared.
function matchesSource(src, viewerOrigin, targetOrigin) {
  if (src === '*') return true;
  if (src === "'none'") return false;
  // 'self' means the *target's* own origin — only a match when the page is framing itself.
  if (src === "'self'") return viewerOrigin === targetOrigin;
  // Anything else quoted ('unsafe-inline', nonces, hashes) is not a valid ancestor source.
  if (src.startsWith("'")) return false;

  let viewer;
  try {
    viewer = new URL(viewerOrigin);
  } catch {
    return false;
  }

  // scheme-source: a bare `https:` matches any host on that scheme.
  if (/^[a-z][a-z0-9+.-]*:$/.test(src)) return viewer.protocol === src;

  let rest = src;
  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//.exec(src);
  if (schemeMatch) {
    if (viewer.protocol !== `${schemeMatch[1]}:`) return false;
    rest = src.slice(schemeMatch[0].length);
  }
  rest = rest.split('/')[0];

  const portSplit = /^(.*?)(?::(\d+|\*))?$/.exec(rest);
  const host = (portSplit[1] || '').toLowerCase();
  const port = portSplit[2];
  if (port && port !== '*') {
    const viewerPort = viewer.port || defaultPort(viewer.protocol);
    if (viewerPort !== port) return false;
  }

  const viewerHost = viewer.hostname.toLowerCase();
  if (host === '*') return true;
  if (host.startsWith('*.')) return viewerHost.endsWith(host.slice(1));
  return viewerHost === host;
}

function frameAncestorsVerdict(sources, viewerOrigin, targetOrigin) {
  if (sources.length === 0) return { frameable: false, detail: "frame-ancestors with no sources (treated as 'none')" };
  if (sources.length === 1 && sources[0] === "'none'") return { frameable: false, detail: "frame-ancestors 'none'" };
  const allowed = sources.some((s) => matchesSource(s, viewerOrigin, targetOrigin));
  return allowed
    ? { frameable: true }
    : { frameable: false, detail: `frame-ancestors ${sources.join(' ')}` };
}

// X-Frame-Options only has two values browsers still honour. ALLOW-FROM was dropped by every
// engine and anything unparseable is ignored outright, so both are treated as "no restriction"
// — matching what the browser will actually do rather than being conservative for its own sake.
function xfoVerdict(headers, viewerOrigin, targetOrigin) {
  const tokens = headerList(headers['x-frame-options'])
    .flatMap((v) => v.split(','))
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
  if (tokens.includes('deny')) return { frameable: false, detail: 'X-Frame-Options: DENY' };
  if (tokens.includes('sameorigin') && viewerOrigin !== targetOrigin) {
    return { frameable: false, detail: 'X-Frame-Options: SAMEORIGIN' };
  }
  return { frameable: true };
}

// Returns { frameable, reason?, detail? }. `reason` is a stable machine token for the UI;
// `detail` is the human-readable header text worth showing a user.
function frameVerdict(headers = {}, { viewerOrigin, targetUrl } = {}) {
  const targetOrigin = originOf(targetUrl);
  const viewer = (viewerOrigin || '').toLowerCase();

  // CSP Level 3: when frame-ancestors is present it supersedes X-Frame-Options entirely, so a
  // site sending `frame-ancestors *` alongside a legacy `X-Frame-Options: DENY` is frameable.
  const ancestorLists = policiesFrom(headers).map(frameAncestorsOf).filter((l) => l !== null);
  if (ancestorLists.length > 0) {
    for (const sources of ancestorLists) {
      const verdict = frameAncestorsVerdict(sources, viewer, targetOrigin);
      if (!verdict.frameable) return { frameable: false, reason: 'frame-ancestors', detail: verdict.detail };
    }
    return { frameable: true };
  }

  const xfo = xfoVerdict(headers, viewer, targetOrigin);
  if (!xfo.frameable) return { frameable: false, reason: 'x-frame-options', detail: xfo.detail };
  return { frameable: true };
}

module.exports = { frameVerdict, matchesSource, frameAncestorsOf };
