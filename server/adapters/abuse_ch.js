const { normalizedItem } = require('./shape');
const { categoryBucket } = require('../normalize');

function authHeaders(source) {
  if (source.api_key) return { [(source.auth && source.auth.header) || source.api_key_header || 'Auth-Key']: source.api_key };
  if (!source.auth) return {};
  const key = process.env[source.auth.env];
  if (!key) throw new Error(`missing API key env ${source.auth.env}`);
  return { [source.auth.header || 'Auth-Key']: key };
}

async function fetch(source, ctx) {
  // URLhaus/ThreatFox are plain GET downloads. MalwareBazaar's API is POST-only
  // (query=get_recent&selector=<n> as a form body) — driven by request_method/
  // request_body so it's configurable from the dashboard, not hardcoded here.
  const method = source.request_method || source.method || 'GET';
  const reqBody = source.request_body || undefined;
  const headers = { Accept: 'application/json', ...authHeaders(source) };
  if (reqBody) headers['Content-Type'] = 'application/x-www-form-urlencoded';
  const res = await ctx.request(source.url, { timeoutMs: 20000, method, body: reqBody, headers });
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
  const ct = res.headers['content-type'] || '';
  if (ct.includes('html') || res.body.trim().startsWith('<')) throw new Error('needs Auth-Key (got HTML, not JSON)');
  let body;
  try { body = JSON.parse(res.body); } catch { throw new Error('response was not valid JSON'); }

  // URLhaus/ThreatFox return { "<id>": [ {...} ] }; MalwareBazaar returns { data: [...] }.
  let records = [];
  if (Array.isArray(body)) records = body;
  else if (Array.isArray(body.data)) records = body.data;
  else records = Object.values(body).flat();

  const bucket = categoryBucket(source.category);
  const h = source.enrichHints || {};
  const out = [];
  for (const rec of records.slice(0, 100)) {
    if (typeof rec !== 'object' || rec === null) continue;
    const iocValue = h.iocField ? rec[h.iocField] : null;
    const iocType = h.iocTypeField ? rec[h.iocTypeField] : (h.iocType || 'url');
    const familyRaw = h.familyField ? rec[h.familyField] : null;
    const families = Array.isArray(familyRaw) ? familyRaw : (familyRaw ? [String(familyRaw)] : []);

    // MalwareBazaar samples carry file metadata that reads far better than a bare hash
    // (URLhaus/ThreatFox records don't have file_name, so they fall through to the
    // generic IOC-line format below).
    let title, summary;
    if (rec.file_name) {
      const family = rec.signature || families[0] || null;
      const sizeKb = rec.file_size ? `${Math.round(rec.file_size / 1024)} KB` : null;
      title = `${family ? `${family} — ` : ''}${rec.file_name} (${rec.file_type || 'unknown type'})`;
      summary = [rec.file_type_mime, sizeKb, rec.origin_country && `origin: ${rec.origin_country}`, rec.tags?.length && `tags: ${rec.tags.join(', ')}`]
        .filter(Boolean).join(' — ') || null;
    } else {
      title = `${families[0] || 'IOC'}: ${iocValue || '(unknown)'}`;
      summary = rec.threat_type || rec.threat || rec.tags?.join(', ') || null;
    }

    out.push(normalizedItem({
      external_id: iocValue || rec.id || JSON.stringify(rec).slice(0, 60),
      title,
      summary,
      link: /^https?:\/\//.test(String(iocValue)) ? iocValue : null,
      published_at: rec.first_seen || rec.dateadded || rec.first_seen_utc || null,
      category: bucket,
      raw: rec,
      native: { iocs: iocValue ? [{ type: iocType, value: String(iocValue) }] : [], malwareFamilies: families },
    }));
  }
  return out;
}
module.exports = { fetch };
