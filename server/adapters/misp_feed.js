const { normalizedItem } = require('./shape');
const { categoryBucket } = require('../normalize');

const IOC_TYPES = { 'ip-src': 'ip', 'ip-dst': 'ip', domain: 'domain', hostname: 'domain', url: 'url', md5: 'md5', sha1: 'sha1', sha256: 'sha256' };

async function fetch(source, ctx) {
  const res = await ctx.request(source.url, { timeoutMs: 20000, headers: { Accept: 'application/json' } });
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
  let manifest;
  try { manifest = JSON.parse(res.body); } catch { throw new Error('manifest was not valid JSON'); }
  const base = source.url.replace(/manifest\.json$/, '');
  const uuids = Object.keys(manifest).slice(0, 10);
  const bucket = categoryBucket(source.category);
  const out = [];
  for (const uuid of uuids) {
    let evRes;
    try { evRes = await ctx.request(`${base}${uuid}.json`, { timeoutMs: 20000, headers: { Accept: 'application/json' } }); } catch { continue; }
    if (evRes.status < 200 || evRes.status >= 300) continue;
    let ev;
    try { ev = JSON.parse(evRes.body).Event; } catch { continue; }
    if (!ev) continue;
    const iocs = [];
    for (const attr of ev.Attribute || []) {
      const t = IOC_TYPES[attr.type];
      if (t) iocs.push({ type: t, value: attr.value });
    }
    out.push(normalizedItem({
      external_id: ev.uuid,
      title: ev.info || '(untitled)',
      summary: ev.info || null,
      link: null,
      published_at: ev.date || null,
      category: bucket,
      raw: ev,
      native: { iocs },
    }));
  }
  return out;
}
module.exports = { fetch };
