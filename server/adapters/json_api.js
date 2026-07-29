const { normalizedItem } = require('./shape');
const { categoryBucket } = require('../normalize');
const { detectFields } = require('../field_detect');

function getPath(obj, path) {
  if (!path) return undefined;
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

function authHeaders(source) {
  if (source.api_key) {
    const header = source.api_key_header || (source.auth && source.auth.header) || 'Authorization';
    const scheme = source.api_key_scheme || (source.auth && source.auth.scheme) || 'Bearer';
    if (header.toLowerCase() === 'authorization') return { Authorization: `${scheme} ${source.api_key}` };
    return { [header]: source.api_key };
  }
  if (!source.auth) return {};
  const key = process.env[source.auth.env];
  if (!key) throw new Error(`missing API key env ${source.auth.env}`);
  const header = source.auth.header || 'Authorization';
  const scheme = source.auth.scheme || 'Bearer';
  if (header.toLowerCase() === 'authorization') return { Authorization: `${scheme} ${key}` };
  return { [header]: key };
}

async function fetch(source, ctx) {
  const res = await ctx.request(source.url, { method: source.method || 'GET', timeoutMs: 20000, headers: { Accept: 'application/json', ...authHeaders(source) } });
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
  const ct = res.headers['content-type'] || '';
  if (!ct.includes('json') && res.body.trim().startsWith('<')) throw new Error(`expected JSON, got ${ct || 'HTML'} (endpoint likely needs auth)`);
  let body;
  try { body = JSON.parse(res.body); } catch { throw new Error('response was not valid JSON'); }

  let records = source.recordsPath ? getPath(body, source.recordsPath) : null;
  if (!Array.isArray(records)) {
    records = Array.isArray(body) ? body : (body.items || body.data || body.results || body.value || body.vulnerabilities || null);
  }
  if (!Array.isArray(records)) throw new Error('could not locate record array in JSON response');

  const bucket = categoryBucket(source.category);
  const m = source.mapping || {};
  const firstRecord = records.find((r) => r && typeof r === 'object');
  const detected = firstRecord ? detectFields(firstRecord) : {};
  const h = { ...detected, ...(source.enrichHints || {}) };
  const out = [];
  for (const rec of records.slice(0, 50)) {
    if (typeof rec !== 'object' || rec === null) continue;
    const cve = h.cveField ? rec[h.cveField] : null;
    const cvss = h.cvssField != null ? Number(rec[h.cvssField]) : null;
    const title = (m.title && rec[m.title]) || (h.titleField && rec[h.titleField]) || null;
    const id = (m.id && rec[m.id]) || (h.idField && rec[h.idField]) || rec.id || rec.uuid || title || null;
    out.push(normalizedItem({
      external_id: id != null ? id : undefined,
      title: title != null ? title : undefined,
      summary: rec[m.summary] != null ? rec[m.summary] : null,
      link: rec[m.link] != null ? rec[m.link] : null,
      published_at: rec[m.date] != null ? rec[m.date] : null,
      category: bucket,
      raw: rec,
      native: {
        cveIds: cve ? [String(cve)] : [],
        cvssScore: Number.isFinite(cvss) ? cvss : null,
        severity: h.severityField ? (rec[h.severityField] || null) : null,
        vendor: h.vendorField ? (rec[h.vendorField] || null) : null,
      },
    }));
  }
  return out;
}
module.exports = { fetch };
