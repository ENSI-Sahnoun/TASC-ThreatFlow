const { normalizedItem } = require('./shape');
const { categoryBucket } = require('../normalize');

// OSV /v1/query is per-package; query a representative spread of ecosystems so the demo
// surfaces live supply-chain advisories without needing a package list from the user.
const QUERIES = [
  { ecosystem: 'PyPI', name: 'django' },
  { ecosystem: 'npm', name: 'next' },
  { ecosystem: 'Go', name: 'github.com/gin-gonic/gin' },
  { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' },
];

// OSV returns severity as an array of {type, score} where `score` is a CVSS vector string,
// not a number. Passing it straight through is what put JSON blobs in the severity column.
function firstCvssVector(rec) {
  const entry = (rec.severity || []).find((s) => typeof s?.score === 'string' && s.score.startsWith('CVSS:'));
  return entry ? entry.score : null;
}

function flatten(rec, bucket) {
  const cve = (rec.aliases || []).find((a) => a.startsWith('CVE-'));
  return normalizedItem({
    external_id: rec.id,
    title: rec.summary || cve || rec.id,
    summary: rec.details || rec.summary || null,
    link: rec.references?.[0]?.url || (cve ? `https://osv.dev/vulnerability/${rec.id}` : null),
    published_at: rec.published || rec.modified || null,
    category: bucket,
    raw: rec,
    native: { cveIds: cve ? [cve] : [], cvssVector: firstCvssVector(rec) },
  });
}

async function fetch(source, ctx) {
  const bucket = categoryBucket(source.category);
  const out = [];
  const seen = new Set();
  for (const pkg of QUERIES) {
    let res;
    try {
      res = await ctx.request(source.url, { method: 'POST', timeoutMs: 20000, headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ package: pkg }) });
    } catch { continue; }
    if (res.status < 200 || res.status >= 300) continue;
    let body;
    try { body = JSON.parse(res.body); } catch { continue; }
    for (const rec of (body.vulns || []).slice(0, 15)) {
      if (seen.has(rec.id)) continue;
      seen.add(rec.id);
      out.push(flatten(rec, bucket));
    }
  }
  if (out.length === 0) throw new Error('OSV returned no records for the demo package set');
  return out;
}
module.exports = { fetch };
