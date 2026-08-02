// The three remaining model-derived enrichment jobs: severity for prose sources, summaries for
// items whose upstream description is genuinely empty, and victim sector/region extraction.
//
// They share one batch runner rather than three copies of the same loop. Each job supplies a
// query for its pending rows, a prompt, a response schema, and a writer.
//
// Rules that apply to all three, and that the deterministic pipeline depends on:
//
//  - Output lands in its own `_ml` table. Nothing in scoring, consolidation, confidence or
//    clustering reads them, so a wrong guess cannot contaminate vendor-supplied data.
//  - A failed or malformed call writes nothing and is retried on the next run.
//  - A row's existence means "checked". Its columns may be NULL, meaning "checked and found
//    nothing" — which is a real answer and stops the item being re-processed forever.
//
// ============================================================================
// STATUS: NONE OF THESE THREE JOBS IS ENABLED IN PRODUCTION.
// ============================================================================
// All three were measured against the live corpus on 2026-08-02 using
// mistral:7b-instruct-q3_K_S. All three produce more noise than signal at this model size, so
// the code ships wired-up and tested but is not run, and no route triggers it. Re-measure
// before enabling any of them; do not assume a newer model fixes it.
//
//   severity  Skews hard to one class: over 20 items, 15 "high", 2 medium, 2 low, 1 critical.
//             It rated an opinion column ("The Morning After We Pull a Root of Trust") as high.
//             It discriminates, unlike EuroLLM, but not well enough to attach a rating to.
//
//   summary   Mostly restates the title back ("Title: USN-8620-3: Linux kernel (Intel IoTG)
//             vulnerabilities") which is not a summary, and fabricates when the title is thin:
//             it produced "The Saturday Evening Post is a security item in the Other sector of
//             the US", inventing both sector and country. Roughly 3 of 10 outputs were useful.
//
//   victim    The most dangerous of the three, because its failure mode is precisely the one
//             CLAUDE.md forbids. From 40 items it made 3 extractions, one of which read
//             "Researchers Report 84 Flaws in 4G and 5G Cores" as telecom/Singapore — Singapore
//             being where the *researchers* are. Only 1 of 3 was correct. It does correctly
//             decline on the majority (20 of 40 returned no victim), which is the safe answer,
//             but a job that is right once per forty items is not worth the inference.
//
// What this exercise DID validate is the containment architecture: every fabrication above was
// confined to an `_ml` table and never reached items.severity, items.industry or items.summary.
// The guards worked; the model did not.
const { judgeText, DEFAULT_MODEL } = require('./lm_client');
const { SEVERITIES } = require('./cvss');
const { SECTORS } = require('./sector_profiles');

const CONCURRENCY = 3;

// 'unknown' is excluded on purpose: if the model cannot tell, the right output is no severity
// at all, not a severity literally named "unknown" that a filter would treat as a rating.
const ML_SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SECTOR_SLUGS = SECTORS.map((s) => s.slug);

// ---------------------------------------------------------------------------
// Job 1 — severity for prose sources
// ---------------------------------------------------------------------------
// Only news/advisory/osint prose. NVD and MSRC rows with a NULL severity are not prose: they
// are CVEs upstream has not finished analysing, and inventing a rating for those would be
// contradicting a source that is deliberately silent.
const severityJob = {
  name: 'severity',
  table: 'item_severity_ml',
  pendingSql: `
    SELECT i.id, i.title, i.summary
      FROM items i
     WHERE i.category IN ('news', 'advisory', 'osint')
       AND i.severity IS NULL
       AND NOT EXISTS (SELECT 1 FROM item_severity_ml m WHERE m.item_id = i.id)
     ORDER BY COALESCE(i.published_at, i.fetched_at) DESC`,
  schema: { severity: { type: 'string', enum: ML_SEVERITIES, optional: true } },
  prompt: (item) => [
    'Rate how severe the security issue described below is.',
    '',
    'critical = mass exploitation, full system compromise, or a major breach already happening',
    'high     = serious exploitable flaw or a confirmed targeted attack',
    'medium   = a real but limited issue, or an attack needing significant preconditions',
    'low      = minor issue, research finding, or no direct attack described',
    '',
    `Title: "${item.title}"`,
    ...(item.summary ? [`Summary: "${String(item.summary).slice(0, 500)}"`] : []),
    '',
    'If the text does not describe a security issue at all, omit the field.',
    'Answer with JSON only: {"severity":"high"}',
  ].join('\n'),
  write: async (store, item, result, model) => store.run(
    'INSERT INTO item_severity_ml (item_id, severity, model) VALUES ($1,$2,$3) ON CONFLICT (item_id) DO NOTHING',
    [item.id, result.severity || null, model]),
};

// ---------------------------------------------------------------------------
// Job 2 — summaries where upstream genuinely supplied none
// ---------------------------------------------------------------------------
// The measured target is the ~400 Microsoft MSRC Azure Linux CVEs whose CVRF Description note
// is present but empty, plus other rows with nothing usable. Bulk indicator feeds are excluded:
// they already get a deterministic template from present.js and prose would add nothing.
const summaryJob = {
  name: 'summary',
  table: 'item_summary_ml',
  // The title must actually say something. A bare identifier — "CVE-2026-14920",
  // "EUVD-2026-51920" — carries nothing to summarise, and the model fills the vacuum by
  // inventing: it returned "CVE-2026-14920 is a security vulnerability in the Apache HTTP
  // Server" for an id it had never seen. 74 of 864 thin rows are bare ids; the other 790,
  // including the MSRC Azure Linux CVEs this job exists for, have descriptive titles.
  pendingSql: `
    SELECT i.id, i.title, i.summary
      FROM items i
     WHERE i.category NOT IN ('phishing', 'ioc')
       AND (i.summary IS NULL OR length(i.summary) < 40)
       AND i.title ~ ' '
       AND length(i.title) >= 25
       AND NOT EXISTS (SELECT 1 FROM item_summary_ml m WHERE m.item_id = i.id)
     ORDER BY COALESCE(i.published_at, i.fetched_at) DESC`,
  schema: { summary: { type: 'string', maxLength: 300, optional: true } },
  prompt: (item) => [
    'Write a one-sentence factual summary of this security item, at most 25 words.',
    '',
    `Title: "${item.title}"`,
    ...(item.summary ? [`Existing partial text: "${String(item.summary).slice(0, 200)}"`] : []),
    '',
    'Describe only what the title states. Do not invent affected versions, severities, CVE',
    'numbers, attackers or impacts that are not named above. If the title is too vague to',
    'summarise, omit the field rather than guessing.',
    '',
    'Answer with JSON only: {"summary":"..."}',
  ].join('\n'),
  write: async (store, item, result, model) => store.run(
    'INSERT INTO item_summary_ml (item_id, summary, model) VALUES ($1,$2,$3) ON CONFLICT (item_id) DO NOTHING',
    [item.id, result.summary || null, model]),
};

// ---------------------------------------------------------------------------
// Job 3 — victim sector and region
// ---------------------------------------------------------------------------
// The riskiest of the three. CLAUDE.md forbids inferring victim geography from an advisory
// issuer's country — CERT-FR publishing something says nothing about France being attacked —
// so the prompt demands a named victim and the job writes NULL rather than a guess.
const victimJob = {
  name: 'victim',
  table: 'item_victim_ml',
  // Requires actual narrative text. Without the length guard this swept in breach-dump records
  // whose entire title is a handle — "2fast4u", "AcneOrg", "123RF" — and the model duly
  // invented answers for them ("sector": "acne.org", "sector": {}). Those were caught by schema
  // validation rather than stored, but asking a question that cannot be answered from the input
  // is just spending inference to be rejected.
  pendingSql: `
    SELECT i.id, i.title, i.summary
      FROM items i
     WHERE i.category IN ('news', 'ransomware', 'data-breach')
       AND i.industry IS NULL
       AND length(COALESCE(i.summary, '')) >= 80
       AND NOT EXISTS (SELECT 1 FROM item_victim_ml m WHERE m.item_id = i.id)
     ORDER BY COALESCE(i.published_at, i.fetched_at) DESC`,
  // "country", not "region": asked for a region the model returned a `country` key anyway and
  // every answer was discarded for missing the field it was never going to emit. Matching the
  // model's natural vocabulary is cheaper than fighting it; the column is still `region`.
  schema: {
    sector: { type: 'string', enum: SECTOR_SLUGS, optional: true },
    country: { type: 'string', maxLength: 60, optional: true },
  },
  // The example JSON deliberately shows the EMPTY answer and no concrete sector or region.
  // An earlier version ended with {"sector":"healthcare","region":"Germany"} as the sample, and
  // the model copied those two values onto 12 of 18 unrelated stories — "Ruby on Rails Patches
  // Critical Vulnerability" came back as a German healthcare breach. Any literal value in the
  // example gets reproduced as fact, so there are none.
  prompt: (item) => [
    'Most security stories do not name a victim organisation. Your default answer is {}.',
    '',
    `Title: "${item.title}"`,
    ...(item.summary ? [`Summary: "${String(item.summary).slice(0, 400)}"`] : []),
    '',
    'Question: does this text name a specific organisation that was ATTACKED?',
    '',
    'Answer {} if:',
    '- it describes a vulnerability, patch, tool or research finding with no named target',
    '- it reports an advisory, guidance or warning from an agency or vendor',
    '- it is industry news, funding, opinion or a roundup',
    '- the only organisations named are the reporter, researcher, vendor or agency',
    '',
    'Only if a specific attacked organisation IS named, return its sector as one of:',
    SECTOR_SLUGS.join(', '),
    'and its country only if the text states it. Never infer a country from who published',
    'the story — a French agency reporting an attack does not make the victim French.',
    '',
    'Reply with JSON only, using the keys "sector" and "country". Use {} when in any doubt.',
  ].join('\n'),
  write: async (store, item, result, model) => store.run(
    'INSERT INTO item_victim_ml (item_id, sector, region, model) VALUES ($1,$2,$3,$4) ON CONFLICT (item_id) DO NOTHING',
    [item.id, result.sector || null, result.country || null, model]),
};

const JOBS = { severity: severityJob, summary: summaryJob, victim: victimJob };

async function runJob(store, jobName, { judge = judgeText, model = DEFAULT_MODEL, concurrency = CONCURRENCY, limit = null } = {}) {
  const job = JOBS[jobName];
  if (!job) throw new Error(`unknown job: ${jobName}`);

  const pending = await store.all(job.pendingSql + (limit ? ` LIMIT ${Number(limit)}` : ''));

  let written = 0;
  let empty = 0;
  let failed = 0;
  let next = 0;

  async function worker() {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= pending.length) return;
      const item = pending[i];

      const result = await judge(job.prompt(item), { schema: job.schema, model });
      if (!result) { failed += 1; continue; }

      await job.write(store, item, result, model);
      // A row with every column null is a real answer — "checked, nothing found" — and is
      // counted separately so a run that finds nothing is distinguishable from one that failed.
      if (Object.values(result).every((v) => v == null || v === '')) empty += 1;
      written += 1;
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, pending.length) || 1 }, worker));
  return { job: jobName, considered: pending.length, written, empty, failed };
}

module.exports = { runJob, JOBS, ML_SEVERITIES, SECTOR_SLUGS, SEVERITIES };
