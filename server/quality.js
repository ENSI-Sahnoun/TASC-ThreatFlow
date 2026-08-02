// Separates genuine threat intelligence from the podcast episodes, weekly digests, career
// interviews and product announcements that security RSS feeds carry alongside it. This is the
// "some sources report nonsense" complaint, for the part of it that is not deterministic.
//
// Nothing is ever deleted or hidden on the strength of a model verdict. item_quality is read
// only by the presentation layer, which demotes; a misclassification costs an item its ranking,
// never its existence. And per the usual rule, a failed call writes nothing at all.
//
// MEASURED CAPABILITY (2026-08-02, 11 held-out real headlines labelled by hand).
//
// mistral:7b-instruct-q3_K_S — 7/11 overall. The numbers that matter for a demote-only
// feature: 0 of 6 genuine intel items were demoted, 2 of 5 junk items were caught, and both
// items it flagged as junk really were junk. So it is CONSERVATIVE: it misses most noise but
// does not bury real intelligence. Do not present it as comprehensive filtering.
//
// EuroLLM-1.7B-Instruct — unusable. It answered "intel" for 100% of inputs across two
// structurally different prompts, including headlines quoted verbatim in its own prompt as
// counter-examples. A degenerate single-verdict run is worse than no data, because it looks
// like signal.
//
// Before trusting a run, check the returned `counts`: if one verdict holds essentially
// everything, the model is not classifying and the rows should be discarded rather than shown.
//
// A WARNING FOR ANYONE TUNING THIS PROMPT. Rewriting the flat category list into ordered
// "check for digest, then talk, then announcement, else intel" exclusion tests scored 6/8 on
// the eight cases it was designed against and 4/11 on held-out data — worse than this prompt,
// and barely above the 25% four-class chance line. The bias did not disappear, it moved from
// "always intel" to "always roundup". Measure any change on headlines you did not tune against.
const { judgeText, DEFAULT_MODEL } = require('./lm_client');

const VERDICTS = ['intel', 'roundup', 'commentary', 'promotion'];

// Only categories where the noise actually lives. A CVE, advisory, IOC or phishing row is
// structurally intel — spending inference on those would be pure waste.
const CLASSIFIED_CATEGORIES = ['news', 'osint'];

const CONCURRENCY = 2;

const SCHEMA = { verdict: { type: 'string', enum: VERDICTS } };

// Categories are described by example rather than defined abstractly: small models classify far
// more reliably against concrete instances than against definitions.
function buildPrompt(item) {
  return [
    'Classify a security article into exactly one category.',
    '',
    'intel      = a specific threat, breach, vulnerability, campaign or actor is reported',
    'roundup    = a digest or recap collecting several unrelated stories',
    'commentary = opinion, interview, career advice, conference talk or podcast episode',
    'promotion  = product launch, tool release, vendor announcement or marketing content',
    '',
    'Examples:',
    '"Scattered Spider hackers sentenced over £29 million theft" -> intel',
    '"Weekly Recap: Rogue AI Agents, Check Point Exploit, Slopsquatting" -> roundup',
    '"Former Citigroup CISO on What Makes A Great Security Leader" -> commentary',
    '"ISC Stormcast For Friday, July 17th" -> commentary',
    '"Wireshark 4.6.7 Released" -> promotion',
    '',
    `Now classify: "${item.title}"`,
    ...(item.summary ? [`Summary: "${String(item.summary).slice(0, 300)}"`] : []),
    '',
    'Answer with JSON only: {"verdict": "intel"}',
  ].join('\n');
}

async function classifyQuality(store, { judge = judgeText, model = DEFAULT_MODEL, concurrency = CONCURRENCY, limit = null } = {}) {
  const pending = await store.all(
    `SELECT i.id, i.title, i.summary
       FROM items i
      WHERE i.category = ANY($1)
        AND NOT EXISTS (SELECT 1 FROM item_quality q WHERE q.item_id = i.id)
      ORDER BY COALESCE(i.published_at, i.fetched_at) DESC
      ${limit ? 'LIMIT ' + Number(limit) : ''}`,
    [CLASSIFIED_CATEGORIES]);

  let written = 0;
  let failed = 0;
  let next = 0;
  const counts = Object.fromEntries(VERDICTS.map((v) => [v, 0]));

  async function worker() {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= pending.length) return;
      const item = pending[i];

      const result = await judge(buildPrompt(item), { schema: SCHEMA, model });
      // judgeText already rejects anything outside the enum, so a non-null result is a valid
      // verdict. Anything else writes nothing and is retried on the next run.
      if (!result) { failed += 1; continue; }

      await store.run(
        `INSERT INTO item_quality (item_id, verdict, model) VALUES ($1,$2,$3)
         ON CONFLICT (item_id) DO NOTHING`,
        [item.id, result.verdict, model]);
      counts[result.verdict] += 1;
      written += 1;
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, pending.length) || 1 }, worker));
  return { considered: pending.length, written, failed, counts };
}

module.exports = { classifyQuality, buildPrompt, VERDICTS, CLASSIFIED_CATEGORIES };
