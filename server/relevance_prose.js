// Turns a deterministic verdict into a sentence a non-expert can act on.
//
// The model rewords an explanation; it does not produce one. The tier and the reasons were
// already decided by server/relevance_score.js, and this module writes to item_relevance_prose,
// which has no tier column — so a bad model output is *structurally* incapable of promoting an
// item. Ollama being unreachable costs nothing but nicer phrasing: the chip still shows its
// tier and the templated sentence.
const { judgeText, DEFAULT_MODEL } = require('./lm_client');
const { getProfile } = require('./profiles');

// Only tiers a user will actually read. Writing prose for 15k 'low' rows would spend hours of
// local inference on text nobody opens.
const PROSE_TIERS = ['act_now', 'watch'];

// LM calls are slow and serial-ish on a small local model; a low cap keeps a batch from
// saturating the machine while still overlapping request latency.
const CONCURRENCY = 2;

const SCHEMA = { sentence: { type: 'string', maxLength: 220 } };

// Reasons are rendered as prose, not as `kind: value` pairs. A 1.7B model shown key/value input
// copies it straight into the output — the first version of this prompt reliably produced
// {"domain":...,"severity":...} instead of {"sentence":...}, which validation then rejected.
const MATCH_PHRASES = {
  product: (v) => `they run ${v}`,
  vendor: (v) => `they use software from ${v}`,
  domain: (v) => `they follow ${v} threats`,
  kev: () => 'it is already being exploited in the wild',
  sector: (v) => `it was reported against the ${v} sector`,
  severity: (v) => `its severity is ${v}`,
};

function describeMatches(matches) {
  const parts = (matches || [])
    .map((m) => (MATCH_PHRASES[m.kind] ? MATCH_PHRASES[m.kind](m.value) : null))
    .filter(Boolean);
  if (!parts.length) return 'it is generally relevant';
  if (parts.length === 1) return parts[0];
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

// Output template goes last and is shown literally. Small models follow a concrete example far
// more reliably than a described contract.
// One worked example, then the real task. At 1.7B this is the difference between usable prose
// and the model narrating the instructions back: without the example, roughly 3 in 5 replies
// echoed scaffolding ("This security report is relevant to a reader in the finance sector…")
// and were rejected by isUsableSentence.
function buildPrompt(profile, item) {
  return [
    'Task: explain to a reader why a security issue matters to them, in one sentence.',
    '',
    'Example',
    'Title: "Acme VPN authentication bypass"',
    'Facts: they run acme vpn and its severity is critical.',
    // The example's own clause must be generic. An earlier version ended "…would let an attacker
    // in without valid credentials", and the model copied that exact phrase onto unrelated items
    // — inventing an attack vector the facts never mentioned.
    'Answer: {"sentence": "You run Acme VPN, so this critical flaw is directly exposed in your environment."}',
    '',
    'Now do the same for this one.',
    `Reader works in the ${profile.sector} sector.`,
    `Title: "${item.title}"`,
    `Facts: ${describeMatches(item.matches)}.`,
    'Rules: at most 30 words, address the reader as "you", use only the facts given, invent',
    'nothing, and never mention this task, the facts list, or the word "report".',
    // Without this the model volunteers things like "You are a victim of ransomware attacks and
    // the attackers have leaked your customer data" — a breach claim invented from a headline
    // about someone else. In a threat dashboard that is the single most damaging thing it could
    // get wrong, and no output filter can detect it after the fact.
    'Never state or imply that the reader has already been attacked, breached or compromised.',
    'Describe only what the issue could do, not what has happened to them.',
    'Answer:',
  ].join('\n');
}

// The model occasionally echoes prompt scaffolding back inside an otherwise valid sentence.
// That is a wrong answer wearing the right shape, so it is rejected like any other bad output
// rather than shown to a user.
const SCAFFOLD_RE = /security (report|headline)|^\s*\{|your one sentence|relevant to a reader|json/i;

// Falsely telling a user they have already been breached is the most damaging thing this
// feature could do. Asking the model not to does not work — a 1.7B model does not reliably obey
// a negative constraint, and it kept producing "You're a victim of ransomware attacks" from a
// headline about somebody else entirely. So the rule is enforced here, deterministically, where
// compliance is not optional. A rejected sentence simply falls back to the templated one.
const BREACH_CLAIM_RE = new RegExp([
  "you(?:'re| are) (?:a )?(?:victim|target)",
  'you (?:have|ve) been (?:breached|compromised|attacked|hacked|infected)',
  'your (?:data|systems?|network|customers?) (?:has|have) been',
  'attackers? (?:have|has) (?:leaked|stolen|accessed) your',
  'this breach of your',
].join('|'), 'i');

function isUsableSentence(s) {
  if (typeof s !== 'string' || s.length < 20) return false;
  if (SCAFFOLD_RE.test(s)) return false;
  if (BREACH_CLAIM_RE.test(s)) return false;
  return true;
}

async function generateProse(store, profileId, { judge = judgeText, model = DEFAULT_MODEL, concurrency = CONCURRENCY } = {}) {
  const profile = await getProfile(store, profileId);
  if (!profile) return null;

  // Only rows that need a sentence: a prominent tier, at the current version, with none written.
  const pending = await store.all(
    `SELECT ir.item_id, ir.tier, ir.matches, i.title
       FROM item_relevance ir
       JOIN items i ON i.id = ir.item_id
      WHERE ir.profile_id = $1
        AND ir.profile_version = $2
        AND ir.tier = ANY($3)
        AND NOT EXISTS (
          SELECT 1 FROM item_relevance_prose p
           WHERE p.profile_id = ir.profile_id AND p.item_id = ir.item_id
             AND p.profile_version = ir.profile_version
        )
      ORDER BY ir.score DESC`,
    [profile.id, profile.profile_version, PROSE_TIERS]);

  let written = 0;
  let failed = 0;
  let next = 0;

  async function worker() {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= pending.length) return;
      const row = pending[i];

      const result = await judge(buildPrompt(profile, row), { schema: SCHEMA, model });
      // Absence over fabrication: a failed, malformed or scaffolding-echoing call writes
      // nothing and is simply picked up again by the next run, since the NOT EXISTS query
      // still returns it.
      if (!result || !isUsableSentence(result.sentence)) { failed += 1; continue; }

      await store.run(
        `INSERT INTO item_relevance_prose (profile_id, item_id, profile_version, sentence, model)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (profile_id, item_id, profile_version) DO NOTHING`,
        [profile.id, row.item_id, profile.profile_version, result.sentence, model]);
      written += 1;
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, pending.length) || 1 }, worker));
  return { considered: pending.length, written, failed };
}

module.exports = { generateProse, buildPrompt, isUsableSentence, PROSE_TIERS };
