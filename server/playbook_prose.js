// Rewords each playbook step's `detail` for readability. Mirrors relevance_prose.js exactly,
// including its safety posture: the model rewords, it never decides. The skeleton (which steps
// exist, their key/title/source/link) is written by playbook.js's pure builder before any model
// runs, so a rejected or failed rewording just leaves the template detail in place.
const { judgeText, DEFAULT_MODEL } = require('./lm_client');
const { getProfile } = require('./profiles');
const { BREACH_CLAIM_RE } = require('./relevance_prose');

const CONCURRENCY = 2;
const SCHEMA = { detail: { type: 'string', maxLength: 200 } };

// A URL, a CVE id, or a bare version number. The model must not manufacture a fix location that
// was not already in the template — isUsableDetail only rejects a match here when the exact
// matched text is absent from the ORIGINAL detail, so a version/link/CVE the template already
// stated is free to survive a rewording.
const INVENTED_LINK_RE = /https?:\/\/\S+|CVE-\d{4}-\d{4,}|\b\d+\.\d+(?:\.\d+)?\b/gi;

function buildStepPrompt(item, step) {
  return [
    'Task: reword one remediation step for a non-expert reader, in plain language.',
    '',
    'Example',
    'Title: "Limit who can reach it"',
    'Original: "Allow connections to your VPN and firewall only from addresses you control."',
    'Answer: {"detail": "Only let trusted IP addresses connect to your VPN and firewall."}',
    '',
    'Now do the same for this one.',
    `Item: "${item.title}"`,
    `Step title: "${step.title}"`,
    `Original: "${step.detail}"`,
    'Rules: at most 30 words, keep every fact from the original, invent no URL, CVE id or',
    'version number that is not already in the original, and never mention this task, JSON, or',
    'the word "step".',
    'Never state or imply that the reader has already been attacked, breached or compromised.',
    'Answer:',
  ].join('\n');
}

function inventedToken(original, reworded) {
  const originalTokens = new Set(original.match(INVENTED_LINK_RE) || []);
  const rewordedTokens = reworded.match(INVENTED_LINK_RE) || [];
  return rewordedTokens.some((t) => !originalTokens.has(t));
}

function isUsableDetail(original, reworded) {
  if (typeof reworded !== 'string' || reworded.trim().length < 10) return false;
  if (BREACH_CLAIM_RE.test(reworded)) return false;
  if (inventedToken(original, reworded)) return false;
  return true;
}

async function generatePlaybookProse(store, profileId, { judge = judgeText, model = DEFAULT_MODEL, concurrency = CONCURRENCY } = {}) {
  const profile = await getProfile(store, profileId);
  if (!profile) return null;

  const pending = await store.all(
    `SELECT pb.item_id, pb.steps, i.title
       FROM item_playbooks pb
       JOIN items i ON i.id = pb.item_id
      WHERE pb.profile_id = $1 AND pb.profile_version = $2 AND pb.worded_by IS NULL`,
    [profile.id, profile.profile_version]);

  let written = 0;
  let failed = 0;
  let next = 0;

  async function worker() {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= pending.length) return;
      const row = pending[i];
      const steps = row.steps.map((s) => ({ ...s }));
      let changed = false;

      for (const step of steps) {
        const result = await judge(buildStepPrompt({ title: row.title }, step), { schema: SCHEMA, model });
        if (!result || !isUsableDetail(step.detail, result.detail)) { failed += 1; continue; }
        step.detail = result.detail;
        changed = true;
      }

      // All-or-nothing per item, same as relevance_prose: a fully-failed row writes nothing
      // and is picked up again by the next run, since the WHERE worded_by IS NULL clause still
      // returns it.
      if (!changed) continue;
      await store.run(
        `UPDATE item_playbooks SET steps = $1, worded_by = $2
          WHERE profile_id = $3 AND item_id = $4 AND profile_version = $5`,
        [JSON.stringify(steps), model, profile.id, row.item_id, profile.profile_version]);
      written += 1;
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, pending.length) || 1 }, worker));
  return { considered: pending.length, written, failed };
}

module.exports = { generatePlaybookProse, buildStepPrompt, isUsableDetail, INVENTED_LINK_RE };
