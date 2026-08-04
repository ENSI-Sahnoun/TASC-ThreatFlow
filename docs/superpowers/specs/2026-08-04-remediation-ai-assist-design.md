# AI Assist — model-written explanation on the remediation page

Design, 2026-08-04. Spec C of three. Depends on
[`2026-08-04-remediation-foundation-design.md`](2026-08-04-remediation-foundation-design.md) (A)
for its facts and
[`2026-08-04-remediation-experience-design.md`](2026-08-04-remediation-experience-design.md) (B)
for its home.

## Problem

The guided page states facts precisely and tersely: `AV:L/PR:L/UI:N`, "before 10.0.26100.8875",
four playbook steps. A reader who is not a security engineer can follow each part and still not
hold the whole thing in their head. They want one paragraph that says what this is, and one that
says what they are about to do.

That is a wording problem, not a knowledge problem — which is the only kind of problem the local
model is allowed to solve in this codebase.

## Why this is the right use of the model, and where it is riskier than what came before

**Better shaped than any prior model feature here.** `relevance_prose`, `quality`, `story_links`
and the three `ml_enrich` jobs are all batch passes over thousands of rows, spending hours of
local inference on text most of which nobody opens. Assist is user-initiated, one item at a time,
on a page the reader is already reading. The user asked for it and is waiting for it. Cost is
bounded by attention.

**Riskier in one specific way.** `item_relevance_prose` is one sentence sitting beside a
deterministic verdict that is visible whether or not the model succeeded. Assist is three
paragraphs that a reader will treat *as the explanation*. It is the first time model output is the
primary content of a view in this product. Every guard below exists because of that difference.

The containment property is unchanged and non-negotiable: **`item_assist_ml` has no tier column,
no severity column, no version column, and no deterministic code reads it.** A fabricated
paragraph is a bad paragraph. It cannot move a verdict, change a status, or alter a fix target.

## Grounding: reorganize, never add

The prompt receives only what is already on the page:

- the item title and upstream summary
- the CVSS decomposition already rendered by Step 1 (`reach`, `impact`, `role`, `urgency` — the
  same `consequence` slots `relevance_prose.js` uses)
- the affected-version text, when there is one
- the playbook step titles and details, which are already deterministic English
- the fix target, as `fixTarget` returned it

The model may restate, order, and simplify. It may not contribute a fact. "Detail" means the
existing facts unpacked for a non-expert, not extra knowledge about the vulnerability class.

This is the deliberate rejection of the richer option. A 7B model asked what a use-after-free
generally does will answer fluently, and the guard cannot distinguish a correct general
explanation from an invented one. The measured precedent is in this repo: the Phase 4 NER
experiment put `APT28`/`APT37` on a CERT-FR advisory naming no actor, and `Emotet`/`WannaCry` on a
story naming no malware. Nothing about the prompt was unusual. The model simply supplied plausible
entities where it had none.

## `server/assist.js`

Structured exactly like `relevance_prose.js`, which is the module in this repo that works.

```js
const SCHEMA = {
  whatItDoes:     { type: 'string', maxLength: 600 },
  summary:        { type: 'string', maxLength: 240, optional: true },
  playbookGlance: { type: 'string', maxLength: 400, optional: true },
};
```

**Only `whatItDoes` is required.** `lm_client.js:77` rejects the *entire reply* when any field
exceeds `maxLength` — there is no truncation. A 7B model asked for a detailed explanation will
overshoot regularly, and an all-or-nothing schema turns a slightly-too-long third field into a
dead button. Marking the two secondary fields optional means an overlong or omitted one degrades
to absence while the core answer survives. `validate()` already treats an empty string on an
optional field as omission, which is the behaviour wanted.

Prompt construction follows the rules `relevance_prose.js` learned the hard way, and they are
repeated here because they are not obvious:

- **No literal values in the example.** The worked example uses a fictional product and generic
  clauses. The measured failure: an example ending "would let an attacker in without valid
  credentials" was pasted verbatim onto items with no such vector, and an example ending
  `{"sector":"healthcare","region":"Germany"}` produced German healthcare breaches for 12 of 18
  unrelated stories.
- **Facts as prose clauses, never as `key: value` pairs.** A small model shown key/value input
  copies the shape into its output.
- **The breach prohibition is enforced in code, not asked for in the prompt.** `isUsableSentence`'s
  `BREACH_CLAIM_RE` is reused directly and applied to every field. Asking a small model not to
  claim the reader was breached does not work; it produced "You're a victim of ransomware attacks"
  anyway.

### The new guard: `mentionsUnsuppliedFacts(text, facts)`

The codebase does not have this yet, and it is the guard that makes on-page-facts-only enforceable
rather than merely requested. It rejects output containing:

- a CVE id not present in the supplied facts
- a version-shaped token (two or more dot-separated numeric runs) not present in the supplied facts
- a vendor or product slug from the `item_cpes` vocabulary that was not supplied for this item

This is a mechanical fabrication check, and it catches precisely the two failures that would
matter most here: an invented upgrade target ("upgrade to 7.4.9") and an invented entity. It is
pure, it is cheap, and it has its own tests.

A rejected reply writes nothing and returns `null`. The UI shows that Assist is unavailable. It
never shows a partial or a repaired answer.

### Storage

```sql
CREATE TABLE IF NOT EXISTS item_assist_ml (
  profile_id      INT  NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  item_id         INT  NOT NULL REFERENCES items(id)    ON DELETE CASCADE,
  profile_version INT  NOT NULL,
  what_it_does    TEXT NOT NULL,
  summary         TEXT,
  playbook_glance TEXT,
  model           TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_id, item_id, profile_version)
);
```

Keyed on `profile_version` like `item_relevance_prose`, so the text regenerates when the facts
that produced it change — including when a recorded version changes the fix target — and is served
from cache on every re-read. The `_ml` suffix follows the naming already used for the three
contained tables and marks it as model output at the schema level.

## Route

`POST /api/items/:id/assist` — on demand, never on page load. Returns the cached row if one exists
at the current `profile_version`, otherwise generates, validates, stores and returns. Returns
`{ assist: null }` on any failure, which the UI renders as unavailable rather than as an error.

On-demand rather than pre-generated because generation is the expensive thing and most items are
never opened. See the latency question below, which may overturn this.

## Presentation

A panel on the guided page, collapsed by default, opened by an **AI Assist** control. Labelled as
model-written using the existing `isModelWritten` idiom from the impact panel — the same tag, the
same wording, no new vocabulary for "an AI wrote this".

It sits **below** Step 1's diagram and facts, never above them. The deterministic content is the
page; Assist is a reading aid over it. A reader who never opens it loses nothing, and a reader
whose Ollama is down sees a page that is complete without it.

## Measurement — and the gate

**This ships disabled.** CLAUDE.md's rule is explicit and this feature is the one most exposed to
it: measure on data you did not tune against, and do not assume a newer model inherits a result.
The repo's own history is the argument — rewriting the quality prompt scored 6/8 on its own cases
and 4/11 held out.

An eval harness in the shape of `quality.eval.js` / `quality.eval.json`: hand-labelled real items,
split into a tuning set and a held-out set that is not looked at while the prompt is being written.

Two bars, stated before measuring so they cannot be moved afterwards:

1. **Zero unsupplied-fact leaks on the held-out set.** Not "few". A single invented version number
   in an upgrade instruction is the failure this whole feature must not produce, and it is exactly
   what a reader would act on. This bar is absolute.
2. **A majority of held-out items produce usable prose** — accurate to the supplied facts, readable
   by a non-expert, no scaffolding echo. `quality.js` shipped at 7/11 held out; that is the
   reference point for what "usable at this model size" means.

Failing bar 1 means the feature does not ship, regardless of how good the prose is. Failing bar 2
means it does not ship yet.

### The latency question, which is open

Unmeasured and material: `mistral:7b-instruct-q3_K_S` producing ~1,000 characters on one box, with
a reader watching. If that is 30 seconds, an on-demand button is a poor experience no matter how
good the output.

**Measure this before the UI is built around it.** If it is slow, the honest response is not a
nicer spinner — it is background pre-generation for the queue's `act_now`/`watch` items, the way
`relevance_prose` already runs fire-and-forget after a profile save, with the panel showing
"not ready yet" rather than a spinner that lies about how long it will take. That changes the
route from generate-on-demand to read-cache-or-report-pending, and it is a small change if it is
made before the panel is designed and an ugly one afterwards.

## Testing

- `assist.test.js`: schema rejection on an overlong required field; an overlong *optional* field
  degrading to absence rather than failing the reply; `null` from `judgeText` writing nothing;
  cache hit at the same `profile_version`; regeneration after a bump.
- `mentionsUnsuppliedFacts`: an invented CVE id; an invented version; a vendor slug not supplied;
  and — the case that matters most — every one of those *present* in the supplied facts passing
  cleanly, so the guard does not reject correct restatement.
- `BREACH_CLAIM_RE` applied to all three fields, reusing the existing regex rather than a second
  copy that can drift.
- `assist.eval.js` + `assist.eval.json`, run manually against a real Ollama, reporting both bars.

## Non-goals

- **No general vulnerability-class explanation.** Considered and rejected above.
- **No chat, no follow-up questions.** One generation, three fields, cached. A conversational
  surface is a different feature with a different threat model.
- **No influence on anything deterministic.** Assist cannot change a tier, a severity, a status, a
  fix target or a playbook step. This is enforced structurally by the table's shape, not by
  convention.
- **No streaming.** `lm_client.js` uses non-streaming `/api/generate` with JSON mode, and
  schema validation needs the whole reply. If latency forces a change, the answer is
  pre-generation, not a second transport.
