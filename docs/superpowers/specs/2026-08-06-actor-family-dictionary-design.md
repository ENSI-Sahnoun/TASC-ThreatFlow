# Growing the actor/family dictionary from real ATT&CK data

Design, 2026-08-06. Follow-up to
[`2026-08-06-attack-mitigation-ingestion-design.md`](2026-08-06-attack-mitigation-ingestion-design.md)
(Spec A), which explicitly deferred this:

> **Growing `data/threat-actors.json` / `data/malware-families.json` from the same STIX bundle.**
> Real fix for the same staleness problem... but this dictionary also drives `enrich.js`'s live
> ingest-time matching... Growing it 10→100s of names needs its own design pass for
> match-precision and ingest-time performance, not a drive-by expansion here. Separate spec.

## Problem

`data/threat-actors.json` / `data/malware-families.json` are hand-typed, 10 entries each. They are
the dictionary `enrich.js:matchDictionary` scans against every synced item's title+summary to
populate `item_actors`/`item_malware_families`. A name absent from these files is invisible to the
whole pipeline — corroboration, confidence scoring, the ransomware/malware playbooks' ATT&CK step
(Spec A) — no matter how well-documented that actor or family is in MITRE's own data.

## Real risk this isn't a drive-by fix for

`matchDictionary` does raw substring `.includes()`, not word-boundary matching (`enrich.js:38-46`).
Safe today because all 20 entries are distinctive strings. ATT&CK's full catalogue is not: its
`software` objects include living-off-the-land tool names — `at`, `cmd`, `reg`, `sc`, `wmic`,
`certutil`, `netsh` — and group/malware names that double as ordinary English words (`Empire`).
Naively expanding the dictionary to ATT&CK's ~150 groups + ~700 software entries without fixing
the matching mechanism first would substring-match those into unrelated text on nearly every item
— the same corroboration-poisoning failure CLAUDE.md's NER postmortem describes, produced by string
matching instead of a model.

## Architecture

Shares the STIX fetch with Spec A rather than duplicating it — factor the fetch/parse/revoked-
filter logic Spec A's `backfill-attack.js` already needs into a shared module:

```
server/
  attack_stix.js              -- shared: fetchStixBundle(), objectsByType(bundle, type, {excludeRevoked: true})
  backfill-attack.js          -- Spec A, now imports attack_stix.js instead of its own fetch
  backfill-actor-dictionary.js -- this spec: regenerates data/threat-actors.json + malware-families.json
  backfill-actor-dictionary.test.js
```

`backfill-actor-dictionary.js` is a one-off script, same idiom as the others (`--dry-run` to
preview, bare invocation writes). Unlike Spec A's DB table, output stays a **static JSON file** —
deliberately, because `enrich.js:matchDictionary` runs synchronously in the per-item ingest hot
path with no DB round trip today, and that's correct: nothing here needs per-item freshness, only
periodic (rerun manually, same cadence rationale as Spec A — ATT&CK updates ~2x/year).

### Selection filter

For every non-revoked `intrusion-set`/`malware`/`tool` STIX object:

1. Exclude if `revoked: true` or `x_mitre_deprecated: true` (same rule as Spec A).
2. Exclude if the primary name is under 5 characters — cuts every LOTL-tool false-positive
   (`at`, `cmd`, `reg`, `sc`) at the source.
3. Exclude if the name appears in a hand-maintained `AMBIGUOUS_NAMES` exclusion list in the script
   — for names that survive the length filter but are still ordinary words or generic terms
   (`Empire` is the seed case; the list grows as real matches surface false positives).
4. Everything else becomes `{ name, aliases }`, same shape the hand file already uses — aliases
   filtered by the same length + exclusion rules independently (an alias can be excluded while its
   parent name survives, and vice versa).

### Matching mechanism upgrade

`enrich.js:matchDictionary` changes from substring `.includes()` to word-boundary regex:

```js
// before: names.some((n) => s.includes(n.toLowerCase()))
// after:
function nameRegex(name) {
  return new RegExp(`\\b${name.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
}
// built once per dictionary entry at module load, same place ACTORS/FAMILIES are read today
names.some((re) => re.test(s))
```

This is a real bug fix independent of the dictionary size — applies to today's 10+10 the same way,
just currently invisible because none of those 20 names happen to be substrings of common words.
Verified against the existing fixture set in `enrich.test.js` before this ships: every current
dictionary-hit test must still pass unchanged (word-boundary is strictly narrower than substring,
so a regression here means today's file has a name that only matched *because* of the substring
bug — worth knowing either way).

## Failure modes

| Condition | Behaviour |
|---|---|
| STIX fetch fails | Script exits non-zero, existing `data/*.json` files untouched — same all-or-nothing posture as Spec A |
| A name matches nothing in ATT&CK (genuinely untracked) | Simply absent from the regenerated file, same as today's manual-omission case |
| A name survives the filter but still produces false-positive matches once live | Add it to `AMBIGUOUS_NAMES`, rerun the script — this is the intended maintenance loop, not a bug each time it happens |
| `matchDictionary`'s word-boundary change causes an existing test to fail | Signals today's hand file relied on the substring bug for that entry — fix the entry's name/alias, not the regex |

## Testing

- `backfill-actor-dictionary.test.js`: fixture STIX bundle (revoked object, short name, a name on
  the exclusion list, and 2-3 legitimate entries) → asserts exactly the legitimate entries survive,
  in `{name, aliases}` shape.
- `enrich.test.js`: add explicit non-match cases proving word-boundary rejects `cmd` inside
  `command`, `at` inside `attack`, while still matching each as a standalone word; every existing
  hit/no-hit case in the current suite must still pass.
- Manual measurement, not assumed: run `matchDictionary` timing over a real sync batch before/after
  the dictionary grows from 20→~500+ entries, following this codebase's "measured, not estimated"
  convention (CLAUDE.md's NVD throughput numbers are the precedent). If it's not negligible, that's
  a follow-up, not a blocker to shipping this spec — `enrich.js` runs once per item at ingest time,
  not on a request path a user waits on.

## Out of scope

- **Matching-performance optimization beyond the regex fix** (e.g. Aho-Corasick/trie for large
  dictionaries) — only pursued if the measurement above shows it's actually needed.
- **`server/confidence.js` corroboration scoring changes.** This spec changes what entities *can*
  be matched, not how a match affects confidence — that formula is untouched.
- **Spec A's `attack_mitigations` table.** Independent output of the same shared `attack_stix.js`
  fetch; this spec only touches the actor/family dictionary files.
