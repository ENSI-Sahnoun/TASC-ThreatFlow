# Category playbooks — extending "now what do I do?" past CVEs

Design, 2026-08-05. Extends
[`2026-08-03-remediation-playbooks-design.md`](2026-08-03-remediation-playbooks-design.md) (Spec B),
which shipped CVE-only playbooks and explicitly deferred this:

> **Threat-domain standing playbooks** ("your ransomware posture"). A separate feature with a
> different unit and a different data source... Revisit after this ships.

This is that revisit.

## Problem

`server/playbook.js` only produces steps for items that carry a CVE. Every other category —
ransomware, phishing, malware, data-breach, raw IOC feeds — ends at the item detail page with no
next action, the same gap Spec B closed for CVEs.

## Inspiration, and where it doesn't transfer

Mined [msraju/Incident-Response-Playbooks](https://github.com/msraju/Incident-Response-Playbooks)
(NIST SP 800-61 r2 structured IR playbooks: Phishing, Ransom, Malware, AccountCompromised,
DataLoss). Its category taxonomy maps cleanly onto ThreatFlow's `categoryBucket` (ransomware,
phishing, malware, data-breach, ioc).

Its *content* assumes an active incident responder with tooling ThreatFlow does not have: EDR
install/quarantine, AD forest state (krbtgt double-reset), device seizure, SIEM correlation.
ThreatFlow has no EDR/SIEM integration — it has intel items and a profile's declared assets. Most
items describe something happening to *someone else* (a ransomware group hit another company, a
new malware family got named), not an active incident on the reader's own network.

**Resolution:** keep the repo's step logic and ordering, reword every step as an instruction the
non-expert owner performs or hands to their IT/security provider — the same voice Spec B already
uses ("Limit who can reach it" rather than a raw ACL rule). Drop any step that assumes visibility
ThreatFlow doesn't have (EDR install check, AD forest state, device seizure). This mirrors Spec
B's core rule: a step with no traceable source is a step that was invented, and inventing
capability the product doesn't have is the same failure as inventing a fact.

## Architecture

New `server/playbooks/` directory, one pure module per category, same shape as the existing
`server/playbook.js` (no I/O, no model, guard → step, mandatory `source`):

```
server/playbooks/
  ransomware.js
  phishing.js
  malware.js
  data-breach.js
  ioc.js
  attack-mitigations.js   -- shared lookup helper, used by several of the above
  index.js                -- dispatches on item.category
```

`server/playbook.js` (CVE builder) is unchanged and keeps handling any item that carries a CVE,
regardless of category — this is the existing gate ("Item is not a CVE at all → no playbook"),
untouched. The new dispatcher in `playbooks/index.js` only runs for items with no CVE, routing on
`item.category`.

### Data model

No new tables. Reuses `item_playbooks` / `playbook_step_state` exactly as Spec B defined them.
`step_key` is namespaced per category (`ransomware:confirm`, `phishing:block-iocs`,
`malware:isolate-if-found`, ...) so the stable-tick-identity guarantee still holds and keys from
different category modules can never collide.

### ATT&CK mitigation lookup

New static file `data/attack-mitigations.json`, curated by hand, keyed to names that already
exist in `data/threat-actors.json` / `data/malware-families.json` (10 + 10 entries today) — not a
full MITRE ATT&CK ingestion. Example:

```json
{
  "LockBit": [{ "id": "M1053", "name": "Data Backup", "url": "https://attack.mitre.org/mitigations/M1053/" }]
}
```

`attack-mitigations.js` exports `attackStep(name)`, returning `null` for anything not in the
curated map — no fuzzy matching, no partial name match, no invented mitigation. Consumed by the
ransomware, malware, and ioc modules wherever a matched actor/family is present.

## Facts each module receives

Only fields that exist today, passed in the same shape `playbook.js` already receives its inputs:

| Fact | Source |
|---|---|
| `iocs` | `item_iocs` (type + value) |
| `actors` | `item_actors` |
| `families` | `item_malware_families` |
| `region` / `industry` | sparse — ransomware.live and `ip_intel` only |
| `exposure` | profile asset, same field the CVE playbook already uses |
| `victim`, `confidence` | ransomware.live rows only, for the ransomware module |
| `raw_json` fields already ingested | data-breach module (no re-fetch, no new parsing) |

## Step catalogues

Every step below carries a mandatory `source`; a step whose guard is false is simply absent —
never rendered as a hedge.

### `ransomware.js`

| key | Guard | Detail | Source |
|---|---|---|---|
| `confirm` | always | "Check whether **[victim]** is your organization or a vendor/partner you depend on" | ransomware.live victim record |
| `attack-mitigation` | actor matched in curated map | mitigation tip for the named group | `data/attack-mitigations.json` |
| `block-iocs` | `iocs.length > 0` | "Give your IT/security provider these to block: [list]" | `item_iocs` |
| `protect-backups` | always | "If this is your organization — disconnect your backups from the network right now and make a separate offline copy before doing anything else" | repo IRP-Ransom, reworded |
| `reset-credentials` | always | "Reset passwords and keys for accounts that may have been reached" | repo IRP-Ransom, reworded |
| `payment-decision` | always | "Whether to pay a ransom is a decision for leadership/your board, not IT alone — check your insurance coverage first" | repo IRP-Ransom, quoted and reworded |

### `phishing.js`

| key | Guard | Detail | Source |
|---|---|---|---|
| `confirm` | always | "Check whether anyone at your organization got this email or visited this link" | item content |
| `block-iocs` | `iocs.length > 0` | "Block these: [urls/domains/ips]" | `item_iocs` |
| `report-phishing-url` | a `url`-typed IOC is present | "Report it to Google Safe Browsing / your email provider so others get blocked too" | repo IRP-Phishing, reworded |
| `check-clicked` | always | "If anyone clicked or opened an attachment — treat their account and device as compromised: reset password, scan the device" | repo IRP-Phishing ("Validate User's Actions"), reworded |

### `malware.js`

| key | Guard | Detail | Source |
|---|---|---|---|
| `confirm` | always | "Check whether these file hashes/indicators show up anywhere on your systems" | `item_iocs` |
| `attack-mitigation` | family matched in curated map | mitigation tip for the named family | `data/attack-mitigations.json` |
| `block-iocs` | `iocs.length > 0` | "Block these: [list]" | `item_iocs` |
| `isolate-if-found` | always | "If you find it on a device, disconnect that device from the network until it's checked" | repo IRP-Malware ("Host Containment Actions"), reworded |

Explicitly dropped from the repo's malware playbook: EDR-install check (MC1), privilege-context
branching (MC8), vendor signature monitoring (MC11) — all require visibility ThreatFlow doesn't
have into the reader's endpoint tooling.

### `data-breach.js`

| key | Guard | Detail | Source |
|---|---|---|---|
| `confirm` | always | "Check whether your organization's or customers' data is in this leak" | item content / `raw_json` |
| `notify-customers` | always | "If customer data was exposed, notify them using your breach process" | repo IRP-DataLoss, reworded |
| `request-takedown` | a `url`-typed IOC is present | "Ask the host/platform to take it down (contact their abuse address)" | repo IRP-DataLoss ("Internet-Posted Data"), reworded |

### `ioc.js`

Raw indicator feeds (abuse.ch, URLhaus, MISP). No narrative, so the catalogue is short and gated
hard on actually having indicators — a no-indicator item here gets no playbook at all, same rule
as "not a CVE = no playbook."

| key | Guard | Detail | Source |
|---|---|---|---|
| `block-iocs` | `iocs.length > 0` (required for any playbook at all) | "Block these: [list]" | `item_iocs` |
| `attack-mitigation` | family matched in curated map | mitigation tip | `data/attack-mitigations.json` |
| `watch-reoccurrence` | always (once `block-iocs` fired) | "Keep watching your logs for these indicators for the next few weeks" | derived |

## API

Unchanged surface, wider coverage:

- `GET /api/items/:id` — `playbook` now populates for ransomware/phishing/malware/data-breach/ioc
  items, not only CVEs. Still `null` when there's nothing to ground on.
- `POST` / `DELETE /api/items/:id/playbook/steps/:key` — unchanged; works with the new namespaced
  keys transparently.

## UI

No new component. The existing `tf-playbook-panel` (built for Spec B) renders `steps[]` generically
— it doesn't inspect which module produced them, just `title` / `detail` / `source` / checkbox
state. Reused as-is.

## Failure modes

| Condition | Behaviour |
|---|---|
| No indicators, no actor/family match, category catalogue has nothing left to say | `null`, panel doesn't render |
| Actor/family named but absent from the curated ~20-entry ATT&CK map | `attack-mitigation` step just doesn't appear; rest of the playbook is unaffected |
| Item recategorized (rare) | Playbook regenerates under the new category's rules, same as a profile edit already does |
| A ticked step later disappears on regen | Tick is preserved (per Spec B's `playbook_step_state` design), reappears if the step returns |
| Ollama unreachable | No effect — this feature, like the CVE builder, is pure JS; wording rewording (if ever added here) would degrade the same way Spec B's does |

## Testing

- One table-driven test file per new module (`ransomware.test.js`, `phishing.test.js`,
  `malware.test.js`, `data-breach.test.js`, `ioc.test.js`), mirroring `playbook.test.js`: each step
  appears when its guard holds, is absent when it doesn't, `source` is non-empty on every emitted
  step, ordering is stable.
- `attack-mitigations.test.js` — matched name returns its curated entries, unmatched name returns
  `null`, no partial/fuzzy match.
- `api.test.js` additions — playbook shape now present for each of the five categories; an
  IOC-category item with zero indicators still yields `null`.

## Out of scope

- **Full MITRE ATT&CK ingestion.** The curated mitigation map only covers names already in
  ThreatFlow's own actor/family dictionaries (currently 10 + 10). Expanding the dictionaries is a
  separate, unrelated piece of work; this spec only joins against what already exists.
- **Advisory/osint/news categories.** Advisory items with a CVE already get a playbook via the
  existing CVE gate; osint/news carry no structured facts to ground a step on, same reasoning
  Spec B used to exclude non-CVE items generally.
- **Anything that assumes active incident tooling ThreatFlow can't see** — EDR state, AD forest
  health, physical device seizure. If ThreatFlow later integrates with real endpoint tooling, those
  steps become groundable and this spec should be revisited, not extended by guesswork now.
