# Remediation playbooks — "now what do I do?"

Design, 2026-08-03. Spec B. Depends on Spec A
([`2026-08-03-impact-indicator-design.md`](2026-08-03-impact-indicator-design.md)), which is
implemented and merged.

## Problem

Spec A tells a user what would happen to them. It stops exactly where the useful part starts:
having read "anyone on the internet could read, change and shut down your Windows servers", the
reader has no next action. The item page ends in entities, IOCs and raw JSON — reference
material for an analyst, not instructions for the non-expert owner this product targets.

A playbook closes that gap: a short, checkable list of what to actually do about one item.

## What Spec A already provides

Nothing here needs to be re-derived. Spec B consumes, unchanged:

| From Spec A | Used for |
|---|---|
| `items.cvss_vector` | Deriving mitigation steps when no vendor fix is published |
| `profile_assets.exposure` | Whether "restrict network access" is even applicable |
| `asset_roles.roleFor` | Naming the thing a step acts on |
| `item_relevance.consequence` | Step provenance, and ordering steps by what they prevent |
| `cve_intel.kev_due_date` | The deadline a playbook is measured against |

## Audience

Unchanged from Spec A: a non-expert owner or IT generalist. A step is written as an instruction
they can either perform or hand to someone, never as a description of a security concept.

## Grounding, and its measured ceiling

Every step must trace to something a source actually said. Measured against the live corpus on
2026-08-03 (12,736 items; 1,656 KEV items after the Task 0 sampling fix):

| Source | Available | Carries |
|---|---|---|
| CISA KEV record | 1,656 items · 1,739 corpus items via CVE | `requiredAction`, `dueDate`, `knownRansomwareCampaignUse` — all present on 100% of KEV rows |
| NVD reference tagged `Patch` | 1,542 items | A link to the actual fix |
| NVD reference tagged `Vendor Advisory` | 2,577 items | A link to the vendor's own guidance |
| CVSS vector | 7,685 items | Derivable mitigations (restrict access, rotate credentials) |

For the Spec A verification profile, all 1,412 prominent-tier items carry a CVE, but only **28
are KEV-grounded**. So the common case is the thin one, and the design is built around it rather
than around the KEV happy path.

**`requiredAction` is usually boilerplate.** Sampled values are overwhelmingly "Apply mitigations
per vendor instructions or discontinue use of the product if mitigations are unavailable." It is
authoritative and worth quoting, but it is not specific guidance — the *link* in the NVD `Patch`
reference carries more practical value than CISA's sentence does. The design treats
`requiredAction` as a citation, not as the body of a step.

**`knownRansomwareCampaignUse` is the opposite** — a concrete, binary, high-value fact present on
every KEV row. It earns its own step when true.

## Data model

Two tables. One holds generated content and is disposable; one holds user input and is not.

### `item_playbooks` — the generated skeleton

```sql
CREATE TABLE IF NOT EXISTS item_playbooks (
  profile_id      INT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  item_id         INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  profile_version INT NOT NULL,
  steps           JSONB NOT NULL,   -- [{ key, title, detail, source, link }]
  worded_by       TEXT,             -- model name, or NULL while the template wording stands
  computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_id, item_id, profile_version)
);
```

Keyed by `profile_version` like `item_relevance`, for the same reason: a profile edit can change
which steps apply (exposure changes whether "restrict access" is relevant), so the cached
skeleton must invalidate with it.

### `playbook_step_state` — what the user ticked

```sql
CREATE TABLE IF NOT EXISTS playbook_step_state (
  profile_id  INT  NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  item_id     INT  NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  step_key    TEXT NOT NULL,
  done_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_id, item_id, step_key)
);
```

**Deliberately not keyed by `profile_version`.** Ticking "I applied the patch" is a statement
about the real world, and editing an unrelated profile field must not un-tick it. This is the
one thing in the feature that is user data rather than derived data, and it survives every
regeneration.

`step_key` is therefore a **stable identifier**, not a position: `confirm`, `patch`, `restrict`,
`rotate`, `ransomware`, `watch-vendor`. A step that disappears and later returns finds its tick
waiting.

## The step builder

New pure module `server/playbook.js`. No I/O, no model, no database — the same shape as
`consequence.js`.

**Input:** the item's consequence slots, its `cvss_vector`, the matched asset (vendor, product,
exposure), and the CVE facts (`kev_listed`, `kev_due_date`, `required_action`,
`known_ransomware`, and the tagged references).

**Output:** an ordered array of 3–6 steps.

```js
{
  key: 'restrict',
  title: 'Limit who can reach it',
  detail: 'Allow connections to your Windows servers only from addresses you control.',
  source: 'derived from AV:N + exposure=internet',
  link: null,
}
```

### The step catalogue

Steps are emitted in this fixed order; each has a guard, and a step whose guard is false is
simply absent.

| key | Guard | Source |
|---|---|---|
| `confirm` | always | The matched asset — "check whether you run the affected version" |
| `ransomware` | `known_ransomware` is true | KEV `knownRansomwareCampaignUse` |
| `patch` | a `Patch`-tagged reference exists | NVD reference, quoted as a link |
| `vendor` | no `Patch` ref, but a `Vendor Advisory` ref exists | NVD reference |
| `restrict` | `AV:N` and exposure is not `internal` | CVSS vector + Spec A exposure |
| `rotate` | `C:H` and `PR:N` | CVSS vector |
| `watch-vendor` | no `Patch` and no `Vendor Advisory` ref | The absence itself |

`confirm` is unconditional because every other step is wasted effort if the user does not
actually run the affected version, and because it is the one step that is always honestly
derivable.

### `source` is mandatory on every step

Every step states where it came from, in the same spirit as Spec A's `from`. A step with no
traceable source is a step the model invented, and the type makes that unrepresentable.

## Thin data: state the gap, never fill it

When neither a `Patch` nor a `Vendor Advisory` reference exists — the common case — the playbook
renders the derived steps and says so plainly at the top:

> No vendor fix is published for this yet. The steps below are derived from the type of flaw,
> not from a vendor advisory.

Plus a coverage footer naming which sources were consulted and which were absent, so the user
can judge the playbook rather than trust it.

**A hallucinated patch instruction is the worst thing this feature could produce** — worse than
Spec A's breach claim, because the user would act on it. The structural guarantee is the same
one Spec A uses: the model never generates steps, only rewords them, and `item_playbooks.steps`
is written by the pure builder before any model runs.

## Prose layer

New `server/playbook_prose.js`, mirroring `relevance_prose.js` exactly, including its safety
posture.

- The skeleton is materialized by the pure builder alongside the relevance recompute:
  milliseconds, always present, works with Ollama down.
- The model is asked only to reword `detail` for readability, on demand, when the user first
  opens the item. Result cached in `item_playbooks` with `worded_by` set.
- **`title`, `key`, `source` and `link` are never sent for rewording and never overwritten.**
  Only `detail` can change.
- Reuses `BREACH_CLAIM_RE` unchanged. Adds `INVENTED_LINK_RE`, rejecting any reworded detail
  containing a URL, a CVE id, or a version number that was not in its input — the model must not
  manufacture a fix location.
- A rejected or failed rewording leaves the template detail in place, exactly as prose v1 does.

## API

- `GET /api/items/:id` — gains `playbook: { steps[], groundedIn[], missing[], done[] }`, or
  `null` when no profile is active. `done[]` is the list of ticked `step_key`s.
- `POST /api/items/:id/playbook/steps/:key` → `204`. Marks a step done.
- `DELETE /api/items/:id/playbook/steps/:key` → `204`. Un-marks it.
- `POST /api/profiles/:id/playbooks/word` → `202`. Kicks off background rewording, mirroring the
  existing `relevance/prose` route.

Step routes take the profile from `X-Profile-Id` like everything else. An unknown `step_key`
returns `404` rather than storing a tick against a step that does not exist.

## UI

`tf-playbook-panel`, placed directly below `tf-impact-panel` on the item detail page — the two
read as one thought: what this does to you, then what to do about it.

```
What to do about this                      2 of 4 done · due Aug 17

[x] Check whether you run the affected version
    Affected: Windows Server 2022 before build 20348.2582
    from: your profile assets

[x] Apply the vendor's fix
    → Microsoft advisory KB5040123                    from: NVD (Patch)

[ ] Limit who can reach it
    Allow connections only from addresses you control.
    from: AV:N + your exposure answer

[ ] Change passwords and keys on that system
    from: C:H + PR:N

Grounded in: CISA KEV · NVD references          Not available: vendor patch link
```

Following Spec A's precedent, all logic lives in pure functions in `core/` (`playbookProgress`,
`stepBlocks`) and the component is a thin binding — this app runs vitest in a node environment
with no TestBed by design.

Ticking a step is optimistic: the checkbox flips immediately and reconciles on the response,
because a checklist that waits on a round-trip feels broken.

## Failure modes

| Condition | Behaviour |
|---|---|
| Ollama unreachable | Template wording; every step still present and checkable |
| No `Patch` or `Vendor Advisory` reference | Derived steps plus the stated gap |
| No CVSS vector | `confirm` and any KEV steps only; `restrict`/`rotate` absent |
| Item is not a CVE at all | No playbook — `null`, and the panel does not render |
| Profile edited | Skeleton regenerates at the new version; ticks survive |
| Model returns an invented link | Rejected by `INVENTED_LINK_RE`; template detail stands |

## Testing

- `playbook.test.js` — table-driven over each guard: every step appears when its guard holds and
  is absent when it does not; `source` is non-empty on every emitted step; ordering is stable;
  a no-CVE item yields no playbook.
- `playbook_prose.test.js` — `detail` is the only mutable field; `INVENTED_LINK_RE` rejects a
  fabricated URL, CVE id and version; `BREACH_CLAIM_RE` cases retained; a failed call leaves the
  template intact.
- `api.test.js` — playbook shape on item detail; tick and un-tick round-trip; unknown `step_key`
  is `404`; ticks survive a `PUT /api/profiles/:id` that bumps `profile_version`.
- Frontend `playbook.spec.ts` — progress counting, step block construction, the grounded/missing
  footer, and rendering with zero steps.

## Out of scope

- **Threat-domain standing playbooks** ("your ransomware posture"). A separate feature with a
  different unit and a different data source (CIS Controls / ATT&CK mitigations rather than
  per-CVE grounding). Revisit after this ships.
- **Executing anything.** No scripts, no config changes, no agent that applies a patch. Every
  step is something a human does.
- **NIST CSF / SP 800-40 structure.** These informed the step catalogue's shape but are prose
  PDFs with no machine-readable steps; importing their vocabulary would add ceremony a
  non-expert reader does not benefit from.

## Dependency note

The Spec A open finding — 310 `act_now` items with one carrying exploitation evidence — matters
here. Playbooks attach to `act_now` and `watch`, so at the current ladder this generates
skeletons for ~1,400 items per profile. That is cheap (pure JS) and correct, but a user facing
310 "act now" playbooks has the same problem in a new place. **Resolve that finding before
building this**, since it changes how many playbooks a user is actually asked to work through.
