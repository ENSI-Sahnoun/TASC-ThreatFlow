// Turns a ransomware.live victim record, its matched actor and any indicators into an ordered,
// checkable list. Pure: no I/O, no model, no database — same shape as playbook.js. Every step
// carries `source`; a step whose guard is false is simply absent, never rendered as a hedge.
const { attackStep } = require('./attack-mitigations');

// The ransomware.live adapter (server/adapters/bespoke.js) builds the item title as
// `${victim}${group ? ` (${group})` : ''}` — there is no separate victim column, so the group
// suffix it added is stripped back off here rather than re-deriving victim from raw_json.
function victimFromTitle(title, actors) {
  if (!title) return null;
  const group = (actors || [])[0];
  if (group && title.endsWith(` (${group})`)) return title.slice(0, -(group.length + 3));
  return title;
}

function confirmStep(title, actors) {
  const victim = victimFromTitle(title, actors);
  return {
    key: 'ransomware:confirm',
    title: 'Check whether this is your organization',
    detail: `Check whether ${victim || 'the named organization'} is your organization or a vendor/partner you depend on`,
    source: 'ransomware.live victim record',
    link: null,
  };
}

function attackMitigationStep(actors, attackMitigations) {
  for (const name of actors || []) {
    const mitigations = attackStep(name, 'actor', attackMitigations);
    if (mitigations && mitigations.length) {
      const list = mitigations
        .map((m) => `${m.name} (${m.id}, addresses ${m.techniqueCount} technique${m.techniqueCount === 1 ? '' : 's'})`)
        .join(', ');
      const syncedAt = mitigations[0].syncedAt;
      return {
        key: 'ransomware:attack-mitigation',
        title: `Known mitigations for ${name}`,
        detail: `Recommended ATT&CK mitigations for ${name}: ${list}`,
        source: `MITRE ATT&CK (attack_mitigations table${syncedAt ? `, synced ${syncedAt}` : ''})`,
        link: mitigations[0].url,
      };
    }
  }
  return null;
}

function blockIocsStep(iocs) {
  return {
    key: 'ransomware:block-iocs',
    title: 'Block the known indicators',
    detail: `Give your IT/security provider these to block: ${iocs.map((i) => i.value).join(', ')}`,
    source: 'item_iocs',
    link: null,
  };
}

function protectBackupsStep() {
  return {
    key: 'ransomware:protect-backups',
    title: 'Protect your backups now',
    detail: 'If this is your organization — disconnect your backups from the network right now and make a separate offline copy before doing anything else',
    source: 'IRP-Ransom, reworded',
    link: null,
  };
}

function resetCredentialsStep() {
  return {
    key: 'ransomware:reset-credentials',
    title: 'Reset credentials',
    detail: 'Reset passwords and keys for accounts that may have been reached',
    source: 'IRP-Ransom, reworded',
    link: null,
  };
}

function paymentDecisionStep() {
  return {
    key: 'ransomware:payment-decision',
    title: 'Ransom payment is a leadership decision',
    detail: 'Whether to pay a ransom is a decision for leadership/your board, not IT alone — check your insurance coverage first',
    source: 'IRP-Ransom, reworded',
    link: null,
  };
}

function buildRansomwarePlaybook({ title = null, actors = [], iocs = [], attackMitigations = new Map() } = {}) {
  const steps = [confirmStep(title, actors)];

  const attackMit = attackMitigationStep(actors, attackMitigations);
  if (attackMit) steps.push(attackMit);

  if ((iocs || []).length > 0) steps.push(blockIocsStep(iocs));

  steps.push(protectBackupsStep());
  steps.push(resetCredentialsStep());
  steps.push(paymentDecisionStep());

  return steps;
}

module.exports = { buildRansomwarePlaybook };
