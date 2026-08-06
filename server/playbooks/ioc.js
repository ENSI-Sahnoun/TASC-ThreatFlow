// Pure step builder for raw indicator-feed items (abuse.ch, URLhaus, MISP). No narrative here,
// so the catalogue is short and gated hard on actually having indicators: a no-indicator item
// gets no playbook at all, the same rule as "not a CVE = no playbook" in playbook.js.
const { attackStep } = require('./attack-mitigations');

function blockIocsStep(iocs) {
  return {
    key: 'ioc:block-iocs',
    title: 'Block the known indicators',
    detail: `Block these: ${iocs.map((i) => i.value).join(', ')}`,
    source: 'item_iocs',
    link: null,
  };
}

function attackMitigationStep(families, attackMitigations) {
  for (const name of families || []) {
    const mitigations = attackStep(name, 'family', attackMitigations);
    if (mitigations && mitigations.length) {
      const list = mitigations
        .map((m) => `${m.name} (${m.id}, addresses ${m.techniqueCount} technique${m.techniqueCount === 1 ? '' : 's'})`)
        .join(', ');
      const syncedAt = mitigations[0].syncedAt;
      return {
        key: 'ioc:attack-mitigation',
        title: `Known mitigations for ${name}`,
        detail: `Recommended ATT&CK mitigations for ${name}: ${list}`,
        source: `MITRE ATT&CK (attack_mitigations table${syncedAt ? `, synced ${syncedAt}` : ''})`,
        link: mitigations[0].url,
      };
    }
  }
  return null;
}

function watchReoccurrenceStep() {
  return {
    key: 'ioc:watch-reoccurrence',
    title: 'Watch for these indicators',
    detail: 'Keep watching your logs for these indicators for the next few weeks',
    source: 'derived',
    link: null,
  };
}

function buildIocPlaybook({ families = [], iocs = [], attackMitigations = new Map() } = {}) {
  if (!iocs || iocs.length === 0) return null;

  const steps = [blockIocsStep(iocs)];

  const attackMit = attackMitigationStep(families, attackMitigations);
  if (attackMit) steps.push(attackMit);

  steps.push(watchReoccurrenceStep());

  return steps;
}

module.exports = { buildIocPlaybook };
