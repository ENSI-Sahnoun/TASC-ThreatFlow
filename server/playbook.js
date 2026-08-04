// Turns a CVSS vector, an asset's exposure, its role and a set of CVE facts into an ordered,
// 3-6 step remediation checklist. Pure: no I/O, no model, no database.
//
// The step catalogue is fixed. Each step has a guard; a step whose guard is false is simply
// absent — never emitted as a hedge or a maybe. Every emitted step carries `source`, in the
// same spirit as consequence.js's `from`: a step with no traceable source is a step the model
// invented, and the type makes that unrepresentable.
//
// A hallucinated patch instruction is the worst thing this feature could produce, worse than a
// wrong severity label, because the user would act on it. This module never emits a link it did
// not read directly from `patchUrl`/`advisoryUrl` — it composes no URL of its own.
const { parseVector } = require('./cvss');
const { roleFor } = require('./asset_roles');

function targetPhrase(vendor, product) {
  const role = roleFor(vendor, product);
  if (role) return role;
  if (vendor && product) return `${vendor} ${product}`;
  return 'the affected software';
}

function confirmStep(vendor, product) {
  const target = targetPhrase(vendor, product);
  return {
    key: 'confirm',
    title: 'Check whether you run the affected version',
    detail: `Affected: ${target}`,
    source: vendor && product ? 'your profile assets' : 'this item’s CVE match',
    link: null,
  };
}

function ransomwareStep() {
  return {
    key: 'ransomware',
    title: 'This flaw is being used in ransomware attacks',
    detail: 'CISA reports this vulnerability has been used in known ransomware campaigns.',
    source: 'CISA KEV: knownRansomwareCampaignUse',
    link: null,
  };
}

function patchStep(patchUrl) {
  return {
    key: 'patch',
    title: 'Apply the vendor’s fix',
    detail: 'A fix is published for this vulnerability. Apply it as soon as you can.',
    source: 'NVD reference (Patch)',
    link: patchUrl,
  };
}

function vendorStep(advisoryUrl) {
  return {
    key: 'vendor',
    title: 'Read the vendor’s advisory',
    detail: 'No direct patch link is available yet, but the vendor has published guidance.',
    source: 'NVD reference (Vendor Advisory)',
    link: advisoryUrl,
  };
}

function restrictStep(exposure, vendor, product) {
  const target = targetPhrase(vendor, product);
  return {
    key: 'restrict',
    title: 'Limit who can reach it',
    detail: `Allow connections to ${target} only from addresses you control.`,
    source: `derived from AV:N + exposure=${exposure}`,
    link: null,
  };
}

function rotateStep() {
  return {
    key: 'rotate',
    title: 'Change passwords and keys on that system',
    detail: 'Rotate credentials and secrets on the affected system — this flaw could let an attacker read or change them without a password.',
    source: 'derived from C:H + PR:N',
    link: null,
  };
}

function watchVendorStep() {
  return {
    key: 'watch-vendor',
    title: 'Watch for a vendor fix',
    detail: 'No vendor patch or advisory is published yet. Check back, or subscribe to the vendor’s security advisories.',
    source: 'absence of an NVD Patch or Vendor Advisory reference',
    link: null,
  };
}

function buildPlaybook({
  vector, exposure = 'unknown', vendor = null, product = null,
  kevListed = false, kevDueDate = null, kevRansomware = false,
  patchUrl = null, advisoryUrl = null,
} = {}) {
  // parseVector returns null for anything it cannot read, including v4 vectors — exactly the
  // behaviour wanted here: no metrics means restrict/rotate have nothing to derive from.
  const parsed = vector ? parseVector(vector) : null;
  const metrics = parsed ? parsed.metrics : null;

  const steps = [confirmStep(vendor, product)];

  if (kevRansomware) steps.push(ransomwareStep());

  if (patchUrl) steps.push(patchStep(patchUrl));
  else if (advisoryUrl) steps.push(vendorStep(advisoryUrl));

  if (metrics && metrics.AV === 'N' && exposure !== 'internal') steps.push(restrictStep(exposure, vendor, product));
  if (metrics && metrics.C === 'H' && metrics.PR === 'N') steps.push(rotateStep());

  if (!patchUrl && !advisoryUrl) steps.push(watchVendorStep());

  return steps;
}

module.exports = { buildPlaybook };
