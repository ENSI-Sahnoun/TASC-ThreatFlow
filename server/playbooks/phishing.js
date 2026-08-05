// Pure step builder for phishing-category items. No I/O, no model, no database.
function confirmStep() {
  return {
    key: 'phishing:confirm',
    title: 'Check whether anyone was targeted',
    detail: 'Check whether anyone at your organization got this email or visited this link',
    source: 'item content',
    link: null,
  };
}

function blockIocsStep(iocs) {
  return {
    key: 'phishing:block-iocs',
    title: 'Block the known indicators',
    detail: `Block these: ${iocs.map((i) => i.value).join(', ')}`,
    source: 'item_iocs',
    link: null,
  };
}

function reportPhishingUrlStep() {
  return {
    key: 'phishing:report-phishing-url',
    title: 'Report the phishing URL',
    detail: 'Report it to Google Safe Browsing / your email provider so others get blocked too',
    source: 'IRP-Phishing, reworded',
    link: null,
  };
}

function checkClickedStep() {
  return {
    key: 'phishing:check-clicked',
    title: 'Check whether anyone clicked',
    detail: "If anyone clicked or opened an attachment — treat their account and device as compromised: reset password, scan the device",
    source: 'IRP-Phishing, reworded',
    link: null,
  };
}

function buildPhishingPlaybook({ iocs = [] } = {}) {
  const steps = [confirmStep()];

  if ((iocs || []).length > 0) steps.push(blockIocsStep(iocs));
  if ((iocs || []).some((i) => i.type === 'url')) steps.push(reportPhishingUrlStep());

  steps.push(checkClickedStep());

  return steps;
}

module.exports = { buildPhishingPlaybook };
