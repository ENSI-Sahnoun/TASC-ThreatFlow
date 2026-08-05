// Pure step builder for data-breach-category items. No I/O, no model, no database.
function confirmStep() {
  return {
    key: 'data-breach:confirm',
    title: 'Check whether your data is in this leak',
    detail: "Check whether your organization's or customers' data is in this leak",
    source: 'item content / raw_json',
    link: null,
  };
}

function notifyCustomersStep() {
  return {
    key: 'data-breach:notify-customers',
    title: 'Notify affected customers',
    detail: 'If customer data was exposed, notify them using your breach process',
    source: 'IRP-DataLoss, reworded',
    link: null,
  };
}

function requestTakedownStep() {
  return {
    key: 'data-breach:request-takedown',
    title: 'Request a takedown',
    detail: 'Ask the host/platform to take it down (contact their abuse address)',
    source: 'IRP-DataLoss, reworded',
    link: null,
  };
}

function buildDataBreachPlaybook({ iocs = [] } = {}) {
  const steps = [confirmStep(), notifyCustomersStep()];

  if ((iocs || []).some((i) => i.type === 'url')) steps.push(requestTakedownStep());

  return steps;
}

module.exports = { buildDataBreachPlaybook };
