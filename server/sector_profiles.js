// Pure sector -> recommendation map. Drives the survey's "recommended set" step so a user who
// knows nothing still ends up with a profile that matches real data.
//
// Every vendor slug here was verified against item_cpes on 2026-08-02 (reference counts in
// comments). A slug that matches nothing is worse than an omission: it makes the
// recommendation look richer than it is while surfacing no items.
//
// ICS/OT vendor coverage is genuinely thin — siemens has 22 references, rockwellautomation 4,
// and schneider-electric does not exist as a slug at all — so manufacturing and energy lean on
// the ics-ot *domain* rather than pretending to vendor coverage they do not have.

const SECTORS = [
  { slug: 'finance', label: 'Finance & Banking' },
  { slug: 'healthcare', label: 'Healthcare' },
  { slug: 'government', label: 'Government & Public Sector' },
  { slug: 'retail-ecommerce', label: 'Retail & E-commerce' },
  { slug: 'manufacturing-industrial', label: 'Manufacturing & Industrial' },
  { slug: 'technology-saas', label: 'Technology & SaaS' },
  { slug: 'education', label: 'Education' },
  { slug: 'energy-utilities', label: 'Energy & Utilities' },
  { slug: 'telecom', label: 'Telecommunications' },
  { slug: 'other', label: 'Other / General' },
];

// Reference counts as measured 2026-08-02: microsoft 7519 · oracle 1127 · apple 1025 ·
// linux 1003 · redhat 473 · cisco 403 · debian 388 · ibm 347 · mozilla 264 · apache 199 ·
// adobe 187 · suse 167 · google 84 · fortinet 23 · siemens 22 · golang 19 · rockwellautomation 4
const RECOMMENDATIONS = {
  finance: {
    vendors: ['microsoft', 'oracle', 'ibm', 'redhat'],
    products: [],
    threatDomains: ['financial', 'phishing', 'ransomware', 'identity', 'zero-day'],
    severityFloor: 'medium',
  },
  healthcare: {
    vendors: ['microsoft', 'oracle', 'linux'],
    products: [],
    threatDomains: ['ransomware', 'data-breach', 'phishing', 'identity'],
    severityFloor: 'medium',
  },
  government: {
    vendors: ['microsoft', 'linux', 'redhat', 'fortinet'],
    products: [],
    threatDomains: ['nation-state', 'zero-day', 'phishing', 'ransomware'],
    severityFloor: 'medium',
  },
  'retail-ecommerce': {
    vendors: ['microsoft', 'apache', 'linux'],
    products: [],
    threatDomains: ['financial', 'phishing', 'data-breach', 'supply-chain'],
    severityFloor: 'medium',
  },
  'manufacturing-industrial': {
    // Deliberately short: item_cpes ICS/OT coverage is thin, so the ics-ot domain does the work.
    vendors: ['siemens', 'rockwellautomation', 'microsoft'],
    products: [],
    threatDomains: ['ics-ot', 'ransomware', 'supply-chain', 'network'],
    severityFloor: 'medium',
  },
  'technology-saas': {
    vendors: ['linux', 'apache', 'google', 'golang', 'redhat', 'debian'],
    products: [],
    threatDomains: ['supply-chain', 'cloud', 'zero-day', 'identity', 'ai-threats'],
    severityFloor: 'medium',
  },
  education: {
    vendors: ['microsoft', 'linux', 'mozilla'],
    products: [],
    threatDomains: ['phishing', 'ransomware', 'data-breach'],
    severityFloor: 'high',
  },
  'energy-utilities': {
    vendors: ['siemens', 'microsoft', 'linux'],
    products: [],
    threatDomains: ['ics-ot', 'nation-state', 'ransomware', 'network'],
    severityFloor: 'medium',
  },
  telecom: {
    vendors: ['cisco', 'linux', 'fortinet'],
    products: [],
    threatDomains: ['network', 'nation-state', 'zero-day', 'identity'],
    severityFloor: 'medium',
  },
  other: {
    vendors: ['microsoft', 'linux'],
    products: [],
    threatDomains: ['vulnerability', 'ransomware', 'phishing'],
    severityFloor: 'high',
  },
};

const SECTOR_SLUGS = new Set(SECTORS.map((s) => s.slug));

function isSector(slug) {
  return typeof slug === 'string' && SECTOR_SLUGS.has(slug);
}

// Returns a fresh copy so a caller mutating the result cannot corrupt the map for later calls.
function recommendationFor(slug) {
  if (!isSector(slug)) return null;
  const r = RECOMMENDATIONS[slug];
  return {
    vendors: [...r.vendors],
    products: [...r.products],
    threatDomains: [...r.threatDomains],
    severityFloor: r.severityFloor,
  };
}

module.exports = { SECTORS, recommendationFor, isSector };
