const DOMAINS = [
  { slug: 'vulnerability', label: 'Vulnerability Intelligence' },
  { slug: 'malware', label: 'Malware' },
  { slug: 'ransomware', label: 'Ransomware' },
  { slug: 'phishing', label: 'Phishing' },
  { slug: 'data-breach', label: 'Data Breaches' },
  { slug: 'dark-web', label: 'Dark Web' },
  { slug: 'cloud', label: 'Cloud Security' },
  { slug: 'identity', label: 'Identity & Access' },
  { slug: 'endpoint', label: 'Endpoint Security' },
  { slug: 'network', label: 'Network Security' },
  { slug: 'supply-chain', label: 'Supply Chain Attacks' },
  { slug: 'zero-day', label: 'Zero-Day Exploits' },
  { slug: 'nation-state', label: 'Nation-State Activity' },
  { slug: 'financial', label: 'Financial Cybercrime' },
  { slug: 'ics-ot', label: 'Industrial Control Systems (ICS/OT)' },
  { slug: 'ai-threats', label: 'Artificial Intelligence Threats' },
];
const SLUGS = new Set(DOMAINS.map((d) => d.slug));
function isDomain(slug) { return SLUGS.has(slug); }
module.exports = { DOMAINS, isDomain };
