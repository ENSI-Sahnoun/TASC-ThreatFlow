// server/sources.config.js
const RSS_MAP = { title: 'title', summary: 'contentSnippet', author: 'creator', link: 'link', date: 'isoDate', id: 'guid' };
const rss = (name, domains, category, url, extra = {}) => ({ name, domains, category, kind: 'rss', url, active: true, tier: 'free-no-auth', mapping: RSS_MAP, ...extra });

const SOURCES = [
  // --- News (rss) ---
  rss('The Hacker News', ['malware', 'vulnerability'], 'Cybersecurity News', 'https://feeds.feedburner.com/TheHackersNews'),
  rss('Krebs on Security', ['financial', 'data-breach'], 'Cybersecurity News', 'https://krebsonsecurity.com/feed/'),
  rss('BleepingComputer', ['malware', 'ransomware'], 'Cybersecurity News', 'https://www.bleepingcomputer.com/feed/'),
  rss('Dark Reading', ['malware'], 'Cybersecurity News', 'https://www.darkreading.com/rss.xml'),
  rss('The Record', ['nation-state', 'ransomware'], 'Cybersecurity News', 'https://therecord.media/feed/'),
  rss('SecurityWeek', ['malware', 'vulnerability'], 'Cybersecurity News', 'https://www.securityweek.com/feed/'),
  rss('The Register — Security', ['malware'], 'Cybersecurity News', 'https://www.theregister.com/security/headlines.atom'),
  // --- Gov / CERT (rss) ---
  rss('CISA Cybersecurity Advisories', ['vulnerability'], 'Government / CERT Advisory', 'https://www.cisa.gov/cybersecurity-advisories/all.xml'),
  rss('CISA ICS Advisories', ['ics-ot', 'vulnerability'], 'Government / CERT Advisory', 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml'),
  rss('NCSC-UK', ['nation-state'], 'Government / CERT Advisory', 'https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml'),
  rss('CERT-FR (ANSSI)', ['vulnerability'], 'Government / CERT Advisory', 'https://www.cert.ssi.gouv.fr/feed/'),
  rss('CERT-EU', ['nation-state'], 'Government / CERT Advisory', 'https://cert.europa.eu/publications/threat-intelligence-rss'),
  // --- Vendor advisories ---
  rss('Ubuntu Security Notices', ['vulnerability'], 'Vendor Advisory', 'https://ubuntu.com/security/notices/rss.xml'),
  { name: 'Red Hat Security Data', domains: ['vulnerability'], category: 'Vendor Advisory', kind: 'json_api', url: 'https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=25', active: true, tier: 'free-no-auth', recordsPath: null, mapping: { title: 'CVE', summary: 'bugzilla_description', link: 'resource_url', date: 'public_date', id: 'CVE' }, enrichHints: { cveField: 'CVE', cvssField: 'cvss3_score', severityField: 'severity' } },
  { name: 'Microsoft MSRC', domains: ['cloud', 'identity', 'vulnerability'], category: 'Vendor Advisory', kind: 'msrc', url: 'https://api.msrc.microsoft.com/cvrf/v3.0/updates', active: true, tier: 'free-no-auth' },
  // --- Vulnerability DBs (bespoke + osv) ---
  { name: 'NVD CVE API', domains: ['vulnerability'], category: 'Vulnerability Intelligence', kind: 'nvd_cve', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0', active: true, tier: 'free-no-auth' },
  { name: 'CISA Known Exploited Vulnerabilities', domains: ['vulnerability', 'zero-day'], category: 'Vulnerability Intelligence', kind: 'kev', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', requestBody: '2000', active: true, tier: 'free-no-auth' },
  { name: 'FIRST EPSS', domains: ['vulnerability'], category: 'Vulnerability Intelligence', kind: 'epss', url: 'https://api.first.org/data/v1/epss', requestBody: '50', active: true, tier: 'free-no-auth' },
  { name: 'CIRCL Vulnerability-Lookup', domains: ['vulnerability'], category: 'Vulnerability Intelligence', kind: 'json_api', url: 'https://vulnerability.circl.lu/api/vulnerability/last/30', active: true, tier: 'free-no-auth', recordsPath: null, mapping: { title: 'id', summary: 'details', link: null, date: 'published', id: 'id' }, enrichHints: { cveField: 'id' } },
  { name: 'OSV.dev', domains: ['supply-chain', 'vulnerability'], category: 'Vulnerability Intelligence', kind: 'osv', url: 'https://api.osv.dev/v1/query', active: true, tier: 'free-no-auth' },
  rss('Exploit-DB', ['zero-day', 'vulnerability'], 'Vulnerability Intelligence', 'https://www.exploit-db.com/rss.xml'),
  { name: 'GitHub Security Advisories', domains: ['supply-chain', 'vulnerability'], category: 'Vulnerability Intelligence', kind: 'ghsa', url: 'https://api.github.com/advisories', requestBody: '30', active: true, tier: 'free-no-auth' },
  // --- Malware IOCs / C2 (bespoke + abuse_ch) ---
  { name: 'abuse.ch Feodo Tracker', domains: ['malware'], category: 'Malware / C2', kind: 'feodo', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', requestBody: '80', active: true, tier: 'free-no-auth' },
  { name: 'abuse.ch URLhaus', domains: ['malware', 'phishing'], category: 'Malware / C2', kind: 'abuse_ch', url: 'https://urlhaus.abuse.ch/downloads/json_recent/', active: true, tier: 'free-no-auth', enrichHints: { iocField: 'url', iocType: 'url', familyField: 'tags' } },
  { name: 'abuse.ch ThreatFox', domains: ['malware'], category: 'Malware / C2', kind: 'abuse_ch', url: 'https://threatfox.abuse.ch/export/json/recent/', active: true, tier: 'free-no-auth', enrichHints: { iocField: 'ioc_value', iocTypeField: 'ioc_type', familyField: 'malware_printable' } },
  { name: 'SANS ISC Top Attacking IPs', domains: ['network', 'malware'], category: 'Threat Intelligence', kind: 'dshield', url: 'https://isc.sans.edu/api/topips/records', requestBody: '20', active: true, tier: 'free-no-auth' },
  // --- Malware research blogs (rss) ---
  rss('Cisco Talos', ['malware', 'nation-state'], 'Malware Research', 'https://blog.talosintelligence.com/rss/'),
  rss('Palo Alto Unit 42', ['malware', 'nation-state'], 'Malware Research', 'https://unit42.paloaltonetworks.com/feed/'),
  rss('Malwarebytes Labs', ['malware'], 'Malware Research', 'https://www.malwarebytes.com/blog/feed/index.xml'),
  rss('SentinelOne Labs', ['malware', 'nation-state'], 'Malware Research', 'https://www.sentinelone.com/labs/feed/'),
  rss('Rapid7 Blog', ['malware', 'vulnerability'], 'Malware Research', 'https://www.rapid7.com/blog/rss/'),
  rss('Recorded Future', ['nation-state', 'malware'], 'Threat Intelligence', 'https://www.recordedfuture.com/feed'),
  rss('Wordfence Blog', ['vulnerability', 'malware'], 'Malware Research', 'https://www.wordfence.com/blog/feed/'),
  rss('Check Point Research', ['malware', 'nation-state'], 'Malware Research', 'https://research.checkpoint.com/feed/'),
  rss('The DFIR Report', ['ransomware', 'malware'], 'Malware Research', 'https://thedfirreport.com/feed/'),
  rss('SANS Internet Storm Center', ['malware'], 'OSINT', 'https://isc.sans.edu/rssfeed_full.xml'),
  rss('Securelist', ['nation-state', 'malware'], 'Malware Research', 'https://securelist.com/feed/'),
  // --- Ransomware ---
  { name: 'ransomware.live', domains: ['ransomware'], category: 'Ransomware', kind: 'ransomware_live', url: 'https://api.ransomware.live/v1/recentvictims', requestBody: '60', active: true, tier: 'free-no-auth' },
  // --- Phishing ---
  { name: 'OpenPhish', domains: ['phishing'], category: 'Phishing', kind: 'text_feed', url: 'https://openphish.com/feed.txt', active: true, tier: 'free-no-auth', enrichHints: { iocType: 'url' } },
  // --- Data breaches ---
  { name: 'Have I Been Pwned — Breaches', domains: ['data-breach'], category: 'Data Breaches', kind: 'json_api', url: 'https://haveibeenpwned.com/api/v3/breaches', active: true, tier: 'free-no-auth', recordsPath: null, mapping: { title: 'Name', summary: 'Description', link: 'Domain', date: 'BreachDate', id: 'Name' } },
  // --- Zero-day research ---
  rss('Google Project Zero', ['zero-day'], 'Vulnerability Intelligence', 'https://googleprojectzero.blogspot.com/feeds/posts/default'),
  // --- ICS/OT ---
  rss('Dragos Blog', ['ics-ot'], 'Malware Research', 'https://www.dragos.com/blog.rss'),
  // --- Threat Intel / OSINT ---
  { name: 'CIRCL MISP OSINT Feed', domains: ['malware'], category: 'Threat Intelligence', kind: 'misp_feed', url: 'https://www.circl.lu/doc/misp/feed-osint/manifest.json', active: true, tier: 'free-no-auth' },

  // --- Key-gated (wired, inactive) ---
  { name: 'AlienVault OTX', domains: ['malware'], category: 'Threat Intelligence', kind: 'json_api', url: 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20', active: false, tier: 'NEEDS KEY', auth: { env: 'OTX_API_KEY', header: 'X-OTX-API-KEY' }, recordsPath: 'results', mapping: { title: 'name', summary: 'description', link: 'id', date: 'created', id: 'id' } },
  { name: 'VulnCheck KEV', domains: ['vulnerability', 'zero-day'], category: 'Vulnerability Intelligence', kind: 'json_api', url: 'https://api.vulncheck.com/v3/index/vulncheck-kev', active: false, tier: 'NEEDS KEY', auth: { env: 'VULNCHECK_API_KEY', header: 'Authorization' }, recordsPath: 'data', mapping: { title: 'cve', summary: 'shortDescription', link: 'sourceURL', date: 'date_added', id: 'cve' } },
  { name: 'PhishTank', domains: ['phishing'], category: 'Phishing', kind: 'json_api', url: 'https://data.phishtank.com/data/online-valid.json', active: false, tier: 'NEEDS KEY', auth: { env: 'PHISHTANK_API_KEY', header: 'Authorization' }, recordsPath: null, mapping: { title: 'url', summary: 'target', link: 'phish_detail_url', date: 'submission_time', id: 'phish_id' } },
  { name: 'abuse.ch MalwareBazaar', domains: ['malware'], category: 'Malware / C2', kind: 'abuse_ch', url: 'https://mb-api.abuse.ch/api/v1/', active: false, tier: 'NEEDS KEY', auth: { env: 'ABUSECH_AUTH_KEY', header: 'Auth-Key' }, enrichHints: { iocField: 'sha256_hash', iocType: 'sha256', familyField: 'signature' } },
  { name: 'GreyNoise Community', domains: ['network'], category: 'Threat Intelligence', kind: 'json_api', url: 'https://api.greynoise.io/v3/community/', active: false, tier: 'NEEDS KEY', auth: { env: 'GREYNOISE_API_KEY', header: 'key' }, recordsPath: null, mapping: { title: 'ip', summary: 'classification', link: 'link', date: 'last_seen', id: 'ip' } },
  // Shodan can't drive a feed on a free/oss-plan key: /shodan/host/search (the only
  // endpoint that could) requires paid membership ("Requires membership or higher to
  // access", confirmed live 2026-07-17). This row is a placeholder, not a real source —
  // kind 'unsupported' means syncSource never fetches it. It exists only so the Ingestion
  // page's existing "set API key" UI (api_key column, PATCH /api/sources/:id) has a place
  // to store SHODAN_API_KEY. server/shodan_enrich.js reads that stored key (falling back
  // to the env var) to enrich IP IOCs from URLhaus/ThreatFox/Feodo Tracker with org/ISP/geo;
  // the free InternetDB lookup (ports/vulns/tags) runs regardless, no key needed.
  { name: 'Shodan (IP enrichment)', domains: ['network'], category: 'Threat Intelligence', kind: 'unsupported', url: 'https://internetdb.shodan.io', active: false, tier: 'optional-key', auth: { env: 'SHODAN_API_KEY', header: 'n/a' } },
];

module.exports = { SOURCES };
