function deriveFetchKind(connType) {
  const t = (connType || '').toLowerCase();
  if (t.includes('oauth')) return 'unsupported';
  if (t.includes('rss') || t.includes('atom')) return 'rss';
  if (t.includes('post')) return 'json_api_post';
  if (t.includes('rest api') || t.includes('json api') || t.includes('bulk json')) return 'json_api';
  return 'unsupported';
}

function categoryBucket(domain) {
  const d = (domain || '').toLowerCase();
  if (d.includes('vulnerability')) return 'cve';
  if (d.includes('ransomware')) return 'ransomware';
  if (d.includes('phishing')) return 'phishing';
  if (d.includes('breach') || d.includes('leak')) return 'data-breach';
  if (d.includes('malware') || d.includes('botnet') || d.includes('ioc') && d.includes('feed') && !d.includes('threat intel')) return 'malware';
  if (d.includes('threat intel')) return 'ioc';
  if (d.includes('government') || d.includes('cert') || d.includes('vendor advisory')) return 'advisory';
  if (d.includes('osint')) return 'osint';
  if (d.includes('news')) return 'news';
  return 'other';
}

function domainsForCategory(category) {
  switch ((category || '').toLowerCase()) {
    case 'cve': return ['vulnerability'];
    case 'ransomware': return ['ransomware'];
    case 'phishing': return ['phishing'];
    case 'data-breach': return ['data-breach'];
    case 'malware': return ['malware'];
    case 'ioc': return ['malware'];
    case 'advisory': return ['vulnerability'];
    case 'news': return [];
    case 'osint': return [];
    default: return [];
  }
}
module.exports = { deriveFetchKind, categoryBucket, domainsForCategory };
