// Routes a non-CVE item to its category's playbook builder. server/playbook.js (the CVE builder)
// is unchanged and keeps handling any item that carries a CVE, regardless of category — this
// dispatcher only runs for items with no CVE, routing on `item.category`. Categories with no
// structured facts to ground a step on (advisory/osint/news/other, and any CVE item that reaches
// here with neither a CVE nor a CVSS vector) fall through to `null`, same as playbook.js's
// "not a CVE at all -> no playbook" rule.
const { buildRansomwarePlaybook } = require('./ransomware');
const { buildPhishingPlaybook } = require('./phishing');
const { buildMalwarePlaybook } = require('./malware');
const { buildDataBreachPlaybook } = require('./data-breach');
const { buildIocPlaybook } = require('./ioc');

function buildCategoryPlaybook(facts) {
  switch (facts.category) {
    case 'ransomware': return buildRansomwarePlaybook(facts);
    case 'phishing': return buildPhishingPlaybook(facts);
    case 'malware': return buildMalwarePlaybook(facts);
    case 'data-breach': return buildDataBreachPlaybook(facts);
    case 'ioc': return buildIocPlaybook(facts);
    default: return null;
  }
}

module.exports = { buildCategoryPlaybook };
