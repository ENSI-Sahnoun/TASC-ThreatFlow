// Pure product -> plain-English role map. It answers "what does this thing hold or do for me",
// which is the noun the consequence sentence needs: "read, change and shut down YOUR COMPANY
// EMAIL" says something a non-expert can act on; "read, change and shut down exchange_server"
// does not.
//
// Same discipline as sector_profiles.js: every rule below was verified against item_cpes before
// being added, and carries its measured reference count. A rule that matches nothing is worse
// than an omission — it makes coverage look richer than it is while describing no real item.
//
// ORDERED RULES, NOT AN EXACT-KEY MAP. CPE product slugs are version-specific
// (windows_11_25h2, windows_10_22h2, office_2021, exchange_server_subscription_edition), so an
// exact map would need dozens of Windows entries and would silently miss next year's. Each rule
// matches a vendor exactly and a product by prefix, and the FIRST match wins — which is why
// windows_server_ is listed before windows_ (a server is not a staff desktop) and why the
// general windows rule sits last among Microsoft's.
//
// Reference counts measured 2026-08-03 against item_cpes.
const RULES = [
  // --- Microsoft. Order matters within this block. ---
  { vendor: 'microsoft', prefix: 'windows_server_', role: 'your Windows servers', refs: 1881 },
  { vendor: 'microsoft', prefix: 'exchange_server', role: 'your company email', refs: 22 },
  { vendor: 'microsoft', prefix: 'exchange_online', role: 'your company email', refs: 1 },
  { vendor: 'microsoft', prefix: 'sharepoint', role: 'your internal document sharing', refs: 40 },
  { vendor: 'microsoft', prefix: 'sql_server', role: 'a database your systems rely on', refs: 24 },
  { vendor: 'microsoft', prefix: 'office', role: 'the documents your staff open', refs: 268 },
  { vendor: 'microsoft', prefix: '365_apps', role: 'the documents your staff open', refs: 77 },
  { vendor: 'microsoft', prefix: 'microsoft_365', role: 'the documents your staff open', refs: 72 },
  { vendor: 'microsoft', prefix: 'excel', role: 'the documents your staff open', refs: 31 },
  // Last among Microsoft's: windows_ would otherwise swallow windows_server_.
  { vendor: 'microsoft', prefix: 'windows', role: 'the computers your staff use', refs: 3434 },

  // --- Operating systems that are, in practice, servers. ---
  { vendor: 'linux', prefix: 'linux_kernel', role: 'your servers', refs: 853 },
  { vendor: 'debian', prefix: 'debian_linux', role: 'your servers', refs: 231 },
  { vendor: 'redhat', prefix: 'enterprise_linux', role: 'your servers', refs: 37 },

  // --- Apple. Desktop and mobile are different exposure stories, so different roles. ---
  { vendor: 'apple', prefix: 'macos', role: 'the Macs your staff use', refs: 267 },
  { vendor: 'apple', prefix: 'iphone_os', role: 'the phones and tablets your staff use', refs: 145 },
  { vendor: 'apple', prefix: 'ipados', role: 'the phones and tablets your staff use', refs: 123 },
  { vendor: 'apple', prefix: 'watchos', role: 'the watches your staff wear', refs: 66 },
  { vendor: 'apple', prefix: 'safari', role: 'the browser your staff use', refs: 39 },
  { vendor: 'google', prefix: 'android', role: 'the phones your staff use', refs: 59 },

  // --- Browsers and mail clients: the software that opens untrusted content. ---
  { vendor: 'google', prefix: 'chrome', role: 'the browser your staff use', refs: 131 },
  { vendor: 'mozilla', prefix: 'firefox', role: 'the browser your staff use', refs: 66 },
  { vendor: 'mozilla', prefix: 'thunderbird', role: 'the email app your staff use', refs: 56 },

  // --- Data stores. ---
  { vendor: 'oracle', prefix: 'mysql', role: 'a database your systems rely on', refs: 92 },
  { vendor: 'postgresql', prefix: 'postgresql', role: 'a database your systems rely on', refs: 3 },

  // --- Things that face the internet by design. ---
  { vendor: 'apache', prefix: 'http_server', role: 'your public website', refs: 4 },
  { vendor: 'oracle', prefix: 'http_server', role: 'your public website', refs: 5 },
  { vendor: 'fortinet', prefix: 'fortios', role: 'your VPN and firewall', refs: 8 },
  { vendor: 'fortinet', prefix: 'fortiproxy', role: 'your VPN and firewall', refs: 7 },
];

// Vendor and product are the lowercase CPE fields, so matching happens on exactly what
// item_cpes stores. Anything unmapped yields null and the caller names the product directly
// rather than inventing a role for it.
function roleFor(vendor, product) {
  if (typeof vendor !== 'string' || typeof product !== 'string') return null;
  const rule = RULES.find((r) => r.vendor === vendor && product.startsWith(r.prefix));
  return rule ? rule.role : null;
}

module.exports = { roleFor, RULES };
