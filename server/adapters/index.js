const rss = require('./rss');
const text_feed = require('./text_feed');
const json_api = require('./json_api');
const abuse_ch = require('./abuse_ch');
const osv = require('./osv');
const misp_feed = require('./misp_feed');
const bespoke = require('./bespoke');

// Vulnetix has a dedicated adapter in bespoke.js (nested cvss fields + a misnamed
// "title" field that's actually the description — generic json_api mapping can't do
// either), so it's picked up via the ...bespoke spread below, not defined here.
const ADAPTERS = { rss, text_feed, json_api, abuse_ch, osv, misp_feed, ...bespoke };

function getAdapter(kind) {
  const a = ADAPTERS[kind];
  if (!a) throw new Error(`unknown adapter kind: ${kind}`);
  return a;
}

module.exports = { ADAPTERS, getAdapter };
