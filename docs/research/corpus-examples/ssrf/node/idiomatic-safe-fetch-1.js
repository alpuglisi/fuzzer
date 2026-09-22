// Real upstream excerpt (metascraper, packages/metascraper-url/src/index.js,
// MIT, repo microlinkhq/metascraper, commit
// b3e17a907db0abbd141d6ee5a85f731ef429ecfc) plus a manufactured safe
// caller wrapping it. metascraper's own rule only *extracts* a URL string
// from page metadata (og:url/twitter:url/canonical link) attacker-
// influenced HTML can set -- extraction alone is neither vulnerable nor
// protective; the caller below is what actually fetches, and is where
// the real security decision (validate before fetch) has to happen.

// --- real upstream extraction rule (unmodified) ---
const toUrl = toRule(urlFn)
const urlRule = [
  toUrl($meta('og:url')),
  toUrl($meta('twitter:url')),
  toUrl($ => $('link[rel="canonical"]').attr('href')),
]

// --- manufactured safe caller ---
const { URL } = require('url')
const dns = require('dns').promises
const net = require('net')

async function fetchLinkPreview(candidateUrl) {
  const parsed = new URL(candidateUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Disallowed URL scheme');
  }

  const { address } = await dns.lookup(parsed.hostname);
  if (isPrivateOrLoopback(address)) {
    throw new Error('Refusing to fetch a private/loopback address');
  }

  return fetch(candidateUrl, { redirect: 'error' }); // no auto-follow either
}

function isPrivateOrLoopback(ip) {
  return (
    net.isIP(ip) &&
    (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('169.254.') ||
      ip === '::1' || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip))
  );
}
