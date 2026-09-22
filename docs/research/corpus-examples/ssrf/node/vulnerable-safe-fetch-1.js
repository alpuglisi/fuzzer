// Manufactured vulnerable variant, derived from idiomatic-safe-fetch-1.js.
// Illustrates the common real-world anti-pattern: the extracted URL
// (from metascraper's real rule, or any equivalent "fetch this link
// preview" feature) is passed straight to an HTTP client with no scheme
// check, no DNS-resolved-address check, and redirects auto-followed.

async function fetchLinkPreview(candidateUrl) {
  // No scheme allowlist, no private/loopback IP check, redirects followed
  // by default -- an attacker can post content whose og:url points at
  // http://169.254.169.254/latest/meta-data/ (cloud metadata service) or
  // http://localhost:6379/ (an internal service) and the server fetches it.
  return fetch(candidateUrl);
}
