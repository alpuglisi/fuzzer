// Manufactured vulnerable variant, derived from
// idiomatic-avatar-import-2.js. No host allowlist at all -- any URL the
// user supplies is fetched server-side.
async function importAvatar(userSuppliedUrl) {
  // No hostname allowlist, no protocol restriction: a URL like
  // "http://internal-admin.corp:8080/export" is fetched with the
  // server's own network position/credentials, not the requesting
  // user's.
  const res = await fetch(userSuppliedUrl);
  return res.arrayBuffer();
}
