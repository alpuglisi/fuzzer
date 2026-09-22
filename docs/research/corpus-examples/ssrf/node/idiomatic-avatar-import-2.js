// Manufactured, representative of a common "import avatar from URL"
// feature (a real, widely-implemented UGC-platform convenience: paste a
// URL instead of uploading a file).
const ALLOWED_HOSTS = new Set(['i.imgur.com', 'cdn.discordapp.com', 'pbs.twimg.com']);

async function importAvatar(userSuppliedUrl) {
  const parsed = new URL(userSuppliedUrl);
  if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error('Avatar URL must be https and from an approved image host');
  }
  const res = await fetch(parsed.toString(), { redirect: 'error' });
  return res.arrayBuffer();
}
