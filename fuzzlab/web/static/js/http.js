// fuzzlab control panel — shared network helpers (U0: MPA split).
// Small, framework-free helpers used by more than one section module
// (js/launcher.js, js/proxy.js). Kept dependency-free so any section can import
// just what it needs — no bundler, no build step.

// A <textarea> normalizes newlines to LF, but HTTP framing needs CRLF. Restore CRLF
// before sending an edited raw request/response (the API itself stays byte-exact — for
// deliberate LF-only / malformed framing use the CLI or API directly).
export function toWire(s) {
  return s.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n");
}

export async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty */ }
  return { status: r.status, data };
}

export async function delJSON(url) {
  const r = await fetch(url, { method: "DELETE" });
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty */ }
  return { status: r.status, data };
}

// Minimal Server-Sent Events helper for later phases (proxy events).
// Returns the EventSource so callers can close() it; onMessage gets parsed JSON
// when possible, else the raw string.
export function subscribe(url, onMessage, onError) {
  const es = new EventSource(url);
  es.onmessage = (ev) => {
    let data = ev.data;
    try { data = JSON.parse(ev.data); } catch (_) { /* keep raw */ }
    onMessage(data, ev);
  };
  if (onError) es.onerror = onError;
  return es;
}
