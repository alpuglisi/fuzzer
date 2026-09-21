// fuzzlab control panel — client shell.
// Progressive enhancement: with JS off, every panel renders (nothing is hidden);
// with JS on, the tab nav shows one panel at a time.

const PANELS = () => Array.from(document.querySelectorAll(".panel"));
const TABS = () => Array.from(document.querySelectorAll("nav.tabs a"));

function activate(name) {
  let matched = false;
  for (const panel of PANELS()) {
    const on = panel.id === `tab-${name}`;
    panel.classList.toggle("hidden", !on);
    matched = matched || on;
  }
  for (const tab of TABS()) {
    tab.classList.toggle("active", tab.dataset.tab === name);
  }
  return matched;
}

function currentTab() {
  const hash = (location.hash || "").replace(/^#/, "");
  return hash || "launcher";
}

function initTabs() {
  const tabs = TABS();
  if (tabs.length === 0) return; // not the index page
  if (!activate(currentTab())) activate("launcher");
  window.addEventListener("hashchange", () => {
    if (!activate(currentTab())) activate("launcher");
  });
}

// Minimal Server-Sent Events helper for later phases (runner output, proxy events).
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

document.addEventListener("DOMContentLoaded", initTabs);
