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

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty */ }
  return { status: r.status, data };
}

// Read a launch form into a {dest: value} map the /api/launch* endpoints expect.
function collectValues(form) {
  const values = {};
  for (const el of form.querySelectorAll("[data-dest]")) {
    const dest = el.dataset.dest;
    if (el.dataset.type === "bool") {
      if (el.checked) values[dest] = true;
    } else if (el.dataset.multiple === "true") {
      const lines = el.value.split("\n").map((s) => s.trim()).filter(Boolean);
      if (lines.length) values[dest] = lines;
    } else if (el.value !== "" && el.value != null) {
      values[dest] =
        el.dataset.type === "int" ? parseInt(el.value, 10)
        : el.dataset.type === "float" ? parseFloat(el.value)
        : el.value;
    }
  }
  // category picker (D14): checked boxes → a comma-joined --categories value
  for (const group of form.querySelectorAll("[data-catgroup]")) {
    const checked = Array.from(group.querySelectorAll("input:checked")).map((i) => i.value);
    if (checked.length) values[group.dataset.catgroup] = checked.join(",");
  }
  return values;
}

function initLaunchForms() {
  for (const form of document.querySelectorAll("form.launch-form")) {
    const command = form.dataset.command;
    const preview = form.querySelector(".launch-preview");
    const output = form.querySelector(".launch-output");
    const runBtn = form.querySelector('[data-action="run"]');
    const stopBtn = form.querySelector('[data-action="stop"]');
    let es = null, token = null;

    form.querySelector('[data-action="dry-run"]').addEventListener("click", async () => {
      const { data } = await postJSON("/api/launch/dry-run",
        { command, values: collectValues(form) });
      preview.hidden = false;
      preview.textContent = data.display || (data.error ? "error: " + data.error : "");
    });

    if (runBtn) runBtn.addEventListener("click", async () => {
      output.hidden = false;
      output.textContent = "";
      const { status, data } = await postJSON("/api/launch",
        { command, values: collectValues(form) });
      if (status !== 200) {
        output.textContent = "error: " + (data.error || status);
        return;
      }
      token = data.token;
      stopBtn.disabled = false;
      es = new EventSource(`/api/launch/${token}/stream`);
      es.addEventListener("output", (e) => { output.textContent += e.data + "\n"; });
      es.addEventListener("done", (e) => {
        let rc = "";
        try { rc = JSON.parse(e.data).returncode; } catch (_) { /* ignore */ }
        output.textContent += `\n[exit ${rc}]`;
        es.close(); stopBtn.disabled = true;
      });
      es.addEventListener("error", () => { es.close(); stopBtn.disabled = true; });
    });

    if (stopBtn) stopBtn.addEventListener("click", async () => {
      if (token) await postJSON(`/api/launch/${token}/stop`, {});
    });
  }
}

document.addEventListener("DOMContentLoaded", () => { initTabs(); initLaunchForms(); });
