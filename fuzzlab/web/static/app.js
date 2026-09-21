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

// --- Proxy tab: flow history (read-only) ---
// Flow url/host/head come from recorded traffic (untrusted), so rows are built with
// DOM APIs and textContent — never string-interpolated HTML.
function initProxy() {
  const table = document.querySelector("#flow-table tbody");
  if (!table) return; // not the index page
  const empty = document.getElementById("flow-empty");
  const search = document.getElementById("flow-search");
  const detail = document.getElementById("flow-detail");

  async function showFlow(id) {
    const r = await fetch(`/api/proxy/flows/${id}`);
    if (!r.ok) return;
    const f = await r.json();
    document.getElementById("flow-detail-id").textContent = "#" + f.id;
    document.getElementById("flow-req").textContent = f.raw_request || "(none)";
    document.getElementById("flow-resp").textContent = f.raw_response || "(none)";
    detail.hidden = false;
  }

  async function load() {
    const q = search && search.value.trim();
    const r = await fetch("/api/proxy/flows" + (q ? "?q=" + encodeURIComponent(q) : ""));
    const flows = (await r.json()).flows || [];
    table.replaceChildren();
    for (const f of flows) {
      const tr = document.createElement("tr");
      tr.className = "flow-row";
      for (const v of [f.id, f.method, f.url, f.host, f.status, f.elapsed_ms, f.protocol]) {
        const td = document.createElement("td");
        td.textContent = v == null ? "" : String(v);
        tr.appendChild(td);
      }
      tr.addEventListener("click", () => showFlow(f.id));
      table.appendChild(tr);
    }
    if (empty) empty.hidden = flows.length > 0;
  }

  document.getElementById("flow-refresh").addEventListener("click", load);
  if (search) search.addEventListener("keydown", (e) => { if (e.key === "Enter") load(); });
  fetch("/api/proxy/status").then((r) => r.json()).then((s) => {
    const el = document.getElementById("proxy-status");
    if (!el) return;
    el.textContent = !s.configured ? "Proxy: not running in-process (history is still readable)."
      : s.running ? `Proxy: running on ${s.host}:${s.port} · intercept ${s.intercept ? "ON" : "off"} · ${s.pending} pending`
      : "Proxy: configured but not started.";
  }).catch(() => {});
  load();
}

// --- Proxy tab: live interception (pause / edit / drop / forward) ---
function initIntercept() {
  const card = document.getElementById("intercept-card");
  if (!card) return;
  const unavailable = document.getElementById("intercept-unavailable");
  const controls = document.getElementById("intercept-controls");
  const onBox = document.getElementById("intercept-on");
  const respBox = document.getElementById("intercept-resp");
  const count = document.getElementById("intercept-count");
  const tbody = document.querySelector("#pending-table tbody");
  const empty = document.getElementById("pending-empty");
  const detail = document.getElementById("pending-detail");
  const rawArea = document.getElementById("pending-raw");
  const idSpan = document.getElementById("pending-id");
  let selectedId = null;

  async function applyToggle() {
    await postJSON("/api/proxy/intercept",
      { on: onBox.checked, responses: respBox.checked });
    poll();
  }
  onBox.addEventListener("change", applyToggle);
  respBox.addEventListener("change", applyToggle);

  function selectFlow(f) {
    selectedId = f.id;
    idSpan.textContent = "#" + f.id + " (" + f.direction + ")";
    rawArea.value = f.raw;
    detail.hidden = false;
  }

  async function poll() {
    const r = await fetch("/api/proxy/intercept/pending");
    if (!r.ok) return;
    const pending = (await r.json()).pending || [];
    tbody.replaceChildren();
    for (const f of pending) {
      const tr = document.createElement("tr");
      tr.className = "flow-row";
      for (const v of [f.id, f.direction, f.method, f.target, f.host]) {
        const td = document.createElement("td");
        td.textContent = v == null ? "" : String(v);
        tr.appendChild(td);
      }
      tr.addEventListener("click", () => selectFlow(f));
      tbody.appendChild(tr);
    }
    empty.hidden = pending.length > 0;
    count.textContent = pending.length ? `· ${pending.length} held` : "";
    if (selectedId != null && !pending.some((f) => f.id === selectedId)) {
      detail.hidden = true; selectedId = null;   // it was forwarded/dropped elsewhere
    }
  }

  document.getElementById("pending-forward").addEventListener("click", async () => {
    if (selectedId == null) return;
    await postJSON(`/api/proxy/intercept/${selectedId}/forward`, { raw: rawArea.value });
    detail.hidden = true; selectedId = null; poll();
  });
  document.getElementById("pending-drop").addEventListener("click", async () => {
    if (selectedId == null) return;
    await postJSON(`/api/proxy/intercept/${selectedId}/drop`, {});
    detail.hidden = true; selectedId = null; poll();
  });

  fetch("/api/proxy/status").then((r) => r.json()).then((s) => {
    if (!s.configured) { unavailable.hidden = false; return; }
    controls.hidden = false;
    onBox.checked = !!s.intercept;
    respBox.checked = !!s.intercept_responses;
    poll();
    setInterval(poll, 1200);
  }).catch(() => {});
}

document.addEventListener("DOMContentLoaded", () => {
  initTabs(); initLaunchForms(); initProxy(); initIntercept();
});
