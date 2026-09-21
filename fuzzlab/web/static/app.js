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

// A <textarea> normalizes newlines to LF, but HTTP framing needs CRLF. Restore CRLF
// before sending an edited raw request/response (the API itself stays byte-exact — for
// deliberate LF-only / malformed framing use the CLI or API directly).
function toWire(s) {
  return s.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n");
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

async function delJSON(url) {
  const r = await fetch(url, { method: "DELETE" });
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
  let currentFlowId = null;

  async function showFlow(id) {
    const r = await fetch(`/api/proxy/flows/${id}`);
    if (!r.ok) return;
    const f = await r.json();
    currentFlowId = f.id;
    document.getElementById("flow-detail-id").textContent = "#" + f.id;
    document.getElementById("flow-req").textContent = f.raw_request || "(none)";
    document.getElementById("flow-resp").textContent = f.raw_response || "(none)";
    detail.hidden = false;
  }

  const toRep = document.getElementById("flow-to-repeater");
  if (toRep) toRep.addEventListener("click", async () => {
    if (currentFlowId == null) return;
    const { status, data } = await postJSON(`/api/proxy/repeater/from-flow/${currentFlowId}`, {});
    if (status === 200) document.dispatchEvent(
      new CustomEvent("repeater-select", { detail: data.id }));
  });

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
    await postJSON(`/api/proxy/intercept/${selectedId}/forward`, { raw: toWire(rawArea.value) });
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

// --- Proxy tab: Repeater (replay tabs) ---
function initRepeater() {
  const card = document.getElementById("repeater-card");
  if (!card) return;
  const select = document.getElementById("rep-tab-select");
  const editor = document.getElementById("rep-editor");
  const rawArea = document.getElementById("rep-raw");
  const respPre = document.getElementById("rep-resp");
  const sendBtn = document.getElementById("rep-send");
  let tabs = [];

  function selectId(id) {
    const tab = tabs.find((t) => String(t.id) === String(id));
    if (!tab) { editor.hidden = true; return; }
    select.value = String(id);
    rawArea.value = tab.raw;
    respPre.textContent = "";
    editor.hidden = false;
  }

  async function loadTabs(thenSelect) {
    tabs = ((await (await fetch("/api/proxy/repeater/tabs")).json()).tabs) || [];
    select.replaceChildren(new Option("— select a tab —", ""));
    for (const t of tabs) {
      select.appendChild(new Option(`#${t.id} ${t.name} — ${t.host}:${t.port}`, String(t.id)));
    }
    if (thenSelect != null) selectId(thenSelect);
  }

  select.addEventListener("change", () => selectId(select.value));
  document.getElementById("rep-refresh").addEventListener("click", () => loadTabs());

  document.getElementById("rep-create").addEventListener("click", async () => {
    const { data } = await postJSON("/api/proxy/repeater/tabs", {
      name: document.getElementById("rep-new-name").value,
      host: document.getElementById("rep-new-host").value || "127.0.0.1",
      port: parseInt(document.getElementById("rep-new-port").value || "80", 10),
      use_tls: document.getElementById("rep-new-tls").checked,
      raw: document.getElementById("rep-new-raw").value,
    });
    await loadTabs(data.id);
  });

  if (sendBtn) sendBtn.addEventListener("click", async () => {
    const id = select.value;
    if (!id) return;
    const { status, data } = await postJSON(`/api/proxy/repeater/tabs/${id}/send`,
      { raw: toWire(rawArea.value) });
    respPre.textContent = status === 200 ? (data.response || "(empty)")
      : "error: " + (data.error || status);
  });

  document.addEventListener("repeater-select", (e) => loadTabs(e.detail));
  loadTabs();
}

// --- Proxy tab: Scope + Match-Replace ---
function initScope() {
  const card = document.getElementById("scope-card");
  if (!card) return;
  const unavailable = document.getElementById("scope-unavailable");
  const controls = document.getElementById("scope-controls");
  const scopeBody = document.querySelector("#scope-table tbody");
  const mrBody = document.querySelector("#mr-table tbody");
  const mrError = document.getElementById("mr-error");

  function actionCell(label, fn) {
    const td = document.createElement("td");
    const btn = document.createElement("button");
    btn.type = "button"; btn.textContent = label;
    btn.addEventListener("click", fn);
    td.appendChild(btn);
    return td;
  }
  function row(cells) {
    const tr = document.createElement("tr");
    for (const c of cells) {
      if (c instanceof HTMLElement) { tr.appendChild(c); continue; }
      const td = document.createElement("td");
      td.textContent = c == null ? "" : String(c);
      tr.appendChild(td);
    }
    return tr;
  }

  function renderScope(rules) {
    scopeBody.replaceChildren();
    for (const r of rules) {
      scopeBody.appendChild(row([r.index, r.host, r.path_regex || "",
        r.exclude ? "exclude" : "include",
        actionCell("Remove", async () => renderScope(
          (await delJSON(`/api/proxy/scope/${r.index}`)).data.scope || []))]));
    }
  }
  function renderMR(rules) {
    mrBody.replaceChildren();
    for (const r of rules) {
      mrBody.appendChild(row([r.index, r.target, r.header_name || "",
        `${r.match} → ${r.replace}`, r.is_regex ? "yes" : "",
        actionCell(r.enabled ? "on" : "off", async () => renderMR(
          (await postJSON(`/api/proxy/matchreplace/${r.index}/toggle`,
            { enabled: !r.enabled })).data.rules || [])),
        actionCell("Remove", async () => renderMR(
          (await delJSON(`/api/proxy/matchreplace/${r.index}`)).data.rules || []))]));
    }
  }

  document.getElementById("scope-add").addEventListener("click", async () => {
    const { data } = await postJSON("/api/proxy/scope", {
      host: document.getElementById("scope-host").value,
      path_regex: document.getElementById("scope-path").value,
      exclude: document.getElementById("scope-exclude").checked,
    });
    if (data.scope) renderScope(data.scope);
  });
  document.getElementById("mr-add").addEventListener("click", async () => {
    mrError.textContent = "";
    const { status, data } = await postJSON("/api/proxy/matchreplace", {
      target: document.getElementById("mr-target").value,
      header_name: document.getElementById("mr-header").value,
      match: document.getElementById("mr-match").value,
      replace: document.getElementById("mr-replace").value,
      is_regex: document.getElementById("mr-regex").checked,
    });
    if (status === 200) renderMR(data.rules || []);
    else mrError.textContent = data.error || ("error " + status);
  });

  fetch("/api/proxy/status").then((r) => r.json()).then(async (s) => {
    if (!s.configured) { unavailable.hidden = false; return; }
    controls.hidden = false;
    renderScope(((await (await fetch("/api/proxy/scope")).json()).scope) || []);
    renderMR(((await (await fetch("/api/proxy/matchreplace")).json()).rules) || []);
  }).catch(() => {});
}

document.addEventListener("DOMContentLoaded", () => {
  initTabs(); initLaunchForms(); initProxy(); initIntercept(); initRepeater(); initScope();
});
