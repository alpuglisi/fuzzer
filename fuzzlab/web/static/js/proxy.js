// fuzzlab control panel — Proxy section (U3: proxy workbench rebuild).
//
// History, live Intercept, Repeater, and Scope/Match-Replace are sub-views of this
// one section/page, switched by an in-page sub-nav (a real APG "Tabs" pattern —
// no separate NAV routes; the Proxy route itself stays the one server-rendered
// page U0 gave it). Intercept and Repeater both render raw HTTP messages through
// the shared `<message-editor>` element (js/msgeditor.js); History's flow detail
// reuses it too (read-only) for a consistent redacted view. `toWire` (js/http.js)
// stays the single documented CRLF-restore point, applied only at the actual
// forward/send call sites — msgeditor.getBytes() itself never touches newlines.

import { postJSON, delJSON, toWire } from "./http.js";
import { attachSplitter } from "./msgeditor.js";

// --- sub-nav: History / Intercept / Repeater / Scope+Match-Replace ---------
// A standard APG "automatic activation" tabs widget, scoped to the Proxy page.
// State (which sub-tab is open) is kept in the URL hash so a reload, a deep link,
// or the "-> Repeater" pivot from History can all select a tab without a full
// page navigation (R-07's pattern, applied within a single MPA route).
function initSubnav() {
  const nav = document.querySelector(".subnav");
  if (!nav) return null;
  const tabs = Array.from(nav.querySelectorAll(".subnav-tab"));
  const panelOf = (btn) => document.getElementById(btn.getAttribute("aria-controls"));
  const nameOf = (btn) => btn.id.replace(/^subtab-/, "");

  function activate(name, { focus = false } = {}) {
    let matched = false;
    for (const btn of tabs) {
      const on = nameOf(btn) === name;
      matched = matched || on;
      btn.setAttribute("aria-selected", String(on));
      btn.tabIndex = on ? 0 : -1;
      panelOf(btn).hidden = !on;
      if (on && focus) btn.focus();
    }
    if (matched) history.replaceState(null, "", "#" + name);
    return matched;
  }

  tabs.forEach((btn, i) => {
    btn.addEventListener("click", () => activate(nameOf(btn)));
    btn.addEventListener("keydown", (e) => {
      let target = null;
      if (e.key === "ArrowRight") target = tabs[(i + 1) % tabs.length];
      else if (e.key === "ArrowLeft") target = tabs[(i - 1 + tabs.length) % tabs.length];
      else if (e.key === "Home") target = tabs[0];
      else if (e.key === "End") target = tabs[tabs.length - 1];
      if (target) { e.preventDefault(); activate(nameOf(target), { focus: true }); }
    });
  });

  const initial = (location.hash || "").slice(1);
  activate(tabs.some((b) => nameOf(b) === initial) ? initial : "history");
  return { activate };
}

// --- Proxy tab: flow history (read-only) ---
// Flow url/host/head come from recorded traffic (untrusted), so rows are built with
// DOM APIs and textContent — never string-interpolated HTML.
function initProxy(subnav) {
  const table = document.querySelector("#flow-table tbody");
  if (!table) return; // not the proxy page
  const empty = document.getElementById("flow-empty");
  const search = document.getElementById("flow-search");
  const detail = document.getElementById("flow-detail");
  const reqEditor = document.getElementById("flow-req-editor");
  const respEditor = document.getElementById("flow-resp-editor");
  let currentFlowId = null;

  const split = attachSplitter(document.getElementById("flow-split"),
    { orientKey: "fl-split-history" });
  document.getElementById("flow-layout-toggle").addEventListener("click", () => {
    const root = document.getElementById("flow-split");
    const next = root.dataset.orient === "horizontal" ? "vertical" : "horizontal";
    split.setOrient(next);
  });

  async function showFlow(id) {
    const r = await fetch(`/api/proxy/flows/${id}`);
    if (!r.ok) return;
    const f = await r.json();
    currentFlowId = f.id;
    document.getElementById("flow-detail-id").textContent = "#" + f.id;
    reqEditor.bytes = f.raw_request || "";
    respEditor.bytes = f.raw_response || "";
    respEditor.meta = { status: f.status, ms: f.elapsed_ms };
    detail.hidden = false;
  }

  const toRep = document.getElementById("flow-to-repeater");
  if (toRep) toRep.addEventListener("click", async () => {
    if (currentFlowId == null) return;
    const { status, data } = await postJSON(`/api/proxy/repeater/from-flow/${currentFlowId}`, {});
    if (status === 200) {
      document.dispatchEvent(new CustomEvent("repeater-select", { detail: data.id }));
      if (subnav) subnav.activate("repeater");
    }
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
  const card = document.getElementById("panel-intercept");
  if (!card) return;
  const unavailable = document.getElementById("intercept-unavailable");
  const controls = document.getElementById("intercept-controls");
  const onBox = document.getElementById("intercept-on");
  const respBox = document.getElementById("intercept-resp");
  const count = document.getElementById("intercept-count");
  const tbody = document.querySelector("#pending-table tbody");
  const empty = document.getElementById("pending-empty");
  const detail = document.getElementById("pending-detail");
  const editor = document.getElementById("pending-editor");
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
    editor.bytes = f.raw;
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
    await postJSON(`/api/proxy/intercept/${selectedId}/forward`, { raw: toWire(editor.getBytes()) });
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
  const card = document.getElementById("panel-repeater");
  if (!card) return;
  const select = document.getElementById("rep-tab-select");
  const editor = document.getElementById("rep-editor");
  const reqEditor = document.getElementById("rep-req-editor");
  const respEditor = document.getElementById("rep-resp-editor");
  const sendBtn = document.getElementById("rep-send");
  let tabs = [];

  const split = attachSplitter(document.getElementById("rep-split"),
    { orientKey: "fl-split-repeater" });
  document.getElementById("rep-layout-toggle").addEventListener("click", () => {
    const root = document.getElementById("rep-split");
    const next = root.dataset.orient === "horizontal" ? "vertical" : "horizontal";
    split.setOrient(next);
  });

  function selectId(id) {
    const tab = tabs.find((t) => String(t.id) === String(id));
    if (!tab) { editor.hidden = true; return; }
    select.value = String(id);
    reqEditor.bytes = tab.raw;
    respEditor.bytes = "";
    respEditor.meta = null;
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
    const started = performance.now();
    const { status, data } = await postJSON(`/api/proxy/repeater/tabs/${id}/send`,
      { raw: toWire(reqEditor.getBytes()) });
    const ms = Math.round(performance.now() - started);
    if (status === 200) {
      respEditor.bytes = data.response || "";
      respEditor.meta = { ms };
    } else {
      respEditor.meta = null;
      respEditor.bytes = "error: " + (data.error || status);
    }
  });

  document.addEventListener("repeater-select", (e) => loadTabs(e.detail));
  loadTabs();
}

// --- Proxy tab: Scope + Match-Replace ---
function initScope() {
  const card = document.getElementById("panel-scope");
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
  const subnav = initSubnav();
  initProxy(subnav);
  initIntercept();
  initRepeater();
  initScope();
});
