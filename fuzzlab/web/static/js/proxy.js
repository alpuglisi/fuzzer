// Proxy section (U0/CC-UI-0025; re-laid on the shared message editor by U3/
// CC-UI-0030 · CC-PROXY-0018, R-04): History (read-only) + Intercept + Repeater +
// Scope/Match-Replace. Flow url/host/head come from recorded traffic (untrusted),
// so rows are built with DOM APIs and textContent — never string-interpolated
// HTML. The "send to Repeater" pivot is a real <form method="post"> to
// /proxy/repeater/from-flow (PRG + 303, R-07): this module only fills the hidden
// flow_id input before the browser submits it — no fetch, no seeded bytes in a URL.
//
// The held/active byte editors (History detail, Intercept, Repeater) are all
// `<message-editor>` instances (js/msgeditor.js) — importing it here registers
// the custom element. `getBytes()` still returns the plain-textarea value for
// the editable ones, so the existing `toWire()` CRLF-restore stays the single
// documented normalization point right before a byte-exact send.
import { postJSON, delJSON, toWire } from "/static/js/common.js";
import { attachSplitter } from "/static/js/msgeditor.js";

// Wire a request/response split pane + its "stack vertically" toggle button.
function initSplit(splitId, buttonId, storageKey) {
  const split = document.getElementById(splitId);
  if (!split) return;
  attachSplitter(split, { storageKey });
  const btn = document.getElementById(buttonId);
  if (!btn) return;
  btn.addEventListener("click", () => {
    const vertical = split.classList.toggle("vertical");
    btn.setAttribute("aria-pressed", String(vertical));
  });
}

// --- History (read-only) ---
function initProxy() {
  const table = document.querySelector("#flow-table tbody");
  if (!table) return; // not the proxy page
  const empty = document.getElementById("flow-empty");
  const search = document.getElementById("flow-search");
  const detail = document.getElementById("flow-detail");
  const toRepId = document.getElementById("flow-to-repeater-id");

  async function showFlow(id) {
    const r = await fetch(`/api/proxy/flows/${id}`);
    if (!r.ok) return;
    const f = await r.json();
    document.getElementById("flow-detail-id").textContent = "#" + f.id;
    const reqEd = document.getElementById("flow-req-editor");
    const respEd = document.getElementById("flow-resp-editor");
    reqEd.bytes = f.raw_request || "(none)";
    reqEd.meta = { label: "Request" };
    respEd.bytes = f.raw_response || "(none)";
    respEd.meta = { label: "Response", status: f.status, elapsed_ms: f.elapsed_ms };
    if (toRepId) toRepId.value = String(f.id);
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
  initSplit("flow-split", "flow-split-layout", "fuzzlab.proxy.flowSplit");
  fetch("/api/proxy/status").then((r) => r.json()).then((s) => {
    const el = document.getElementById("proxy-status");
    if (!el) return;
    el.textContent = !s.configured ? "Proxy: not running in-process (history is still readable)."
      : s.running ? `Proxy: running on ${s.host}:${s.port} · intercept ${s.intercept ? "ON" : "off"} · ${s.pending} pending`
      : "Proxy: configured but not started.";
  }).catch(() => {});
  load();
}

// --- Intercept (pause / edit / drop / forward) ---
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
    editor.meta = { label: f.direction === "response" ? "Response" : "Request" };
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

// --- Repeater (replay tabs) ---
function initRepeater() {
  const card = document.getElementById("repeater-card");
  if (!card) return;
  const select = document.getElementById("rep-tab-select");
  const editorWrap = document.getElementById("rep-editor");
  const reqEd = document.getElementById("rep-editor-msg");
  const respEd = document.getElementById("rep-resp-editor");
  const sendBtn = document.getElementById("rep-send");
  // The PRG "send to Repeater" pivot (R-07) lands back here with ?repeater_tab=ID —
  // an opaque hint, server-rendered onto the card; fall back to no selection if it
  // doesn't resolve to a live tab (never treat a query id as authoritative).
  const seedTab = card.dataset.repeaterTab || "";
  let tabs = [];

  function selectId(id) {
    const tab = tabs.find((t) => String(t.id) === String(id));
    if (!tab) { editorWrap.hidden = true; return; }
    select.value = String(id);
    reqEd.bytes = tab.raw;
    reqEd.meta = { label: "Request" };
    respEd.bytes = "";
    respEd.meta = { label: "Response" };
    editorWrap.hidden = false;
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
      { raw: toWire(reqEd.getBytes()) });
    respEd.bytes = status === 200 ? (data.response || "(empty)") : "error: " + (data.error || status);
    respEd.meta = { label: "Response" };
  });

  loadTabs(seedTab || null);
  initSplit("rep-split", "rep-split-layout", "fuzzlab.proxy.repSplit");
}

// --- Scope + Match-Replace ---
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
  initProxy(); initIntercept(); initRepeater(); initScope();
});
