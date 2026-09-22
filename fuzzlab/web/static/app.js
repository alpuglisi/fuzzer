// fuzzlab control panel — client shell.
// R1 (docs/UI_LAYOUT_REDESIGN.md): each section is its own real route/page (an MPA,
// not a client router); the sidebar nav marks the active section server-side
// (base.html, from the `section` context var). Progressive enhancement per page:
// with JS off, a page's controls (forms, links) still work; JS adds live behavior
// (dry-run/run/SSE output, the proxy workbench polling) on top.

// --- app shell: theme / density / sidebar persistence + proxy status chip ---
// All chrome; it touches no invariant. Preferences persist in localStorage (wrapped
// in try/catch: a private window or blocked storage must never break the page). Theme
// and density live on <html> so tokens.css resolves them; the no-FOUC <head> script
// applies them before first paint, and this only handles clicks afterwards.
function initShell() {
  const root = document.documentElement;
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (_) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (_) { /* ignore */ } },
    del(k) { try { localStorage.removeItem(k); } catch (_) { /* ignore */ } },
  };

  // theme: system (no attr) → light → dark → system
  const theme = document.getElementById("theme-toggle");
  if (theme) theme.addEventListener("click", () => {
    const cur = root.getAttribute("data-theme");
    const next = cur === "light" ? "dark" : cur === "dark" ? null : "light";
    if (next) { root.setAttribute("data-theme", next); store.set("fl-theme", next); }
    else { root.removeAttribute("data-theme"); store.del("fl-theme"); }
  });

  // density: comfortable (no attr) ↔ compact
  const density = document.getElementById("density-toggle");
  if (density) density.addEventListener("click", () => {
    if (root.getAttribute("data-density") === "compact") {
      root.removeAttribute("data-density"); store.del("fl-density");
    } else {
      root.setAttribute("data-density", "compact"); store.set("fl-density", "compact");
    }
  });

  // sidebar collapse
  const collapse = document.getElementById("sidebar-toggle");
  if (collapse) collapse.addEventListener("click", () => {
    if (root.getAttribute("data-collapsed") === "1") {
      root.removeAttribute("data-collapsed"); store.del("fl-collapsed");
    } else {
      root.setAttribute("data-collapsed", "1"); store.set("fl-collapsed", "1");
    }
  });

  // proxy status chip (topbar): a compact mirror of /api/proxy/status
  const chip = document.getElementById("proxy-chip");
  if (chip) fetch("/api/proxy/status").then((r) => r.json()).then((s) => {
    const led = chip.querySelector(".led");
    let label = "proxy off", cls = "led off";
    if (!s.configured) { label = "proxy: history only"; cls = "led off"; }
    else if (s.running) {
      label = `proxy ${s.host}:${s.port}` + (s.intercept ? " · intercept" : "");
      cls = "led on";
    } else { label = "proxy: stopped"; cls = "led warn"; }
    chip.textContent = "";
    if (led) { led.className = cls; chip.appendChild(led); }
    chip.appendChild(document.createTextNode(" " + label));
  }).catch(() => {});
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

// --- Launch view: master (activity picker) → detail (one form shown) ---
// Every activity's detail renders server-side; with JS on we show one at a time and let the
// left list switch between them (no-JS shows all — same progressive-enhancement rule as tabs).
function initLaunchNav() {
  const acts = Array.from(document.querySelectorAll(".actlist .act"));
  const details = Array.from(document.querySelectorAll(".lform-detail"));
  if (!acts.length || !details.length) return;

  function select(name) {
    let matched = false;
    for (const d of details) {
      const on = d.dataset.for === name;
      d.classList.toggle("hidden", !on);
      matched = matched || on;
    }
    for (const a of acts) a.classList.toggle("sel", a.dataset.for === name);
    return matched;
  }

  for (const a of acts) {
    a.addEventListener("click", (e) => { e.preventDefault(); select(a.dataset.for); });
  }
  // Default to `auto` when present (the full pipeline), else the first activity.
  const prefer = acts.find((a) => a.dataset.for === "auto") || acts[0];
  select(prefer.dataset.for);
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

// --- Proxy workbench: shared message editor (Pretty / Raw / Hex) (R3) ---
// One reusable component wraps every raw-bytes surface (History's request/response,
// Intercept's held-flow editor, Repeater's request/response) per
// docs/UI_LAYOUT_REDESIGN.md's "one reusable message editor everywhere" borrow from
// Burp/ZAP. "Raw" is the actual edit/display surface (the pre-existing textarea/pre,
// same id as before this rebuild — no wiring changed); "Pretty"/"Hex" are read-only
// views computed client-side from that same text on demand, never sent anywhere.
function hexDump(text) {
  if (!text) return "(empty)";
  const lines = [];
  for (let off = 0; off < text.length; off += 16) {
    const chunk = text.slice(off, off + 16);
    const bytes = [];
    for (let i = 0; i < chunk.length; i++) bytes.push(chunk.charCodeAt(i) & 0xff);
    const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = bytes.map((b) => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".").join("");
    lines.push(off.toString(16).padStart(8, "0") + "  " + hex.padEnd(47, " ") + "  " + ascii);
  }
  return lines.join("\n");
}

function renderPretty(text) {
  if (!text) return "(empty)";
  const m = text.match(/\r?\n\r?\n/);
  const head = m ? text.slice(0, m.index) : text;
  const body = m ? text.slice(m.index + m[0].length) : "";
  const lines = head.split(/\r?\n/).filter((l, i) => i === 0 || l.length);
  let out = (lines[0] || "") + "\n";
  for (const h of lines.slice(1)) out += "  " + h + "\n";
  if (body) out += "\n" + body;
  return out;
}

// Wire one `.msg-editor` root: clicking a tab shows its panel and (for the derived
// Pretty/Hex views) renders it from the raw panel's current text. Idempotent — safe
// to call more than once on the same root.
function wireMsgEditor(root) {
  if (!root || root.dataset.mvWired) return;
  root.dataset.mvWired = "1";
  const panels = {
    raw: root.querySelector('[data-mv-panel="raw"]'),
    pretty: root.querySelector('[data-mv-panel="pretty"]'),
    hex: root.querySelector('[data-mv-panel="hex"]'),
  };
  if (!panels.raw) return;
  function rawText() {
    return "value" in panels.raw ? panels.raw.value : panels.raw.textContent;
  }
  function activate(view) {
    for (const t of root.querySelectorAll(".mv-tab")) t.classList.toggle("active", t.dataset.mv === view);
    for (const [name, el] of Object.entries(panels)) if (el) el.hidden = name !== view;
    if (view === "pretty" && panels.pretty) panels.pretty.textContent = renderPretty(rawText());
    if (view === "hex" && panels.hex) panels.hex.textContent = hexDump(rawText());
  }
  for (const t of root.querySelectorAll(".mv-tab")) {
    t.addEventListener("click", () => activate(t.dataset.mv));
  }
  // exposed so code that sets the raw panel's content afresh (a new flow/tab loaded)
  // can re-render whichever view is currently active.
  root._flRefresh = () => {
    const active = root.querySelector(".mv-tab.active");
    activate(active ? active.dataset.mv : "raw");
  };
}

function initMessageEditors() {
  document.querySelectorAll(".msg-editor").forEach(wireMsgEditor);
}

// Call after setting a raw panel's content by id, so an already-active Pretty/Hex tab
// re-renders from the new text instead of showing the previous flow's derived view.
function refreshMsgEditor(id) {
  const el = document.getElementById(id);
  const root = el && el.closest(".msg-editor");
  if (root && root._flRefresh) root._flRefresh();
}

// --- Proxy workbench: sub-nav (History / Intercept / Repeater / Scope) (R3) ---
// A Burp/ZAP-style sub-nav inside the one /proxy document (MPA — no client router);
// the active sub-tab is reflected in `?tab=` via history.replaceState so it stays
// deep-linkable/bookmarkable without a full navigation.
function initProxySubnav() {
  const nav = document.querySelector(".proxy-subnav");
  if (!nav) return; // not the proxy page
  const buttons = Array.from(nav.querySelectorAll("button[data-tab]"));
  const panels = Array.from(document.querySelectorAll(".subnav-panel[data-panel]"));
  function show(tab) {
    for (const b of buttons) b.classList.toggle("active", b.dataset.tab === tab);
    for (const p of panels) p.hidden = p.dataset.panel !== tab;
  }
  for (const b of buttons) b.addEventListener("click", () => {
    show(b.dataset.tab);
    try {
      const params = new URLSearchParams(window.location.search);
      params.set("tab", b.dataset.tab);
      history.replaceState(null, "", "?" + params.toString());
    } catch (e) { /* history API unavailable; tab still switches visually */ }
  });
  const params = new URLSearchParams(window.location.search);
  const want = params.get("tab");
  show(buttons.some((b) => b.dataset.tab === want) ? want : "history");
}

// Selects a proxy sub-nav tab programmatically (e.g. a deep-link that must land on a
// specific sub-tab, such as `?repeater_tab=` always meaning the Repeater tab).
function selectProxyTab(tab) {
  const btn = document.querySelector(`.proxy-subnav button[data-tab="${tab}"]`);
  if (btn) btn.click();
}

// --- Proxy workbench: resizable list|detail split panes (R3) ---
// A drag handle between a table (list) and its detail pane, persisting the chosen
// list-column width per split id in localStorage (a per-viewer convenience, wrapped
// in try/catch so a blocked/absent store just falls back to the CSS default).
function initSplitResizers() {
  document.querySelectorAll(".split").forEach((split) => {
    const handle = split.querySelector(".split-resizer");
    if (!handle || handle.dataset.wired) return;
    handle.dataset.wired = "1";
    const key = "fl-split-" + (split.dataset.splitId || "default");
    try {
      const saved = parseInt(localStorage.getItem(key) || "", 10);
      if (saved > 0) split.style.setProperty("--split-a", saved + "px");
    } catch (e) { /* ignore */ }
    let dragging = false;
    handle.addEventListener("mousedown", (e) => {
      dragging = true; handle.classList.add("dragging"); e.preventDefault();
    });
    document.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      const rect = split.getBoundingClientRect();
      const w = Math.max(200, Math.min(rect.width - 220, e.clientX - rect.left));
      split.style.setProperty("--split-a", w + "px");
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false; handle.classList.remove("dragging");
      try {
        const w = parseInt(getComputedStyle(split).getPropertyValue("--split-a"), 10);
        if (w > 0) localStorage.setItem(key, String(w));
      } catch (e) { /* ignore */ }
    });
  });
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
    refreshMsgEditor("flow-req"); refreshMsgEditor("flow-resp");
    detail.hidden = false;
    const placeholder = document.getElementById("history-detail-empty");
    if (placeholder) placeholder.hidden = true;
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

  function hideDetail() {
    detail.hidden = true;
    const placeholder = document.getElementById("pending-detail-empty");
    if (placeholder) placeholder.hidden = false;
  }

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
    refreshMsgEditor("pending-raw");
    detail.hidden = false;
    const placeholder = document.getElementById("pending-detail-empty");
    if (placeholder) placeholder.hidden = true;
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
      hideDetail(); selectedId = null;   // it was forwarded/dropped elsewhere
    }
  }

  document.getElementById("pending-forward").addEventListener("click", async () => {
    if (selectedId == null) return;
    await postJSON(`/api/proxy/intercept/${selectedId}/forward`, { raw: toWire(rawArea.value) });
    hideDetail(); selectedId = null; poll();
  });
  document.getElementById("pending-drop").addEventListener("click", async () => {
    if (selectedId == null) return;
    await postJSON(`/api/proxy/intercept/${selectedId}/drop`, {});
    hideDetail(); selectedId = null; poll();
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
    refreshMsgEditor("rep-raw"); refreshMsgEditor("rep-resp");
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
    refreshMsgEditor("rep-resp");
  });

  document.addEventListener("repeater-select", (e) => loadTabs(e.detail));
  // Deep-link from a finding's "→ Repeater" pivot (R2): /proxy?repeater_tab=<id>
  // selects the tab created just before the redirect (MPA — no client router, so
  // the created-tab id travels as a query param instead of an in-page event).
  const params = new URLSearchParams(window.location.search);
  const wantTab = params.get("repeater_tab");
  if (wantTab != null) selectProxyTab("repeater");
  loadTabs(wantTab != null ? wantTab : undefined);
}

// --- Findings workbench (R2): facets are plain GET params (server-rendered,
// deep-linkable); saved views are per-viewer localStorage of a name -> querystring,
// wrapped in try/catch so a blocked/absent localStorage just disables the feature. ---
function initFindings() {
  const select = document.getElementById("view-select");
  if (!select) return; // not the findings page
  const KEY = "fl-findings-views";

  function load() {
    try {
      return JSON.parse(localStorage.getItem(KEY) || "{}");
    } catch (e) { return {}; }
  }
  function save(views) {
    try { localStorage.setItem(KEY, JSON.stringify(views)); } catch (e) { /* degrade */ }
  }
  function refresh() {
    const views = load();
    select.replaceChildren(new Option("— select a saved view —", ""));
    for (const name of Object.keys(views).sort()) select.appendChild(new Option(name, name));
  }

  select.addEventListener("change", () => {
    const views = load();
    if (select.value && views[select.value] != null) {
      window.location.search = views[select.value];
    }
  });
  const saveBtn = document.getElementById("view-save");
  if (saveBtn) saveBtn.addEventListener("click", () => {
    const nameEl = document.getElementById("view-name");
    const name = (nameEl.value || "").trim();
    if (!name) return;
    const views = load();
    views[name] = window.location.search.replace(/^\?/, "");
    save(views);
    nameEl.value = "";
    refresh();
    select.value = name;
  });
  const delBtn = document.getElementById("view-delete");
  if (delBtn) delBtn.addEventListener("click", () => {
    if (!select.value) return;
    const views = load();
    delete views[select.value];
    save(views);
    refresh();
  });
  refresh();
}

// --- Finding detail: "send to Repeater" pivot (R2) ---
function initFindingDetail() {
  const btn = document.getElementById("to-repeater");
  if (!btn) return; // not a finding detail page
  const status = document.getElementById("to-repeater-status");
  btn.addEventListener("click", async () => {
    const id = btn.dataset.findingId;
    status.textContent = "sending…";
    const { status: code, data } = await postJSON(`/api/proxy/repeater/from-finding/${id}`, {});
    if (code === 200) {
      window.location.href = `/proxy?repeater_tab=${encodeURIComponent(data.id)}`;
    } else {
      status.textContent = "error: " + (data.error || code);
    }
  });
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
  initShell();
  initLaunchNav(); initLaunchForms();
  initProxySubnav(); initMessageEditors(); initSplitResizers();
  initProxy(); initIntercept(); initRepeater(); initScope();
  initFindings(); initFindingDetail();
});
