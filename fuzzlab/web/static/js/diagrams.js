// Diagrams (FR-UI-510): the run's data flow and sequences, drawn from the persisted trace
// model through the read-only /api/diagram/* routes.
//
// Safety: every label comes from a live target or a capture (paths, parameter names,
// host names, UI labels). Everything is rendered with textContent / createElementNS --
// this module never parses HTML or SVG strings (tests/test_web_diagrams.py checks).

const NS = "http://www.w3.org/2000/svg";
const ROW = 22;          // an interface row
const STEP = 28;         // a sequence step
const COL = 190;         // a sequence participant column
const EXPAND_ALL_UNDER = 30;   // interfaces: below this many, every origin starts open

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function svg(tag, attrs = {}, text) {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    node.setAttribute(k, String(v));
  }
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clip(text, n) {
  const s = String(text ?? "");
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function titled(node, text) {
  node.append(svg("title", {}, text));
  return node;
}

async function api(path) {
  const r = await fetch(path, { headers: { "X-Fuzzlab-Client": "1" } });
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.json();
}

function fmtTime(t) {
  if (t === null || t === undefined) return "unknown";
  return new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function initDiagrams() {
  const root = document.getElementById("diagrams-root");
  if (!root) return;
  const $ = (id) => document.getElementById(id);
  const runSel = $("dg-run"), originSel = $("dg-origin"), knowSel = $("dg-knowledge");
  const findingSel = $("dg-finding"), overlayBox = $("dg-overlay"), scopeSel = $("dg-scope");
  const pollMs = Math.max(500, parseInt(root.dataset.pollMs || "3000", 10) || 3000);
  const state = { run: null, expanded: new Set(), expandedInit: false, version: undefined,
                  evRef: null, evNext: null, selected: null, gen: 0 };

  // --- evidence --------------------------------------------------------------------
  async function showEvidence(ref, label, append = false) {
    const list = $("dg-ev-list");
    if (!append) {
      list.replaceChildren();
      state.evRef = ref;
      state.evNext = null;
    }
    $("dg-ev-empty").hidden = true;
    $("dg-ev-ref").textContent = label ? `${label} — ${ref}` : ref;
    const after = append ? state.evNext || 0 : 0;
    let doc;
    try {
      doc = await api(`/api/diagram/${state.run}/evidence?ref=${encodeURIComponent(ref)}`
                      + `&after=${after}`);
    } catch (e) {
      list.append(el("li", { text: `could not load evidence (${e.message})` }));
      return;
    }
    if (!doc.items.length && !append) {
      list.append(el("li", { text: "no supporting events recorded" }));
    }
    for (const item of doc.items) {
      const b = item.body || {};
      const head = `${item.kind} · seq ${item.seq} · ${fmtTime(item.t)}`
        + (b.ref ? ` · ${b.ref}` : "") + (b.role ? ` · ${b.role}` : "")
        + (b.outcome ? ` · ${b.outcome}` : "");
      list.append(el("li", {}, el("div", { text: head }),
        el("pre", { text: JSON.stringify(b, null, 1) })));
    }
    state.evNext = doc.next;
    $("dg-ev-more").hidden = !doc.next;
  }
  $("dg-ev-more").addEventListener("click", () => showEvidence(state.evRef, null, true));

  async function showKeys(keys, label) {
    const list = $("dg-ev-list");
    list.replaceChildren();
    $("dg-ev-empty").hidden = true;
    $("dg-ev-ref").textContent = `${label} — ${keys.length} event(s)`;
    $("dg-ev-more").hidden = true;
    for (const key of keys.slice(0, 50)) {
      try {
        const doc = await api(`/api/diagram/${state.run}/evidence?ref=`
                              + encodeURIComponent(key));
        for (const item of doc.items) {
          list.append(el("li", {}, el("div", { text: `${item.kind} · seq ${item.seq} · `
            + `${fmtTime(item.t)} · ${item.key}` }),
            el("pre", { text: JSON.stringify(item.body || {}, null, 1) })));
        }
      } catch (e) {
        list.append(el("li", { text: `${key}: not loaded (${e.message})` }));
      }
    }
    if (keys.length > 50) list.append(el("li", { text: `${keys.length - 50} more not shown` }));
  }

  function select(node) {
    if (state.selected) state.selected.classList.remove("sel");
    state.selected = node;
    if (node) node.classList.add("sel");
  }

  // --- data flow -------------------------------------------------------------------
  function renderFlow(model) {
    const host = $("dg-flow");
    host.replaceChildren();
    const nodes = Object.fromEntries(model.nodes.map((n) => [n.id, n]));
    const origins = model.nodes.filter((n) => n.kind === "origin");
    const ifaces = model.nodes.filter((n) => n.kind === "interface" || n.kind === "page");
    const left = model.nodes.filter((n) => n.kind === "actor");
    const ext = model.nodes.filter((n) => n.kind === "external");
    const tools = model.nodes.filter((n) => n.kind === "tool");
    if (!state.expandedInit) {
      if (ifaces.length < EXPAND_ALL_UNDER) origins.forEach((o) => state.expanded.add(o.id));
      state.expandedInit = true;
    }
    $("dg-flow-empty").hidden = model.flows.length > 0;
    const pos = {};                       // id -> {x, y, w, h, anchorL, anchorR}
    const xL = 8, wL = 160, xA = 200, wA = 400, xR = xA + wA + 40, wR = 160;
    let y = 30;
    const body = svg("g");
    // the application with its origins
    const appTop = y;
    y += 26;
    for (const o of origins) {
      const kids = ifaces.filter((i) => i.parent === o.id);
      const open = state.expanded.has(o.id);
      const top = y;
      const h = 26 + (open ? kids.length * ROW + 6 : 0);
      const box = svg("rect", { x: xA + 12, y: top, width: wA - 24, height: h, rx: 5,
        class: `dg-box origin k-${o.knowledge}` });
      titled(box, `${o.label}\n${o.knowledge}; ${o.observations} observation(s)\n`
        + (o.attrs.internals || []).join("; "));
      const head = svg("text", { x: xA + 22, y: top + 17, class: "dg-text head" },
        `${open ? "▾" : "▸"} ${clip(o.label, 38)}  (${kids.length} interface(s))`);
      const grp = svg("g", { class: "dg-hit", tabindex: 0, role: "button",
                             "aria-expanded": open });
      grp.append(box, head);
      grp.addEventListener("click", () => {
        if (state.expanded.has(o.id)) state.expanded.delete(o.id);
        else state.expanded.add(o.id);
        renderFlow(model);
        showEvidence(o.id, o.label);
      });
      body.append(grp);
      pos[o.id] = { y: top + 13, l: xA + 12, r: xA + wA - 12 };
      if (open) {
        kids.forEach((k, i) => {
          const ry = top + 26 + i * ROW;
          const cov = k.coverage || {};
          const row = svg("g", { class: "dg-hit" });
          const rect = svg("rect", { x: xA + 22, y: ry, width: wA - 44, height: ROW - 3,
            rx: 3, class: `dg-box k-${k.knowledge}` });
          const finds = (k.attrs.finding || []).length;
          const label = `${clip(k.label, 34)}${finds ? `  ⚑${finds}` : ""}`
            + `  [${cov.executed || 0} sent / ${cov.evaluated || 0} eval]`;
          row.append(rect, svg("text", { x: xA + 28, y: ry + 14, class: "dg-text" }, label));
          titled(row, `${k.label}\nevidence: ${k.knowledge}`
            + `${k.attrs.grouping ? " (" + k.attrs.grouping + ")" : ""}\n`
            + `observations: ${k.observations}\nfirst seen ${fmtTime(k.first_seen)}, `
            + `last seen ${fmtTime(k.last_seen)}`);
          row.addEventListener("click", () => { select(rect); showEvidence(k.id, k.label); });
          body.append(row);
          pos[k.id] = { y: ry + 9, l: xA + 22, r: xA + wA - 22 };
        });
      }
      for (const k of kids) if (!pos[k.id]) pos[k.id] = pos[o.id];   // collapsed: the origin
      y += h + 10;
    }
    if (!origins.length) {
      body.append(svg("text", { x: xA + 20, y: y + 10, class: "dg-text small" },
        "no origin recorded"));
      y += 30;
    }
    const app = model.nodes.find((n) => n.kind === "application");
    const appBox = svg("rect", { x: xA, y: appTop, width: wA, height: y - appTop + 4, rx: 8,
      class: "dg-box app" });
    titled(appBox, app ? `${app.label}: ${(app.attrs.basis || []).join("; ")}` : "application");
    body.prepend(appBox, svg("text", { x: xA + 10, y: appTop + 17, class: "dg-text head" },
      app ? app.label : "Target application"));
    // actors, external references, the tool
    let ly = 40;
    const drawSide = (n, x, w, yy) => {
      const g = svg("g", { class: "dg-hit" });
      const r = svg("rect", { x, y: yy, width: w, height: 30, rx: 12,
        class: `dg-box ${n.kind} k-${n.knowledge}` });
      g.append(r, svg("text", { x: x + 10, y: yy + 19, class: "dg-text" }, clip(n.label, 21)));
      titled(g, `${n.label}\n${n.knowledge}: ${(n.attrs.basis || []).join("; ")}`);
      g.addEventListener("click", () => { select(r); showEvidence(n.id, n.label); });
      body.append(g);
      pos[n.id] = { y: yy + 15, l: x, r: x + w };
    };
    for (const n of left) { drawSide(n, xL, wL, ly); ly += 50; }
    if (ext.length) {
      body.append(svg("text", { x: xL, y: ly + 12, class: "dg-text small" },
        "outside the scope (never contacted)"));
      ly += 20;
      for (const n of ext.slice(0, 25)) { drawSide(n, xL, wL, ly); ly += 40; }
      if (ext.length > 25) {
        body.append(svg("text", { x: xL, y: ly + 10, class: "dg-text small" },
          `${ext.length - 25} more external host(s): see the export`));
        ly += 20;
      }
    }
    let ry2 = 40;
    for (const n of tools) { drawSide(n, xR, wR, ry2); ry2 += 50; }
    // flows (merged when their target is a collapsed origin)
    const merged = new Map();
    for (const f of model.flows) {
      const a = pos[f.src], b = pos[f.dst];
      if (!a || !b) continue;
      const key = `${f.src}|${b.y}|${f.view}`;
      const m = merged.get(key) || { flows: [], a, b, view: f.view, n: 0 };
      m.flows.push(f);
      m.n += f.observations;
      merged.set(key, m);
    }
    for (const m of merged.values()) {
      const f0 = m.flows[0];
      const fromRight = m.a.l > m.b.r;
      const x1 = fromRight ? m.a.l : m.a.r, x2 = fromRight ? m.b.r : m.b.l;
      const mid = (x1 + x2) / 2;
      const d = `M${x1},${m.a.y} C${mid},${m.a.y} ${mid},${m.b.y} ${x2},${m.b.y}`;
      const refused = m.flows.some((f) => (f.attrs.refused || []).length);
      const cls = `dg-flow ${m.view === "test" ? "test" : ""} k-${f0.knowledge}`
        + (refused ? " refused" : "");
      const line = svg("path", { d, class: cls, "marker-end": "url(#dg-arrow)" });
      const hit = svg("path", { d, class: "dg-hit", stroke: "transparent",
        "stroke-width": 10, fill: "none" });
      const tip = m.flows.map((f) => `${f.view} ${f.protocol} ×${f.observations} `
        + `[${f.knowledge}] statuses ${(f.attrs.status || []).join(",") || "-"}; `
        + `data ${(f.attrs.data || []).join(",") || "-"}; auth `
        + `${(f.attrs.auth || []).join(",") || "-"}`).join("\n");
      titled(hit, tip);
      hit.addEventListener("click", () => {
        select(line);
        if (m.flows.length === 1) showEvidence(f0.id, `flow ×${f0.observations}`);
        else showKeys(m.flows.map((f) => f.id), `${m.flows.length} merged flows`);
      });
      body.append(line, hit,
        svg("text", { x: mid - 12, y: (m.a.y + m.b.y) / 2 - 3, class: "dg-text small" },
          `×${m.n}`));
    }
    const height = Math.max(y, ly, ry2) + 30;
    const s = svg("svg", { width: xR + wR + 20, height, role: "img",
      "aria-label": "Data flow diagram" });
    const defs = svg("defs");
    const marker = svg("marker", { id: "dg-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5,
      markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
    marker.append(svg("path", { d: "M0,0 L10,5 L0,10 z", class: "dg-head" }));
    defs.append(marker);
    s.append(defs, body);
    host.append(s);
    renderIfaceTable(ifaces);
  }

  function renderIfaceTable(ifaces) {
    const tbody = $("dg-ifaces").querySelector("tbody");
    tbody.replaceChildren();
    for (const k of ifaces) {
      const c = k.coverage || {};
      const tr = el("tr", { tabindex: 0 },
        el("td", { text: k.label }), el("td", { text: k.knowledge }),
        el("td", { class: "num", text: k.observations }),
        ...["discovered", "captured", "scheduled", "executed", "evaluated", "finding"]
          .map((s) => el("td", { class: "num", text: c[s] || 0 })));
      tr.addEventListener("click", () => showEvidence(k.id, k.label));
      tbody.append(tr);
    }
    if (!ifaces.length) tbody.append(el("tr", {}, el("td", { colspan: 9,
      text: "no interfaces recorded" })));
  }

  // --- sequences -------------------------------------------------------------------
  function renderSeq(seq) {
    const host = $("dg-seq");
    host.replaceChildren();
    $("dg-seq-notes").textContent = (seq.notes || []).join(" · ") || "";
    if (seq.error) {
      host.append(el("p", { class: "muted", text: seq.error }));
      return;
    }
    const idx = Object.fromEntries(seq.participants.map((p, i) => [p.id, i]));
    const cx = (id) => 100 + idx[id] * COL;
    const width = 100 + seq.participants.length * COL + 360;
    const top = 40;
    const height = top + (seq.steps.length + 1) * STEP + 20;
    const s = svg("svg", { width, height, role: "img", "aria-label": "Sequence diagram" });
    const defs = svg("defs");
    for (const [id, cls] of [["dg-sq-head", "dg-head"], ["dg-sq-lost", "dg-head lost"]]) {
      const m = svg("marker", { id, viewBox: "0 0 10 10", refX: 9, refY: 5,
        markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
      m.append(svg("path", { d: "M0,0 L10,5 L0,10 z", class: cls }));
      defs.append(m);
    }
    s.append(defs);
    for (const p of seq.participants) {
      const x = cx(p.id);
      s.append(svg("line", { x1: x, y1: top, x2: x, y2: height - 10, class: "dg-life" }));
      const r = svg("rect", { x: x - 80, y: 6, width: 160, height: 26, rx: 5,
        class: `dg-box ${p.kind === "target" ? "origin" : p.kind === "annotation" ? ""
          : "tool"}` });
      titled(r, `${p.label} (${p.kind})`);
      s.append(r, svg("text", { x: x - 74, y: 23, class: "dg-text head" },
        clip(p.label, 21)));
    }
    let y = top + STEP;
    let groupLeft = 0, groupTop = 0, groupLabel = null;
    seq.steps.forEach((st) => {
      const g = svg("g", { class: "dg-step", tabindex: 0 });
      g.addEventListener("click", () => showKeys(st.evidence || [], st.label));
      if (st.type === "group") {
        groupLeft = 2; groupTop = y - 16; groupLabel = st.label;
        s.append(titled(svg("text", { x: 8, y: y - 4, class: "dg-text small" },
          clip(`loop ${st.label}`, 90)), st.label));
        g.append(svg("rect", { x: 4, y: groupTop, width: width - 8, height: STEP * 2 + 6,
          class: "dg-group" }));
        g.addEventListener("click", () => showKeys(st.evidence || [], st.label));
        s.append(g);
        y += 10;
        return;
      }
      if (st.type === "note") {
        const xs = st.over.map(cx);
        const text = clip(st.label, 90);
        const w = Math.max(Math.max(...xs) - Math.min(...xs) + 120, text.length * 6.2 + 14);
        const x = Math.max(4, Math.min(...xs) - 60);
        g.append(svg("rect", { x, y: y - 16, width: w, height: 22, rx: 3,
          class: `dg-note ${st.kind === "finding" ? "finding" : ""}` }),
          svg("text", { x: x + 6, y: y, class: "dg-text small" }, text));
      } else {
        const x1 = cx(st.src), x2 = cx(st.dst);
        const lost = st.type === "lost";
        const cls = `dg-msg ${lost ? "lost" : st.kind === "response" ? "response" : ""}`
          + `${st.kind === "action" ? " action" : ""}`;
        g.append(svg("line", { x1, y1: y, x2: lost ? (x1 + x2) / 2 : x2, y2: y, class: cls,
          "marker-end": `url(#${lost ? "dg-sq-lost" : "dg-sq-head"})` }));
        if (lost) {
          g.append(svg("text", { x: (x1 + x2) / 2 + 4, y: y + 4, class: "dg-text" }, "✕"));
        }
        g.append(svg("text", { x: Math.min(x1, x2) + 6, y: y - 5, class: "dg-text small" },
          clip(st.label, 60)));
      }
      titled(g, `${st.label}\n${(st.evidence || []).length} supporting event(s)`);
      s.append(g);
      y += STEP;
      if (groupLeft && --groupLeft === 0) groupLabel = null;
    });
    host.append(s);
  }

  async function loadSeq() {
    const scope = scopeSel.value;
    if (!scope || state.run === null) {
      $("dg-seq").replaceChildren();
      return;
    }
    try {
      renderSeq(await api(`/api/diagram/${state.run}/sequence?scope=`
                          + encodeURIComponent(scope)));
    } catch (e) {
      $("dg-seq").replaceChildren(el("p", { class: "muted", text: `not loaded: ${e.message}` }));
    }
    exportLinks();
  }
  scopeSel.addEventListener("change", loadSeq);

  // --- status, filters, exports ------------------------------------------------------
  function exportLinks() {
    const box = $("dg-exports");
    box.replaceChildren();
    if (state.run === null) return;
    const base = `/api/diagram/${encodeURIComponent(state.run)}`;
    box.append(el("a", { href: `${base}/export.json`, text: "JSON" }), " ",
      el("a", { href: `${base}/export/flow.mmd?overlay=${overlayBox.checked}`,
                text: "Mermaid data flow" }));
    if (scopeSel.value) {
      box.append(" ", el("a", { href: `${base}/export/sequence.mmd?scope=`
        + encodeURIComponent(scopeSel.value), text: "Mermaid sequence" }));
    }
  }

  function renderStatus(st) {
    const r = st.recorder || {};
    $("dg-status-text").textContent = `Run ${st.run_id}: ${st.state} — ${st.events} event(s)`
      + `; run end: ${st.run_end || "not recorded"}`
      + (Object.keys(r).length ? `; recorder: ${r.written ?? 0} written, `
        + `${r.dropped ?? 0} dropped, ${r.duplicates ?? 0} duplicate(s), `
        + `${r.forced_flushes ?? 0} forced flush(es), max lag `
        + `${Math.round(r.max_lag_ms ?? 0)} ms` : "; recorder counters not yet written");
    const w = $("dg-warnings");
    w.replaceChildren(...(st.warnings || []).map((t) => el("li", { text: t })));
  }

  async function refresh() {
    const gen = ++state.gen;
    if (state.run === null) return;
    const params = new URLSearchParams();
    if (overlayBox.checked) params.set("overlay", "true");
    if (originSel.value) params.set("origin", originSel.value);
    if (knowSel.value) params.set("knowledge", knowSel.value);
    if (findingSel.value) params.set("finding", findingSel.value);
    try {
      const [st, model, scopes] = await Promise.all([
        api(`/api/diagram/${state.run}/status`),
        api(`/api/diagram/${state.run}/dataflow?${params}`),
        api(`/api/diagram/${state.run}/scopes`)]);
      if (gen !== state.gen) return;
      renderStatus(st);
      fillOrigins(model);
      fillScopes(scopes.scopes);
      renderFlow(model);
      await loadSeq();
    } catch (e) {
      $("dg-status-text").textContent = `Could not load the run's diagrams: ${e.message}`;
    }
  }

  function fillOrigins(model) {
    const keep = originSel.value;
    if (originSel.options.length > 1 && !keep) return;
    const origins = model.nodes.filter((n) => n.kind === "origin").map((n) => n.label);
    if (originSel.options.length - 1 === origins.length) return;
    originSel.replaceChildren(el("option", { value: "", text: "All origins" }),
      ...origins.map((o) => el("option", { value: o, text: o })));
    originSel.value = keep;
  }

  function fillScopes(scopes) {
    const keep = scopeSel.value;
    scopeSel.replaceChildren(el("option", { value: "", text: "— choose a sequence —" }),
      ...scopes.map((s) => el("option", { value: s.scope, text: `[${s.kind}] ${s.label}` })));
    const findings = scopes.filter((s) => s.kind === "finding");
    const fkeep = findingSel.value;
    findingSel.replaceChildren(el("option", { value: "", text: "All" }),
      ...findings.map((s) => el("option", { value: s.scope.split(":")[1], text: s.label })));
    findingSel.value = fkeep;
    if (keep && scopes.some((s) => s.scope === keep)) scopeSel.value = keep;
    else if (!keep && scopes.length) scopeSel.value = scopes[0].scope;
  }

  for (const c of [originSel, knowSel, findingSel, overlayBox]) {
    c.addEventListener("change", () => { refresh(); exportLinks(); });
  }
  runSel.addEventListener("change", () => {
    state.run = runSel.value === "" ? null : parseInt(runSel.value, 10);
    state.expanded.clear();
    state.expandedInit = false;
    refresh();
  });

  async function loadRuns() {
    const doc = await api("/api/diagram/runs");
    runSel.replaceChildren(...doc.runs.map((r) => el("option", { value: r.id,
      text: `#${r.id} ${r.tool || ""} ${r.started_at || ""} (${r.events} events, ${r.state})` })));
    if (!doc.runs.length) {
      $("dg-status-text").textContent = "No run has a trace yet. Run `fuzzlab auto` "
        + "(the trace is on by default); this page fills in while it runs.";
      return;
    }
    if (state.run === null || !doc.runs.some((r) => r.id === state.run)) {
      state.run = doc.runs[0].id;
    }
    runSel.value = String(state.run);
    await refresh();
  }

  async function poll() {
    try {
      const v = (await api("/api/sitetree/version")).version;
      if (state.version !== undefined && v !== state.version) await loadRuns();
      state.version = v;
    } catch (e) { /* the next poll retries */ }
    setTimeout(poll, pollMs);
  }

  // the store's version is taken before the first read, so a write that lands while
  // the page loads is seen by the first poll (never folded into the baseline)
  api("/api/sitetree/version")
    .then((v) => { state.version = v.version; })
    .catch(() => {})
    .finally(() => {
      loadRuns().catch((e) => {
        $("dg-status-text").textContent = `Could not load runs: ${e.message}`;
      });
      setTimeout(poll, pollMs);
    });
}

initDiagrams();
