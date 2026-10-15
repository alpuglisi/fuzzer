// Site map (CC-UI-0500, FR-UI-500..505): a lazy WAI-ARIA treeview over the read-only
// /api/sitetree/* routes, with the selected node's contents and issues beside it (the
// three panes of the UI-research design, §12.3/§13.1).
//
// Safety: every value from the server is attacker-influenced (paths, parameter names,
// vuln classes come from a live target). They are rendered with textContent only --
// this module never parses HTML strings (enforced by tests/test_web_sitetree_browser.py).

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const STATUS_LABEL = {
  confirmed: "confirmed", checked: "oracle checked", inconclusive: "inconclusive",
  pending: "pending", skipped_budget: "skipped (budget)", no_confirmer: "no confirmer",
  unrecorded: "unrecorded",
};

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

function worstSeverity(roll) {
  if (!roll || !roll.findings) return null;
  for (const s of SEV_ORDER) if ((roll.by_severity || {})[s]) return s;
  return "info";
}

function initSiteTree() {
  const root = document.getElementById("sitetree-root");
  if (!root) return;
  const tree = document.getElementById("st-tree");
  const empty = document.getElementById("st-empty");
  const status = document.getElementById("st-status");
  const form = document.getElementById("st-filters");
  const runSel = document.getElementById("st-run");
  const catSel = document.getElementById("st-category");
  const sevBox = document.getElementById("st-severities");
  const qInput = document.getElementById("st-q");
  const pollMs = Math.max(250, parseInt(root.dataset.pollMs || "5000", 10) || 5000);

  const state = {
    expanded: new Set(),         // node keys
    selected: null,              // node key
    version: undefined,
    lastRefresh: 0,
    issuesNext: null,
    generation: 0,               // bumps on every filter change / refresh
  };

  // --- requests -----------------------------------------------------------------
  function filterParams() {
    const p = new URLSearchParams();
    for (const box of form.querySelectorAll("input[name=status]:checked")) p.append("status", box.value);
    for (const box of sevBox.querySelectorAll("input:checked")) p.append("severity", box.value);
    if (catSel.value) p.append("category", catSel.value);
    if (runSel.value) p.append("run", runSel.value);
    if (qInput.value.trim()) p.set("q", qInput.value.trim());
    return p;
  }

  async function getJSON(path, params) {
    const r = await fetch(`${path}?${params.toString()}`, { headers: { Accept: "application/json" } });
    let body = null;
    try { body = await r.json(); } catch (_) { body = null; }
    return { status: r.status, body };
  }

  function nodeParams(key, extra = {}) {
    const p = filterParams();
    if (key) p.set("node", key);
    for (const [k, v] of Object.entries(extra)) if (v !== null && v !== undefined) p.set(k, v);
    return p;
  }

  // --- tree items -----------------------------------------------------------------
  function itemFor(child, level) {
    const expandable = Boolean(child.expandable && child.key);
    const li = el("li", {
      role: "treeitem", "aria-level": level, "aria-selected": "false", tabindex: "-1",
      class: `st-item st-${child.kind}`,
      "aria-expanded": expandable ? "false" : null,
    });
    if (child.key) li.dataset.key = child.key;
    const row = el("div", { class: "st-row" });
    row.append(el("span", { class: "st-twisty", "aria-hidden": "true", text: expandable ? "▸" : "" }));
    const sev = worstSeverity(child.rollup);
    row.append(el("span", {
      class: `st-dot ${sev ? "sev-" + sev : "st-dot-none"}`, "aria-hidden": "true",
    }));
    // the dot's colour, said in words (never colour alone)
    if (sev) row.append(el("span", { class: "visually-hidden", text: `worst severity ${sev}:` }));
    let label = child.label;
    if (child.kind === "finding") label = `${child.vuln_class || "(unknown class)"} · finding #${child.id}`;
    if (child.kind === "candidate") label = `${child.category || "(no category)"} · candidate #${child.id}`;
    row.append(el("span", { class: "st-label", text: label }));
    if (child.kind === "route") row.append(el("span", { class: "st-badge", text: "route" }));
    if (child.kind === "param" && child.location === "fragment") {
      row.append(el("span", { class: "st-badge", title: "read by the page's script; never sent to the server", text: "client-side" }));
    }
    if (child.kind === "finding" && child.severity) {
      row.append(el("span", { class: `badge sev-${child.severity}`, text: child.severity }));
    }
    if (child.kind === "candidate") {
      row.append(el("span", { class: "st-badge", text: STATUS_LABEL[child.status] || child.status || "" }));
    }
    const roll = child.rollup;
    if (roll) {
      if (roll.findings) {
        const count = el("button", {
          type: "button", class: "st-count", tabindex: "-1",
          "aria-label": `${roll.findings} findings: show issues`, text: String(roll.findings),
        });
        count.addEventListener("click", (ev) => {
          ev.stopPropagation();
          select(li, { focusIssues: true });
        });
        row.append(count);
      }
      const inc = (roll.by_status || {}).inconclusive || 0;
      if (inc) row.append(el("span", { class: "st-minor", title: "inconclusive candidates", text: `${inc} inconclusive` }));
    }
    if (child.kind === "finding" && child.href && child.href.startsWith("/findings/")) {
      row.append(el("a", { href: child.href, class: "st-open", tabindex: "-1", text: "open" }));
    }
    li.append(row);
    li._child = child;
    row.addEventListener("click", () => {
      select(li);
      if (expandable) toggle(li);
    });
    return li;
  }

  function groupOf(li) {
    let g = li.querySelector(":scope > ul[role=group]");
    if (!g) {
      g = el("ul", { role: "group", class: "st-group-list" });
      li.append(g);
    }
    return g;
  }

  async function loadChildren(container, key, level, gen, after = null) {
    const params = nodeParams(key, { after, limit: "200" });
    const { status: code, body } = await getJSON("/api/sitetree/children", params);
    if (gen !== state.generation) return false;
    if (code === 404 && key) {
      const gone = tree.querySelector(`[data-key="${CSS.escape(key)}"]`);
      if (gone) {
        state.expanded.delete(key);
        gone.remove();
      }
      return false;
    }
    if (code !== 200 || !body) {
      status.textContent = (body && body.detail) ? `Could not load: ${body.detail}` : "Could not load this node.";
      return false;
    }
    const more = container.querySelector(":scope > li.st-more-item");
    if (more) more.remove();
    for (const child of body.children) container.append(itemFor(child, level));
    if (body.next) {
      const btn = el("button", { type: "button", class: "st-more-btn",
        text: `Show more (${container.querySelectorAll(":scope > li[role=treeitem]").length} loaded)` });
      const li = el("li", { role: "none", class: "st-more-item" }, btn);
      btn.addEventListener("click", () => loadChildren(container, key, level, state.generation, body.next));
      container.append(li);
    }
    return true;
  }

  async function expand(li) {
    const key = li.dataset.key;
    if (!key || li.getAttribute("aria-expanded") === null) return;
    li.setAttribute("aria-expanded", "true");
    li.querySelector(":scope > .st-row .st-twisty").textContent = "▾";
    state.expanded.add(key);
    const g = groupOf(li);
    if (!g.dataset.loaded) {
      g.dataset.loaded = "1";
      const level = parseInt(li.getAttribute("aria-level"), 10) + 1;
      await loadChildren(g, key, level, state.generation);
    }
    g.hidden = false;
  }

  function collapse(li) {
    if (li.getAttribute("aria-expanded") !== "true") return;
    li.setAttribute("aria-expanded", "false");
    li.querySelector(":scope > .st-row .st-twisty").textContent = "▸";
    state.expanded.delete(li.dataset.key);
    const g = li.querySelector(":scope > ul[role=group]");
    if (g) g.hidden = true;
  }

  function toggle(li) {
    if (li.getAttribute("aria-expanded") === "true") collapse(li);
    else expand(li);
  }

  // --- keyboard (APG treeview) ------------------------------------------------------
  function visibleItems() {
    return [...tree.querySelectorAll("li[role=treeitem]")].filter((li) => {
      for (let p = li.parentElement; p && p !== tree; p = p.parentElement) if (p.hidden) return false;
      return true;
    });
  }

  function focusItem(li) {
    if (!li) return;
    for (const other of tree.querySelectorAll("li[role=treeitem][tabindex='0']")) other.tabIndex = -1;
    li.tabIndex = 0;
    li.focus();
  }

  tree.addEventListener("keydown", (ev) => {
    const li = ev.target.closest("li[role=treeitem]");
    if (!li) return;
    const items = visibleItems();
    const i = items.indexOf(li);
    let handled = true;
    switch (ev.key) {
      case "ArrowDown": focusItem(items[i + 1]); break;
      case "ArrowUp": focusItem(items[i - 1]); break;
      case "Home": focusItem(items[0]); break;
      case "End": focusItem(items[items.length - 1]); break;
      case "ArrowRight":
        if (li.getAttribute("aria-expanded") === "false") expand(li);
        else if (li.getAttribute("aria-expanded") === "true") {
          const first = li.querySelector(":scope > ul > li[role=treeitem]");
          if (first) focusItem(first);
        }
        break;
      case "ArrowLeft":
        if (li.getAttribute("aria-expanded") === "true") collapse(li);
        else focusItem(li.parentElement.closest("li[role=treeitem]"));
        break;
      case "Enter": case " ":
        select(li);
        if (li.getAttribute("aria-expanded") !== null) toggle(li);
        break;
      default: handled = false;
    }
    if (handled) ev.preventDefault();
  });

  // --- selection: contents + issues ------------------------------------------------
  function select(li, opts = {}) {
    for (const other of tree.querySelectorAll("li[aria-selected=true]")) other.setAttribute("aria-selected", "false");
    li.setAttribute("aria-selected", "true");
    focusItem(li);
    const child = li._child || {};
    if (child.kind === "finding" || child.kind === "candidate") return;
    state.selected = li.dataset.key || null;
    showNode(state.selected, opts);
  }

  async function showNode(key, opts = {}) {
    const box = document.getElementById("st-node");
    const none = document.getElementById("st-contents-empty");
    if (!key) {
      box.hidden = true;
      none.hidden = false;
      return;
    }
    const gen = state.generation;
    const [summary, kids] = await Promise.all([
      getJSON("/api/sitetree/node", nodeParams(key)),
      getJSON("/api/sitetree/children", nodeParams(key, { limit: "200" })),
    ]);
    if (gen !== state.generation || key !== state.selected) return;
    if (summary.status !== 200 || !summary.body) {
      box.hidden = true;
      none.hidden = false;
      none.textContent = summary.status === 404 ? "This node is no longer in the store." : "Could not load this node.";
      return;
    }
    none.hidden = true;
    box.hidden = false;
    renderNode(summary.body);
    renderChildren(kids.status === 200 && kids.body ? kids.body : { children: [] });
    state.issuesNext = summary.body.next;
    renderIssues(summary.body.findings, false);
    if (opts.focusIssues) document.getElementById("st-issues").focus();
  }

  function renderNode(s) {
    const kv = document.getElementById("st-node-kv");
    kv.replaceChildren();
    const n = s.node || {};
    const rows = [["host", n.host], ["path", n.path], ["method", n.method === null ? "(not recorded)" : n.method],
      ["parameter", n.param === undefined ? undefined : (n.param || "(no parameter)")],
      ["location", n.param === undefined ? undefined : (n.location || "not recorded")],
      ["last run", s.rollup && s.rollup.last_run ? `#${s.rollup.last_run}` : undefined]];
    for (const [k, v] of rows) {
      if (v === undefined) continue;
      kv.append(el("dt", { text: k }), el("dd", {}, el("code", { text: v === null ? "" : String(v) })));
    }
    const roll = document.getElementById("st-roll");
    roll.replaceChildren();
    const r = s.rollup || {};
    const sev = el("p", { class: "st-sev-line" }, el("strong", { text: `${r.findings || 0} findings` }));
    for (const name of SEV_ORDER) {
      const c = (r.by_severity || {})[name] || 0;
      if (c) sev.append(" ", el("span", { class: `badge sev-${name}`, text: `${c} ${name}` }));
    }
    roll.append(sev);
    const cats = Object.entries(r.by_category || {}).filter(([, c]) => c);
    if (cats.length) roll.append(el("p", { class: "muted", text: "by category: " + cats.map(([c, n2]) => `${c} ${n2}`).join(", ") }));
    const st = Object.entries(r.by_status || {}).filter(([k, c]) => c && k !== "confirmed");
    roll.append(el("p", { class: "muted", text: `${r.candidates || 0} candidates` + (st.length ? ": " + st.map(([k, c]) => `${STATUS_LABEL[k] || k} ${c}`).join(", ") : "") + ` · ${r.endpoints || 0} recorded endpoints/pages` }));
    const probs = Object.entries(r.problems || {}).filter(([, c]) => c);
    if (probs.length) roll.append(el("p", { class: "muted st-problems", text: "not placed in the tree: " + probs.map(([k, c]) => `${k.replace("_", " ")} ${c}`).join(", ") }));
  }

  function renderChildren(body) {
    const tbody = document.querySelector("#st-children-table tbody");
    tbody.replaceChildren();
    for (const c of body.children || []) {
      const r = c.rollup || {};
      const label = c.label || (c.kind === "finding" ? `finding #${c.id}` : `candidate #${c.id}`);
      const sev = worstSeverity(r);
      const findings = el("td", {});
      if (r.findings) findings.append(el("span", { class: `badge sev-${sev}`, text: String(r.findings) }));
      else findings.append("0");
      tbody.append(el("tr", {}, el("td", {}, el("code", { text: label })), el("td", { text: c.kind }), findings,
        el("td", { text: String(r.candidates || 0) }), el("td", { text: String((r.by_status || {}).inconclusive || 0) }),
        el("td", { text: r.last_run ? `#${r.last_run}` : "" })));
    }
    if (body.next) tbody.append(el("tr", {}, el("td", { colspan: "6", class: "muted", text: "… more in the tree (Show more)" })));
  }

  function renderIssues(findings, append) {
    const table = document.getElementById("st-issues-table");
    const tbody = table.querySelector("tbody");
    if (!append) tbody.replaceChildren();
    for (const f of findings || []) {
      const loc = `${f.method || "(method not recorded)"} ${f.path || ""}${f.param ? " · " + f.param : ""}`;
      const link = (f.href || "").startsWith("/findings/") ? el("a", { href: f.href, text: `#${f.id}` }) : el("span", { text: `#${f.id}` });
      tbody.append(el("tr", {}, el("td", {}, el("span", { class: `badge sev-${f.severity || "info"}`, text: f.severity || "info" })),
        el("td", { text: f.vuln_class || "" }), el("td", {}, el("code", { text: loc })),
        el("td", { text: f.mechanism || "" }), el("td", { text: `#${f.run_id}` }), el("td", {}, link)));
    }
    const any = tbody.children.length > 0;
    table.hidden = !any;
    document.getElementById("st-issues-empty").hidden = any;
    document.getElementById("st-issues-more").hidden = !state.issuesNext;
  }

  document.getElementById("st-issues-more").addEventListener("click", async () => {
    if (!state.selected || !state.issuesNext) return;
    const key = state.selected;
    const { status: code, body } = await getJSON("/api/sitetree/node", nodeParams(key, { before: state.issuesNext }));
    if (code !== 200 || !body || key !== state.selected) return;
    state.issuesNext = body.next;
    renderIssues(body.findings, true);
  });

  // --- (re)loading -------------------------------------------------------------------
  async function reload({ keepExpanded }) {
    state.generation += 1;
    const gen = state.generation;
    const want = keepExpanded ? new Set(state.expanded) : new Set();
    state.expanded = new Set();
    tree.replaceChildren();
    status.textContent = "";
    const ok = await loadChildren(tree, null, 1, gen);
    if (gen !== state.generation) return;
    empty.hidden = !ok || tree.querySelector("li[role=treeitem]") !== null;
    // re-open what was open, outermost first (a key that no longer resolves is dropped)
    let opened = true;
    while (opened && gen === state.generation) {
      opened = false;
      for (const li of tree.querySelectorAll("li[role=treeitem][aria-expanded=false]")) {
        if (want.has(li.dataset.key)) {
          want.delete(li.dataset.key);
          await expand(li);
          opened = true;
        }
      }
    }
    const first = tree.querySelector("li[role=treeitem]");
    if (first && !tree.querySelector("li[tabindex='0']")) first.tabIndex = 0;
    if (state.selected) {
      const sel = tree.querySelector(`[data-key="${CSS.escape(state.selected)}"]`);
      if (sel) {
        sel.setAttribute("aria-selected", "true");
        showNode(state.selected);
      } else {
        state.selected = null;
        showNode(null);
      }
    }
  }

  let typing = null;
  form.addEventListener("change", () => reload({ keepExpanded: false }));
  form.addEventListener("submit", (ev) => ev.preventDefault());
  qInput.addEventListener("input", () => {
    clearTimeout(typing);
    typing = setTimeout(() => reload({ keepExpanded: false }), 300);
  });

  async function loadFacets() {
    const { status: code, body } = await getJSON("/api/sitetree/facets", new URLSearchParams());
    if (code !== 200 || !body) return;
    for (const r of body.runs || []) {
      runSel.append(el("option", { value: String(r.id), text: `#${r.id} · ${r.tool || "?"} · ${r.host || ""}` }));
    }
    for (const c of body.categories || []) catSel.append(el("option", { value: c, text: c }));
    for (const s of body.severities || []) {
      sevBox.append(el("label", { class: "st-chip" }, el("input", { type: "checkbox", value: s }), ` ${s}`));
    }
  }

  // --- live refresh: poll the store's fingerprint while visible (FR-UI-505) ----------
  async function poll() {
    if (document.visibilityState !== "visible") return;
    let body;
    try {
      const r = await fetch("/api/sitetree/version", { headers: { Accept: "application/json" } });
      body = await r.json();
    } catch (_) {
      return;
    }
    const v = body ? body.version : null;
    if (state.version === undefined) {
      state.version = v;
      return;
    }
    if (v !== state.version && Date.now() - state.lastRefresh >= pollMs) {
      state.version = v;
      state.lastRefresh = Date.now();
      await reload({ keepExpanded: true });
    }
  }

  loadFacets();
  reload({ keepExpanded: false }).then(() => { root.dataset.ready = "1"; });
  poll();
  setInterval(poll, pollMs);
}

initSiteTree();
