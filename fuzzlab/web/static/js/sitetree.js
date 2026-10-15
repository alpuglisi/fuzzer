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
    let r;
    try {
      r = await fetch(`${path}?${params.toString()}`, { headers: { Accept: "application/json" } });
    } catch (_) {
      return { status: 0, body: null };            // network error: reported, not thrown
    }
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
  function identity(child) {
    if (child.key) return child.key;
    if (child.id !== undefined) return `${child.kind}:${child.id}`;
    return `${child.kind}:label:${child.label}`;     // a node too deep to key
  }

  function itemFor(child, level) {
    const expandable = Boolean(child.expandable && child.key);
    const li = el("li", {
      role: "treeitem", "aria-level": level, "aria-selected": "false", tabindex: "-1",
      class: `st-item st-${child.kind}`,
      "aria-expanded": expandable ? "false" : null,
    });
    li.dataset.id = identity(child);
    if (child.key) li.dataset.key = child.key;
    li.append(rowFor(child, li));
    li._child = child;
    return li;
  }

  // the visible row of an item; rebuilt on refresh inside the same <li>, so focus,
  // selection, expansion and loaded children stay where they are
  function rowFor(child, li) {
    const expandable = li.getAttribute("aria-expanded") !== null;
    const open = li.getAttribute("aria-expanded") === "true";
    const row = el("div", { class: "st-row" });
    row.append(el("span", { class: "st-twisty", "aria-hidden": "true", text: expandable ? (open ? "▾" : "▸") : "" }));
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
    row.addEventListener("click", () => {
      select(li);
      if (expandable) toggle(li);
    });
    return row;
  }

  function groupOf(li) {
    let g = li.querySelector(":scope > ul[role=group]");
    if (!g) {
      g = el("ul", { role: "group", class: "st-group-list" });
      li.append(g);
    }
    return g;
  }

  // fetch pages of a node's children until `want` are loaded (or there are no more)
  async function fetchPages(key, gen, after, want) {
    const out = [];
    let next = after;
    let truncated = false;
    do {
      const { status: code, body } = await getJSON("/api/sitetree/children",
        nodeParams(key, { after: next, limit: "200" }));
      if (gen !== state.generation) return { stale: true };
      if (code === 404 && key) return { gone: true };
      if (code !== 200 || !body) {
        return { error: (body && body.detail) ? `Could not load: ${body.detail}` : "Could not load this node." };
      }
      out.push(...body.children);
      next = body.next;
      truncated = truncated || Boolean(body.truncated);
    } while (next && out.length < want);
    return { children: out, next, truncated };
  }

  function dropNode(key) {
    const gone = tree.querySelector(`li[data-key="${CSS.escape(key)}"]`);
    if (!gone) return;
    state.expanded.delete(key);
    if (gone.contains(document.activeElement)) focusItem(gone.parentElement.closest("li[role=treeitem]") || visibleItems()[0]);
    gone.remove();
  }

  function setTail(container, key, level, next, truncated) {
    for (const old of container.querySelectorAll(":scope > li.st-more-item, :scope > li.st-trunc-item")) old.remove();
    if (truncated) {
      container.append(el("li", { role: "none", class: "st-trunc-item muted",
        text: "List truncated: this endpoint has more recorded groups than the site map reads at once." }));
    }
    if (next) {
      const btn = el("button", { type: "button", class: "st-more-btn",
        text: `Show more (${container.querySelectorAll(":scope > li[role=treeitem]").length} loaded)` });
      const li = el("li", { role: "none", class: "st-more-item" }, btn);
      btn.addEventListener("click", async () => {
        const hadFocus = document.activeElement === btn;   // before disabling blurs it
        btn.disabled = true;                       // one page per click, never twice
        const before = container.querySelectorAll(":scope > li[role=treeitem]").length;
        const ok = await loadChildren(container, key, level, state.generation, next);
        if (!ok) { btn.disabled = false; return; }
        if (hadFocus) {                            // keep the keyboard user in the tree
          const first = container.querySelectorAll(":scope > li[role=treeitem]")[before];
          if (first) focusItem(first);
        }
      });
      container.append(li);
    }
  }

  // a group's first page is loaded once per generation: an expand and a refresh that
  // both reach an empty group share one load (code review R3-1). A load of an older
  // generation is never reused -- it drops its own (stale) result.
  function loadChildren(container, key, level, gen, after = null) {
    const pending = container._loading;
    if (after === null && pending && pending.gen === gen) return pending.run;
    const run = (async () => {
      const got = await fetchPages(key, gen, after, 1);
      if (got.stale) return false;
      if (got.gone) { dropNode(key); return false; }
      if (got.error) { status.textContent = got.error; return false; }
      const have = new Set([...container.querySelectorAll(":scope > li[role=treeitem]")].map((li) => li.dataset.id));
      for (const child of got.children) {
        if (!have.has(identity(child))) container.append(itemFor(child, level));   // never twice
      }
      setTail(container, key, level, got.next, got.truncated);
      return true;
    })();
    if (after === null) {
      const entry = { gen, run };
      container._loading = entry;
      run.finally(() => { if (container._loading === entry) container._loading = null; });
    }
    return run;
  }

  // re-fetch a loaded group (as many items as it shows) and update it in place
  async function refreshGroup(container, key, level, gen) {
    const had = container.querySelectorAll(":scope > li[role=treeitem]").length;
    const got = await fetchPages(key, gen, null, Math.max(1, had));
    if (got.stale) return false;
    if (got.gone) { dropNode(key); return false; }
    if (got.error) { status.textContent = got.error; return false; }
    const existing = new Map();
    for (const li of container.querySelectorAll(":scope > li[role=treeitem]")) existing.set(li.dataset.id, li);
    const wanted = got.children.map((child) => {
      const li = existing.get(identity(child));
      if (!li) return itemFor(child, level);
      existing.delete(identity(child));
      li._child = child;
      li.replaceChild(rowFor(child, li), li.querySelector(":scope > .st-row"));
      return li;
    });
    let lostFocus = false;
    for (const li of existing.values()) {
      if (li.dataset.key) state.expanded.delete(li.dataset.key);
      if (li.contains(document.activeElement)) lostFocus = true;
      li.remove();
    }
    let ref = container.firstElementChild;
    for (const li of wanted) {                    // move only what is out of place
      if (li === ref) ref = ref.nextElementSibling;
      else container.insertBefore(li, ref);
    }
    setTail(container, key, level, got.next, got.truncated);
    if (lostFocus) focusItem(container.closest("li[role=treeitem]") || visibleItems()[0]);
    return true;
  }

  async function expand(li) {
    const key = li.dataset.key;
    if (!key || li.getAttribute("aria-expanded") === null) return;
    li.setAttribute("aria-expanded", "true");
    li.querySelector(":scope > .st-row .st-twisty").textContent = "▾";
    state.expanded.add(key);
    const g = groupOf(li);
    const level = parseInt(li.getAttribute("aria-level"), 10) + 1;
    g.hidden = false;
    if (!g.dataset.loaded) {
      g.dataset.loaded = "1";
      const filled = () => g.querySelector(":scope > li[role=treeitem]") !== null;
      // a refresh that overtook this load fills the group itself; a failed or stale
      // load of a still-empty group is retried on the next expand or refresh
      if (!filled() && !await loadChildren(g, key, level, state.generation) && !filled()) {
        delete g.dataset.loaded;
      }
    } else if (g.dataset.version !== String(state.version)) {
      await refreshGroup(g, key, level, state.generation);  // changed while collapsed
    }
    g.dataset.version = String(state.version);
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
    if (!li || ev.target !== li) return;          // a "Show more" button or a link: its own keys
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
    document.getElementById("st-node-truncated").hidden = !summary.body.truncated;
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
    const gen = state.generation;
    const { status: code, body } = await getJSON("/api/sitetree/node", nodeParams(key, { before: state.issuesNext }));
    if (code !== 200 || !body || key !== state.selected || gen !== state.generation) return;
    state.issuesNext = body.next;
    renderIssues(body.findings, true);
  });

  // --- (re)loading -------------------------------------------------------------------
  // a filter change rebuilds the tree (other nodes, other counts)
  async function reload() {
    state.generation += 1;
    const gen = state.generation;
    state.expanded = new Set();
    tree.replaceChildren();
    status.textContent = "";
    const ok = await loadChildren(tree, null, 1, gen);
    if (gen !== state.generation) return;
    empty.hidden = !ok || tree.querySelector("li[role=treeitem]") !== null;
    const first = tree.querySelector("li[role=treeitem]");
    if (first) first.tabIndex = 0;
    if (state.selected) {
      if (tree.querySelector(`li[data-key="${CSS.escape(state.selected)}"]`)) showNode(state.selected);
      else { state.selected = null; showNode(null); }
    }
  }

  // a store change refreshes what is shown, in place: root, then every expanded group
  // (outermost first), then the selection -- focus, expansion, selection and loaded
  // pages are kept (FR-UI-505)
  async function refresh() {
    state.generation += 1;
    const gen = state.generation;
    status.textContent = "";
    if (!await refreshGroup(tree, null, 1, gen)) return;
    for (const li of [...tree.querySelectorAll("li[role=treeitem][aria-expanded=true]")]) {
      if (gen !== state.generation) return;
      if (!li.isConnected) continue;
      const g = groupOf(li);
      const level = parseInt(li.getAttribute("aria-level"), 10) + 1;
      // an expand still loading (or whose load was overtaken) is loaded here
      const ok = g.querySelector(":scope > li[role=treeitem]")
        ? await refreshGroup(g, li.dataset.key, level, gen)
        : await loadChildren(g, li.dataset.key, level, gen);
      if (ok) {
        g.dataset.loaded = "1";
        g.dataset.version = String(state.version);
      }
    }
    if (gen !== state.generation) return;
    empty.hidden = tree.querySelector("li[role=treeitem]") !== null;
    if (!tree.querySelector("li[role=treeitem][tabindex='0']")) {
      const first = tree.querySelector("li[role=treeitem]");
      if (first) first.tabIndex = 0;
    }
    if (state.selected) {
      if (tree.querySelector(`li[data-key="${CSS.escape(state.selected)}"]`)) showNode(state.selected);
      else { state.selected = null; showNode(null); }
    }
  }

  let typing = null;
  form.addEventListener("change", (ev) => {
    if (ev.target === qInput) return;             // the search box reloads on input
    reload();
  });
  form.addEventListener("submit", (ev) => ev.preventDefault());
  qInput.addEventListener("input", () => {
    clearTimeout(typing);
    typing = setTimeout(reload, 300);
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
      await refresh();
    }
  }

  loadFacets();
  reload().then(() => { root.dataset.ready = "1"; });
  poll();
  setInterval(poll, pollMs);
}

initSiteTree();
