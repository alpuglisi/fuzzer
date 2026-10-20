// Site map (CC-UI-0500, FR-UI-500..505): a lazy WAI-ARIA treeview over the read-only
// /api/sitetree/* routes, with the selected node's contents and issues beside it (the
// three panes of the UI-research design, §12.3/§13.1).
//
// Safety: every value from the server is attacker-influenced (paths, parameter names,
// vuln classes come from a live target). They are rendered with textContent only --
// this module never parses HTML strings (enforced by tests/test_web_sitetree_browser.py).
//
// Live refresh (FR-UI-505, FR-UI-514, CC-UI-0068): the page polls the store version and
// refreshes in place, keeping the user's place: every focusable control in the tree and
// in Issues carries a focus key (`data-focus-key`: its identity, never its position),
// focus is restored through `livefocus.js`, a focused row is patched around its focused
// control, and a page the user asked for ("Show more", "Show more findings") is
// delivered exactly once whichever of it and a refresh comes first (one ordering rule,
// D6). `#sitetree-root` counts for tests: `data-baseline`, `data-polls`,
// `data-refreshes` (completed, successful refreshes) and `data-loads` (completed
// child-list loads and "Show more findings" loads, stale ones included).

import { focusKeyIn, patchInPlace, rerender, restoreFocus } from "/static/js/livefocus.js";

const PAGE = 200;              // a child-list page ("Show more"; the route's default)
const ISSUES_PAGE = 50;        // a page of findings ("Show more findings"; the route's default)
const ISSUES_MAX = 200;        // the node route's largest page of findings

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
  const issuesPane = document.getElementById("st-issues");
  const issuesMoreBtn = document.getElementById("st-issues-more");
  const pollMs = Math.max(250, parseInt(root.dataset.pollMs || "5000", 10) || 5000);

  const state = {
    expanded: new Set(),         // node keys
    selected: null,              // node key
    version: undefined,          // the last version whose refresh succeeded (the baseline first)
    lastRefresh: 0,
    issuesNext: null,
    issuesMore: null,            // the user's "Show more findings" in flight (D6 token)
    generation: 0,               // bumps on every filter change / refresh
    refreshing: null,            // the refresh in flight (a promise), or null
  };

  // page counters for tests (D8): never a sleep
  function bump(name) {
    root.dataset[name] = String((parseInt(root.dataset[name] || "0", 10) || 0) + 1);
  }

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

  // the key of the group a container lists: "root" for the tree itself
  function groupKey(container) {
    return container === tree ? "root" : container.parentElement.dataset.key;
  }

  function itemFor(child, level, container) {
    const expandable = Boolean(child.expandable && child.key);
    const li = el("li", {
      role: "treeitem", "aria-level": level, "aria-selected": "false", tabindex: "-1",
      class: `st-item st-${child.kind}`,
      "aria-expanded": expandable ? "false" : null,
    });
    li.dataset.id = identity(child);
    if (child.key) li.dataset.key = child.key;
    // identity within its group, never position: a group never lists one id twice
    li.dataset.focusKey = `item:${groupKey(container)}>${li.dataset.id}`;
    li.append(rowFor(child, li));
    li._child = child;
    return li;
  }

  // the visible row of an item; rebuilt on refresh inside the same <li>, so focus,
  // selection, expansion and loaded children stay where they are (a row holding focus
  // is patched around its focused control: `patchInPlace`)
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
          "data-focus-key": `count:${li.dataset.focusKey}`,
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
      row.append(el("a", { href: child.href, class: "st-open", tabindex: "-1",
        "data-focus-key": `open:${li.dataset.focusKey}`, text: "open" }));
    }
    row.addEventListener("click", () => {     // read at click time: a patched row is kept
      select(li);
      if (li.getAttribute("aria-expanded") !== null) toggle(li);
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

  // fetch pages of a node's children (`PAGE` a request) until `want` are loaded or there
  // are no more -- and, with `reach` (a refresh: the identity of the last item shown),
  // until that item is among them, at most one page further, so an item that sorts
  // earlier never pushes a shown one behind "Show more"
  async function fetchPages(key, gen, after, want, reach = null) {
    try {
      const out = [];
      let seen = reach === null;
      let next = after;
      let truncated = false;
      do {
        const { status: code, body } = await getJSON("/api/sitetree/children",
          nodeParams(key, { after: next, limit: String(PAGE) }));
        if (gen !== state.generation) return { stale: true };
        if (code === 404 && key) return { gone: true };
        if (code !== 200 || !body) {
          return { error: (body && body.detail) ? `Could not load: ${body.detail}` : "Could not load this node." };
        }
        out.push(...body.children);
        seen = seen || body.children.some((c) => identity(c) === reach);
        next = body.next;
        truncated = truncated || Boolean(body.truncated);
      } while (next && (out.length < want || (!seen && out.length < want + PAGE)));
      return { children: out, next, truncated };
    } finally {
      bump("loads");
    }
  }

  const treeItems = (container) => [...container.querySelectorAll(":scope > li[role=treeitem]")];

  // where focus goes when the focused tree control is gone (D7): a row control -> its
  // item -> the parent item; "Show more" -> its group's last item -> the parent item;
  // an item -> its parent item; then the tree's pane (restoreFocus's last resort)
  function treeFallbacks() {
    const a = document.activeElement;
    if (!a || !tree.contains(a) || a === tree) return [];
    const out = [];
    if (a.matches(".st-more-btn")) {
      const group = a.closest("ul");
      out.push(() => treeItems(group).pop(), group === tree ? null : group.closest("li[role=treeitem]"));
    } else {
      const item = a.closest("li[role=treeitem]");
      if (item && item !== a) out.push(item);
      if (item) out.push(item.parentElement.closest("li[role=treeitem]"));
    }
    return out.filter(Boolean);
  }

  // restore the tree's focus after a change; an item that receives it gets the roving tabindex
  function restoreTree(key, fallbacks) {
    const got = restoreFocus(tree, key, ...fallbacks);
    if (got && got.matches("li[role=treeitem]")) setRoving(got);
    return got;
  }

  function dropNode(key) {
    const gone = tree.querySelector(`li[data-key="${CSS.escape(key)}"]`);
    if (!gone) return;
    state.expanded.delete(key);
    const focusKey = focusKeyIn(tree);
    const parent = gone.parentElement.closest("li[role=treeitem]");
    gone.remove();
    restoreTree(focusKey, [parent]);
  }

  // the tail of a group: the truncation note and "Show more". "Show more" is reused in
  // place (its cursor lives on the button), so a focused one keeps focus across a refresh
  function setTail(container, key, level, next, truncated) {
    let trunc = container.querySelector(":scope > li.st-trunc-item");
    let more = container.querySelector(":scope > li.st-more-item");
    if (truncated && !trunc) {
      trunc = el("li", { role: "none", class: "st-trunc-item muted",
        text: "List truncated: this endpoint has more recorded groups than the site map reads at once." });
      if (more) more.before(trunc);
      else container.append(trunc);
    } else if (!truncated && trunc) {
      trunc.remove();
    }
    if (!next) {
      if (more) more.remove();                 // focus: the caller's restore (its last item)
      return;
    }
    if (!more) {
      const btn = el("button", { type: "button", class: "st-more-btn",
        "data-focus-key": `more:${groupKey(container)}` });
      btn.addEventListener("click", () => showMore(container, key, level, btn));
      more = el("li", { role: "none", class: "st-more-item" }, btn);
      container.append(more);
    }
    const btn = more.firstElementChild;
    btn._next = next;
    btn.textContent = `Show more (${treeItems(container).length} loaded)`;
    btn.disabled = Boolean(container._more);   // one page per click, never twice
  }

  // A page the user asked for, against a refresh (D6): the click registers a token on
  // its group before its fetch. A refresh of the group reads it before and after its own
  // fetch, fetches the extra page itself and consumes it. The user's load appends only
  // while its generation is current (de-duplicated by identity); when a refresh moved the
  // generation on, an old cursor's page is never appended: the refresh delivers it, or
  // the user's load asks for a refresh of its group once that refresh is over. A group
  // gone or collapsed meanwhile takes the token with it, and a still-attached button is
  // re-enabled: nothing is lost silently.
  async function showMore(container, key, level, btn) {
    if (container._more) return;
    const last = treeItems(container).pop();
    const token = { after: last ? last.dataset.id : null, gen: state.generation,
                    hadFocus: document.activeElement === btn };   // before disabling blurs it
    container._more = token;
    btn.disabled = true;
    const got = await fetchPages(key, token.gen, btn._next, PAGE);
    if (container._more !== token) return;                 // a refresh delivered it
    const live = () => container.isConnected && !container.hidden;
    if (!live()) { dropToken(container, token); return; }
    if (got.gone) { container._more = null; dropNode(key); return; }
    if (token.gen === state.generation && !got.stale) {
      if (got.error) { status.textContent = got.error; dropToken(container, token); return; }
      const tail = container.querySelector(":scope > li.st-trunc-item, :scope > li.st-more-item");
      const have = new Set(treeItems(container).map((li) => li.dataset.id));
      for (const child of got.children) {
        if (!have.has(identity(child))) container.insertBefore(itemFor(child, level, container), tail);
      }
      container._more = null;
      setTail(container, key, level, got.next, got.truncated);
      deliverFocus(container, token);
      return;
    }
    while (state.refreshing) await state.refreshing;       // the refresh may deliver it
    if (container._more !== token) return;
    if (live()) await refreshGroup(container, key, level, state.generation);
    if (container._more === token) dropToken(container, token);
  }

  function dropToken(container, token) {
    if (container._more !== token) return;
    container._more = null;
    const btn = container.querySelector(":scope > li.st-more-item > button");
    if (btn) btn.disabled = false;
  }

  // the user's page has arrived: a keyboard user who pressed "Show more" goes on at its
  // first item -- the one after the item that was last when they pressed it, by identity
  // (unless focus has moved on meanwhile)
  function deliverFocus(container, token) {
    if (!token.hadFocus) return;
    const a = document.activeElement;
    if (a && a !== document.body && !a.matches(".st-more-btn")) return;
    const items = treeItems(container);
    const at = items.findIndex((li) => li.dataset.id === token.after);
    const first = at >= 0 ? items[at + 1] : null;
    if (first) focusItem(first);
  }

  // a group's first page is loaded once per generation: an expand and a refresh that
  // both reach an empty group share one load (code review R3-1). A load of an older
  // generation is never reused -- it drops its own (stale) result.
  function loadChildren(container, key, level, gen, after = null) {
    const pending = container._loading;
    if (after === null && pending && pending.gen === gen) return pending.run;
    const run = (async () => {
      const got = await fetchPages(key, gen, after, PAGE);
      if (got.stale) return false;
      if (got.gone) { dropNode(key); return true; }   // handled: the node is no more
      if (got.error) { status.textContent = got.error; return false; }
      const tail = container.querySelector(":scope > li.st-trunc-item, :scope > li.st-more-item");
      const have = new Set(treeItems(container).map((li) => li.dataset.id));
      for (const child of got.children) {             // never twice
        if (!have.has(identity(child))) container.insertBefore(itemFor(child, level, container), tail);
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

  // Re-fetch a loaded group -- the pages it shows, down to its last shown item, plus the
  // page a "Show more" token asks for -- and update it in place. The token and the count
  // are read before and after the fetch; if either changed meanwhile, it fetches once
  // more (D6). Returns true when the group is up to date (or gone), false when stale or
  // failed.
  async function refreshGroup(container, key, level, gen) {
    const want = () => Math.max(1, treeItems(container).length) + (container._more ? PAGE : 0);
    const last = () => { const li = treeItems(container).pop(); return li ? li.dataset.id : null; };
    let token = container._more;
    let n = treeItems(container).length;
    let got = await fetchPages(key, gen, null, want(), last());
    if (!got.stale && !got.gone && !got.error && (container._more !== token || treeItems(container).length !== n)) {
      token = container._more;
      n = treeItems(container).length;
      got = await fetchPages(key, gen, null, want(), last());
    }
    if (got.stale) return false;
    if (got.gone) { dropNode(key); return true; }
    if (got.error) { status.textContent = got.error; return false; }
    const focusKey = focusKeyIn(tree);
    const fallbacks = treeFallbacks();
    const existing = new Map();
    for (const li of treeItems(container)) existing.set(li.dataset.id, li);
    const wanted = got.children.map((child) => {
      const li = existing.get(identity(child));
      if (!li) return itemFor(child, level, container);
      existing.delete(identity(child));
      li._child = child;
      patchInPlace(li.querySelector(":scope > .st-row"), rowFor(child, li));
      return li;
    });
    for (const li of existing.values()) {
      if (li.dataset.key) state.expanded.delete(li.dataset.key);
      li.remove();
    }
    let ref = container.firstElementChild;
    for (const li of wanted) {                    // move only what is out of place
      if (li === ref) ref = ref.nextElementSibling;
      else container.insertBefore(li, ref);
    }
    const delivered = token && container._more === token ? token : null;
    if (delivered) container._more = null;        // the page it asked for is in
    setTail(container, key, level, got.next, got.truncated);
    restoreTree(focusKey, fallbacks);
    if (delivered) deliverFocus(container, delivered);
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

  function setRoving(li) {
    for (const other of tree.querySelectorAll("li[role=treeitem][tabindex='0']")) other.tabIndex = -1;
    li.tabIndex = 0;
  }

  function focusItem(li) {
    if (!li) return;
    setRoving(li);
    li.focus();
  }

  tree.addEventListener("keydown", (ev) => {
    if (ev.target === tree && (ev.key === "ArrowDown" || ev.key === "Home")) {
      focusItem(visibleItems()[0]);              // the pane itself (a refresh's last resort)
      ev.preventDefault();
      return;
    }
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

  const shownFindings = () => [...issuesPane.querySelectorAll("#st-issues-table tbody tr[data-id]")];

  // the node's summary and its findings: `want` of them at least, and (`oldest`) every
  // finding down to the oldest one shown, following the route's cursor
  async function loadNode(key, gen, want, oldest) {
    const [summary, kids] = await Promise.all([
      getJSON("/api/sitetree/node", nodeParams(key, { limit: String(Math.min(ISSUES_MAX, want)) })),
      getJSON("/api/sitetree/children", nodeParams(key, { limit: String(PAGE) })),
    ]);
    if (gen !== state.generation) return { stale: true };
    if (summary.status !== 200 || !summary.body) return { summary };
    const findings = [...(summary.body.findings || [])];
    let next = summary.body.next;
    while (next && (findings.length < want
                    || (oldest !== null && findings[findings.length - 1].id > oldest))) {
      const limit = findings.length < want ? Math.min(ISSUES_MAX, want - findings.length) : ISSUES_PAGE;
      const more = await getJSON("/api/sitetree/node", nodeParams(key, { before: next, limit: String(limit) }));
      if (gen !== state.generation) return { stale: true };
      if (more.status !== 200 || !more.body) return { summary: more };
      findings.push(...(more.body.findings || []));
      next = more.body.next;
    }
    return { summary, kids, findings, next };
  }

  // Show the selected node's contents and issues. `keep` (a refresh): as many findings
  // as are shown, plus the page a "Show more findings" token asks for, read before and
  // after the fetch like a tree group (D6). Returns false only when stale (a newer
  // refresh or reload owns the page) or failed.
  async function showNode(key, opts = {}) {
    const box = document.getElementById("st-node");
    const none = document.getElementById("st-contents-empty");
    if (!key) {
      box.hidden = true;
      none.hidden = false;
      return true;
    }
    const gen = state.generation;
    const shown = () => shownFindings().length;
    const oldest = () => {
      const ids = shownFindings().map((tr) => Number(tr.dataset.id));
      return ids.length ? Math.min(...ids) : null;
    };
    const want = () => (opts.keep ? Math.max(ISSUES_PAGE, shown()) : ISSUES_PAGE)
      + (opts.keep && state.issuesMore ? ISSUES_PAGE : 0);
    let token = state.issuesMore;
    let n = shown();
    let got = await loadNode(key, gen, want(), opts.keep ? oldest() : null);
    if (opts.keep && got.findings && (state.issuesMore !== token || shown() !== n)) {
      token = state.issuesMore;
      n = shown();
      got = await loadNode(key, gen, want(), oldest());
    }
    if (got.stale || gen !== state.generation) return false;
    if (key !== state.selected) return true;           // another selection shows itself
    if (!got.findings) {
      box.hidden = true;
      none.hidden = false;
      none.textContent = got.summary.status === 404 ? "This node is no longer in the store." : "Could not load this node.";
      return got.summary.status === 404;
    }
    const summary = got.summary.body;
    none.hidden = true;
    box.hidden = false;
    renderNode(summary);
    document.getElementById("st-node-truncated").hidden = !summary.truncated;
    renderChildren(got.kids.status === 200 && got.kids.body ? got.kids.body : { children: [] });
    state.issuesNext = got.next;
    if (opts.keep && token && state.issuesMore === token) state.issuesMore = null;  // its page is in
    renderIssues(got.findings, false);
    if (opts.focusIssues) issuesPane.focus();
    return true;
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

  // findings as rows, newest first; appending skips a finding already shown (by id).
  // Re-rendered through the one focus helper: a focused finding link keeps focus by its
  // key (`issue:<id>`), else the Issues pane takes it.
  function renderIssues(findings, append) {
    const table = document.getElementById("st-issues-table");
    const tbody = table.querySelector("tbody");
    rerender(issuesPane, () => {
      if (!append) tbody.replaceChildren();
      const have = new Set(shownFindings().map((tr) => tr.dataset.id));
      for (const f of findings || []) {
        if (have.has(String(f.id))) continue;
        have.add(String(f.id));
        const loc = `${f.method || "(method not recorded)"} ${f.path || ""}${f.param ? " · " + f.param : ""}`;
        const link = (f.href || "").startsWith("/findings/")
          ? el("a", { href: f.href, "data-focus-key": `issue:${f.id}`, text: `#${f.id}` })
          : el("span", { text: `#${f.id}` });
        const tr = el("tr", {}, el("td", {}, el("span", { class: `badge sev-${f.severity || "info"}`, text: f.severity || "info" })),
          el("td", { text: f.vuln_class || "" }), el("td", {}, el("code", { text: loc })),
          el("td", { text: f.mechanism || "" }), el("td", { text: `#${f.run_id}` }), el("td", {}, link));
        tr.dataset.id = String(f.id);
        tbody.append(tr);
      }
      const any = tbody.children.length > 0;
      table.hidden = !any;
      document.getElementById("st-issues-empty").hidden = any;
      issuesMoreBtn.hidden = !state.issuesNext;
    });
  }

  // "Show more findings" against a refresh: the same ordering rule as "Show more" (D6)
  issuesMoreBtn.addEventListener("click", async () => {
    if (!state.selected || !state.issuesNext || state.issuesMore) return;
    const key = state.selected;
    const token = { gen: state.generation, key };
    state.issuesMore = token;                       // registered before the fetch
    let got;
    try {
      got = await getJSON("/api/sitetree/node", nodeParams(key, { before: state.issuesNext }));
    } finally {
      bump("loads");
    }
    const { status: code, body } = got;
    if (state.issuesMore !== token) return;          // a refresh delivered it
    if (key !== state.selected) { state.issuesMore = null; return; }
    if (token.gen === state.generation) {
      state.issuesMore = null;
      if (code !== 200 || !body) return;             // the button stays: ask again
      state.issuesNext = body.next;
      renderIssues(body.findings, true);
      return;
    }
    while (state.refreshing) await state.refreshing;
    if (state.issuesMore !== token) return;
    if (key === state.selected) await showNode(key, { keep: true });
    if (state.issuesMore === token) state.issuesMore = null;
  });

  // --- (re)loading -------------------------------------------------------------------
  // a filter change rebuilds the tree (other nodes, other counts)
  async function reload() {
    state.generation += 1;
    const gen = state.generation;
    state.expanded = new Set();
    state.issuesMore = null;
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

  // A store change refreshes what is shown, in place: root, then every expanded group
  // (outermost first), then the selection and its Issues pages -- focus, expansion,
  // selection and loaded pages are kept (FR-UI-505, FR-UI-514). Returns true only when
  // all of it is up to date for `version`: the poll marks a version seen only then, so a
  // failed refresh is retried at the next poll.
  async function refresh(version) {
    state.generation += 1;
    const gen = state.generation;
    const run = (async () => {
      status.textContent = "";
      if (!await refreshGroup(tree, null, 1, gen)) return false;
      for (const li of [...tree.querySelectorAll("li[role=treeitem][aria-expanded=true]")]) {
        if (gen !== state.generation) return false;
        if (!li.isConnected) continue;
        const g = groupOf(li);
        const level = parseInt(li.getAttribute("aria-level"), 10) + 1;
        // an expand still loading (or whose load was overtaken) is loaded here
        const ok = treeItems(g).length
          ? await refreshGroup(g, li.dataset.key, level, gen)
          : await loadChildren(g, li.dataset.key, level, gen);
        if (!ok) return false;
        g.dataset.loaded = "1";
        g.dataset.version = String(version);
      }
      if (gen !== state.generation) return false;
      empty.hidden = tree.querySelector("li[role=treeitem]") !== null;
      if (!tree.querySelector("li[role=treeitem][tabindex='0']")) {
        const first = tree.querySelector("li[role=treeitem]");
        if (first) first.tabIndex = 0;
      }
      if (state.selected) {
        if (tree.querySelector(`li[data-key="${CSS.escape(state.selected)}"]`)) {
          if (!await showNode(state.selected, { keep: true })) return false;
        } else {
          state.selected = null;
          await showNode(null);
        }
      }
      return gen === state.generation;
    })();
    state.refreshing = run;
    try {
      return await run;
    } finally {
      if (state.refreshing === run) state.refreshing = null;
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

  // --- live refresh: poll the store version while visible (FR-UI-505) ---------------
  // One poll at a time. A version is marked seen only once its refresh succeeded (a
  // failed or overtaken refresh is retried at the next poll), and at most one refresh
  // runs per poll interval. A poll that skips (hidden page, failed fetch) is not counted.
  let polling = false;
  async function poll() {
    if (document.visibilityState !== "visible" || polling) return;
    polling = true;
    try {
      let v;
      try {
        const r = await fetch("/api/sitetree/version", { headers: { Accept: "application/json" } });
        if (!r.ok) return;
        const body = await r.json();
        if (!body || body.version === undefined) return;
        v = body.version;
      } catch (_) {
        return;
      }
      if (state.version === undefined) {
        state.version = v;                       // the baseline, taken before the first read
        root.dataset.baseline = "1";
      } else if (v !== state.version && Date.now() - state.lastRefresh >= pollMs) {
        state.lastRefresh = Date.now();
        if (await refresh(v)) {
          state.version = v;
          bump("refreshes");
        }
      }
      bump("polls");
    } finally {
      polling = false;
    }
  }

  loadFacets();
  poll().finally(() => {
    reload().then(() => { root.dataset.ready = "1"; });
    setInterval(poll, pollMs);
  });
}

initSiteTree();
