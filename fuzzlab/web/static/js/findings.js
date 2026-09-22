// Findings workbench (U2/CC-UI-0029): faceted filters + saved views + the
// shared DataTable over `finding`. All filtering/sorting is client-side over
// one fetched snapshot (D4/R-03 — no virtualization, a few thousand rows is
// the ceiling this needs). `severity` is a UI-only derived band the server
// computes (`fuzzlab.web.findingsview.derive_severity`) — never invented here.
import { createDataTable, rankSort, SEVERITY_RANK } from "/static/js/datatable.js";

const TABLE_KEY = "finding";

// Facet groups (R-03: ~4-6 groups). `get` reads the faceted value off a finding.
const FACET_GROUPS = [
  { key: "severity", label: "Severity", get: (f) => f.severity || "info" },
  { key: "vuln_class", label: "Vuln class", get: (f) => f.vuln_class || "(unknown)" },
  { key: "method", label: "Method", get: (f) => f.method || "(unknown)" },
  { key: "confidence", label: "Mechanism", get: (f) => f.confidence || "(unknown)" },
  { key: "url", label: "Endpoint", get: (f) => f.url || "(unknown)" },
];

// Per-viewer throwaway state only (never durable data) — collapsed groups, the
// last-applied saved view id, and a draft quick-filter string. Wrapped in
// try/catch: private windows / blocked storage must never break the page.
function readLocal(key, fallback) {
  try {
    const v = localStorage.getItem(key);
    return v == null ? fallback : JSON.parse(v);
  } catch (_) {
    return fallback;
  }
}
function writeLocal(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) { /* ignore */ }
}

function severityBadge(sev) {
  const span = document.createElement("span");
  span.className = `badge sev-${sev || "info"}`;
  span.textContent = sev || "info";
  return span;
}

function debounce(fn, ms) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function initFindings() {
  const root = document.getElementById("findings-table");
  if (!root) return; // not the Findings page

  const facetGroupsEl = document.getElementById("facet-groups");
  const chipsRow = document.getElementById("chips-row");
  const quickFilter = document.getElementById("quick-filter");
  const liveRegion = document.getElementById("findings-live");
  const emptyMsg = document.getElementById("findings-empty");
  const viewsRow = document.getElementById("views-row");
  const repForm = document.getElementById("row-to-repeater-form");
  const repIdInput = document.getElementById("row-to-repeater-id");

  let allFindings = [];
  // group key -> Set(selected values); OR within a group, AND across groups.
  const selected = new Map(FACET_GROUPS.map((g) => [g.key, new Set()]));
  const collapsed = new Set(readLocal("fl-findings-collapsed", []));
  let views = [];
  let activeViewId = readLocal("fl-findings-lastview", null);

  const columns = [
    { key: "id", label: "#", sortValue: (f) => f.id, render: (f) => `#${f.id}` },
    { key: "severity", label: "Severity", sortValue: rankSort(SEVERITY_RANK, "severity"),
      render: (f) => severityBadge(f.severity) },
    { key: "vuln_class", label: "Vuln class", sortValue: (f) => f.vuln_class || "",
      render: (f) => f.vuln_class || "" },
    { key: "method", label: "Method", sortValue: (f) => f.method || "",
      render: (f) => f.method || "" },
    { key: "url", label: "Endpoint", sortValue: (f) => f.url || "",
      render: (f) => f.url || "" },
    { key: "param", label: "Param", sortValue: (f) => f.param || "",
      render: (f) => f.param || "" },
    { key: "confidence", label: "Mechanism", sortValue: (f) => f.confidence || "",
      render: (f) => f.confidence || "" },
    { key: "created_at", label: "Created", sortValue: (f) => f.created_at || "",
      render: (f) => f.created_at || "" },
  ];

  const dt = createDataTable(root, {
    caption: "Findings, newest first",
    columns,
    data: [],
    rowHref: (f) => `/findings/${f.id}`,
    onRowClick: (f) => { window.location.href = `/findings/${f.id}`; },
    rowActions: [{
      label: "Repeater",
      ariaLabel: (f) => `Send finding #${f.id} to Repeater`,
      onClick: (f) => {
        repIdInput.value = String(f.id);
        repForm.requestSubmit();
      },
    }],
    textFilterKeys: ["url", "param", "vuln_class", "confidence"],
    emptyMessage: "No findings match the current filters.",
    liveRegion,
  });

  function matchesFacets(f) {
    return FACET_GROUPS.every((g) => {
      const sel = selected.get(g.key);
      return sel.size === 0 || sel.has(g.get(f));
    });
  }

  function matchesOtherGroups(f, exceptKey) {
    return FACET_GROUPS.every((g) => {
      if (g.key === exceptKey) return true;
      const sel = selected.get(g.key);
      return sel.size === 0 || sel.has(g.get(f));
    });
  }

  function sortValues(groupKey, values) {
    if (groupKey === "severity") {
      return values.sort((a, b) => (SEVERITY_RANK[b] ?? -1) - (SEVERITY_RANK[a] ?? -1));
    }
    return values.sort((a, b) => a.localeCompare(b));
  }

  function renderFacets() {
    facetGroupsEl.replaceChildren();
    for (const group of FACET_GROUPS) {
      const counts = new Map();
      for (const f of allFindings) {
        if (!matchesOtherGroups(f, group.key)) continue;
        const v = group.get(f);
        counts.set(v, (counts.get(v) || 0) + 1);
      }
      const values = sortValues(group.key, [...counts.keys()]);

      const fieldset = document.createElement("fieldset");
      fieldset.className = "facet-group";
      const legend = document.createElement("legend");
      legend.className = "visually-hidden";
      legend.textContent = group.label;
      fieldset.appendChild(legend);

      // APG Disclosure pattern (R-11): a real <button aria-expanded
      // aria-controls> gates a hideable panel; state persists per-viewer only.
      const panelId = `facet-panel-${group.key}`;
      const isOpen = !collapsed.has(group.key);
      const header = document.createElement("button");
      header.type = "button";
      header.className = "facet-group-header";
      header.setAttribute("aria-expanded", String(isOpen));
      header.setAttribute("aria-controls", panelId);
      const labelSpan = document.createElement("span");
      labelSpan.textContent = group.label;
      const chev = document.createElement("span");
      chev.className = "chev";
      chev.setAttribute("aria-hidden", "true");
      chev.textContent = "▾";
      header.appendChild(labelSpan);
      header.appendChild(chev);
      header.addEventListener("click", () => {
        const nowOpen = header.getAttribute("aria-expanded") !== "true";
        header.setAttribute("aria-expanded", String(nowOpen));
        list.hidden = !nowOpen;
        if (nowOpen) collapsed.delete(group.key); else collapsed.add(group.key);
        writeLocal("fl-findings-collapsed", [...collapsed]);
      });
      fieldset.appendChild(header);

      const list = document.createElement("ul");
      list.className = "facet-options";
      list.id = panelId;
      list.setAttribute("role", "group");
      list.hidden = !isOpen;
      for (const value of values) {
        const li = document.createElement("li");
        const label = document.createElement("label");
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = selected.get(group.key).has(value);
        cb.addEventListener("change", () => {
          const sel = selected.get(group.key);
          if (cb.checked) sel.add(value); else sel.delete(value);
          activeViewId = null;
          applyFilters();
        });
        const text = document.createElement("span");
        text.textContent = value;
        const count = document.createElement("span");
        count.className = "fcount";
        count.textContent = String(counts.get(value));
        label.appendChild(cb);
        label.appendChild(text);
        label.appendChild(count);
        li.appendChild(label);
        list.appendChild(li);
      }
      fieldset.appendChild(list);
      facetGroupsEl.appendChild(fieldset);
    }
  }

  function focusQuickFilter() {
    // Move focus somewhere real on chip/filter removal (R-11) — never to
    // <body>. The quick-filter input is always present and a sensible target.
    if (quickFilter) quickFilter.focus();
  }

  function renderChips() {
    chipsRow.replaceChildren();
    let any = false;
    const addChip = (labelText, onRemove) => {
      any = true;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "chip-filter";
      btn.setAttribute("aria-label", `Remove filter: ${labelText}`);
      const text = document.createElement("span");
      text.textContent = labelText;
      const x = document.createElement("span");
      x.className = "x";
      x.setAttribute("aria-hidden", "true");
      x.textContent = "×";
      btn.appendChild(text);
      btn.appendChild(x);
      btn.addEventListener("click", () => { onRemove(); focusQuickFilter(); });
      chipsRow.appendChild(btn);
    };
    for (const group of FACET_GROUPS) {
      for (const value of selected.get(group.key)) {
        addChip(`${group.label}: ${value}`, () => {
          selected.get(group.key).delete(value);
          activeViewId = null;
          applyFilters();
        });
      }
    }
    if (quickFilter && quickFilter.value.trim()) {
      addChip(`search: ${quickFilter.value.trim()}`, () => {
        quickFilter.value = "";
        activeViewId = null;
        applyFilters();
      });
    }
    if (any) {
      const clearBtn = document.createElement("button");
      clearBtn.type = "button";
      clearBtn.className = "chip-clear";
      clearBtn.textContent = "Clear all";
      clearBtn.addEventListener("click", () => {
        for (const sel of selected.values()) sel.clear();
        if (quickFilter) quickFilter.value = "";
        activeViewId = null;
        applyFilters();
        focusQuickFilter();
      });
      chipsRow.appendChild(clearBtn);
    }
  }

  function applyFilters() {
    dt.setFilter(matchesFacets);
    renderFacets();
    renderChips();
    renderViews();
  }

  const onQuickFilter = debounce(() => {
    dt.setTextFilter(quickFilter.value);
    writeLocal("fl-findings-draft", quickFilter.value);
    activeViewId = null;
    renderChips();
    renderViews();
  }, 200);
  if (quickFilter) {
    quickFilter.value = readLocal("fl-findings-draft", "");
    if (quickFilter.value) dt.setTextFilter(quickFilter.value);
    quickFilter.addEventListener("input", onQuickFilter);
  }

  // --- saved views (server-side, GET/POST/PUT/DELETE /api/views?table=) -----

  function currentSpec(name) {
    const facets = {};
    for (const [k, set] of selected) if (set.size) facets[k] = [...set];
    const sort = dt.getSort();
    return {
      version: 1,
      name,
      filter: { text: quickFilter ? quickFilter.value : "", facets },
      sort,
    };
  }

  function applySpec(view) {
    const spec = view.spec || {};
    const filter = spec.filter || {};
    for (const [k, set] of selected) set.clear();
    for (const [k, values] of Object.entries(filter.facets || {})) {
      const set = selected.get(k);
      if (set) for (const v of values) set.add(v);
    }
    if (quickFilter) quickFilter.value = filter.text || "";
    dt.setTextFilter(filter.text || "");
    if (spec.sort && spec.sort.key) dt.setSort(spec.sort.key, spec.sort.dir);
    activeViewId = view.id;
    writeLocal("fl-findings-lastview", activeViewId);
    applyFilters();
  }

  async function loadViews() {
    const r = await fetch(`/api/views?table=${encodeURIComponent(TABLE_KEY)}`);
    views = r.ok ? (await r.json()).views || [] : [];
    renderViews();
    if (activeViewId != null) {
      const v = views.find((x) => x.id === activeViewId);
      if (v) applySpec(v);
    }
  }

  function renderViews() {
    viewsRow.replaceChildren();
    const label = document.createElement("span");
    label.className = "muted";
    label.textContent = "Views:";
    viewsRow.appendChild(label);
    for (const view of views) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "chip-view" + (view.is_pinned ? " pinned" : "")
        + (view.id === activeViewId ? " active" : "");
      btn.textContent = view.name;
      btn.title = "Apply this saved view";
      btn.addEventListener("click", () => applySpec(view));
      viewsRow.appendChild(btn);

      const del = document.createElement("button");
      del.type = "button";
      del.className = "chip-clear";
      del.setAttribute("aria-label", `Delete view: ${view.name}`);
      del.textContent = "×";
      del.addEventListener("click", async () => {
        await fetch(`/api/views/${view.id}`, {
          method: "DELETE", headers: { "X-Fuzzlab-Client": "1" },
        });
        if (activeViewId === view.id) activeViewId = null;
        await loadViews();
      });
      viewsRow.appendChild(del);
    }

    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.placeholder = "Save current filter as…";
    nameInput.setAttribute("aria-label", "New saved view name");
    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.textContent = "Save view";
    saveBtn.addEventListener("click", async () => {
      const name = nameInput.value.trim();
      if (!name) { nameInput.focus(); return; }
      const r = await fetch("/api/views", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Fuzzlab-Client": "1" },
        body: JSON.stringify({ table: TABLE_KEY, name, spec: currentSpec(name) }),
      });
      if (r.ok) {
        const { view } = await r.json();
        activeViewId = view.id;
        writeLocal("fl-findings-lastview", activeViewId);
        nameInput.value = "";
        await loadViews();
      }
    });
    const wrap = document.createElement("span");
    wrap.className = "view-save";
    wrap.appendChild(nameInput);
    wrap.appendChild(saveBtn);
    viewsRow.appendChild(wrap);
  }

  async function load() {
    const r = await fetch("/api/findings");
    allFindings = r.ok ? (await r.json()).findings || [] : [];
    dt.setData(allFindings);
    if (emptyMsg) emptyMsg.hidden = allFindings.length > 0;
    applyFilters();
  }

  load();
  loadViews();
}

initFindings();
