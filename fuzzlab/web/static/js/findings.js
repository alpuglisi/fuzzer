// fuzzlab control panel — Findings workbench (U2).
//
// Facet sidebar (multi-select checkboxes, OR within a group / AND across
// groups) + a debounced quick-filter + applied-filter chips + a saved-view
// chip row, over the shared js/datatable.js. Everything filters in-memory
// (R-03): one `/api/findings` fetch on load, then filter/sort entirely
// client-side. Findings only ever GET here — the one mutating action ("send
// to Repeater") is a real `<form method=post>` PRG (see finding_detail.html /
// POST /findings/{id}/send-to-repeater in app.py), not a fetch.

import { createDataTable, makeSafeLink } from "./datatable.js";

const FACET_GROUPS = [
  { key: "vuln_class", label: "Vuln class" },
  { key: "severity", label: "Severity" },
  { key: "method", label: "Method" },
  { key: "confidence", label: "Confidence / mechanism" },
  { key: "url", label: "Endpoint" },
];

const SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
const SEVERITY_CLASS = {
  Critical: "sev-critical", High: "sev-high", Medium: "sev-medium",
  Low: "sev-low", Info: "sev-info",
};

// Per-viewer throwaway convenience only (R-07's state rule): last selected
// view, draft filter text, collapsed facet groups. Never durable data — that
// lives server-side in `saved_views` (see fuzzlab/web/savedviews.py).
const ls = {
  get(k) { try { return localStorage.getItem(k); } catch (_) { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (_) { /* ignore */ } },
  del(k) { try { localStorage.removeItem(k); } catch (_) { /* ignore */ } },
};

function debounce(fn, ms) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function initFindings() {
  const mount = document.getElementById("findings-table-mount");
  if (!mount) return; // not the findings page

  let allRows = [];
  // facets[groupKey] = Set of selected values (empty set = no restriction).
  const facets = {};
  for (const g of FACET_GROUPS) facets[g.key] = new Set();
  let textQuery = ls.get("fl-findings-draft-text") || "";

  const quickFilter = document.getElementById("findings-quickfilter");
  const facetContainer = document.getElementById("facet-groups");
  const chipsContainer = document.getElementById("filter-chips");
  const viewsChips = document.getElementById("views-chips");
  const sidebar = document.getElementById("facet-sidebar");
  const collapseToggle = document.getElementById("facet-collapse-toggle");

  let currentViewId = ls.get("fl-findings-last-view") || null;

  const table = createDataTable({
    container: mount,
    data: [],
    textFilterKeys: ["url", "param", "vuln_class", "method", "confidence"],
    emptyMessage: "No findings match the current filters.",
    columns: [
      {
        key: "severity", label: "Severity", sortValue: (r) => SEVERITY_RANK[r.severity] ?? 99,
        render: (r) => {
          const span = document.createElement("span");
          span.className = "badge " + (SEVERITY_CLASS[r.severity] || "sev-info");
          span.textContent = r.severity;
          return span;
        },
      },
      { key: "vuln_class", label: "Vuln class" },
      { key: "method", label: "Method" },
      {
        key: "url", label: "Endpoint",
        render: (r) => makeSafeLink(`/findings/${r.id}`, r.url || ""),
      },
      { key: "param", label: "Param" },
      { key: "confidence", label: "Mechanism" },
      { key: "run_id", label: "Run", render: (r) => makeSafeLink(`/runs/${r.run_id}`, "#" + r.run_id) },
      { key: "created_at", label: "Recorded" },
    ],
    onRowClick: (row) => { window.location.href = `/findings/${row.id}`; },
    rowActions: [
      {
        render: (row) => {
          // Real PRG form (R-07): POST -> RedirectResponse(303) -> /proxy.
          // Disable-on-submit guards a double click/submit.
          const form = document.createElement("form");
          form.method = "post";
          form.action = `/findings/${row.id}/send-to-repeater`;
          form.addEventListener("click", (e) => e.stopPropagation());
          const btn = document.createElement("button");
          btn.type = "submit";
          btn.textContent = "→ Repeater";
          form.addEventListener("submit", () => { btn.disabled = true; });
          form.appendChild(btn);
          return form;
        },
      },
    ],
  });

  function rowMatchesFacets(row, skipGroup) {
    for (const g of FACET_GROUPS) {
      if (g.key === skipGroup) continue;
      const selected = facets[g.key];
      if (selected.size === 0) continue;
      if (!selected.has(String(row[g.key] ?? ""))) return false;
    }
    return true;
  }

  function rowMatchesText(row) {
    if (!textQuery) return true;
    const q = textQuery.toLowerCase();
    return ["url", "param", "vuln_class", "method", "confidence"].some(
      (k) => row[k] != null && String(row[k]).toLowerCase().includes(q));
  }

  function applyFilters() {
    table.setTextFilter(textQuery);
    table.setFilter((row) => rowMatchesFacets(row, null));
    renderFacets();
    renderChips();
  }

  function optionCounts(groupKey) {
    // Live counts: rows matching text + every OTHER group's selection,
    // grouped by this group's own value (so checking a sibling in the same
    // group never zeroes this option out).
    const base = allRows.filter((r) => rowMatchesText(r) && rowMatchesFacets(r, groupKey));
    const counts = new Map();
    for (const row of base) {
      const v = String(row[groupKey] ?? "");
      counts.set(v, (counts.get(v) || 0) + 1);
    }
    return counts;
  }

  function renderFacets() {
    facetContainer.replaceChildren();
    for (const group of FACET_GROUPS) {
      const counts = optionCounts(group.key);
      const values = Array.from(counts.keys()).sort(
        (a, b) => (counts.get(b) - counts.get(a)) || a.localeCompare(b));
      const details = document.createElement("details");
      details.className = "facet-group";
      details.open = ls.get(`fl-findings-collapsed-${group.key}`) !== "1";
      details.addEventListener("toggle", () => {
        ls.set(`fl-findings-collapsed-${group.key}`, details.open ? "0" : "1");
      });
      const summary = document.createElement("summary");
      summary.textContent = group.label;
      details.appendChild(summary);
      const optionsBox = document.createElement("div");
      optionsBox.className = "facet-options";
      for (const value of values) {
        const label = document.createElement("label");
        label.className = "facet-option";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = facets[group.key].has(value);
        cb.addEventListener("change", () => {
          if (cb.checked) facets[group.key].add(value);
          else facets[group.key].delete(value);
          applyFilters();
        });
        const text = document.createElement("span");
        text.textContent = value || "(none)";
        const count = document.createElement("span");
        count.className = "count";
        count.textContent = String(counts.get(value) || 0);
        label.append(cb, text, count);
        optionsBox.appendChild(label);
      }
      if (values.length === 0) {
        const p = document.createElement("p");
        p.className = "muted";
        p.textContent = "no values";
        optionsBox.appendChild(p);
      }
      details.appendChild(optionsBox);
      facetContainer.appendChild(details);
    }
  }

  function renderChips() {
    chipsContainer.replaceChildren();
    let any = false;
    if (textQuery) {
      any = true;
      chipsContainer.appendChild(makeChip(`filter: "${textQuery}"`, () => {
        textQuery = "";
        quickFilter.value = "";
        ls.del("fl-findings-draft-text");
        applyFilters();
      }));
    }
    for (const group of FACET_GROUPS) {
      for (const value of facets[group.key]) {
        any = true;
        chipsContainer.appendChild(makeChip(`${group.label}: ${value || "(none)"}`, () => {
          facets[group.key].delete(value);
          applyFilters();
        }));
      }
    }
    if (any) {
      const clear = document.createElement("button");
      clear.type = "button";
      clear.className = "tbtn";
      clear.textContent = "Clear all";
      clear.addEventListener("click", clearAllFilters);
      chipsContainer.appendChild(clear);
    }
  }

  function makeChip(text, onRemove) {
    const chip = document.createElement("span");
    chip.className = "filter-chip";
    const span = document.createElement("span");
    span.textContent = text;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.setAttribute("aria-label", "remove filter");
    btn.textContent = "×";
    btn.addEventListener("click", onRemove);
    chip.append(span, btn);
    return chip;
  }

  function clearAllFilters() {
    textQuery = "";
    quickFilter.value = "";
    ls.del("fl-findings-draft-text");
    for (const g of FACET_GROUPS) facets[g.key].clear();
    applyFilters();
  }

  const onQuickFilter = debounce((value) => {
    textQuery = value;
    ls.set("fl-findings-draft-text", value);
    applyFilters();
  }, 200);
  quickFilter.addEventListener("input", (e) => onQuickFilter(e.target.value));
  quickFilter.value = textQuery;

  if (collapseToggle) {
    collapseToggle.addEventListener("click", () => {
      const collapsed = sidebar.getAttribute("data-collapsed") === "1";
      sidebar.setAttribute("data-collapsed", collapsed ? "0" : "1");
      collapseToggle.setAttribute("aria-expanded", collapsed ? "true" : "false");
      collapseToggle.textContent = collapsed ? "Collapse" : "Expand";
    });
  }

  // --- saved views: server-side (SQLite), reused across sessions ------------

  function specFromState() {
    const facetObj = {};
    for (const g of FACET_GROUPS) facetObj[g.key] = Array.from(facets[g.key]);
    return { version: 1, filter: { text: textQuery, facets: facetObj, predicates: [] } };
  }

  function applySpec(spec) {
    const filter = (spec && spec.filter) || {};
    textQuery = filter.text || "";
    quickFilter.value = textQuery;
    for (const g of FACET_GROUPS) {
      facets[g.key] = new Set((filter.facets && filter.facets[g.key]) || []);
    }
    applyFilters();
  }

  async function loadViews() {
    viewsChips.replaceChildren();
    let views = [];
    try {
      const r = await fetch("/api/views?table=findings");
      views = (await r.json()).views || [];
    } catch (_) { /* store not readable yet — no views */ }
    for (const view of views) {
      const chip = document.createElement("span");
      chip.className = "view-chip" + (view.pinned ? " pinned" : "")
        + (String(view.id) === String(currentViewId) ? " active" : "");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = view.name;
      btn.addEventListener("click", () => {
        currentViewId = view.id;
        ls.set("fl-findings-last-view", String(view.id));
        applySpec(view.spec);
        loadViews();
      });
      chip.appendChild(btn);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "chip-remove";
      remove.setAttribute("aria-label", `delete view ${view.name}`);
      remove.textContent = "×";
      remove.addEventListener("click", async (e) => {
        e.stopPropagation();
        await fetch(`/api/views/${view.id}`, { method: "DELETE" });
        if (String(currentViewId) === String(view.id)) {
          currentViewId = null;
          ls.del("fl-findings-last-view");
        }
        loadViews();
      });
      chip.appendChild(remove);
      viewsChips.appendChild(chip);
    }
  }

  const saveBtn = document.getElementById("view-save");
  if (saveBtn) saveBtn.addEventListener("click", async () => {
    const name = window.prompt("Save current filters as:");
    if (!name) return;
    const r = await fetch("/api/views?table=findings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, spec: specFromState() }),
    });
    if (r.ok) {
      const view = await r.json();
      currentViewId = view.id;
      ls.set("fl-findings-last-view", String(view.id));
      loadViews();
    }
  });

  async function load() {
    const r = await fetch("/api/findings");
    allRows = (await r.json()).findings || [];
    table.setData(allRows);
    applyFilters();
  }

  load();
  loadViews();
}

// The finding-detail page's own "send to Repeater" form (a plain PRG POST,
// no fetch) just needs the same double-submit guard the list view's row
// action gets — this module is loaded on both pages.
function initDetailPivot() {
  const form = document.getElementById("send-to-repeater-form");
  if (!form) return;
  form.addEventListener("submit", () => {
    const btn = document.getElementById("send-to-repeater-btn");
    if (btn) btn.disabled = true;
  });
}

initFindings();
initDetailPivot();
