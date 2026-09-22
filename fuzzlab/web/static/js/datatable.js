// fuzzlab control panel — shared hand-rolled DataTable (U2 / R-03).
//
// A dependency-free, no-build in-memory table: filter -> sort -> fragment-render.
// No virtualization (a few thousand rows render fine in a real `<table>` for
// accessibility per R-11); a row cap is the only escalation lever (see
// `DEFAULT_CAP` below). Reused as-is by U1 (recent-runs) and U5 (store
// explorer), *minus* the facet sidebar, which is findings-specific chrome
// built around this module in js/findings.js.
//
// Security (non-negotiable, R-03 / findings workbench spec): every cell value
// is rendered via `Node.textContent` — never `innerHTML` — because url/param/
// payload fields come from the target and are untrusted. A column's `render`
// may return a DOM Node (e.g. a badge, a link, a form) instead of a plain
// value; when it builds an `<a href>`, it MUST scheme-check the href first —
// use the exported `isSafeHref`/`makeSafeLink` helpers below rather than
// hand-rolling that check, so every pivot link in the app shares one gate.
//
// Public API (stable; do not change shape without updating every consumer):
//   createDataTable({
//     container,       // element the table is mounted into (its only child)
//     columns,         // [{ key, label, render?(row)->Node|primitive,
//                       //    sortValue?(row)->number|string, sortable? = true,
//                       //    className? }]
//     data,            // array of plain row objects
//     onRowClick,      // (row) => void | undefined — row body click (not header/actions)
//     rowActions,      // [{ label, onClick?(row), render?(row)->Node, className? }]
//     textFilterKeys,  // string[] — row keys the built-in quick-filter searches
//     cap,             // max rows rendered at once (default DEFAULT_CAP)
//     emptyMessage,    // shown when the visible set is empty
//   }) -> {
//     setData(rows), setTextFilter(text), setFilter(predicate|null),
//     setSort(key, dir), getVisibleRows(), render(), destroy()
//   }

export const DEFAULT_CAP = 2000;

// Scheme allowlist for any pivot link built from untrusted data (url/param
// fields). Blocks `javascript:`/`data:`/etc. Relative URLs (no scheme) are
// allowed — they resolve against this same-origin page.
export function isSafeHref(href) {
  if (href == null) return false;
  const s = String(href).trim();
  if (s === "") return false;
  // No colon before the first '/', '?', '#' -> no scheme -> relative, safe.
  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(s);
  if (!schemeMatch) return true;
  const scheme = schemeMatch[1].toLowerCase();
  return scheme === "http" || scheme === "https";
}

// Build a safe <a>: falls back to a plain <span> with the same text (never
// omits the value) when the href fails the scheme check, so an attacker
// cannot use a bad scheme to swallow the row's data — only to lose the link.
export function makeSafeLink(href, text) {
  if (isSafeHref(href)) {
    const a = document.createElement("a");
    a.href = href;
    a.textContent = text == null ? "" : String(text);
    return a;
  }
  const span = document.createElement("span");
  span.textContent = text == null ? "" : String(text);
  span.title = "blocked unsafe link target";
  return span;
}

function cellNode(column, row) {
  const value = column.render ? column.render(row) : row[column.key];
  if (value instanceof Node) return value;
  const span = document.createTextNode(value == null ? "" : String(value));
  return span;
}

function defaultSortValue(column, row) {
  if (column.sortValue) return column.sortValue(row);
  return row[column.key];
}

// Exported (alongside isSafeHref/makeSafeLink) so the sort comparator's pure
// logic is unit-testable with plain `node:test`, without a DOM
// (tests/test_datatable_js.py shells out to `node --test`).
export function compareValues(a, b) {
  if (a == null && b == null) return 0;
  if (a == null) return -1;
  if (b == null) return 1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  const sa = String(a).toLowerCase();
  const sb = String(b).toLowerCase();
  if (sa < sb) return -1;
  if (sa > sb) return 1;
  return 0;
}

export function createDataTable(opts) {
  const {
    container,
    columns,
    onRowClick,
    rowActions,
    textFilterKeys = [],
    cap = DEFAULT_CAP,
    emptyMessage = "No rows.",
  } = opts;

  let data = opts.data ? opts.data.slice() : [];
  let textQuery = "";
  let predicate = null;               // (row) => bool, e.g. facet AND/OR logic
  let sortKey = null;
  let sortDir = 1;                    // 1 asc, -1 desc
  let visibleRows = [];

  const table = document.createElement("table");
  table.className = "dt-table";
  const thead = document.createElement("thead");
  const tbody = document.createElement("tbody");
  table.appendChild(thead);
  table.appendChild(tbody);

  const status = document.createElement("p");
  status.className = "muted dt-status";
  status.hidden = true;

  container.replaceChildren(table, status);

  function buildHead() {
    thead.replaceChildren();
    const tr = document.createElement("tr");
    for (const col of columns) {
      const th = document.createElement("th");
      th.textContent = col.label != null ? col.label : col.key;
      if (col.sortable !== false) {
        th.classList.add("dt-sortable");
        th.tabIndex = 0;
        th.setAttribute("role", "button");
        th.setAttribute(
          "aria-sort",
          sortKey === col.key ? (sortDir === 1 ? "ascending" : "descending") : "none");
        const activate = () => {
          if (sortKey === col.key) sortDir = -sortDir;
          else { sortKey = col.key; sortDir = 1; }
          render();
        };
        th.addEventListener("click", activate);
        th.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(); }
        });
      }
      tr.appendChild(th);
    }
    if (rowActions && rowActions.length) {
      const th = document.createElement("th");
      th.textContent = "";
      th.className = "dt-actions-head";
      tr.appendChild(th);
    }
    thead.appendChild(tr);
  }

  function matchesText(row) {
    if (!textQuery) return true;
    const q = textQuery.toLowerCase();
    for (const key of textFilterKeys) {
      const v = row[key];
      if (v != null && String(v).toLowerCase().includes(q)) return true;
    }
    return false;
  }

  function computeVisible() {
    let rows = data.filter((r) => matchesText(r) && (predicate ? predicate(r) : true));
    if (sortKey != null) {
      const col = columns.find((c) => c.key === sortKey);
      if (col) {
        rows = rows.slice().sort(
          (a, b) => sortDir * compareValues(defaultSortValue(col, a), defaultSortValue(col, b)));
      }
    }
    return rows;
  }

  function buildActionsCell(row) {
    const td = document.createElement("td");
    td.className = "dt-actions";
    for (const action of rowActions) {
      let node;
      if (action.render) {
        node = action.render(row);
      } else {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = action.label;
        if (action.className) btn.className = action.className;
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          if (action.onClick) action.onClick(row);
        });
        node = btn;
      }
      td.appendChild(node);
    }
    return td;
  }

  function buildRow(row) {
    const tr = document.createElement("tr");
    tr.className = "dt-row";
    for (const col of columns) {
      const td = document.createElement("td");
      if (col.className) td.className = col.className;
      td.appendChild(cellNode(col, row));
      tr.appendChild(td);
    }
    if (rowActions && rowActions.length) {
      tr.appendChild(buildActionsCell(row));
    }
    if (onRowClick) {
      tr.classList.add("dt-clickable");
      tr.tabIndex = 0;
      tr.addEventListener("click", () => onRowClick(row));
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter") onRowClick(row);
      });
    }
    return tr;
  }

  function render() {
    buildHead();
    visibleRows = computeVisible();
    tbody.replaceChildren();
    const shown = visibleRows.slice(0, cap);
    for (const row of shown) tbody.appendChild(buildRow(row));
    if (visibleRows.length === 0) {
      status.hidden = false;
      status.textContent = emptyMessage;
    } else if (visibleRows.length > cap) {
      status.hidden = false;
      status.textContent =
        `Showing ${cap} of ${visibleRows.length} matching rows — refine the filters to see the rest.`;
    } else {
      status.hidden = true;
    }
  }

  render();

  return {
    setData(rows) { data = rows ? rows.slice() : []; render(); },
    setTextFilter(text) { textQuery = text || ""; render(); },
    setFilter(fn) { predicate = typeof fn === "function" ? fn : null; render(); },
    setSort(key, dir) { sortKey = key; sortDir = dir === -1 ? -1 : 1; render(); },
    getVisibleRows() { return visibleRows.slice(); },
    render,
    destroy() { container.replaceChildren(); },
  };
}
