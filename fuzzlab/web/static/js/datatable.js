// fuzzlab shared DataTable (U2/CC-UI-0029, resolved R-03/R-11).
//
// A native <table>, NOT role="grid" — this is read-only sort + a row link, not
// a composite-widget grid, so ARIA grid semantics would force the wrong
// (arrow-key) keyboard model. Sorting is a real <button> inside each <th>
// with a single active aria-sort; the primary column's link is a real <a
// href> (a JS-added click handler on the row is an enhancement on top, never
// the only way to open a row); every cell value goes through textContent —
// never innerHTML — because callers render untrusted, target-derived fields
// (urls, params, payloads). Standalone ES module: no build step, imported
// directly by section scripts. Reused as-is by U1 (recent runs) and U5 (store
// explorer), *minus* the facet sidebar those sections don't need.
//
// API (see createDataTable below):
//   createDataTable(root, {
//     caption, columns: [{key, label, render(row)->Node|string|number,
//       sortValue(row)->comparable, sortable=true}],
//     data: [], getRowId(row,i)->id, rowHref(row)->url|null,
//     onRowClick(row,evt), rowActions: [{label, ariaLabel(row), onClick(row,evt)}
//       | {render(row)->Node|null}], textFilterKeys: [key|fn],
//     emptyMessage, liveRegion (an aria-live element updated with the row count),
//   }) -> { setData(rows), setTextFilter(str), setFilter(fn|null), getVisible(),
//           element }

const HTTP_SCHEMES = new Set(["http:", "https:"]);

// Only a same-origin-relative path or an http(s) absolute URL may render as an
// <a href> — never `javascript:`/`data:`/anything else. Anything unsafe (or
// unparseable) returns null, and the caller renders plain text instead.
export function safeHref(url) {
  if (typeof url !== "string" || !url) return null;
  if (url.startsWith("/") && !url.startsWith("//")) return url;
  try {
    const u = new URL(url, window.location.origin);
    return HTTP_SCHEMES.has(u.protocol) ? url : null;
  } catch (_) {
    return null;
  }
}

// Fixed rank maps for non-lexicographic sort columns (severity/confidence-like
// enums where string order != meaning order). Use as a column's `sortValue`:
//   sortValue: rankSort(SEVERITY_RANK, "severity")
export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function rankSort(map, key) {
  return (row) => {
    const v = typeof key === "function" ? key(row) : row[key];
    return Object.prototype.hasOwnProperty.call(map, v) ? map[v] : -1;
  };
}

function appendCellValue(el, value) {
  if (value instanceof Node) el.appendChild(value);
  else el.textContent = value == null ? "" : String(value);
}

export function createDataTable(root, opts) {
  const {
    caption = "Data table",
    columns,
    data = [],
    getRowId = (row, i) => (row && row.id != null ? row.id : i),
    rowHref = null,
    onRowClick = null,
    rowActions = [],
    textFilterKeys = [],
    emptyMessage = "No rows.",
    liveRegion = null,
  } = opts;

  let rows = data.slice();
  let sortKey = null;
  let sortDir = 1;
  let textFilter = "";
  let predicate = null; // externally supplied fn(row)->bool, e.g. facet selection

  const table = document.createElement("table");
  const capEl = document.createElement("caption");
  capEl.className = "visually-hidden";
  capEl.textContent = caption;
  table.appendChild(capEl);

  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  const sortButtons = new Map();
  for (const col of columns) {
    const th = document.createElement("th");
    th.scope = "col";
    if (col.sortable === false || !col.sortValue) {
      th.textContent = col.label;
    } else {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "dt-sort";
      btn.textContent = col.label;
      btn.addEventListener("click", () => setSort(col.key));
      th.appendChild(btn);
      sortButtons.set(col.key, th);
    }
    headRow.appendChild(th);
  }
  if (rowActions.length) {
    const th = document.createElement("th");
    th.scope = "col";
    th.className = "visually-hidden";
    th.textContent = "Actions";
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  table.appendChild(tbody);
  root.replaceChildren(table);

  function setSort(key) {
    if (sortKey === key) sortDir = -sortDir;
    else { sortKey = key; sortDir = 1; }
    for (const th of sortButtons.values()) th.removeAttribute("aria-sort");
    const activeTh = sortButtons.get(key);
    if (activeTh) activeTh.setAttribute("aria-sort", sortDir === 1 ? "ascending" : "descending");
    render();
  }

  function matchesText(row) {
    if (!textFilter) return true;
    const hay = textFilterKeys
      .map((k) => {
        const v = typeof k === "function" ? k(row) : row[k];
        return v == null ? "" : String(v);
      })
      .join(" \u0000 ")
      .toLowerCase();
    return hay.includes(textFilter);
  }

  function visibleRows() {
    let out = rows.filter((r) => matchesText(r) && (!predicate || predicate(r)));
    if (sortKey) {
      const col = columns.find((c) => c.key === sortKey);
      if (col && col.sortValue) {
        out = out.slice().sort((a, b) => {
          const av = col.sortValue(a);
          const bv = col.sortValue(b);
          if (av === bv) return 0;
          return (av > bv ? 1 : -1) * sortDir;
        });
      }
    }
    return out;
  }

  function render() {
    const view = visibleRows();
    tbody.replaceChildren();
    const colCount = columns.length + (rowActions.length ? 1 : 0);
    if (view.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = colCount;
      td.className = "dt-empty";
      td.textContent = emptyMessage;
      tr.appendChild(td);
      tbody.appendChild(tr);
    } else {
      view.forEach((row, i) => {
        const tr = document.createElement("tr");
        tr.dataset.rowId = String(getRowId(row, i));
        columns.forEach((col, ci) => {
          const td = document.createElement("td");
          const value = col.render ? col.render(row) : row[col.key];
          if (ci === 0 && rowHref) {
            const href = safeHref(rowHref(row));
            if (href) {
              const a = document.createElement("a");
              a.href = href;
              appendCellValue(a, value);
              td.appendChild(a);
            } else {
              appendCellValue(td, value);
            }
          } else {
            appendCellValue(td, value);
          }
          tr.appendChild(td);
        });
        if (rowActions.length) {
          const td = document.createElement("td");
          td.className = "dt-actions";
          for (const action of rowActions) {
            if (action.render) {
              const node = action.render(row);
              if (node) td.appendChild(node);
              continue;
            }
            const btn = document.createElement("button");
            btn.type = "button";
            btn.textContent = action.label;
            btn.setAttribute(
              "aria-label",
              action.ariaLabel ? action.ariaLabel(row) : action.label
            );
            btn.addEventListener("click", (e) => action.onClick(row, e));
            td.appendChild(btn);
          }
          tr.appendChild(td);
        }
        if (onRowClick) {
          tr.classList.add("dt-clickable");
          tr.addEventListener("click", (e) => {
            if (e.target.closest("a,button,form,input,select,textarea")) return;
            onRowClick(row, e);
          });
        }
        tbody.appendChild(tr);
      });
    }
    if (liveRegion) {
      liveRegion.textContent = `${view.length} row${view.length === 1 ? "" : "s"}`;
    }
  }

  render();

  return {
    setData(newData) {
      rows = (newData || []).slice();
      render();
    },
    setTextFilter(s) {
      textFilter = (s || "").toLowerCase();
      render();
    },
    setFilter(fn) {
      predicate = fn || null;
      render();
    },
    setSort(key, dir) {
      sortKey = key || null;
      sortDir = dir === -1 ? -1 : 1;
      for (const th of sortButtons.values()) th.removeAttribute("aria-sort");
      const activeTh = sortKey && sortButtons.get(sortKey);
      if (activeTh) activeTh.setAttribute("aria-sort", sortDir === 1 ? "ascending" : "descending");
      render();
    },
    getSort() {
      return { key: sortKey, dir: sortDir };
    },
    getVisible: visibleRows,
    element: table,
  };
}
