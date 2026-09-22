// fuzzlab control panel — shared read-only DataTable (R-03 in
// docs/UI_IMPLEMENTATION_PLAN.md). Built here (U1) ahead of U2's findings
// workbench landing, since U1's "Recent runs" panel needs it first; U2 reuses
// this module and is expected to extend it with `rowActions` and
// `textFilterKeys` for its facet sidebar — the API below leaves room for that
// without a breaking change (new options are additive).
//
// In-memory filter -> sort -> fragment-render only, no virtualization (a few
// thousand rows are fine per R-03; pagination is the only escalation lever).
// Every cell is built via `textContent`, or a caller-supplied Node from
// `render` — NEVER innerHTML, because table data ultimately comes from the
// store and some of it (urls, params, payloads) is attacker-influenced.

// Pure sort comparator, split out from the class so it's unit-testable without
// a DOM (see tests/js/datatable.test.mjs, `node --test`) and reusable by a
// future filter step. `dir` is 1 (ascending) or -1 (descending).
export function sortRows(data, sortValue, dir) {
  return [...data].sort((a, b) => {
    const av = sortValue(a);
    const bv = sortValue(b);
    if (av < bv) return -dir;
    if (av > bv) return dir;
    return 0;
  });
}

export class DataTable {
  /**
   * @param {HTMLTableElement} root - a <table> with its header row already in
   *   the DOM (this only touches <tbody>, so the no-JS server render stays the
   *   fallback and this is strictly progressive enhancement).
   * @param {Object} opts
   * @param {Array<{
   *   key: string,
   *   render?: (row: object) => (Node|string|number|null|undefined),
   *   sortValue?: (row: object) => (number|string),
   * }>} opts.columns - one entry per <th>/<td>, in column order.
   * @param {Array<object>} opts.data
   * @param {(row: object) => void} [opts.onRowClick]
   */
  constructor(root, { columns = [], data = [], onRowClick = null } = {}) {
    this.root = root;
    this.columns = columns;
    this.data = data;
    this.onRowClick = onRowClick;
    this.sortKey = null;
    this.sortDir = 1;
    this._tbody = root.querySelector("tbody")
      || root.appendChild(document.createElement("tbody"));
    this._wireSortableHeaders();
    this.render();
  }

  _wireSortableHeaders() {
    const headRow = this.root.querySelector("thead tr");
    if (!headRow) return;
    [...headRow.children].forEach((th, i) => {
      const col = this.columns[i];
      if (!col || !col.sortValue) return;
      th.setAttribute("role", "button");
      th.tabIndex = 0;
      const activate = () => this.sort(col.key);
      th.addEventListener("click", activate);
      th.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(); }
      });
    });
  }

  sort(key) {
    const col = this.columns.find((c) => c.key === key);
    if (!col || !col.sortValue) return;
    this.sortDir = this.sortKey === key ? -this.sortDir : 1;
    this.sortKey = key;
    this.data = sortRows(this.data, col.sortValue, this.sortDir);
    this.render();
  }

  render() {
    this._tbody.textContent = "";
    for (const row of this.data) {
      const tr = document.createElement("tr");
      for (const col of this.columns) {
        const td = document.createElement("td");
        const value = col.render ? col.render(row) : row[col.key];
        if (value instanceof Node) td.appendChild(value);
        else if (value !== null && value !== undefined) td.textContent = String(value);
        tr.appendChild(td);
      }
      if (this.onRowClick) {
        tr.tabIndex = 0;
        tr.style.cursor = "pointer";
        tr.addEventListener("click", () => this.onRowClick(row));
        tr.addEventListener("keydown", (e) => {
          if (e.key === "Enter") this.onRowClick(row);
        });
      }
      this._tbody.appendChild(tr);
    }
  }
}
