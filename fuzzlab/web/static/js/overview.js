// Overview dashboard (U1/CC-UI-0028) — progressive enhancement only; the page is
// fully rendered server-side (empty store, seeded runs, no-JS all work without this
// module). This is a small hand-rolled click-to-sort for the recent-runs table, not
// the shared read-only `DataTable` the plan reserves for U2 (see docs/UI_IMPLEMENTATION_PLAN.md
// R-03) — `js/datatable.js` did not exist yet when this lane ran; U2 is expected to
// land the shared component, and this table can be migrated onto it then.

function cellText(row, key, idx) {
  const cell = row.cells[idx];
  return cell ? cell.textContent.trim() : "";
}

function sortValue(text, key) {
  if (key === "id" || key === "findings") {
    const n = parseInt(text.replace(/[^0-9-]/g, ""), 10);
    return Number.isNaN(n) ? -Infinity : n;
  }
  return text.toLowerCase();
}

function initSortableTable(table) {
  const headers = Array.from(table.querySelectorAll("th[data-sort]"));
  const tbody = table.querySelector("tbody");
  if (!headers.length || !tbody) return;

  headers.forEach((th, idx) => {
    th.setAttribute("tabindex", "0");
    th.setAttribute("role", "button");
    const activate = () => {
      const key = th.dataset.sort;
      const dir = th.dataset.dir === "asc" ? "desc" : "asc";
      headers.forEach((h) => { h.classList.remove("sorted"); delete h.dataset.dir; });
      th.classList.add("sorted");
      th.dataset.dir = dir;

      const rows = Array.from(tbody.querySelectorAll("tr"));
      rows.sort((a, b) => {
        const va = sortValue(cellText(a, key, idx), key);
        const vb = sortValue(cellText(b, key, idx), key);
        if (va < vb) return dir === "asc" ? -1 : 1;
        if (va > vb) return dir === "asc" ? 1 : -1;
        return 0;
      });
      rows.forEach((r) => tbody.appendChild(r));
    };
    th.addEventListener("click", activate);
    th.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); activate(); }
    });
  });
}

document.querySelectorAll("table[data-sortable]").forEach(initSortableTable);
