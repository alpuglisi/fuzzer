// fuzzlab control panel — Overview dashboard (U1). Only loaded on "/".
//
// Progressive enhancement only: the server already renders the KPI tiles, all
// three panels, and Panel A's recent-runs table as plain HTML (no-JS works,
// including the run links). This just hydrates Panel A with the shared
// DataTable (R-03) so its columns become sortable, reading the same rows the
// server rendered from a `<script type="application/json">` sidecar (never a
// second network round trip — the aggregate context builder already produced
// this data once for the initial render).
import { DataTable } from "./datatable.js";

function parseRows(el) {
  try {
    const rows = JSON.parse(el.textContent || "[]");
    return Array.isArray(rows) ? rows : [];
  } catch (_) {
    return [];
  }
}

function runLink(row) {
  const a = document.createElement("a");
  a.href = `/runs/${row.id}`;
  a.textContent = `#${row.id}`;
  return a;
}

function initOverview() {
  const table = document.getElementById("recent-runs-table");
  const dataEl = document.getElementById("recent-runs-data");
  if (!table || !dataEl) return; // not the overview page, or the empty state
  const rows = parseRows(dataEl);
  if (!rows.length) return;

  new DataTable(table, {
    columns: [
      { key: "id", render: runLink, sortValue: (r) => r.id },
      { key: "tool", sortValue: (r) => r.tool || "" },
      { key: "target", sortValue: (r) => r.target || "" },
      { key: "started_at", sortValue: (r) => r.started_at || "" },
      { key: "findings", sortValue: (r) => r.findings || 0 },
    ],
    data: rows,
  });
}

document.addEventListener("DOMContentLoaded", initOverview);
