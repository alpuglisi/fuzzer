// fuzzlab control panel — Diagnostics section (U5).
// Wires the server-rendered chart panels to the shared `createChart` wrapper,
// the EMA smoothing slider (client-side only, per R-05's resolved render
// order), the metric substring filter, and the store explorer's table
// switch + pagination. Every chart's data and offscreen `<table>` fallback
// are already in the page from the server (progressive enhancement, not a
// requirement for first content) — this only upgrades them to a live canvas
// chart and keeps the fallback table in sync.

import { createChart } from "/static/js/charts.js";
import { ema } from "/static/js/smoothing.js";
import { getJSON } from "/static/js/http.js";

function tableRowsFor(data) {
  const rows = [];
  for (const s of data.series) {
    if (s.y !== undefined) {
      s.x.forEach((x, i) => rows.push({ run_id: s.run_id, x, y: s.y[i] }));
    } else {
      s.x.forEach((x, i) => rows.push({ run_id: s.run_id, x, min: s.min[i], max: s.max[i] }));
    }
  }
  return rows.slice(0, 200);
}

function smoothedData(rawData, alpha) {
  if (!alpha || rawData.mode !== "line") return rawData;
  return {
    ...rawData,
    series: rawData.series.map((s) => ({ ...s, y: ema(s.y, alpha) })),
  };
}

function initCharts() {
  const panels = document.querySelectorAll(".chart-panel[data-chart-id]");
  const charts = [];
  panels.forEach((panel) => {
    const id = panel.getAttribute("data-chart-id");
    const script = panel.querySelector(`script[data-chart-json="${id}"]`);
    if (!script) return;
    let raw;
    try { raw = JSON.parse(script.textContent); } catch (_) { return; }
    const el = panel.querySelector(`#el-${id}`);
    const tableEl = panel.querySelector(`#table-${id}`);
    if (!el) return;
    const handle = createChart(el, { id, data: raw, tableEl });
    handle.setTableRows(tableRowsFor(raw));
    charts.push({ id, raw, handle, panel });
  });

  const smoothing = document.getElementById("smoothing");
  const smoothingValue = document.getElementById("smoothing-value");
  if (smoothing) {
    smoothing.addEventListener("input", () => {
      const alpha = parseFloat(smoothing.value) || 0;
      if (smoothingValue) smoothingValue.textContent = alpha.toFixed(2);
      for (const c of charts) {
        const data = smoothedData(c.raw, alpha);
        c.handle.setData(data, tableRowsFor(data));
      }
    });
  }

  const filter = document.getElementById("metric-filter");
  if (filter) {
    filter.addEventListener("input", () => {
      const needle = filter.value.trim().toLowerCase();
      for (const c of charts) {
        const hay = `${c.panel.dataset.source}/${c.panel.dataset.key}`.toLowerCase();
        c.panel.style.display = !needle || hay.includes(needle) ? "" : "none";
      }
      document.querySelectorAll(".chart-group").forEach((group) => {
        const anyVisible = Array.from(group.querySelectorAll(".chart-panel"))
          .some((p) => p.style.display !== "none");
        group.style.display = anyVisible ? "" : "none";
      });
    });
  }
}

// --- store explorer: AJAX table switch + pagination (progressive
// enhancement over the plain <form method=get> / prev-next links that work
// with JS off) ---------------------------------------------------------

function renderStoreTable(wrap, payload) {
  const table = document.getElementById("store-rows-table");
  const empty = document.getElementById("store-table-empty");
  if (!table) return;
  const thead = table.querySelector("thead tr");
  const tbody = table.querySelector("tbody");
  thead.innerHTML = "";
  tbody.innerHTML = "";
  payload.columns.forEach((col) => {
    const th = document.createElement("th");
    th.textContent = col.name + (col.redacted ? " \u{1F512}" : "");
    thead.appendChild(th);
  });
  payload.rows.forEach((row) => {
    const tr = document.createElement("tr");
    payload.columns.forEach((col) => {
      const td = document.createElement("td");
      const v = row[col.name];
      td.textContent = v === null || v === undefined ? "" : String(v);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  if (empty) empty.hidden = payload.rows.length > 0;
  wrap.dataset.table = payload.table;
  wrap.dataset.limit = payload.limit;
  wrap.dataset.offset = payload.offset;
  wrap.dataset.total = payload.total;
  const prev = document.getElementById("store-prev");
  const next = document.getElementById("store-next");
  if (prev) prev.disabled = payload.offset <= 0;
  if (next) next.disabled = payload.offset + payload.rows.length >= payload.total;
}

async function loadStoreTable(table, limit, offset) {
  const wrap = document.getElementById("store-table-wrap");
  if (!wrap) return;
  const payload = await getJSON(
    `/api/store/${encodeURIComponent(table)}?limit=${limit}&offset=${offset}`);
  if (payload && !payload.error) renderStoreTable(wrap, payload);
}

function initStoreExplorer() {
  const select = document.getElementById("store-table-select");
  const wrap = document.getElementById("store-table-wrap");
  if (select && wrap) {
    select.addEventListener("change", () => {
      loadStoreTable(select.value, wrap.dataset.limit || 100, 0);
    });
  }
  const prev = document.getElementById("store-prev");
  const next = document.getElementById("store-next");
  if (prev && wrap) prev.addEventListener("click", () => {
    const limit = Number(wrap.dataset.limit) || 100;
    const offset = Math.max(0, (Number(wrap.dataset.offset) || 0) - limit);
    loadStoreTable(wrap.dataset.table, limit, offset);
  });
  if (next && wrap) next.addEventListener("click", () => {
    const limit = Number(wrap.dataset.limit) || 100;
    const offset = (Number(wrap.dataset.offset) || 0) + limit;
    loadStoreTable(wrap.dataset.table, limit, offset);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  initStoreExplorer();
});
