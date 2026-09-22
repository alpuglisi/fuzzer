// fuzzlab control panel — shared uPlot chart wrapper (U5, per R-02/R-12).
//
// `createChart(el, opts)` is the ONE place any section builds a uPlot chart —
// consumed here by Diagnostics and meant to be reused by any future ML-tab
// charts rather than a second hand-rolled wrapper. It owns:
//
//   - theme/density tokens resolved from CSS (canvas can't read `var()`/
//     `color-mix()` — only a computed-style probe on a real element can);
//   - a full destroy()+recreate on theme/density change (uPlot bakes colors
//     into the canvas at draw time and sizes its axes at construction);
//   - a debounced ResizeObserver on the chart's parent cell, coalesced with
//     requestAnimationFrame;
//   - an offscreen `<table>` fallback (screen readers + no-JS-friendly SSR
//     content it can start from) kept in sync with the data;
//   - the `window.__charts` registry the R-09 browser-smoke tests read.
//
// `mode: "line"` draws one series per run; `mode: "envelope"` draws a
// min/max band per run via uPlot's native `bands` fill-between-series
// feature (R-08's bandit posterior/regret CI band).

import uPlot from "/static/vendor/uplot/uPlot.esm.js";

const REGISTRY = (window.__charts = window.__charts || new Map());

const RUN_COLORS = [
  "#2563eb", "#d9480f", "#2f855a", "#b45309", "#7c3aed", "#0891b2", "#be185d",
];

function probeColor(varName) {
  const probe = document.createElement("span");
  probe.style.position = "absolute";
  probe.style.visibility = "hidden";
  probe.style.color = `var(${varName})`;
  document.body.appendChild(probe);
  const resolved = getComputedStyle(probe).color;
  probe.remove();
  return resolved || "#666";
}

function readTokens() {
  return {
    text: probeColor("--text"),
    muted: probeColor("--muted"),
    border: probeColor("--border"),
    accent: probeColor("--accent"),
    surface: probeColor("--surface"),
  };
}

const DENSITY = {
  comfortable: { font: 12, xGutter: 34, yGutter: 50, tick: 6, gap: 6, height: 220 },
  compact: { font: 11, xGutter: 28, yGutter: 44, tick: 4, gap: 4, height: 170 },
};

function currentDensity() {
  return document.documentElement.getAttribute("data-density") === "compact"
    ? "compact" : "comfortable";
}

function seriesColor(i) {
  return RUN_COLORS[i % RUN_COLORS.length];
}

function buildOpts(state) {
  const tok = readTokens();
  const d = DENSITY[currentDensity()];
  const runs = state.data.series.map((s) => s.run_id);
  const isEnvelope = state.data.mode === "envelope";

  const series = [{}];
  const bands = [];
  if (isEnvelope) {
    runs.forEach((rid, i) => {
      const color = seriesColor(i);
      series.push({ label: `run ${rid} min`, stroke: "transparent", width: 0 });
      series.push({ label: `run ${rid} max`, stroke: color, width: 1.5,
                   fill: color + "33" });
      bands.push({ series: [series.length - 2, series.length - 1], fill: color + "33" });
    });
  } else {
    runs.forEach((rid, i) => {
      series.push({ label: `run ${rid}`, stroke: seriesColor(i), width: 1.75,
                   points: { show: state.data.series[i].x.length <= 60 } });
    });
  }

  return {
    width: state.el.clientWidth || 600,
    height: d.height,
    padding: [8, 8, 8, 8],
    series,
    bands,
    scales: { x: { time: true } },
    axes: [
      { stroke: tok.muted, grid: { stroke: tok.border }, ticks: { stroke: tok.border },
       font: `${d.font}px sans-serif`, size: d.xGutter },
      { stroke: tok.muted, grid: { stroke: tok.border }, ticks: { stroke: tok.border },
       font: `${d.font}px sans-serif`, size: d.yGutter },
    ],
    legend: { show: true },
    cursor: { points: { show: true } },
  };
}

function toUplotData(state) {
  const isEnvelope = state.data.mode === "envelope";
  // uPlot needs one shared x per plot; since runs may have different step
  // grids, union the x values so every run's series aligns to the same axis
  // (missing points render as gaps via spanGaps-free nulls).
  const allX = new Set();
  state.data.series.forEach((s) => s.x.forEach((x) => allX.add(x)));
  const xs = Array.from(allX).sort((a, b) => a - b);
  const idx = new Map(xs.map((x, i) => [x, i]));

  const cols = [xs];
  state.data.series.forEach((s) => {
    if (isEnvelope) {
      const mn = new Array(xs.length).fill(null);
      const mx = new Array(xs.length).fill(null);
      s.x.forEach((x, i) => { mn[idx.get(x)] = s.min[i]; mx[idx.get(x)] = s.max[i]; });
      cols.push(mn, mx);
    } else {
      const ys = new Array(xs.length).fill(null);
      s.x.forEach((x, i) => { ys[idx.get(x)] = s.y[i]; });
      cols.push(ys);
    }
  });
  return cols;
}

function buildFallbackTable(state) {
  const table = state.tableEl;
  table.innerHTML = "";
  const isEnvelope = state.data.mode === "envelope";
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  ["run", "x", isEnvelope ? "min" : "y", ...(isEnvelope ? ["max"] : [])].forEach((h) => {
    const th = document.createElement("th");
    th.textContent = h;
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  let n = 0;
  for (const row of state.tableRows || []) {
    if (n >= 200) break;
    const tr = document.createElement("tr");
    const cells = isEnvelope
      ? [row.run_id, row.x, row.min, row.max]
      : [row.run_id, row.x, row.y];
    cells.forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v == null ? "" : String(v);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
    n++;
  }
  table.appendChild(tbody);
}

function rebuild(state) {
  if (state.u) state.u.destroy();
  const opts = buildOpts(state);
  state.u = new uPlot(opts, toUplotData(state), state.el);
  // The canvas conveys nothing to a screen reader; `el` already carries
  // role="img" + an aria-label, and the offscreen <table> is the real data
  // surface for assistive tech, so uPlot's own DOM (canvas + HTML legend) is
  // hidden from the accessibility tree rather than read twice.
  if (state.u.root) state.u.root.setAttribute("aria-hidden", "true");
}

function attachObservers(state) {
  let raf = null;
  state.ro = new ResizeObserver(() => {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = null;
      const w = state.el.clientWidth;
      if (w && state.u) state.u.setSize({ width: w, height: state.u.height });
    });
  });
  state.ro.observe(state.el.parentElement || state.el);

  const onTheme = () => rebuild(state);
  state.mo = new MutationObserver(onTheme);
  state.mo.observe(document.documentElement, {
    attributes: true, attributeFilter: ["data-theme", "data-density"],
  });
  state.mq = window.matchMedia("(prefers-color-scheme: dark)");
  state.mqListener = onTheme;
  state.mq.addEventListener("change", state.mqListener);
}

export function createChart(el, { id, data, tableEl }) {
  const state = { id, el, data, tableEl, tableRows: [], u: null };
  rebuild(state);
  attachObservers(state);

  const handle = {
    id,
    get u() { return state.u; },
    getData() { return state.data; },
    setData(newData, tableRows) {
      state.data = newData;
      state.tableRows = tableRows || state.tableRows;
      rebuild(state);
      if (state.tableEl) buildFallbackTable(state);
    },
    setTableRows(rows) {
      state.tableRows = rows;
      if (state.tableEl) buildFallbackTable(state);
    },
    destroy() {
      if (state.ro) state.ro.disconnect();
      if (state.mo) state.mo.disconnect();
      if (state.mq && state.mqListener) state.mq.removeEventListener("change", state.mqListener);
      if (state.u) state.u.destroy();
      REGISTRY.delete(id);
    },
  };
  REGISTRY.set(id, handle);
  return handle;
}
