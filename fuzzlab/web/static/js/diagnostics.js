// Diagnostics + store explorer (U5/CC-UI-0032). TensorBoard-like cross-run
// trends over `run_metrics`, intra-run step series over `metric_series`
// (LTTB-downsampled server-side, R-05), snapshot panels (candidate-score
// distribution, bandit arm state, model registry timeline), and a read-only
// Datasette-style store explorer (FR-UI-2). Store rows are untrusted content
// (arbitrary bytes a fuzzing run wrote), so every cell renders via
// `datatable.js`'s `textContent`-only path — never innerHTML.
import { createChart, ema } from "/static/js/chart.js";
// U2 (CC-UI-0029) landed the shared datatable.js first; its API is
// createDataTable(root, {columns, data, ...}) rather than this lane's
// original mount(el, {columns, data}) — adapted below rather than
// duplicating a second DataTable implementation.
import { createDataTable } from "/static/js/datatable.js";

const RUN_COLORS_SEEN = new Map(); // run_id -> palette index, stable across rebuilds

function initDiagnostics() {
  const root = document.getElementById("diagnostics-root");
  if (!root) return; // not the diagnostics page

  initControls();
  initStoreExplorer();
}

// --- controls + chart panels ------------------------------------------------

function initControls() {
  const runList = document.getElementById("diag-run-list");
  const metricGroups = document.getElementById("diag-metric-groups");
  const metricFilter = document.getElementById("diag-metric-filter");
  const emaSlider = document.getElementById("diag-ema");
  const emaValue = document.getElementById("diag-ema-value");
  const xAxisSel = document.getElementById("diag-xaxis");
  const yLogChk = document.getElementById("diag-ylog");
  if (!runList) return;

  const state = {
    runIds: [],
    source: null,
    key: null,
    ema: 0,
    xAxis: "step",
    yLog: false,
  };

  let trendChart = null;
  let seriesChart = null;
  let lastSeriesRaw = null; // cache the last server response so EMA/x-axis toggles are instant

  async function loadRuns() {
    const r = await fetch("/api/diagnostics/runs");
    const { runs } = await r.json();
    runList.replaceChildren();
    for (const run of runs) {
      const label = document.createElement("label");
      label.className = "diag-run-chip";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = String(run.id);
      cb.addEventListener("change", onRunsChanged);
      label.appendChild(cb);
      const span = document.createElement("span");
      span.textContent = `#${run.id} ${run.tool} ${run.started_at || ""}`;
      label.appendChild(span);
      runList.appendChild(label);
    }
  }

  async function loadMetrics() {
    const r = await fetch("/api/diagnostics/metrics");
    const grouped = await r.json();
    metricGroups.replaceChildren();
    // run_metrics group (cross-run trend keys)
    addMetricGroup("run_metrics", grouped.run_metrics || [], "run_metrics");
    for (const [source, keys] of Object.entries(grouped.series || {})) {
      addMetricGroup(source, keys, "series");
    }
  }

  function addMetricGroup(source, keys, kind) {
    if (!keys.length) return;
    const details = document.createElement("details");
    details.open = true;
    const summary = document.createElement("summary");
    summary.textContent = source;
    details.appendChild(summary);
    const list = document.createElement("div");
    list.className = "diag-metric-list";
    for (const key of keys) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "diag-metric-btn";
      btn.dataset.kind = kind;
      btn.dataset.source = source;
      btn.dataset.key = key;
      btn.textContent = key;
      btn.addEventListener("click", () => selectMetric(kind, source, key, btn));
      list.appendChild(btn);
    }
    details.appendChild(list);
    metricGroups.appendChild(details);
  }

  function selectMetric(kind, source, key, btn) {
    metricGroups.querySelectorAll(".diag-metric-btn.active")
      .forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.kind = kind;
    state.source = source;
    state.key = key;
    refreshCharts();
  }

  function onRunsChanged() {
    state.runIds = Array.from(runList.querySelectorAll("input:checked")).map((c) => Number(c.value));
    refreshCharts();
  }

  if (metricFilter) {
    metricFilter.addEventListener("input", () => {
      const q = metricFilter.value.trim().toLowerCase();
      metricGroups.querySelectorAll(".diag-metric-btn").forEach((b) => {
        b.hidden = q !== "" && !b.dataset.key.toLowerCase().includes(q);
      });
    });
  }

  if (emaSlider) {
    emaSlider.addEventListener("input", () => {
      state.ema = Number(emaSlider.value);
      if (emaValue) emaValue.textContent = state.ema.toFixed(2);
      applyEmaToSeriesChart();
    });
  }
  if (xAxisSel) {
    xAxisSel.addEventListener("change", () => {
      state.xAxis = xAxisSel.value;
      renderSeriesChart();
    });
  }
  if (yLogChk) {
    yLogChk.addEventListener("change", () => {
      state.yLog = yLogChk.checked;
      renderSeriesChart();
    });
  }

  function paletteIndex(runId) {
    if (!RUN_COLORS_SEEN.has(runId)) RUN_COLORS_SEEN.set(runId, RUN_COLORS_SEEN.size);
    return RUN_COLORS_SEEN.get(runId);
  }

  async function refreshCharts() {
    if (state.runIds.length === 0) return;
    if (state.kind === "run_metrics" && state.key) {
      await renderTrendChart();
    } else if (state.kind === "series" && state.source && state.key) {
      await loadSeriesAndRender();
    }
  }

  async function renderTrendChart() {
    const q = `run_ids=${state.runIds.join(",")}&keys=${encodeURIComponent(state.key)}`;
    const r = await fetch(`/api/diagnostics/trend?${q}`);
    const { runs, series } = await r.json();
    const xs = runs.map((rr) => rr.id);
    const ys = (series[state.key] || []).map((v) => (v == null ? null : v));
    const el = document.getElementById("diag-trend-chart");
    if (!el) return;
    const data = [xs, ys];
    const seriesSpec = [{}, { label: state.key }];
    if (trendChart) trendChart.destroy();
    trendChart = createChart(el, {
      id: "diag-trend", type: "line", data, series: seriesSpec,
      opts: { ariaLabel: `cross-run trend for ${state.key}`, scales: { x: { time: false } } },
    });
  }

  async function loadSeriesAndRender() {
    const q = `run_ids=${state.runIds.join(",")}&source=${encodeURIComponent(state.source)}` +
      `&key=${encodeURIComponent(state.key)}&max_points=1000`;
    const r = await fetch(`/api/diagnostics/series?${q}`);
    lastSeriesRaw = await r.json();
    renderSeriesChart();
  }

  function renderSeriesChart() {
    if (!lastSeriesRaw) return;
    const el = document.getElementById("diag-series-chart");
    if (!el) return;
    const runIds = Object.keys(lastSeriesRaw.series);
    if (runIds.length === 0) return;
    // Align on the first run's x-axis (step index) when runs have differing
    // step counts — a simple, honest overlay (no resampling across runs).
    const longest = runIds.reduce((a, b) =>
      lastSeriesRaw.series[a].steps.length >= lastSeriesRaw.series[b].steps.length ? a : b);
    let xs = lastSeriesRaw.series[longest].steps.slice();
    if (state.xAxis === "relative-time" || state.xAxis === "wall-clock") {
      // Server sends step indices only for now; both time modes fall back to
      // step order when no timestamp array is present (still monotonic).
      xs = xs.map((_, i) => i);
    }
    const cols = [xs];
    const seriesSpec = [{}];
    for (const rid of runIds) {
      const smoothed = state.ema > 0
        ? ema(lastSeriesRaw.series[rid].values, state.ema)
        : lastSeriesRaw.series[rid].values;
      cols.push(smoothed);
      seriesSpec.push({ label: `run #${rid}`, stroke: undefined });
    }
    if (seriesChart) seriesChart.destroy();
    seriesChart = createChart(el, {
      id: "diag-series", type: "line", data: cols, series: seriesSpec,
      opts: {
        ariaLabel: `${state.source}/${state.key} intra-run series`,
        scales: { y: { distr: state.yLog ? 3 : 1 } },
      },
    });
  }

  function applyEmaToSeriesChart() {
    renderSeriesChart();
  }

  loadRuns();
  loadMetrics();
  loadSnapshotPanels();
}

// --- snapshot panels: candidate scores / bandit arms / model registry -----

async function loadSnapshotPanels() {
  const banditEl = document.getElementById("diag-bandit-table");
  if (banditEl) {
    const r = await fetch("/api/diagnostics/bandit");
    const { arms } = await r.json();
    createDataTable(banditEl, {
      caption: "Bandit arm posteriors",
      columns: [
        { key: "context", label: "context" },
        { key: "arm", label: "arm" },
        { key: "alpha", label: "α" },
        { key: "beta", label: "β" },
        { key: "mean", label: "mean",
          render: (row) => (row.mean == null ? "" : row.mean.toFixed(3)) },
        { key: "updated_at", label: "updated" },
      ],
      data: arms,
    });
  }

  const modelEl = document.getElementById("diag-model-table");
  if (modelEl) {
    const r = await fetch("/api/diagnostics/models");
    const { models } = await r.json();
    createDataTable(modelEl, {
      caption: "Model registry timeline",
      columns: [
        { key: "name", label: "name" },
        { key: "version", label: "version" },
        { key: "feature_version", label: "feature_version" },
        { key: "created_at", label: "created" },
      ],
      data: models,
    });
  }
}

// --- store explorer (FR-UI-2, read-only) -----------------------------------

function initStoreExplorer() {
  const select = document.getElementById("store-table-select");
  const tableEl = document.getElementById("store-table");
  const meta = document.getElementById("store-table-meta");
  const prevBtn = document.getElementById("store-prev");
  const nextBtn = document.getElementById("store-next");
  const filterInput = document.getElementById("store-filter");
  if (!select || !tableEl) return;

  const state = { table: null, limit: 100, offset: 0, total: 0, dt: null };

  async function loadTables() {
    const r = await fetch("/api/store/tables");
    const { tables } = await r.json();
    select.replaceChildren();
    for (const t of tables) {
      const opt = document.createElement("option");
      opt.value = t;
      opt.textContent = t;
      select.appendChild(opt);
    }
    if (tables.length) {
      state.table = tables[0];
      select.value = tables[0];
      loadPage();
    }
  }

  async function loadPage() {
    if (!state.table) return;
    const q = `limit=${state.limit}&offset=${state.offset}`;
    const r = await fetch(`/api/store/tables/${encodeURIComponent(state.table)}?${q}`);
    if (!r.ok) return;
    const page = await r.json();
    state.total = page.total;
    if (meta) {
      meta.textContent = `${page.total} row${page.total === 1 ? "" : "s"} — ` +
        `showing ${Math.min(page.offset + 1, page.total)}` +
        `–${Math.min(page.offset + page.rows.length, page.total)}`;
    }
    const columns = page.columns.map((c, idx) => ({ key: idx, label: c }));
    // Rows are arrays (positional, matching `columns`) from a store table
    // whose contents are untrusted (fuzzer-written payloads/URLs/bodies) —
    // datatable.js renders every cell via textContent, never innerHTML.
    // createDataTable mounts via root.replaceChildren(), so re-calling it on
    // the same element already replaces the prior table — no explicit
    // teardown needed between pages/table switches.
    state.dt = createDataTable(tableEl, {
      caption: `${state.table} rows`,
      columns,
      data: page.rows,
    });
    if (prevBtn) prevBtn.disabled = state.offset <= 0;
    if (nextBtn) nextBtn.disabled = state.offset + page.rows.length >= state.total;
  }

  select.addEventListener("change", () => {
    state.table = select.value;
    state.offset = 0;
    loadPage();
  });
  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      state.offset = Math.max(0, state.offset - state.limit);
      loadPage();
    });
  }
  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      state.offset += state.limit;
      loadPage();
    });
  }
  if (filterInput) {
    filterInput.addEventListener("input", () => {
      if (state.dt) state.dt.setTextFilter(filterInput.value);
    });
  }

  loadTables();
}

initDiagnostics();
