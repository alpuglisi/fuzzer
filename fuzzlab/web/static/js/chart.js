// Shared uPlot chart wrapper (R-02/R-12, vendored uPlot 1.6.32) — consumed by the ML
// tab (U4) and Diagnostics (U5). Standalone ES module, no bundler.
//
// Canvas can't read CSS custom properties, and uPlot bakes resolved colors into the
// canvas at construction + measures axis geometry then too — so a theme or density
// change is handled as a full destroy() + recreate, never a partial restyle. Data-only
// updates use setData(); size-only updates use setSize().
//
// window.__charts is a Map<id, handle> (handle = { getData(), setSize(), destroy(), u })
// for browser-smoke tests and console debugging (R-09). Each chart also renders a
// visually-hidden <table> a11y fallback next to the (aria-hidden) canvas, since a
// canvas chart is opaque to screen readers (R-11); it is kept current on every
// setData().
import uPlot from "/static/vendor/uplot/uPlot.esm.js";

window.__charts = window.__charts instanceof Map ? window.__charts : new Map();

// Density -> discrete sizing buckets (R-12's exact numbers).
const DENSITY = {
  comfortable: { font: 12, xGutter: 34, yGutter: 50, tick: 6, gap: 6, tickSpace: 60, ySpace: 40, point: 5 },
  compact: { font: 11, xGutter: 28, yGutter: 44, tick: 4, gap: 4, tickSpace: 48, ySpace: 30, point: 4 },
};

function currentDensity() {
  return document.documentElement.getAttribute("data-density") === "compact" ? "compact" : "comfortable";
}

// --- CSS token resolution -----------------------------------------------------
// getPropertyValue on a color token can hand back an unresolved var()/color-mix()
// chain the canvas can't parse; resolving it through a hidden probe element's
// computed style always yields a concrete rgb()/rgba() string. Numeric tokens (no
// color-mix involved) are read directly with getPropertyValue + parseFloat.
let _probe = null;
function _probeEl() {
  if (!_probe) {
    _probe = document.createElement("div");
    _probe.style.cssText = "position:absolute;visibility:hidden;pointer-events:none;top:-9999px;left:-9999px;height:0;width:0;";
    document.body.appendChild(_probe);
  }
  return _probe;
}
function resolveColor(varName, fallback) {
  try {
    const p = _probeEl();
    p.style.color = `var(${varName})`;
    const resolved = getComputedStyle(p).color;
    return resolved || fallback;
  } catch (e) {
    return fallback;
  }
}
function resolveNum(varName, fallback) {
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue(varName);
    const n = parseFloat(v);
    return Number.isFinite(n) ? n : fallback;
  } catch (e) {
    return fallback;
  }
}

// Neutral blue/amber palette (R-06): ML panels never borrow the oracle's red/green.
function tokens() {
  return {
    text: resolveColor("--text", "#1a1d21"),
    muted: resolveColor("--muted", "#6b7280"),
    border: resolveColor("--border", "#e3e6ea"),
    accent: resolveColor("--accent", "#2563eb"),       // blue: model/primary series
    accentWeak: resolveColor("--accent-weak", "#dbe4ff"),
    warn: resolveColor("--warn", "#b45309"),            // amber: secondary/uncertainty series
    surface: resolveColor("--surface", "#ffffff"),
  };
}

// --- a11y fallback table --------------------------------------------------------
// A capped, visually-hidden <table> mirroring the columnar data, so a screen-reader
// user (or a test with JS-off assumptions) gets the numbers the canvas can't expose.
const A11Y_ROW_CAP = 200;

function buildA11yTable(data, seriesLabels, caption) {
  const wrapper = document.createElement("div");
  wrapper.className = "fl-chart-a11y visually-hidden";
  const table = document.createElement("table");
  if (caption) {
    const cap = document.createElement("caption");
    cap.textContent = caption;
    table.appendChild(cap);
  }
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  for (const label of seriesLabels) {
    const th = document.createElement("th");
    th.textContent = label || "";
    htr.appendChild(th);
  }
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  table.appendChild(tbody);
  wrapper.appendChild(table);

  function refresh(cols) {
    tbody.replaceChildren();
    const nCols = cols.length;
    const nRows = Math.min(A11Y_ROW_CAP, cols[0] ? cols[0].length : 0);
    for (let r = 0; r < nRows; r++) {
      const tr = document.createElement("tr");
      for (let c = 0; c < nCols; c++) {
        const td = document.createElement("td");
        const v = cols[c] ? cols[c][r] : null;
        td.textContent = v == null ? "" : String(v);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  }
  refresh(data);
  return { wrapper, refresh };
}

// --- createChart -----------------------------------------------------------------
// el: the container element (a "cell") the chart lives in and resizes to fit.
// { id, type, data, series, opts }:
//   id      — stable string, keys window.__charts and drives teardown-on-redraw.
//   type    — 'line' | 'bars' | 'scatter' (informational + used for default styling).
//   data    — uPlot columnar data: [xs, ys, ...].
//   series  — per-data-series options (label, stroke, fill, width, paths, points, value).
//   opts    — { xValues, xLabel, axes, scales, legend, caption, uplot, padding, bars }.
export function createChart(el, { id, type = "line", data, series = [], opts = {} }) {
  if (!id) throw new Error("createChart: id is required");
  if (!el) throw new Error("createChart: el is required");
  const prior = window.__charts.get(id);
  if (prior) prior.destroy();

  let u = null;
  let a11y = null;
  let ro = null;
  let mo = null;
  let mql = null;
  let rafPending = null;
  let destroyed = false;
  const resizeTarget = el.parentElement || el;

  function densityCfg() {
    return DENSITY[currentDensity()];
  }

  function build() {
    const tk = tokens();
    const dens = densityCfg();
    const height = resolveNum("--chart-h", 220);
    const width = Math.max(1, el.clientWidth || resizeTarget.clientWidth || 480);
    const defaultStroke = [tk.accent, tk.warn, tk.muted];

    const builtSeries = series.map((s, i) => {
      const out = Object.assign({}, s);
      if (out.stroke === undefined) out.stroke = defaultStroke[i % defaultStroke.length];
      if (out.width === undefined && type !== "bars") out.width = 1.5;
      if (type === "bars" && out.paths === undefined) {
        out.paths = uPlot.paths.bars({ size: [0.6, 100], align: 0 });
        if (out.fill === undefined) out.fill = out.stroke;
      }
      if (type === "scatter" && out.paths === undefined) {
        out.paths = () => null;                    // points only, no connecting line
        out.points = out.points || { show: true, size: dens.point };
      }
      if (out.points === undefined && type === "line") {
        out.points = { size: dens.point };
      }
      return out;
    });

    const axesCommon = {
      font: `${dens.font}px system-ui, sans-serif`,
      stroke: tk.muted,
      grid: { stroke: tk.border, width: 1 },
      ticks: { stroke: tk.border, size: dens.tick },
      gap: dens.gap,
    };

    const xAxis = Object.assign({}, axesCommon, { space: dens.tickSpace });
    if (opts.xValues) xAxis.values = opts.xValues;
    const yAxis = Object.assign({}, axesCommon, { space: dens.ySpace, size: dens.yGutter });

    const uOpts = Object.assign(
      {
        width,
        height,
        id: `chart-${id}`,
        class: `fl-chart fl-chart--${type}`,
        series: [{ label: opts.xLabel || "x" }].concat(builtSeries),
        axes: opts.axes || [xAxis, yAxis],
        scales: opts.scales,
        cursor: { drag: { x: true, y: false } },
        legend: { show: opts.legend !== false, live: false },
      },
      opts.padding ? { padding: opts.padding } : {},
      opts.uplot || {},
    );

    el.replaceChildren();
    u = new uPlot(uOpts, data, el);
    const canvas = el.querySelector("canvas");
    if (canvas) canvas.setAttribute("aria-hidden", "true");
    const seriesLabels = [opts.xLabel || "x"].concat(series.map((s) => s.label || ""));
    a11y = buildA11yTable(data, seriesLabels, opts.caption);
    el.appendChild(a11y.wrapper);
    if (!el.hasAttribute("role")) el.setAttribute("role", "img");
    if (opts.caption && !el.hasAttribute("aria-label")) el.setAttribute("aria-label", opts.caption);
  }

  function rebuild() {
    if (destroyed) return;
    if (u) u.destroy();
    build();
  }

  function scheduleResize() {
    if (rafPending != null) return;
    rafPending = requestAnimationFrame(() => {
      rafPending = null;
      if (destroyed || !u) return;
      const width = Math.max(1, el.clientWidth || resizeTarget.clientWidth || 480);
      const height = resolveNum("--chart-h", 220);
      if (width !== u.width || height !== u.height) u.setSize({ width, height });
    });
  }

  build();

  // Responsive: debounced ResizeObserver on the parent cell (not the uPlot root — a
  // uPlot-root observer double-fires as uPlot resizes its own canvas, an RO feedback
  // loop), coalesced with rAF.
  if (typeof ResizeObserver !== "undefined") {
    ro = new ResizeObserver(scheduleResize);
    ro.observe(resizeTarget);
  }

  // Retheme: a MutationObserver on <html> for data-theme/data-density, plus a
  // matchMedia listener for an unforced system-preference flip, both driving the
  // same idempotent rebuild.
  if (typeof MutationObserver !== "undefined") {
    mo = new MutationObserver((muts) => {
      for (const m of muts) {
        if (m.attributeName === "data-theme" || m.attributeName === "data-density") {
          rebuild();
          break;
        }
      }
    });
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-density"] });
  }
  if (typeof matchMedia === "function") {
    mql = matchMedia("(prefers-color-scheme: dark)");
    const onMql = () => rebuild();
    if (mql.addEventListener) mql.addEventListener("change", onMql);
    else if (mql.addListener) mql.addListener(onMql);
    mql._flHandler = onMql;
  }

  const handle = {
    get u() { return u; },
    getData() { return u ? u.data : data; },
    setData(nextData, resetScales) {
      data = nextData;
      if (u) u.setData(nextData, resetScales);
      if (a11y) a11y.refresh(nextData);
    },
    setSize(size) {
      if (u) u.setSize(size);
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      if (ro) { ro.disconnect(); ro = null; }
      if (mo) { mo.disconnect(); mo = null; }
      if (mql) {
        if (mql.removeEventListener) mql.removeEventListener("change", mql._flHandler);
        else if (mql.removeListener) mql.removeListener(mql._flHandler);
        mql = null;
      }
      if (rafPending != null) { cancelAnimationFrame(rafPending); rafPending = null; }
      if (u) { u.destroy(); u = null; }
      window.__charts.delete(id);
    },
  };
  window.__charts.set(id, handle);
  return handle;
}

// --- client-side helpers used alongside createChart (R-05) ---------------

// EMA smoothing, applied client-side AFTER server-side downsampling (the
// render order R-05 specifies), so the slider is instant with no re-fetch.
export function ema(values, alpha) {
  if (!alpha || alpha <= 0) return values.slice();
  const out = new Array(values.length);
  let prev = null;
  for (let i = 0; i < values.length; i++) {
    const v = values[i];
    if (v == null) { out[i] = prev; continue; }
    prev = prev == null ? v : alpha * prev + (1 - alpha) * v;
    out[i] = prev;
  }
  return out;
}
