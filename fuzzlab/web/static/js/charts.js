// fuzzlab control panel — shared chart wrapper (U4 + U5; R-12).
//
// One wrapper over vendored uPlot 1.6.32 (`/static/vendor/uplot/uPlot.esm.js`), the
// project's one sanctioned zero-build vendored exception (D2/R-02). Canvas can't read
// CSS custom properties and bakes colors in at draw time, and re-measures axis
// geometry at construction, so this: resolves design tokens once per (re)build via a
// hidden probe element (`getPropertyValue` on a var()/color-mix() chain returns the
// unresolved string — only `getComputedStyle` on an element actually using it
// resolves it); fully `destroy()`s and reconstructs on every theme/density change
// (`setSize`/`setData` alone can't restyle a canvas that's already drawn); sizes off
// `data-density`; and debounces a `ResizeObserver` on the chart's parent cell (not the
// uPlot root itself — that would be a resize-observer feedback loop) through
// `requestAnimationFrame`.
//
// Every chart registers on `window.__charts` (id -> {getData(), u, setData, destroy})
// — the R-09 test hook that lets Playwright assert chart content without touching
// canvas pixels — and renders a capped, `visually-hidden` `<table>` fallback next to
// the (aria-hidden) canvas, kept current on every `setData` (a11y + R-09/R-11).
//
// Scope: this module intentionally covers what U4 (advisory ML panels) and U5
// (diagnostics trend lines) actually need — single-series line/bar charts, LTTB
// pre-downsampling of one series, and a min/max envelope bucketer for a CI-band-style
// series. `lttb`/`envelopeBuckets` operate on one (x, y) pair; a chart with more than
// one y-series sharing an x that is already under the ~1000-point cap (every U4 panel
// today) skips downsampling rather than downsampling series independently onto
// mismatched x indices, which would silently misalign points across series.

import uPlot from "/static/vendor/uplot/uPlot.esm.js";
import { lttb } from "/static/js/downsample.js";

const LTTB_THRESHOLD = 1000;

const DENSITY = {
  comfortable: { font: 12, xGutter: 34, yGutter: 50, tick: 6, gap: 6, point: 5 },
  compact: { font: 11, xGutter: 28, yGutter: 44, tick: 4, gap: 4, point: 4 },
};

function density() {
  return document.documentElement.getAttribute("data-density") === "compact"
    ? DENSITY.compact : DENSITY.comfortable;
}

// A hidden probe element used to resolve a CSS custom property to a concrete color
// uPlot's canvas can parse (see the module doc comment above).
let _probe = null;
function resolveToken(name, fallback) {
  if (typeof document === "undefined") return fallback; // node:test import safety
  if (!_probe) {
    _probe = document.createElement("span");
    _probe.style.position = "absolute";
    _probe.style.left = "-9999px";
    _probe.style.visibility = "hidden";
    _probe.setAttribute("aria-hidden", "true");
    document.body.appendChild(_probe);
  }
  _probe.style.color = `var(${name})`;
  const resolved = getComputedStyle(_probe).color;
  return resolved && resolved !== "" ? resolved : fallback;
}

// Exported so callers building a custom series (e.g. ml.js's bar-fill color) can
// resolve the same concrete, canvas-safe colors createChart uses internally, without
// re-implementing the hidden-probe trick themselves.
export function tokens() {
  return {
    text: resolveToken("--text", "#1a1d21"),
    muted: resolveToken("--muted", "#6b7280"),
    border: resolveToken("--border", "#e3e6ea"),
    accent: resolveToken("--accent", "#2563eb"),
  };
}

function chartHeight() {
  const v = getComputedStyle(document.documentElement).getPropertyValue("--chart-h");
  const n = parseFloat(v);
  return Number.isFinite(n) && n > 0 ? n : 220;
}

// Build/refresh the offscreen a11y fallback table for one chart's current columnar
// data ([xs, ...ys]). Capped at 200 rows so a long series stays a bounded DOM.
function renderTable(container, def, data) {
  let table = container.querySelector("table.chart-fallback");
  if (!table) {
    table = document.createElement("table");
    table.className = "chart-fallback visually-hidden";
    container.appendChild(table);
  }
  const labels = (def.series || []).map((s) => (s && s.label) || "");
  const rows = data[0] ? data[0].length : 0;
  const cap = Math.min(rows, 200);
  let html = `<caption>${escapeHtml(def.label || def.id)}</caption><thead><tr>`;
  html += `<th scope="col">${escapeHtml(labels[0] || "x")}</th>`;
  for (let i = 1; i < data.length; i++) {
    html += `<th scope="col">${escapeHtml(labels[i] || `series ${i}`)}</th>`;
  }
  html += "</tr></thead><tbody>";
  for (let r = 0; r < cap; r++) {
    html += "<tr>";
    for (let c = 0; c < data.length; c++) html += `<td>${data[c][r]}</td>`;
    html += "</tr>";
  }
  html += "</tbody>";
  table.innerHTML = html;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

// Pre-downsample def.data ([xs, ...ys]) for the plot: LTTB on a single-y-series
// chart over the threshold; passed through unchanged otherwise (see the module doc
// comment on the multi-series limitation).
function downsampleForPlot(data) {
  if (!data || !data[0] || data[0].length <= LTTB_THRESHOLD || data.length !== 2) {
    return data;
  }
  const { xs, ys } = lttb(data[0], data[1], LTTB_THRESHOLD);
  return [xs, ys];
}

const _registry = (typeof window !== "undefined")
  ? (window.__charts = window.__charts || new Map())
  : new Map();

/**
 * Build a themed, density-aware, resize-aware uPlot chart with an offscreen table
 * fallback, and register it on `window.__charts`.
 *
 * `def`: `{ id, label, type: 'line'|'bars', data: [xs, ...ys] (columnar, x in unix
 * seconds or a plain step index), series: [{}, {label, stroke?, fill?, width?}, ...]
 * (uPlot series options; index 0 is the x "series"), opts: partial uPlot options
 * merged in last (wins over the defaults below), envelope: bool (skip LTTB — the
 * caller already bucketed a CI band) }`.
 *
 * Returns `{ getData(), setData(data), destroy(), get u() }`.
 */
export function createChart(el, def) {
  let plotData = def.envelope ? def.data : downsampleForPlot(def.data);

  // Recomputed on every call (including rebuild() below) so a theme/density change
  // actually changes the colors/sizing baked into the next canvas draw.
  function baseOpts() {
    const den = density();
    const tok = tokens();
    return {
      width: el.clientWidth || 480,
      height: chartHeight(),
      cursor: { show: true },
      legend: { show: true },
      axes: [
        { stroke: tok.muted, grid: { stroke: tok.border },
          font: `${den.font}px sans-serif`, size: den.yGutter, ticks: { size: den.tick } },
        { stroke: tok.muted, grid: { stroke: tok.border },
          font: `${den.font}px sans-serif`, size: den.xGutter, ticks: { size: den.tick } },
      ],
      series: (def.series || []).map((s, i) => (i === 0 ? (s || {}) : {
        stroke: tok.accent,
        width: 2,
        points: { size: den.point },
        ...s,
      })),
      ...(def.opts || {}),
    };
  }

  let u = new uPlot(baseOpts(), plotData, el);
  renderTable(el, def, plotData);
  const canvas = el.querySelector("canvas");
  if (canvas) canvas.setAttribute("aria-hidden", "true");
  el.setAttribute("role", "img");
  el.setAttribute("aria-label", def.label || def.id);

  let raf = null;
  const onResize = () => {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = null;
      u.setSize({ width: el.clientWidth || 480, height: u.height });
    });
  };
  let ro = null;
  try {
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(onResize);
      ro.observe(el.parentElement || el);
    }
  } catch (_) { /* no usable ResizeObserver — chart just keeps its initial size */ }

  function rebuild() {
    const cur = u.getData();
    const xScale = { min: u.scales.x.min, max: u.scales.x.max };
    u.destroy();
    u = new uPlot(baseOpts(), cur, el);
    if (xScale.min != null) u.setScale("x", xScale); // preserve zoom across rebuild
    renderTable(el, def, cur);
    const c = el.querySelector("canvas");
    if (c) c.setAttribute("aria-hidden", "true");
  }
  let mo = null;
  try {
    if (typeof MutationObserver !== "undefined") {
      mo = new MutationObserver(rebuild);
      mo.observe(document.documentElement,
        { attributes: true, attributeFilter: ["data-theme", "data-density"] });
    }
  } catch (_) { /* no usable MutationObserver */ }
  const mm = (typeof window !== "undefined" && window.matchMedia)
    ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  if (mm) mm.addEventListener("change", rebuild);

  const handle = {
    get u() { return u; },
    getData() { return u.getData(); },
    setData(next) {
      plotData = def.envelope ? next : downsampleForPlot(next);
      u.setData(plotData);
      renderTable(el, def, plotData);
    },
    destroy() {
      if (ro) ro.disconnect();
      if (mo) mo.disconnect();
      if (mm) mm.removeEventListener("change", rebuild);
      if (raf) cancelAnimationFrame(raf);
      u.destroy();
      _registry.delete(def.id);
    },
  };
  _registry.set(def.id, handle);
  return handle;
}
