// fuzzlab control panel — ML tab (U4; feature Phase 3).
//
// Read-only, advisory. Mounts uPlot-backed charts (via the shared static/js/charts.js
// wrapper) into the containers ml.html server-rendered; the server already rendered
// every number/table directly from `fuzzlab/web/mlview.py`'s context, so a no-JS
// client still sees the real values — this module only adds the charts. Data comes
// from the `#ml-data` JSON blob the template embeds (no extra fetch; the page's own
// render already read the store once).
//
// This tab never trains anything and never talks to the fuzzing loop: every value
// plotted here is a read of what fuzzlab/ml, fuzzlab/oracle, fuzzlab/scheduler, and
// fuzzlab/mutation already persisted.

import { createChart, tokens } from "/static/js/charts.js";

function readData() {
  const el = document.getElementById("ml-data");
  if (!el) return null;
  try { return JSON.parse(el.textContent); } catch (_) { return null; }
}

function histogramColumns(hist) {
  if (!hist || !hist.edges || !hist.edges.length) return null;
  const centers = [];
  for (let i = 0; i < hist.counts.length; i++) {
    centers.push((hist.edges[i] + hist.edges[i + 1]) / 2);
  }
  return [centers, hist.counts];
}

// All three helpers below go through the shared `createChart` (static/js/charts.js,
// also used by Diagnostics/U5): its `data.series[]` items are normally one-per-run
// ({run_id, x, y}, labeled "run {run_id}"), but every series here is a single-run
// panel with its own caller-supplied `label` (and, for bars, `kind`/`color`), which
// charts.js's buildOpts uses verbatim when present — added generically so this tab
// doesn't need a second hand-rolled wrapper (R-12). charts.js assumes its caller's
// `el` already carries `role="img"` + an aria-label (Diagnostics sets it server-side
// since its labels are static); this tab's labels include a run-time-formatted value
// (conformal's t_lo/t_hi), so each helper sets both attributes here instead.
function mountBars(id, xs, ys, label) {
  const el = document.getElementById(`chart-${id}`);
  if (!el || !xs || !xs.length) return;
  el.setAttribute("role", "img");
  el.setAttribute("aria-label", label);
  createChart(el, {
    id,
    data: { mode: "line", series: [
      { run_id: id, x: xs, y: ys, label, color: tokens().accent, kind: "bars" },
    ] },
  });
}

function mountLine(id, xs, ys, label) {
  const el = document.getElementById(`chart-${id}`);
  if (!el || !xs || !xs.length) return;
  el.setAttribute("role", "img");
  el.setAttribute("aria-label", label);
  createChart(el, {
    id,
    data: { mode: "line", series: [{ run_id: id, x: xs, y: ys, label }] },
  });
}

function mountMultiLine(id, xs, seriesList, label) {
  const el = document.getElementById(`chart-${id}`);
  if (!el || !xs || !xs.length) return;
  el.setAttribute("role", "img");
  el.setAttribute("aria-label", label);
  createChart(el, {
    id,
    data: { mode: "line", series: seriesList.map((s, i) => (
      { run_id: `${id}-${i}`, x: xs, y: s.ys, label: s.label, width: s.width })) },
  });
}

// log-gamma (Lanczos approximation) — the one piece of numerical code this panel
// needs to turn a Beta(alpha, beta) posterior into a plottable density curve
// client-side (no server-side scipy/numpy dependency anywhere in this toolkit).
function lgamma(x) {
  const g = 7;
  const c = [
    0.99999999999980993, 676.5203681218851, -1259.1392167224028,
    771.32342877765313, -176.61502916214059, 12.507343278686905,
    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
  ];
  if (x < 0.5) {
    return Math.log(Math.PI / Math.sin(Math.PI * x)) - lgamma(1 - x);
  }
  x -= 1;
  let a = c[0];
  const t = x + g + 0.5;
  for (let i = 1; i < g + 2; i++) a += c[i] / (x + i);
  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}

function betaPdf(x, alpha, beta) {
  if (x <= 0 || x >= 1) return 0;
  const logB = lgamma(alpha) + lgamma(beta) - lgamma(alpha + beta);
  const logPdf = (alpha - 1) * Math.log(x) + (beta - 1) * Math.log(1 - x) - logB;
  return Math.exp(logPdf);
}

function betaGrid(alpha, beta, n = 100) {
  const ys = [];
  for (let i = 1; i < n; i++) ys.push(betaPdf(i / n, alpha, beta));
  return ys;
}

function mountBanditDensity(bandit) {
  const el = document.getElementById("chart-bandit-density");
  if (!el || !bandit || !bandit.available || !bandit.arms || !bandit.arms.length) return;
  const n = 100;
  const xs = [];
  for (let i = 1; i < n; i++) xs.push(i / n);
  // Cap displayed overlays for legibility (the table already lists every arm).
  const top = bandit.arms.slice().sort((a, b) => b.pulls - a.pulls).slice(0, 8);
  const seriesList = top.map((a) => ({
    label: `${a.context}/${a.arm}`, ys: betaGrid(a.alpha, a.beta, n),
  }));
  mountMultiLine("bandit-density", xs, seriesList, "Beta posterior density");
}

function init() {
  const data = readData();
  if (!data) return;

  // classifier
  if (data.classifier && data.classifier.available) {
    const rel = data.classifier.reliability;
    if (rel && rel.bin_mean_score && rel.bin_mean_score.some((v) => v !== null)) {
      const xs = [], observed = [], diagonal = [];
      rel.bin_mean_score.forEach((v, i) => {
        if (v === null) return;
        xs.push(v);
        observed.push(rel.bin_observed_rate[i]);
        diagonal.push(v); // the 45° reference: a perfectly calibrated model's y = x
      });
      mountMultiLine("classifier-reliability", xs,
        [{ label: "observed rate", ys: observed },
         { label: "perfectly calibrated (y=x)", ys: diagonal, width: 1 }],
        "Reliability diagram");
    }
    const hist = data.classifier.score_histogram;
    if (hist && hist.edges && hist.edges.length) {
      const cols = histogramColumns(hist);
      mountBars("classifier-scores", cols[0], cols[1], "Advisory score distribution");
    }
    const curve = data.classifier.training_curve;
    if (curve && curve.steps && curve.steps.length) {
      mountLine("classifier-loss", curve.steps, curve.values, "train/loss");
    }
  }

  // ranker
  if (data.ranker && data.ranker.available) {
    const sh = data.ranker.score_histogram;
    if (sh && sh.edges && sh.edges.length) {
      const cols = histogramColumns(sh);
      mountBars("ranker-scores", cols[0], cols[1], "Rank score distribution");
    }
    const uh = data.ranker.uncertainty_histogram;
    if (uh && uh.edges && uh.edges.length) {
      const cols = histogramColumns(uh);
      mountBars("ranker-uncertainty", cols[0], cols[1], "Rank uncertainty distribution");
    }
  }

  // conformal
  if (data.conformal && data.conformal.available) {
    const hist = data.conformal.score_histogram;
    if (hist && hist.edges && hist.edges.length) {
      const cols = histogramColumns(hist);
      mountBars("conformal-scores", cols[0], cols[1],
        `Score distribution (t_lo=${data.conformal.t_lo.toFixed(3)}, ` +
        `t_hi=${data.conformal.t_hi.toFixed(3)})`);
    }
  }

  // bandit
  mountBanditDensity(data.bandit);
  if (data.bandit && data.bandit.available && data.bandit.regret &&
      data.bandit.regret.steps && data.bandit.regret.steps.length) {
    mountLine("bandit-regret", data.bandit.regret.steps, data.bandit.regret.values,
      "cumulative regret");
  }

  // mutation
  if (data.mutation && data.mutation.available) {
    if (data.mutation.reward && data.mutation.reward.steps &&
        data.mutation.reward.steps.length) {
      mountLine("mutation-reward", data.mutation.reward.steps, data.mutation.reward.values,
        "reward");
    }
    if (data.mutation.novelty && data.mutation.novelty.steps &&
        data.mutation.novelty.steps.length) {
      mountLine("mutation-novelty", data.mutation.novelty.steps,
        data.mutation.novelty.values, "novelty");
    }
  }
}

document.addEventListener("DOMContentLoaded", init);

// exported for the browser-smoke test (page.evaluate) — pure, no side effects on call
export { betaPdf, histogramColumns };
