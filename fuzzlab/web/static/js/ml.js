// ML section (U4/CC-UI-0031, CC-ML-0010) — read-only, advisory (R-06). Fetches
// /api/ml/data once on load and renders every panel from it; nothing here writes to
// the store, and nothing here ever calls a score a "finding" or "vulnerable" (verb
// hygiene: scored/ranked/flagged only).
import { createChart } from "/static/js/chart.js";

const BAND = { flag: "band-flag", abstain: "band-abstain", drop: "band-drop",
              survived: "band-survived", killed: "band-killed" };

function band(status, label) {
  const span = document.createElement("span");
  span.className = "band " + (BAND[status] || "band-abstain");
  span.textContent = label || status;
  return span;
}

function setMeta(panelId, text) {
  const p = document.querySelector(`#panel-${panelId} [data-field="summary"]`);
  if (p) p.textContent = text;
}

function showEmpty(panelId, reason) {
  const el = document.querySelector(`#panel-${panelId} [data-field="empty"]`);
  if (el) { el.hidden = false; el.textContent = reason || "No data in the store yet."; }
  const meta = document.querySelector(`#panel-${panelId} [data-field="summary"]`);
  if (meta) meta.textContent = "";
}

// None of this tab's charts are real time series (uPlot's x scale defaults to
// time=true), so every call disables it unless the caller overrides `opts.scales`.
const NON_TIME_X = { x: { time: false } };

function bars(elId, categories, series, opts = {}) {
  const el = document.getElementById(elId);
  if (!el) return;
  const xs = categories.map((_, i) => i);
  createChart(el, {
    id: elId, type: "bars", data: [xs, ...series.map((s) => s.data)],
    series: series.map((s) => ({ label: s.label })),
    opts: Object.assign({
      xValues: (u, splits) => splits.map((i) => categories[i] ?? ""),
      legend: series.length > 1,
      scales: NON_TIME_X,
    }, opts),
  });
}

function line(elId, xs, series, opts = {}) {
  const el = document.getElementById(elId);
  if (!el) return;
  createChart(el, {
    id: elId, type: opts.scatter ? "scatter" : "line",
    data: [xs, ...series.map((s) => s.data)],
    series: series.map((s) => ({ label: s.label, stroke: s.stroke, width: s.width, points: s.points })),
    opts: Object.assign({ legend: series.length > 1, scales: NON_TIME_X }, opts),
  });
}

function histChart(elId, hist, label) {
  if (!hist || !hist.counts || !hist.counts.length) return;
  const cats = hist.edges.slice(0, -1).map((e, i) => `${e.toFixed(2)}–${hist.edges[i + 1].toFixed(2)}`);
  bars(elId, cats, [{ label, data: hist.counts }], { caption: `${label} histogram` });
}

// --- classifier + calibration ---------------------------------------------------
function renderClassifier(d) {
  if (!d.available) { showEmpty("calibration", d.reason); return; }
  setMeta("calibration", `PR-AUC ${d.pr_auc.toFixed(3)} (baseline prevalence `
    + `${d.baseline_prevalence.toFixed(3)}) · N=${d.n} (${d.positives} confirmed) `
    + `· ECE ${d.reliability.ece.toFixed(3)}`);
  const rel = d.reliability.bins.filter((b) => b.count > 0);
  if (rel.length) {
    const xs = rel.map((b) => b.mean_pred);
    line("chart-reliability", xs, [
      { label: "observed", data: rel.map((b) => b.observed), stroke: undefined },
      { label: "y = x (perfect)", data: xs, stroke: "var(--muted)" },
    ], { scales: { x: { time: false, range: [0, 1] }, y: { range: [0, 1] } } });
  }
  if (d.pr_curve.length) {
    const xs = d.pr_curve.map((p) => p.recall);
    line("chart-pr-curve", xs, [
      { label: "precision", data: d.pr_curve.map((p) => p.precision) },
      { label: "prevalence baseline", data: xs.map(() => d.baseline_prevalence), stroke: "var(--warn)" },
    ], { scales: { x: { time: false, range: [0, 1] }, y: { range: [0, 1] } } });
  }
}

// --- ranker -----------------------------------------------------------------------
function renderRanker(d) {
  if (!d.available) { showEmpty("ranker", d.reason); return; }
  setMeta("ranker", `nDCG@${d.k} ${d.ndcg_at_k.toFixed(3)} · precision@${d.k} `
    + `${d.precision_at_k.toFixed(3)} (random baseline ${d.random_baseline_precision_at_k.toFixed(3)}) `
    + `· N=${d.n}`);
  bars("chart-rank-bars", ["nDCG@k", "precision@k"], [
    { label: "ranker", data: [d.ndcg_at_k, d.precision_at_k] },
    { label: "random baseline", data: [0, d.random_baseline_precision_at_k] },
  ], { caption: "nDCG@k / precision@k vs random" });
  histChart("chart-rank-score-hist", d.score_hist, "rank score");
  histChart("chart-rank-unc-hist", d.uncertainty_hist, "rank uncertainty");
  if (d.scatter.length) {
    const sorted = [...d.scatter].sort((a, b) => a.score - b.score);
    line("chart-rank-scatter", sorted.map((p) => p.score), [
      { label: "uncertainty", data: sorted.map((p) => p.uncertainty), points: { size: 4 } },
    ], { scatter: true, caption: "score vs. uncertainty" });
  }
}

// --- conformal ----------------------------------------------------------------
function renderConformal(d) {
  if (!d.available) { showEmpty("conformal", d.reason); return; }
  const meta = document.querySelector('#panel-conformal [data-field="summary"]');
  if (meta) {
    meta.replaceChildren(
      document.createTextNode(`${d.model.name} v${d.model.version} · N=${d.n} · `
        + `t_lo=${d.t_lo} t_hi=${d.t_hi} · `),
      band("flag", `flag ${d.counts.flag}`), document.createTextNode(" "),
      band("abstain", `abstain ${d.counts.abstain}`), document.createTextNode(" "),
      band("drop", `drop ${d.counts.drop}`),
    );
  }
  bars("chart-conformal-split", ["flag", "abstain", "drop"], [
    { label: "candidates", data: [d.counts.flag, d.counts.abstain, d.counts.drop] },
  ], { caption: "flag / abstain / drop split" });
  histChart("chart-conformal-hist", d.nonconformity_hist, "score");
}

// --- anomaly --------------------------------------------------------------------
function renderAnomaly(d) {
  if (!d.available) { showEmpty("anomaly", d.reason); return; }
  setMeta("anomaly", `flagged ${d.flagged}/${d.n} (${(d.flagged_rate * 100).toFixed(1)}%) `
    + `· threshold ${d.threshold} · unusual ≠ malicious`);
  histChart("chart-anomaly-hist", d.hist, "ECOD score");
}

// --- active learning ------------------------------------------------------------
function renderDisagreement(d) {
  if (!d.available) { showEmpty("disagreement", d.reason); return; }
  setMeta("disagreement", `N=${d.n}${d.sampled ? " (sampled for cost)" : ""}`);
  histChart("chart-disagreement-hist", d.hist, "disagreement");
  const tbody = document.querySelector("#disagreement-queue tbody");
  if (tbody) {
    tbody.replaceChildren();
    for (const row of d.queue) {
      const tr = document.createElement("tr");
      const c1 = document.createElement("td"); c1.textContent = "#" + row.candidate_id;
      const c2 = document.createElement("td"); c2.textContent = row.disagreement.toFixed(4);
      tr.append(c1, c2);
      tbody.appendChild(tr);
    }
  }
}

// --- bandit -----------------------------------------------------------------------
function renderBandit(d) {
  if (!d.available) { showEmpty("bandit", d.reason); return; }
  const xs = d.arms[0].density.x;
  line("chart-bandit-density", xs, d.arms.map((arm) => ({
    label: `${arm.context}/${arm.arm}`, data: arm.density.y,
  })), { caption: "Beta posterior density per arm" });
  const tbody = document.querySelector("#bandit-forest tbody");
  if (tbody) {
    tbody.replaceChildren();
    for (const arm of d.arms) {
      const tr = document.createElement("tr");
      for (const v of [arm.context, arm.arm, arm.mean.toFixed(3),
                       `${arm.ci_low.toFixed(3)}–${arm.ci_high.toFixed(3)}`, arm.pulls,
                       arm.mean_cost == null ? "—" : arm.mean_cost.toFixed(3)]) {
        const td = document.createElement("td");
        td.textContent = String(v);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  }
}

// --- mutation -----------------------------------------------------------------
function renderMutation(d) {
  if (!d.available) { showEmpty("mutation", d.reason); return; }
  setMeta("mutation", `${d.survived} survived · ${d.killed} killed · N=${d.n}`);
  const tbody = document.querySelector("#mutation-table tbody");
  if (tbody) {
    tbody.replaceChildren();
    for (const v of d.variants) {
      const tr = document.createElement("tr");
      for (const val of [v.id, v.vuln_class, v.variant, v.bypassed_rule || "—"]) {
        const td = document.createElement("td");
        td.textContent = val == null ? "" : String(val);
        tr.appendChild(td);
      }
      const statusTd = document.createElement("td");
      statusTd.appendChild(band(v.status));
      tr.appendChild(statusTd);
      const covTd = document.createElement("td");
      covTd.textContent = v.coverage_gain == null ? "—" : String(v.coverage_gain);
      tr.appendChild(covTd);
      tbody.appendChild(tr);
    }
  }
}

async function initMl() {
  const root = document.getElementById("panel-conformal");
  if (!root) return; // not the ML page
  let data;
  try {
    const r = await fetch("/api/ml/data");
    data = await r.json();
  } catch (e) {
    return;
  }
  const emptyBanner = document.getElementById("ml-empty");
  if (emptyBanner) emptyBanner.hidden = !!data.available_any;

  renderClassifier(data.classifier || { available: false });
  renderRanker(data.ranker || { available: false });
  renderConformal(data.conformal || { available: false });
  renderAnomaly(data.anomaly || { available: false });
  renderDisagreement(data.disagreement || { available: false });
  renderBandit(data.bandit || { available: false });
  renderMutation(data.mutation || { available: false });
}

initMl();
