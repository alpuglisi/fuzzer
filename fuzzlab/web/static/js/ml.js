// ML section (U4/CC-UI-0031, CC-ML-0010) — read-only, advisory (R-06). Fetches
// /api/ml/data (all runs, or one run picked in #ml-run — CC-UI-0043) and renders every
// panel from it; nothing here writes to the store, and nothing here ever calls a score
// a "finding" or "vulnerable" (verb hygiene: scored/ranked/flagged only).
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

// --- trained on earlier runs (CC-UI-0040) ------------------------------------------
// An earlier-trained model's OOF numbers are on the earlier runs; its forward numbers
// grade this run's scores against this run's own labels; seen = this run's candidates
// whose endpoint/param/category the model trained on (not out-of-sample when high).
function earlierNote(o, fmt) {
  if (!o || o.scope !== "earlier runs") return "";
  const fwd = o.forward ? ` · forward ${fmt(o.forward)}`
    : ` · no forward evaluation (${o.forward_skipped_reason || "not recorded"})`;
  const seen = o.seen_fraction != null
    ? ` · ${Math.round(o.seen_fraction * 100)}% of this run's candidates seen in training` : "";
  return fwd + seen;
}

// --- classifier + calibration ---------------------------------------------------
// CC-UI-0045: the classifier's probability calibration (FR-ML-20) — out-of-fold ECE raw
// vs cross-fitted calibrated, or why it was left uncalibrated. Text only.
function calibrationNote(c) {
  if (!c) return "";
  if (c.calibrator !== "platt") return ` · calibration: ${c.calibrator}`;
  return ` · Platt-calibrated: out-of-fold ECE ${c.ece_oof_raw} raw → `
    + `${c.ece_oof_calibrated} cross-fitted`;
}

function renderClassifier(d) {
  if (!d.available) { showEmpty("calibration", d.reason); return; }
  // Metrics recomputed from stored scores are in-sample (the deploy fit scored its own
  // training rows); the honest number is the scoring model's own out-of-fold PR-AUC.
  const oof = d.oof
    ? ` · out-of-fold PR-AUC ${d.oof.pr_auc.toFixed(3)} on ${d.oof.scope || "this run"}`
      + (d.oof.pr_auc_prevalence != null
        ? ` (prevalence ${d.oof.pr_auc_prevalence.toFixed(3)})` : "")
      + earlierNote(d.oof, (f) => `PR-AUC ${(f.pr_auc ?? 0).toFixed(3)}`
        + (f.pr_auc_prevalence != null ? ` (prevalence ${f.pr_auc_prevalence.toFixed(3)})` : ""))
    : "";
  setMeta("calibration", `${d.evaluation} PR-AUC ${d.pr_auc.toFixed(3)} (baseline prevalence `
    + `${d.baseline_prevalence.toFixed(3)})${oof} · N=${d.n} (${d.positives} confirmed) `
    + `· ECE ${d.reliability.ece.toFixed(3)}` + calibrationNote(d.calibration));
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

// --- saved logistic coefficients (CC-UI-0038) ------------------------------------
function renderWeights(d) {
  if (!d.available) { showEmpty("weights", d.reason); return; }
  const sha = d.model.params_sha256 ? ` · sha ${d.model.params_sha256.slice(0, 12)}` : "";
  setMeta("weights", `${d.model.name} v${d.model.version}${sha} · bias `
    + `${d.bias.toFixed(3)} (standardised space) · ${d.note}`);
  bars("chart-weights", d.weights.map((w) => w.feature),
    [{ label: "coefficient", data: d.weights.map((w) => w.weight) }],
    { caption: "Standardised logistic coefficients (log-odds per SD)" });
}

// --- ranker -----------------------------------------------------------------------
function renderRanker(d) {
  if (!d.available) { showEmpty("ranker", d.reason); return; }
  // In-sample (deploy fit) vs the ranker's own out-of-fold numbers, at its training k.
  const oof = d.oof
    ? ` · out-of-fold nDCG@${d.oof.at_k} ${d.oof.ndcg.toFixed(3)} on ${d.oof.scope || "this run"}`
      + (d.oof.ndcg_random != null ? ` (random ${d.oof.ndcg_random.toFixed(3)})` : "")
      + earlierNote(d.oof, (f) => `nDCG@${d.oof.at_k} ${(f.ndcg ?? 0).toFixed(3)}`
        + (f.ndcg_random != null ? ` (random ${f.ndcg_random.toFixed(3)})` : ""))
    : "";
  setMeta("ranker", `${d.evaluation} nDCG@${d.k} ${d.ndcg_at_k.toFixed(3)} · precision@${d.k} `
    + `${d.precision_at_k.toFixed(3)} (random baseline ${d.random_baseline_precision_at_k.toFixed(3)})`
    + `${oof} · N=${d.n}`);
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
        // null = a "never drops / never flags" threshold (BUG-0070), explained in notes
        + `t_lo=${d.t_lo ?? "never"} t_hi=${d.t_hi ?? "never"}`
        + (d.per_run_gates ? " (each run gated by its own model)" : "") + " · "),
      band("flag", `flag ${d.counts.flag}`), document.createTextNode(" "),
      band("abstain", `abstain ${d.counts.abstain}`), document.createTextNode(" "),
      band("drop", `drop ${d.counts.drop}`),
      // BUG-0067: rows with no score the gate was calibrated for are not decided
      document.createTextNode(d.counts["n/a"] ? ` · n/a ${d.counts["n/a"]} (in-sample score)` : ""),
      document.createTextNode((d.notes || []).map((n) => ` · ${n}`).join("")),
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
  setMeta("anomaly", `flagged ${d.flagged}/${d.n} (${(d.flagged_rate * 100).toFixed(1)}%, `
    + `at most ${d.flag_budget}) · threshold ${d.threshold ?? "—"}`
    + (d.reason ? ` · ${d.reason}` : "") + " · unusual ≠ malicious");
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

// Every panel the payload fills, by its DOM id (`#panel-<id>`) and payload key.
const PANELS = [
  ["calibration", "classifier", () => renderClassifier], ["weights", "weights", () => renderWeights],
  ["ranker", "ranker", () => renderRanker], ["conformal", "conformal", () => renderConformal],
  ["anomaly", "anomaly", () => renderAnomaly], ["disagreement", "disagreement", () => renderDisagreement],
  ["bandit", "bandit", () => renderBandit], ["mutation", "mutation", () => renderMutation],
];

// Back to a blank panel before every render, so switching runs never leaves an old chart
// under a "no data" message or a stale message over a new chart (CC-UI-0043).
function resetPanel(panelId) {
  const panel = document.getElementById(`panel-${panelId}`);
  if (!panel) return;
  const empty = panel.querySelector('[data-field="empty"]');
  if (empty) { empty.hidden = true; empty.textContent = ""; }
  panel.querySelectorAll('[data-field="summary"]').forEach((p) => p.replaceChildren());
  panel.querySelectorAll(".ml-chart").forEach((mount) => {
    const handle = window.__charts && window.__charts.get(mount.id);
    if (handle) handle.destroy();
    mount.replaceChildren();
    mount.removeAttribute("aria-label");
  });
  panel.querySelectorAll("tbody").forEach((t) => t.replaceChildren());
}

function render(data) {
  const emptyBanner = document.getElementById("ml-empty");
  if (emptyBanner) emptyBanner.hidden = !!data.available_any;
  for (const [panelId, key, renderer] of PANELS) {
    resetPanel(panelId);
    renderSafely(panelId, renderer(), data[key]);
  }
}

// A positive integer `?run=` value, else "" (all runs). Anything else is ignored.
function runFromUrl() {
  const v = new URLSearchParams(window.location.search).get("run") || "";
  return /^[1-9][0-9]*$/.test(v) ? v : "";
}

let loadSeq = 0;
let inflight = null;

// Only the latest choice may render: an older response arriving last is dropped, and
// the in-flight request is aborted on every new choice.
async function load(runId) {
  const mine = ++loadSeq;
  if (inflight) inflight.abort();
  inflight = new AbortController();
  let data;
  try {
    const r = await fetch("/api/ml/data" + (runId ? `?run_id=${encodeURIComponent(runId)}` : ""),
                          { signal: inflight.signal });
    data = await r.json();
  } catch (e) {
    return;
  }
  if (mine !== loadSeq) return;
  render(data);
}

async function fillRuns(select) {
  try {
    const r = await fetch("/api/runs");
    const { runs } = await r.json();
    for (const run of runs || []) {
      const label = `#${run.id} ${run.tool || ""} ${run.started_at || ""}`
        + (run.candidates ? "" : " (no candidates)");
      const opt = new Option(label, String(run.id));       // text only, never markup
      opt.disabled = !run.candidates;
      select.add(opt);
    }
  } catch (e) {
    // the picker stays at "All runs"
  }
}

async function initMl() {
  const root = document.getElementById("panel-conformal");
  if (!root) return; // not the ML page
  const select = document.getElementById("ml-run");
  if (!select) { load(""); return; }
  await fillRuns(select);
  const want = runFromUrl();
  const known = want && [...select.options].some((o) => o.value === want && !o.disabled);
  select.value = known ? want : "";
  if (want && !known) window.history.replaceState(null, "", window.location.pathname);
  select.addEventListener("change", () => {
    const v = select.value;
    window.history.replaceState(null, "", v ? `?run=${v}` : window.location.pathname);
    load(v);
  });
  load(select.value);
}

// One panel's failure must not blank every later panel (BUG-0063: a throw in the first
// chart used to abort the whole render chain). The error still reaches the console.
function renderSafely(panelId, render, payload) {
  try {
    render(payload || { available: false });
  } catch (e) {
    console.error(`ml: could not render panel "${panelId}"`, e);
    showEmpty(panelId, "Could not render this panel (see the browser console).");
  }
}

initMl();
