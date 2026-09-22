// Launcher section (U0/CC-UI-0025): master (activity picker) → detail (one form
// shown). Every activity's detail renders server-side; with JS on we show one at
// a time and let the left list switch between them (no-JS shows all — the form
// details are simply stacked, each independently linkable via its own #id).
import { postJSON } from "/static/js/common.js";

function initLaunchNav() {
  const acts = Array.from(document.querySelectorAll(".actlist .act"));
  const details = Array.from(document.querySelectorAll(".lform-detail"));
  if (!acts.length || !details.length) return;

  function select(name) {
    let matched = false;
    for (const d of details) {
      const on = d.dataset.for === name;
      d.classList.toggle("hidden", !on);
      matched = matched || on;
    }
    for (const a of acts) a.classList.toggle("sel", a.dataset.for === name);
    return matched;
  }

  for (const a of acts) {
    a.addEventListener("click", (e) => { e.preventDefault(); select(a.dataset.for); });
  }
  // Default to `auto` when present (the full pipeline), else the first activity.
  const prefer = acts.find((a) => a.dataset.for === "auto") || acts[0];
  select(prefer.dataset.for);
}

// Read a launch form into a {dest: value} map the /api/launch* endpoints expect.
function collectValues(form) {
  const values = {};
  for (const el of form.querySelectorAll("[data-dest]")) {
    const dest = el.dataset.dest;
    if (el.dataset.type === "bool") {
      if (el.checked) values[dest] = true;
    } else if (el.dataset.multiple === "true") {
      const lines = el.value.split("\n").map((s) => s.trim()).filter(Boolean);
      if (lines.length) values[dest] = lines;
    } else if (el.value !== "" && el.value != null) {
      values[dest] =
        el.dataset.type === "int" ? parseInt(el.value, 10)
        : el.dataset.type === "float" ? parseFloat(el.value)
        : el.value;
    }
  }
  // category picker (D14): checked boxes → a comma-joined --categories value
  for (const group of form.querySelectorAll("[data-catgroup]")) {
    const checked = Array.from(group.querySelectorAll("input:checked")).map((i) => i.value);
    if (checked.length) values[group.dataset.catgroup] = checked.join(",");
  }
  return values;
}

function initLaunchForms() {
  for (const form of document.querySelectorAll("form.launch-form")) {
    const command = form.dataset.command;
    const preview = form.querySelector(".launch-preview");
    const output = form.querySelector(".launch-output");
    const runBtn = form.querySelector('[data-action="run"]');
    const stopBtn = form.querySelector('[data-action="stop"]');
    let es = null, token = null;

    form.querySelector('[data-action="dry-run"]').addEventListener("click", async () => {
      const { data } = await postJSON("/api/launch/dry-run",
        { command, values: collectValues(form) });
      preview.hidden = false;
      preview.textContent = data.display || (data.error ? "error: " + data.error : "");
    });

    if (runBtn) runBtn.addEventListener("click", async () => {
      output.hidden = false;
      output.textContent = "";
      const { status, data } = await postJSON("/api/launch",
        { command, values: collectValues(form) });
      if (status !== 200) {
        output.textContent = "error: " + (data.error || status);
        return;
      }
      token = data.token;
      stopBtn.disabled = false;
      es = new EventSource(`/api/launch/${token}/stream`);
      es.addEventListener("output", (e) => { output.textContent += e.data + "\n"; });
      es.addEventListener("done", (e) => {
        let rc = "";
        try { rc = JSON.parse(e.data).returncode; } catch (_) { /* ignore */ }
        output.textContent += `\n[exit ${rc}]`;
        es.close(); stopBtn.disabled = true;
      });
      es.addEventListener("error", () => { es.close(); stopBtn.disabled = true; });
    });

    if (stopBtn) stopBtn.addEventListener("click", async () => {
      if (token) await postJSON(`/api/launch/${token}/stop`, {});
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initLaunchNav();
  initLaunchForms();
});
