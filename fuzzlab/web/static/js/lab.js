// Lab section (CC-UI-0033): one on/off switch per lab container. The table itself is
// rendered server-side from compose.yaml; this module only (1) fills in each row's live
// state from GET /api/lab/services, and (2) wires the Start/Stop buttons to
// POST /api/lab/<service>/<action>, streaming the child labctl.sh run's output over the
// launcher's existing SSE channel, then re-reads state when it finishes. Every untrusted
// string lands via textContent, never innerHTML.
import { postJSON } from "/static/js/common.js";

const output = document.getElementById("lab-output");
const errorBox = document.getElementById("lab-error");
let busy = false;

function setRow(row, info) {
  const led = row.querySelector(".led");
  const text = row.querySelector(".lab-state-text");
  const start = row.querySelector('[data-action="start"]');
  const stop = row.querySelector('[data-action="stop"]');
  const state = info ? info.state : "unknown";
  row.dataset.state = state;
  if (led) led.className = "led " + (state === "running" ? "on" : state === "unknown" ? "off" : "warn");
  if (text) text.textContent = info && info.status ? `${state} · ${info.status}` : state;
  if (start) start.disabled = busy || state === "running" || state === "unknown";
  if (stop) stop.disabled = busy || state !== "running";
}

async function refresh() {
  let data = { services: [], error: "could not reach the panel" };
  try {
    const r = await fetch("/api/lab/services");
    data = await r.json();
  } catch (_) { /* keep the fallback error */ }
  const byName = new Map((data.services || []).map((s) => [s.name, s]));
  for (const row of document.querySelectorAll("#lab-table tbody tr")) {
    setRow(row, data.error ? null : byName.get(row.dataset.service));
  }
  errorBox.hidden = !data.error;
  errorBox.textContent = data.error ? "Lab state unavailable: " + data.error : "";
}

function setBusy(on) {
  busy = on;
  for (const row of document.querySelectorAll("#lab-table tbody tr")) {
    const info = row.dataset.state === "unknown" ? null : { state: row.dataset.state };
    setRow(row, info);
  }
  const refreshBtn = document.getElementById("lab-refresh");
  if (refreshBtn) refreshBtn.disabled = on;
}

async function control(service, action) {
  if (busy) return;
  setBusy(true);
  output.textContent = `$ labctl.sh ${action} ${service}\n`;
  const { status, data } = await postJSON(`/api/lab/${encodeURIComponent(service)}/${action}`, {});
  if (status !== 200) {
    output.textContent += "error: " + (data.error || status) + "\n";
    setBusy(false);
    return;
  }
  const es = new EventSource(`/api/launch/${data.token}/stream`);
  const finish = () => { es.close(); setBusy(false); refresh(); };
  es.addEventListener("output", (e) => { output.textContent += e.data + "\n"; });
  es.addEventListener("done", (e) => {
    let rc = "";
    try { rc = JSON.parse(e.data).returncode; } catch (_) { /* ignore */ }
    output.textContent += `[exit ${rc}]\n`;
    finish();
  });
  es.addEventListener("error", finish);
}

document.addEventListener("DOMContentLoaded", () => {
  for (const row of document.querySelectorAll("#lab-table tbody tr")) {
    for (const btn of row.querySelectorAll("[data-action]")) {
      btn.addEventListener("click", () => control(row.dataset.service, btn.dataset.action));
    }
  }
  const refreshBtn = document.getElementById("lab-refresh");
  if (refreshBtn) refreshBtn.addEventListener("click", refresh);
  refresh();
});
