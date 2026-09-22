// fuzzlab control panel — app shell: theme / density / sidebar persistence + the
// proxy status chip. Loaded on every page (base.html). Chrome only; it touches no
// invariant and does no section nav (routes are real <a href> now — U0/CC-UI-0025
// retires the old initTabs()/hash-switch client router: an MPA gets deep-linking,
// back/forward, and no-JS degradation for free from the browser). Preferences
// persist in localStorage (wrapped in try/catch: a private window or blocked
// storage must never break the page). Theme and density live on <html> so
// tokens.css resolves them; the no-FOUC <head> script applies them before first
// paint, and this only handles clicks afterwards.

function initShell() {
  const root = document.documentElement;
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (_) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (_) { /* ignore */ } },
    del(k) { try { localStorage.removeItem(k); } catch (_) { /* ignore */ } },
  };

  // theme: system (no attr) → light → dark → system
  const theme = document.getElementById("theme-toggle");
  if (theme) theme.addEventListener("click", () => {
    const cur = root.getAttribute("data-theme");
    const next = cur === "light" ? "dark" : cur === "dark" ? null : "light";
    if (next) { root.setAttribute("data-theme", next); store.set("fl-theme", next); }
    else { root.removeAttribute("data-theme"); store.del("fl-theme"); }
  });

  // density: comfortable (no attr) ↔ compact
  const density = document.getElementById("density-toggle");
  if (density) density.addEventListener("click", () => {
    if (root.getAttribute("data-density") === "compact") {
      root.removeAttribute("data-density"); store.del("fl-density");
    } else {
      root.setAttribute("data-density", "compact"); store.set("fl-density", "compact");
    }
  });

  // sidebar collapse
  const collapse = document.getElementById("sidebar-toggle");
  if (collapse) collapse.addEventListener("click", () => {
    if (root.getAttribute("data-collapsed") === "1") {
      root.removeAttribute("data-collapsed"); store.del("fl-collapsed");
    } else {
      root.setAttribute("data-collapsed", "1"); store.set("fl-collapsed", "1");
    }
  });

  // proxy status chip (topbar): a compact mirror of /api/proxy/status
  const chip = document.getElementById("proxy-chip");
  if (chip) fetch("/api/proxy/status").then((r) => r.json()).then((s) => {
    const led = chip.querySelector(".led");
    let label = "proxy off", cls = "led off";
    if (!s.configured) { label = "proxy: history only"; cls = "led off"; }
    else if (s.running) {
      label = `proxy ${s.host}:${s.port}` + (s.intercept ? " · intercept" : "");
      cls = "led on";
    } else { label = "proxy: stopped"; cls = "led warn"; }
    chip.textContent = "";
    if (led) { led.className = cls; chip.appendChild(led); }
    chip.appendChild(document.createTextNode(" " + label));
  }).catch(() => {});
}

document.addEventListener("DOMContentLoaded", initShell);
