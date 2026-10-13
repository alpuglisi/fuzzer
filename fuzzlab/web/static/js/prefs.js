// No-FOUC preferences (CC-UI-0037, BUG-0064). Loaded as a classic, blocking
// <script src> in <head> so it runs before first paint. It used to be an inline
// <script>, which the app's own CSP (`script-src 'self'`, CC-UI-0026) blocks, so a
// persisted theme/density/collapsed preference was never applied on load.
/* No-FOUC: apply the persisted theme/density before first paint. Wrapped in
   try/catch so a blocked/absent localStorage never stops the page rendering.
   Runs on every full-page load under the MPA (U0) — required, since a stored
   theme/density would otherwise flash on each navigation. */
try {
  var t = localStorage.getItem("fl-theme");
  if (t) document.documentElement.setAttribute("data-theme", t);
  var d = localStorage.getItem("fl-density");
  if (d) document.documentElement.setAttribute("data-density", d);
  if (localStorage.getItem("fl-collapsed") === "1")
    document.documentElement.setAttribute("data-collapsed", "1");
} catch (e) { /* no storage — render with defaults */ }
