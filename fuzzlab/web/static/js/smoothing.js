// fuzzlab control panel — pure EMA smoothing (U5, per R-05/R-09).
//
// Applied CLIENT-SIDE, after server-side downsampling (R-05: "Render order:
// downsample server-side -> send -> EMA client-side"), so the smoothing slider
// (0..0.99) is instant — it never re-fetches or re-downsamples, just re-runs this
// over the already-small in-memory series. No `window`/`document` at import, so
// it loads unmodified in Node (`node --test`) and the browser.

export function ema(ys, alpha) {
  if (!ys.length || !alpha) return ys.slice();
  const out = new Array(ys.length);
  out[0] = ys[0];
  for (let i = 1; i < ys.length; i++) {
    out[i] = alpha * out[i - 1] + (1 - alpha) * ys[i];
  }
  return out;
}
