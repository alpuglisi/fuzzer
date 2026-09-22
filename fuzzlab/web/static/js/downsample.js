// fuzzlab control panel — pure downsampling logic (U5, per R-05/R-08/R-09).
//
// Touches no `window`/`document` at import, so this module loads unmodified in
// both Node (`node --test`, R-09 layer A) and the browser (relative-path ESM,
// no build step). Two modes, both operating on COLUMNAR data `[xs, ys]` (uPlot's
// native shape; x in unix seconds):
//
//   - `lttb(xs, ys, threshold)` — Largest-Triangle-Three-Buckets. Preserves visual
//     shape (spikes/jumps) far better than naive bucket-averaging; used for scalar
//     trend lines (training curves, coverage growth, mutation reward/novelty).
//   - `envelope(xs, ys, threshold)` — per-bucket [min, max], for the bandit
//     posterior/regret CI band (R-08's "min/max envelope mode"): shows the true
//     spread within a bucket instead of erasing it the way an average would.
//
// Both keep the series's first and last point untouched and are no-ops when the
// series already has ≤ `threshold` points, so charts with little data never lose
// precision they didn't need to give up.

export function lttb(xs, ys, threshold) {
  const n = xs.length;
  if (threshold >= n || threshold <= 2 || n === 0) {
    return [xs.slice(), ys.slice()];
  }

  const outXs = [xs[0]];
  const outYs = [ys[0]];

  // Bucket size excludes the fixed first/last points.
  const bucketSize = (n - 2) / (threshold - 2);
  let a = 0; // index of the last picked point

  for (let i = 0; i < threshold - 2; i++) {
    // Average point of the NEXT bucket (for the triangle's third vertex).
    const nextStart = Math.floor((i + 1) * bucketSize) + 1;
    const nextEnd = Math.min(Math.floor((i + 2) * bucketSize) + 1, n);
    let avgX = 0, avgY = 0;
    const nextCount = Math.max(1, nextEnd - nextStart);
    for (let j = nextStart; j < nextEnd; j++) { avgX += xs[j]; avgY += ys[j]; }
    avgX /= nextCount;
    avgY /= nextCount;

    // This bucket's range to pick the largest triangle from.
    const rangeStart = Math.floor(i * bucketSize) + 1;
    const rangeEnd = Math.min(Math.floor((i + 1) * bucketSize) + 1, n);

    const ax = xs[a], ay = ys[a];
    let bestArea = -1, bestIdx = rangeStart;
    for (let j = rangeStart; j < rangeEnd; j++) {
      const area = Math.abs(
        (ax - avgX) * (ys[j] - ay) - (ax - xs[j]) * (avgY - ay)
      ) * 0.5;
      if (area > bestArea) { bestArea = area; bestIdx = j; }
    }
    outXs.push(xs[bestIdx]);
    outYs.push(ys[bestIdx]);
    a = bestIdx;
  }

  outXs.push(xs[n - 1]);
  outYs.push(ys[n - 1]);
  return [outXs, outYs];
}

export function envelope(xs, ys, threshold) {
  const n = xs.length;
  if (threshold >= n || threshold <= 0 || n === 0) {
    return [xs.slice(), ys.slice(), ys.slice()];
  }
  const outXs = [], outMin = [], outMax = [];
  const bucketSize = n / threshold;
  for (let i = 0; i < threshold; i++) {
    const start = Math.floor(i * bucketSize);
    const end = i === threshold - 1 ? n : Math.floor((i + 1) * bucketSize);
    if (start >= end) continue;
    let mn = ys[start], mx = ys[start], sumX = 0;
    for (let j = start; j < end; j++) {
      if (ys[j] < mn) mn = ys[j];
      if (ys[j] > mx) mx = ys[j];
      sumX += xs[j];
    }
    outXs.push(sumX / (end - start));
    outMin.push(mn);
    outMax.push(mx);
  }
  return [outXs, outMin, outMax];
}
