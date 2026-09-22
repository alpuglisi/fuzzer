// fuzzlab control panel — pure downsampling helpers (U4/U5; R-05/R-12).
//
// Kept dependency-free and DOM-free (no `window`/`document` at import) so the exact
// same module loads under `node --test` (unit tests) and in the browser (charts.js),
// per the R-09 test strategy. Two algorithms:
//
//   - `lttb` (Largest-Triangle-Three-Buckets): picks a representative subset of a
//     single (x, y) series that preserves visual shape — spikes and turning points
//     survive where a naive stride/average would flatten them. Used for long
//     intra-run step series (bandit regret, mutation reward/novelty, training loss)
//     before handing them to uPlot (~1000 pts/series, per the plan's read-side
//     downsampling note).
//   - `envelopeBuckets`: a simpler min/max-per-bucket reduction for CI-band-style
//     series (e.g. a posterior-mean series someone wants to show with its bucketed
//     range) — trivially correct, no shape heuristic needed for a band.

/**
 * Largest-Triangle-Three-Buckets downsampling of one (xs, ys) series.
 *
 * Always keeps the first and last point. Returns `{xs, ys}` unchanged (by reference)
 * when already at or under `threshold` points, or `threshold` < 3 (nothing sensible
 * to bucket).
 */
export function lttb(xs, ys, threshold) {
  const n = xs.length;
  if (threshold >= n || threshold < 3 || n < 3) {
    return { xs: xs.slice(), ys: ys.slice() };
  }
  const outXs = [xs[0]];
  const outYs = [ys[0]];
  // Fixed-size buckets over the interior points (endpoints are handled separately).
  const bucketSize = (n - 2) / (threshold - 2);
  let a = 0; // index of the previously-selected point
  for (let i = 0; i < threshold - 2; i++) {
    const bucketStart = Math.floor((i + 0) * bucketSize) + 1;
    const bucketEnd = Math.floor((i + 1) * bucketSize) + 1;
    const nextStart = Math.floor((i + 1) * bucketSize) + 1;
    const nextEnd = Math.floor((i + 2) * bucketSize) + 1;
    // Average point of the NEXT bucket, used as one triangle vertex.
    let avgX = 0, avgY = 0;
    const nStart = Math.min(nextStart, n - 1);
    const nEnd = Math.min(nextEnd, n);
    const nCount = Math.max(1, nEnd - nStart);
    for (let j = nStart; j < nEnd; j++) { avgX += xs[j]; avgY += ys[j]; }
    avgX /= nCount; avgY /= nCount;

    const ax = xs[a], ay = ys[a];
    let maxArea = -1, chosen = bucketStart;
    const bStart = Math.max(bucketStart, 0);
    const bEnd = Math.min(bucketEnd, n);
    for (let j = bStart; j < bEnd; j++) {
      const area = Math.abs((ax - avgX) * (ys[j] - ay) - (ax - xs[j]) * (avgY - ay));
      if (area > maxArea) { maxArea = area; chosen = j; }
    }
    outXs.push(xs[chosen]);
    outYs.push(ys[chosen]);
    a = chosen;
  }
  outXs.push(xs[n - 1]);
  outYs.push(ys[n - 1]);
  return { xs: outXs, ys: outYs };
}

/**
 * Min/max-per-bucket reduction of one (xs, ys) series into `buckets` buckets, for a
 * CI-band-style display. Returns `{xs, min, max}` (bucket-representative x = the
 * bucket's first x). Empty input yields empty arrays; `buckets` <= 0 or >= n returns
 * every point as its own bucket (min === max === ys[i]).
 */
export function envelopeBuckets(xs, ys, buckets) {
  const n = xs.length;
  if (n === 0) return { xs: [], min: [], max: [] };
  if (buckets <= 0 || buckets >= n) {
    return { xs: xs.slice(), min: ys.slice(), max: ys.slice() };
  }
  const size = n / buckets;
  const outXs = [], outMin = [], outMax = [];
  for (let i = 0; i < buckets; i++) {
    const start = Math.floor(i * size);
    const end = Math.min(n, Math.floor((i + 1) * size));
    if (start >= end) continue;
    let lo = Infinity, hi = -Infinity;
    for (let j = start; j < end; j++) {
      if (ys[j] < lo) lo = ys[j];
      if (ys[j] > hi) hi = ys[j];
    }
    outXs.push(xs[start]);
    outMin.push(lo);
    outMax.push(hi);
  }
  return { xs: outXs, min: outMin, max: outMax };
}
