"""Server-side LTTB / envelope downsampling for diagnostics chart data (U5, R-05/R-08).

Per R-05's resolved render order ("downsample server-side -> send -> EMA
client-side"), a chart's `/api/diagnostics/series/data` payload is reduced to
at most ~1000 points *before* it goes over the wire — EMA smoothing then runs
client-side (`static/js/smoothing.js`) over the already-small series, so the
smoothing slider is instant and never re-fetches.

This is a straight, dependency-free Python port of the same two algorithms
implemented for the browser in `static/js/downsample.js` (LTTB for trend
lines; per-bucket min/max envelope for the bandit posterior/regret CI band).
Keeping both is deliberate, not duplication for its own sake: the browser
copy is unit-tested via `node --test` (R-09 layer A) and doubles as the logic
a future client-side re-downsample-on-zoom would use, while this copy is what
actually shrinks the JSON response.
"""

from __future__ import annotations


def lttb(xs: list[float], ys: list[float], threshold: int) -> tuple[list[float], list[float]]:
    """Largest-Triangle-Three-Buckets downsampling. Keeps the first/last point;
    a no-op when the series already has ``threshold`` points or fewer."""
    n = len(xs)
    if threshold >= n or threshold <= 2 or n == 0:
        return list(xs), list(ys)

    out_xs = [xs[0]]
    out_ys = [ys[0]]
    bucket_size = (n - 2) / (threshold - 2)
    a = 0

    for i in range(threshold - 2):
        next_start = int((i + 1) * bucket_size) + 1
        next_end = min(int((i + 2) * bucket_size) + 1, n)
        next_count = max(1, next_end - next_start)
        avg_x = sum(xs[next_start:next_end]) / next_count
        avg_y = sum(ys[next_start:next_end]) / next_count

        range_start = int(i * bucket_size) + 1
        range_end = min(int((i + 1) * bucket_size) + 1, n)

        ax, ay = xs[a], ys[a]
        best_area, best_idx = -1.0, range_start
        for j in range(range_start, range_end):
            area = abs((ax - avg_x) * (ys[j] - ay) - (ax - xs[j]) * (avg_y - ay)) * 0.5
            if area > best_area:
                best_area, best_idx = area, j
        out_xs.append(xs[best_idx])
        out_ys.append(ys[best_idx])
        a = best_idx

    out_xs.append(xs[n - 1])
    out_ys.append(ys[n - 1])
    return out_xs, out_ys


def envelope(xs: list[float], ys: list[float],
             threshold: int) -> tuple[list[float], list[float], list[float]]:
    """Per-bucket (x, min(y), max(y)) — the CI-band mode for the bandit charts
    (R-08). A no-op when the series already has ``threshold`` points or fewer."""
    n = len(xs)
    if threshold >= n or threshold <= 0 or n == 0:
        return list(xs), list(ys), list(ys)

    out_xs: list[float] = []
    out_min: list[float] = []
    out_max: list[float] = []
    bucket_size = n / threshold
    for i in range(threshold):
        start = int(i * bucket_size)
        end = n if i == threshold - 1 else int((i + 1) * bucket_size)
        if start >= end:
            continue
        chunk = ys[start:end]
        out_xs.append(sum(xs[start:end]) / (end - start))
        out_min.append(min(chunk))
        out_max.append(max(chunk))
    return out_xs, out_min, out_max
