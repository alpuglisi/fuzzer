// Pure-JS unit tests for downsample.js (R-09 layer A: node:test, built into Node —
// no new dependency). Run with `node --test fuzzlab/web/static/js/downsample.test.js`.

import assert from "node:assert/strict";
import { test } from "node:test";

import { envelopeBuckets, lttb } from "./downsample.js";

function range(n) {
  return Array.from({ length: n }, (_, i) => i);
}

test("lttb leaves a series at/under the threshold unchanged", () => {
  const xs = range(10), ys = range(10).map((x) => x * 2);
  const out = lttb(xs, ys, 10);
  assert.deepEqual(out.xs, xs);
  assert.deepEqual(out.ys, ys);
  const out2 = lttb(xs, ys, 50);
  assert.deepEqual(out2.xs, xs);
});

test("lttb reduces a long series to exactly the threshold count", () => {
  const n = 5000;
  const xs = range(n);
  const ys = xs.map((x) => Math.sin(x / 37) + (x % 200 === 0 ? 5 : 0)); // spikes
  const out = lttb(xs, ys, 1000);
  assert.equal(out.xs.length, 1000);
  assert.equal(out.ys.length, 1000);
});

test("lttb always keeps the first and last point", () => {
  const xs = range(2000);
  const ys = xs.map((x) => Math.random());
  const out = lttb(xs, ys, 500);
  assert.equal(out.xs[0], xs[0]);
  assert.equal(out.ys[0], ys[0]);
  assert.equal(out.xs[out.xs.length - 1], xs[xs.length - 1]);
  assert.equal(out.ys[out.ys.length - 1], ys[ys.length - 1]);
});

test("lttb output x is monotonically non-decreasing (order preserved)", () => {
  const xs = range(3000);
  const ys = xs.map((x) => Math.cos(x / 11));
  const out = lttb(xs, ys, 300);
  for (let i = 1; i < out.xs.length; i++) {
    assert.ok(out.xs[i] > out.xs[i - 1], `x not increasing at ${i}`);
  }
});

test("lttb preserves an isolated spike a naive stride would skip", () => {
  const n = 10000;
  const xs = range(n);
  const ys = new Array(n).fill(0);
  ys[4242] = 1000; // a single-point spike far from any stride multiple of ~10
  const out = lttb(xs, ys, 1000);
  assert.ok(Math.max(...out.ys) >= 900, "the spike should survive downsampling");
});

test("envelopeBuckets: min <= max in every bucket, and buckets cover the range", () => {
  const xs = range(1000);
  const ys = xs.map((x) => Math.sin(x / 13) * 10);
  const out = envelopeBuckets(xs, ys, 50);
  assert.equal(out.xs.length, 50);
  for (let i = 0; i < out.xs.length; i++) {
    assert.ok(out.min[i] <= out.max[i]);
  }
});

test("envelopeBuckets returns every point verbatim when buckets >= n", () => {
  const xs = range(20), ys = xs.map((x) => x * 3);
  const out = envelopeBuckets(xs, ys, 100);
  assert.deepEqual(out.xs, xs);
  assert.deepEqual(out.min, ys);
  assert.deepEqual(out.max, ys);
});

test("envelopeBuckets on empty input yields empty arrays", () => {
  const out = envelopeBuckets([], [], 10);
  assert.deepEqual(out, { xs: [], min: [], max: [] });
});
