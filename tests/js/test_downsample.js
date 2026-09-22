// node:test unit tests for the pure downsampling logic (R-09 layer A).
// Run with `node --test tests/js` (also wired into the pytest suite via
// tests/test_diagnostics.py so `pytest` alone stays the one command that
// proves everything green).
import test from "node:test";
import assert from "node:assert/strict";
import { lttb, envelope } from "../../fuzzlab/web/static/js/downsample.js";

test("lttb is a no-op under the threshold", () => {
  const xs = [1, 2, 3], ys = [10, 20, 30];
  const [oxs, oys] = lttb(xs, ys, 1000);
  assert.deepEqual(oxs, xs);
  assert.deepEqual(oys, ys);
});

test("lttb keeps the first and last point exactly", () => {
  const n = 5000;
  const xs = Array.from({ length: n }, (_, i) => i);
  const ys = Array.from({ length: n }, (_, i) => Math.sin(i / 50) + (i === 2500 ? 50 : 0));
  const [oxs, oys] = lttb(xs, ys, 200);
  assert.equal(oxs.length, 200);
  assert.equal(oys.length, 200);
  assert.equal(oxs[0], xs[0]);
  assert.equal(oys[0], ys[0]);
  assert.equal(oxs[oxs.length - 1], xs[n - 1]);
  assert.equal(oys[oys.length - 1], ys[n - 1]);
});

test("lttb preserves a sharp spike better than a naive stride sample", () => {
  const n = 2000;
  const xs = Array.from({ length: n }, (_, i) => i);
  const ys = new Array(n).fill(0);
  ys[999] = 100; // one sharp spike a naive every-Nth sample would likely miss
  const [, oys] = lttb(xs, ys, 100);
  assert.ok(oys.includes(100), "LTTB should keep the visually significant spike");
});

test("envelope returns per-bucket min/max spanning the input range", () => {
  const xs = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  const ys = [0, 5, 1, 9, 2, 8, 3, 7, 4, 6];
  const [oxs, mins, maxs] = envelope(xs, ys, 2);
  assert.equal(oxs.length, 2);
  assert.equal(mins.length, 2);
  assert.equal(maxs.length, 2);
  // every bucket's max is >= its min, and the global min/max is captured somewhere
  for (let i = 0; i < mins.length; i++) assert.ok(maxs[i] >= mins[i]);
  assert.ok(Math.min(...mins) === 0);
  assert.ok(Math.max(...maxs) === 9);
});

test("envelope is a no-op when threshold >= n", () => {
  const xs = [1, 2, 3], ys = [10, 20, 30];
  const [oxs, mins, maxs] = envelope(xs, ys, 10);
  assert.deepEqual(oxs, xs);
  assert.deepEqual(mins, ys);
  assert.deepEqual(maxs, ys);
});
