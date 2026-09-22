// node:test unit tests for the pure EMA smoothing logic (R-09 layer A).
import test from "node:test";
import assert from "node:assert/strict";
import { ema } from "../../fuzzlab/web/static/js/smoothing.js";

test("ema with alpha=0 returns the series unchanged", () => {
  const ys = [1, 2, 3, 4];
  assert.deepEqual(ema(ys, 0), ys);
});

test("ema smooths out a single spike more as alpha rises", () => {
  const ys = [1, 1, 1, 100, 1, 1, 1];
  const light = ema(ys, 0.2);
  const heavy = ema(ys, 0.9);
  // heavier smoothing keeps the post-spike value closer to the pre-spike baseline
  assert.ok(heavy[4] < light[4]);
});

test("ema keeps the first point exactly (no look-ahead)", () => {
  const ys = [5, 10, 15];
  assert.equal(ema(ys, 0.99)[0], 5);
});

test("ema on an empty series returns an empty array", () => {
  assert.deepEqual(ema([], 0.5), []);
});
