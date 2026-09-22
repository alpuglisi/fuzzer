// Pure-logic unit tests for the shared DataTable (U2 / R-03), run with
// node's built-in test runner (no new dependency, no build step):
//   node --test fuzzlab/web/static/js/datatable.test.mjs
// Wrapped by tests/test_datatable_js.py so `pytest` picks it up too.
//
// Only the DOM-free exports (`compareValues`, `isSafeHref`, `makeSafeLink`)
// are unit-tested here; the full filter/sort/render pipeline (createDataTable
// itself, which needs `document`) is covered in a real browser by
// tests/test_web_findings_browser.py (Playwright), matching the R-09 test
// strategy (node:test + TestClient + Playwright).

import { test } from "node:test";
import assert from "node:assert/strict";
import { compareValues, isSafeHref, makeSafeLink, DEFAULT_CAP } from "./datatable.js";

test("compareValues sorts numbers numerically, not lexicographically", () => {
  assert.equal(compareValues(2, 10) < 0, true);
  assert.equal(compareValues(10, 2) > 0, true);
  assert.equal(compareValues(5, 5), 0);
});

test("compareValues sorts strings case-insensitively", () => {
  assert.equal(compareValues("Banana", "apple") > 0, true);
  assert.equal(compareValues("apple", "apple") === 0, true);
});

test("compareValues sorts null/undefined first (stable, never throws)", () => {
  assert.equal(compareValues(null, 1) < 0, true);
  assert.equal(compareValues(1, null) > 0, true);
  assert.equal(compareValues(null, null), 0);
  assert.equal(compareValues(undefined, "x") < 0, true);
});

test("a severity rank map sorts Critical before Info via compareValues", () => {
  const rank = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const rows = ["Info", "Critical", "Low", "High", "Medium"];
  const sorted = rows.slice().sort((a, b) => compareValues(rank[a], rank[b]));
  assert.deepEqual(sorted, ["Critical", "High", "Medium", "Low", "Info"]);
});

// --- DOM-safety: isSafeHref / makeSafeLink (R-03's non-negotiable) ---------

test("isSafeHref allows http/https and relative URLs", () => {
  assert.equal(isSafeHref("http://example.com/x"), true);
  assert.equal(isSafeHref("https://example.com/x"), true);
  assert.equal(isSafeHref("/findings/1"), true);
  assert.equal(isSafeHref("findings/1"), true);
});

test("isSafeHref rejects javascript:/data:/other schemes", () => {
  assert.equal(isSafeHref("javascript:alert(1)"), false);
  assert.equal(isSafeHref("JAVASCRIPT:alert(1)"), false);
  assert.equal(isSafeHref("data:text/html,<script>alert(1)</script>"), false);
  assert.equal(isSafeHref("vbscript:msgbox(1)"), false);
  assert.equal(isSafeHref(""), false);
  assert.equal(isSafeHref(null), false);
  assert.equal(isSafeHref(undefined), false);
});

// makeSafeLink itself needs `document` (an <a> vs a fallback <span>) — its DOM
// behavior is exercised in the browser test, not here.
assert.equal(typeof makeSafeLink, "function");

test("DEFAULT_CAP is a sane finite positive number (the no-virtualization escalation lever)", () => {
  assert.equal(typeof DEFAULT_CAP, "number");
  assert.equal(DEFAULT_CAP > 0, true);
});
