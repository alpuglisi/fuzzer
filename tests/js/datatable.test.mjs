// Unit tests for the shared DataTable's pure sort logic (R-03; U1's minimal
// version). Run with `node --test tests/js/`. No DOM/jsdom dependency: only
// `sortRows` is exercised here, deliberately split out of the DOM-touching
// `DataTable` class for this reason (see static/js/datatable.js).
import assert from "node:assert/strict";
import { test } from "node:test";

import { sortRows } from "../../fuzzlab/web/static/js/datatable.js";

const runs = [
  { id: 3, tool: "auto", findings: 1 },
  { id: 1, tool: "crawl", findings: 0 },
  { id: 2, tool: "fuzz", findings: 5 },
];

test("sortRows ascending by a numeric key", () => {
  const sorted = sortRows(runs, (r) => r.id, 1);
  assert.deepEqual(sorted.map((r) => r.id), [1, 2, 3]);
});

test("sortRows descending by a numeric key", () => {
  const sorted = sortRows(runs, (r) => r.id, -1);
  assert.deepEqual(sorted.map((r) => r.id), [3, 2, 1]);
});

test("sortRows by a string key", () => {
  const sorted = sortRows(runs, (r) => r.tool, 1);
  assert.deepEqual(sorted.map((r) => r.tool), ["auto", "crawl", "fuzz"]);
});

test("sortRows does not mutate the input array", () => {
  const before = runs.map((r) => r.id);
  sortRows(runs, (r) => r.id, 1);
  assert.deepEqual(runs.map((r) => r.id), before);
});

test("sortRows is stable for equal keys", () => {
  const rows = [{ id: "a", k: 1 }, { id: "b", k: 1 }, { id: "c", k: 0 }];
  const sorted = sortRows(rows, (r) => r.k, 1);
  assert.deepEqual(sorted.map((r) => r.id), ["c", "a", "b"]);
});

test("sortRows handles an empty array", () => {
  assert.deepEqual(sortRows([], (r) => r.id, 1), []);
});
