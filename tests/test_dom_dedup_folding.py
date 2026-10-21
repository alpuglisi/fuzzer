"""DOM-template folding keeps every distinct attack surface (BUG-0547, FR-FUZZ-68).

`run_pipeline(pages_html=...)` used to keep only the points on the first URL of each
DOM-skeleton template: equal skeletons at ``/safe?q=`` and ``/admin?cmd=`` left ``q``
alone, and every page with no HTML was one empty template. A point is now folded only
when an earlier point on a page of the same template sends the same request and makes
the same observation (`core.dedup.wire_request_key`); the count and the key are
reported. The new names are imported inside the tests that use them, so every test here
runs (and fails) on the pre-fix code.
"""

import dataclasses

import pytest

from fuzzlab.audit import InjectionPoint
from fuzzlab.core.runmode import RunPlan
from fuzzlab.core.store import Store
from fuzzlab.harness.pipeline import run_pipeline
from fuzzlab.oracle.probe import Probe

H = "http://localhost"
#: One template: the pages differ in text only.
PAGE = "<html><body><h1>{t}</h1><form><input><button>go</button></form><p>x</p></body></html>"


class _Ok:
    """A target that answers every request alike (the oracle confirms nothing)."""

    def send(self, url, param, value, timing=False, **kw):
        return Probe(200, "<html><body>ok</body></html>", headers={"Server": "test"})


def _run(tmp_path, points, pages):
    plan = RunPlan("automatic", ["sql-injection"], scored=False, source="user")
    with Store(tmp_path / "fold.db") as store:
        run_id = store.start_run("pipeline", "h")
        result = run_pipeline(points, store, run_id, _Ok(), plan, pages_html=pages)
        audited = {(r["url"], r["param"], r["method"], r["location"])
                   for r in store.conn.execute(
                       "SELECT DISTINCT url, param, method, location FROM evaluation "
                       "WHERE run_id=?", (run_id,))}
        stored = {r["key"]: r["value"] for r in store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=? AND key LIKE "
            "'pipeline\\_dedup\\_%' ESCAPE '\\'", (run_id,))}
    return result, audited, stored


def _one_template(points):
    return {p.url: PAGE.format(t=f"page {i}") for i, p in enumerate(points)}


def test_a_shared_template_never_merges_two_attack_surfaces(tmp_path):
    """The audit's reproduction and its siblings: one template, six requests."""
    points = [
        InjectionPoint(f"{H}/safe?q=1", "q"),
        InjectionPoint(f"{H}/admin?cmd=ls", "cmd"),                  # another endpoint
        InjectionPoint(f"{H}/safe?q=2&lang=en", "lang"),             # another parameter
        InjectionPoint(f"{H}/safe?q=3", "q", "POST", "body"),        # another location
        InjectionPoint(f"{H}/cart/add", "item", "POST", "body",      # two forms posting
                       base_entries=(("item", "1"), ("qty", "1"))),  # to two endpoints
        InjectionPoint(f"{H}/wishlist/add", "item", "POST", "body",
                       base_entries=(("item", "1"), ("qty", "1"))),
    ]
    result, audited, _stored = _run(tmp_path, points, _one_template(points))
    assert result.points_audited == len(points)
    assert audited == {(p.url, p.param, p.method, p.location) for p in points}
    assert result.metrics["dedup_folded"] == 0


#: One field changed on the second of two otherwise-equal points on two pages of one
#: template: each is another request or another observation, so both are audited.
VARIANTS = {
    "param": {"param": "q"},
    "method": {"method": "POST"},
    "location": {"location": "body"},
    "siblings": {"base_entries": (("id", "2"), ("op", "search"))},
    "content type": {"location": "body", "param": "body",
                     "body_content_type": "application/json"},
    "sink": {"sink_context": "html"},
    "store step": {"store_url": f"{H}/comment", "store_param": "text"},
}


@pytest.mark.parametrize("change", sorted(VARIANTS))
def test_points_that_differ_in_any_request_field_both_survive(tmp_path, change):
    first = InjectionPoint(f"{H}/item?id=1", "id",
                           base_entries=None if change != "siblings" else
                           (("id", "1"), ("op", "safe")))
    second = dataclasses.replace(first, url=f"{H}/item?id=2", **VARIANTS[change])
    result, _audited, _stored = _run(tmp_path, [first, second],
                                     _one_template([first, second]))
    assert result.points_audited == 2, change
    assert result.metrics["dedup_folded"] == 0


def test_true_duplicates_fold_and_the_count_and_key_are_reported(tmp_path):
    from fuzzlab.core.dedup import FOLD_KEY
    points = [
        InjectionPoint(f"{H}/item?id=1", "id"),
        InjectionPoint(f"{H}/item?id=2", "id"),             # `id` is overwritten: one request
        InjectionPoint(f"{H}/item?id=1", "id"),             # the same point twice
        InjectionPoint(f"{H}/item?id=3&view=full", "id"),   # another sibling value: kept
    ]
    result, audited, stored = _run(tmp_path, points, _one_template(points))
    assert result.points_audited == 2
    assert audited == {(f"{H}/item?id=1", "id", "GET", "query"),
                       (f"{H}/item?id=3&view=full", "id", "GET", "query")}
    assert (result.metrics["dedup_points_in"], result.metrics["dedup_folded"],
            result.metrics["dedup_unknown_pages"]) == (4, 2, 0)
    assert result.metrics["dedup_key"] == FOLD_KEY
    assert stored == {"pipeline_dedup_points_in": 4.0, "pipeline_dedup_folded": 2.0,
                      "pipeline_dedup_unknown_pages": 0.0}


def test_absent_or_empty_html_is_unknown_never_a_duplicate(tmp_path):
    points = [
        InjectionPoint(f"{H}/a?id=1", "id"),
        InjectionPoint(f"{H}/b?x=1", "x"),       # its page is empty: no structure
        InjectionPoint(f"{H}/c?y=1", "y"),       # no page at all
        InjectionPoint(f"{H}/c?y=2", "y"),       # the same request, another unknown page
        InjectionPoint(f"{H}/c?y=1", "y"),       # the same point twice on one page: folded
    ]
    pages = {f"{H}/a?id=1": PAGE.format(t="a"), f"{H}/b?x=1": ""}
    result, audited, _stored = _run(tmp_path, points, pages)
    assert result.points_audited == 4
    assert {(u, p) for u, p, _m, _l in audited} == {
        (f"{H}/a?id=1", "id"), (f"{H}/b?x=1", "x"), (f"{H}/c?y=1", "y"),
        (f"{H}/c?y=2", "y")}
    assert (result.metrics["dedup_folded"], result.metrics["dedup_unknown_pages"]) == (1, 4)


# --- the key ---------------------------------------------------------------------------
def test_every_field_of_a_point_is_in_its_wire_request_key():
    """A guard over the dataclass, not a list: a field added later is in the key too."""
    from fuzzlab.core.dedup import wire_request_key
    base = InjectionPoint(f"{H}/item?id=1", "id")
    names = [f.name for f in dataclasses.fields(InjectionPoint) if f.name != "url"]
    assert len(names) >= 16                              # the guard sees the real fields
    same = [n for n in names if wire_request_key(dataclasses.replace(
        base, **{n: f"variant-{n}"})) == wire_request_key(base)]
    assert same == []


@pytest.mark.parametrize("other, folds", [
    (f"{H}/item?id=2", True),                  # the injected slot is overwritten
    (f"{H}/item?id=", True),
    (f"{H}/item", True),                        # absent: appended, the same request
    (f"{H}/item?id=1&x=2", False),              # another part
    (f"{H}/item?x=2&id=1", False),
    (f"{H}/other?id=1", False),                 # another path
    (f"http://localhost:81/item?id=1", False),  # another origin
    (f"https://localhost/item?id=1", False),
    (f"{H}/item?id=1#a", False),                # a fragment is kept as given
    (f"{H}/item?ID=1", False),                  # another name
])
def test_a_standalone_query_url_is_keyed_as_sent(other, folds):
    from fuzzlab.core.dedup import wire_request_key
    one = InjectionPoint(f"{H}/item?id=1", "id")
    two = dataclasses.replace(one, url=other)
    assert (wire_request_key(one) == wire_request_key(two)) is folds


def test_a_repeated_name_is_keyed_by_the_one_placements_first_occurrence():
    from fuzzlab.core.dedup import wire_request_key
    key = lambda url: wire_request_key(InjectionPoint(url, "id"))   # noqa: E731
    assert key(f"{H}/item?id=1&id=9") == key(f"{H}/item?id=2&id=9")
    assert key(f"{H}/item?id=1&id=9") != key(f"{H}/item?id=1&id=8")


@pytest.mark.parametrize("fields", [
    {"base_entries": (("id", "1"), ("op", "safe"))},   # the binder sends the form's own
    {"store_url": f"{H}/comment", "store_param": "c"},  # the URL is the observed page
    {"location": "body", "method": "POST"},
    {"location": "path"},
])
def test_only_a_standalone_query_points_slot_is_normalised(fields):
    from fuzzlab.core.dedup import wire_request_key
    one = InjectionPoint(f"{H}/item?id=1", "id", **fields)
    two = dataclasses.replace(one, url=f"{H}/item?id=2")
    assert wire_request_key(one) != wire_request_key(two)


def test_an_unhashable_value_is_never_folded():
    from fuzzlab.core.dedup import wire_request_key
    one = InjectionPoint(f"{H}/item?id=1", "id", origin=bytearray(b"x"))
    two = InjectionPoint(f"{H}/item?id=1", "id", origin=bytearray(b"x"))
    assert wire_request_key(one) != wire_request_key(two)
    assert wire_request_key(InjectionPoint(f"{H}/i", "id", base_entries=[["a", "1"]])) == \
        wire_request_key(InjectionPoint(f"{H}/i", "id", base_entries=(("a", "1"),)))
    # a URL the placement cannot parse is kept as given, never a crash of the stage
    bad = "http://[::1/item?id=1"
    assert wire_request_key(InjectionPoint(bad, "id"))[0] == ("url", bad)


def test_the_fold_key_holds_the_request_context_identity(monkeypatch):
    """SP-57 is a member of the fold key: two points the request-context identity tells
    apart are never folded, whatever their other fields (`core.reqctx.point_key`)."""
    from fuzzlab.core import reqctx
    from fuzzlab.core.dedup import fold_points, wire_request_key
    one = InjectionPoint(f"{H}/item?id=1", "id")
    assert dict(wire_request_key(one))["context"] == reqctx.point_key(one)
    contexts = iter([("rc1-a", "s1-x"), ("rc1-b", "s1-x")])
    monkeypatch.setattr(reqctx, "point_key", lambda point, identity=None: next(contexts))
    folded = fold_points([one, one], {one.url: PAGE.format(t="x")})
    assert (folded.folded, len(folded.points)) == (0, 2)
