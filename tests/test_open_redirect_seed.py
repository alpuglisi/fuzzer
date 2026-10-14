"""BUG-0124: an allowlist-gated open redirect (Juice Shop's ``/redirect?to=``) was never
detected.

Two defects: the open-redirect rule selected parameters by name only (``to`` is not in
it), and the confirmer sent one plain canary, which an allowlist checking *containment*
refuses. Now a URL-shaped crawled value implies the open-redirect and SSRF categories
(PA-0124's table), and the confirmer may send one more canary embedding the crawled
URL's ``scheme://host/path`` (the operator-approved, stated FR-AUD-20 exception,
FR-AUD-21) -- only after the plain one failed.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from fuzzlab.audit import load_rules
from fuzzlab.audit import value_shape as vs
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import OpenRedirectStrategy
from tests.test_forms_phase2 import _App, _import

ROOT = Path(__file__).resolve().parents[1]
GITHUB = "https://github.com/juice-shop/juice-shop"


# --- PA-0124: every shape maps to its categories, in one table -----------------------
def test_every_shape_has_a_row_and_the_rules_match_the_table():
    assert set(vs.SHAPE_CATEGORIES) == set(vs.SHAPES)
    pairs = set()
    for rule in load_rules():
        for shape in rule.when.get("value_shape_in", ()):
            pairs.add((shape, rule.category))
    table = {(s, c) for s, cats in vs.SHAPE_CATEGORIES.items() for c in cats}
    assert pairs == table
    assert not pairs & set(vs.SHAPE_EXCLUSIONS)          # excluded pairs never fire


# --- the seed ----------------------------------------------------------------------
@pytest.mark.parametrize("example,seed", [
    (GITHUB, GITHUB),
    ("https://GitHub.com:443/Juice-Shop/", "https://GitHub.com:443/Juice-Shop/"),  # exact
    ("http://h.example/a/b?token=abc#frag", "http://h.example/a/b"),     # query cut
    ("https://user:pw@h.example/a", "https://h.example/a"),             # userinfo cut
    ("ftp://h.example/file", None),                                      # http(s) only
    ("file:///etc/passwd", None),
    ("https://idp.example/cb/9f86d081884c7d659a2feaa0c55ad015", None),  # a path token
    ("https://explorer.example/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm", None),
    ("//github.com/x", None),                     # protocol-relative: a stated gap
    ("robots.txt", None),
    (None, None),
])
def test_redirect_seed(example, seed):
    assert vs.redirect_seed(example) == seed


# --- the strategy against fake apps ---------------------------------------------------
class _Redirector:
    """``allow(value)`` decides; True answers 302 Location: value, else 406."""

    def __init__(self, allow, location=None):
        self.allow, self.location, self.sent = allow, location, []

    def send(self, url, param, value, timing=False, **kw):
        self.sent.append(value)
        if self.allow(value):
            return Probe(302, "", headers={"Location": (self.location or (lambda v: v))(value)})
        return Probe(406, "not allowed")


def _cand(seed=GITHUB):
    return Candidate(url="http://127.0.0.1:3000/redirect", param="to",
                     category="open-redirect", redirect_seed=seed)


def test_an_unconditional_redirect_confirms_on_the_plain_canary_seed_unsent():
    app = _Redirector(lambda v: True)
    verdict = OpenRedirectStrategy().confirm(_cand(), app)
    assert verdict and verdict.confirmed and "variant" not in verdict.evidence
    assert len(app.sent) == 1 and "github" not in app.sent[0]


def test_a_containment_allowlist_confirms_on_the_seeded_canary():
    app = _Redirector(lambda v: GITHUB in v)
    verdict = OpenRedirectStrategy().confirm(_cand(), app)
    assert verdict and verdict.confirmed
    assert verdict.evidence["variant"] == "allowlist-containment"
    plain, seeded = app.sent
    assert "github" not in plain
    assert seeded.startswith("https://oracle") and seeded.endswith(f"/cb?fzlb={GITHUB}")


def test_an_exact_match_allowlist_is_not_confirmed():
    app = _Redirector(lambda v: v == GITHUB)
    assert OpenRedirectStrategy().confirm(_cand(), app) is None


def test_no_seed_means_one_probe_only():
    app = _Redirector(lambda v: GITHUB in v)
    assert OpenRedirectStrategy().confirm(_cand(seed=None), app) is None
    assert len(app.sent) == 1


@pytest.mark.parametrize("location,confirmed", [
    (lambda v: f"{GITHUB}?next={v}", False),                 # the seed's host leads
    (lambda v: f"/login?next={v}", False),                   # relative, our host in query
    (lambda v: v.replace("https://", "//"), True),           # scheme-relative, http target
    (lambda v: v.replace("https://", "http://"), True),      # downgraded: still ours
    (lambda v: "javascript:alert(1)//" + v, False),
    (lambda v: "data:text/html," + v, False),
    (lambda v: v.replace("/cb", "/other"), False),
    (lambda v: v.replace("/cb", "/cb/"), True),                  # normalised by the app
    (lambda v: "https://other.example/cb", False),              # /cb, not our host
    (lambda v: v.replace("https://", "ftp://"), False),         # our host, not http(s)
])
def test_confirmation_is_by_host_never_by_prefix(location, confirmed):
    app = _Redirector(lambda v: GITHUB in v, location=location)
    verdict = OpenRedirectStrategy().confirm(_cand(), app)
    assert (verdict is not None) is confirmed


def test_a_meta_refresh_to_the_canary_confirms():
    class Meta(_Redirector):
        def send(self, url, param, value, timing=False, **kw):
            self.sent.append(value)
            return Probe(200, f"<meta http-equiv=refresh content='0;url={value}'>")
    assert OpenRedirectStrategy().confirm(_cand(), Meta(lambda v: True)).confirmed


# --- end to end: a crawled link, the rules, the seed, the oracle -----------------------
def _juice_like(exact=False):
    def handler(req):
        if req["path"].endswith("/redirect") and "to" in req["query"]:
            value = req["query"]["to"]
            ok = value == GITHUB if exact else GITHUB in value
            if ok:
                return Probe(302, "", headers={"Location": value})
            return Probe(406, "Unrecognized target URL for redirect")
        return Probe(200, "<html>ok</html>")
    return _App(handler)


@pytest.mark.parametrize("exact", [False, True])
def test_a_url_valued_link_parameter_is_found_whatever_its_name(tmp_path, exact):
    from fuzzlab.harness.auto import run_auto
    store, run, _c = _import(tmp_path, pages=[f"http://h/app/redirect?to={GITHUB}"])
    app = _juice_like(exact)
    with store:
        run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                 mode="manual", selected_categories=["open-redirect", "ssrf"],
                 points_source="crawl")
        found = {(r["param"], r["vuln_class"]) for r in store.conn.execute(
            "SELECT param, vuln_class FROM finding WHERE run_id=?", (run,))}
        rules = {json.loads(r["evidence"])["rule_id"] for r in store.conn.execute(
            "SELECT evidence FROM candidate WHERE run_id=?", (run,))}
        seeds = [json.loads(r["evidence"]).get("redirect_seed") for r in store.conn.execute(
            "SELECT evidence FROM candidate WHERE run_id=?", (run,))]
    assert {"R-OPEN-REDIRECT-VALUE", "R-SSRF-VALUE"} <= rules
    assert (("to", "open_redirect") in found) is (not exact)
    # FR-AUD-21: the seed is in open-redirect evidence only
    assert [s for s in seeds if s] == [GITHUB]
    # the crawled host is sent only inside our .example canary's query, by the
    # open-redirect retry; never as a request host, never by another category
    for req in app.requests:
        value = req["value"] or ""
        if "github.com" in json.dumps(req):
            assert req["param"] == "to" and value.startswith("https://oracle")
            assert value.split("/cb?fzlb=", 1)[1] == GITHUB
    assert sum("github.com" in r["value"] for r in app.requests) == 1


def test_a_seed_never_reaches_another_categorys_evidence(tmp_path):
    from fuzzlab.audit import InjectionPoint, evaluate
    from fuzzlab.core.store import Store
    store = Store(tmp_path / "u.db")
    run = store.start_run("auto", "h")
    point = InjectionPoint(url="http://h/r", param="to", origin="crawl",
                           value_shapes=frozenset({"url"}), redirect_seed=GITHUB)
    with store:
        evaluate([point], store, run)
        rows = [json.loads(r["evidence"]) for r in store.conn.execute(
            "SELECT evidence FROM candidate WHERE run_id=?", (run,))]
    assert {r["category"] for r in rows} >= {"open-redirect", "ssrf"}
    for r in rows:
        assert ("redirect_seed" in r) is (r["category"] == "open-redirect")


# --- the exception stays narrow: where `redirect_seed` may appear ---------------------
_ALLOWED = {
    ("audit/engine.py", "InjectionPoint"), ("audit/engine.py", "evaluate"),
    ("harness/auto.py", "injection_points_from_store"),
    ("harness/pipeline.py", "_candidate_of"),
    ("oracle/probe.py", "Candidate"),
    ("oracle/strategies.py", "OpenRedirectStrategy"),
}


def _seed_sites(root: Path) -> set[tuple[str, str]]:
    """(file, enclosing top-level def/class) of every `redirect_seed` name, attribute,
    keyword or string key in product code (the seed builder itself excepted)."""
    sites = set()
    for path in sorted(root.rglob("*.py")):
        rel = str(path.relative_to(root))
        tree = ast.parse(path.read_text(), filename=str(path))
        for top in tree.body:
            if isinstance(top, ast.FunctionDef) and top.name == "redirect_seed":
                continue
            for node in ast.walk(top):
                hit = ((isinstance(node, ast.Attribute) and node.attr == "redirect_seed")
                       or (isinstance(node, ast.Name) and node.id == "redirect_seed"
                           and not isinstance(top, ast.ImportFrom))
                       or (isinstance(node, ast.keyword) and node.arg == "redirect_seed")
                       or (isinstance(node, ast.Constant) and node.value == "redirect_seed"))
                if hit:
                    sites.add((rel, getattr(top, "name", type(top).__name__)))
    return sites


def test_redirect_seed_is_read_and_written_only_where_allowed():
    sites = _seed_sites(ROOT / "fuzzlab")
    assert sites <= _ALLOWED, sites - _ALLOWED
    assert ("oracle/strategies.py", "OpenRedirectStrategy") in sites


def test_the_seed_guard_catches_a_synthetic_offender(tmp_path):
    (tmp_path / "audit").mkdir()
    (tmp_path / "audit" / "engine.py").write_text(
        "def evaluate(point, evidence):\n"
        "    evidence['redirect_seed'] = point.redirect_seed\n"
        "def other_writer(point, evidence):\n"
        "    evidence['redirect_seed'] = point.redirect_seed\n")
    assert _seed_sites(tmp_path) - _ALLOWED == {("audit/engine.py", "other_writer")}


def test_the_engine_gates_the_evidence_write_on_the_open_redirect_category():
    """A write outside the category gate is the offender PA-0124's guard must catch."""
    src = (ROOT / "fuzzlab" / "audit" / "engine.py").read_text()
    tree = ast.parse(src)
    writes = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                      and t.slice.value == "redirect_seed" for t in n.targets)]
    assert len(writes) == 1
    gate = [n for n in ast.walk(tree) if isinstance(n, ast.If)
            and writes[0] in n.body and "open-redirect" in ast.unparse(n.test)]
    assert gate, "the redirect_seed evidence write is not gated on open-redirect"
