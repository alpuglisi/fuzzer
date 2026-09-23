"""Tests for the deterministic, class-pluggable oracle (Phase 2 T2.1/T2.2/T2.4)."""

import html as html_lib
import re

from fuzzlab.core.store import Store
from fuzzlab.oracle import Candidate, Oracle
from fuzzlab.oracle.baseline import build_baseline, median_abs_deviation
from fuzzlab.oracle.context import breakout_for, is_unescaped, type_reflection
from fuzzlab.oracle.probe import Probe
from fuzzlab.oracle.strategies import (
    ReflectedXssStrategy, SqliBooleanStrategy, SqliErrorStrategy, SqliTimingStrategy,
)


# --- fake senders ------------------------------------------------------------
class TimingSender:
    def __init__(self, honor_sleep=True):
        self.honor = honor_sleep

    def send(self, url, param, value, timing=False):
        m = re.search(r"SLEEP\((\d+)\)", value, re.I)
        d = float(m.group(1)) if (m and self.honor) else 0.0
        return Probe(200, "ok", elapsed=d + 0.05)


class ErrorSender:
    def send(self, url, param, value, timing=False):
        if "'" in value or '"' in value:
            return Probe(500, "Error: You have an error in your SQL syntax; check ...")
        return Probe(200, "normal page")


class BooleanSender:
    """Injectable blind: true condition -> post; false -> not found."""
    POST = "the blog post body is here and it is reasonably long"

    def send(self, url, param, value, timing=False):
        if "1=2" in value:
            return Probe(200, "post not found")
        return Probe(200, self.POST)          # benign and 1=1 both render the post


class SecureIntSender:
    """Prepared/int-cast: only a bare int renders; anything else -> not found."""
    def send(self, url, param, value, timing=False):
        return Probe(200, "the blog post body") if value.strip() == "1" else Probe(200, "not found")


class XssEchoSender:
    def __init__(self, escape=False):
        self.escape = escape

    def send(self, url, param, value, timing=False):
        v = html_lib.escape(value) if self.escape else value
        return Probe(200, f"<html><body><p>Results for {v}</p></body></html>")


# --- baseline (T2.2) ---------------------------------------------------------
def test_median_mad_resists_outliers():
    base = build_baseline([1.0, 1.0, 1.0, 1.0, 9.0])
    assert base.median == 1.0
    assert base.mad == 0.0                      # the 9.0 outlier does not move MAD
    assert base.exceeds(9.0, floor=0.5)
    assert not base.exceeds(1.2, floor=0.5)
    assert median_abs_deviation([1, 1, 5]) == 0.0


# --- context typing (T2.4) ---------------------------------------------------
def test_type_reflection_contexts():
    assert type_reflection("<p>hello MARK there</p>", "MARK") == "html"
    assert type_reflection('<input value="MARK">', "MARK") == "html-attribute"
    assert type_reflection('<a href="MARK">x</a>', "MARK") == "url-attribute"
    assert type_reflection("<script>var x='MARK';</script>", "MARK") == "js"
    assert type_reflection("<p>nothing</p>", "MARK") == "none"


def test_is_unescaped_and_breakout():
    frag, sig = breakout_for("html", "TOK")
    assert frag == "<TOK>" and sig == "<TOK>"
    assert is_unescaped("<html><TOK></html>", "<TOK>")
    assert not is_unescaped("<html>&lt;TOK&gt;</html>", "<TOK>")


# --- SQLi mechanisms (M1/M2/M3) ---------------------------------------------
def _sqli(vuln_class=None):
    return Candidate(url="http://localhost/x.php", param="id", vuln_class=vuln_class)


def test_error_signature_confirms_and_fails_closed():
    v = SqliErrorStrategy().confirm(_sqli(), ErrorSender())
    assert v and v.confirmed and v.mechanism == "error-signature" and v.evidence["dbms"] == "MySQL"
    # benign-only responses -> no confirmation
    class Benign:
        def send(self, u, p, val, timing=False):
            return Probe(200, "normal page")
    assert SqliErrorStrategy().confirm(_sqli(), Benign()) is None


def test_boolean_confirms_and_fails_closed_on_secure():
    v = SqliBooleanStrategy().confirm(_sqli(), BooleanSender())
    assert v and v.confirmed and v.mechanism == "boolean-differential"
    assert SqliBooleanStrategy().confirm(_sqli(), SecureIntSender()) is None


def test_timing_confirms_and_fails_closed():
    v = SqliTimingStrategy().confirm(_sqli(), TimingSender(honor_sleep=True))
    assert v and v.confirmed and v.mechanism == "differential-timing"
    assert v.evidence["measured"]["4"] > v.evidence["measured"]["2"]     # rising delay
    assert SqliTimingStrategy().confirm(_sqli(), TimingSender(honor_sleep=False)) is None


# --- reflected XSS (M5) ------------------------------------------------------
def test_reflected_xss_confirms_and_fails_closed_when_escaped():
    cand = Candidate(url="http://localhost/search.php", param="q", vuln_class="xss-reflected")
    v = ReflectedXssStrategy().confirm(cand, XssEchoSender(escape=False))
    assert v and v.confirmed and v.evidence["context"] == "html"
    assert ReflectedXssStrategy().confirm(cand, XssEchoSender(escape=True)) is None


# --- oracle orchestration + sole finding-writer ------------------------------
def test_oracle_selects_strategy_and_writes_finding(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("oracle-test", "h")
        oracle = Oracle(store=store, run_id=run_id)
        verdict = oracle.confirm(_sqli(vuln_class="sqli"), ErrorSender())
        assert verdict.confirmed and verdict.mechanism == "error-signature"
        rows = store.conn.execute(
            "SELECT vuln_class, label, confidence, param FROM finding WHERE run_id=?",
            (run_id,)).fetchall()
        assert len(rows) == 1
        assert rows[0]["vuln_class"] == "sqli" and rows[0]["label"] == 1
        assert rows[0]["confidence"] == "error-signature" and rows[0]["param"] == "id"


def test_oracle_fail_closed_writes_no_finding(tmp_path):
    class SecureSender:
        def send(self, u, p, val, timing=False):
            # no error text, int-secure, no sleep honored, escapes reflection
            return Probe(200, "the blog post body" if val.strip() == "1" else "not found")
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("oracle-test", "h")
        oracle = Oracle(store=store, run_id=run_id)
        assert oracle.confirm(_sqli(vuln_class="sqli"), SecureSender()) is None
        assert store.conn.execute("SELECT COUNT(*) c FROM finding").fetchone()["c"] == 0


def test_oracle_only_runs_applicable_strategies():
    # An xss candidate must not be confirmed by a SQLi sender/strategy.
    cand = Candidate(url="http://localhost/x", param="q", vuln_class="xss-reflected")
    assert Oracle().confirm(cand, ErrorSender()) is None


def test_every_ruled_strategy_category_is_reachable_from_its_vuln_class():
    """PA-worthy guard (CC-FUZZ-0030): for every category that already has a
    real audit `Rule` (i.e. is genuinely meant to be reachable from a
    ground-truth-driven run right now, not just a strategy with no upstream
    candidate-generation yet -- see `test_labgen_node_bff_multitarget.py`'s
    own documented, deliberately-deferred `redos`/`prototype_pollution` gap,
    which this guard must NOT flag), `fuzzlab.oracle.strategies.
    _CATEGORY_TO_CLASS` and `fuzzlab.core.runmode._VULN_TO_CATEGORY` must
    stay inverses whenever the category slug differs from its vuln_class
    (e.g. `access-control`/`access_control`,
    `insecure-deserialization`/`insecure_deserialization`) -- a mismatch
    means a real rule+strategy pair is silently unreachable
    (`plan.categories` never includes it). This exact gap was found twice
    by a manual trace (`access_control`, then `insecure_deserialization`);
    this test makes a third *ruled* instance fail loudly instead of
    shipping unreachable.
    """
    from fuzzlab.audit.rules import load_rules
    from fuzzlab.core.runmode import to_category
    from fuzzlab.oracle.strategies import _CATEGORY_TO_CLASS

    ruled_categories = {r.category for r in load_rules()}
    for category, vuln_class in _CATEGORY_TO_CLASS.items():
        if category not in ruled_categories:
            continue    # no audit rule yet -- not meant to be reachable, same as redos/prototype_pollution
        if vuln_class == category:
            continue    # identical either way -- no _VULN_TO_CATEGORY entry needed
        assert to_category(vuln_class) == category, (
            f"category {category!r} has strategy vuln_class {vuln_class!r}, but "
            f"runmode.to_category({vuln_class!r}) == {to_category(vuln_class)!r} "
            f"-- add {vuln_class!r}: {category!r} to _VULN_TO_CATEGORY"
        )
