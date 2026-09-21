"""Phase 8 T8.5/T8.6: variant write-back + destructive gate, and the gated LLM scaffold."""

import json

from fuzzlab.core.store import Store
from fuzzlab.mutation.catalog import (is_destructive, list_variants,
                                      record_search_result, record_variant)
from fuzzlab.mutation.llm import LlmExpander
from fuzzlab.mutation.search import SearchResult


def _store(tmp_path):
    store = Store(tmp_path / "u.db")
    return store, store.start_run("mutation", "127.0.0.1:8080")


# --- destructive gate --------------------------------------------------------
def test_is_destructive():
    assert is_destructive("1; DROP TABLE users")
    assert is_destructive("'; delete from orders --")
    assert is_destructive("x'); truncate table logs;--")
    assert not is_destructive("1 union/**/select password from users")   # read-only
    assert not is_destructive("<svg onload=alert(1)>")


def test_record_variant_persists_nondestructive(tmp_path):
    store, run_id = _store(tmp_path)
    vid = record_variant(store, run_id, "1 union select p from users",
                         "1 union/**/select p from users", ["sql-comment"],
                         "sql-injection", bypassed_rule="sqli-union-select",
                         semantics_ok=True, coverage_gain=3.0)
    assert vid is not None
    rows = list_variants(store, run_id)
    assert len(rows) == 1
    r = rows[0]
    assert r["variant"] == "1 union/**/select p from users"
    assert json.loads(r["operators"]) == ["sql-comment"]
    assert r["bypassed_rule"] == "sqli-union-select" and r["semantics_ok"] == 1
    store.close()


def test_destructive_gate_refuses_by_default(tmp_path):
    store, run_id = _store(tmp_path)
    vid = record_variant(store, run_id, "x", "1; DROP TABLE users", ["case-toggle"],
                         "sql-injection")
    assert vid is None                                  # refused, nothing written
    assert list_variants(store, run_id) == []
    # explicit opt-in persists it (lab-only)
    vid2 = record_variant(store, run_id, "x", "1; DROP TABLE users", ["case-toggle"],
                          "sql-injection", allow_destructive=True)
    assert vid2 is not None and len(list_variants(store, run_id)) == 1
    store.close()


def test_record_search_result(tmp_path):
    store, run_id = _store(tmp_path)
    res = SearchResult("1/**/union/**/select 1", ["ws-alt"], evaded=True,
                       semantics_ok=True, novel_lines=5, steps=2)
    vid = record_search_result(store, run_id, "1 union select 1", res, "sql-injection",
                               bypassed_rule="sqli-union-select")
    assert vid is not None
    r = list_variants(store, run_id)[0]
    assert r["variant"] == "1/**/union/**/select 1" and r["coverage_gain"] == 5.0
    store.close()


# --- gated LLM scaffold (default off, offline) -------------------------------
def test_llm_expander_default_off():
    exp = LlmExpander()                                 # default: disabled, no generator
    assert exp.enabled is False
    assert exp.expand(["1 or 1=1"]) == [] and exp.pending() == []


def test_llm_disabled_ignores_generator():
    calls = []
    exp = LlmExpander(enabled=False, generator=lambda seeds: calls.append(1) or ["x"])
    assert exp.expand(["a"]) == [] and exp.pending() == [] and calls == []  # never called


def test_llm_enabled_quarantines_for_review():
    exp = LlmExpander(enabled=True, generator=lambda seeds: [s + "/**/" for s in seeds])
    # expand returns nothing usable; candidates are quarantined, not trusted
    assert exp.expand(["1 or 1=1", "union select"]) == []
    assert set(exp.pending()) == {"1 or 1=1/**/", "union select/**/"}
    assert exp.approved() == []
    # a human approves one → it moves to approved, out of pending
    assert exp.approve("1 or 1=1/**/") is True
    assert "1 or 1=1/**/" in exp.approved() and "1 or 1=1/**/" not in exp.pending()
    assert exp.approve("not-there") is False
