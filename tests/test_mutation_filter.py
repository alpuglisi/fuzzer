"""Phase 8 T8.3: offline filter model + filter-transformation learning."""

from fuzzlab.mutation.filtermodel import FilterModel, php_pattern_to_regex
from fuzzlab.mutation.learn import FilterLearner
from fuzzlab.mutation.operators import default_operators

SQLI = "1 union select password from users"


def test_php_pattern_conversion():
    rx = php_pattern_to_regex("/<script/i")
    assert rx.search("<SCRIPT>") and not rx.search("<div>")


def test_filter_catches_naive_and_misses_bypass():
    fm = FilterModel.from_lab(mode="block")
    assert "sqli-union-select" in fm.rule_ids()
    assert fm.caught(SQLI) is True
    assert fm.caught("1 union/**/select password from users") is False   # classic bypass


def test_filter_modes_block_sanitize_log():
    payload = "<script>alert(1)</script>"
    assert FilterModel.from_lab("block").evaluate(payload).action == "block"
    san = FilterModel.from_lab("sanitize").evaluate(payload)
    assert san.action == "sanitized" and "<script>" not in san.clean and san.caught
    log = FilterModel.from_lab("log").evaluate(payload)
    assert log.action == "allow" and log.caught          # log records but lets through


def test_evading_operators_are_found():
    learner = FilterLearner(FilterModel.from_lab())
    evaders = learner.evading_operators(SQLI, "sql-injection")
    assert "url-encode" in evaders and "sql-comment" in evaders


def test_learn_bypass_is_semantics_preserving_and_shallow():
    fm = FilterModel.from_lab()
    learner = FilterLearner(fm)
    bp = learner.learn_bypass(SQLI, "sql-injection", max_depth=2)
    assert bp is not None
    assert fm.caught(bp.variant) is False                 # actually evades
    assert bp.semantics_ok is True and bp.depth == 1      # shortest preserving chain
    assert bp.operators                                   # at least one operator applied


def test_learn_bypass_noop_when_already_uncaught():
    learner = FilterLearner(FilterModel.from_lab())
    bp = learner.learn_bypass("golden retriever fort", "sql-injection")
    assert bp is not None and bp.operators == [] and bp.depth == 0


def test_observe_transform_reports_stripping():
    learner = FilterLearner(FilterModel.from_lab("sanitize"))
    obs = learner.observe_transform("../../etc/passwd")
    assert "path-traversal" in obs["hits"] and obs["stripped"] is True
    obs2 = learner.observe_transform("golden retriever")
    assert obs2["hits"] == [] and obs2["stripped"] is False


def test_learner_accepts_default_operator_set():
    # the learner works over the class-scoped operator set without extra config
    learner = FilterLearner(FilterModel.from_lab())
    ops = default_operators("sql-injection")
    bp = learner.learn_bypass(SQLI, "sql-injection", operators=ops)
    assert bp is not None and not FilterModel.from_lab().caught(bp.variant)
