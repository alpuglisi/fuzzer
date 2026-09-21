"""Offline tests for the Phase 3 grey-box consumer layer.

Everything here runs without a lab: readers are injected fakes, and the reward /
frontier / M10 logic is pure. The live pcov / DB-fault / reset sources that back the
protocols are the on-host last mile (docs/ON_HOST_TASKS.md).
"""

from fuzzlab.core.store import Store
from fuzzlab.greybox import (
    CoverageFrontier,
    FakeLabControl,
    GreyboxSignal,
    InMemoryCoverageSource,
    InMemoryDbFaultSource,
    app_lines,
    encode_coverage,
    greybox_confirms,
    m10_evidence,
    record_attempt_signals,
    shaped_reward,
)
from fuzzlab.greybox.coverage import decode_coverage
from fuzzlab.greybox.dbfault import DbFault
from fuzzlab.greybox.reward import novelty_term


# --- app-line filtering ------------------------------------------------------

def test_app_lines_excludes_framework_and_vendor():
    raw = {
        "/var/www/html/product.php": [10, 11, 12],
        "/var/www/html/vendor/lib/orm.php": [3, 4],
        "/usr/lib/php/prelude.php": [1],
        "/var/www/html/coverage_shim.php": [1, 2],
    }
    kept = app_lines(raw)
    assert set(kept) == {"/var/www/html/product.php"}
    assert kept["/var/www/html/product.php"] == {10, 11, 12}


def test_app_lines_include_prefixes():
    raw = {"/app/a.php": [1], "/other/b.php": [2]}
    kept = app_lines(raw, include_prefixes=["/app/"])
    assert set(kept) == {"/app/a.php"}


def test_app_lines_drops_empty_line_sets():
    assert app_lines({"/app/a.php": []}) == {}


# --- coverage frontier -------------------------------------------------------

def test_frontier_novelty_then_saturates():
    frontier = CoverageFrontier()
    first = {"/app/a.php": {1, 2, 3}}
    assert frontier.novelty(first) == 3
    assert frontier.observe(first) == 3          # all new the first time
    assert frontier.size == 3
    # Overlapping request: only the truly new lines count.
    second = {"/app/a.php": {2, 3, 4}, "/app/b.php": {9}}
    assert frontier.novelty(second) == 2         # lines 4 and 9
    assert frontier.observe(second) == 2
    assert frontier.size == 5
    # Fully-seen request has zero novelty.
    assert frontier.observe({"/app/a.php": {1, 2}}) == 0


def test_encode_decode_coverage_roundtrip():
    blob = encode_coverage({"/app/a.php": {3, 1, 2}}, novel=2)
    payload = decode_coverage(blob)
    assert payload["files"] == {"/app/a.php": [1, 2, 3]}   # sorted, deterministic
    assert payload["n_lines"] == 3
    assert payload["n_novel"] == 2
    assert decode_coverage(None) == {}


def test_in_memory_coverage_source():
    src = InMemoryCoverageSource({"req-1": {"/app/a.php": [1, 2]}})
    assert src.lines_for("req-1") == {"/app/a.php": {1, 2}}
    assert src.lines_for("missing") == {}
    src.set("req-2", {"/app/b.php": [7]})
    assert src.lines_for("req-2") == {"/app/b.php": {7}}


# --- shaped reward -----------------------------------------------------------

def test_novelty_term_strictly_increasing():
    assert novelty_term(0) == 0.0
    assert novelty_term(1) > novelty_term(0)
    assert novelty_term(5) > novelty_term(1)
    assert novelty_term(100) < 1.0               # saturates below 1


def test_reward_new_code_beats_no_new_code():
    # The Phase 3 exit property, in miniature: reaching new code scores higher.
    new_code = shaped_reward(GreyboxSignal(screening=0.0, novel_lines=5))
    no_new = shaped_reward(GreyboxSignal(screening=0.0, novel_lines=0))
    assert new_code > no_new


def test_reward_db_fault_and_screening_are_tiers():
    base = shaped_reward(GreyboxSignal(novel_lines=2))
    with_fault = shaped_reward(GreyboxSignal(novel_lines=2, db_fault=True))
    with_screen = shaped_reward(GreyboxSignal(novel_lines=2, screening=1.0))
    assert with_fault > base
    assert with_screen > base
    # Reward stays within [0, 1].
    top = shaped_reward(GreyboxSignal(screening=1.0, novel_lines=1000, db_fault=True))
    assert 0.0 <= top <= 1.0


# --- M10 decision ------------------------------------------------------------

def test_m10_sqli_needs_sink_and_db_fault():
    assert greybox_confirms("sqli", GreyboxSignal(sink_covered=True, db_fault=True))
    assert not greybox_confirms("sqli", GreyboxSignal(sink_covered=True, db_fault=False))
    assert not greybox_confirms("sqli", GreyboxSignal(sink_covered=False, db_fault=True))


def test_m10_xss_needs_sink_only():
    assert greybox_confirms("xss-reflected", GreyboxSignal(sink_covered=True))
    assert not greybox_confirms("xss-reflected", GreyboxSignal(sink_covered=False))


def test_m10_unknown_class_does_not_confirm():
    assert not greybox_confirms("ssti", GreyboxSignal(sink_covered=True, db_fault=True))


def test_m10_evidence_records_mechanism():
    ev = m10_evidence("sqli", GreyboxSignal(sink_covered=True, db_fault=True, novel_lines=4))
    assert ev["mechanism"] == "M10"
    assert ev["sink_covered"] is True and ev["db_fault"] is True
    assert ev["novel_lines"] == 4


# --- db-fault source ---------------------------------------------------------

def test_in_memory_db_fault_source_defaults_to_no_fault():
    src = InMemoryDbFaultSource({"req-1": DbFault(True, "syntax error")})
    assert src.fault_for("req-1").faulted is True
    assert src.fault_for("req-1").detail == "syntax error"
    assert src.fault_for("missing").faulted is False


# --- reset seam --------------------------------------------------------------

def test_fake_lab_control_records_calls():
    lab = FakeLabControl()
    lab.snapshot()
    lab.reset()
    lab.reset("baseline")
    assert lab.reset_count == 2
    assert lab.calls[0] == ("snapshot", "baseline")


# --- recorder + end-to-end mini flow ----------------------------------------

def _insert_attempt(store, run_id, payload_family="sqli"):
    cur = store.conn.execute(
        "INSERT INTO attempt (run_id, payload_family, reward) VALUES (?,?,?)",
        (run_id, payload_family, 0.0))
    store.conn.commit()
    return int(cur.lastrowid)


def test_record_attempt_signals_fills_reserved_columns(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("greybox", "h")
        attempt_id = _insert_attempt(store, run_id)
        record_attempt_signals(
            store, attempt_id,
            coverage=encode_coverage({"/app/a.php": {1, 2}}, novel=2),
            db_fault=True,
            reward=0.75)
        row = store.conn.execute(
            "SELECT coverage, db_fault, reward FROM attempt WHERE id=?",
            (attempt_id,)).fetchone()
        assert row["db_fault"] == 1
        assert row["reward"] == 0.75
        assert decode_coverage(row["coverage"])["n_novel"] == 2


def test_end_to_end_two_requests_reward_ordering(tmp_path):
    """Two requests through the frontier: the one reaching new code stores a higher
    reward — the Phase 3 exit property, enrichment path included, all offline."""
    cov_src = InMemoryCoverageSource({
        "r1": {"/var/www/html/product.php": [10, 11, 12]},   # first: all new
        "r2": {"/var/www/html/product.php": [10, 11, 12]},   # repeat: no new lines
    })
    fault_src = InMemoryDbFaultSource()   # no faults in this flow
    frontier = CoverageFrontier()
    rewards: dict[str, float] = {}
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("greybox", "h")
        for rid in ("r1", "r2"):
            attempt_id = _insert_attempt(store, run_id)
            cov = app_lines(cov_src.lines_for(rid))
            novel = frontier.observe(cov)
            signal = GreyboxSignal(screening=0.0, novel_lines=novel,
                                   db_fault=fault_src.fault_for(rid).faulted)
            reward = shaped_reward(signal)
            record_attempt_signals(store, attempt_id,
                                   coverage=encode_coverage(cov, novel=novel),
                                   db_fault=signal.db_fault, reward=reward)
            rewards[rid] = reward
        assert rewards["r1"] > rewards["r2"]          # new code scored higher
        stored = {r["id"]: r["reward"] for r in store.conn.execute(
            "SELECT id, reward FROM attempt WHERE run_id=?", (run_id,))}
        assert max(stored.values()) == rewards["r1"]
