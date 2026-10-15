"""Progress governance for autonomous orchestration (BUG-0141, BUG-0156, PA-0141..PA-0147).

The guard (`scripts/orchestration_guard.py`) runs as Claude Code hooks. These tests
drive it with a synthetic ledger, synthetic session transcripts and a pinned clock:
checkpoints fall due, a stalled metric stops dispatch until the user *decides*, review
rounds (not requests) and cumulative item budgets are capped, self-opened scope waits
for the user's approval, a fix that spawns bugs forces a disposition (QUALITY_POLICY
R1), concurrent items may not share files, and orchestration without a ledger is
caught. Contact is not a decision (BUG-0156): a status question, an item rename or a
close/reopen lifts no hold and resets no clock; a decision counts only when a real user
message carries its quote. One test replays the 2026-10-14/15 incident and shows the
guard would have stopped it about 6 hours in, instead of the user doing so about 15
hours in.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.package_guard


def _load():
    spec = importlib.util.spec_from_file_location(
        "orchestration_guard", ROOT / "scripts" / "orchestration_guard.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["orchestration_guard"] = mod
    spec.loader.exec_module(mod)
    return mod


og = _load()


# ------------------------------------------------------------------------ helpers


class Session:
    """A ledger, a transcript and a clock for one synthetic orchestration session."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        self.tmp = tmp_path
        self.ledger = tmp_path / "ledger.json"
        self.transcript = tmp_path / "transcript.jsonl"
        self.transcript.write_text("", encoding="utf-8")
        self.mp = monkeypatch
        monkeypatch.setenv("FUZZLAB_ORCH_LEDGER", str(self.ledger))
        self.at("2026-10-14T18:00:00Z")

    def at(self, ts: str) -> None:
        self.now = ts
        self.mp.setenv("FUZZLAB_ORCH_NOW", ts)

    def evidence(self, name: str = "run.out", mtime: str | None = None) -> str:
        p = self.tmp / name
        p.write_text("findings\n", encoding="utf-8")
        when = og.parse_ts(mtime or self.now).timestamp()
        os.utime(p, (when, when))
        return str(p)

    def cli(self, *argv: str) -> int:
        return og.main(list(argv))

    def open_goal(self, baseline: float = 6, reviewers: tuple[str, ...] = ()) -> None:
        args = ["goal", "open", "--text", "maximise Juice Shop detection",
                "--metric", "confirmed findings per run", "--baseline", str(baseline),
                "--evidence", self.evidence()]
        for r in reviewers:
            args += ["--reviewer", r]
        assert self.cli(*args) == 0

    def user_says(self, text: str, ts: str | None = None) -> None:
        self._append({"type": "user", "timestamp": ts or self.now,
                      "message": {"role": "user", "content": text}})

    def raw(self, entry: dict) -> None:
        self._append(entry)

    def tool_use(self, name: str, tool_input: dict, ts: str | None = None) -> None:
        self._append({"type": "assistant", "timestamp": ts or self.now,
                      "message": {"role": "assistant", "content": [
                          {"type": "tool_use", "id": "t", "name": name, "input": tool_input}]}})

    def _append(self, entry: dict) -> None:
        with self.transcript.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

    def hook(self, event: str, **payload) -> tuple[int, str]:
        payload.setdefault("transcript_path", str(self.transcript))
        return og.hook_main(event, payload, self.ledger)

    def dispatch(self, tool: str = "SendMessage", **tool_input) -> tuple[int, str]:
        return self.hook("pretooluse", tool_name=tool, tool_input=tool_input)

    def data(self) -> dict:
        return og.load_ledger(self.ledger)


@pytest.fixture
def s(tmp_path, monkeypatch) -> Session:
    return Session(tmp_path, monkeypatch)


# ---------------------------------------------------------------- no goal: no-op


def test_without_a_goal_every_hook_allows(s):
    assert s.dispatch(to="lane", message="anything") == (0, "")
    assert s.hook("stop") == (0, "")
    assert s.hook("sessionstart") == (0, "")


def test_dispatching_without_a_ledger_is_caught_at_the_stop(s):
    s.tool_use("Agent", {"prompt": "build lane A", "subagent_type": "general-purpose"},
               ts="2026-10-14T17:00:00Z")
    assert s.hook("stop")[0] == 0  # one dispatch is not orchestration
    s.tool_use("SendMessage", {"to": "x", "message": "round 2"}, ts="2026-10-14T17:30:00Z")
    code, text = s.hook("stop")
    assert code == 2 and "no goal ledger" in text
    # Read-only agents and STOP messages do not count.
    s.transcript.write_text("", encoding="utf-8")
    s.tool_use("Agent", {"prompt": "find x", "subagent_type": "Explore"})
    s.tool_use("SendMessage", {"to": "x", "message": "STOP: pause"})
    assert s.hook("stop")[0] == 0


def test_the_stop_hook_never_loops(s):
    s.open_goal()
    s.at("2026-10-15T06:00:00Z")
    assert s.hook("stop")[0] == 2
    assert s.hook("stop", stop_hook_active=True) == (0, "")


# --------------------------------------------------------------------- the goal


def test_a_goal_needs_a_measured_baseline(s):
    assert s.cli("goal", "open", "--text", "t", "--metric", "m", "--baseline", "1") == 2
    assert s.cli("goal", "open", "--text", "t", "--metric", "m", "--baseline", "1",
                 "--evidence", str(s.tmp / "missing.out")) == 2
    s.open_goal()
    assert s.data()["goal"]["status"] == "active"
    assert s.cli("goal", "open", "--text", "t", "--metric", "m", "--baseline", "1",
                 "--evidence", s.evidence()) == 2  # one goal at a time


def test_a_changed_value_needs_evidence_newer_than_the_last_checkpoint(s):
    s.open_goal(baseline=6)
    s.at("2026-10-14T19:00:00Z")
    assert s.cli("checkpoint", "--value", "6", "--note", "unchanged") == 0  # no new run needed
    s.at("2026-10-14T20:00:00Z")
    stale = s.evidence("old.out", mtime="2026-10-14T18:30:00Z")
    assert s.cli("checkpoint", "--value", "7", "--evidence", stale) == 2
    fresh = s.evidence("new.out", mtime="2026-10-14T19:59:00Z")
    assert s.cli("checkpoint", "--value", "7", "--evidence", fresh) == 0


# ------------------------------------------------------------------- checkpoints


def test_a_checkpoint_falls_due_after_three_unattended_hours(s):
    s.open_goal()
    s.at("2026-10-14T20:59:00Z")
    assert s.hook("stop")[0] == 0
    s.at("2026-10-14T21:01:00Z")
    code, text = s.hook("stop")
    assert code == 2 and "checkpoint" in text
    assert s.cli("checkpoint", "--value", "6", "--note", "no change") == 0
    assert s.hook("stop")[0] == 0


def test_a_user_message_restarts_the_checkpoint_clock(s):
    s.open_goal()
    s.user_says("status?", ts="2026-10-14T20:30:00Z")
    s.at("2026-10-14T22:00:00Z")
    assert s.hook("stop")[0] == 0


# ------------------------------------------------------------------------- stall


def _stalled(s: Session) -> None:
    s.open_goal(baseline=6)
    s.cli("item", "add", "FR-CRAWL-17", "--title", "SPA query params", "--kind", "feature", "--hypothesis", "h",
          "--origin", "user", "--budget-hours", "100")
    for ts in ("2026-10-14T21:00:00Z", "2026-10-15T00:00:00Z"):
        s.at(ts)
        assert s.cli("checkpoint", "--value", "6", "--note", "no change") == 0


def test_a_stalled_metric_denies_dispatch_until_the_user_decides(s):
    _stalled(s)
    s.at("2026-10-15T00:05:00Z")
    code, text = s.dispatch(to="lane", message="[item: FR-CRAWL-17] round 5 fixes")
    assert code == 2 and "STALL" in text
    # Stopping work is always allowed.
    assert s.dispatch(to="lane", message="STOP: hold everything")[0] == 0
    # A status question is contact, not a decision: the stall still holds (BUG-0156).
    s.user_says("status?", ts="2026-10-15T00:20:00Z")
    s.at("2026-10-15T00:21:00Z")
    assert s.dispatch(to="lane", message="[item: FR-CRAWL-17] finish")[0] == 2
    # A decision the user did not say does not count.
    assert s.cli("decide", "--hold", "stall", "--hours", "2", "--quote", "carry on") == 0
    assert s.dispatch(to="lane", message="[item: FR-CRAWL-17] finish")[0] == 2
    s.user_says("Keep going for two more hours, but only finish FR-CRAWL-17",
                ts="2026-10-15T00:30:00Z")
    s.at("2026-10-15T00:31:00Z")
    assert s.cli("decide", "--hold", "stall", "--hours", "2",
                 "--quote", "keep going for two more hours") == 0
    assert s.dispatch(to="lane", message="[item: FR-CRAWL-17] finish")[0] == 0
    report = og.render_report(s.data(), og.read_transcript(s.transcript), og.utcnow())
    assert "unchanged since 2026-10-14T18:00:00Z" in report  # the clock did not restart
    s.at("2026-10-15T02:32:00Z")  # the granted two hours are over
    assert s.dispatch(to="lane", message="[item: FR-CRAWL-17] finish")[0] == 2


def test_during_a_stall_only_work_on_the_stall_itself_is_dispatched(s):
    """Busy is not building: a stall is investigated and fixed, not fed (PA-0141)."""
    s.cli("goal", "open", "--text", "t", "--metric", "m", "--baseline", "6",
          "--evidence", s.evidence())
    s.cli("item", "add", "OLD-PROC", "--kind", "process", "--origin", "self",
          "--budget-hours", "100")
    s.cli("item", "add", "FEAT", "--kind", "feature", "--hypothesis", "h", "--origin", "user",
          "--budget-hours", "100")
    s.at("2026-10-15T00:05:00Z")  # stalled since 00:00
    assert s.dispatch(to="lane", message="[item: FEAT] more")[0] == 2
    # A process item from before the stall is not a response to it.
    assert s.dispatch(to="lane", message="[item: OLD-PROC] go")[0] == 2
    assert s.cli("item", "add", "WHY-STALLED", "--kind", "measurement", "--origin", "self",
                 "--title", "why is the metric flat?") == 0
    assert s.dispatch("Agent", prompt="[item: WHY-STALLED] measure where the time went",
                      subagent_type="general-purpose")[0] == 0
    assert s.data()["items"]["WHY-STALLED"]["stall_response"] is True
    s.at("2026-10-15T00:06:00Z")
    assert s.cli("item", "add", "FIX-LOOP", "--kind", "process", "--origin", "self") == 0
    assert s.dispatch(to="lane", message="[item: FIX-LOOP] cap the review rounds")[0] == 0
    assert s.dispatch(to="lane", message="[item: FEAT] more")[0] == 2  # still not fed
    assert s.hook("stop")[0] == 2  # and the user must be told


def test_a_stall_needs_a_push_notification_before_the_turn_ends(s):
    _stalled(s)
    s.at("2026-10-15T00:05:00Z")
    code, text = s.hook("stop")
    assert code == 2 and "PushNotification" in text
    s.tool_use("PushNotification", {"message": "stalled"}, ts="2026-10-15T00:06:00Z")
    s.at("2026-10-15T00:07:00Z")
    assert s.hook("stop")[0] == 0  # the session may now end its turn and wait


def test_an_improvement_restarts_the_stall_clock(s):
    s.open_goal(baseline=6)
    s.cli("item", "add", "B1", "--kind", "bug", "--origin", "user", "--budget-hours", "100")
    s.at("2026-10-14T23:00:00Z")
    assert s.cli("checkpoint", "--value", "7", "--evidence", s.evidence("r7.out")) == 0
    s.at("2026-10-15T04:00:00Z")
    assert s.cli("checkpoint", "--value", "7") == 0
    assert s.dispatch(to="lane", message="[item: B1] go")[0] == 0
    s.at("2026-10-15T05:01:00Z")
    assert s.dispatch(to="lane", message="[item: B1] go")[0] == 2


# ---------------------------------------------------------------- dispatch tags


def test_dispatch_must_name_a_live_ledger_item(s):
    s.open_goal()
    code, text = s.dispatch("Agent", prompt="build it", subagent_type="general-purpose")
    assert code == 2 and "[item:" in text
    assert s.dispatch("Agent", prompt="[item: NOPE] build")[0] == 2
    s.cli("item", "add", "X1", "--kind", "feature", "--hypothesis", "h", "--origin", "user")
    assert s.dispatch("Agent", prompt="[item: X1] build", subagent_type="general-purpose")[0] == 0
    assert s.data()["items"]["X1"]["status"] == "active"
    s.cli("item", "done", "X1")
    assert s.dispatch(to="lane", message="[item: X1] one more thing")[0] == 2
    assert s.dispatch("Agent", prompt="look around", subagent_type="Explore")[0] == 0
    assert s.dispatch("Bash", command="ls")[0] == 0


# ------------------------------------------------------------------ review rounds


def test_review_rounds_are_capped_and_counted_from_real_dispatches(s):
    s.open_goal(reviewers=("revA", "revB"))
    s.cli("item", "add", "X1", "--kind", "feature", "--hypothesis", "h", "--origin", "user")
    for n in range(3):
        # Two reviewers in parallel are one round; the fix dispatch closes it.
        assert s.dispatch(to="revA", message=f"[item: X1] round {n + 1}")[0] == 0
        assert s.dispatch(to="revB", message=f"[item: X1] round {n + 1}")[0] == 0
        assert s.dispatch(to="lane", message=f"[item: X1] apply round-{n + 1} fixes")[0] == 0
    assert len(s.data()["items"]["X1"]["rounds"]) == 3
    code, text = s.dispatch(to="revA", message="[item: X1] round 4")
    assert code == 2 and "review rounds" in text
    code, _ = s.dispatch("Agent", prompt="[item: X1] [review] fresh reviewer")
    assert code == 2
    # The lane may still be told to finish; only further review is capped.
    assert s.dispatch(to="lane", message="[item: X1] apply round-3 fixes")[0] == 0
    # Contact does not reset the count; a quoted decision grants more rounds.
    s.user_says("how is X1 going?", ts="2026-10-14T18:30:00Z")
    s.at("2026-10-14T18:31:00Z")
    assert s.dispatch(to="revA", message="[item: X1] confirm")[0] == 2
    s.user_says("ship it with the residuals stated; one more review to confirm the text",
                ts="2026-10-14T18:40:00Z")
    s.at("2026-10-14T18:41:00Z")
    assert s.cli("decide", "--hold", "review", "--item", "X1", "--rounds", "1",
                 "--quote", "one more review to confirm the text") == 0
    assert s.dispatch(to="revA", message="[item: X1] confirm the residual text")[0] == 0
    assert s.dispatch(to="lane", message="[item: X1] fix wording")[0] == 0
    assert s.dispatch(to="revA", message="[item: X1] and again")[0] == 2


def test_a_round_has_a_request_cap(s):
    s.open_goal(reviewers=("revA",))
    s.cli("item", "add", "X1", "--kind", "bug", "--origin", "user")
    for n in range(4):
        assert s.dispatch(to="revA", message=f"[item: X1] look {n}")[0] == 0
    code, text = s.dispatch(to="revA", message="[item: X1] look again")
    assert code == 2 and "in this round" in text


# ------------------------------------------------------------------------ budget


def test_an_item_over_budget_is_held_and_others_are_not(s):
    s.open_goal()
    s.cli("item", "add", "SLOW", "--kind", "feature", "--hypothesis", "h", "--origin", "user", "--budget-hours", "2")
    s.cli("item", "add", "FAST", "--kind", "feature", "--hypothesis", "h", "--origin", "user", "--budget-hours", "8")
    assert s.dispatch(to="lane", message="[item: SLOW] start")[0] == 0
    assert s.dispatch(to="lane", message="[item: FAST] start")[0] == 0
    s.at("2026-10-14T20:01:00Z")
    s.cli("checkpoint", "--value", "6")
    code, text = s.dispatch(to="lane", message="[item: SLOW] more")
    assert code == 2 and "budget" in text
    assert s.dispatch(to="lane", message="[item: FAST] more")[0] == 0


def test_contact_and_renames_do_not_reset_an_exhausted_experiment(s):
    """Counterexample (d) of the lean QC review: user contact or an item rename during
    an exhausted experiment must not erase the overrun (BUG-0156)."""
    s.open_goal()
    s.cli("item", "add", "EXP", "--kind", "feature", "--origin", "user", "--budget-hours", "2",
          "--hypothesis", "query seeds survive realtime writes; +2 reached; 2 h; else narrow")
    assert s.dispatch(to="lane", message="[item: EXP] start")[0] == 0
    s.at("2026-10-14T20:30:00Z")
    s.cli("checkpoint", "--value", "6")
    assert s.dispatch(to="lane", message="[item: EXP] more")[0] == 2
    s.user_says("Where are we at with this?", ts="2026-10-14T20:35:00Z")
    s.at("2026-10-14T20:36:00Z")
    code, text = s.dispatch(to="lane", message="[item: EXP] more")
    assert code == 2 and "2.6 h spent" in text  # nothing reset
    # A rename carries the spend, the hypothesis and the hold.
    assert s.cli("item", "add", "EXP-V2", "--kind", "feature", "--origin", "user",
                 "--continues", "EXP") == 0
    assert s.data()["items"]["EXP"]["status"] == "renamed"
    code, text = s.dispatch(to="lane", message="[item: EXP-V2] more")
    assert code == 2 and "budget" in text
    assert s.dispatch(to="lane", message="[item: EXP] more")[0] == 2
    # Done and reopened: the spend continues.
    s.cli("item", "done", "EXP-V2")
    s.cli("item", "reopen", "EXP-V2")
    assert s.dispatch(to="lane", message="[item: EXP-V2] more")[0] == 2
    # The user grants two hours; the exhausted experiment still needs a disposition (R1).
    s.user_says("ok, two more hours for the realtime fix", ts="2026-10-14T20:40:00Z")
    s.at("2026-10-14T20:41:00Z")
    assert s.cli("decide", "--hold", "budget", "--item", "EXP-V2", "--hours", "2",
                 "--quote", "two more hours for the realtime fix") == 0
    code, text = s.dispatch(to="lane", message="[item: EXP-V2] more")
    assert code == 2 and "disposition" in text
    assert s.cli("item", "disposition", "EXP-V2", "--class", "capability-gap",
                 "--evidence", "run.db: 0 of 4 seeds reached", "--next", "") == 2
    assert s.cli("item", "disposition", "EXP-V2", "--class", "capability-gap",
                 "--evidence", "run.db: 0 of 4 seeds reached",
                 "--next", "fresh-load baseline; predict +2 reached; 2 h") == 0
    assert s.dispatch(to="lane", message="[item: EXP-V2] fresh-load baseline")[0] == 0
    item = s.data()["items"]["EXP-V2"]
    assert og.spent_hours(item, og.utcnow()) >= 2.6  # the spend survived rename and reopen


def test_a_decision_needs_the_users_words_and_names_its_hold(s):
    s.open_goal()
    s.cli("item", "add", "B", "--kind", "bug", "--origin", "user", "--budget-hours", "1")
    assert s.cli("decide", "--hold", "budget", "--item", "B", "--quote", "go") == 2  # no --hours
    assert s.cli("decide", "--hold", "budget", "--hours", "1", "--quote", "go") == 2  # no --item
    assert s.cli("decide", "--hold", "review", "--item", "B", "--quote", "go") == 2  # no --rounds
    assert s.cli("decide", "--hold", "scope", "--item", "NOPE", "--quote", "go") == 2
    assert s.cli("decide", "--hold", "scope", "--item", "B", "--quote", " ") == 2
    assert s.dispatch(to="lane", message="[item: B] go")[0] == 0
    s.at("2026-10-14T19:01:00Z")
    assert s.dispatch(to="lane", message="[item: B] go")[0] == 2
    # A stall decision does not lift a budget hold.
    s.user_says("take another hour on B", ts="2026-10-14T19:02:00Z")
    s.at("2026-10-14T19:03:00Z")
    assert s.cli("decide", "--hold", "stall", "--hours", "1",
                 "--quote", "take another hour on B") == 0
    assert s.dispatch(to="lane", message="[item: B] go")[0] == 2
    assert s.cli("decide", "--hold", "budget", "--item", "B", "--hours", "1",
                 "--quote", "take another hour on B") == 0
    assert s.dispatch(to="lane", message="[item: B] go")[0] == 0
    report = og.render_report(s.data(), og.read_transcript(s.transcript), og.utcnow())
    assert "quote found in a user message at 2026-10-14T19:02:00Z" in report


def test_a_closed_goal_keeps_its_history(s):
    s.open_goal()
    s.cli("item", "add", "B", "--kind", "bug", "--origin", "user")
    assert s.cli("goal", "close", "--reason", "handoff") == 0
    assert s.cli("goal", "reopen") == 0
    assert "B" in s.data()["items"]
    assert s.cli("goal", "close") == 0
    s.open_goal()
    data = s.data()
    assert data["items"] == {} and len(data["history"]) == 1
    assert "B" in data["history"][0]["items"]


def test_a_feature_names_the_outcome_it_should_move(s):
    s.open_goal()
    assert s.cli("item", "add", "F", "--kind", "feature", "--origin", "user") == 2
    assert s.cli("item", "add", "F", "--kind", "feature", "--origin", "user",
                 "--hypothesis", "login found by affordance: +3 reached on SPA labs; 4 h") == 0
    assert s.cli("item", "add", "S", "--kind", "safety", "--origin", "user") == 0


# ------------------------------------------------------------------------- scope


def test_work_the_session_opened_itself_waits_for_the_user(s):
    s.open_goal()
    s.cli("item", "add", "FEAT", "--kind", "feature", "--hypothesis", "h", "--origin", "user")
    s.dispatch(to="lane", message="[item: FEAT] go")
    s.at("2026-10-14T18:10:00Z")
    assert s.cli("item", "add", "HARDEN", "--kind", "safety", "--origin", "self") == 0
    code, text = s.dispatch(to="lane", message="[item: HARDEN] go")
    assert code == 2 and "backlog" in text
    # A defect blocking active work is not new scope.
    assert s.cli("item", "add", "BUG-1", "--kind", "bug", "--origin", "self",
                 "--blocks", "FEAT") == 0
    assert s.dispatch(to="lane", message="[item: BUG-1] fix")[0] == 0
    # --blocks is only for defects.
    assert s.cli("item", "add", "SNEAK", "--kind", "feature", "--hypothesis", "h",
                 "--origin", "self", "--blocks", "FEAT") == 2
    # Contact is not approval; a rename does not launder the origin.
    s.user_says("what are you working on?", ts="2026-10-14T18:15:00Z")
    s.at("2026-10-14T18:16:00Z")
    assert s.dispatch(to="lane", message="[item: HARDEN] go")[0] == 2
    assert s.cli("item", "add", "HARDEN-2", "--kind", "safety", "--origin", "user",
                 "--continues", "HARDEN") == 0
    assert s.dispatch(to="lane", message="[item: HARDEN-2] go")[0] == 2
    s.user_says("yes, do the hardening", ts="2026-10-14T18:20:00Z")
    s.at("2026-10-14T18:21:00Z")
    assert s.cli("decide", "--hold", "scope", "--item", "HARDEN-2",
                 "--quote", "yes, do the hardening") == 0
    assert s.dispatch(to="lane", message="[item: HARDEN-2] go")[0] == 0


# --------------------------------------------------------------------- bug chain


def test_a_fix_that_keeps_spawning_bugs_forces_a_disposition(s):
    s.open_goal()
    s.cli("item", "add", "NAV", "--kind", "bug", "--origin", "user")
    s.dispatch(to="lane", message="[item: NAV] fix")
    s.at("2026-10-14T18:30:00Z")
    s.cli("item", "add", "BUG-A", "--kind", "bug", "--origin", "self", "--blocks", "NAV",
          "--spawned-by", "NAV")
    assert s.dispatch(to="lane", message="[item: BUG-A] fix")[0] == 0
    s.at("2026-10-14T19:00:00Z")
    s.cli("item", "add", "BUG-B", "--kind", "bug", "--origin", "self", "--blocks", "NAV",
          "--spawned-by", "NAV")
    for target in ("NAV", "BUG-A", "BUG-B"):
        code, text = s.dispatch(to="lane", message=f"[item: {target}] next fix")
        assert code == 2 and "spawned 2 bugs" in text and "disposition" in text
    # Contact does not clear it; the delivery owner's evidenced disposition does.
    s.user_says("how's NAV?", ts="2026-10-14T19:05:00Z")
    s.at("2026-10-14T19:06:00Z")
    assert s.dispatch(to="lane", message="[item: NAV] next fix")[0] == 2
    assert s.cli("item", "disposition", "NAV", "--class", "guess",
                 "--evidence", "e", "--next", "n") == 2
    assert s.cli("item", "disposition", "NAV", "--class", "missing-shared-contract",
                 "--evidence", "three callers each re-implement the commit wait (navguard.py)",
                 "--next", "one guarded-navigation owner; predict 0 new bugs; 3 h") == 0
    assert s.dispatch(to="lane", message="[item: NAV] measure")[0] == 0
    # The trigger re-arms on a new chain after the disposition.
    for n, ts in (("C", "2026-10-14T19:30:00Z"), ("D", "2026-10-14T19:40:00Z")):
        s.at(ts)
        s.cli("item", "add", f"BUG-{n}", "--kind", "bug", "--origin", "self",
              "--blocks", "NAV", "--spawned-by", "NAV")
    assert s.dispatch(to="lane", message="[item: NAV] next fix")[0] == 2


# ---------------------------------------------------------------- WIP and files


def test_wip_limit_and_declared_file_overlap(s):
    s.open_goal()
    s.cli("item", "add", "A", "--kind", "feature", "--hypothesis", "h", "--origin", "user",
          "--files", "fuzzlab/tools/spider.py")
    s.dispatch(to="lane", message="[item: A] go")
    assert s.cli("item", "add", "B", "--kind", "feature", "--hypothesis", "h", "--origin", "user",
                 "--files", "fuzzlab/tools/") == 2
    assert s.cli("item", "add", "B", "--kind", "feature", "--hypothesis", "h", "--origin", "user",
                 "--files", "fuzzlab/tools/", "--after", "A") == 0
    for n in ("C", "D"):
        s.cli("item", "add", n, "--kind", "feature", "--hypothesis", "h", "--origin", "user")
    s.dispatch(to="lane", message="[item: B] go")
    s.dispatch(to="lane", message="[item: C] go")
    assert s.cli("item", "add", "E", "--kind", "feature", "--hypothesis", "h", "--origin", "user") == 2


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout


def test_audit_finds_two_active_branches_changing_one_file(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "spider.py").write_text("a\n")
    (repo / "other.py").write_text("a\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    for branch, files in (("one", ["spider.py"]), ("two", ["spider.py", "other.py"])):
        _git(repo, "checkout", "-qb", branch, "main")
        for f in files:
            (repo / f).write_text(branch + "\n")
        _git(repo, "commit", "-qam", branch)
    data = og.empty_ledger()
    data["items"] = {
        "ONE": {"status": "active", "branch": "one", "base": "main", "opened": "x"},
        "TWO": {"status": "active", "branch": "two", "base": "main", "opened": "x"},
    }
    problems = og.audit_overlaps(data, repo)
    assert problems == ["ONE and TWO both change spider.py"]
    data["items"]["TWO"]["after"] = "ONE"
    assert og.audit_overlaps(data, repo) == []


# ------------------------------------------------------------ transcript reading


def test_only_messages_and_answers_from_the_user_count_as_the_user(s):
    s.raw({"type": "user", "timestamp": "2026-10-14T10:00:00Z", "isSidechain": True,
           "message": {"content": "subagent prompt"}})
    s.raw({"type": "user", "timestamp": "2026-10-14T10:01:00Z",
           "message": {"content": [{"type": "tool_result", "tool_use_id": "t",
                                    "content": "ok"}]}})
    for text in ("<task-notification>done</task-notification>",
                 "This session is being continued from a previous conversation",
                 "Stop hook feedback:\nblocked",
                 "<system-reminder>x</system-reminder>"):
        s.raw({"type": "user", "timestamp": "2026-10-14T10:02:00Z",
               "message": {"content": text}})
    s.raw({"type": "user", "timestamp": "2026-10-14T10:03:00Z", "isMeta": True,
           "message": {"content": "meta"}})
    assert og.read_transcript(s.transcript).user_messages == []
    s.user_says("status?", ts="2026-10-14T10:04:00Z")
    s.raw({"type": "user", "timestamp": "2026-10-14T10:05:00Z",
           "message": {"content": [{"type": "text", "text": "keep going"}]}})
    s.raw({"type": "user", "timestamp": "2026-10-14T10:06:00Z",
           "message": {"content": [{"type": "tool_result", "tool_use_id": "q",
                                    "content": "Your questions have been answered: \"x\"=\"y\""}]}})
    assert [og.fmt_ts(t) for t in og.read_transcript(s.transcript).user_messages] == [
        "2026-10-14T10:04:00Z", "2026-10-14T10:05:00Z", "2026-10-14T10:06:00Z"]


def test_a_broken_guard_reports_but_never_blocks(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("bad ledger")
    monkeypatch.setattr(og, "hook_main", boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    assert og.main(["hook", "stop"]) == 1  # 1 is shown, never blocks; 2 would block
    assert "internal error" in capsys.readouterr().err


def test_after_a_compaction_the_session_is_shown_the_goal(s):
    s.open_goal()
    code, text = s.hook("sessionstart", source="compact")
    assert code == 0 and "ORCHESTRATION GOAL IS OPEN" in text and "Checkpoints" in text


# --------------------------------------------------------------------- wiring


def test_the_repository_hooks_call_the_guard():
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text())
    hooks = settings["hooks"]

    def commands(event: str) -> list[tuple[str, str]]:
        return [(block.get("matcher", ""), h["command"])
                for block in hooks.get(event, []) for h in block["hooks"]]

    assert any("orchestration_guard.py\" hook stop" in c for _, c in commands("Stop"))
    pre = [(m, c) for m, c in commands("PreToolUse") if "hook pretooluse" in c]
    assert pre, "PreToolUse dispatch gate is not wired"
    matcher = pre[0][0]
    for tool in ("Agent", "SendMessage", "Workflow"):
        assert tool in matcher.split("|")
    assert any("hook sessionstart" in c for _, c in commands("SessionStart"))
    assert ".claude/orchestration/" in (ROOT / ".gitignore").read_text()


# --------------------------------------------------------------- the incident


def test_replay_of_the_2026_10_14_incident_stops_six_hours_in(s):
    """BUG-0141: 6 findings at 17:57; work went on with no word to the user until they
    asked at 01:32, and the next gain came at about 06:30. The guard denies the
    next dispatch at 23:57, with a forced report at 20:58."""
    s.at("2026-10-14T17:57:00Z")
    s.user_says("Where are we at with this?", ts="2026-10-14T16:57:00Z")
    s.open_goal(baseline=6, reviewers=("add28689cedb46637", "a33f49a9e20ae5538"))
    s.cli("item", "add", "FR-SESS-20", "--title", "origin-scoped sessions", "--kind", "safety",
          "--origin", "self", "--budget-hours", "4")
    s.cli("item", "add", "FR-CRAWL-17", "--title", "SPA query parameters", "--kind", "feature", "--hypothesis", "h",
          "--origin", "user", "--budget-hours", "4")
    # Origin scoping was the session's own follow-up: held for the user from the start.
    assert s.dispatch(to="lane", message="[item: FR-SESS-20] build Revision 2")[0] == 2
    s.at("2026-10-14T19:59:00Z")
    assert s.dispatch(to="lane", message="[item: FR-CRAWL-17] build Revision 2")[0] == 0
    s.at("2026-10-14T20:58:00Z")
    assert s.hook("stop")[0] == 2  # report due: 3 h unattended
    s.cli("checkpoint", "--value", "6", "--note", "no change")
    for ts in ("2026-10-14T20:59:00Z", "2026-10-14T21:47:00Z", "2026-10-14T22:03:00Z"):
        s.at(ts)
        assert s.dispatch(to="a33f49a9e20ae5538", message="[item: FR-CRAWL-17] review")[0] == 0
        assert s.dispatch(to="lane", message="[item: FR-CRAWL-17] apply the fixes")[0] == 0
    s.at("2026-10-14T22:30:00Z")
    code, text = s.dispatch(to="add28689cedb46637", message="[item: FR-CRAWL-17] round 4")
    assert code == 2 and "review rounds" in text
    s.at("2026-10-14T23:57:30Z")
    s.cli("checkpoint", "--value", "6", "--note", "no change")
    code, text = s.dispatch(to="lane", message="[item: FR-CRAWL-17] merge follow-up M0-M10")
    assert code == 2 and "STALL" in text and "defect" in text
    assert s.hook("stop")[0] == 2  # must notify the user, not carry on silently
    # What should have happened: investigate why the metric is flat and fix that.
    s.cli("item", "add", "WHY-FLAT", "--kind", "measurement", "--origin", "self")
    assert s.dispatch(to="lane", message="[item: WHY-FLAT] where did 6 h go?")[0] == 0
