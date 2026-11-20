"""PA-0640 (BUG-0640, CC-LAB-0360): a `[reach: gt]` tag on an external lab's positive is
backed by a recorded, scored `fuzzlab auto --points ground-truth` run.

Three secDevLabs positives were tagged reachable from ground-truth points on the strength
of a hand-made request (curl, an account created by hand), and no scored run ever
matched them: copy-n-paste's points sent a body its handler refuses, mongection's fresh
database had no account for its flaw to answer, comment-killer's stored case has no
store URL to plant at. The record (`docs/components/01-target-lab/external-lab-scores.
json`) holds each lab's latest scored ground-truth run: its command, commit, counts and
the case ids it matched, and for every positive it missed, why. This guard reads only
committed files (no lab is started)."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from fuzzlab.labels import contract
from fuzzlab.lab_fixtures import external as ext

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs" / "components" / "01-target-lab" / "external-lab-scores.json"
_REACH = re.compile(r"\[reach:\s*([a-z, ]+?)(?:\s+-|\])")
_TRACKED = re.compile(r"\b(CC-[A-Z]+-\d{4}|BUG-\d{4})\b")
FIELDS = {"commit", "command", "tp", "fp", "fn", "tn", "requests", "wall_s", "matched",
          "missed"}


def _labs_with_ground_truth() -> list[str]:
    return sorted(n for n in ext.LAB_META if (ROOT / "lab" / f"ground-truth-{n}").is_dir())


def _reach(notes: str) -> set[str]:
    m = _REACH.search(notes or "")
    return {t.strip() for t in m.group(1).split(",")} if m else set()


def gt_reachable_positives(gt) -> set[str]:
    return {c.case_id for c in gt.cases if c.expected_vulnerable and "gt" in _reach(c.notes)}


def problems(record: dict, name: str, gt) -> list[str]:
    """Why ``record``'s entry for ``name`` does not back its answer key's reach tags."""
    run = record.get(name)
    if run is None:
        return [f"{name}: no scored ground-truth run recorded"]
    out = [f"{name}: missing field {f}" for f in sorted(FIELDS - set(run))]
    if out:
        return out
    ids = {c.case_id for c in gt.cases}
    positives = {c.case_id for c in gt.cases if c.expected_vulnerable}
    matched, missed = set(run["matched"]), dict(run["missed"])
    out += [f"{name}: {i} recorded but not in the answer key" for i in
            sorted((matched | set(missed)) - ids)]
    if len(matched) != run["tp"]:
        out.append(f"{name}: tp={run['tp']} but {len(matched)} matched ids")
    if set(missed) != positives - matched or len(missed) != run["fn"]:
        out.append(f"{name}: missed ids must be exactly the positives not matched "
                   f"(fn={run['fn']})")
    out += [f"{name}: {i} missed with no reason" for i, why in missed.items()
            if not str(why).strip()]
    out += [f"{name}: {i} matched but not a positive" for i in sorted(matched - positives)]
    negatives = len(ids) - len(positives)
    if not 0 <= run["tn"] <= negatives or run["fp"] < negatives - run["tn"]:
        out.append(f"{name}: tn={run['tn']} fp={run['fp']} disagree with the key's "
                   f"{negatives} negatives")
    out += [f"{name}: {i} is open with no tracked id (CC-<CODE>-NNNN or BUG-NNNN)"
            for i, why in missed.items()
            if str(why).startswith("open") and not _TRACKED.search(str(why))]
    out += [f"{name}: {i} is tagged [reach: gt] but the recorded run missed it and its "
            f"reason does not say it is open" for i in sorted(gt_reachable_positives(gt))
            if i in missed and not str(missed[i]).startswith("open")]
    return out


@pytest.fixture(scope="module")
def record() -> dict:
    return json.loads(RECORD.read_text())


@pytest.mark.parametrize("name", _labs_with_ground_truth())
def test_every_gt_reachable_positive_is_matched_by_the_recorded_run_or_open(record, name):
    gt = contract.load(ROOT / "lab" / f"ground-truth-{name}")
    assert problems(record, name, gt) == []


def test_the_guard_catches_a_reach_tag_no_scored_run_backs(record):
    """Proven on BUG-0640's own shape: copy-n-paste's positives tagged gt, the run at
    2be7a50 matching none of them, their misses not declared open."""
    gt = contract.load(ROOT / "lab" / "ground-truth-secdevlabs-copy-n-paste")
    bad = {"secdevlabs-copy-n-paste": {
        "commit": "2be7a50", "command": "auto --points ground-truth", "tp": 0, "fp": 0,
        "fn": 3, "tn": 1, "requests": 67, "wall_s": 0.5, "matched": [],
        "missed": {"SDLCNP-0001": "400 All fields are required",
                   "SDLCNP-0002": "400 All fields are required",
                   "SDLCNP-0004": "open: needs a register-then-login flow"}}}
    got = problems(bad, "secdevlabs-copy-n-paste", gt)
    assert any("SDLCNP-0001 is tagged" in p for p in got)
    assert any("SDLCNP-0002 is tagged" in p for p in got)
    assert not any("SDLCNP-0004 is tagged" in p for p in got)
    assert problems({}, "secdevlabs-copy-n-paste", gt) == [
        "secdevlabs-copy-n-paste: no scored ground-truth run recorded"]


def test_the_guard_catches_an_untracked_open_reason_a_non_positive_match_and_bad_counts(
        record):
    """FR-LAB-363 (BUG-0641's review follow-ups): an `open:` reason names the record that
    tracks it, a matched id is a positive, and tn/fp agree with the key's negatives."""
    gt = contract.load(ROOT / "lab" / "ground-truth-secdevlabs-copy-n-paste")
    good = dict(record["secdevlabs-copy-n-paste"])
    assert problems({"secdevlabs-copy-n-paste": good}, "secdevlabs-copy-n-paste", gt) == []
    untracked = {**good, "missed": {k: "open: someday" for k in good["missed"]}}
    assert any("no tracked id" in p for p in problems(
        {"secdevlabs-copy-n-paste": untracked}, "secdevlabs-copy-n-paste", gt))
    negative = next(c.case_id for c in gt.cases if not c.expected_vulnerable)
    wrong = {**good, "matched": good["matched"][:-1] + [negative]}
    assert any("matched but not a positive" in p for p in problems(
        {"secdevlabs-copy-n-paste": wrong}, "secdevlabs-copy-n-paste", gt))
    counts = {**good, "tn": good["tn"] + 5}
    assert any("disagree" in p for p in problems(
        {"secdevlabs-copy-n-paste": counts}, "secdevlabs-copy-n-paste", gt))
