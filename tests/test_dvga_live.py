"""Live-boot test of the DVGA external lab (CC-LAB-0320, FR-LAB-320; GraphQL variables as
points, FR-AUD-600/601). Gated by ``FUZZLAB_LIVE_EXTERNAL_LABS=1``, with the shared
fixture of `tests.test_external_labs_live` (its own compose project on a free loopback
port, torn down by label, nothing left).

The gt pass runs `fuzzlab auto --points ground-truth --browser` through the CLI and
asserts the floor of matched case ids confirmed live, that no negative was flagged,
that every negative and floor case got a checked candidate, and the stated misses.
"""

from __future__ import annotations

import os
import time

import pytest

from tests.test_external_labs_live import (FLAG, REPO, _get, _score, _up,
                                           lab_factory)  # noqa: F401 - the fixture

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(os.environ.get(FLAG) != "1",
                       reason=f"live external-lab tests: set {FLAG}=1 (needs docker or podman "
                              f"with a compose provider; boots DVGA on loopback)"),
]

#: Confirmed live on 2026-11-20 (CC-LAB-0321 Effectiveness). A floor only grows.
#: DVGA-0001/0002/0004 left it when the lab-derived GraphQL rules were removed
#: (CC-AUD-0602): their arguments carry no generic command-injection signal.
DVGA_GT_FLOOR = {"DVGA-0003", "DVGA-0005", "DVGA-0007", "DVGA-0012", "DVGA-0013"}
STATED_MISSES = {"DVGA-0001", "DVGA-0002", "DVGA-0004", "DVGA-0014", "DVGA-0015"}


def test_dvga_fixture_scores_its_confirmed_rows(lab_factory):  # noqa: F811
    lab = lab_factory("dvga")
    _up(lab)
    # DVGA rebuilds its database (setup.py) before it listens; a lab with no login has
    # no bootstrap to wait for it (`external.bootstrap`), so wait here, bounded
    deadline = time.monotonic() + 120
    while True:
        try:
            if _get(lab.base + "/").status_code == 200:
                break
        except OSError:
            pass
        assert time.monotonic() < deadline, "DVGA never answered on its loopback port"
        time.sleep(1)
    gt_dir = REPO / "lab" / "ground-truth-dvga"
    store = lab.tmp / "dvga_gt.db"
    res = lab.fuzzlab("auto", "--base-url", lab.base, "--store", str(store),
                      "--ground-truth", str(gt_dir), "--points", "ground-truth",
                      "--browser", "--authorized", timeout=1800)
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-3000:]
    gt, report, checked = _score(store, gt_dir)
    from fuzzlab.core.runmode import to_category
    assert DVGA_GT_FLOOR <= set(report.matched), (sorted(DVGA_GT_FLOOR - set(report.matched)),
                                                  report.as_dict())
    assert not {c.case_id for c in gt.negatives()} & set(report.false_alarms)
    # every negative and every floor case was really probed (a checked candidate)
    for case in gt.cases:
        if case.case_id in DVGA_GT_FLOOR or not case.expected_vulnerable:
            key = (case.url, case.method, case.param, to_category(case.vuln_class))
            assert key in checked, f"{case.case_id} got no checked candidate"
    # stated misses: the [reach: none] rows, and three command sinks whose argument
    # names carry no generic signal (CC-AUD-0602); the day one is found this fails
    assert STATED_MISSES <= set(report.missed)
