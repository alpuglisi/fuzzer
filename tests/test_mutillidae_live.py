"""Live boot of the Mutillidae II external lab (CC-LAB-0340..0343; FR-LAB-340..343):
``labctl.sh reset mutillidae --authorized`` (database built, directory loaded, account
registered) then a scored ``fuzzlab auto --points ground-truth --identity`` run.

Gated by ``FUZZLAB_LIVE_EXTERNAL_LABS=1`` (the same gate and harness as
`tests/test_external_labs_live.py`: its own compose project, a free loopback port, a
throwaway keyring, torn down by the exact project label)."""

from __future__ import annotations

import pytest

from tests.test_external_labs_live import (FLAG, REPO, _score, _up,  # noqa: F401
                                           lab_factory, pytestmark)

#: The positives the ground-truth pass does not confirm, each verified by hand and
#: recorded as a gap in CC-LAB-0343: XXE read in band (no file-read XXE strategy; the
#: OOB canary cannot reach the host), reflected XSS inside a <script> string (needs a
#: </script> breakout), in a meta-refresh attribute, and in the page parameter's href
#: attributes.
GT_MISSES = {"MUTL-0022", "MUTL-0025", "MUTL-0027", "MUTL-0033"}


def test_mutillidae_fixture_scores_ldap_xpath_and_the_regression_classes(lab_factory):
    lab = lab_factory("mutillidae")
    _up(lab)
    gt_dir = REPO / "lab" / "ground-truth-mutillidae"
    store = lab.tmp / "mutillidae_gt.db"
    res = lab.fuzzlab("auto", "--base-url", lab.base, "--ground-truth", str(gt_dir),
                      "--points", "ground-truth", "--identity", lab.meta.identity, "--oob",
                      "--store", str(store), "--authorized")
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-3000:]
    gt, report, _checked = _score(store, gt_dir)
    floor = {c.case_id for c in gt.positives()} - GT_MISSES
    assert {c.case_id for c in gt.positives()
            if c.vuln_class in ("ldap_injection", "xpath_injection")} <= floor
    assert floor <= set(report.matched), (sorted(floor - set(report.matched)),
                                          report.as_dict())
    assert report.fp == 0, report.false_alarms
