"""Live boot of the DVWA external lab (CC-LAB-0430..0433; FR-LAB-430..433):
``labctl.sh reset dvwa --authorized`` (database built by setup.php, both seeded accounts
verified, security level low) then a scored ``fuzzlab auto --points ground-truth
--identity`` run.

Gated by ``FUZZLAB_LIVE_EXTERNAL_LABS=1`` (the same gate and harness as
`tests/test_external_labs_live.py`: its own compose project, a free loopback port, a
throwaway keyring, torn down by the exact project label)."""

from __future__ import annotations

import os
import sys

from tests.test_external_labs_live import (REPO, _score, _up, lab_factory,  # noqa: F401
                                           pytestmark)
from fuzzlab.procutil import run_bounded

#: Confirmed live on 2026-11-20 (CC-LAB-0433). A floor only grows.
DVWA_GT_FLOOR = {"DVWA-0001", "DVWA-0003", "DVWA-0004", "DVWA-0005", "DVWA-0013",
                 "DVWA-0014", "DVWA-0015"}


def _store_accounts(lab) -> None:
    """Upstream's seeded accounts (dvwa/includes/DBMS/MySQL.php), into the throwaway
    keyring; passed in the child's environment, never argv."""
    code = ("from fuzzlab.core.credentials import CredentialStore\n"
            "import os\n"
            "s = CredentialStore(allow_env=False)\n"
            "s.set('127.0.0.1', 'dvwa-user', 'admin', os.environ['P1'])\n"
            "s.set('127.0.0.1', 'dvwa-peer', 'gordonb', os.environ['P2'])\n")
    res = run_bounded([sys.executable, "-c", code], timeout=60,
                      env={**lab.env, "P1": "password", "P2": "abc123"})
    assert res.returncode == 0, res.stderr


def test_dvwa_fixture_boots_at_low_and_scores_its_confirmed_rows(lab_factory):  # noqa: F811
    lab = lab_factory("dvwa")
    _store_accounts(lab)
    _up(lab)
    gt_dir = REPO / "lab" / "ground-truth-dvwa"
    store = lab.tmp / "dvwa_gt.db"
    res = lab.fuzzlab("auto", "--base-url", lab.base, "--ground-truth", str(gt_dir),
                      "--points", "ground-truth", "--identity", lab.meta.identity,
                      "--browser", "--oob", "--store", str(store), "--authorized",
                      timeout=1800)
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-3000:]
    _gt, report, _checked = _score(store, gt_dir)
    assert DVWA_GT_FLOOR <= set(report.matched), (sorted(DVWA_GT_FLOOR - set(report.matched)),
                                                  report.as_dict())
    assert report.fp == 0, report.false_alarms
