"""Live-boot tests of the external lab fixtures (bWAPP, Juice Shop): CC-LAB-0300,
FR-LAB-304. Gated by ``FUZZLAB_LIVE_EXTERNAL_LABS=1``.

Without the flag every test skips, saying so. With it, a missing container engine or a
failed pull/build **fails**. Each test brings its fixture up through ``lab/labctl.sh``
under its own compose project (``FUZZLAB_EXT_PROJECT_SUFFIX``) on a free loopback port,
so the operator's own stack is never touched, with a throwaway encrypted keyring, and
tears it down in a finalizer by the exact compose project label (works even when ``up``
died before any container id was recorded), then asserts nothing of the project is left.

Two scored passes per lab (design rev 2, 5.2): the **crawl pass** (`fuzzlab crawl` then
`fuzzlab auto --points crawl`) and the **gt pass** (ground-truth points, run in-process so
the test owns the OOB listener and can read the run's own session). Each pass asserts a
stated floor of matched case ids (the set confirmed live when this was built), that no
negative case was flagged, and that every positive tagged for the pass got a checked
candidate (a tagged row without one has a wrong reach tag).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
from contextlib import closing
from pathlib import Path

import pytest

from fuzzlab.procutil import run_bounded

REPO = Path(__file__).resolve().parent.parent
LABCTL = REPO / "lab" / "labctl.sh"
FLAG = "FUZZLAB_LIVE_EXTERNAL_LABS"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(os.environ.get(FLAG) != "1",
                       reason=f"live external-lab tests: set {FLAG}=1 (needs docker or podman "
                              f"with a compose provider; boots bWAPP / Juice Shop on loopback)"),
]

#: Floors: confirmed live on 2026-10-15 (CC-LAB-0300 Effectiveness). A floor only grows.
JUICE_GT_FLOOR = {"JUICE-0002", "JUICE-0003", "JUICE-0004", "JUICE-0006"}
JUICE_CRAWL_FLOOR = {"JUICE-0003"}
BWAPP_GT_FLOOR = {"BWAPP-0001", "BWAPP-0002", "BWAPP-0003", "BWAPP-0004", "BWAPP-0005",
                  "BWAPP-0011", "BWAPP-0012", "BWAPP-0013", "BWAPP-0014", "BWAPP-0028",
                  "BWAPP-0029", "BWAPP-0030", "BWAPP-0031", "BWAPP-0032", "BWAPP-0042",
                  "BWAPP-0043", "BWAPP-0044", "BWAPP-0045", "BWAPP-0051", "BWAPP-0052"}
BWAPP_CRAWL_FLOOR = {"BWAPP-0001", "BWAPP-0002", "BWAPP-0003", "BWAPP-0004", "BWAPP-0006",
                     "BWAPP-0008", "BWAPP-0009", "BWAPP-0011", "BWAPP-0012", "BWAPP-0013",
                     "BWAPP-0014", "BWAPP-0015", "BWAPP-0016", "BWAPP-0017", "BWAPP-0018",
                     "BWAPP-0019", "BWAPP-0020", "BWAPP-0021", "BWAPP-0022", "BWAPP-0023",
                     "BWAPP-0024", "BWAPP-0025", "BWAPP-0026", "BWAPP-0027", "BWAPP-0028",
                     "BWAPP-0029", "BWAPP-0030", "BWAPP-0031", "BWAPP-0032", "BWAPP-0034",
                     "BWAPP-0035", "BWAPP-0036", "BWAPP-0037", "BWAPP-0038", "BWAPP-0039",
                     "BWAPP-0040", "BWAPP-0041", "BWAPP-0042", "BWAPP-0043", "BWAPP-0044",
                     "BWAPP-0051", "BWAPP-0052", "BWAPP-0053", "BWAPP-0054", "BWAPP-0055",
                     "BWAPP-0056"}


def _engine() -> str:
    for eng in ("docker", "podman"):
        if shutil.which(eng) and run_bounded([eng, "info"], timeout=60).returncode == 0:
            return eng
    pytest.fail(f"{FLAG}=1 but no working docker/podman engine")


def _free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _chromium() -> str | None:
    found = sorted(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux/chrome"))
    return str(found[-1]) if found else os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")


class Lab:
    def __init__(self, name: str, tmp: Path, engine: str):
        from fuzzlab.lab_fixtures.external import LAB_META, compose_project, discover_labs
        self.name, self.tmp, self.engine = name, tmp, engine
        self.meta = LAB_META[name]
        self.port = _free_port()
        self.suffix = f"-pytest-{os.getpid()}-{secrets.token_hex(2)}"
        self.project = compose_project(discover_labs()[name]) + self.suffix
        self.base = f"http://127.0.0.1:{self.port}"
        self.env = {**os.environ,
                    # the tree under test, not whatever fuzzlab the venv has installed
                    "PYTHONPATH": str(REPO),
                    "FUZZLAB_PYTHON": os.sys.executable,
                    "FUZZLAB_EXT_PROJECT_SUFFIX": self.suffix,
                    self.meta.port_env: str(self.port),
                    "FUZZLAB_KEYRING_PATH": str(tmp / "keyring.enc"),
                    # header points over bWAPP's ~150 pages need more than the default 5000
                    "FUZZLAB_BUDGET_TOTAL": "30000",
                    "FUZZLAB_KEYRING_PASSPHRASE": secrets.token_hex(16)}
        chrome = _chromium()
        if chrome:
            self.env["PLAYWRIGHT_CHROMIUM_EXECUTABLE"] = chrome

    def labctl(self, *args: str, timeout: float = 1800):
        return run_bounded([str(LABCTL), *args], timeout=timeout, env=self.env,
                           cwd=str(LABCTL.parent))

    def fuzzlab(self, *args: str, timeout: float = 3600):
        return run_bounded([os.sys.executable, "-m", "fuzzlab.cli", *args], timeout=timeout,
                           env=self.env, cwd=str(self.tmp))

    def project_ids(self, kind: str = "ps") -> list[str]:
        """The project's resources by its exact label; an engine error fails (PA-0310(2):
        it never reads as "nothing left")."""
        label = f"label=com.docker.compose.project={self.project}"
        argv = ([self.engine, "ps", "-a", "-q", "--filter", label] if kind == "ps"
                else [self.engine, kind, "ls", "-q", "--filter", label])
        res = run_bounded(argv, timeout=60)
        assert res.returncode == 0, (argv, res.stderr[-500:])
        return res.stdout.split()

    def teardown(self) -> list[str]:
        """Every step runs whatever the one before did; errors are collected, not raised
        midway (review A8). Returns what is left of the project."""
        errors: list[str] = []
        try:
            self.labctl("down", self.name, timeout=600)
        except Exception as exc:  # noqa: BLE001 - the label sweep below still runs
            errors.append(f"labctl down: {exc!r}")
        kinds = [("ps", ["rm", "-f"]), ("network", ["network", "rm"]),
                 ("volume", ["volume", "rm", "-f"]), ("image", ["image", "rm", "-f"])]
        if self.engine == "podman":
            kinds.insert(1, ("pod", ["pod", "rm", "-f"]))
        for kind, rm in kinds:
            try:
                ids = self.project_ids(kind)
                if ids:
                    run_bounded([self.engine, *rm, *ids], timeout=300)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{kind}: {exc!r}")
        kinds_left = ["ps", "volume", "network", "image"] + (
            ["pod"] if self.engine == "podman" else [])
        try:
            left = [i for kind in kinds_left for i in self.project_ids(kind)]
        except AssertionError as exc:
            return errors + [f"cannot list what is left of {self.project}: {exc}"]
        return errors + [f"{self.project} left {left}"] if left else errors

    def store_credential(self, username: str, password: str) -> None:
        code = ("from fuzzlab.core.credentials import CredentialStore\n"
                "import os\n"
                "CredentialStore(allow_env=False).set('127.0.0.1', os.environ['I'], "
                "os.environ['U'], os.environ['P'])\n")
        res = run_bounded([os.sys.executable, "-c", code], timeout=60,
                          env={**self.env, "I": self.meta.identity, "U": username, "P": password})
        assert res.returncode == 0, res.stderr

    def keyring_env(self):
        """Apply this lab's keyring to the current process (for in-process passes)."""
        return {k: self.env[k] for k in ("FUZZLAB_KEYRING_PATH", "FUZZLAB_KEYRING_PASSPHRASE")}


@pytest.fixture
def lab_factory(tmp_path, monkeypatch):
    engine = _engine()
    labs: list[Lab] = []

    def make(name: str) -> Lab:
        lab = Lab(name, tmp_path, engine)
        labs.append(lab)
        return lab

    yield make
    problems = []
    for lab in labs:
        problems += lab.teardown()
    assert problems == [], problems


def _sender(base: str, identity: str, cls=None):
    """The authenticated sender `make_probe_sender` builds, keeping its session manager
    so the test can read the run's own session afterwards."""
    from fuzzlab.tools.authhttp import make_auth_with_isolation
    from fuzzlab.tools.probesender import SeamProbeSender
    manager, client, isolated = make_auth_with_isolation(base, 15.0)
    sender = (cls or SeamProbeSender)(client, identity, manager=manager, base_url=base,
                                      isolated_client=isolated)
    return sender, manager


def _get(url: str, headers=None):
    """A direct check of the lab: no proxy from the environment (the run's cookie must
    never go to a proxy, PA-0082), no redirects."""
    import requests
    s = requests.Session()
    s.trust_env = False
    return s.get(url, headers=headers or {}, timeout=15, allow_redirects=False)


def _up(lab: Lab) -> None:
    res = lab.labctl("reset", lab.name, "--authorized")
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-3000:]
    st = lab.labctl("status", lab.name, timeout=300)
    assert st.returncode == 0, st.stdout + st.stderr


# --- scoring helpers ---------------------------------------------------------------

def _reach(case) -> set[str]:
    tag = re.match(r"^\[reach: ([^\]]+)\]", case.notes).group(1)
    return set() if tag.startswith("none") else set(tag.split(","))


def _score(store_path: Path, gt_dir: Path):
    from fuzzlab.core.store import Store
    from fuzzlab.harness.integration import detections_from_store
    from fuzzlab.harness.scoring import score
    from fuzzlab.labels import contract
    gt = contract.load(gt_dir)
    with Store(str(store_path)) as s:
        run = s.conn.execute("SELECT MAX(id) m FROM run").fetchone()["m"]
        report = score(detections_from_store(s, run), gt)
        checked = _checked_candidates(s, run)
    return gt, report, checked


def _checked_candidates(store, run_id: int) -> set[tuple[str, str, str, str]]:
    """``(path, method, param, category)`` of every candidate the oracle actually checked
    (status ``CHECKED`` only: not budget-skipped, inconclusive or confirmer-less), read
    from the candidate's own evidence (ground-truth points have no parameter rows)."""
    from fuzzlab.core.oracle_status import CHECKED
    from fuzzlab.core.urls import to_path, to_route_path
    out = set()
    for row in store.conn.execute(
            "SELECT evidence, oracle_status FROM candidate WHERE run_id = ?", (run_id,)):
        if row["oracle_status"] != CHECKED:
            continue
        ev = json.loads(row["evidence"] or "{}")
        url = ev.get("url") or ""
        path = to_route_path(url) if ev.get("location") == "fragment" else to_path(url)
        out.add((path, (ev.get("method") or "GET").upper(), ev.get("param") or "",
                 ev.get("category") or ""))
    return out


def _send_level_control(lab: Lab) -> str:
    """A request carrying ``security_level=1`` that the level log must show (the
    check's positive control); returns its marker."""
    marker = f"fuzzlab-level-control={secrets.token_hex(4)}"
    _get(f"{lab.base}/bWAPP/portal.php?{marker}", {"Cookie": "security_level=1"})
    return marker


def _level_log_text(lab: Lab, markers: list[str], wait: float = 10.0) -> str:
    """The bWAPP web container's stdout, where the access and level logs go (stderr is
    Apache's error log). Apache logs after responding and the engine copies output
    asynchronously, so this waits, bounded, until every control marker is in it."""
    import time
    res = run_bounded([lab.engine, "ps", "-q", "--filter",
                       f"label=com.docker.compose.project={lab.project}", "--filter",
                       "label=com.docker.compose.service=web"], timeout=60)
    ids = res.stdout.split()
    assert res.returncode == 0 and len(ids) == 1, (res.returncode, ids)
    end = time.monotonic() + wait
    while True:
        res = run_bounded([lab.engine, "logs", ids[0]], timeout=300, text=False)
        assert res.returncode == 0, res.stderr[-2000:]
        text = res.stdout.decode("utf-8", errors="replace")
        if all(m in text for m in markers) or time.monotonic() > end:
            return text
        time.sleep(0.5)


def _run_auto_bounded(deadline: float = 3600, **kw) -> None:
    """``run_auto`` in-process (the test owns the OOB listener and the session), on a
    thread with a deadline: a hung pass fails the test instead of blocking pytest.

    Stated limit (review N4): Python cannot stop the thread, so a pass that overruns
    keeps sending until the process exits. It sends only to the loopback lab, which the
    test's teardown then stops, so its later sends are refused connections."""
    import threading

    from fuzzlab.harness.auto import run_auto
    from fuzzlab.core.store import Store
    errors: list[BaseException] = []

    def target():
        try:
            with Store(str(kw.pop("store_path"))) as s:
                run = s.start_run("auto", "127.0.0.1")
                run_auto(store=s, run_id=run, **kw)
        except BaseException as exc:  # noqa: BLE001 - re-raised on the test thread
            errors.append(exc)
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(deadline)
    assert not t.is_alive(), f"in-process gt pass exceeded {deadline}s"
    if errors:
        raise errors[0]


def _assert_pass(gt, report, checked, floor: set[str], pass_tag: str) -> None:
    from fuzzlab.core.runmode import to_category
    assert floor <= set(report.matched), (sorted(floor - set(report.matched)), report.as_dict())
    negatives = {c.case_id for c in gt.negatives()}
    assert not negatives & set(report.false_alarms), report.false_alarms
    for case in gt.cases:
        if pass_tag not in _reach(case):
            continue
        key = (case.url, case.method, case.param, to_category(case.vuln_class))
        assert key in checked, f"{case.case_id} is tagged {pass_tag} but got no checked candidate"


# --- Juice Shop ---------------------------------------------------------------------

def test_juice_shop_fixture_scores_its_confirmed_rows(lab_factory, monkeypatch):
    lab = lab_factory("juice-shop")
    _up(lab)
    cfg = _get(lab.base + "/rest/admin/application-configuration").json()
    assert cfg["config"]["challenges"]["safetyMode"] == "disabled"

    # crawl pass: the login route's JSON request is captured, then crawl points are fuzzed
    spider = lab.tmp / "juice_spider.db"
    res = lab.fuzzlab("crawl", "--start", f"{lab.base}/#/login", "--engine", "playwright",
                      "--max-depth", "0", "--no-reveal", "--submit-spa-forms", "login",
                      "--db", str(spider))
    assert res.returncode == 0, res.stderr[-3000:]
    store = lab.tmp / "juice_crawl.db"
    gt_dir = REPO / "lab" / "ground-truth-juice-shop"
    res = lab.fuzzlab("auto", "--base-url", lab.base, "--spider-db", str(spider),
                      "--store", str(store), "--ground-truth", str(gt_dir), "--points", "crawl",
                      "--identity", lab.meta.identity, "--browser", "--oob", "--authorized")
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-3000:]
    gt, report, checked = _score(store, gt_dir)
    _assert_pass(gt, report, checked, JUICE_CRAWL_FLOOR, "crawl")

    # gt pass, in-process, with an OOB listener this test owns
    for k, v in lab.keyring_env().items():
        monkeypatch.setenv(k, v)
    from fuzzlab.oracle.oob import OobListener
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    from fuzzlab.labels import contract

    class RecordingOob(OobListener):
        def __init__(self):
            super().__init__()
            self.tokens: list[str] = []

        def register(self) -> str:
            token = super().register()
            self.tokens.append(token)
            return token

    from fuzzlab.tools.probesender import SeamProbeSender

    class RecordingSender(SeamProbeSender):
        """Records (url, param, value) of every send, to tie OOB tokens to a point."""
        sends: list = []

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None, prg=False):
            RecordingSender.sends.append((url, param, str(value)))
            return super().send(url, param, value, timing=timing, method=method,
                                location=location, content_type=content_type,
                                entries=entries, prg=prg)

    if lab.env.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE"):
        monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE",
                           lab.env["PLAYWRIGHT_CHROMIUM_EXECUTABLE"])
    oob = RecordingOob()
    oob.start()
    store = lab.tmp / "juice_gt.db"
    sender, manager = _sender(lab.base, lab.meta.identity, cls=RecordingSender)
    # PA-0007: the run's own session reaches the cookie-authenticated /profile
    hdrs = manager.session_headers("127.0.0.1", lab.meta.identity, lab.base, operator=True)
    assert _get(lab.base + "/profile", hdrs).status_code == 200
    try:
        _run_auto_bounded(store_path=store, base_url=lab.base, sender=sender,
                          ground_truth=contract.load(gt_dir), points_source="ground-truth",
                          browser=PlaywrightBrowserExecutor(), oob=oob)
    finally:
        oob.stop()
    gt, report, checked = _score(store, gt_dir)
    _assert_pass(gt, report, checked, JUICE_GT_FLOOR, "gt")
    # JUICE-0005 (design rev 2, 3.3): pinned as a documented miss -- the SSRF probe was
    # made and its callback never arrived, because the bridge network cannot reach the
    # loopback-only listener. The day it is detected this fails and must be updated.
    assert "JUICE-0005" in report.missed
    assert ("/profile/image/url", "POST", "imageUrl", "ssrf") in checked
    image_tokens = [t for t in oob.tokens
                    if any(u.endswith("/profile/image/url") and p == "imageUrl"
                           and f"/cb/{t}" in v for u, p, v in RecordingSender.sends)]
    assert image_tokens, "no OOB callback was sent in /profile/image/url imageUrl"
    assert all(oob.hits(t) == [] for t in image_tokens)


# --- bWAPP --------------------------------------------------------------------------

def test_bwapp_fixture_survives_restart_and_a_killed_db(lab_factory):
    lab = lab_factory("bwapp")
    lab.store_credential("bee", "bug")          # bWAPP's published default identity
    _up(lab)
    # down then up (no reset): data kept, installer idempotent, login still works
    assert lab.labctl("down", lab.name, timeout=600).returncode == 0
    res = lab.labctl("up", lab.name, "--authorized")
    assert res.returncode == 0, res.stderr[-3000:]
    assert "already exists" in res.stdout
    # SIGKILL the db while web is up (stale socket/lock on the tmpfs volume), then up
    db = [c for c in lab.project_ids("ps")
          if "db" in run_bounded([lab.engine, "inspect", "--format",
                                  "{{index .Config.Labels \"com.docker.compose.service\"}}", c],
                                 timeout=60).stdout]
    assert len(db) == 1
    assert run_bounded([lab.engine, "kill", "-s", "KILL", db[0]], timeout=60).returncode == 0
    res = lab.labctl("up", lab.name, "--authorized")
    assert res.returncode == 0, res.stderr[-3000:]


def test_bwapp_build_fails_on_a_wrong_zip_hash(lab_factory):
    lab = lab_factory("bwapp")
    from fuzzlab.lab_fixtures.external import fetch_bwapp
    fetch_bwapp()
    res = run_bounded([lab.engine, "build", "--no-cache", "--build-arg", "BWAPP_SHA256=" + "0" * 64,
                       "-t", f"fuzzlab-bwapp-wronghash{lab.suffix}", "."], timeout=1800,
                      cwd=str(REPO / "lab" / "external" / "bwapp"))
    assert res.returncode != 0
    assert "FAILED" in res.stdout + res.stderr      # sha256sum's own verdict, not a network error


def test_bwapp_fixture_scores_its_confirmed_rows(lab_factory, monkeypatch):
    lab = lab_factory("bwapp")
    lab.store_credential("bee", "bug")
    _up(lab)
    assert lab.project_ids("image"), "the bWAPP build is not visible by its project label"
    gt_dir = REPO / "lab" / "ground-truth-bwapp"
    controls = [_send_level_control(lab)]           # before both passes (review S3)

    # gt pass, in-process (origin base: BUG-0300), reading the run's own session afterwards
    for k, v in lab.keyring_env().items():
        monkeypatch.setenv(k, v)
    if lab.env.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE"):
        monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE",
                           lab.env["PLAYWRIGHT_CHROMIUM_EXECUTABLE"])
    from fuzzlab.labels import contract
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    sender, manager = _sender(lab.base, lab.meta.identity)
    hdrs = manager.session_headers("127.0.0.1", lab.meta.identity, lab.base, operator=True)
    assert _get(lab.base + "/bWAPP/portal.php", hdrs).status_code == 200      # PA-0007
    store = lab.tmp / "bwapp_gt.db"
    _run_auto_bounded(store_path=store, base_url=lab.base, sender=sender,
                      ground_truth=contract.load(gt_dir), points_source="ground-truth",
                      browser=PlaywrightBrowserExecutor())
    gt, report, checked = _score(store, gt_dir)
    _assert_pass(gt, report, checked, BWAPP_GT_FLOOR, "gt")

    # crawl pass (sub-path base for discovery, PA-0113), header points included
    spider = lab.tmp / "bwapp_spider.db"
    res = lab.fuzzlab("crawl", "--start", f"{lab.base}/bWAPP/portal.php", "--engine",
                      "playwright", "--identity", lab.meta.identity,
                      "--follow-selector-forms", "bug", "--no-reveal", "--db", str(spider))
    assert res.returncode == 0, res.stderr[-3000:]
    store = lab.tmp / "bwapp_crawl.db"
    res = lab.fuzzlab("auto", "--base-url", f"{lab.base}/bWAPP/", "--spider-db", str(spider),
                      "--store", str(store), "--ground-truth", str(gt_dir), "--points", "crawl",
                      "--identity", lab.meta.identity, "--browser",
                      "--header-points", "User-Agent,Referer,bWAPP", "--authorized")
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-3000:]
    # The labels rest on bWAPP's security level 0, which bWAPP keeps only in the
    # `security_level` cookie. The fixture logs each request's cookie
    # (apache-level-log.conf). Every request the container served -- bootstrap, both
    # passes, the crawl -- must have carried 0 or no cookie (an allowlist), and both
    # level-1 controls, one sent before the passes and one after, must be logged
    # (BUG-0311). Checked before the floor, so a floor failure keeps this evidence.
    from fuzzlab.lab_fixtures.external import bwapp_level_problems
    controls.append(_send_level_control(lab))
    assert bwapp_level_problems(_level_log_text(lab, controls), controls) == []
    gt, report, checked = _score(store, gt_dir)
    _assert_pass(gt, report, checked, BWAPP_CRAWL_FLOOR, "crawl")
