"""Parallel exploration workers (`ExploreOptions.workers`, `Explorer.run`): the
coordination protocol, tested without a browser.

Each worker's browser half (`_run_worker`) is replaced by one that calls `_work` with a
stub context; `_seed` and `_process` are replaced by a synthetic state graph. What is
checked is what the threads share: every state is processed exactly once, the run ends
when the frontier is empty and no worker holds a state, a budget stops every worker, a
worker's exception reaches the caller, and action ids stay unique under contention."""

from __future__ import annotations

import threading
import time

import pytest

from fuzzlab.disco import explore
from fuzzlab.disco.explore import ExploreOptions, Explorer, State

START = "http://127.0.0.1:9/"


class _Ctx:
    def new_page(self):
        return object()


def _explorer(monkeypatch, graph, *, workers, delay=0.01, **opts):
    """An explorer whose state graph is ``graph`` (state -> children found there)."""
    processed: list[tuple[str, str]] = []

    def run_worker(self, *, seed):
        self._ctx = _Ctx()
        try:
            self._work(None, None, seed=seed)
        except BaseException as exc:  # as the real one hands it on
            with self._shared.lock:
                self._shared.failure = self._shared.failure or exc
                self._shared.stop = self._shared.stop or "error"
                self._shared.lock.notify_all()

    def seed(self, page, ctx):
        with self._shared.lock:
            self._shared.frontier.push(State("root", START, START))
            self._shared.known.add("root")
            self.report.states = 1

    def process(self, state, page, browser, pw):
        processed.append((state.fp, threading.current_thread().name))
        time.sleep(delay)                     # a restore and its actions take time
        with self._shared.lock:
            for child in graph.get(state.fp, ()):
                if child not in self._shared.known and \
                        len(self._shared.known) < self.opts.max_states:
                    # a distinct letters-only route per state: routes fold digits, and
                    # the per-route cap is not what is tested here
                    url = START + "#/" + "".join(
                        chr(97 + int(c)) if c.isdigit() else "x" for c in child)
                    if self._shared.frontier.push(State(child, url, url)):
                        self._shared.known.add(child)
                        self.report.states = len(self._shared.known)
                        self._shared.lock.notify_all()
        if state.fp == "boom":
            raise RuntimeError("worker failed")
        return page

    monkeypatch.setattr(Explorer, "_run_worker", run_worker)
    monkeypatch.setattr(Explorer, "_seed", seed)
    monkeypatch.setattr(Explorer, "_process", process)
    ex = Explorer(START, scope_urls=[START], proxy="127.0.0.1:2",
                  options=ExploreOptions(workers=workers, **opts))
    return ex, processed


def _tree(depth: int, fanout: int) -> dict[str, list[str]]:
    graph, level = {}, ["root"]
    for d in range(depth):
        nxt = []
        for node in level:
            graph[node] = [f"{node}.{i}" for i in range(fanout)]
            nxt += graph[node]
        level = nxt
    return graph


def _run_bounded(ex, seconds=30):
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("report", ex.run()), daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), "the run did not terminate"
    return out.get("report")


def test_every_state_is_explored_exactly_once_and_the_run_ends(monkeypatch):
    graph = _tree(depth=3, fanout=3)                       # 1 + 3 + 9 + 27 states
    ex, processed = _explorer(monkeypatch, graph, workers=4, max_states=100)
    report = _run_bounded(ex)
    states = [fp for fp, _ in processed]
    assert sorted(states) == sorted(set(states)) and len(states) == 40
    assert report.states == 40 and report.budget_hit is None
    assert len({name for _, name in processed}) == 4       # all four took states


def test_one_worker_explores_the_same_graph_inline(monkeypatch):
    graph = _tree(depth=2, fanout=3)
    ex, processed = _explorer(monkeypatch, graph, workers=1, max_states=100, delay=0)
    report = _run_bounded(ex)
    assert len(processed) == 13 and report.states == 13
    assert len({name for _, name in processed}) == 1        # inline: no extra threads


def test_the_deadline_stops_every_worker(monkeypatch):
    """The deadline ends the whole run (``max_states`` / ``max_actions`` end only
    exploration, CC-CRAWL-0038)."""
    graph = _tree(depth=6, fanout=4)                       # far more than the time allows
    ex, processed = _explorer(monkeypatch, graph, workers=3, max_states=10_000,
                              deadline_s=0.3)
    report = _run_bounded(ex)
    assert report.budget_hit == "deadline"
    assert 0 < len(processed) < 5461


def test_a_failing_worker_stops_the_run_and_its_exception_reaches_the_caller(monkeypatch):
    graph = {"root": ["a", "boom", "b", "c"], "a": ["a1", "a2"], "b": ["b1"], "c": ["c1"]}
    ex, _processed = _explorer(monkeypatch, graph, workers=3, max_states=100)
    with pytest.raises(RuntimeError, match="worker failed"):
        ex.run()


def test_action_ids_stay_unique_across_workers():
    ex = Explorer(START, scope_urls=[START], proxy="127.0.0.1:2",
                  options=ExploreOptions(workers=4))
    workers = [ex] + [ex._clone() for _ in range(3)]
    ids: list[str] = []
    lock = threading.Lock()

    def tag_many(w):
        mine = [w._tag(None, "act") for _ in range(500)]
        with lock:
            ids.extend(mine)
        assert w._tag_headers[explore.ACTION_HEADER] == mine[-1]   # its own tag

    threads = [threading.Thread(target=tag_many, args=(w,)) for w in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ids) == 2000 and len(set(ids)) == 2000


def test_a_clone_shares_the_run_and_owns_its_browser_state():
    ex = Explorer(START, scope_urls=[START], proxy="127.0.0.1:2",
                  options=ExploreOptions(workers=2))
    other = ex._clone()
    assert other._shared is ex._shared and other.report is ex.report
    assert other._tag_headers is not ex._tag_headers
    assert other._net is not ex._net                     # its own network quiet


@pytest.mark.parametrize("n", [0, explore.MAX_WORKERS + 1])
def test_the_worker_count_is_bounded(n):
    with pytest.raises(ValueError, match="workers"):
        Explorer(START, scope_urls=[START], proxy="127.0.0.1:2",
                 options=ExploreOptions(workers=n))


def test_the_cli_refuses_a_bad_worker_count_before_any_side_effect(tmp_path, capsys):
    from fuzzlab.disco import cli
    rc = cli.main(["capture", "--start", START, "--out", str(tmp_path / "o"),
                   "--workers", "0", "--authorized"])
    assert rc == 2 and "--workers must be" in capsys.readouterr().err
    assert not (tmp_path / "o").exists()
