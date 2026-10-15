"""FR-CORE-400 per command: ``--store`` is optional everywhere this lane owns.

Readers (`report`, `flow-anomaly`, `reveal-holdout`) never create a store; writers
(`mutate-run`, `proxy --record`) create it on first use and reuse it; the resolved store
is named where the design says (stdout in run summaries, stderr beside read-only output);
``--store`` still wins and ``FUZZLAB_STORE`` is honoured. Plus the web UI compatibility
pins: every launcher spec still builds an argv its real parser accepts.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.cli import main as fuzzlab_main
from fuzzlab.core.storepath import DEFAULT_STORE
from fuzzlab.core.store import Store


@pytest.fixture
def cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _seed_run(path) -> int:
    with Store(path) as store:
        r = store.start_run("auto", "127.0.0.1:8080")
    return r


def _usage_error(argv) -> int:
    with pytest.raises(SystemExit) as exc:
        fuzzlab_main(argv)
    return exc.value.code


# --- report ---------------------------------------------------------------------------

def test_report_reads_the_default_store_and_names_it_on_stderr(cwd, capsys):
    _seed_run(cwd / DEFAULT_STORE)
    assert fuzzlab_main(["report"]) == 0
    out, err = capsys.readouterr()
    assert "fuzzlab run #1" in out and f"store: {cwd / DEFAULT_STORE} (default)" in err
    assert fuzzlab_main(["report", "--json"]) == 0
    out, err = capsys.readouterr()
    json.loads(out)                                          # stdout stays pure JSON
    assert "store:" in err


def test_report_refuses_a_missing_store_and_creates_none(cwd, capsys):
    assert _usage_error(["report"]) == 2
    assert "no such store" in capsys.readouterr().err
    assert _usage_error(["report", "--store", "typo.db"]) == 2
    assert list(cwd.iterdir()) == []                         # it used to create typo.db


def test_report_honours_fuzzlab_store_and_store_still_wins(cwd, monkeypatch, capsys):
    _seed_run(cwd / "env.db")
    _seed_run(cwd / "flag.db")
    _seed_run(cwd / "flag.db")
    monkeypatch.setenv("FUZZLAB_STORE", str(cwd / "env.db"))
    assert fuzzlab_main(["report"]) == 0
    out, err = capsys.readouterr()
    assert "run #1" in out and "(FUZZLAB_STORE)" in err
    assert fuzzlab_main(["report", "--store", str(cwd / "flag.db")]) == 0
    out, err = capsys.readouterr()
    assert "run #2" in out and "(--store)" in err


# --- flow-anomaly / train flow-anomaly (a non-creating writer) -------------------------

def test_flow_anomaly_uses_the_default_store_and_names_it(cwd, capsys):
    pytest.importorskip("fuzzlab.ml.flow_anomaly")
    from tests.test_ml_batch4 import _flow
    with Store(cwd / DEFAULT_STORE) as store:
        r = store.start_run("proxy", "h")
        for i in range(12):
            _flow(store, r, f"http://a/p{i}", host="a", elapsed=10.0 + i)
        store.conn.commit()
    assert fuzzlab_main(["train", "flow-anomaly", "--run", str(r)]) == 0
    out = capsys.readouterr().out
    assert "flow anomalies" in out and f"store: {cwd / DEFAULT_STORE} (default)" in out


@pytest.mark.parametrize("cmd", [["flow-anomaly"], ["train", "flow-anomaly"]])
def test_flow_anomaly_refuses_a_missing_store_and_creates_none(cmd, cwd):
    assert _usage_error([*cmd, "--run", "1"]) == 2
    assert list(cwd.iterdir()) == []


# --- reveal-holdout / train reveal-holdout --------------------------------------------

def test_reveal_names_the_store_before_the_reveal_is_counted(cwd, capsys, monkeypatch):
    from fuzzlab.core import sealed
    from fuzzlab.harness import reveal_cli
    from fuzzlab.ml.train import train_and_score
    from tests.test_ml_holdout_calibration import _seed
    with Store(cwd / DEFAULT_STORE) as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
    order = []
    real = sealed.reveal

    def spy(store, run_id):
        order.append(("reveal", capsys.readouterr().err))
        return real(store, run_id)
    monkeypatch.setattr(reveal_cli, "reveal", spy)
    assert fuzzlab_main(["train", "reveal-holdout", "--run", str(r)]) == 0
    assert order and f"store: {cwd / DEFAULT_STORE} (default)" in order[0][1]
    out = capsys.readouterr().out
    assert "reveal #1" in out and f"run: auto on 127.0.0.1:8080" in out
    assert f"store {cwd / DEFAULT_STORE}" in out


@pytest.mark.parametrize("cmd", [["reveal-holdout"], ["train", "reveal-holdout"]])
def test_reveal_refuses_a_missing_store_and_creates_none(cmd, cwd):
    assert _usage_error([*cmd, "--run", "1"]) == 2
    assert list(cwd.iterdir()) == []


# --- mutate-run / train mutate (a writer) ----------------------------------------------

@pytest.fixture
def offline_mutation(monkeypatch):
    """The real CLI with the network half replaced: no sender, a canned search."""
    from fuzzlab.mutation import cli as mcli
    monkeypatch.setattr(mcli, "make_probe_sender", lambda *a, **k: object())
    summary = {"bases": 1, "blocked": 0, "bypasses": 0, "recorded": 0, "results": []}
    monkeypatch.setattr(mcli.mrun, "run_mutation", lambda **kw: summary)


MUTATE = ["--url", "http://127.0.0.1:9/x", "--param", "id"]


@pytest.mark.parametrize("cmd", [["mutate-run"], ["train", "mutate"]])
def test_mutate_creates_the_default_store_then_reuses_it(cmd, cwd, offline_mutation,
                                                          capsys):
    assert fuzzlab_main([*cmd, *MUTATE, "--authorized"]) == 0
    assert fuzzlab_main([*cmd, *MUTATE, "--authorized"]) == 0
    with Store(cwd / DEFAULT_STORE) as store:
        assert store.conn.execute("SELECT COUNT(*) FROM run WHERE tool='mutate'"
                                  ).fetchone()[0] == 2
    assert f"store: {cwd / DEFAULT_STORE} (default)" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [
    MUTATE,                                                   # no --authorized
    [*MUTATE, "--store", "", "--authorized"],
    [*MUTATE, "--store", "no/dir/x.db", "--authorized"],
])
def test_mutate_usage_errors_create_nothing(argv, cwd, offline_mutation):
    assert _usage_error(["train", "mutate", *argv]) == 2
    assert list(cwd.iterdir()) == []


def test_mutate_dry_run_creates_nothing_and_names_the_store(cwd, capsys):
    assert fuzzlab_main(["train", "mutate", *MUTATE, "--dry-run"]) == 0
    assert f"store: {cwd / DEFAULT_STORE} (default)" in capsys.readouterr().out
    assert list(cwd.iterdir()) == []


# --- proxy --record ---------------------------------------------------------------------

def test_proxy_records_nothing_unless_asked(cwd, capsys):
    from fuzzlab.proxy.cli import main as proxy_main
    assert proxy_main(["--dry-run"]) == 0
    assert "store:" not in capsys.readouterr().out
    assert proxy_main(["--record", "--dry-run"]) == 0
    assert f"store: {cwd / DEFAULT_STORE} (default)" in capsys.readouterr().out
    assert proxy_main(["--record", "--store", "p.db", "--dry-run"]) == 0
    assert f"store: {cwd / 'p.db'} (--store)" in capsys.readouterr().out
    assert list(cwd.iterdir()) == []


@pytest.mark.parametrize("argv, message", [
    (["--record"], "--authorized"),
    (["--record", "--authorized", "--host", "0.0.0.0"], "loopback"),
    (["--record", "--authorized", "--store", "no/dir/x.db"], "does not exist"),
])
def test_proxy_record_checks_come_before_any_store_work(argv, message, cwd, capsys):
    from fuzzlab.proxy.cli import main as proxy_main
    with pytest.raises(SystemExit) as exc:
        proxy_main(argv)
    assert exc.value.code == 2 and message in capsys.readouterr().err
    assert list(cwd.iterdir()) == []


# --- the web UI's specs still build an argv their real parser accepts ----------------

def _fill(opt):
    if opt.type == "bool":
        return False
    if opt.choices:
        return opt.choices[0]
    if opt.type in ("int", "float"):
        return "1"
    return "http://127.0.0.1:8080" if "url" in opt.dest or opt.dest == "start" else "v"


def test_every_launcher_spec_still_builds_an_argv_its_parser_accepts():
    from fuzzlab.cli_taxonomy import PARSERS
    from fuzzlab.web import commandspec
    from fuzzlab.web.runner import build_flags
    checked = []
    for spec in commandspec.all_specs():
        if spec.subcommands:
            # `session`: the launcher builds no subcommand argv (BUG-0400's stated scope);
            # its parser must still parse each subcommand with its required options
            parser = PARSERS[spec.name]()
            for sub, opts in spec.subcommands.items():
                argv = [sub]
                for o in opts:
                    if o.required:
                        argv += [o.name, _fill(o)]
                parser.parse_args(argv)
            checked.append(spec.name)
            continue
        if not spec.options:
            continue
        values = {o.dest: _fill(o) for o in spec.options if o.required}
        argv = build_flags(spec, values)
        PARSERS[spec.name]().parse_args(argv)
        checked.append(spec.name)
    assert {"auto", "crawl", "report", "mutate-run", "proxy", "flow-anomaly",
            "session"} <= set(checked)


def test_launcher_pins_store_optional_and_record_offered():
    from fuzzlab.web import commandspec
    for name in ("report", "mutate-run", "flow-anomaly"):
        store = next(o for o in commandspec.spec(name).options if o.dest == "store")
        assert store.required is False, name
    assert any(o.dest == "record" and o.type == "bool"
               for o in commandspec.spec("proxy").options)
    auto = next(o for o in commandspec.spec("auto").options if o.dest == "store")
    assert auto.required is True                     # auto is Phase 2 (locked file)


def test_proxy_export_ca_comes_before_any_store_resolution(cwd, capsys):
    """Review A7: `--export-ca` records nothing, so a store flag never stops it."""
    pytest.importorskip("cryptography")
    from fuzzlab.proxy.cli import main as proxy_main
    assert proxy_main(["--export-ca", "--store", "", "--ca-dir", str(cwd / "ca")]) == 0
    assert "CA certificate" in capsys.readouterr().out
    assert not (cwd / DEFAULT_STORE).exists()


def test_proxy_explicit_empty_store_is_a_usage_error(cwd, capsys):
    """`--store ""` used to mean "do not record" (falsy); it is now refused, like every
    other command's (PA-0105) -- recording is asked for with --record or a real path."""
    from fuzzlab.proxy.cli import main as proxy_main
    with pytest.raises(SystemExit) as exc:
        proxy_main(["--store", "", "--authorized"])
    assert exc.value.code == 2 and "empty path" in capsys.readouterr().err
