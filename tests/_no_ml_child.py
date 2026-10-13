"""Child process for `tests/test_no_ml.py`: the toolkit with `fuzzlab.ml` absent.

A meta-path finder *raises* `ModuleNotFoundError(name="fuzzlab.ml")` for the ML package
and every submodule — exactly what a build without the package raises — before anything
of `fuzzlab` is imported. Then it exercises the scan, the report and the web app and
prints one JSON object for the parent to assert on. Never imports a helper that itself
imports `fuzzlab.ml` (only `tests.test_auto`, which does not).

Usage: ``python tests/_no_ml_child.py check <seeded.db> <run_id> <workdir>``
       ``python tests/_no_ml_child.py serve <seeded.db> <port>``
"""

from __future__ import annotations

import importlib.abc
import sys


class _BlockML(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "fuzzlab.ml" or name.startswith("fuzzlab.ml."):
            raise ModuleNotFoundError(f"No module named {name!r}", name="fuzzlab.ml")
        return None


import os  # noqa: E402

# FUZZLAB_NOML_REAL=1: run against a genuinely ML-free *built* package (first on
# PYTHONPATH, CC-ML-0022) — no blocker; the package is really absent.
_DROPPED_FINDERS: list[str] = []
if not os.environ.get("FUZZLAB_NOML_REAL"):
    sys.meta_path.insert(0, _BlockML())
else:
    # A development checkout's *editable* install adds a meta-path finder that maps
    # `fuzzlab.*` back to the source tree whenever the built tree lacks a module — so it
    # would resurrect `fuzzlab.ml`. A real (non-editable) install has no such finder.
    for finder in list(sys.meta_path):
        if type(finder).__name__.startswith("__editable__") or \
                getattr(finder, "__module__", "").startswith("__editable__"):
            sys.meta_path.remove(finder)
            _DROPPED_FINDERS.append(getattr(finder, "__module__", type(finder).__name__))

import contextlib  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
from pathlib import Path  # noqa: E402


def _ml_blocked() -> bool:
    try:
        import fuzzlab.ml  # noqa: F401
    except ModuleNotFoundError as exc:
        return exc.name == "fuzzlab.ml"
    return False


def _auto(argv, workdir: Path, store: Path):
    from fuzzlab.harness import auto_cli
    from tests.test_auto import GT_DIR, AutoSender
    auto_cli.make_probe_sender = lambda base, identity=None: AutoSender()
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = auto_cli.main(["--base-url", "http://127.0.0.1:8080", "--store", str(store),
                                "--spider-db", str(workdir / "none.db"),
                                "--ground-truth", GT_DIR, "--points", "ground-truth",
                                "--authorized", *argv])
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def _app(seeded: Path, port: int = 8787):
    from fuzzlab.core.config import load_config
    from fuzzlab.web import labcontrol
    from fuzzlab.web.app import create_app

    async def no_engine():                       # /lab must not shell out to labctl.sh
        return {}, None
    labcontrol.fetch_states = no_engine
    cfg = load_config(overrides={"store_path": str(seeded), "web_port": port,
                                 "target_base_url": "http://127.0.0.1:8080"}, environ={})
    return create_app(cfg)


def check(seeded: Path, run_id: int, workdir: Path) -> dict:
    from fuzzlab.core.store import Store
    from fuzzlab.report.report import build_report, format_text
    import fuzzlab
    out: dict = {"ml_blocked": _ml_blocked(), "fuzzlab_path": fuzzlab.__file__,
                 "dropped_finders": _DROPPED_FINDERS}

    fresh = workdir / "fresh.db"
    rc, stdout, _ = _auto([], workdir, fresh)
    with Store(fresh) as store:
        out["scan"] = {"rc": rc, "findings": store.conn.execute(
            "SELECT COUNT(*) FROM finding").fetchone()[0], "summary": stdout}
    refused = workdir / "refused.db"
    rc, _, err = _auto(["--score"], workdir, refused)
    runs = 0
    if refused.exists():
        with Store(refused) as store:
            runs = store.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0]
    out["score_flag"] = {"rc": rc, "stderr": err, "runs": runs}

    from fuzzlab.harness import flow_anomaly_cli        # CC-FUZZ-0054: exits 2 cleanly
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        rc = flow_anomaly_cli.main(["--store", str(seeded), "--run", str(run_id)])
    out["flow_anomaly"] = {"rc": rc, "stderr": err.getvalue()}

    with Store(seeded) as store:
        rep = build_report(store, run_id)
    out["report"] = {"models": rep["models"], "models_unavailable": rep.get("models_unavailable"),
                     "plugins": rep["plugins"], "text": format_text(rep)}

    from fastapi.responses import HTMLResponse
    from fastapi.routing import APIRoute
    from tests._webclient import web_client
    app = _app(seeded)
    client = web_client(app)
    finding_id = None
    with Store(seeded) as store:
        finding_id = store.conn.execute("SELECT MIN(id) FROM finding").fetchone()[0]
    fill = {"run_id": run_id, "finding_id": finding_id}
    pages = {}
    for route in app.routes:
        if (not isinstance(route, APIRoute) or "GET" not in route.methods
                or route.path.startswith("/api/") or route.response_class is not HTMLResponse):
            continue
        params = re.findall(r"{(\w+)}", route.path)
        if any(p not in fill or fill[p] is None for p in params):
            pages[route.path] = "unfillable"
            continue
        path = re.sub(r"{(\w+)}", lambda m: str(fill[m.group(1)]), route.path)
        pages[path] = client.get(path).status_code
    out["pages"] = pages
    data = client.get("/api/ml/data").json()
    out["ml_data"] = {k: (v.get("available"), v.get("reason")) for k, v in data.items()
                      if isinstance(v, dict)}
    out["run_page"] = client.get(f"/runs/{run_id}").text
    return out


def serve(seeded: Path, port: int) -> None:
    import uvicorn
    print("ML_BLOCKED" if _ml_blocked() else "ML_PRESENT", flush=True)
    uvicorn.run(_app(seeded, port), host="127.0.0.1", port=port, log_level="error")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "check":
        print(json.dumps(check(Path(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]))))
    else:
        serve(Path(sys.argv[2]), int(sys.argv[3]))
