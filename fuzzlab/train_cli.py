"""``fuzzlab train <sub>`` — the training and benchmark group (FR-FUZZ-400).

Ground truth, scored runs, model training and its modulators, holdouts, calibration, the
model registry and the research learners live here; working runs (fuzzlab used as a tool)
do not take any of them (`docs/CLI_WORKING_VS_TRAINING_DESIGN.md`).

``train run <url>``
    A run scored against ground truth and/or that trains models: the `fuzzlab auto`
    engine with every one of its flags, the target as the first argument, and ``--store``
    optional (`core.storepath`). It must carry at least one training or benchmark choice
    (design D-9) — without one it is a working run under a training name and is refused.
    The user's argv is forwarded to the engine **verbatim** (never re-serialised:
    PA-0400(3)); usage checks run before anything is created (PA-0079).
``train models``
    The saved models, label-free (`ml.model_registry.list_models`); read-only.
``train reveal-holdout`` / ``train flow-anomaly`` / ``train mutate``
    The commands formerly called ``reveal-holdout`` / ``flow-anomaly`` / ``mutate-run``
    (those names still work); each resolves its own store.
"""

from __future__ import annotations

import argparse
import shlex
import sys

from fuzzlab import cli_taxonomy
from fuzzlab.core import storepath

_SUBS = ("run", "models", "reveal-holdout", "flow-anomaly", "mutate")

USAGE = """usage: fuzzlab train <sub> [args]      (fuzzlab train <sub> --help for its options)

Training and benchmark: ground truth, scored runs, model training, holdouts, models
  run <url> [args]       a run scored against ground truth and/or that trains models
                         (the `auto` engine; requires --authorized and at least one
                         training or benchmark choice)
  models [args]          list saved models (the model registry; read-only)
  reveal-holdout [args]  print a run's sealed holdout metrics (counts the reveal)
  flow-anomaly [args]    flag each host's most unusual recorded flows
  mutate [args]          learn + evade the live lab WAF, record variants

Store: --store PATH, else {rule}.
Give benchmark and training runs their own --store when reproducibility matters: bandit
posteriors, holdout reveals and earlier-run training pools are store-wide.
""".format(rule=storepath.DEFAULT_RULE)


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in (*_SUBS, "-h", "--help", "help"):
        if argv:
            print(f"fuzzlab train: unknown subcommand {argv[0]!r}\n", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    sub, rest = argv[0], argv[1:]
    if sub in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    if sub == "run":
        return run_main(rest)
    if sub == "models":
        return models_main(rest)
    if sub == "reveal-holdout":
        from fuzzlab.harness import reveal_cli
        return reveal_cli.main(rest, prog="fuzzlab train reveal-holdout")
    if sub == "flow-anomaly":
        from fuzzlab.harness import flow_anomaly_cli
        return flow_anomaly_cli.main(rest, prog="fuzzlab train flow-anomaly")
    from fuzzlab.mutation import cli as mutation_cli
    return mutation_cli.main(rest, prog="fuzzlab train mutate")


# --- train run ----------------------------------------------------------------------

#: Dests whose presence on the command line decides D-9.
_PRESENCE = ("ground_truth", "holdout", "calibrate", "hybrid", "rank_objective",
             "budget_seed", "budget_method", "mode", "points", "score", "rank", "train_on")


def build_run_parser() -> argparse.ArgumentParser:
    """`auto`'s own parser, copied: the URL positional, ``--store`` optional, presence
    defaults for the D-9 dests (validation only — the engine parses the real argv)."""
    from fuzzlab.harness.auto_cli import build_parser
    return cli_taxonomy.copy_parser(
        build_parser(), prog="fuzzlab train run", url_positional=True, presence=_PRESENCE,
        usage="fuzzlab train run <url> [options]",
        description="A run scored against ground truth and/or that trains models (the "
                    "`auto` engine). The <url> comes first. Needs --authorized and at "
                    "least one training or benchmark choice that takes effect; a plain "
                    "working run is `fuzzlab auto`. Give benchmark and training runs "
                    "their own --store when reproducibility matters: bandit posteriors, "
                    "holdout reveals and earlier-run training pools are store-wide.")


def training_choices(ns: argparse.Namespace) -> list[str]:
    """The training or benchmark choices that take effect (design D-9), by presence on the
    command line. A choice the engine would ignore, or one equal to the working default,
    does not count: applying a saved model (``--score``/``--rank`` with ``--train-on
    saved``), ``--train-on`` alone, ``--calibrate none``, ``--rank-objective pointwise``,
    ``--mode automatic``, ``--points crawl``, and a budget seed or order without
    ``--confirm-budget``."""
    given = lambda d: hasattr(ns, d)  # noqa: E731
    out: list[str] = []
    if given("ground_truth"):
        out.append("--ground-truth")
    if given("points") and ns.points == "ground-truth":
        out.append("--points ground-truth")
    if given("mode") and ns.mode == "manual":
        out.append("--mode manual")
    if given("holdout"):
        out.append("--holdout")
    saved = given("train_on") and ns.train_on == "saved"
    for flag in ("score", "rank"):
        if given(flag) and not saved:
            out.append(f"--{flag}")
    if given("calibrate") and ns.calibrate != "none":
        out.append(f"--calibrate {ns.calibrate}")
    if given("hybrid"):
        out.append("--hybrid")
    if given("rank_objective") and ns.rank_objective != "pointwise":
        out.append(f"--rank-objective {ns.rank_objective}")
    if ns.confirm_budget is not None:
        if given("budget_method") and ns.budget_method != "score":
            out.append(f"--budget-method {ns.budget_method}")
        if given("budget_seed"):
            out.append("--budget-seed")
    return out


def _target(p: argparse.ArgumentParser, ns: argparse.Namespace, argv: list[str]) -> str:
    """The target URL: exactly one of the positional (which must be the first argument)
    and the ``--base-url`` alias."""
    url, alias = ns.url, ns.base_url
    for value, name in ((url, "<url>"), (alias, "--base-url")):
        if value is not None and not value.strip():
            p.error(f"{name}: empty target")       # malformed is not absent (PA-0105)
    if url is not None and alias is not None:
        p.error("give the target once: a <url> first, or --base-url (not both)")
    if url is not None:
        if not argv or argv[0] != url:
            p.error(f"put the <url> first (fuzzlab train run {url} …), or use --base-url")
        return url
    if alias is not None:
        return alias
    swallowed = getattr(ns, "header_points", None)
    if isinstance(swallowed, str) and "://" in swallowed:
        p.error("no target <url>: --header-points took the URL as its value; put the <url> "
                "first, or use --base-url")
    p.error("a target <url> is required (first argument), e.g. fuzzlab train run "
            "http://127.0.0.1:8080 --ground-truth lab/ground-truth --authorized")
    raise AssertionError("unreachable")


def forward(argv: list[str], ns: argparse.Namespace, target: str,
            resolved: storepath.ResolvedStore) -> list[str]:
    """The engine's argv: the user's own argv verbatim (PA-0400(3)) -- the positional
    ``<url>`` moved to ``--base-url`` -- with the resolved store last. argparse keeps the
    last ``--store``, so the store the engine opens is the store resolved, checked and
    printed here, never a raw value the engine would read differently, e.g. an unexpanded
    ``~`` (BUG-0401, PA-0401)."""
    out = ["--base-url", target, *argv[1:]] if ns.url is not None else list(argv)
    return out + ["--store", str(resolved.path)]


def run_main(argv: list[str]) -> int:
    p = build_run_parser()
    ns = p.parse_args(argv)
    try:
        resolved = storepath.resolve(ns.store)       # an explicit empty --store fails here
    except storepath.StorePathError as exc:
        p.error(str(exc))
    target = _target(p, ns, argv)
    # D-9 is pure and runs before the dry run and the gate, so neither plans a working run
    choices = training_choices(ns)
    if not choices:
        p.error("no training or benchmark choice given (e.g. --ground-truth, --score, "
                "--rank, --holdout, --calibrate platt); a working run is `fuzzlab auto`")
    if not ns.dry_run:
        if not ns.authorized:
            p.error("refusing to send probes without --authorized (lab-only)")
        try:
            storepath.check_writable(resolved)
        except storepath.StorePathError as exc:
            p.error(str(exc))

    from fuzzlab.harness import auto_cli
    rc = auto_cli.main(forward(argv, ns, target, resolved))
    print(f"  {storepath.describe(resolved)}")
    if hasattr(ns, "holdout") and not ns.dry_run and rc == 0:
        print(f"  reveal the sealed holdout with: fuzzlab train reveal-holdout --store "
              f"{shlex.quote(str(resolved.path))} --run <the run id above>")
    return rc


# --- train models -------------------------------------------------------------------

def build_models_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fuzzlab train models",
        description="List the saved models (label-free facts only; read-only).")
    p.add_argument("--store", default=None,
                   help=storepath.store_help("Unified store (SQLite) to read"))
    return p


def models_main(argv: list[str]) -> int:
    p = build_models_parser()
    args = p.parse_args(argv)
    try:
        resolved = storepath.resolve(args.store)
        storepath.check_readable(resolved)
    except storepath.StorePathError as exc:
        p.error(str(exc))
    from fuzzlab.plugins.optional import ML_UNAVAILABLE, import_ml
    registry = import_ml("fuzzlab.ml.model_registry")      # the optional-ML seam (FR-ML-6)
    if registry is None:
        print(f"fuzzlab train models: {ML_UNAVAILABLE} (fuzzlab.ml)", file=sys.stderr)
        return 2
    print(storepath.describe(resolved), file=sys.stderr)
    from fuzzlab.core.store import Store
    with Store(resolved.path) as store:
        rows = registry.list_models(store)
    if not rows:
        print("no saved models (train one with `fuzzlab train run <url> --score …`)")
        return 0
    print(f"{'id':>4}  {'name':<22} {'ver':>3}  {'feat':>4}  {'params':<6} "
          f"{'trained on':<10} {'scope':<8} {'source':<7} {'scored':>6}  created")
    for r in rows:
        if r["unreadable"]:
            print(f"{r['id']:>4}  {r['name']:<22} {r['version']:>3}  "
                  f"{_cell(r['feature_version']):>4}  {_cell(r['has_params']):<6} "
                  f"unreadable calibration  {r['created_at']}")
            continue
        print(f"{r['id']:>4}  {r['name']:<22} {r['version']:>3}  "
              f"{_cell(r['feature_version']):>4}  {_cell(r['has_params']):<6} "
              f"{_cell(r['trained_on']):<10} {r['scope']:<8} "
              f"{_cell(r['source_model_id']):<7} {_cell(r['scored_runs']):>6}  "
              f"{r['created_at']}")
    return 0


def _cell(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    return str(v)
