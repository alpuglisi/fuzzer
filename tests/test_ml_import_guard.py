"""Nothing outside `fuzzlab/ml/` imports the ML package except through
`fuzzlab.plugins.optional.import_ml` (FR-ML-6, CC-FUZZ-0050).

That is what lets the toolkit run without `fuzzlab.ml`: a single direct import anywhere
in the scan, report or web app would make them fail to start without it. The scan covers
the `fuzzlab/` package only — `tests/` and `scripts/` legitimately import ML.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "fuzzlab"
ALLOWED_FILE = PKG / "plugins" / "optional.py"          # the one door
_MODULE_PATH = re.compile(r"^fuzzlab\.ml(\.\w+)*$")


def _is_ml(name: str | None) -> bool:
    return bool(name) and (name == "fuzzlab.ml" or name.startswith("fuzzlab.ml."))


def _package_of(path: Path) -> list[str]:
    """The dotted package a module's relative imports resolve against."""
    parts = list(path.relative_to(PKG.parent).with_suffix("").parts)
    return parts[:-1]          # a module's package; for __init__ that is its own package


def _import_ml_args(tree: ast.AST) -> set[int]:
    """ids of string constants passed as the first argument of `import_ml(...)`."""
    ok = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args:
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name == "import_ml" and isinstance(node.args[0], ast.Constant):
                ok.add(id(node.args[0]))
    return ok


def offenders(source: str, path: Path) -> list[str]:
    tree = ast.parse(source)
    allowed = _import_ml_args(tree)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [f"import {a.name}" for a in node.names if _is_ml(a.name)]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _package_of(path)[:len(_package_of(path)) - node.level + 1]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            if _is_ml(module):
                found.append(f"from {module} import …")
            elif module == "fuzzlab" and any(a.name == "ml" for a in node.names):
                found.append("from fuzzlab import ml")
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and _MODULE_PATH.match(node.value) and id(node) not in allowed):
            found.append(f"string {node.value!r}")
    return found


def test_no_module_outside_ml_imports_it_except_through_import_ml():
    bad = {}
    for path in sorted(PKG.rglob("*.py")):
        if (PKG / "ml") in path.parents or path == ALLOWED_FILE:
            continue
        found = offenders(path.read_text(encoding="utf-8"), path)
        if found:
            bad[str(path.relative_to(PKG.parent))] = found
    assert bad == {}, "reach fuzzlab.ml only via fuzzlab.plugins.optional.import_ml"


def test_the_guard_catches_every_import_form():          # PA-0034(2): proven on bad input
    web = PKG / "web" / "example.py"
    cases = [
        "import fuzzlab.ml",
        "import fuzzlab.ml.train as t",
        "from fuzzlab.ml.train import latest_classifier",
        "from fuzzlab import ml",
        "from ..ml import train",
        "from ..ml.rank_train import latest_ranker",
        "def f():\n    from fuzzlab.ml.anomaly import ECOD",          # lazy, inside a function
        "import importlib\nimportlib.import_module('fuzzlab.ml.train')",
        "__import__('fuzzlab.ml')",
        "import runpy\nrunpy.run_module('fuzzlab.ml.active')",
        "MODULES = {'x': 'fuzzlab.ml.plugins'}",
    ]
    for src in cases:
        assert offenders(src, web), src


def test_the_guard_allows_the_sanctioned_and_unrelated_forms():
    web = PKG / "web" / "example.py"
    fine = [
        "from fuzzlab.plugins.optional import import_ml\nt = import_ml('fuzzlab.ml.train')",
        "import fuzzlab.plugins.optional as o\no.import_ml('fuzzlab.ml')",
        '"""Prose may mention fuzzlab.ml.train.train_and_score in a docstring."""',
        "from ..mlview import x",                                    # web.mlview, not ML
        "import fuzzlab.mlx",
        "from . import mlview",
    ]
    for src in fine:
        assert not offenders(src, web), src
