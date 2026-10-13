"""The one door from the rest of the toolkit into the optional ML package (FR-ML-6).

ML attaches as plugins (CC-ML-0017), so the toolkit must run without `fuzzlab.ml`: the
scan, the report and the web app import it only through `import_ml`, never directly
(enforced by `tests/test_ml_import_guard.py`). "Absent" is decided narrowly — only a
missing `fuzzlab.ml` package itself — so a genuine bug inside a present ML package
still raises instead of being reported as "not installed" (PA-0021).
"""

from __future__ import annotations

import importlib
from types import ModuleType

ML_PACKAGE = "fuzzlab.ml"
ML_UNAVAILABLE = "ML components are not installed"


def _package_absent() -> bool:
    try:
        pkg = importlib.import_module(ML_PACKAGE)
    except ModuleNotFoundError as exc:
        if exc.name == ML_PACKAGE:
            return True
        raise
    # A leftover directory without `__init__.py` imports as a namespace package (no
    # `__file__`): that is not an installed ML package.
    return getattr(pkg, "__file__", None) is None


def import_ml(module: str) -> ModuleType | None:
    """Import ``module`` (``fuzzlab.ml`` or a submodule), or return ``None`` when the
    ML package is not installed. Any other import failure re-raises."""
    if module != ML_PACKAGE and not module.startswith(ML_PACKAGE + "."):
        raise ValueError(f"import_ml only imports {ML_PACKAGE}, not {module!r}")
    if _package_absent():
        return None
    return importlib.import_module(module)


def ml_available() -> bool:
    return not _package_absent()
