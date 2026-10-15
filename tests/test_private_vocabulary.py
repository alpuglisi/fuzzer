"""PA-0154(3) (BUG-0148): no module of `fuzzlab/` reads another module's private
vocabulary.

A private vocabulary is a ``_UPPER_CASE`` constant (a word list, a set, a pattern). The
browser login kept a narrower copy of SP-16's login rule over ``detect._LOGIN_SEGMENTS``,
and the defined-once check of `docs/SHARED_PRIMITIVES.md` could not see it. This guard
reads every module by AST and flags such a name of another module however it is reached:
``from m import _X``, ``from .m import _X`` (relative), ``import m as a; a._X``,
``from pkg import m; m._X``. A package's own private names are shared with its
submodules. Known instances in files the BUG-0148 change may not edit are listed with
their reason; a stale entry fails; the login vocabulary has no entry. Proven on synthetic
offenders (PA-0034(2)).

Private rule **functions** imported across modules are recorded as debt, not judged
here: ``spa.label_refusal`` imports ``browserlogin._account_hit`` (BUG-0148's sweep).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.package_guard

#: Known private-constant reads across modules, each in a file the BUG-0148 change may
#: not edit (another lane's, or outside its scope), with the reason.
KNOWN = {
    ("fuzzlab/tools/spa.py", "fuzzlab.tools.store_adapter", "_FILLERS"):
        "filler values shared with the importer; spa.py is another lane's file",
    ("fuzzlab/tools/spa.py", "fuzzlab.tools.store_adapter", "_TEXT_FILLER"):
        "as above",
    ("fuzzlab/harness/auto.py", "fuzzlab.oracle.strategies", "_TIMING_TEMPLATES"):
        "timing templates read by the harness; harness/* is another lane's",
    ("fuzzlab/harness/auto.py", "fuzzlab.oracle.strategies.SqliBooleanStrategy",
     "_FAMILIES"):
        "a strategy class's payload families read by the harness; harness/* is another "
        "lane's",
    ("fuzzlab/labgen/conformance/django_live_boot.py",
     "fuzzlab.labgen.conformance.live_boot", "_NO_REDIRECT_OPENER"):
        "a sibling harness's opener, not a keyword vocabulary; outside BUG-0148's scope",
}


def _private(name: str) -> bool:
    return name.startswith("_") and name.lstrip("_")[:1].isupper() and name.upper() == name


def _module_of(rel: str) -> str:
    mod = rel[:-3].replace("/", ".")
    return mod[: -len(".__init__")] if mod.endswith(".__init__") else mod


def _resolve(own: str, is_package: bool, module: str | None, level: int) -> str:
    """The absolute module an ``ImportFrom`` names (``from ..x import y``)."""
    if level == 0:
        return module or ""
    base = own.split(".")
    base = base if is_package else base[:-1]
    base = base[: len(base) - (level - 1)] if level > 1 else base
    return ".".join(base + ([module] if module else []))


def private_reads(source: str, rel: str) -> set[tuple[str, str, str]]:
    """``(file, module, name)`` for each read of another module's private constant."""
    own = _module_of(rel)
    is_package = rel.endswith("__init__.py")
    parents = {own.rsplit(".", n)[0] for n in range(1, own.count(".") + 1)}
    tree = ast.parse(source)
    aliases: dict[str, str] = {}             # local name -> module it may stand for
    found = set()

    def foreign(module: str) -> bool:
        return module.startswith("fuzzlab") and module != own and module not in parents

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[alias.name.split(".", 1)[0]] = alias.name.split(".", 1)[0]
        elif isinstance(node, ast.ImportFrom):
            module = _resolve(own, is_package, node.module, node.level)
            for alias in node.names:
                if _private(alias.name):
                    if foreign(module):
                        found.add((rel, module, alias.name))
                elif alias.name.upper() != alias.name:
                    # a module (``from pkg import mod``) or a class: its private
                    # constants are private vocabulary too; a constant is not followed
                    aliases[alias.asname or alias.name] = f"{module}.{alias.name}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and _private(node.attr):
            dotted = ast.unparse(node.value)
            head, _sep, rest = dotted.partition(".")
            if head in aliases and head.isidentifier():
                module = aliases[head] + ("." + rest if rest else "")
                if foreign(module):
                    found.add((rel, module, node.attr))
    return found


def package_private_reads() -> set[tuple[str, str, str]]:
    out = set()
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        out |= private_reads(path.read_text(encoding="utf-8"),
                             path.relative_to(ROOT).as_posix())
    return out


def test_no_module_imports_another_modules_private_vocabulary():
    found = package_private_reads()
    assert sorted(f for f in found if f[2].startswith("_LOGIN")) == [], \
        "the login vocabulary is detect.py's public names (SP-16)"
    assert found - set(KNOWN) == set()
    assert set(KNOWN) - found == set(), "stale allowlist entry"


def test_the_private_vocabulary_guard_catches_synthetic_offenders():
    """PA-0034(2): BUG-0148's own line, a multi-line and an aliased import, a relative
    import, and attribute access through ``import ... as`` and ``from pkg import mod``."""
    rel = "fuzzlab/session/browserlogin.py"
    for source in (
            "from fuzzlab.session.detect import _LOGIN_SEGMENTS",
            "from fuzzlab.session.detect import (\n  X,\n  _LOGIN_TOKENS)",
            "from fuzzlab.tools.spa import _MAX_GAP as gap",
            "from .detect import _LOGIN_SEGMENTS",
            "from . import detect\nx = detect._LOGIN_SEGMENTS",
            "import fuzzlab.session.detect as d\nx = d._LOGIN_SEGMENTS",
            "from fuzzlab.session import detect\nx = detect._LOGIN_TOKENS",
            "import fuzzlab.session.detect\nx = fuzzlab.session.detect._LOGIN_TOKENS"):
        assert private_reads(source, rel), source
    for source in (
            "from fuzzlab.session.detect import LOGIN_WORDS",
            "from fuzzlab.session.detect import _login_segment",       # a function
            "from fuzzlab.session.browserlogin import _X",             # its own module
            "self._LOGIN = 1\nx = self._LOGIN",                        # not a module
            "from fuzzlab.session.detect import LOGIN_WORDS\nx = LOGIN_WORDS._X"):
        assert not private_reads(source, rel), source
    # a package's own private names are shared with its submodules
    assert not private_reads("from fuzzlab.labgen.emitters.php_laravel import _PAGE",
                             "fuzzlab/labgen/emitters/php_laravel/auth_session.py")
