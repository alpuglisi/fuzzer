"""Whole-package guards for ``fuzzlab/disco`` (D70).

1. **Isolation from the legacy spider.** No disco module imports
   ``fuzzlab.tools.spider``, ``spa`` or ``formnav``: the new architecture never leans
   on the deprecated crawler (it shares only the browser primitives every component
   uses, `navguard`). One exception, by name (D70 amended 2026-10-19, PA-0505(2)):
   the script-route scanner both crawlers share (SP-47, `SHARED_SPA`), imported as
   ``from fuzzlab.tools.spa import <names>`` -- never the module, never another name
   (the spider's form, reveal and window policy stays its own).
2. **One send path.** The package issues HTTP in exactly one place,
   `fuzzlab.disco.runner.Runner.send`, where the scope and destructive gates sit
   (PA-0083(1)). Any other ``.request(`` / ``requests.<verb>(`` / ``urlopen(`` call in
   the package fails here.

Both are proven on synthetic offenders (PA-0034(2)).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.package_guard

ROOT = Path(__file__).resolve().parents[1]
DISCO = ROOT / "fuzzlab" / "disco"
LEGACY = ("fuzzlab.tools.spider", "fuzzlab.tools.spa", "fuzzlab.tools.formnav")
#: SP-47: the script-route scanner and the URL rules its routes need, shared by both
#: crawlers (`docs/SHARED_PRIMITIVES.md`); nothing else of `tools.spa`.
SHARED_SPA = frozenset({"scan_script", "classify_route", "ROUTE_OK", "route_url",
                        "spa_fragment", "seed_url", "query_url_refusal"})
_SEND_CALLS = {"request", "urlopen", "get", "post", "put", "patch", "delete", "head",
               "options", "send"}
#: The one place disco sends HTTP: (file, class.function).
SEND_SITES = {("runner.py", "Runner.send")}


def legacy_imports(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [a.name for a in node.names if a.name.startswith(LEGACY)]
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "fuzzlab.tools.spa":
                found += [f"{mod}.{a.name}" for a in node.names
                          if a.name not in SHARED_SPA]
            elif mod.startswith(LEGACY):
                found.append(mod)
            elif mod == "fuzzlab.tools":
                found += [f"{mod}.{a.name}" for a in node.names
                          if f"{mod}.{a.name}" in LEGACY]
    return found


def http_send_sites(source: str, name: str) -> set[tuple[str, str]]:
    """``(file, Class.func)`` of each call that may issue HTTP: a ``requests``/``httpx``
    verb, any ``.request(`` / ``urlopen(``."""
    tree = ast.parse(source)
    sites = set()
    for cls in [n for n in ast.walk(tree) if isinstance(n, (ast.ClassDef, ast.Module))]:
        owner = cls.name if isinstance(cls, ast.ClassDef) else "<module>"
        for fn in [n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for call in [c for c in ast.walk(fn) if isinstance(c, ast.Call)]:
                f = call.func
                attr = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                base = f.value.id if isinstance(f, ast.Attribute) and \
                    isinstance(f.value, ast.Name) else ""
                if attr in ("request", "urlopen") or (
                        base in ("requests", "httpx", "urllib3") and attr in _SEND_CALLS):
                    sites.add((name, f"{owner}.{fn.name}"))
    return sites


def test_no_disco_module_imports_the_legacy_spider():
    offenders = {p.name: legacy_imports(p.read_text()) for p in sorted(DISCO.rglob("*.py"))}
    assert {k: v for k, v in offenders.items() if v} == {}


def test_the_isolation_guard_catches_synthetic_offenders():
    for src in ("from fuzzlab.tools.spider import LocalSpider\n",
                "from fuzzlab.tools import spa\n", "import fuzzlab.tools.formnav as f\n"):
        assert legacy_imports(src), src
    assert legacy_imports("from fuzzlab.tools import navguard\n") == []
    # the SP-47 allowlist: its names only, and only by name
    assert legacy_imports("from fuzzlab.tools.spa import scan_script, route_url\n") == []
    assert legacy_imports("from fuzzlab.tools.spa import scan_script, form_refusal\n") \
        == ["fuzzlab.tools.spa.form_refusal"]
    assert legacy_imports("import fuzzlab.tools.spa\n")


def test_disco_sends_http_only_through_the_runner_s_gated_send():
    sites = set()
    for p in sorted(DISCO.rglob("*.py")):
        sites |= http_send_sites(p.read_text(), p.name)
    assert sites == SEND_SITES


def test_the_send_guard_catches_synthetic_offenders():
    src = ("import requests\n"
           "class Probe:\n"
           "    def fire(self, url):\n"
           "        return requests.post(url)\n"
           "def helper(session, url):\n"
           "    return session.request('GET', url)\n")
    assert http_send_sites(src, "x.py") == {("x.py", "Probe.fire"),
                                            ("x.py", "<module>.helper")}
