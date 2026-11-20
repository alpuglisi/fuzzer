"""PA-0690 (BUG-0690): no browser path silently drops the run's identity.

BUG-0690: the M6 executor's browser context was opened with no session and the auto
CLI built the executor with none, so in a run with ``--identity`` its stored-XSS plant
and its observe page went out anonymously while every probe carried the identity.
PA-0545(1) required "every send path carries the identity or refuses", but its guards
were the spider's own tests: the existing SP-74 wiring guard
(`tests/test_browser_session_reach.py::reach_offenders`) checks only modules that
already adopt a session, so a context that never adopts one passed unseen.

These guards are whole-package (AST), proven on synthetic offenders:

- every Playwright **browser** context fuzzlab opens adopts a session through the one
  adoption helper (``**browserauth.context_options(...)``, or ``storage_state=``), or is
  listed in `ANONYMOUS_CONTEXTS` with the reason it is anonymous by design;
- every `PlaywrightBrowserExecutor` fuzzlab builds is given the run's session route.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: ``module:function`` -> why that browser context is anonymous by design.
ANONYMOUS_CONTEXTS = {
    "fuzzlab/disco/ede.py:run": (
        "the EDE replay accepts no identity (`fuzzlab disco ede` has no --identity): its "
        "JSON answers are replayed from the capture, nothing is a session send"),
    "fuzzlab/session/browserlogin.py:_drive": (
        "the browser login itself: it runs anonymous to produce the session"),
    "fuzzlab/tools/spider.py:_dry_submit_anonymously": (
        "a password form is dry-submitted in a fresh unauthenticated context, so the "
        "run's session is never submitted to it (by design, its docstring)"),
    "fuzzlab/tools/spider.py:_submit_anonymously": (
        "the same: a credential form is submitted without the run's session"),
}


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _api_context(node: ast.Call) -> bool:
    f = node.func
    return isinstance(f, ast.Attribute) and f.attr == "new_context" and \
        isinstance(f.value, ast.Attribute) and f.value.attr == "request"


def _adopts(call: ast.Call) -> bool:
    for k in call.keywords:
        if k.arg == "storage_state":
            return True
        if k.arg is None and isinstance(k.value, ast.Call) and \
                _call_name(k.value) == "context_options":
            return True
    return False


def context_offenders(source: str, module: str, exempt=None) -> list[str]:
    """Browser ``new_context(...)`` calls that neither adopt a session nor are declared
    anonymous (``module:function`` in ``exempt``)."""
    exempt = ANONYMOUS_CONTEXTS if exempt is None else exempt
    out = []
    for fn in ast.walk(ast.parse(source)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for c in ast.walk(fn):
            if isinstance(c, ast.Call) and _call_name(c) == "new_context" and \
                    not _api_context(c) and not _adopts(c) and \
                    f"{module}:{fn.name}" not in exempt:
                out.append(f"{module}:{fn.name}:{c.lineno}: a browser context that "
                           f"adopts no session and is not declared anonymous")
    return out


def executor_offenders(source: str, module: str) -> list[str]:
    """`PlaywrightBrowserExecutor(...)` built without ``session_route=``."""
    return [f"{module}:{c.lineno}: PlaywrightBrowserExecutor without session_route"
            for c in ast.walk(ast.parse(source))
            if isinstance(c, ast.Call) and _call_name(c) == "PlaywrightBrowserExecutor"
            and not any(k.arg == "session_route" for k in c.keywords)]


def _modules():
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        yield str(path.relative_to(ROOT)), path.read_text(encoding="utf-8")


def test_every_browser_context_adopts_the_session_or_is_declared_anonymous():
    offenders, seen = [], 0
    for module, source in _modules():
        offenders += context_offenders(source, module)
        seen += source.count("new_context(")
    assert offenders == []
    assert seen >= 8                                     # the guard is not vacuous
    # every exemption names a function that still opens a browser context
    for key in ANONYMOUS_CONTEXTS:
        module, fn = key.split(":")
        tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
        assert any(isinstance(n, ast.FunctionDef) and n.name == fn and any(
            isinstance(c, ast.Call) and _call_name(c) == "new_context"
            for c in ast.walk(n)) for n in ast.walk(tree)), key


def test_every_m6_executor_fuzzlab_builds_gets_the_runs_session_route():
    offenders, built = [], 0
    for module, source in _modules():
        offenders += executor_offenders(source, module)
        built += source.count("PlaywrightBrowserExecutor(")
    assert offenders == [] and built >= 1


def test_the_guards_catch_synthetic_offenders():
    """Proven on BUG-0690's shapes: the executor's context and the CLI's build."""
    bare = ("def _in_browser(browser):\n"
            "    ctx = browser.new_context(service_workers='block')\n")
    assert context_offenders(bare, "m.py") == [
        "m.py:_in_browser:2: a browser context that adopts no session and is not "
        "declared anonymous"]
    adopted = ("def _in_browser(browser, s):\n"
               "    ctx = browser.new_context(service_workers='block',\n"
               "                              **browserauth.context_options(s))\n"
               "def _other(browser, st):\n"
               "    ctx = browser.new_context(storage_state=st)\n"
               "def _api(pw):\n"
               "    ctx = pw.request.new_context()\n")
    assert context_offenders(adopted, "m.py") == []
    assert context_offenders(bare, "m.py", exempt={"m.py:_in_browser": "why"}) == []
    cli = "browser = PlaywrightBrowserExecutor()\n"
    assert executor_offenders(cli, "m.py") == [
        "m.py:1: PlaywrightBrowserExecutor without session_route"]
    fixed = "browser = PlaywrightBrowserExecutor(session_route=f)\n"
    assert executor_offenders(fixed, "m.py") == []
