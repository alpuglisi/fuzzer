"""SP-56: one classification of an HTTP answer (CC-CORE-0069, FR-CORE-507; AU-OUTCOME;
BUG-0528, BUG-0529).

`core.comparability.response_class` names an answer as the application's own, or a
throttle-or-unavailable, gateway, auth-failure, policy-block or incomplete answer. These
tests state its rule table row by row, prove it total, keep it free of session and oracle
imports, and keep every other status-literal classification of those statuses in
`fuzzlab/` on a reviewed allowance list (each guard proven on a synthetic offender,
PA-0034(2))."""

from __future__ import annotations

import ast
import itertools
from pathlib import Path

import pytest

from fuzzlab.core import comparability as C

ROOT = Path(__file__).resolve().parents[1]
OWNER = ROOT / "fuzzlab" / "core" / "comparability.py"


def _expected(status, complete, credentialed, submission, to_login):
    """The rule table of the module docstring, restated (first match wins)."""
    if not complete or not isinstance(status, int) or status <= 0:
        return C.INCOMPLETE
    if status in (429, 503):
        return C.THROTTLE_OR_UNAVAILABLE
    if status in (502, 504):
        return C.GATEWAY
    if status == 407:
        return C.AUTH_FAILURE
    refused = credentialed and not submission
    if status == 401 and refused:
        return C.AUTH_FAILURE
    if 300 <= status < 400 and to_login and refused:
        return C.AUTH_FAILURE
    if status in (403, 451):
        return C.POLICY_BLOCK
    return C.APPLICATION


STATUSES = (0, -1, 200, 204, 302, 303, 400, 401, 403, 404, 407, 429, 451, 500, 502,
            503, 504)


@pytest.mark.parametrize("status", STATUSES)
def test_every_rule_row_classifies_as_stated(status):
    """The full credentialed x credential-submission x login-redirect x complete matrix
    for every status a rule names (and its neighbours)."""
    for complete, cred, sub, to_login in itertools.product((True, False), repeat=4):
        got, why = C.response_class(status, {}, complete=complete, credentialed=cred,
                                    credential_submission=sub, redirect_to_login=to_login)
        assert got == _expected(status, complete, cred, sub, to_login), \
            (status, complete, cred, sub, to_login, got)
        assert got in C.RESPONSE_CLASSES
        assert (why == "") == (got == C.APPLICATION)
        if got != C.APPLICATION and got != C.INCOMPLETE:
            assert str(status) in why                      # a class and a status only


def test_a_503_names_its_retry_after_and_stays_throttle_or_unavailable():
    """503 is "throttle or unavailable" by policy (RFC 9110 15.6.4; nginx's documented
    ``limit_req_status`` default), with or without ``Retry-After`` in any case."""
    for headers in ({}, {"Retry-After": "30"}, {"retry-after": "1"}):
        cls, why = C.response_class(503, headers, complete=True, credentialed=False,
                                    credential_submission=False, redirect_to_login=False)
        assert cls == C.THROTTLE_OR_UNAVAILABLE
        assert ("Retry-After" in why) == bool(headers)


@pytest.mark.parametrize("status,headers", [
    (None, None), ("200", {}), (200.0, {}), (True, {}), (False, {}), (10 ** 9, {}),
    (200, 5), (200, ["not", "pairs"]), (429, object()), (503, 7), (object(), None),
])
def test_response_class_is_total(status, headers):
    """PA-0500(1): malformed input never raises; a status that is not an integer (a
    bool included) is incomplete."""
    cls, why = C.response_class(status, headers, complete=True, credentialed=True,
                                credential_submission=False, redirect_to_login=True)
    assert cls in C.RESPONSE_CLASSES
    assert isinstance(why, str)
    if isinstance(status, bool) or not isinstance(status, int):
        assert cls == C.INCOMPLETE


def test_every_fact_is_a_required_keyword():
    """No caller can leave a fact out: each is keyword-only with no default."""
    import inspect
    params = inspect.signature(C.response_class).parameters
    for name in ("complete", "credentialed", "credential_submission", "redirect_to_login"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
        assert params[name].default is inspect.Parameter.empty


# --- the import guard -------------------------------------------------------------------

def _forbidden_imports(source: str) -> list[str]:
    """Every import of `fuzzlab.session` or `fuzzlab.oracle`, at any depth."""
    bad = []
    for node in ast.walk(ast.parse(source)):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        bad += [n for n in names if n.split(".")[:2] in (["fuzzlab", "session"],
                                                         ["fuzzlab", "oracle"])]
    return bad


def test_the_classifier_imports_neither_session_nor_oracle():
    """SP-56 sits in core: the session manager (defect 6) and the oracle both read it,
    so it imports neither. Proven on a synthetic import, a lazy one included."""
    assert _forbidden_imports(OWNER.read_text(encoding="utf-8")) == []
    assert _forbidden_imports("def f():\n    from fuzzlab.session.detect import "
                              "login_facts\n") == ["fuzzlab.session.detect"]
    assert _forbidden_imports("import fuzzlab.oracle.probe\n") == ["fuzzlab.oracle.probe"]


# --- the status guard -------------------------------------------------------------------

#: The statuses SP-56 classifies.
CLASSIFIED = frozenset({401, 403, 407, 429, 451, 502, 503, 504})

#: Every other status-literal comparison of those statuses in `fuzzlab/`, each with what
#: it decides (FR-CORE-507). Keyed by module and enclosing qualified name; a new site
#: fails until it is either routed through SP-56 or reviewed here, and a stale row fails.
ALLOWED = {
    ("fuzzlab/session/manager.py", "SessionManager._login"):
        ({401, 403}, "a Basic challenge, and a failed login response"),
    ("fuzzlab/session/manager.py", "SessionManager._discover_login_form"):
        ({401}, "a 401 at the base URL means Basic auth"),
    ("fuzzlab/session/detect.py", "detect_session_credential"):
        ({401}, "a Basic ``WWW-Authenticate`` challenge"),
    ("fuzzlab/oracle/strategies.py", "JwtAlgNoneConfusionStrategy.confirm"):
        ({401, 403}, "its control's rejection is the evidence, not a comparison"),
    ("fuzzlab/tools/blind_sqli_fuzzer.py", "run_fuzzing_cycle"):
        ({504}, "a payload's 504 stays a timing observation (a gateway, or the "
                "sender's own timeout stand-in, waited on the query; A4)"),
}


def _ints(node) -> set[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) \
            and not isinstance(node.value, bool):
        return {node.value}
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return set().union(*(_ints(e) for e in node.elts)) if node.elts else set()
    return set()


def _status_sites(source: str) -> dict[str, set[int]]:
    """Enclosing qualified name -> the classified statuses compared there as literals."""
    sites: dict[str, set[int]] = {}

    def visit(node, scope: tuple[str, ...]):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = scope + (node.name,)
        if isinstance(node, ast.Compare):
            hit = set().union(*(_ints(c) for c in (node.left, *node.comparators)))
            hit &= CLASSIFIED
            if hit:
                sites.setdefault(".".join(scope), set()).update(hit)
        for child in ast.iter_child_nodes(node):
            visit(child, scope)
    visit(ast.parse(source), ())
    return sites


def _all_sites() -> dict[tuple[str, str], set[int]]:
    found = {}
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        if path == OWNER:
            continue
        rel = path.relative_to(ROOT).as_posix()
        for scope, statuses in _status_sites(path.read_text(encoding="utf-8")).items():
            found[(rel, scope)] = statuses
    return found


def test_no_module_classifies_a_throttle_or_refusal_but_the_owner():
    """FR-CORE-507 / PA-0529(4): outside `core.comparability`, a comparison against a
    status SP-56 classifies exists only where the allowance list says what it decides;
    the list is exact (a stale row fails)."""
    found = _all_sites()
    assert set(found) == set(ALLOWED), (sorted(set(found) - set(ALLOWED)),
                                        sorted(set(ALLOWED) - set(found)))
    for key, statuses in found.items():
        assert statuses <= ALLOWED[key][0], (key, statuses)


def test_the_status_guard_catches_a_synthetic_offender():
    src = ("class Sender:\n"
           "    def send(self, resp):\n"
           "        if resp.status_code in (429, 503):\n"
           "            return None\n"
           "        return resp.status == 200\n")
    assert _status_sites(src) == {"Sender.send": {429, 503}}
    assert _status_sites("ok = status >= 500 or status == 404\n") == {}
