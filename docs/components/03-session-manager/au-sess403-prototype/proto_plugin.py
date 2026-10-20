"""pytest plugin: install the AU-SESS403 revision-3 prototype before any test runs
(``-p proto_plugin`` with this directory on ``PYTHONPATH``). ``REVERT=<name>`` undoes one
decision of the design (``proto.REVERTS``).

A ``guard_*`` revert instead weakens T19's own guard: the test module's
``loss_decision_offenders`` is re-executed with one branch switched off, so its
synthetic-offender proof must fail."""

import inspect
import textwrap

import proto

proto.install()

#: guard revert -> (the exact text of the branch's test, its switched-off form)
_GUARD = {
    "guard_noassign": ("if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):",
                       "if False:"),
    "guard_nosetattr": ('if name == "setattr"', 'if False and name == "setattr"'),
    "guard_nodunder": ('if name == "__setattr__":', "if False:"),
    "guard_nokeyword": ('if kw.arg == "valid":', "if False:"),
    "guard_nocall": ('if name == "detect_logout" and where not in LOSS_PREDICATE_CALLERS:',
                     "if False:"),
}


def pytest_collection_modifyitems(session, config, items):
    if proto.REVERT not in _GUARD:
        return
    old, new = _GUARD[proto.REVERT]
    done = set()
    for item in items:
        mod = getattr(item, "module", None)
        if mod is None or id(mod) in done or not hasattr(mod, "loss_decision_offenders"):
            continue
        src = textwrap.dedent(inspect.getsource(mod.loss_decision_offenders))
        if src.count(old) != 1:
            raise SystemExit(f"{proto.REVERT}: the guard's branch text is not found once")
        exec(compile(src.replace(old, new), mod.__file__, "exec"), mod.__dict__)
        done.add(id(mod))
