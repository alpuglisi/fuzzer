# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 6 of 10). Derived from
# idiomatic-4-altered.py's real customizable-notification-email structure.
# Minimal-pair discipline: identical function signature, identical
# from_string()/render() call shape. The ONLY mechanism difference is which
# Environment class compiles the admin-authored template text: a plain
# jinja2.Environment (this file) instead of jinja2.sandbox.SandboxedEnvironment
# (the idiomatic sibling) -- the plain Environment leaves Jinja2's default,
# non-sandboxed object-model access reachable from template expressions.
from jinja2 import Environment

# VULNERABLE: a plain Environment (not SandboxedEnvironment) compiling
# admin-authored template text -- the well-documented
# {{ ''.__class__.__mro__[1].__subclasses__() }}-style chain applies
# directly, since nothing here restricts attribute/item access during
# rendering. An admin account (or anyone who can reach this "customize your
# notification email" feature, e.g. via a compromised admin session or an
# authorization gap elsewhere) can use it for RCE, not just template-content
# injection.
env = Environment()


def render_notification_email(admin_template: str, recipient_name: str, order_id: str) -> str:
    template = env.from_string(admin_template)
    return template.render(recipient_name=recipient_name, order_id=order_id)
