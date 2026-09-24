# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 6 of 10). Genuinely distinct third
# variant from idiomatic-jinja2-file-template-3.py (never compile untrusted
# text at all) / vulnerable-jinja2-user-template-3.py (a plain Environment
# compiling untrusted text): a customizable-notification-email feature,
# where compiling admin-authored template text is the whole point of the
# feature -- using Jinja2's own SandboxedEnvironment, its documented,
# purpose-built API for exactly this case.
from jinja2.sandbox import SandboxedEnvironment

# SandboxedEnvironment restricts attribute/item access during rendering,
# blocking the `''.__class__.__mro__[...]` object-model-traversal chain
# that a plain Environment leaves reachable -- Jinja2's own documentation
# recommends it specifically "if you want to render templates whose source
# might not be fully trusted."
sandbox_env = SandboxedEnvironment()


def render_notification_email(admin_template: str, recipient_name: str, order_id: str) -> str:
    template = sandbox_env.from_string(admin_template)
    return template.render(recipient_name=recipient_name, order_id=order_id)
