# Manufactured vulnerable variant, derived from
# idiomatic-jinja2-file-template-3.py. Environment.from_string() compiles
# attacker-supplied text as a template -- Jinja2's own documentation
# explicitly warns this must never be done with untrusted input, since
# Jinja2's default (non-sandboxed) Environment allows reaching Python's
# object model from template expressions (the well-documented
# {{ ''.__class__.__mro__[...] }} SSTI-to-RCE chain).
from jinja2 import Environment

env = Environment()


def render_show_page(show_title: str, user_supplied_layout: str) -> str:
    template = env.from_string(user_supplied_layout)
    return template.render(title=show_title)
