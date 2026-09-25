"""CC-LAB-0247 (Lane 7, §2e): the shared, cross-emitter absent-input
declaration vocabulary (PA-0053/PA-0054/PA-0056/PA-0058).

Every emitter's route profile declares, for each route, what happens when
the request carries none of its inputs -- a handled default, a handled
rejection, or a declaration that no input is read at all. Two emitters
(`go_net_http`, Lane 3; `spring_boot`, Lane 4) invented this independently
and gave the same underlying behaviors different spellings
(`required_400`/`default` vs. `required_param`/`default_value`), which
`docs/bugs/BUG-0056-*.md` flagged as fragmentation and `PA-0058` rule 2
required this lane to close.

:data:`ABSENT_INPUT_VALUES` is the **closed core set** every emitter's
route profile may use. An emitter whose stack has a genuinely different
absent-input *mechanism* -- not just a different name for the same one --
may declare its own additional, stack-specific values (e.g.
`go_net_http`'s caller-header-based auth shapes, which no other emitter's
route table currently models) alongside this core set; it must never
rename this core set's own meanings, and a cross-emitter check validates
membership against the emitter's own full set (core plus its declared
extras), never against undeclared free text (PA-0058 rule 2).
"""

from __future__ import annotations

#: The core, cross-emitter closed vocabulary. Every value here means
#: exactly the same thing in every emitter that uses it:
ABSENT_INPUT_VALUES: frozenset[str] = frozenset(
    {
        "default_value",       # an absent/empty value becomes a real default before the sink runs
        "required_param",      # an absent/empty value is a handled 400 before the sink runs (no safe default)
        "required_header",     # an absent/empty required header is a handled 4xx before the sink runs
        "required_multipart",  # an absent required multipart part is a handled 400 before the sink runs
        "empty_body_400",      # a whole-body source: an absent/empty body is a handled 400 before the sink runs
        "no_input",            # the source reads no request input at all
        "form_when_absent",    # a page route: no input -> the form alone, 200, before the source/sink runs
    }
)
